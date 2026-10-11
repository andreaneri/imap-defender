package main

import (
    "context"
    "crypto/sha256"
    "encoding/json"
    "fmt"
    "time"

    "github.com/redis/go-redis/v9"
)

const (
    accountHistoryTTL = 30 * 24 * time.Hour
    accountFailureWindow = 15 * time.Minute
)

// accountReputationKey hashes structured fields to avoid ambiguous concatenation
// and exposing declared usernames in Redis key names.
func accountReputationKey(kind string, parts ...string) string {
    payload, _ := json.Marshal(parts)
    return fmt.Sprintf("proxy:account:v1:%s:%x", kind, sha256.Sum256(payload))
}

func validAccountOutcome(event authEvent) bool {
    if !event.UsernameKnown || event.Username == "" { return false }
    return event.Outcome == "OK" || event.Outcome == "NO" || event.Outcome == "BAD"
}

// queueAccountReputation stores only backend-authoritative outcomes.
// Failure streaks aggregate across IPs for the same account and JA4;
// country-scoped failures are independent and cannot block other countries.
// No enforcement or block keys are created at this stage.
func queueAccountReputation(ctx context.Context, pipe redis.Pipeliner, event authEvent) {
    if !validAccountOutcome(event) { return }
    account := event.Username
    knownKey := accountReputationKey("known", account)
    pipe.Set(ctx, knownKey, "1", accountHistoryTTL)
    if event.JA4 == "" { return }

    originKey := accountReputationKey("origin", account, event.JA4, event.RemoteIP)
    pipe.HSet(ctx, originKey, map[string]interface{}{
        "last_outcome": event.Outcome,
        "last_seen": event.Timestamp.UTC().Format(time.RFC3339Nano),
    })
    pipe.Expire(ctx, originKey, accountHistoryTTL)

    globalFailures := accountReputationKey("failures", account, event.JA4)
    switch event.Outcome {
    case "OK":
        pipe.HSet(ctx, originKey, "last_success", event.Timestamp.UTC().Format(time.RFC3339Nano))
        // A successful origin does not erase failures observed on other IPs.
    case "NO", "BAD":
        pipe.Incr(ctx, globalFailures)
        pipe.Expire(ctx, globalFailures, accountFailureWindow)
        if validCountryCode(event.CountryCode) {
            countryFailures := accountReputationKey("country-failures", account, event.JA4, event.CountryCode)
            pipe.Incr(ctx, countryFailures)
            pipe.Expire(ctx, countryFailures, accountFailureWindow)
        }
    }
}

func validCountryCode(country string) bool {
    if len(country) != 2 || country == "ZZ" { return false }
    for i:=0; i<2; i++ { if country[i] < 'A' || country[i] > 'Z' { return false } }
    return true
}

// AccountKnown reports only whether an authoritative outcome was previously
// recorded. Redis errors are returned to the caller; they are not a third
// account knowledge state and must fail open at the enforcement boundary.
func (rt *RedisTracker) AccountKnown(ctx context.Context, account string) (bool, error) {
    if account == "" { return false, nil }
    ctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
    defer cancel()
    count, err := rt.client.Exists(ctx, accountReputationKey("known", account)).Result()
    return count > 0, err
}
