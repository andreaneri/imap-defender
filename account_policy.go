package main

import (
    "context"
    "time"

    "github.com/redis/go-redis/v9"
)

// accountSignals contains historical evidence, not proof of account ownership.
type accountSignals struct {
    Known bool
    OriginSucceeded bool
    GlobalFailures int64
    CountryFailures int64
    CountryValid bool
}

type accountAction string

const (
    accountAllow accountAction = "ALLOW"
    accountPace accountAction = "PACE"
    accountBlockCandidate accountAction = "BLOCK_CANDIDATE"
)

type accountDecision struct {
    Action accountAction
    Delay time.Duration
    Reason string
}

// accountPolicy is deliberately internal and not wired to the relay.
// Values are conservative provisional defaults for shadow evaluation.
type accountPolicy struct {
    SoftFailures int64
    HardFailures int64
    BlockGlobalFailures int64
    BlockCountryFailures int64
    SoftDelay time.Duration
    HardDelay time.Duration
}

func defaultAccountPolicy() accountPolicy {
    return accountPolicy{
        SoftFailures: 3,
        HardFailures: 8,
        BlockGlobalFailures: 20,
        BlockCountryFailures: 12,
        SoftDelay: time.Second,
        HardDelay: 8 * time.Second,
    }
}

// evaluateAccountRisk is pure and does not block, delay, or generate IMAP
// responses. The caller must only apply PACE to a genuine backend failure.
func evaluateAccountRisk(s accountSignals, p accountPolicy) accountDecision {
    if !s.Known {
        return accountDecision{Action: accountAllow, Reason: "unknown_account"}
    }
    if s.GlobalFailures < 0 || s.CountryFailures < 0 {
        return accountDecision{Action: accountAllow, Reason: "invalid_signals"}
    }
    if s.CountryValid && s.GlobalFailures >= p.BlockGlobalFailures && s.CountryFailures >= p.BlockCountryFailures {
        return accountDecision{Action: accountBlockCandidate, Reason: "scoped_failure_threshold"}
    }
    if s.GlobalFailures >= p.HardFailures {
        return accountDecision{Action: accountPace, Delay: p.HardDelay, Reason: "repeated_failures"}
    }
    if s.GlobalFailures >= p.SoftFailures {
        return accountDecision{Action: accountPace, Delay: p.SoftDelay, Reason: "elevated_failures"}
    }
    return accountDecision{Action: accountAllow, Reason: "below_threshold"}
}

// ReadAccountSignals performs a bounded, read-only snapshot of the current
// reputation. An error is returned to the caller for explicit fail-open;
// no synthetic knowledge state is invented. This is not an atomic snapshot.
func (rt *RedisTracker) ReadAccountSignals(ctx context.Context, account, ja4, ip, country string) (accountSignals, error) {
    if account == "" || ja4 == "" || rt == nil || rt.client == nil {
        return accountSignals{}, nil
    }
    ctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
    defer cancel()

    countryValid := validCountryCode(country)
    knownKey := accountReputationKey("known", account)
    originKey := accountReputationKey("origin", account, ja4, ip)
    globalKey := accountReputationKey("failures", account, ja4)

    pipe := rt.client.Pipeline()
    known := pipe.Exists(ctx, knownKey)
    origin := pipe.HExists(ctx, originKey, "last_success")
    global := pipe.Get(ctx, globalKey)
    var local *redis.StringCmd
    if countryValid {
        local = pipe.Get(ctx, accountReputationKey("country-failures", account, ja4, country))
    }
    _, err := pipe.Exec(ctx)
    if err != nil && err != redis.Nil {
        return accountSignals{}, err
    }
    // Redis.Nil is the expected absence of a failure counter, not an error.
    readCount := func(cmd *redis.StringCmd) (int64, error) {
        if cmd == nil { return 0, nil }
        count, e := cmd.Int64()
        if e == redis.Nil { return 0, nil }
        return count, e
    }
    g, err := readCount(global)
    if err != nil { return accountSignals{}, err }
    c, err := readCount(local)
    if err != nil { return accountSignals{}, err }
    if known.Err() != nil { return accountSignals{}, known.Err() }
    if origin.Err() != nil { return accountSignals{}, origin.Err() }
    return accountSignals{
        Known: known.Val() > 0,
        OriginSucceeded: origin.Val(),
        GlobalFailures: g,
        CountryFailures: c,
        CountryValid: countryValid,
    }, nil
}
