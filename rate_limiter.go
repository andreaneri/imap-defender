package main

import (
    "net/netip"
    "math"
    "sync"
    "time"
)

const maxRateLimitBuckets = 100000

// ipRateLimiter limits connections per source IP. JA4 is not an identity.
type ipRateLimiter struct {
    mu sync.Mutex
    buckets map[string]ipBucket
    lastCleanup time.Time
    lastCapacityCleanup time.Time
}

type ipBucket struct {
    tokens float64
    updated time.Time
}

// allowedSource checks exact IPs and CIDR prefixes. Invalid entries are
// rejected by configuration validation, not silently ignored here.
func allowedSource(ip string, exceptions []string) bool {
    addr, err := netip.ParseAddr(ip)
    if err != nil { return false }
    addr = addr.Unmap()
    for _, entry := range exceptions {
        prefix, err := netip.ParsePrefix(entry)
        if err != nil { continue }
        // Canonical IPv4-mapped IPv6 prefixes are rejected at config load.
        if prefix.Contains(addr) { return true }
    }
    return false
}

func (l *ipRateLimiter) allow(ip string, rate, burst int, now time.Time) bool {
    if rate <= 0 || burst <= 0 || ip == "" { return true }
    l.mu.Lock()
    defer l.mu.Unlock()
    if l.buckets == nil { l.buckets = make(map[string]ipBucket) }
    // An inactive bucket has recovered its entire burst. Evicting it
    // cannot grant any more tokens than keeping it would.
    idleSeconds := float64(burst) * 60 / float64(rate)
    // Clamp extreme configurations to prevent time.Duration overflow.
    if idleSeconds > float64(math.MaxInt64)/float64(time.Second) {
        idleSeconds = float64(math.MaxInt64)/float64(time.Second)
    }
    idle := time.Duration(idleSeconds * float64(time.Second))
    if idle < time.Second { idle = time.Second }
    atCapacity := len(l.buckets) >= maxRateLimitBuckets
    regularCleanup := l.lastCleanup.IsZero() || now.Sub(l.lastCleanup) >= time.Minute
    capacityCleanup := atCapacity && (l.lastCapacityCleanup.IsZero() || now.Sub(l.lastCapacityCleanup) >= time.Second)
    if regularCleanup || capacityCleanup {
        for key, bucket := range l.buckets {
            if now.Sub(bucket.updated) >= idle { delete(l.buckets, key) }
        }
        l.lastCleanup = now
        if atCapacity { l.lastCapacityCleanup = now }
    }
    b, ok := l.buckets[ip]
    if !ok {
        if len(l.buckets) >= maxRateLimitBuckets {
            // Saturated storage must not grant an untracked source a fresh
            // burst. Reject until an idle bucket can be reclaimed.
            return false
        }
        b = ipBucket{tokens: float64(burst), updated: now}
    } else {
        if elapsed := now.Sub(b.updated).Seconds(); elapsed > 0 {
            b.tokens += elapsed * float64(rate) / 60
            if b.tokens > float64(burst) { b.tokens = float64(burst) }
        }
    }
    // Record the accounting instant, including denied attempts, to avoid
    // double-counting refill time. Rejected attempts do not consume tokens.
    b.updated = now
    if b.tokens < 1 { l.buckets[ip] = b; return false }
    b.tokens--
    l.buckets[ip] = b
    return true
}

// allowConnectionRate applies the session's immutable configuration snapshot.
// Exceptions never bypass the separate Risk Engine.
func (l *ipRateLimiter) allowConnectionRate(cfg *Config, ip string, now time.Time) bool {
    if cfg.Security.Mode != ModeDefender || !cfg.Security.RateLimit.Enabled {
        return true
    }
    policy := cfg.Security.RateLimit
    if allowedSource(ip, policy.ExceptCIDRs) {
        return true
    }
    return l.allow(ip, policy.PerMinute, policy.Burst, now)
}
