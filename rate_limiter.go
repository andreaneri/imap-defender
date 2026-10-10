package main

import (
    "net/netip"
    "sync"
    "time"
)

const maxRateLimitBuckets = 100000

// ipRateLimiter limits connections per source IP. JA4 is not an identity.
type ipRateLimiter struct {
    mu sync.Mutex
    buckets map[string]ipBucket
    lastCleanup time.Time
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
        if prefix.Masked().Contains(addr) { return true }
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
    idle := time.Duration(float64(burst) / float64(rate) * float64(time.Minute))
    if idle < time.Second { idle = time.Second }
    if l.lastCleanup.IsZero() || now.Sub(l.lastCleanup) >= time.Minute || len(l.buckets) >= maxRateLimitBuckets {
        for key, bucket := range l.buckets {
            if now.Sub(bucket.updated) >= idle { delete(l.buckets, key) }
        }
        l.lastCleanup = now
    }
    b, ok := l.buckets[ip]
    if !ok {
        if len(l.buckets) >= maxRateLimitBuckets {
            // Bounded-memory policy: evict the oldest bucket rather than
            // silently disabling enforcement for newly observed IPs.
            var oldestKey string
            var oldest time.Time
            for key, candidate := range l.buckets {
                if oldestKey == "" || candidate.updated.Before(oldest) {
                    oldestKey, oldest = key, candidate.updated
                }
            }
            delete(l.buckets, oldestKey)
        }
        b = ipBucket{tokens: float64(burst), updated: now}
    } else {
        if elapsed := now.Sub(b.updated).Seconds(); elapsed > 0 {
            b.tokens += elapsed * float64(rate) / 60
            if b.tokens > float64(burst) { b.tokens = float64(burst) }
        }
    }
    b.updated = now
    if b.tokens < 1 { l.buckets[ip] = b; return false }
    b.tokens--
    l.buckets[ip] = b
    return true
}
