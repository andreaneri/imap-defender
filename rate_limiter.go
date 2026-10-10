package main

import (
 "sync"
 "time"
)

// ipRateLimiter limits connection attempts per source IP using a rolling
// token bucket. It never treats a shared TLS fingerprint as an identity.
type ipRateLimiter struct {
 mu sync.Mutex
 buckets map[string]ipBucket
}
type ipBucket struct { tokens float64; updated time.Time }
func (l *ipRateLimiter) allow(ip string, rate int, burst int, now time.Time) bool {
 if rate <= 0 || burst <= 0 || ip == "" { return true }
 l.mu.Lock()
 defer l.mu.Unlock()
 if l.buckets == nil { l.buckets = make(map[string]ipBucket) }
 b, ok := l.buckets[ip]
 if !ok {
   // Bound memory usage under source-address churn; fail open rather than
   // allowing unbounded growth or evicting active legitimate clients.
   if len(l.buckets) >= 100000 {
     for key, old := range l.buckets {
       if now.Sub(old.updated) > time.Duration(burst)*time.Minute {
         delete(l.buckets, key)
       }
     }
     if len(l.buckets) >= 100000 { return true }
   }
   b = ipBucket{tokens: float64(burst), updated: now}
 } else {
   elapsed := now.Sub(b.updated).Seconds()
   if elapsed > 0 {
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
