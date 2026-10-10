package main

import (
 "testing"
 "time"
)
func TestIPRateLimiter(t *testing.T) {
 var l ipRateLimiter
 now := time.Unix(100, 0)
 if !l.allow("192.0.2.1", 60, 2, now) || !l.allow("192.0.2.1", 60, 2, now) { t.Fatal("initial burst denied") }
 if l.allow("192.0.2.1", 60, 2, now) { t.Fatal("burst exceeded") }
 if !l.allow("192.0.2.2", 60, 2, now) { t.Fatal("different IP affected") }
 if !l.allow("192.0.2.1", 60, 2, now.Add(time.Second)) { t.Fatal("token did not refill") }
 if l.allow("192.0.2.1", 60, 2, now.Add(time.Second)) { t.Fatal("extra token granted") }
 if !l.allow("192.0.2.1", 0, 0, now) { t.Fatal("disabled limiter denied") }
}
func TestRateLimitConfig(t *testing.T) {
 c := &Config{Server: ServerConfig{ListenAddr:":993", BackendIMAPAddr:"localhost:143", CertFile:"cert", KeyFile:"key"}, Security:SecurityConfig{Mode:ModeTransparent, Thresholds:ThresholdConfig{30,60,90}, RateLimit:RateLimitConfig{Enabled:true, PerMinute:60, Burst:2}}}
 if err:=validateConfig(c); err==nil { t.Fatal("transparent mode accepted rate-limit enforcement configuration") }
 c.Security.Mode=ModeDefender
 c.Redis=RedisConfig{Addr:"localhost:6379", QueueBufferSize:10}
 if err:=validateConfig(c); err!=nil { t.Fatal(err) }
 c.Security.RateLimit.Burst=0
 if err:=validateConfig(c); err==nil { t.Fatal("invalid burst accepted") }
}

func TestRateLimitExceptions(t *testing.T) {
    if !allowedSource("192.0.2.7", []string{"192.0.2.0/24"}) { t.Fatal("CIDR not matched") }
    if allowedSource("198.51.100.1", []string{"192.0.2.0/24"}) { t.Fatal("unrelated IP matched") }
    if !allowedSource("2001:db8::1", []string{"2001:db8::/32"}) { t.Fatal("IPv6 CIDR not matched") }
    if allowedSource("invalid", []string{"192.0.2.0/24"}) { t.Fatal("invalid address matched") }
}

func TestRateLimiterEvictsInactiveBuckets(t *testing.T) {
    var l ipRateLimiter
    now := time.Unix(1000, 0)
    if !l.allow("192.0.2.1", 60, 2, now) { t.Fatal("initial request denied") }
    if !l.allow("192.0.2.2", 60, 2, now.Add(2*time.Minute)) { t.Fatal("other IP denied") }
    l.mu.Lock()
    _, exists := l.buckets["192.0.2.1"]
    l.mu.Unlock()
    if exists { t.Fatal("inactive bucket not evicted") }
}

func BenchmarkIPRateLimiter(b *testing.B) {
    var l ipRateLimiter
    now := time.Unix(1000, 0)
    b.ResetTimer()
    for i:=0; i<b.N; i++ { l.allow("192.0.2.1", 600000, 100, now) }
}
