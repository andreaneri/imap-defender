package main

import (
 "testing"
 "fmt"
 "math"
 "sync"
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

func TestRateLimiterConcurrent(t *testing.T) {
    var l ipRateLimiter
    now := time.Unix(100, 0)
    var wg sync.WaitGroup
    results := make(chan bool, 100)
    for i:=0;i<100;i++ {
        wg.Add(1)
        go func() { defer wg.Done(); results <- l.allow("192.0.2.10", 60, 10, now) }()
    }
    wg.Wait()
    close(results)
    accepted:=0
    for ok:=range results { if ok { accepted++ } }
    if accepted != 10 { t.Fatalf("accepted %d; want 10",accepted) }
}

func BenchmarkIPRateLimiterParallel(b *testing.B) {
    var l ipRateLimiter
    b.RunParallel(func(pb *testing.PB) {
        for pb.Next() { l.allow("192.0.2.1", 600000, 100, time.Now()) }
    })
}

func BenchmarkIPRateLimiterManyIPs(b *testing.B) {
    var l ipRateLimiter
    ips:=make([]string, 4096)
    for i:=range ips { ips[i]=fmt.Sprintf("198.51.%d.%d",i/256,i%256) }
    now:=time.Unix(1000,0)
    b.ResetTimer()
    for i:=0;i<b.N;i++ { l.allow(ips[i%len(ips)], 600000, 100, now) }
}

func TestRateLimitExceptionValidation(t *testing.T) {
    for _, prefix := range []string{"192.0.2.1/24", "not-a-cidr", "::ffff:192.0.2.1/128"} {
        c := &Config{
            Server: ServerConfig{ListenAddr: ":993", BackendIMAPAddr: "localhost:143", CertFile: "cert", KeyFile: "key"},
            Redis: RedisConfig{Addr: "localhost:6379", QueueBufferSize: 10},
            Security: SecurityConfig{Mode: ModeDefender, Thresholds: ThresholdConfig{30, 60, 90},
                RateLimit: RateLimitConfig{Enabled: true, PerMinute: 60, Burst: 10, ExceptCIDRs: []string{prefix}}},
        }
        if err := validateConfig(c); err == nil { t.Fatalf("accepted invalid prefix %q", prefix) }
    }
}
func TestRateLimiterFullRefill(t *testing.T) {
    var l ipRateLimiter
    start := time.Unix(1000, 0)
    for i:=0;i<3;i++ { if !l.allow("203.0.113.1", 60, 3, start) { t.Fatal("burst rejected") } }
    if l.allow("203.0.113.1", 60, 3, start) { t.Fatal("extra token") }
    for i:=0;i<3;i++ { if !l.allow("203.0.113.1", 60, 3, start.Add(time.Minute)) { t.Fatal("refill incomplete") } }
    if l.allow("203.0.113.1", 60, 3, start.Add(time.Minute)) { t.Fatal("over-refill") }
}

func TestRateLimiterCapacityDoesNotResetActiveQuotas(t *testing.T) {
    now := time.Unix(1000, 0)
    l := ipRateLimiter{buckets: make(map[string]ipBucket, maxRateLimitBuckets)}
    for i:=0;i<maxRateLimitBuckets;i++ {
        l.buckets[fmt.Sprintf("source-%d", i)] = ipBucket{tokens: 0, updated: now}
    }
    l.lastCleanup = now
    if l.allow("new-source", 60, 2, now) { t.Fatal("new source admitted at capacity") }
    if len(l.buckets) != maxRateLimitBuckets { t.Fatal("bucket capacity changed") }
    if l.allow("source-1", 60, 2, now) { t.Fatal("existing exhausted source gained tokens") }
    if !l.allow("new-source", 60, 2, now.Add(2*time.Minute)) {
        t.Fatal("idle cleanup did not free capacity")
    }
}

func TestRateLimitModeAndReloadSnapshot(t *testing.T) {
    now := time.Unix(1000, 0)
    var limiter ipRateLimiter
    old := modeConfig(ModeLearning)
    old.Security.RateLimit = RateLimitConfig{Enabled: true, PerMinute: 60, Burst: 1}
    // The mode gate must take precedence even if the flag is present.
    for i:=0;i<3;i++ {
        if !limiter.allowConnectionRate(old, "192.0.2.1", now) { t.Fatal("learning was limited") }
    }
    next := modeConfig(ModeDefender)
    next.Security.RateLimit = RateLimitConfig{Enabled: true, PerMinute: 60, Burst: 1}
    ac := &AtomicConfig{}
    ac.Store(old)
    ac.Store(next)
    if !limiter.allowConnectionRate(ac.Load(), "192.0.2.1", now) { t.Fatal("first Defender request denied") }
    if limiter.allowConnectionRate(ac.Load(), "192.0.2.1", now) { t.Fatal("Defender limit not enforced") }
    // New sessions pick up new exceptions, while an existing session's
    // configuration snapshot remains unchanged.
    withException := *next
    withException.Security.RateLimit.ExceptCIDRs = []string{"192.0.2.0/24"}
    ac.Store(&withException)
    if !limiter.allowConnectionRate(ac.Load(), "192.0.2.1", now) { t.Fatal("reload exception ignored") }
    if limiter.allowConnectionRate(next, "192.0.2.1", now) { t.Fatal("old snapshot unexpectedly changed") }
    disabled := *next
    disabled.Security.RateLimit.Enabled = false
    if !limiter.allowConnectionRate(&disabled, "192.0.2.1", now) { t.Fatal("disabled limiter enforced") }
    if !limiter.allowConnectionRate(modeConfig(ModeTransparent), "192.0.2.1", now) { t.Fatal("transparent was limited") }
}

func TestRateLimiterExtremeParameters(t *testing.T) {
    var l ipRateLimiter
    now := time.Unix(1000, 0)
    if !l.allow("192.0.2.1", 1, math.MaxInt, now) { t.Fatal("large burst denied") }
    if !l.allow("192.0.2.2", math.MaxInt, 1, now) { t.Fatal("large refill denied") }
    if l.allow("192.0.2.2", math.MaxInt, 1, now) { t.Fatal("burst exceeded") }
}

func TestRateLimiterCapacityCleanupThrottled(t *testing.T) {
    now := time.Unix(1000, 0)
    l := ipRateLimiter{buckets: make(map[string]ipBucket, maxRateLimitBuckets)}
    for i:=0; i<maxRateLimitBuckets; i++ {
        l.buckets[fmt.Sprintf("source-%d", i)] = ipBucket{tokens: 0, updated: now}
    }
    l.lastCleanup = now
    if l.allow("new-1", 60, 2, now) { t.Fatal("new IP admitted at capacity") }
    first := l.lastCapacityCleanup
    if first.IsZero() { t.Fatal("capacity cleanup not recorded") }
    if l.allow("new-2", 60, 2, now.Add(100*time.Millisecond)) { t.Fatal("new IP admitted") }
    if !l.lastCapacityCleanup.Equal(first) { t.Fatal("capacity cleanup repeated within throttle interval") }
    if l.allow("new-3", 60, 2, now.Add(2*time.Second)) { t.Fatal("new IP admitted") }
    if !l.lastCapacityCleanup.After(first) { t.Fatal("capacity cleanup did not resume") }
}
