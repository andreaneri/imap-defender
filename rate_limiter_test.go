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
