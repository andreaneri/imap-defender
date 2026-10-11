package main

import (
    "testing"
    "time"
)

func TestJA4IPRateLimitScope(t *testing.T) {
    now := time.Unix(1000, 0)
    cfg := modeConfig(ModeDefender)
    cfg.Security.RateLimit = RateLimitConfig{Enabled: true, Scope: "ja4_ip", PerMinute: 60, Burst: 1}
    var limiter ipRateLimiter
    check := func(ip, ja4 string, want bool) {
        t.Helper()
        got := limiter.allowConnectionRateWithJA4(cfg, ip, ja4, now)
        if got != want { t.Fatalf("ip=%q ja4=%q got %v want %v", ip, ja4, got, want) }
    }
    check("192.0.2.1", "a", true)
    check("192.0.2.1", "a", false)
    check("192.0.2.1", "b", true)
    check("192.0.2.2", "a", true)
    check("192.0.2.1", "", true)
    check("192.0.2.1", "", false)
    check("192.0.2.1", "a", false)
}

func TestJA4IPRateLimitModesAndExceptions(t *testing.T) {
    now := time.Unix(1000, 0)
    cfg := modeConfig(ModeDefender)
    cfg.Security.RateLimit = RateLimitConfig{Enabled: true, Scope: "ja4_ip", PerMinute: 60, Burst: 1, ExceptCIDRs: []string{"192.0.2.0/24"}}
    var limiter ipRateLimiter
    for i:=0; i<3; i++ {
        if !limiter.allowConnectionRateWithJA4(cfg, "192.0.2.1", "a", now) { t.Fatal("CIDR exception denied") }
    }
    cfg.Security.Mode = ModeLearning
    for i:=0; i<3; i++ {
        if !limiter.allowConnectionRateWithJA4(cfg, "198.51.100.1", "a", now) { t.Fatal("Learning limited") }
    }
    cfg.Security.Mode = ModeDefender
    if !limiter.allowConnectionRateWithJA4(cfg, "198.51.100.1", "a", now) { t.Fatal("initial request denied") }
    if limiter.allowConnectionRateWithJA4(cfg, "198.51.100.1", "a", now) { t.Fatal("rate limit bypassed") }
}

func TestJA4IPRateLimitScopeValidation(t *testing.T) {
    cfg := modeConfig(ModeDefender)
    cfg.Security.RateLimit = RateLimitConfig{Enabled: true, Scope: "unknown", PerMinute: 60, Burst: 1}
    if err:=validateConfig(cfg); err==nil { t.Fatal("invalid scope accepted") }
    cfg.Security.RateLimit.Scope = "ja4_ip"
    if err:=validateConfig(cfg); err!=nil { t.Fatal(err) }
}
