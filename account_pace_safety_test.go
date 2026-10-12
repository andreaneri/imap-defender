package main

import (
    "testing"
    "time"
)

func TestEffectiveFailurePace(t *testing.T) {
    cases := []struct {
        name string
        decision accountDecision
        outcome string
        max time.Duration
        want time.Duration
    }{
        {"allow", accountDecision{Action:accountAllow}, "NO", 2*time.Second, 0},
        {"success", accountDecision{Action:accountPace, Delay:time.Second}, "OK", 2*time.Second, 0},
        {"indeterminate", accountDecision{Action:accountPace, Delay:time.Second}, "INDETERMINATE", 2*time.Second, 0},
        {"normal", accountDecision{Action:accountPace, Delay:time.Second}, "BAD", 2*time.Second, time.Second},
        {"capped", accountDecision{Action:accountPace, Delay:8*time.Second}, "NO", 2*time.Second, 2*time.Second},
        {"disabled", accountDecision{Action:accountPace, Delay:time.Second}, "NO", 0, 0},
        {"negative", accountDecision{Action:accountPace, Delay:-time.Second}, "NO", 2*time.Second, 0},
        {"block candidate remains inert", accountDecision{Action:accountBlockCandidate}, "NO", 2*time.Second, 0},
    }
    for _, tc := range cases {
        t.Run(tc.name,func(t *testing.T) {
            if got:=effectiveFailurePace(tc.decision,tc.outcome,tc.max);got!=tc.want {
                t.Fatalf("got %v, want %v",got,tc.want)
            }
        })
    }
}
