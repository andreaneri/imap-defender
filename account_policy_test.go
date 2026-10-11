package main

import (
    "testing"
    "time"
)

func TestEvaluateAccountRisk(t *testing.T) {
    p := defaultAccountPolicy()
    tests := []struct {
        name string
        signals accountSignals
        action accountAction
        delay time.Duration
    }{
        {"unknown", accountSignals{Known:false, GlobalFailures:100, CountryFailures:100, CountryValid:true}, accountAllow, 0},
        {"known below threshold", accountSignals{Known:true, GlobalFailures:2, CountryValid:true}, accountAllow, 0},
        {"soft pacing", accountSignals{Known:true, GlobalFailures:3, CountryValid:true}, accountPace, time.Second},
        {"hard pacing", accountSignals{Known:true, GlobalFailures:8, CountryValid:true}, accountPace, 8*time.Second},
        {"global failures insufficient locally", accountSignals{Known:true, GlobalFailures:100, CountryFailures:2, CountryValid:true}, accountPace, 8*time.Second},
        {"local failures insufficient globally", accountSignals{Known:true, GlobalFailures:19, CountryFailures:19, CountryValid:true}, accountPace, 8*time.Second},
        {"block candidate", accountSignals{Known:true, GlobalFailures:20, CountryFailures:12, CountryValid:true}, accountBlockCandidate, 0},
        {"unknown country", accountSignals{Known:true, GlobalFailures:100, CountryFailures:100, CountryValid:false}, accountPace, 8*time.Second},
        {"success not global allowlist", accountSignals{Known:true, OriginSucceeded:true, GlobalFailures:20, CountryFailures:12, CountryValid:true}, accountBlockCandidate, 0},
        {"invalid global", accountSignals{Known:true, GlobalFailures:-1, CountryValid:true}, accountAllow, 0},
    }
    for _, tt := range tests {
        t.Run(tt.name,func(t *testing.T) {
            got:=evaluateAccountRisk(tt.signals,p)
            if got.Action!=tt.action || got.Delay!=tt.delay {
                t.Fatalf("got action=%s delay=%s, want action=%s delay=%s",got.Action,got.Delay,tt.action,tt.delay)
            }
        })
    }
}

func TestAccountCountryIsolation(t *testing.T) {
    p:=defaultAccountPolicy()
    ru:=accountSignals{Known:true,GlobalFailures:30,CountryFailures:20,CountryValid:true}
    de:=accountSignals{Known:true,GlobalFailures:30,CountryFailures:0,CountryValid:true}
    if evaluateAccountRisk(ru,p).Action!=accountBlockCandidate {t.Fatal("RU should be candidate")}
    if evaluateAccountRisk(de,p).Action==accountBlockCandidate {t.Fatal("block leaked to DE")}
}

func BenchmarkEvaluateAccountRisk(b *testing.B) {
    p:=defaultAccountPolicy()
    s:=accountSignals{Known:true,GlobalFailures:10,CountryFailures:4,CountryValid:true}
    for i:=0;i<b.N;i++ { _=evaluateAccountRisk(s,p) }
}
