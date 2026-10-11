package main

import "testing"

func TestAuthResponseCorrelator(t *testing.T) {
    var c authResponseCorrelator
    if !c.register("A1","LOGIN") || !c.register("A2","AUTHENTICATE") {t.Fatal("register failed")}
    if _,ok:=c.complete("X","NO");ok {t.Fatal("unregistered response matched")}
    if _,ok:=c.complete("A1","OK");ok {t.Fatal("successful authentication penalized")}
    if _,ok:=c.complete("A1","NO");ok {t.Fatal("replayed tag matched")}
    f,ok:=c.complete("A2","NO")
    if !ok || f.Tag!="A2" || f.Method!="AUTHENTICATE" || f.Outcome!="NO" {t.Fatalf("unexpected failure %+v %v",f,ok)}
    if _,ok:=c.complete("A2","BAD");ok {t.Fatal("duplicate completion matched")}
}

func TestAuthResponseCorrelatorAmbiguity(t *testing.T) {
    var c authResponseCorrelator
    if c.register("*","LOGIN") || c.register("A","NOOP") {t.Fatal("invalid registration")}
    if !c.register("A","LOGIN") {t.Fatal("valid registration failed")}
    if c.register("A","LOGIN") || !c.disabled {t.Fatal("duplicate tag must disable correlation")}
    if _,ok:=c.complete("A","NO");ok {t.Fatal("disabled registry matched")}
    if c.register("B","LOGIN") {t.Fatal("disabled registry resumed")}
}

func TestAuthResponseCorrelatorLimit(t *testing.T) {
    var c authResponseCorrelator
    for i:=0;i<maxPendingAuth;i++ {
        if !c.register("A"+string(rune('a'+i)),"LOGIN") {t.Fatalf("registration %d",i)}
    }
    if c.register("overflow","LOGIN") || !c.disabled {t.Fatal("limit not enforced")}
}

func TestAuthResponseCorrelatorBadOutcome(t *testing.T) {
    var c authResponseCorrelator
    c.register("A","LOGIN")
    if _,ok:=c.complete("A","INDETERMINATE");ok || !c.disabled {t.Fatal("ambiguous completion must fail open")}
}
