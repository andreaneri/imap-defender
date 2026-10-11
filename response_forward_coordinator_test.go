package main

import (
    "sync"
    "testing"
)

func TestAuthForwardCoordinatorOrdered(t *testing.T) {
    var c authForwardCoordinator
    if !c.stage("A","LOGIN") || !c.stage("B","AUTHENTICATE") {t.Fatal("stage")}
    if _,ok:=c.commit("A");ok {t.Fatal("completion not received")}
    if f,ok:=c.complete("A","NO");!ok || f.Tag!="A" || f.Outcome!="NO" {t.Fatalf("failure: %+v %v",f,ok)}
    if _,ok:=c.commit("B");ok {t.Fatal("completion not received")}
    if _,ok:=c.complete("B","OK");ok {t.Fatal("successful auth penalized")}
    if _,ok:=c.complete("A","BAD");ok {t.Fatal("replay accepted")}
}

func TestAuthForwardCoordinatorResponseBeforeCommit(t *testing.T) {
    var c authForwardCoordinator
    if !c.stage("A","LOGIN") {t.Fatal("stage")}
    if _,ok:=c.complete("A","NO");ok {t.Fatal("uncommitted failure classified")}
    f,ok:=c.commit("A")
    if !ok || f.Tag!="A" || f.Outcome!="NO" {t.Fatalf("commit lost early response: %+v %v",f,ok)}
    if _,ok:=c.commit("A");ok {t.Fatal("duplicate commit")}
}

func TestAuthForwardCoordinatorAbort(t *testing.T) {
    var c authForwardCoordinator
    c.stage("A","LOGIN")
    c.complete("A","NO")
    c.abort()
    if _,ok:=c.commit("A");ok {t.Fatal("classified failed forward")}
    if c.stage("B","LOGIN") {t.Fatal("resumed after abort")}
}

func TestAuthForwardCoordinatorAmbiguity(t *testing.T) {
    var c authForwardCoordinator
    c.stage("A","LOGIN")
    if c.stage("A","LOGIN") || !c.disabled {t.Fatal("duplicate not rejected")}
    var d authForwardCoordinator
    d.stage("A","LOGIN")
    d.complete("A","NO")
    if _,ok:=d.complete("A","BAD");ok || !d.disabled {t.Fatal("duplicate completion not rejected")}
}

func TestAuthForwardCoordinatorConcurrentRace(t *testing.T) {
    for i:=0;i<100;i++ {
        var c authForwardCoordinator
        if !c.stage("A","LOGIN") {t.Fatal("stage")}
        var wg sync.WaitGroup
        wg.Add(2)
        var mu sync.Mutex
        classified:=0
        record:=func(_ correlatedAuthFailure,ok bool) {
            if ok {mu.Lock();classified++;mu.Unlock()}
        }
        go func(){defer wg.Done();record(c.commit("A"))}()
        go func(){defer wg.Done();record(c.complete("A","NO"))}()
        wg.Wait()
        if classified!=1 {t.Fatalf("race classified %d times",classified)}
    }
}
