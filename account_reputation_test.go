package main

import (
    "context"
    "strings"
    "testing"
    "time"
    "github.com/redis/go-redis/v9"
)

type reputationCommand struct { name string; key string }
type reputationPipe struct {
    redis.Pipeliner
    commands []reputationCommand
}
func (p *reputationPipe) Set(_ context.Context, key string, _ interface{}, _ time.Duration) *redis.StatusCmd {
    p.commands=append(p.commands,reputationCommand{"set",key}); return nil
}
func (p *reputationPipe) HSet(_ context.Context, key string, _ ...interface{}) *redis.IntCmd {
    p.commands=append(p.commands,reputationCommand{"hset",key}); return nil
}
func (p *reputationPipe) Incr(_ context.Context, key string) *redis.IntCmd {
    p.commands=append(p.commands,reputationCommand{"incr",key}); return nil
}
func (p *reputationPipe) Expire(_ context.Context, key string, _ time.Duration) *redis.BoolCmd {
    p.commands=append(p.commands,reputationCommand{"expire",key}); return nil
}
func TestAccountReputationScopedCounters(t *testing.T) {
    base:=authEvent{authResult:authResult{UsernameKnown:true,Username:"alice",Outcome:"NO"},JA4:"fp",RemoteIP:"192.0.2.1",CountryCode:"IT",Timestamp:time.Unix(1000,0)}
    capture:=func(e authEvent) []reputationCommand {
        p:=&reputationPipe{}
        queueAccountReputation(context.Background(),p,e)
        return p.commands
    }
    count:=func(cmds []reputationCommand, name string) int {
        n:=0;for _,c:=range cmds {if c.name==name {n++};if strings.Contains(c.key,"alice") {t.Fatal("plaintext account in key")} };return n
    }
    if got:=count(capture(base),"incr");got!=2 {t.Fatalf("expected global and country counters, got %d",got)}
    other:=base;other.RemoteIP="198.51.100.2"
    first:=capture(base);second:=capture(other)
    if first[0].key!=second[0].key {t.Fatal("account key changed with IP")}
    other.CountryCode="DE"
    third:=capture(other)
    if first[3].key!=third[3].key {t.Fatal("global counter changed with country")}
    if first[5].key==third[5].key {t.Fatal("country counters not isolated")}
    other.CountryCode="ZZ"
    if got:=count(capture(other),"incr");got!=1 {t.Fatalf("unknown country created scoped counter: %d",got)}
    other.Outcome="OK"
    if got:=count(capture(other),"incr");got!=0 {t.Fatal("OK incremented failures")}
    other.UsernameKnown=false
    if got:=len(capture(other));got!=0 {t.Fatal("unknown identity stored")}
    other.UsernameKnown=true;other.Outcome="INDETERMINATE"
    if got:=len(capture(other));got!=0 {t.Fatal("indeterminate stored")}
}
func TestAccountReputationKeyUnambiguous(t *testing.T) {
    if accountReputationKey("origin","a:b","c")==accountReputationKey("origin","a","b:c") {t.Fatal("ambiguous key")}
    if accountReputationKey("origin","a","b")==accountReputationKey("failures","a","b") {t.Fatal("key namespaces collide")}
}
func TestValidCountryCode(t *testing.T) {
    for _,tt:=range []struct{value string;want bool}{{"IT",true},{"DE",true},{"ZZ",false},{"",false},{"it",false},{"ITA",false}} {
        if got:=validCountryCode(tt.value);got!=tt.want {t.Fatalf("%q: got %v",tt.value,got)}
    }
}
