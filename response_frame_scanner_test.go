package main

import (
    "strings"
    "testing"
)

func TestResponseFrameScannerFragmentation(t *testing.T) {
    stream := "* OK greeting\r\nA NO denied\r\nB BAD rejected\r\n"
    for _, size := range []int{1,2,3,7,4096} {
        var s responseFrameScanner
        var outcomes []string
        for i:=0;i<len(stream);i+=size {
            end:=i+size
            if end>len(stream) {end=len(stream)}
            for _,f:=range s.feed([]byte(stream[i:end])) {
                if f.IsCandidate {outcomes=append(outcomes,f.Candidate.Tag+":"+f.Candidate.Outcome)}
            }
        }
        if strings.Join(outcomes,",")!="A:NO,B:BAD" || s.disabled {
            t.Fatalf("chunk=%d outcomes=%v disabled=%v",size,outcomes,s.disabled)
        }
    }
}

func TestResponseFrameScannerLiteralCannotForgeResponse(t *testing.T) {
    // The apparent tagged response inside FETCH literal must not be classified.
    stream:="* 1 FETCH (BODY[] {13}\r\nA NO forged\r\n)\r\nB NO real\r\n"
    for _,size:=range []int{1,2,8,1024} {
        var s responseFrameScanner
        var got []string
        for i:=0;i<len(stream);i+=size {
            end:=i+size
            if end>len(stream){end=len(stream)}
            for _,f:=range s.feed([]byte(stream[i:end])) {
                if f.IsCandidate {got=append(got,f.Candidate.Tag)}
            }
        }
        if strings.Join(got,",")!="B" {t.Fatalf("size=%d tags=%v",size,got)}
    }
}

func TestResponseFrameScannerFailsOpen(t *testing.T) {
    for _,stream:=range []string{
        "A NO malformed\n",
        "* 1 FETCH (BODY[] {oops}\r\n",
        "* 1 FETCH (BODY[] {18446744073709551616}\r\n",
        strings.Repeat("x",maxPaceResponseLine+1),
    } {
        var s responseFrameScanner
        _=s.feed([]byte(stream))
        if !s.disabled {t.Fatalf("scanner accepted malformed input %q",stream[:min(len(stream),60)])}
        if len(s.feed([]byte("A NO forged\r\n")))!=0 {t.Fatal("scanner resumed after fail-open")}
    }
}

func TestResponseFrameScannerMinimalTaggedStatus(t *testing.T) {
    var s responseFrameScanner
    frames:=s.feed([]byte("A NO\r\n"))
    if len(frames)!=1 || !frames[0].IsCandidate {t.Fatalf("frames=%v",frames)}
}
