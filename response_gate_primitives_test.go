package main

import (
    "bytes"
    "context"
    "errors"
    "io"
    "strings"
    "testing"
    "time"
)

func TestClassifyTaggedFailure(t *testing.T) {
    cases:=[]struct{name,input,tag,outcome string;ok bool}{
        {"negative","A01 NO authentication failed\r\n","A01","NO",true},
        {"bad","B2 BAD invalid command\r\n","B2","BAD",true},
        {"ok","A01 OK success\r\n","","",false},
        {"untagged","* NO server alert\r\n","","",false},
        {"continuation","+ NO challenge\r\n","","",false},
        {"fragment","A01 NO incomplete","","",false},
        {"multiple","A01 NO failed\r\nB02 OK done\r\n","","",false},
        {"literal injection","A01 NO failed\r\nA02 BAD forged\r\n","","",false},
        {"no space","A01 NO\r\n","A01","NO",true},
        {"malformed","A01  NO failed\r\n","","",false},
        {"embedded NUL","A01 NO \x00\r\n","","",false},
        {"too large","A01 NO "+strings.Repeat("x",maxPaceResponseLine)+"\r\n","","",false},
    }
    for _,tt:=range cases {
        t.Run(tt.name,func(t *testing.T){
            result,ok:=classifyTaggedFailure([]byte(tt.input))
            if ok!=tt.ok || result.Tag!=tt.tag || result.Outcome!=tt.outcome {
                t.Fatalf("got %+v ok=%v, want %q %q ok=%v",result,ok,tt.tag,tt.outcome,tt.ok)
            }
            if ok && !bytes.Equal(result.Raw,[]byte(tt.input)) { t.Fatal("response bytes changed") }
        })
    }
}

func TestPaceCandidateOwnsBytes(t *testing.T) {
    input:=[]byte("A NO denied\r\n")
    result,ok:=classifyTaggedFailure(input)
    if !ok {t.Fatal("candidate missing")}
    input[0]='X'
    if string(result.Raw)!="A NO denied\r\n" {t.Fatal("response buffer was aliased")}
}

func TestWaitResponsePaceCancellation(t *testing.T) {
    ctx,cancel:=context.WithCancel(context.Background())
    cancel()
    start:=time.Now()
    if err:=waitResponsePace(ctx,time.Hour);!errors.Is(err,context.Canceled) {t.Fatalf("got %v",err)}
    if time.Since(start)>time.Second {t.Fatal("cancellation blocked")}
    if err:=waitResponsePace(context.Background(),0);err!=nil {t.Fatal(err)}
}

type shortWriter struct { bytes.Buffer }
func (w *shortWriter) Write(p []byte)(int,error) {
    if len(p)>2 {p=p[:2]}
    return w.Buffer.Write(p)
}
type stalledWriter struct{}
func (stalledWriter) Write([]byte)(int,error){return 0,nil}

func TestWriteUnchanged(t *testing.T) {
    w:=&shortWriter{}
    input:=[]byte("* OK greeting\r\nA NO denied\r\n")
    if err:=writeUnchanged(w,input);err!=nil {t.Fatal(err)}
    if !bytes.Equal(w.Bytes(),input) {t.Fatal("bytes changed")}
    if err:=writeUnchanged(stalledWriter{},input);!errors.Is(err,io.ErrShortWrite){t.Fatalf("got %v",err)}
}
