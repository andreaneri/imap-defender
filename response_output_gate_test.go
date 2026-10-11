package main

import (
    "bytes"
    "errors"
    "io"
    "strings"
    "testing"
)

func TestResponseOutputGateFragmentedByteIntegrity(t *testing.T) {
    input:=[]byte("* OK ready\r\nA NO denied\r\n* 1 FETCH (BODY[] {13}\r\nA NO forged\r\n)\r\nB OK done\r\n")
    for _,size:=range []int{1,2,3,7,256} {
        var dst bytes.Buffer
        gate:=newResponseOutputGate(&dst)
        for i:=0;i<len(input);i+=size {
            end:=i+size;if end>len(input){end=len(input)}
            n,err:=gate.Write(input[i:end])
            if err!=nil || n!=end-i {t.Fatalf("size=%d n=%d err=%v",size,n,err)}
        }
        if err:=gate.Flush();err!=nil {t.Fatal(err)}
        if !bytes.Equal(dst.Bytes(),input) {t.Fatalf("size=%d output changed",size)}
    }
}

func TestResponseOutputGateOverflowFailsOpen(t *testing.T) {
    input:=[]byte(strings.Repeat("x",maxPaceResponseLine+128)+"\r\nA NO denied\r\n")
    var dst bytes.Buffer
    gate:=newResponseOutputGate(&dst)
    for i:=0;i<len(input);i+=100 {
        end:=i+100;if end>len(input){end=len(input)}
        if _,err:=gate.Write(input[i:end]);err!=nil {t.Fatal(err)}
    }
    if !gate.passthrough {t.Fatal("oversized line should disable framing")}
    if err:=gate.Flush();err!=nil {t.Fatal(err)}
    if !bytes.Equal(dst.Bytes(),input) {t.Fatal("overflow lost bytes")}
}

func TestResponseOutputGateFlushesUnterminated(t *testing.T) {
    var dst bytes.Buffer
    gate:=newResponseOutputGate(&dst)
    gate.Write([]byte("partial"))
    if dst.Len()!=0 {t.Fatal("partial line emitted early")}
    if err:=gate.Flush();err!=nil {t.Fatal(err)}
    if dst.String()!="partial" {t.Fatal("flush lost bytes")}
}

type brokenOutputWriter struct{}
func (brokenOutputWriter) Write([]byte)(int,error) {return 0,errors.New("broken")}
func TestResponseOutputGateWriteFailure(t *testing.T) {
    gate:=newResponseOutputGate(brokenOutputWriter{})
    if _,err:=gate.Write([]byte("A NO denied\r\n"));err==nil {t.Fatal("write error hidden")}
    if _,err:=gate.Write([]byte("B OK\r\n"));!errors.Is(err,io.ErrClosedPipe){t.Fatalf("got %v",err)}
}

func TestResponseOutputGateDoesNotRetainConsumedBytes(t *testing.T) {
    var dst bytes.Buffer
    gate:=newResponseOutputGate(&dst)
    // A completed line and a partial line in the same write require
    // compaction without retaining the completed response in spare capacity.
    if _,err:=gate.Write([]byte("A NO denied\\r\\npartial"));err!=nil {t.Fatal(err)}
    if dst.String()!="A NO denied\\r\\n" {t.Fatalf("unexpected output %q",dst.String())}
    if string(gate.pending)!="partial" {t.Fatalf("pending=%q",gate.pending)}
    for _,b:=range gate.pending[len(gate.pending):cap(gate.pending)] {
        if b!=0 {t.Fatal("consumed bytes retained in backing buffer")}
    }
    if err:=gate.Flush();err!=nil {t.Fatal(err)}
    if dst.String()!="A NO denied\\r\\npartial" {t.Fatal("flush changed byte order")}
}

func TestResponseOutputGateCompletedLinesAreImmediate(t *testing.T) {
    var dst bytes.Buffer
    gate:=newResponseOutputGate(&dst)
    if _,err:=gate.Write([]byte("* OK greeting\\r\\n"));err!=nil {t.Fatal(err)}
    if dst.String()!="* OK greeting\\r\\n" {t.Fatal("completed greeting withheld")}
    if _,err:=gate.Write([]byte("+ Ready for literal\\r\\n"));err!=nil {t.Fatal(err)}
    if dst.String()!="* OK greeting\\r\\n+ Ready for literal\\r\\n" {t.Fatal("continuation withheld")}
}
