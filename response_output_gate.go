package main

import (
    "bytes"
    "io"
)

// responseOutputGate is an inert, bounded server-to-client framing writer.
// It buffers at most one physical line to exercise chunk-independent
// forwarding. It NEVER paces, classifies authentication or changes bytes.
// The live relay is not connected to this component.
type responseOutputGate struct {
    dst io.Writer
    pending []byte
    passthrough bool
    closed bool
}

func newResponseOutputGate(dst io.Writer) *responseOutputGate {
    return &responseOutputGate{dst: dst}
}

// Write consumes input only when its bytes were either forwarded or retained
// in the bounded buffer. If forwarding fails, the gate becomes unusable.
// Call Flush on EOF to forward any unterminated bytes unchanged.
func (g *responseOutputGate) Write(p []byte) (int, error) {
    if g.closed { return 0, io.ErrClosedPipe }
    if g.passthrough {
        if err:=writeUnchanged(g.dst,p);err!=nil {g.closed=true;return 0,err}
        return len(p),nil
    }
    consumed:=0
    for len(p)>0 {
        if len(g.pending)==0 {
            if end:=bytes.Index(p,[]byte("\r\n"));end<0 && len(p)>maxPaceResponseLine {
                g.passthrough=true
                if err:=writeUnchanged(g.dst,p);err!=nil {g.closed=true;return consumed,err}
                return consumed+len(p),nil
            }
        }
        capacity:=maxPaceResponseLine-len(g.pending)
        if capacity==0 {
            if err:=g.flushPending();err!=nil {g.closed=true;return consumed,err}
            g.passthrough=true
            if err:=writeUnchanged(g.dst,p);err!=nil {g.closed=true;return consumed,err}
            return consumed+len(p),nil
        }
        n:=len(p)
        if n>capacity {n=capacity}
        g.pending=append(g.pending,p[:n]...)
        consumed+=n
        p=p[n:]
        // Flush every complete physical line immediately. This deliberately
        // does not infer IMAP message boundaries or retain response literals.
        if end:=bytes.LastIndex(g.pending,[]byte("\r\n"));end>=0 {
            if err:=writeUnchanged(g.dst,g.pending[:end+2]);err!=nil {g.closed=true;return consumed,err}
            remainder := len(g.pending)-end-2
            copy(g.pending,g.pending[end+2:])
            clear(g.pending[remainder:])
            g.pending=g.pending[:remainder]
        }
    }
    return consumed,nil
}

func (g *responseOutputGate) flushPending() error {
    if len(g.pending)==0 {return nil}
    err:=writeUnchanged(g.dst,g.pending)
    clear(g.pending)
    g.pending=nil
    return err
}

func (g *responseOutputGate) Flush() error {
    if g.closed {return io.ErrClosedPipe}
    if err:=g.flushPending();err!=nil {g.closed=true;return err}
    return nil
}
