package main

import (
    "bytes"
    "io"
    "net"
    "strings"
    "testing"
    "time"
)

// This is a local bidirectional TCP simulation, not a Dovecot test.
// It exercises the inert output writer with real blocking socket writes.
func TestOutputGateBidirectionalPipe(t *testing.T) {
    client, proxyClient := net.Pipe()
    proxyBackend, backend := net.Pipe()
    defer client.Close()
    defer proxyClient.Close()
    defer proxyBackend.Close()
    defer backend.Close()

    done := make(chan error, 2)
    go func() {
        _, err := io.Copy(proxyBackend, proxyClient)
        done <- err
    }()
    go func() {
        gate := newResponseOutputGate(proxyClient)
        _, err := io.Copy(gate, proxyBackend)
        if flushErr := gate.Flush(); err == nil { err = flushErr }
        done <- err
    }()

    commands := []byte("A1 LOGIN alice secret\r\nA2 NOOP\r\n")
    responses := []byte("* OK IMAP ready\r\nA1 NO invalid credentials\r\nA2 OK done\r\n")

    if err := client.SetDeadline(time.Now().Add(3*time.Second)); err != nil { t.Fatal(err) }
    if err := backend.SetDeadline(time.Now().Add(3*time.Second)); err != nil { t.Fatal(err) }

    commandRead := make(chan []byte, 1)
    go func() {
        received := make([]byte, len(commands))
        _, err := io.ReadFull(backend, received)
        if err != nil { commandRead <- nil; return }
        commandRead <- received
    }()

    if _, err := client.Write(commands); err != nil { t.Fatal(err) }
    if got := <-commandRead; !bytes.Equal(got, commands) { t.Fatalf("commands changed: %q", got) }

    responseRead := make(chan []byte, 1)
    go func() {
        received := make([]byte, len(responses))
        _, err := io.ReadFull(client, received)
        if err != nil { responseRead <- nil; return }
        responseRead <- received
    }()
    for _, line := range strings.SplitAfter(string(responses), "\r\n") {
        if line == "" { continue }
        for i := 0; i < len(line); i += 3 {
            end := i+3
            if end > len(line) { end = len(line) }
            if _, err := backend.Write([]byte(line[i:end])); err != nil { t.Fatal(err) }
        }
    }
    if got := <-responseRead; !bytes.Equal(got, responses) { t.Fatalf("responses changed: %q", got) }

    // Closing both ends unblocks the relay goroutines.
    _ = client.Close()
    _ = backend.Close()
    _ = proxyClient.Close()
    _ = proxyBackend.Close()
    for i:=0; i<2; i++ {
        select {
        case <-done:
        case <-time.After(3*time.Second): t.Fatal("relay goroutine did not exit")
        }
    }
}

// A partial line remains buffered until its CRLF arrives. This documents
// the latency cost of line buffering and why the gate is not enabled.
func TestOutputGatePartialLineLatencyLimitation(t *testing.T) {
    var output bytes.Buffer
    gate := newResponseOutputGate(&output)
    if _, err := gate.Write([]byte("* OK partial")); err != nil { t.Fatal(err) }
    if output.Len() != 0 { t.Fatal("partial line unexpectedly forwarded") }
    if _, err := gate.Write([]byte("\r\n")); err != nil { t.Fatal(err) }
    if output.String() != "* OK partial\r\n" { t.Fatalf("got %q", output.String()) }
}
