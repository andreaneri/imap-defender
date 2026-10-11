package main

import (
    "bytes"
    "context"
    "errors"
    "io"
    "time"
)

// responsePaceCandidate is a conservative framing primitive, not a relay.
// It recognizes only a single complete, CRLF-terminated tagged NO/BAD line.
// It never stores or parses authentication secrets. Tag correlation and
// authentication method verification remain the responsibility of a future
// protocol-aware gate; this primitive alone MUST NOT enable enforcement.
type responsePaceCandidate struct {
    Tag string
    Outcome string
    Raw []byte
}

const maxPaceResponseLine = 16 * 1024

// classifyTaggedFailure accepts only one physical response line with a
// printable IMAP tag, an exact status atom, and no embedded line endings.
// All unsupported frames fail open, without attempting to reinterpret them.
func classifyTaggedFailure(line []byte) (responsePaceCandidate, bool) {
    if len(line) < 7 || len(line) > maxPaceResponseLine ||
        !bytes.HasSuffix(line, []byte("\r\n")) {
        return responsePaceCandidate{}, false
    }
    body := line[:len(line)-2]
    if bytes.IndexAny(body, "\r\n\x00") >= 0 {
        return responsePaceCandidate{}, false
    }
    first := bytes.IndexByte(body, ' ')
    if first < 1 || first > maxObservedTag {
        return responsePaceCandidate{}, false
    }
    tag := string(body[:first])
    if !validObservedTag(tag) { return responsePaceCandidate{}, false }
    tail := body[first+1:]
    second := bytes.IndexByte(tail, ' ')
    status := tail
    if second >= 0 { status = tail[:second] }
    if !bytes.Equal(status, []byte("NO")) && !bytes.Equal(status, []byte("BAD")) {
        return responsePaceCandidate{}, false
    }
    // This helper deliberately returns an owned copy for use after read
    // buffers are reused. Callers must still correlate tag and command.
    return responsePaceCandidate{Tag: tag, Outcome: string(status), Raw: bytes.Clone(line)}, true
}

// waitResponsePace is independently cancellable and does not hold the
// observer mutex. It must only be invoked after a future safe correlation
// stage has confirmed an authoritative authentication failure.
func waitResponsePace(ctx context.Context, delay time.Duration) error {
    if delay <= 0 { return nil }
    timer := time.NewTimer(delay)
    defer timer.Stop()
    select {
    case <-ctx.Done(): return ctx.Err()
    case <-timer.C: return nil
    }
}

// writeUnchanged is a short-write-safe forwarding helper. It must not
// retry a write that reported an error.
func writeUnchanged(dst io.Writer, data []byte) error {
    for len(data) != 0 {
        n, err := dst.Write(data)
        if n < 0 || n > len(data) { return errors.New("invalid write count") }
        data = data[n:]
        if err != nil { return err }
        if n == 0 { return io.ErrShortWrite }
    }
    return nil
}
