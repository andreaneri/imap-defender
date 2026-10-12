package main

import (
    "bytes"
    "strconv"
)

// responseFrameScanner splits a server-to-client stream into complete physical
// lines, while skipping literal payloads. It is a bounded, inert component:
// it does not delay, consume or rewrite bytes in the active relay.
type responseFrameScanner struct {
    line []byte
    literal uint64
    continuation bool
    disabled bool
}

type responseFrame struct {
    Candidate responsePaceCandidate
    IsCandidate bool
}

// feed examines a chunk and returns complete line classifications. No output
// from this scanner is sufficient by itself to authorize response pacing.
// When framing is unsupported or ambiguous it permanently fails open.
func (s *responseFrameScanner) feed(chunk []byte) []responseFrame {
    if s.disabled { return nil }
    var frames []responseFrame
    for _, b := range chunk {
        if s.literal > 0 {
            s.literal--
            continue
        }
        if len(s.line) >= maxPaceResponseLine {
            s.disable()
            return nil
        }
        s.line = append(s.line, b)
        if b != '\n' { continue }
        if len(s.line) < 2 || s.line[len(s.line)-2] != '\r' {
            s.disable()
            return nil
        }
        // A line following a server literal may be a continuation of the
        // enclosing response, not a new tagged completion. Never classify it.
        candidate, ok := responsePaceCandidate{}, false
        if !s.continuation {
            candidate, ok = classifyTaggedFailure(s.line)
        }
        frames = append(frames, responseFrame{Candidate: candidate, IsCandidate: ok})
        literal, valid := trailingServerLiteral(s.line)
        if !valid {
            s.disable()
            return nil
        }
        s.literal = literal
        s.continuation = literal > 0
        // Clear the previous physical line before reusing the backing buffer.
        // Server responses may contain sensitive mailbox metadata.
        clear(s.line)
        s.line = s.line[:0]
    }
    return frames
}

func (s *responseFrameScanner) disable() {
    s.disabled = true
    s.literal = 0
    s.continuation = false
    clear(s.line)
    s.line = nil
}

// trailingServerLiteral recognizes a trailing {n} or ~{n} marker only.
// Any apparent marker with malformed numeric framing disables inspection.
// Literal bytes themselves are never retained.
func trailingServerLiteral(line []byte) (uint64, bool) {
    body := line[:len(line)-2]
    if len(body) == 0 || body[len(body)-1] != '}' { return 0, true }
    open := bytes.LastIndexByte(body, '{')
    if open < 0 { return 0, true }
    if open == 0 { return 0, false }
    prefix := body[open-1]
    if prefix != ' ' && prefix != '~' && prefix != '(' { return 0, true }
    digits := body[open+1:len(body)-1]
    if len(digits) == 0 { return 0, false }
    if digits[len(digits)-1] == '+' { digits = digits[:len(digits)-1] }
    if len(digits) == 0 { return 0, false }
    for _, b := range digits {
        if b < '0' || b > '9' { return 0, false }
    }
    n, err := strconv.ParseUint(string(digits), 10, 64)
    return n, err == nil
}
