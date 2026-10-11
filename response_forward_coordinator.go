package main

import "sync"

// authForwardCoordinator models the race between forwarding an IMAP command
// and observing its backend completion. It is intentionally NOT connected
// to the live relay. No bytes, usernames, passwords, or response bodies are
// retained; only tags, methods and completion status.
//
// A tag is staged before writing the command. A completion observed before
// the write returns is remembered but cannot be classified until commit.
// If the write fails or is partial, abort discards all staged state.
// Ambiguity disables correlation for the entire session (fail open).
type authForwardCoordinator struct {
    mu sync.Mutex
    pending map[string]*authForwardEntry
    disabled bool
}

type authForwardEntry struct {
    method string
    committed bool
    completed bool
    outcome string
}

func (c *authForwardCoordinator) stage(tag, method string) bool {
    c.mu.Lock()
    defer c.mu.Unlock()
    if c.disabled || !validObservedTag(tag) || (method != "LOGIN" && method != "AUTHENTICATE") {
        return false
    }
    if c.pending == nil { c.pending = make(map[string]*authForwardEntry) }
    if _, exists := c.pending[tag]; exists || len(c.pending) >= maxPendingAuth {
        c.disableLocked()
        return false
    }
    c.pending[tag] = &authForwardEntry{method:method}
    return true
}

// commit must only be called when the complete command has been forwarded.
// A response that raced the write is returned here, exactly once.
func (c *authForwardCoordinator) commit(tag string) (correlatedAuthFailure, bool) {
    c.mu.Lock()
    defer c.mu.Unlock()
    if c.disabled { return correlatedAuthFailure{}, false }
    entry, ok := c.pending[tag]
    if !ok || entry.committed { c.disableLocked(); return correlatedAuthFailure{}, false }
    entry.committed = true
    if !entry.completed { return correlatedAuthFailure{}, false }
    delete(c.pending, tag)
    return failureFromCompletion(tag, entry)
}

// complete must be called only for an unambiguously framed tagged
// completion. If the command write is still pending, defer classification.
func (c *authForwardCoordinator) complete(tag, outcome string) (correlatedAuthFailure, bool) {
    c.mu.Lock()
    defer c.mu.Unlock()
    if c.disabled { return correlatedAuthFailure{}, false }
    entry, ok := c.pending[tag]
    if !ok { return correlatedAuthFailure{}, false }
    if entry.completed || (outcome != "OK" && outcome != "NO" && outcome != "BAD") {
        c.disableLocked()
        return correlatedAuthFailure{}, false
    }
    entry.completed = true
    entry.outcome = outcome
    if !entry.committed { return correlatedAuthFailure{}, false }
    delete(c.pending, tag)
    return failureFromCompletion(tag, entry)
}

func failureFromCompletion(tag string, e *authForwardEntry) (correlatedAuthFailure, bool) {
    if e.outcome == "OK" { return correlatedAuthFailure{}, false }
    return correlatedAuthFailure{Tag:tag, Method:e.method, Outcome:e.outcome}, true
}

// abort invalidates the entire correlation state after a failed or partial
// forward; a different tag must never be classified using stale state.
func (c *authForwardCoordinator) abort() {
    c.mu.Lock()
    defer c.mu.Unlock()
    c.disableLocked()
}

func (c *authForwardCoordinator) disableLocked() {
    c.disabled = true
    c.pending = nil
}
