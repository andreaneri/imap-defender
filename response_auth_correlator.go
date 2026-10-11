package main

// authResponseCorrelator is an inert, bounded tag registry for a future
// protocol-aware response gate. A caller may register a tag only after a
// complete LOGIN or AUTHENTICATE command has been safely parsed. It must
// never infer authentication from a response tag alone.
//
// This registry intentionally does not retain credentials, account names,
// or complete command lines. It is not connected to the relay.
type authResponseCorrelator struct {
    pending map[string]string
    disabled bool
}

type correlatedAuthFailure struct {
    Tag string
    Method string
    Outcome string
}

func (c *authResponseCorrelator) register(tag, method string) bool {
    if c.disabled || !validObservedTag(tag) ||
        (method != "LOGIN" && method != "AUTHENTICATE") {
        return false
    }
    if c.pending == nil {
        c.pending = make(map[string]string)
    }
    if _, exists := c.pending[tag]; exists || len(c.pending) >= maxPendingAuth {
        c.disable()
        return false
    }
    c.pending[tag] = method
    return true
}

// complete consumes the tag for any authoritative tagged completion,
// including OK. Only NO/BAD yields a failure candidate. The caller must
// separately prove that the response was not inside a literal, that the
// command was forwarded intact, and that its identity is known.
func (c *authResponseCorrelator) complete(tag, outcome string) (correlatedAuthFailure, bool) {
    if c.disabled { return correlatedAuthFailure{}, false }
    method, exists := c.pending[tag]
    if !exists { return correlatedAuthFailure{}, false }
    if outcome != "OK" && outcome != "NO" && outcome != "BAD" {
        c.disable()
        return correlatedAuthFailure{}, false
    }
    delete(c.pending, tag)
    if outcome == "OK" { return correlatedAuthFailure{}, false }
    return correlatedAuthFailure{Tag: tag, Method: method, Outcome: outcome}, true
}

func (c *authResponseCorrelator) disable() {
    c.disabled = true
    c.pending = nil
}
