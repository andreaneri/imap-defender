package main

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
)

// authResult contains account identities and backend outcomes, never secrets.
type authResult struct {
	Method          string
	Outcome         string
	Username        string
	UsernameKnown   bool
	AuthorizationID string
	Mechanism       string
}

type authObserver struct {
	captured    []authResult
	capturing   bool
	callbackMu  sync.Mutex
	mu          sync.Mutex
	pending     map[string]*authIdentity
	callback    func(authResult)
	client      lineObserver
	server      lineObserver
	disabled    bool
	saslTag     string
	current     *authIdentity
	gateEnabled bool
	gateUnsafe  bool
	activeTags  map[string]struct{}
}

// Framing retains only tag and verb. A separate bounded extractor captures
// account identities; literal bodies and SASL payloads are not buffered.
type lineObserver struct {
	tokens          [2][]byte
	field           int
	literal         uint64
	continuation    bool
	quoted, escaped bool
	marker          int
	length          uint64
	digits          bool
	cr              bool
	inLine          bool
	registered      bool
}

const maxObservedTag = 128
const maxPendingAuth = 64

func newAuthObserver(callback func(authResult)) *authObserver {
	return &authObserver{pending: make(map[string]*authIdentity), callback: callback}
}

// disableLocked stops classification when framing or correlation is ambiguous.
// Forwarding is independent and continues unchanged.
func (o *authObserver) disableLocked() {
	o.disabled = true
	o.finishLocked()
	o.client = lineObserver{}
	o.server = lineObserver{}
}

func (o *authObserver) finishLocked() {
	for tag, identity := range o.pending {
		delete(o.pending, tag)
		o.emitLocked(identity.result("INDETERMINATE"))
	}
	o.saslTag = ""
	o.current = nil
}

func (o *authObserver) finish() {
	o.mu.Lock()
	o.capturing = true
	o.finishLocked()
	o.client = lineObserver{}
	o.server = lineObserver{}
	o.disabled = true
	o.capturing = false
	results := o.captured
	o.captured = nil
	o.mu.Unlock()
	o.dispatch(results)
}

func (o *authObserver) dispatch(results []authResult) {
	o.callbackMu.Lock()
	defer o.callbackMu.Unlock()
	for _, result := range results {
		o.callback(result)
	}
}

func (o *authObserver) observe(fromClient bool, chunk []byte) {
	results := o.capture(fromClient, chunk)
	o.dispatch(results)
}

// capture separates framing from persistence and policy. No I/O or timers run
// under the observer mutex; the gate reads history before publishing this event.
func (o *authObserver) capture(fromClient bool, chunk []byte) []authResult {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.capturing = true
	o.observeLocked(fromClient, chunk)
	o.capturing = false
	results := o.captured
	o.captured = nil
	return results
}

func (o *authObserver) emitLocked(r authResult) {
	if o.capturing {
		o.captured = append(o.captured, r)
	} else {
		o.callback(r)
	}
}

func (o *authObserver) observeLocked(fromClient bool, chunk []byte) {
	if o.disabled {
		return
	}
	state := &o.server
	if fromClient {
		state = &o.client
	}
	for _, b := range chunk {
		if o.gateEnabled && state.literal == 0 && (b == 0 || b < 0x20 && b != '\r' && b != '\n') {
			o.gateUnsafe = true
		}
		if state.literal > 0 {
			state.literal--
			if fromClient && o.current != nil {
				o.current.literalByte(b, state.literal)
			}
			continue
		}
		if b == '\n' {
			if !state.cr || state.quoted {
				o.disableLocked()
				return
			}
			if fromClient && o.current != nil {
				o.current.endLine(state.marker == 3 && state.digits, state.length)
			}
			if !state.continuation && !(fromClient && o.saslTag != "") {
				o.observeHeader(fromClient, state.tokens)
				if o.disabled {
					return
				}
			}
			literal := uint64(0)
			continued := false
			if state.marker == 3 && state.digits {
				literal, continued = state.length, true
			} else if state.marker != 0 {
				o.disableLocked()
				return
			}
			if fromClient && !continued && o.saslTag == "" {
				o.current = nil
			}
			*state = lineObserver{literal: literal, continuation: continued}
			continue
		}
		if state.cr {
			o.disableLocked()
			return
		}
		if fromClient && !state.inLine && o.saslTag != "" && b == '*' && o.current != nil {
			o.current.invalid = true // SASL cancellation cannot authorize pacing.
		}
		state.inLine = true
		if b == '\r' {
			state.cr = true
			continue
		}
		wasHeader := !state.continuation && o.saslTag == "" && state.field < 2
		// Suppress prefix capture for literal continuations and SASL responses.
		if !state.continuation && !(fromClient && o.saslTag != "") && state.field < 2 {
			if b == ' ' {
				if len(state.tokens[state.field]) == 0 {
					o.disableLocked()
					return
				}
				state.field++
				if fromClient && state.field == 2 {
					o.startAuth(state.tokens)
					state.registered = true
					if o.disabled {
						return
					}
				}
				if !fromClient && string(state.tokens[0]) == "+" {
					state.field = 2
				}
			} else {
				limit := maxObservedTag
				if state.field == 1 {
					limit = 16
				}
				if len(state.tokens[state.field]) >= limit {
					o.disableLocked()
					return
				}
				state.tokens[state.field] = append(state.tokens[state.field], b)
			}
		}
		if fromClient && !wasHeader && o.current != nil {
			o.current.consume(b)
		}
		if (fromClient && o.saslTag != "") || (!fromClient && state.field == 2 && string(state.tokens[0]) == "+") {
			continue
		}
		// Recognize a trailing literal marker outside quoted strings, without
		// retaining the surrounding arguments. Supports {n}, {n+} and ~{n}.
		if state.quoted {
			if state.escaped {
				state.escaped = false
			} else if b == '\\' {
				state.escaped = true
			} else if b == '"' {
				state.quoted = false
			}
			continue
		}
		if !fromClient && b == '"' {
			o.gateUnsafe = true
		}
		if fromClient && b == '"' {
			state.quoted = true
			state.marker = 0
			continue
		}
		if b == '{' {
			state.marker = 1
			state.length = 0
			state.digits = false
			continue
		}
		switch state.marker {
		case 1:
			if b >= '0' && b <= '9' {
				digit := uint64(b - '0')
				if state.length > (^uint64(0)-digit)/10 {
					o.disableLocked()
					return
				}
				state.length = state.length*10 + digit
				state.digits = true
			} else if b == '+' && state.digits {
				state.marker = 2
			} else if b == '}' && state.digits {
				state.marker = 3
			} else {
				state.marker = 0
			}
		case 2:
			if b == '}' {
				state.marker = 3
			} else {
				state.marker = 0
			}
		case 3:
			state.marker = 0
		}
	}
}

func (o *authObserver) startAuth(tokens [2][]byte) {
	o.current = nil
	tag := string(tokens[0])
	verb := strings.ToUpper(string(tokens[1]))
	if !validObservedTag(tag) {
		if o.gateEnabled {
			o.gateUnsafe = true
		}
		return
	}
	if o.gateEnabled {
		if o.activeTags == nil {
			o.activeTags = make(map[string]struct{})
		}
		if _, duplicate := o.activeTags[tag]; duplicate || len(o.activeTags) >= maxPendingAuth {
			o.gateUnsafe = true
		}
		if !o.gateUnsafe {
			o.activeTags[tag] = struct{}{}
		}
		if verb == "COMPRESS" || verb == "STARTTLS" {
			o.gateUnsafe = true
		}
	}
	if _, exists := o.pending[tag]; exists {
		o.disableLocked()
		return
	}
	if verb != "LOGIN" && verb != "AUTHENTICATE" {
		return
	}
	if len(o.pending) >= maxPendingAuth {
		o.disableLocked()
		return
	}
	o.current = &authIdentity{method: verb}
	o.pending[tag] = o.current
}

func validObservedTag(tag string) bool {
	if tag == "" || tag == "*" || tag == "+" {
		return false
	}
	for _, b := range []byte(tag) {
		if b <= 0x20 || b >= 0x7f || strings.ContainsRune("(){%*\\\"+", rune(b)) {
			return false
		}
	}
	return true
}

func (o *authObserver) observeHeader(fromClient bool, tokens [2][]byte) {
	tag := string(tokens[0])
	verb := strings.ToUpper(string(tokens[1]))
	if !fromClient && tag == "*" && verb == "BYE" {
		o.disableLocked()
		return
	}
	if !validObservedTag(tag) {
		return
	}
	if fromClient {
		if !o.client.registered {
			o.startAuth(tokens)
		}
		if verb == "AUTHENTICATE" {
			if o.current != nil && !strings.EqualFold(string(o.current.mechanism), "PLAIN") && !strings.EqualFold(string(o.current.mechanism), "LOGIN") {
				o.gateUnsafe = true
			}
			o.saslTag = tag
		}
		return
	}

	if o.gateEnabled && (verb == "OK" || verb == "NO" || verb == "BAD") {
		if _, found := o.activeTags[tag]; !found {
			o.gateUnsafe = true
		}
		delete(o.activeTags, tag)
	}
	identity, found := o.pending[tag]
	if !found || (verb != "OK" && verb != "NO" && verb != "BAD") {
		return
	}
	delete(o.pending, tag)
	if o.current == identity {
		o.current = nil
	}
	saslPartial := o.saslTag == tag && o.client.inLine
	if o.saslTag == tag {
		o.saslTag = ""
	}

	o.emitLocked(identity.result(verb))
	if saslPartial || o.client.literal > 0 || o.client.continuation {
		o.disableLocked()
	}
}

type observingWriter struct {
	target net.Conn
	obs    *authObserver
	client bool
}

func (w observingWriter) Write(p []byte) (int, error) {
	// Observe before publishing bytes so an immediate backend reply cannot
	// overtake registration of its client tag. Write failures finish pending
	// attempts as indeterminate when the relay ends.
	w.obs.observe(w.client, p)
	return w.target.Write(p)
}

// relayObserved forwards bytes unchanged. The observer cannot fail the relay.
func relayObserved(client, backend net.Conn, obs *authObserver) error {
	return relayObservedContext(context.Background(), client, backend, obs)
}

func relayObservedContext(ctx context.Context, client, backend net.Conn, obs *authObserver) error {
	defer obs.finish()
	stop := context.AfterFunc(ctx, func() { _ = client.Close(); _ = backend.Close() })
	defer stop()
	errs := make(chan error, 2)
	copyOne := func(dst, src net.Conn, fromClient bool) {
		_, err := io.Copy(observingWriter{target: dst, obs: obs, client: fromClient}, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		errs <- err
	}
	go copyOne(backend, client, true)
	go copyOne(client, backend, false)
	first := <-errs
	if first != nil {
		_ = client.Close()
		_ = backend.Close()
	}
	second := <-errs
	return errors.Join(first, second)
}
