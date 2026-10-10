package main

import (
	"errors"
	"io"
	"net"
	"strings"
	"sync"
)

// authResult contains no credentials or user identifiers.
type authResult struct {
	Method  string
	Outcome string
}

type authObserver struct {
	mu       sync.Mutex
	pending  map[string]string
	callback func(authResult)
	client   lineObserver
	server   lineObserver
	disabled bool
	saslTag  string
}

// Only the tag and verb are retained. Arguments, literal bodies and SASL
// payloads are never copied into observer-owned buffers.
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
}

const maxObservedTag = 128
const maxPendingAuth = 64

func newAuthObserver(callback func(authResult)) *authObserver {
	return &authObserver{pending: make(map[string]string), callback: callback}
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
	for tag, method := range o.pending {
		delete(o.pending, tag)
		o.callback(authResult{Method: method, Outcome: "INDETERMINATE"})
	}
	o.saslTag = ""
}

func (o *authObserver) finish() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.finishLocked()
	o.client = lineObserver{}
	o.server = lineObserver{}
	o.disabled = true
}

func (o *authObserver) observe(fromClient bool, chunk []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.disabled {
		return
	}
	state := &o.server
	if fromClient {
		state = &o.client
	}
	for _, b := range chunk {
		if state.literal > 0 {
			state.literal--
			continue
		}
		if b == '\n' {
			if !state.cr || state.quoted {
				o.disableLocked()
				return
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
			*state = lineObserver{literal: literal, continuation: continued}
			continue
		}
		if state.cr {
			o.disableLocked()
			return
		}
		state.inLine = true
		if b == '\r' {
			state.cr = true
			continue
		}
		// Suppress prefix capture for literal continuations and SASL responses.
		if !state.continuation && !(fromClient && o.saslTag != "") && state.field < 2 {
			if b == ' ' {
				if len(state.tokens[state.field]) == 0 {
					o.disableLocked()
					return
				}
				state.field++
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

func validObservedTag(tag string) bool {
	if tag == "" || tag == "*" || tag == "+" {
		return false
	}
	for _, b := range []byte(tag) {
		if b <= 0x20 || b >= 0x7f || strings.ContainsRune("(){}%*\\\"+]", rune(b)) {
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
		o.pending[tag] = verb
		if verb == "AUTHENTICATE" {
			o.saslTag = tag
		}
		return
	}
	method, found := o.pending[tag]
	if !found || (verb != "OK" && verb != "NO" && verb != "BAD") {
		return
	}
	delete(o.pending, tag)
	saslPartial := o.saslTag == tag && o.client.inLine
	if o.saslTag == tag {
		o.saslTag = ""
	}

	o.callback(authResult{Method: method, Outcome: verb})
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
	defer obs.finish()
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
