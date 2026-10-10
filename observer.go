package main

import (
	"bytes"
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
}

type lineObserver struct {
	buffer   []byte
	overflow bool
}

const maxObservedLine = 8192

func newAuthObserver(callback func(authResult)) *authObserver {
	return &authObserver{pending: make(map[string]string), callback: callback}
}

// Write always succeeds: parsing failures must never affect forwarding.
func (o *authObserver) observe(fromClient bool, chunk []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	state := &o.server
	if fromClient {
		state = &o.client
	}
	for _, b := range chunk {
		if b == '\n' {
			if !state.overflow {
				line := bytes.TrimSuffix(state.buffer, []byte{'\r'})
				o.observeLine(fromClient, line)
			}
			state.buffer = state.buffer[:0]
			state.overflow = false
			continue
		}
		if !state.overflow {
			if len(state.buffer) >= maxObservedLine {
				state.buffer = state.buffer[:0]
				state.overflow = true
			} else {
				state.buffer = append(state.buffer, b)
			}
		}
	}
}

func (o *authObserver) observeLine(fromClient bool, line []byte) {
	// Inspect only the tag and verb, never parse or retain credential arguments.
	fields := bytes.Fields(line)
	if len(fields) < 2 {
		return
	}
	tag := string(fields[0])
	if fromClient {
		if len(o.pending) >= 64 {
			return
		}
		method := strings.ToUpper(string(fields[1]))
		if method == "LOGIN" || method == "AUTHENTICATE" {
			o.pending[tag] = method
		}
		return
	}
	method, found := o.pending[tag]
	if !found {
		return
	}
	status := strings.ToUpper(string(fields[1]))
	if status != "OK" && status != "NO" && status != "BAD" {
		return
	}
	delete(o.pending, tag)
	o.callback(authResult{Method: method, Outcome: status})
}

type observingWriter struct {
	target net.Conn
	obs    *authObserver
	client bool
}

func (w observingWriter) Write(p []byte) (int, error) {
	n, err := w.target.Write(p)
	if n > 0 {
		w.obs.observe(w.client, p[:n])
	}
	return n, err
}

// relayObserved forwards only bytes successfully written to the peer and
// observes those bytes after the write. The observer cannot fail the relay.
func relayObserved(client, backend net.Conn, obs *authObserver) error {
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
