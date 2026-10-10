package main

import (
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
)

func TestAuthObserverFraming(t *testing.T) {
	cases := []struct {
		name, client, server string
		want                 []authResult
	}{
		{"literal command injection", "A LOGIN {15+}\r\nX LOGIN a b\r\nzz {0}\r\n\r\n", "X OK fake\r\nA NO real\r\n", []authResult{{Method: "LOGIN", Outcome: "NO"}}},
		{"multiple literals", "A LOGIN {4}\r\nuser {6+}\r\nsecret\r\nB LOGIN u p\r\n", "A NO denied\r\nB OK done\r\n", []authResult{{Method: "LOGIN", Outcome: "NO"}, {Method: "LOGIN", Outcome: "OK"}}},
		{"binary literal", "A LOGIN ~{13+}\r\nX LOGIN\x00\r\nzzz p\r\n", "X OK fake\r\nA BAD rejected\r\n", []authResult{{Method: "LOGIN", Outcome: "BAD"}}},
		{"server literal injection", "A LOGIN u p\r\n", "* 1 FETCH (BODY[] {13}\r\nA OK forged\r\n)\r\nA NO real\r\n", []authResult{{Method: "LOGIN", Outcome: "NO"}}},
		{"quoted marker", "A LOGIN \"u\\\"{9}\" \"{123}\"\r\nB LOGIN u p\r\n", "A NO denied\r\nB OK done\r\n", []authResult{{Method: "LOGIN", Outcome: "NO"}, {Method: "LOGIN", Outcome: "OK"}}},
		{"long arguments", "A LOGIN u " + strings.Repeat("s", 100000) + "\r\n", "A NO denied\r\n", []authResult{{Method: "LOGIN", Outcome: "NO"}}},
		{"server response text quote", "A LOGIN u p\r\n", "A NO unmatched quote \"\r\n", []authResult{{Method: "LOGIN", Outcome: "NO"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, size := range []int{1, 2, 7, 4096} {
				var got []authResult
				o := newAuthObserver(func(r authResult) { got = append(got, withoutIdentity(r)) })
				for _, direction := range []struct {
					client bool
					input  string
				}{{true, tc.client}, {false, tc.server}} {
					p := []byte(direction.input)
					for len(p) > 0 {
						n := min(size, len(p))
						o.observe(direction.client, p[:n])
						p = p[n:]
					}
				}
				o.finish()
				if !reflect.DeepEqual(got, tc.want) {
					t.Fatalf("chunk %d: got %+v, want %+v", size, got, tc.want)
				}
			}
		})
	}
}

func TestAuthObserverSASL(t *testing.T) {
	var got []authResult
	o := newAuthObserver(func(r authResult) { got = append(got, withoutIdentity(r)) })
	o.observe(true, []byte("A AUTHENTICATE PLAIN initial-secret\r\n"))
	o.observe(false, []byte("+ cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\r\n"))
	o.observe(true, []byte("X LOGIN secret password\r\n*\r\n"))
	o.observe(false, []byte("X OK fake\r\nA NO cancelled\r\n"))
	o.observe(true, []byte("B LOGIN u p\r\n"))
	o.observe(false, []byte("B OK real\r\n"))
	o.finish()
	if want := []authResult{{Method: "AUTHENTICATE", Outcome: "NO"}, {Method: "LOGIN", Outcome: "OK"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
}

func TestAuthObserverIndeterminate(t *testing.T) {
	for _, input := range []string{
		"A LOGIN u p\r\nA LOGIN u p\r\n",
		"A LOGIN u p\r\n" + strings.Repeat("x", maxObservedTag+1) + " LOGIN u p\r\n",
		"A LOGIN u p\r\nB APPEND mailbox {18446744073709551616}\r\n",
		"A LOGIN u p\r\nB APPEND mailbox {12\r\n",
		"A LOGIN u p\r\nB NOOP\n",
		"A LOGIN {123}\r\npartial",
	} {
		var got []authResult
		o := newAuthObserver(func(r authResult) { got = append(got, withoutIdentity(r)) })
		o.observe(true, []byte(input))
		o.finish()
		o.finish()
		if !reflect.DeepEqual(got, []authResult{{Method: "LOGIN", Outcome: "INDETERMINATE"}}) {
			t.Fatalf("got %+v", got)
		}
	}
}

func TestAuthObserverPendingLimitAndBYE(t *testing.T) {
	count := 0
	o := newAuthObserver(func(r authResult) {
		if r.Outcome != "INDETERMINATE" {
			t.Fatal(r)
		}
		count++
	})
	for i := 0; i <= maxPendingAuth; i++ {
		o.observe(true, []byte(fmt.Sprintf("A%d LOGIN u p\r\n", i)))
	}
	if !o.disabled || len(o.pending) != 0 || count != maxPendingAuth {
		t.Fatalf("limit: disabled=%v pending=%d count=%d", o.disabled, len(o.pending), count)
	}
	o = newAuthObserver(func(r authResult) {
		if r.Outcome != "INDETERMINATE" {
			t.Fatal(r)
		}
		count++
	})
	o.observe(true, []byte("A LOGIN u p\r\n"))
	o.observe(false, []byte("* BYE closing\r\nA OK bogus\r\n"))
	o.finish()
	if count != maxPendingAuth+1 {
		t.Fatal(count)
	}
}

func TestAuthObserverDoesNotRetainArguments(t *testing.T) {
	o := newAuthObserver(func(authResult) {})
	o.observe(true, []byte("A LOGIN username SECRET"))
	if string(o.client.tokens[0]) != "A" || string(o.client.tokens[1]) != "LOGIN" {
		t.Fatal("unexpected retained header")
	}
	o.observe(true, []byte("\r\nB AUTHENTICATE PLAIN\r\nSECRET"))
	if len(o.client.tokens[0]) != 0 || len(o.client.tokens[1]) != 0 {
		t.Fatal("SASL payload retained")
	}
}

type immediateAuthReplyConn struct {
	net.Conn
	observer *authObserver
}

func (c immediateAuthReplyConn) Write(p []byte) (int, error) {
	c.observer.observe(false, []byte("A OK immediate\r\n"))
	return len(p), nil
}

func TestObserverRegistersBeforeBackendReply(t *testing.T) {
	var got []authResult
	o := newAuthObserver(func(r authResult) { got = append(got, withoutIdentity(r)) })
	w := observingWriter{target: immediateAuthReplyConn{observer: o}, obs: o, client: true}
	p := []byte("A LOGIN user secret\r\n")
	if n, err := w.Write(p); n != len(p) || err != nil {
		t.Fatalf("write: %d %v", n, err)
	}
	o.finish()
	if !reflect.DeepEqual(got, []authResult{{Method: "LOGIN", Outcome: "OK"}}) {
		t.Fatalf("got %+v", got)
	}
}

func TestAuthObserverEarlyLiteralRejection(t *testing.T) {
	var got []authResult
	o := newAuthObserver(func(r authResult) { got = append(got, withoutIdentity(r)) })
	o.observe(true, []byte("A LOGIN {100}\r\n"))
	o.observe(false, []byte("A NO rejected\r\n"))
	o.observe(true, []byte("X LOGIN forged password\r\n"))
	o.observe(false, []byte("X OK bogus\r\n"))
	o.finish()
	if !o.disabled || !reflect.DeepEqual(got, []authResult{{Method: "LOGIN", Outcome: "NO"}}) {
		t.Fatalf("got %+v", got)
	}
}

func withoutIdentity(r authResult) authResult {
	return authResult{Method: r.Method, Outcome: r.Outcome}
}
