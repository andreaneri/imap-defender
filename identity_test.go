package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"reflect"
	"strings"
	"testing"
)

func TestObservedUsernames(t *testing.T) {
	plain := base64.StdEncoding.EncodeToString([]byte("delegated@example.it\x00alice@example.it\x00PASSWORD-SENTINEL"))
	user := base64.StdEncoding.EncodeToString([]byte("alice@example.it"))
	cases := []struct {
		name, request, username, authzid, mechanism string
		known                                       bool
	}{
		{"atom", "A LOGIN alice@example.it PASSWORD-SENTINEL\r\n", "alice@example.it", "", "", true},
		{"tilde atom", "A LOGIN ~alice PASSWORD-SENTINEL\r\n", "~alice", "", "", true},
		{"quoted escapes", "A LOGIN \"a\\\"b\\\\c\" \"PASSWORD-SENTINEL\"\r\n", "a\"b\\c", "", "", true},
		{"UTF8 literal", "A LOGIN {5+}\r\nmári PASSWORD-SENTINEL\r\n", "mári", "", "", true},
		{"two literals", "A LOGIN {5}\r\nalice {17+}\r\nPASSWORD-SENTINEL\r\n", "alice", "", "", true},
		{"PLAIN initial", "A AUTHENTICATE PLAIN " + plain + "\r\n", "alice@example.it", "delegated@example.it", "PLAIN", true},
		{"PLAIN continuation", "A AUTHENTICATE PLAIN\r\n" + plain + "\r\n", "alice@example.it", "delegated@example.it", "PLAIN", true},
		{"SASL LOGIN initial", "A AUTHENTICATE LOGIN " + user + "\r\n" + base64.StdEncoding.EncodeToString([]byte("PASSWORD-SENTINEL")) + "\r\n", "alice@example.it", "", "LOGIN", true},
		{"SASL LOGIN continuation", "A AUTHENTICATE LOGIN\r\n" + user + "\r\n" + base64.StdEncoding.EncodeToString([]byte("PASSWORD-SENTINEL")) + "\r\n", "alice@example.it", "", "LOGIN", true},
		{"unsupported", "A AUTHENTICATE SCRAM-SHA-256 SECRET-TOKEN\r\n", "", "", "SCRAM-SHA-256", false},
		{"invalid Base64", "A AUTHENTICATE PLAIN " + plain + "!\r\n", "", "", "PLAIN", false},
		{"cancelled", "A AUTHENTICATE PLAIN\r\n*\r\n", "", "", "PLAIN", false},
		{"empty IR", "A AUTHENTICATE PLAIN =\r\n", "", "", "PLAIN", false},
		{"overlong account", "A LOGIN " + strings.Repeat("u", maxObservedIdentity+1) + " PASSWORD-SENTINEL\r\n", "", "", "", false},
		{"binary username", "A LOGIN ~{3+}\r\na\x00b PASSWORD-SENTINEL\r\n", "", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, chunkSize := range []int{1, 2, 3, 7, 4096} {
				var got []authResult
				o := newAuthObserver(func(r authResult) { got = append(got, r) })
				request := []byte(tc.request)
				for len(request) > 0 {
					n := min(chunkSize, len(request))
					o.observe(true, request[:n])
					request = request[n:]
				}
				o.observe(false, []byte("A NO rejected by backend\r\n"))
				o.finish()
				want := authResult{Method: "LOGIN", Outcome: "NO", Username: tc.username, UsernameKnown: tc.known, AuthorizationID: tc.authzid, Mechanism: tc.mechanism}
				if tc.mechanism != "" {
					want.Method = "AUTHENTICATE"
				}
				if !reflect.DeepEqual(got, []authResult{want}) {
					t.Fatalf("chunk %d: got %+v want %+v", chunkSize, got, want)
				}
			}
		})
	}
}

func TestPlainIdentityStructuralValidation(t *testing.T) {
	for _, payload := range []string{"", "\x00user\x00", "\x00\x00password", "\x00u\x00p", "other\x00u\x00p", "\x00" + strings.Repeat("u", maxObservedIdentity+1) + "\x00p", "\x00bad\nname\x00p"} {
		encoded := base64.StdEncoding.EncodeToString([]byte(payload))
		var p plainIdentity
		for _, b := range []byte(encoded) {
			p.consume(b)
		}
		p.finish()
		want := payload == "\x00u\x00p" || payload == "other\x00u\x00p"
		if p.known != want {
			t.Fatalf("known=%v for structural case len=%d", p.known, len(payload))
		}
	}
}

func TestUsernamesStayCorrelatedByTag(t *testing.T) {
	var got []authResult
	o := newAuthObserver(func(r authResult) { got = append(got, r) })
	o.observe(true, []byte("A LOGIN alice password-a\r\nB LOGIN bob password-b\r\n"))
	o.observe(false, []byte("B OK bob accepted\r\nA NO alice rejected\r\n"))
	o.observe(true, []byte("C LOGIN charlie password-c\r\n"))
	o.finish()
	want := []authResult{
		{Method: "LOGIN", Outcome: "OK", Username: "bob", UsernameKnown: true},
		{Method: "LOGIN", Outcome: "NO", Username: "alice", UsernameKnown: true},
		{Method: "LOGIN", Outcome: "INDETERMINATE", Username: "charlie", UsernameKnown: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
}

func TestNoPasswordInIdentityStorageOrEvent(t *testing.T) {
	for _, request := range []string{
		"A LOGIN alice PASSWORD-SENTINEL\r\n",
		"A AUTHENTICATE PLAIN " + base64.StdEncoding.EncodeToString([]byte("\x00alice\x00PASSWORD-SENTINEL")) + "\r\n",
		"A AUTHENTICATE LOGIN\r\n" + base64.StdEncoding.EncodeToString([]byte("alice")) + "\r\n" + base64.StdEncoding.EncodeToString([]byte("PASSWORD-SENTINEL")) + "\r\n",
	} {
		var output bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&output, nil))
		o := newAuthObserver(func(r authResult) { logAuthEvent(logger, newAuthEvent(r, "192.0.2.1", "IT", "test-ja4")) })
		o.observe(true, []byte(request))
		identity := o.pending["A"]
		for _, stored := range [][]byte{identity.name, identity.mechanism, identity.plain.authcid, identity.plain.authzid, o.client.tokens[0], o.client.tokens[1]} {
			if bytes.Contains(stored, []byte("PASSWORD-SENTINEL")) || bytes.Contains(stored, []byte(base64.StdEncoding.EncodeToString([]byte("PASSWORD-SENTINEL")))) {
				t.Fatal("secret retained")
			}
		}
		if identity.method == "AUTHENTICATE" && string(identity.mechanism) == "PLAIN" && (identity.plain.acc != 0 || identity.plain.bits != 0) {
			t.Fatal("password decoder bits retained")
		}
		o.observe(false, []byte("A OK authenticated\r\n"))
		o.finish()
		if strings.Contains(output.String(), "PASSWORD-SENTINEL") {
			t.Fatal("secret logged")
		}
		var event map[string]any
		if err := json.Unmarshal(output.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		for field, want := range map[string]any{"remote_ip": "192.0.2.1", "country_code": "IT", "ja4": "test-ja4", "username": "alice", "username_known": true, "outcome": "OK"} {
			if event[field] != want {
				t.Fatalf("field %s=%v want %v", field, event[field], want)
			}
		}
		if event["observed_at"] == nil {
			t.Fatal("missing timestamp")
		}
	}
}

func TestAccountLimitsAndIncompleteInputs(t *testing.T) {
	inputs := []struct {
		request string
		known   bool
	}{
		{"A LOGIN " + strings.Repeat("u", maxObservedIdentity) + " password\r\n", true},
		{"A LOGIN {1025+}\r\n" + strings.Repeat("u", 1025) + " password\r\n", false},
		{"A LOGIN {10}\r\npartial", false},
		{"A AUTHENTICATE PLAIN\r\n" + base64.StdEncoding.EncodeToString([]byte("\x00u\x00"+strings.Repeat("p", maxObservedSASLResponse))), false},
		{"A LOGIN \"unfinished", false},
	}
	for _, tc := range inputs {
		var got []authResult
		o := newAuthObserver(func(r authResult) { got = append(got, r) })
		o.observe(true, []byte(tc.request))
		o.finish()
		if len(got) != 1 || got[0].Outcome != "INDETERMINATE" || got[0].UsernameKnown != tc.known {
			t.Fatalf("unexpected bounded/incomplete result: %+v", got)
		}
	}
}

func TestAuthEventUsesHostAddress(t *testing.T) {
	for source, want := range map[string]string{"192.0.2.1:1234": "192.0.2.1", "[2001:db8::1]:5678": "2001:db8::1", "192.0.2.1": "192.0.2.1"} {
		event := newAuthEvent(authResult{}, source, "ZZ", "ja4")
		if event.RemoteIP != want {
			t.Fatalf("IP=%q want %q", event.RemoteIP, want)
		}
	}
}

func BenchmarkPlainAuthIdentity(b *testing.B) {
	payload := []byte(base64.StdEncoding.EncodeToString([]byte("\x00alice@example.it\x00benchmark-password")))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var p plainIdentity
		for _, c := range payload {
			p.consume(c)
		}
		p.finish()
	}
}
