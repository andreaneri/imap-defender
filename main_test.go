package main

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestEvaluateRisk(t *testing.T) {
	cfg := SecurityConfig{
		Thresholds: ThresholdConfig{TarpitSoft: 30, TarpitHard: 60, Drop: 90},
		Weights: WeightConfig{JA4Unknown: 25, GeoAnomaly: 35},
	}
	cases := []struct {
		name string
		ctx ClientContext
		want string
	}{
		{"known domestic", ClientContext{JA4Known: true, CountryCode: "IT"}, "ALLOW"},
		{"unknown domestic", ClientContext{JA4Known: false, CountryCode: "IT"}, "ALLOW"},
		{"known foreign", ClientContext{JA4Known: true, CountryCode: "US"}, "TARPIT_SOFT"},
		{"unknown foreign", ClientContext{JA4Known: false, CountryCode: "US"}, "TARPIT_HARD"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := EvaluateRisk(&tc.ctx, cfg)
			if got != tc.want {
				t.Fatalf("action = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAuthObserver(t *testing.T) {
	var results []authResult
	o := newAuthObserver(func(r authResult) { results = append(results, r) })
	o.observe(false, []byte("* OK backend ready\r\n"))
	o.observe(true, []byte("A1 CAPABILITY\r\nA2 LOGIN \"test@example.org\" \"secret with spaces\"\r\n"))
	o.observe(false, []byte("* CAPABILITY IMAP4rev1\r\nA1 OK CAPABILITY completed\r\nA2 "))
	o.observe(false, []byte("NO Authentication failed\r\n"))
	o.observe(true, []byte("A3 AUTHENTICATE PLAIN\r\n"))
	o.observe(false, []byte("+ \r\n"))
	o.observe(true, []byte("dXNlcgBwYXNz\r\n"))
	o.observe(false, []byte("A3 OK authenticated\r\n"))
	o.observe(true, []byte("A4 LOGIN {4}\r\nuser {6}\r\nsecret\r\n"))
	o.observe(false, []byte("A4 BAD invalid literal\r\n"))
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3: %+v", len(results), results)
	}
	for i, want := range []authResult{{"LOGIN", "NO"}, {"AUTHENTICATE", "OK"}, {"LOGIN", "BAD"}} {
		if results[i] != want {
			t.Fatalf("result %d = %+v, want %+v", i, results[i], want)
		}
	}
}

func TestObservedRelayPreservesBytes(t *testing.T) {
	client, proxyClient := net.Pipe()
	proxyBackend, backend := net.Pipe()
	defer client.Close()
	defer backend.Close()
	results := make(chan authResult, 2)
	done := make(chan error, 1)
	go func() {
		done <- relayObserved(proxyClient, proxyBackend, newAuthObserver(func(r authResult) {
			results <- r
		}))
	}()
	backendScript := "* OK Dovecot ready\r\n"
	request := "A1 CAPABILITY\r\nA2 LOGIN ~{13+}\r\nX LOGIN\x00\r\nzzz \"secret with spaces\"\r\n"
	response := "* CAPABILITY IMAP4rev1\r\nA1 OK done\r\n* 1 FETCH (BODY[] {13}\r\nA2 OK bogus\r\n)\r\nA2 NO invalid password\r\n"
	go func() {
		defer backend.Close()
		_, _ = io.WriteString(backend, backendScript)
		buf := make([]byte, len(request))
		if _, err := io.ReadFull(backend, buf); err != nil {
			t.Errorf("backend read: %v", err)
			return
		}
		if string(buf) != request {
			t.Errorf("backend got %q", buf)
		}
		_, _ = io.WriteString(backend, response)
	}()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	greeting := make([]byte, len(backendScript))
	if _, err := io.ReadFull(client, greeting); err != nil { t.Fatal(err) }
	if string(greeting) != backendScript { t.Fatalf("greeting changed: %q", greeting) }
	if _, err := io.WriteString(client, request); err != nil { t.Fatal(err) }
	reply := make([]byte, len(response))
	if _, err := io.ReadFull(client, reply); err != nil { t.Fatal(err) }
	if !bytes.Equal(reply, []byte(response)) { t.Fatalf("response changed: %q", reply) }
	client.Close()
	select {
	case result := <-results:
		if result.Method != "LOGIN" || result.Outcome != "NO" { t.Fatalf("unexpected result: %+v", result) }
	case <-time.After(3 * time.Second): t.Fatal("missing authentication result")
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second): t.Fatal("relay did not stop")
	}
}

func BenchmarkEvaluateRisk(b *testing.B) {
	cfg := SecurityConfig{Thresholds: ThresholdConfig{TarpitSoft: 30, TarpitHard: 60, Drop: 90}, Weights: WeightConfig{JA4Unknown: 25, GeoAnomaly: 35}}
	ctx := ClientContext{JA4Known: false, CountryCode: "US"}
	for i := 0; i < b.N; i++ { _, _ = EvaluateRisk(&ctx, cfg) }
}

func BenchmarkAuthObserver(b *testing.B) {
	o := newAuthObserver(func(authResult) {})
	line := []byte("A1 LOGIN user password\r\n")
	for i := 0; i < b.N; i++ {
		o.observe(true, line)
		o.observe(false, []byte("A1 NO denied\r\n"))
	}
}
