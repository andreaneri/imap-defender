package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testPacingConfig() AccountPacingConfig {
	return AccountPacingConfig{Enabled: true, SoftDelay: 60 * time.Millisecond, HardDelay: 80 * time.Millisecond, MaxDelay: 100 * time.Millisecond, MaxConcurrent: 4}
}

func TestAccountPacingConfiguration(t *testing.T) {
	good := testPacingConfig()
	for _, c := range []AccountPacingConfig{{}, good} {
		if err := validateAccountPacing(c); err != nil {
			t.Fatal(err)
		}
	}
	for _, change := range []func(*AccountPacingConfig){
		func(c *AccountPacingConfig) { c.SoftFailures = -1 },
		func(c *AccountPacingConfig) { c.SoftFailures = 8; c.HardFailures = 3 },
		func(c *AccountPacingConfig) { c.SoftDelay = -1 },
		func(c *AccountPacingConfig) { c.MaxDelay = time.Millisecond },
		func(c *AccountPacingConfig) { c.MaxDelay = 9 * time.Second },
		func(c *AccountPacingConfig) { c.MaxConcurrent = 1025 },
	} {
		c := good
		change(&c)
		if validateAccountPacing(c) == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	for _, mode := range []OperatingMode{ModeTransparent, ModeLearning, ModeDefender} {
		cfg := modeConfig(mode)
		cfg.Redis = RedisConfig{"localhost:6379", 4}
		cfg.Security.AccountPacing = good
		if err := validateConfig(cfg); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAccountFailureDelay(t *testing.T) {
	c := testPacingConfig()
	for _, tc := range []struct {
		s    accountSignals
		want time.Duration
	}{
		{accountSignals{GlobalFailures: 100}, 0},
		{accountSignals{Known: true, OriginSucceeded: true}, 0},
		{accountSignals{Known: true}, c.SoftDelay},
		{accountSignals{Known: true, OriginSucceeded: true, GlobalFailures: 3}, c.SoftDelay},
		{accountSignals{Known: true, OriginSucceeded: true, GlobalFailures: 8}, c.HardDelay},
		// Country corroboration never activates blocks or bypasses repeated pacing.
		{accountSignals{Known: true, GlobalFailures: 100, CountryFailures: 100, CountryValid: true}, c.HardDelay},
		{accountSignals{Known: true, GlobalFailures: 100, CountryValid: false}, c.HardDelay},
		{accountSignals{Known: true, GlobalFailures: -1}, 0},
	} {
		if got := accountFailureDelay(tc.s, c); got != tc.want {
			t.Fatalf("%+v got %v want %v", tc.s, got, tc.want)
		}
	}
}

type gateHarness struct {
	dst      net.Conn
	reads    chan backendRead
	observer *authObserver
	gate     *accountResponsePacer
	state    *paceForwardState
	done     chan error
	cancel   context.CancelFunc
	events   chan authResult
}

func newGateHarness(t *testing.T, request string, lookup func(context.Context, authResult) (accountSignals, error)) *gateHarness {
	t.Helper()
	dst, writer := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	h := &gateHarness{dst: dst, reads: make(chan backendRead), state: &paceForwardState{activity: make(chan struct{}, 1)}, done: make(chan error, 1), cancel: cancel, events: make(chan authResult, 128)}
	h.observer = newAuthObserver(func(r authResult) { h.events <- r })
	h.observer.gateEnabled = true
	h.observer.observe(true, []byte(request))
	h.gate = &accountResponsePacer{config: testPacingConfig(), limiter: &accountPaceLimiter{}, metrics: &proxyMetrics{}, lookup: lookup}
	go func() {
		var lookups sync.WaitGroup
		err := copyAccountResponses(ctx, writer, h.observer, h.gate, h.state, h.reads, &lookups)
		cancel()
		writer.Close()
		lookups.Wait()
		h.done <- err
	}()
	t.Cleanup(func() {
		cancel()
		dst.Close()
		select {
		case <-h.done:
		case <-time.After(time.Second):
			t.Error("gate or lookup did not terminate")
		}
	})
	return h
}

func (h *gateHarness) send(t *testing.T, data string) {
	t.Helper()
	select {
	case h.reads <- backendRead{data: []byte(data)}:
	case <-time.After(time.Second):
		t.Fatal("gate blocked backend input")
	}
}
func (h *gateHarness) receive(t *testing.T, want string) {
	t.Helper()
	h.dst.SetReadDeadline(time.Now().Add(time.Second))
	got := make([]byte, len(want))
	if _, err := io.ReadFull(h.dst, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("bytes %q != %q", got, want)
	}
}

func knownFailures(_ context.Context, _ authResult) (accountSignals, error) {
	return accountSignals{Known: true, GlobalFailures: 9}, nil
}

func TestAccountGateFragmentationAndCompleteResponseDelay(t *testing.T) {
	for _, size := range []int{1, 2, 7, 4096} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			h := newGateHarness(t, "A LOGIN user secret\r\n", knownFailures)
			reply := "A NO [AUTHENTICATIONFAILED] original backend message\r\n"
			// No partial physical line is buffered; each prefix arrives before the
			// next fragment is sent, including a split CRLF.
			for off := 0; off < len(reply)-1; {
				n := min(size, len(reply)-1-off)
				part := reply[off : off+n]
				h.send(t, part)
				h.receive(t, part)
				off += n
			}
			started := time.Now()
			h.send(t, "\n")
			h.receive(t, "\n")
			if elapsed := time.Since(started); elapsed < 60*time.Millisecond || elapsed > 500*time.Millisecond {
				t.Fatalf("delay %s", elapsed)
			}
			select {
			case event := <-h.events:
				if event.Username != "user" || event.Outcome != "NO" {
					t.Fatal(event)
				}
			case <-time.After(time.Second):
				t.Fatal("missing outcome")
			}
		})
	}
}

func TestAccountGateNeverPacesSuccessUnknownOrAmbiguity(t *testing.T) {
	plain := base64.StdEncoding.EncodeToString([]byte("\x00user\x00secret"))
	login := base64.StdEncoding.EncodeToString([]byte("user"))
	for _, tc := range []struct {
		name, request, reply string
		signals              accountSignals
	}{
		{"OK", "A LOGIN user secret\r\n", "A OK authenticated\r\n", accountSignals{Known: true, GlobalFailures: 100}},
		{"unknown first NO", "A LOGIN user secret\r\n", "A NO original\r\n", accountSignals{}},
		{"unknown first OK", "A LOGIN user secret\r\n", "A OK original\r\n", accountSignals{}},
		{"unknown identity", "A AUTHENTICATE SCRAM-SHA-256 token\r\n", "A NO original\r\n", accountSignals{Known: true, GlobalFailures: 100}},
		{"cancelled PLAIN", "A AUTHENTICATE PLAIN\r\n" + plain + "\r\n*\r\n", "A BAD cancelled\r\n", accountSignals{Known: true, GlobalFailures: 100}},
		{"cancelled LOGIN", "A AUTHENTICATE LOGIN\r\n" + login + "\r\n*\r\n", "A NO cancelled\r\n", accountSignals{Known: true, GlobalFailures: 100}},
		{"duplicate tag", "A LOGIN user secret\r\nA NOOP\r\n", "A NO original\r\n", accountSignals{Known: true, GlobalFailures: 100}},
		{"pending pipeline", "A LOGIN user secret\r\nB NOOP\r\n", "A NO original\r\n", accountSignals{Known: true, GlobalFailures: 100}},
		{"compression", "C COMPRESS DEFLATE\r\nA LOGIN user secret\r\n", "C OK enabled\r\nA NO original\r\n", accountSignals{Known: true, GlobalFailures: 100}},
		{"literal injection", "A LOGIN user secret\r\n", "* 1 FETCH (BODY[] {13}\r\nA NO forged\r\n)\r\n", accountSignals{Known: true, GlobalFailures: 100}},
		{"zero literal continuation", "A LOGIN user secret\r\n", "* 1 FETCH (BODY[] {0}\r\nA NO forged\r\n", accountSignals{Known: true, GlobalFailures: 100}},
		{"quoted literal ambiguity", "A LOGIN user secret\r\n", "* OK \"{3}\"\r\nA NO original\r\n", accountSignals{Known: true, GlobalFailures: 100}},
		{"BYE", "A LOGIN user secret\r\n", "* BYE done\r\nA NO original\r\n", accountSignals{Known: true, GlobalFailures: 100}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newGateHarness(t, tc.request, func(context.Context, authResult) (accountSignals, error) { return tc.signals, nil })
			started := time.Now()
			h.send(t, tc.reply)
			h.receive(t, tc.reply)
			if time.Since(started) > 50*time.Millisecond {
				t.Fatal("unexpected deliberate delay")
			}
		})
	}
}

func TestAccountGateLOGINLiteralsAndSASL(t *testing.T) {
	plain := base64.StdEncoding.EncodeToString([]byte("delegated\x00user\x00secret"))
	for _, request := range []string{
		"A LOGIN {4+}\r\nuser {6+}\r\nsecret\r\n",
		"A LOGIN \"user\" \"secret\"\r\n",
		"A AUTHENTICATE PLAIN " + plain + "\r\n",
		"A AUTHENTICATE PLAIN\r\n" + plain + "\r\n",
		"A AUTHENTICATE LOGIN\r\ndXNlcg==\r\nc2VjcmV0\r\n",
	} {
		t.Run(request[:min(len(request), 30)], func(t *testing.T) {
			calls := make(chan authResult, 1)
			h := newGateHarness(t, request, func(_ context.Context, r authResult) (accountSignals, error) {
				calls <- r
				return knownFailures(context.Background(), r)
			})
			h.send(t, "A BAD authoritative\r\n")
			h.receive(t, "A BAD authoritative\r\n")
			select {
			case r := <-calls:
				if r.Username != "user" {
					t.Fatalf("identity %+v", r)
				}
			case <-time.After(time.Second):
				t.Fatal("literal/SASL not paced")
			}
		})
	}
}

func TestAccountGateReleasesForFollowingTraffic(t *testing.T) {
	for _, duringLookup := range []bool{false, true} {
		for _, direction := range []string{"server", "client", "EOF"} {
			t.Run(fmt.Sprintf("%s/lookup=%v", direction, duringLookup), func(t *testing.T) {
				entered := make(chan struct{})
				h := newGateHarness(t, "A LOGIN user secret\r\n", func(ctx context.Context, _ authResult) (accountSignals, error) {
					close(entered)
					if duringLookup {
						<-ctx.Done()
						return accountSignals{}, ctx.Err()
					}
					return accountSignals{Known: true, GlobalFailures: 9}, nil
				})
				h.send(t, "A NO original\r\n")
				h.receive(t, "A NO original\r")
				<-entered
				if !duringLookup {
					deadline := time.Now().Add(time.Second)
					for h.gate.metrics.accountPaceActive.Load() == 0 {
						if time.Now().After(deadline) {
							t.Fatal("timer not entered")
						}
						select {
						case <-time.After(time.Millisecond):
						case <-time.After(time.Second):
							t.Fatal("timer not entered")
						}
					}
				}
				started := time.Now()
				switch direction {
				case "server":
					go func() { h.reads <- backendRead{data: []byte("* OK unrelated\r\n")} }()
					h.receive(t, "\n* OK unrelated\r\n")
				case "client":
					h.state.activity <- struct{}{}
					h.receive(t, "\n")
				case "EOF":
					close(h.reads)
					h.receive(t, "\n")
				}
				if time.Since(started) > 50*time.Millisecond {
					t.Fatal("following traffic withheld")
				}
			})
		}
	}
}

func TestAccountGateLookupFailuresAndCapacity(t *testing.T) {
	for _, kind := range []string{"error", "timeout", "saturated", "partial write", "failed write"} {
		t.Run(kind, func(t *testing.T) {
			h := newGateHarness(t, "A LOGIN user secret\r\n", func(ctx context.Context, r authResult) (accountSignals, error) {
				if kind == "timeout" {
					<-ctx.Done()
					return accountSignals{}, ctx.Err()
				}
				return accountSignals{}, errors.New("unavailable")
			})
			switch kind {
			case "saturated":
				h.gate.limiter.active.Store(4)
			case "partial write":
				h.state.writing.Store(true)
			case "failed write":
				h.state.failed.Store(true)
			}
			started := time.Now()
			h.send(t, "A NO original\r\n")
			h.receive(t, "A NO original\r\n")
			limit := 50 * time.Millisecond
			if kind == "timeout" {
				limit = 350 * time.Millisecond
			}
			if time.Since(started) > limit {
				t.Fatal("failed open too late")
			}
		})
	}
}

func TestAccountGateBoundedLookupConcurrency(t *testing.T) {
	var maximum atomic.Int64
	var active atomic.Int64
	limiter := &accountPaceLimiter{}
	started := make(chan struct{}, 50)
	unblock := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			obs := newAuthObserver(func(authResult) {})
			obs.gateEnabled = true
			state := &paceForwardState{activity: make(chan struct{}, 1)}
			g := &accountResponsePacer{config: testPacingConfig(), limiter: limiter, lookup: func(ctx context.Context, r authResult) (accountSignals, error) {
				n := active.Add(1)
				defer active.Add(-1)
				for {
					m := maximum.Load()
					if n <= m || maximum.CompareAndSwap(m, n) {
						break
					}
				}
				started <- struct{}{}
				select {
				case <-unblock:
				case <-ctx.Done():
				}
				return accountSignals{}, nil
			}}
			var lookups sync.WaitGroup
			g.holdCompletion(context.Background(), authResult{UsernameKnown: true}, obs, state, make(chan backendRead), &lookups)
			lookups.Wait()
		}()
	}
	<-started
	close(unblock)
	wg.Wait()
	if maximum.Load() > 4 || limiter.active.Load() != 0 {
		t.Fatalf("peak %d remaining %d", maximum.Load(), limiter.active.Load())
	}
}

func TestPacedRelayLiveByteIntegrityAndCancellation(t *testing.T) {
	client, relayClient := net.Pipe()
	backend, relayBackend := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer client.Close()
	defer backend.Close()
	obs := newAuthObserver(func(authResult) {})
	gate := &accountResponsePacer{config: testPacingConfig(), limiter: &accountPaceLimiter{}, lookup: knownFailures}
	done := make(chan error, 1)
	go func() { done <- relayAccountPaced(ctx, relayClient, relayBackend, obs, gate) }()
	greeting := "* OK backend greeting\r\n"
	go io.WriteString(backend, greeting)
	client.SetDeadline(time.Now().Add(2 * time.Second))
	backend.SetDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, len(greeting))
	if _, err := io.ReadFull(client, got); err != nil || string(got) != greeting {
		t.Fatalf("greeting %q %v", got, err)
	}
	request := "A LOGIN {4+}\r\nuser {6+}\r\nsecret\r\n"
	sent := make(chan error, 1)
	go func() { _, err := io.WriteString(client, request); sent <- err }()
	got = make([]byte, len(request))
	if _, err := io.ReadFull(backend, got); err != nil || string(got) != request {
		t.Fatalf("request changed %q %v", got, err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	// Allow the command writer to publish its commit before this specific test
	// exercises pacing; the separate partial-write tests cover the racing path.
	time.Sleep(2 * time.Millisecond)
	reply := "A NO original\r\n"
	go io.WriteString(backend, reply)
	prefix := make([]byte, len(reply)-1)
	if _, err := io.ReadFull(client, prefix); err != nil || string(prefix) != reply[:len(reply)-1] {
		t.Fatal("prefix changed", err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("relay leaked on cancellation")
	}
}

func TestAccountGateParserMemoryAndSecrets(t *testing.T) {
	obs := newAuthObserver(func(authResult) {})
	obs.gateEnabled = true
	obs.observe(true, []byte("A LOGIN user "+strings.Repeat("PASSWORD-SENTINEL", 100000)+"\r\n"))
	if !obs.canPace() && len(obs.pending) != 1 {
		t.Fatal("unbounded password disrupted bounded identity")
	}
	for _, id := range obs.pending {
		if strings.Contains(fmt.Sprintf("%+v", id), "PASSWORD-SENTINEL") {
			t.Fatal("retained credentials")
		}
	}
	for i := 0; i < 1000; i++ {
		obs.observe(true, []byte(fmt.Sprintf("T%d NOOP\r\n", i)))
	}
	if len(obs.activeTags) > 64 || !obs.gateUnsafe {
		t.Fatal("command registry exceeded bound")
	}
}

func TestAccountGatePipelineBytesAndShortWrites(t *testing.T) {
	h := newGateHarness(t, "A LOGIN user secret\r\nB NOOP\r\n", knownFailures)
	stream := "* CAPABILITY IMAP4rev1\r\nA NO original\r\nB OK done\r\n"
	for _, b := range []byte(stream) {
		h.send(t, string(b))
		h.receive(t, string(b))
	}
	// All previous primitives remain covered; verify the production copier also
	// uses short-write-safe forwarding without attempting a retry after errors.
	obs := newAuthObserver(func(authResult) {})
	reads := make(chan backendRead, 1)
	reads <- backendRead{data: []byte(stream), err: io.EOF}
	close(reads)
	dst := &shortGateWriter{}
	var wg sync.WaitGroup
	if err := copyAccountResponses(context.Background(), dst, obs, h.gate, h.state, reads, &wg); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dst.Bytes(), []byte(stream)) {
		t.Fatal("short writes changed bytes")
	}
}

type shortGateWriter struct{ bytes.Buffer }

func (w *shortGateWriter) Write(p []byte) (int, error) { return w.Buffer.Write(p[:min(len(p), 2)]) }

func BenchmarkAccountGateStreaming(b *testing.B) {
	stream := []byte("* OK greeting\r\n* CAPABILITY IMAP4rev1\r\nA NO original\r\n")
	b.SetBytes(int64(len(stream)))
	for i := 0; i < b.N; i++ {
		obs := newAuthObserver(func(authResult) {})
		reads := make(chan backendRead, 1)
		reads <- backendRead{data: stream, err: io.EOF}
		close(reads)
		g := &accountResponsePacer{}
		state := &paceForwardState{}
		var wg sync.WaitGroup
		if err := copyAccountResponses(context.Background(), io.Discard, obs, g, state, reads, &wg); err != nil {
			b.Fatal(err)
		}
	}
}

func TestAccountGateIndeterminateFramingAndEOF(t *testing.T) {
	for _, stream := range []string{
		"A NO incomplete",
		"A NO bad newline\n",
		"A NO binary\x00text\r\n",
		"* 1 FETCH (BODY[] {18446744073709551616}\r\nA NO ambiguous\r\n",
		"* 1 FETCH (BODY[] {3}\r\nxyz {0}\r\nA NO forged\r\n",
		strings.Repeat("*", maxObservedTag+1) + " NO text\r\nA NO text\r\n",
	} {
		t.Run(fmt.Sprintf("len=%d", len(stream)), func(t *testing.T) {
			h := newGateHarness(t, "A LOGIN user secret\r\n", func(context.Context, authResult) (accountSignals, error) {
				t.Error("ambiguous stream consulted history")
				return accountSignals{}, nil
			})
			h.send(t, stream)
			h.receive(t, stream)
		})
	}
}

func TestAccountGateHistoryPrecedesCurrentTelemetry(t *testing.T) {
	var written atomic.Bool
	h := newGateHarness(t, "A LOGIN user secret\r\n", func(context.Context, authResult) (accountSignals, error) {
		if written.Load() {
			t.Error("current event was published before historical lookup")
		}
		return accountSignals{}, nil
	})
	h.observer.callback = func(authResult) { written.Store(true) } // before sending server data
	h.send(t, "A NO original\r\n")
	h.receive(t, "A NO original\r\n")
	deadline := time.Now().Add(time.Second)
	for !written.Load() {
		if time.Now().After(deadline) {
			t.Fatal("outcome lost")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestPacedRelayTCPHalfClosePreservesBackendResponse(t *testing.T) {
	pair := func() (*net.TCPConn, *net.TCPConn) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		accepted := make(chan *net.TCPConn, 1)
		go func() {
			conn, err := listener.Accept()
			if err == nil {
				accepted <- conn.(*net.TCPConn)
			}
		}()
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		return conn.(*net.TCPConn), <-accepted
	}
	client, relayClient := pair()
	backend, relayBackend := pair()
	defer client.Close()
	defer backend.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	gate := &accountResponsePacer{config: testPacingConfig(), limiter: &accountPaceLimiter{}, lookup: knownFailures}
	done := make(chan error, 1)
	go func() {
		done <- relayAccountPaced(ctx, relayClient, relayBackend, newAuthObserver(func(authResult) {}), gate)
	}()
	request := "A LOGIN user secret\r\n"
	if _, err := io.WriteString(client, request); err != nil {
		t.Fatal(err)
	}
	client.CloseWrite()
	commands, err := io.ReadAll(backend)
	if err != nil || string(commands) != request {
		t.Fatalf("half close commands %q %v", commands, err)
	}
	reply := "A NO final backend response\r\n"
	io.WriteString(backend, reply)
	backend.CloseWrite()
	responses, err := io.ReadAll(client)
	if err != nil || string(responses) != reply {
		t.Fatalf("half close response %q %v", responses, err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("half-close relay leaked")
	}
}

func TestAccountGateDestinationErrorPreservesAuthoritativeObservation(t *testing.T) {
	obs := newAuthObserver(func(r authResult) {
		if r.Outcome != "NO" {
			t.Fatalf("wrong backend outcome %+v", r)
		}
	})
	obs.gateEnabled = true
	obs.observe(true, []byte("A LOGIN user secret\r\n"))
	reads := make(chan backendRead, 1)
	reads <- backendRead{data: []byte("A NO original\r\n"), err: io.EOF}
	close(reads)
	dst := &errorGateWriter{}
	var wg sync.WaitGroup
	err := copyAccountResponses(context.Background(), dst, obs, &accountResponsePacer{}, &paceForwardState{}, reads, &wg)
	if !errors.Is(err, io.ErrClosedPipe) || dst.calls != 1 || dst.String() != "A N" {
		t.Fatalf("write retry or mutation: %q %d %v", dst.String(), dst.calls, err)
	}
	if len(obs.pending) != 0 {
		t.Fatal("authoritative completion not consumed")
	}
}

type errorGateWriter struct {
	bytes.Buffer
	calls int
}

func (w *errorGateWriter) Write(p []byte) (int, error) {
	w.calls++
	n, _ := w.Buffer.Write(p[:min(len(p), 3)])
	return n, io.ErrClosedPipe
}

func TestPacedClientWriterPartialFailureDisablesPacing(t *testing.T) {
	target, peer := net.Pipe()
	defer peer.Close()
	defer target.Close()
	failing := &partialBackendConn{Conn: target}
	state := &paceForwardState{activity: make(chan struct{}, 1)}
	obs := newAuthObserver(func(authResult) {})
	obs.gateEnabled = true
	n, err := (pacedClientWriter{failing, obs, state}).Write([]byte("A LOGIN user secret\r\n"))
	if n != 0 || !errors.Is(err, io.ErrClosedPipe) || failing.calls != 1 || failing.prefix.String() != "A LOG" {
		t.Fatalf("partial forwarding %d %v %q", n, err, failing.prefix.String())
	}
	reads := make(chan backendRead, 1)
	reads <- backendRead{data: []byte("A NO original\r\n")}
	close(reads)
	var got bytes.Buffer
	var wg sync.WaitGroup
	gate := &accountResponsePacer{config: testPacingConfig(), limiter: &accountPaceLimiter{}, lookup: func(context.Context, authResult) (accountSignals, error) {
		t.Error("partial command authorized lookup")
		return accountSignals{}, nil
	}}
	if err := copyAccountResponses(context.Background(), &got, obs, gate, state, reads, &wg); err != nil || got.String() != "A NO original\r\n" {
		t.Fatalf("response %q %v", got.String(), err)
	}
}

type partialBackendConn struct {
	net.Conn
	prefix bytes.Buffer
	calls  int
}

func (c *partialBackendConn) Write(p []byte) (int, error) {
	c.calls++
	n, _ := c.prefix.Write(p[:min(5, len(p))])
	return n, io.ErrClosedPipe
}

func TestAccountPacingYAMLAndReloadSnapshot(t *testing.T) {
	cfg, err := LoadConfig("config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Security.AccountPacing.Enabled || cfg.Security.AccountPacing.SoftDelay != 250*time.Millisecond || cfg.Security.AccountPacing.MaxConcurrent != 64 {
		t.Fatal("sample opt-in or duration decoding")
	}
	ac := &AtomicConfig{}
	ac.Store(cfg)
	session := ac.Load()
	next := *cfg
	next.Security.AccountPacing.Enabled = true
	if err := validateConfig(&next); err != nil {
		t.Fatal(err)
	}
	if err := validateReload(cfg, &next); err != nil {
		t.Fatal(err)
	}
	ac.Store(&next)
	if session.Security.AccountPacing.Enabled || !ac.Load().Security.AccountPacing.Enabled {
		t.Fatal("reload changed active session policy")
	}
	invalid := next
	invalid.Security.AccountPacing.MaxDelay = time.Millisecond
	if validateConfig(&invalid) == nil {
		t.Fatal("accepted invalid reloaded budget")
	}
	if ac.Load() != &next {
		t.Fatal("invalid candidate changed current snapshot")
	}
}
