package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func modeConfig(mode OperatingMode) *Config {
	return &Config{Server: ServerConfig{ListenAddr: ":993", BackendIMAPAddr: "localhost:143", CertFile: "cert", KeyFile: "key"}, Security: SecurityConfig{Mode: mode, Thresholds: ThresholdConfig{30, 60, 90}, Weights: WeightConfig{100, 35}}}
}

func TestModeConfiguration(t *testing.T) {
	for _, mode := range []OperatingMode{"", ModeTransparent, ModeLearning, ModeDefender, "invalid"} {
		cfg := modeConfig(mode)
		err := validateConfig(cfg)
		if mode == "" || mode == ModeTransparent {
			if err != nil || cfg.Security.Mode != ModeTransparent {
				t.Fatalf("default/transparent: %v", err)
			}
		} else if err == nil {
			t.Fatalf("accepted mode %q without Redis", mode)
		}
		cfg.Redis = RedisConfig{"localhost:6379", 10}
		err = validateConfig(cfg)
		if (err != nil) != (mode == "invalid") {
			t.Fatalf("mode %q: %v", mode, err)
		}
	}
	cfg := modeConfig(ModeTransparent)
	legacy := false
	cfg.Security.LegacyDeepInspection = &legacy
	if validateConfig(cfg) == nil {
		t.Fatal("legacy field must require migration")
	}
}

func TestModeDecisionAndPersistence(t *testing.T) {
	// An unusable tracker detects any accidental Redis access by observing modes.
	for _, mode := range []OperatingMode{ModeTransparent, ModeLearning} {
		p := &IMAPProxy{tracker: &RedisTracker{eventQueue: make(chan authEvent, 1)}}
		cfg := modeConfig(mode)
		action, delay := p.connectionDecision(context.Background(), cfg, "fp", "192.0.2.1", "US")
		if action != "ALLOW" || delay != 0 {
			t.Fatalf("%s mitigated", mode)
		}
		event := newAuthEvent(authResult{Method: "LOGIN", Outcome: "NO", Username: "user", UsernameKnown: true}, "192.0.2.1:1", "US", "fp")
		p.recordAuthEvent(mode, event)
		want := 0
		if mode == ModeLearning {
			want = 1
		}
		if len(p.tracker.eventQueue) != want {
			t.Fatalf("%s persistence", mode)
		}
	}
}

func TestAuthPersistenceFieldsAndTTL(t *testing.T) {
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", MaxRetries: -1})
	defer client.Close()
	for _, outcome := range []string{"OK", "NO", "BAD", "INDETERMINATE"} {
		event := newAuthEvent(authResult{Method: "AUTHENTICATE", Mechanism: "PLAIN", Outcome: outcome, Username: "user", UsernameKnown: true, AuthorizationID: "other"}, "192.0.2.1:12", "US", "fp")
		pipe := client.Pipeline()
		queueAuthEvent(context.Background(), pipe, event)
		cmds, err := pipe.Exec(context.Background())
		// The pipeline is inspected after a failed write to an invalid local endpoint.
		if err == nil || len(cmds) < 2 {
			t.Fatal("expected commands and unavailable Redis")
		}
		args := cmds[0].Args()
		fields := map[string]interface{}{}
		for i := 2; i < len(args); i += 2 {
			fields[args[i].(string)] = args[i+1]
		}
		if fields["outcome"] != outcome || fields["username"] != "user" || fields["authorization_id"] != "other" || fields["ip"] != "192.0.2.1" {
			t.Fatalf("incorrect fields: %v", fields)
		}
		if cmds[1].Args()[2] != int64(7*24*60*60) {
			t.Fatalf("observation TTL: %v", cmds[1].Args())
		}
		want := 2
		if outcome == "OK" {
			want = 3
		}
		if len(cmds) != want {
			t.Fatalf("outcome %s created success signal", outcome)
		}
	}
	if signalKey("a:b", "c") == signalKey("a", "b:c") {
		t.Fatal("ambiguous key")
	}
}

func TestQueueSaturationAndConcurrentClose(t *testing.T) {
	rt := &RedisTracker{eventQueue: make(chan authEvent, 1)}
	rt.TrackEventAsync(authEvent{})
	done := make(chan struct{})
	go func() { rt.TrackEventAsync(authEvent{}); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("full queue blocked")
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); rt.TrackEventAsync(authEvent{}) }()
	}
	rt.queueMu.Lock()
	rt.closed = true
	close(rt.eventQueue)
	rt.queueMu.Unlock()
	wg.Wait()
}

func TestDefenderRedisUnavailableAndCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	stop := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		<-stop
	}()
	defer close(stop)
	rt := NewRedisTracker(listener.Addr().String(), 1)
	defer rt.Close()
	p := &IMAPProxy{tracker: rt}
	started := time.Now()
	action, delay := p.connectionDecision(context.Background(), modeConfig(ModeDefender), "fp", "ip", "US")
	if action != "ALLOW" || delay != 0 || time.Since(started) > time.Second {
		t.Fatal("Redis failure did not fail open promptly")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = rt.HasSuccessfulOrigin(ctx, "fp", "ip")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
}

func TestModeReload(t *testing.T) {
	old := modeConfig(ModeTransparent)
	old.Redis = RedisConfig{"localhost:6379", 10}
	next := *old
	next.Security.Mode = ModeLearning
	if err := validateReload(old, &next); err != nil {
		t.Fatal(err)
	}
	ac := &AtomicConfig{}
	ac.Store(old)
	ac.Store(&next)
	if old.Security.Mode != ModeTransparent || ac.Load().Security.Mode != ModeLearning {
		t.Fatal("session snapshot changed")
	}
	next.Redis.Addr = "localhost:6380"
	if validateReload(old, &next) == nil {
		t.Fatal("accepted inactive Redis configuration")
	}
}

func BenchmarkTransparentDecision(b *testing.B) {
	p := &IMAPProxy{}
	cfg := modeConfig(ModeTransparent)
	for i := 0; i < b.N; i++ {
		p.connectionDecision(context.Background(), cfg, "fp", "ip", "US")
	}
}

func TestNoSecretsInPersistence(t *testing.T) {
	o := newAuthObserver(func(r authResult) {
		client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", MaxRetries: -1})
		defer client.Close()
		pipe := client.Pipeline()
		queueAuthEvent(context.Background(), pipe, newAuthEvent(r, "ip", "ZZ", "fp"))
		cmds, _ := pipe.Exec(context.Background())
		for _, cmd := range cmds {
			if strings.Contains(cmd.String(), "very-secret-password") {
				t.Fatal("password persisted")
			}
		}
	})
	o.observe(true, []byte("a LOGIN user very-secret-password\r\n"))
	o.observe(false, []byte("a OK done\r\n"))
}

// A controlled RESP peer exercises successful Redis lookups without depending
// on an external service; production Redis interoperability remains a CI concern.
func testRedisPeer(t *testing.T, exists int) (string, <-chan []string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	commands := make(chan []string, 100)
	var conns sync.Map
	t.Cleanup(func() {
		listener.Close()
		conns.Range(func(k, v interface{}) bool { k.(net.Conn).Close(); return true })
	})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conns.Store(conn, true)
			go func() {
				defer conn.Close()
				defer conns.Delete(conn)
				r := bufio.NewReader(conn)
				inTransaction := false
				var replies []string
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "*")))
					if err != nil {
						return
					}
					cmd := make([]string, n)
					for i := range cmd {
						line, err = r.ReadString('\n')
						if err != nil {
							return
						}
						size, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "$")))
						if err != nil {
							return
						}
						data := make([]byte, size+2)
						if _, err = io.ReadFull(r, data); err != nil {
							return
						}
						cmd[i] = string(data[:size])
					}
					commands <- cmd
					verb := strings.ToLower(cmd[0])
					if verb == "multi" {
						inTransaction = true
						replies = nil
						io.WriteString(conn, "+OK\r\n")
						continue
					}
					if verb == "exec" {
						fmt.Fprintf(conn, "*%d\r\n", len(replies))
						for _, reply := range replies {
							io.WriteString(conn, reply)
						}
						inTransaction = false
						continue
					}
					if inTransaction {
						reply := "+OK\r\n"
						if verb == "hset" || verb == "expire" {
							reply = ":1\r\n"
						}
						replies = append(replies, reply)
						io.WriteString(conn, "+QUEUED\r\n")
						continue
					}
					switch verb {
					case "hello":
						io.WriteString(conn, "-ERR unknown command hello\r\n")
					case "exists":
						fmt.Fprintf(conn, ":%d\r\n", exists)
					case "hset", "expire":
						io.WriteString(conn, ":1\r\n")
					default:
						io.WriteString(conn, "+OK\r\n")
					}
				}
			}()
		}
	}()
	return listener.Addr().String(), commands
}

func TestDefenderUsesScopedHistory(t *testing.T) {
	for _, exists := range []int{0, 1} {
		t.Run(strconv.Itoa(exists), func(t *testing.T) {
			addr, _ := testRedisPeer(t, exists)
			rt := NewRedisTracker(addr, 1)
			defer rt.Close()
			cfg := modeConfig(ModeDefender)
			p := &IMAPProxy{tracker: rt}
			action, _ := p.connectionDecision(context.Background(), cfg, "fp", "ip", "IT")
			want := "DROP"
			if exists == 1 {
				want = "ALLOW"
			}
			if action != want {
				t.Fatalf("got %s want %s", action, want)
			}
			// A learned origin still incurs country risk and is not an unconditional allow.
			if exists == 1 {
				action, _ = p.connectionDecision(context.Background(), cfg, "fp", "ip", "US")
				if action != "TARPIT_SOFT" {
					t.Fatal("historical success bypassed country policy")
				}
			}
		})
	}
}

func TestWorkerDrainsBackendEvents(t *testing.T) {
	addr, commands := testRedisPeer(t, 0)
	rt := NewRedisTracker(addr, 4)
	rt.TrackEventAsync(newAuthEvent(authResult{Method: "LOGIN", Username: "user", UsernameKnown: true, Outcome: "NO"}, "192.0.2.1", "IT", "fp"))
	rt.Close()
	found := false
	for len(commands) > 0 {
		cmd := <-commands
		if cmd[0] == "hset" {
			found = true
			if !strings.Contains(strings.Join(cmd, " "), "outcome NO") {
				t.Fatal("backend outcome missing")
			}
		}
	}
	if !found {
		t.Fatal("worker closed before persistence")
	}
	rt.TrackEventAsync(authEvent{})
}

func TestModesRelayTLSAndRealBackendOutcome(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}, &x509.Certificate{SerialNumber: big.NewInt(1)}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []OperatingMode{ModeTransparent, ModeLearning, ModeDefender} {
		t.Run(string(mode), func(t *testing.T) {
			backend, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer backend.Close()
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			cfg := modeConfig(mode)
			cfg.Server.BackendIMAPAddr = backend.Addr().String()
			ac := &AtomicConfig{}
			ac.Store(cfg)
			// Observing modes must never touch this tracker client's nil pointer.
			rt := &RedisTracker{eventQueue: make(chan authEvent, 4)}
			if mode == ModeDefender {
				addr, _ := testRedisPeer(t, 1)
				rt = NewRedisTracker(addr, 4)
				defer rt.Close()
			}
			p := &IMAPProxy{tracker: rt, atomicCfg: ac}
			p.tlsConfig = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, GetConfigForClient: p.handleGetConfigForClient}
			done := make(chan struct{})
			go func() {
				defer close(done)
				conn, err := listener.Accept()
				if err == nil {
					p.handleConnection(context.Background(), conn)
				}
			}()
			request := "a CAPABILITY\r\nb LOGIN user secret\r\n"
			reply := "* CAPABILITY IMAP4rev1\r\na OK done\r\nb NO denied\r\n"
			backendDone := make(chan error, 1)
			go func() {
				conn, err := backend.Accept()
				if err != nil {
					backendDone <- err
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(2 * time.Second))
				io.WriteString(conn, "* OK backend\r\n")
				data := make([]byte, len(request))
				_, err = io.ReadFull(conn, data)
				if err == nil && string(data) != request {
					err = fmt.Errorf("request altered")
				}
				if err == nil {
					_, err = io.WriteString(conn, reply)
				}
				backendDone <- err
			}()
			conn, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{InsecureSkipVerify: true})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(2 * time.Second))
			greeting := make([]byte, len("* OK backend\r\n"))
			if _, err = io.ReadFull(conn, greeting); err != nil {
				t.Fatal(err)
			}
			if string(greeting) != "* OK backend\r\n" {
				t.Fatal("greeting altered")
			}
			io.WriteString(conn, request)
			data := make([]byte, len(reply))
			if _, err = io.ReadFull(conn, data); err != nil {
				t.Fatal(err)
			}
			if string(data) != reply {
				t.Fatal("response altered")
			}
			conn.Close()
			if err = <-backendDone; err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("relay hung")
			}
			if mode == ModeTransparent && len(rt.eventQueue) != 0 {
				t.Fatal("transparent persisted")
			}
			if mode == ModeLearning {
				select {
				case event := <-rt.eventQueue:
					if event.Outcome != "NO" || event.Username != "user" {
						t.Fatalf("wrong event: %+v", event)
					}
				default:
					t.Fatal("learning lost result")
				}
			}
		})
	}
}
