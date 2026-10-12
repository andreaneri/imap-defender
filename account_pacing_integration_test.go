package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAccountSignalsRedisSnapshot(t *testing.T) {
	for _, tc := range []struct {
		name           string
		known, success int
		global, local  string
		country        string
		wantErr        bool
	}{
		{"unknown", 0, 0, "$-1\r\n", "$-1\r\n", "IT", false},
		{"known", 1, 1, "$1\r\n9\r\n", "$1\r\n2\r\n", "IT", false},
		{"rotated origin", 1, 0, "$1\r\n9\r\n", "$-1\r\n", "DE", false},
		{"unknown GeoIP", 1, 0, "$1\r\n9\r\n", "$-1\r\n", "ZZ", false},
		{"malformed counter", 1, 0, "$3\r\nbad\r\n", "$-1\r\n", "IT", true},
		{"wrong type", 1, 0, "-WRONGTYPE incompatible key\r\n", "$-1\r\n", "IT", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			account, ja4, ip := "exact/User", "shared-fingerprint", "192.0.2.1"
			countryKey := accountReputationKey("country-failures", account, ja4, tc.country)
			var localReads atomic.Int64
			address, _ := testRedisPeer(t, 1, func(cmd []string) string {
				switch strings.ToLower(cmd[0]) {
				case "exists":
					return fmt.Sprintf(":%d\r\n", tc.known)
				case "hexists":
					return fmt.Sprintf(":%d\r\n", tc.success)
				case "get":
					if cmd[1] == countryKey {
						localReads.Add(1)
						return tc.local
					}
					return tc.global
				}
				return ""
			})
			rt := NewRedisTracker(address, 4)
			defer rt.Close()
			signals, err := rt.ReadAccountSignals(context.Background(), account, ja4, ip, tc.country)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err %v", err)
			}
			if !tc.wantErr && (signals.Known != (tc.known == 1) || signals.OriginSucceeded != (tc.success == 1) || signals.CountryValid != validCountryCode(tc.country)) {
				t.Fatalf("signals %+v", signals)
			}
			if tc.country == "ZZ" && localReads.Load() != 0 {
				t.Fatal("read invalid geography")
			}
		})
	}
}

// Runs the actual TLS handler, opt-in config, account Redis lookup, response
// gate and asynchronous event worker against controlled TCP peers. The backend
// owns every greeting and result; no mock credential verifier exists here.
func TestAccountPacingTLSRuntime(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}, &x509.Certificate{SerialNumber: big.NewInt(2)}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		mode     OperatingMode
		enabled  bool
		outcome  string
		known    int
		failures string
		paced    bool
	}{
		{"transparent opt-in ignored", ModeTransparent, true, "NO", 1, "9", false},
		{"learning opt-in ignored", ModeLearning, true, "NO", 1, "9", false},
		{"defender default disabled", ModeDefender, false, "NO", 1, "9", false},
		{"defender negative paced", ModeDefender, true, "NO", 1, "9", true},
		{"defender BAD paced", ModeDefender, true, "BAD", 1, "9", true},
		{"defender OK unpenalized", ModeDefender, true, "OK", 1, "99", false},
		{"unknown first NO", ModeDefender, true, "NO", 0, "9", false},
		{"unknown first OK", ModeDefender, true, "OK", 0, "9", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backendListener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer backendListener.Close()
			proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer proxyListener.Close()
			address, _ := testRedisPeer(t, 1, func(cmd []string) string {
				switch strings.ToLower(cmd[0]) {
				case "exists":
					if cmd[1] == accountReputationKey("known", "user") {
						return fmt.Sprintf(":%d\r\n", tc.known)
					}
					return ":1\r\n"
				case "hexists":
					return ":0\r\n" // changed origin soft signal
				case "get":
					return fmt.Sprintf("$%d\r\n%s\r\n", len(tc.failures), tc.failures)
				}
				return ""
			})
			rt := NewRedisTracker(address, 16)
			defer rt.Close()
			cfg := modeConfig(tc.mode)
			cfg.Redis = RedisConfig{address, 16}
			cfg.Security.Weights = WeightConfig{}
			cfg.Server.BackendIMAPAddr = backendListener.Addr().String()
			cfg.Security.AccountPacing = testPacingConfig()
			cfg.Security.AccountPacing.Enabled = tc.enabled
			ac := &AtomicConfig{}
			ac.Store(cfg)
			p := &IMAPProxy{tracker: rt, atomicCfg: ac, metrics: &proxyMetrics{}}
			p.tlsConfig = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, GetConfigForClient: p.handleGetConfigForClient}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			proxyDone := make(chan struct{})
			go func() {
				defer close(proxyDone)
				conn, err := proxyListener.Accept()
				if err == nil {
					p.handleConnection(ctx, conn)
				}
			}()
			ready := make(chan struct{})
			releaseBackend := make(chan struct{})
			backendDone := make(chan error, 1)
			reply := "A " + tc.outcome + " [AUTHENTICATIONFAILED] unchanged backend text\r\n"
			go func() {
				conn, err := backendListener.Accept()
				if err != nil {
					backendDone <- err
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(2 * time.Second))
				if _, err = io.WriteString(conn, "* OK actual backend\r\n"); err != nil {
					backendDone <- err
					return
				}
				request, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil || request != "A LOGIN user secret\r\n" {
					backendDone <- fmt.Errorf("request %q %v", request, err)
					return
				}
				close(ready)
				// Let the frontend test explicitly release the authoritative backend reply.
				<-releaseBackend
				_, err = io.WriteString(conn, reply)
				if err != nil {
					backendDone <- err
					return
				}
				// Keep the backend open; EOF during pacing intentionally releases it.
				data := make([]byte, 1)
				_, err = conn.Read(data)
				backendDone <- nil
			}()
			client, err := tls.Dial("tcp", proxyListener.Addr().String(), &tls.Config{InsecureSkipVerify: true})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			client.SetDeadline(time.Now().Add(2 * time.Second))
			reader := bufio.NewReader(client)
			greeting, err := reader.ReadString('\n')
			if err != nil || greeting != "* OK actual backend\r\n" {
				t.Fatal("greeting changed", err)
			}
			if _, err = io.WriteString(client, "A LOGIN user secret\r\n"); err != nil {
				t.Fatal(err)
			}
			<-ready
			time.Sleep(2 * time.Millisecond)
			started := time.Now()
			close(releaseBackend)
			got, err := reader.ReadString('\n')
			elapsed := time.Since(started)
			if err != nil || got != reply {
				t.Fatalf("response %q %v", got, err)
			}
			if tc.paced && elapsed < 60*time.Millisecond {
				t.Fatalf("not paced: %s", elapsed)
			}
			if !tc.paced && elapsed > 50*time.Millisecond {
				t.Fatalf("unexpected pacing: %s", elapsed)
			}
			if elapsed > 500*time.Millisecond {
				t.Fatal("delay not bounded")
			}
			cancel()
			client.Close()
			select {
			case <-proxyDone:
			case <-time.After(time.Second):
				t.Fatal("handler leaked")
			}
			select {
			case err := <-backendDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("backend leaked")
			}
			if tc.paced && p.metrics.accountPaceDelayed.Load() != 1 {
				t.Fatal("missing pacing metric")
			}
			if p.accountPacer.active.Load() != 0 {
				t.Fatal("capacity leaked")
			}
		})
	}
}
