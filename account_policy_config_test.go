package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestAccountPolicyYAMLDefaults(t *testing.T) {
	for _, body := range []string{"{}", "account_policy: {}", "account_policy: null"} {
		t.Run(body, func(t *testing.T) {
			cfg := modeConfig(ModeTransparent)
			if err := yaml.Unmarshal([]byte(body), &cfg.Security); err != nil {
				t.Fatal(err)
			}
			if err := validateConfig(cfg); err != nil {
				t.Fatal(err)
			}
			if got := accountPolicy(*cfg.Security.AccountPolicy); got != defaultAccountPolicy() {
				t.Fatalf("default policy = %+v", got)
			}
		})
	}
	cfg := modeConfig(ModeTransparent)
	if err := yaml.Unmarshal([]byte("account_policy:\n  soft_delay: 250ms\n  hard_failures: 9\n"), &cfg.Security); err != nil {
		t.Fatal(err)
	}
	if err := validateConfig(cfg); err != nil {
		t.Fatal(err)
	}
	want := defaultAccountPolicy()
	want.SoftDelay, want.HardFailures = 250*time.Millisecond, 9
	if got := accountPolicy(*cfg.Security.AccountPolicy); got != want {
		t.Fatalf("partial override = %+v, want %+v", got, want)
	}
}

func TestAccountPolicyConfigurationValidation(t *testing.T) {
	for _, body := range []string{
		"soft_failures: 0", "soft_failures: -1", "soft_failures: 8",
		"hard_failures: 0", "hard_failures: 3", "hard_failures: 20",
		"block_global_failures: 0", "block_global_failures: 8", "block_global_failures: 1000001",
		"block_country_failures: 0", "block_country_failures: -1", "block_country_failures: 21",
		"soft_delay: 0s", "soft_delay: -1s", "soft_delay: 9s",
		"hard_delay: 0s", "hard_delay: -1s", "hard_delay: 500ms", "hard_delay: 31s",
		"soft_delay: invalid", "soft_delay: 1000", "soft_failures: 1.5",
		"soft_failures: null", "hard_delay: null", "soft_failures: '3'", "soft_failure: 3",
		"soft_failures: 3\n  soft_failures: 4",
		"soft_failures: 9223372036854775808", "hard_delay: 999999999999999999h",
	} {
		t.Run(body, func(t *testing.T) {
			for _, mode := range []OperatingMode{ModeTransparent, ModeLearning, ModeDefender} {
				cfg := modeConfig(mode)
				cfg.Redis = RedisConfig{"localhost:6379", 10}
				err := yaml.Unmarshal([]byte("account_policy:\n  "+body+"\n"), &cfg.Security)
				if err == nil {
					err = validateConfig(cfg)
				}
				if err == nil {
					t.Fatalf("accepted invalid policy in %s", mode)
				}
			}
		})
	}
	// Both safety limits are inclusive, and equal nonzero delays are valid.
	p := AccountPolicyConfig(defaultAccountPolicy())
	p.BlockGlobalFailures, p.BlockCountryFailures = 1_000_000, 1_000_000
	p.SoftDelay, p.HardDelay = 30*time.Second, 30*time.Second
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
}

func TestAccountPolicyLoadAndReloadSnapshot(t *testing.T) {
	body, err := os.ReadFile("config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	old, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	ac := &AtomicConfig{}
	ac.Store(old)
	oldPolicy := *old.Security.AccountPolicy
	var next Config
	if err := yaml.Unmarshal(body, &next); err != nil {
		t.Fatal(err)
	}
	next.Security.AccountPolicy.SoftDelay = 17 * time.Millisecond
	updated, err := yaml.Marshal(&next)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, updated, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateReload(old, loaded); err != nil {
		t.Fatal(err)
	}
	ac.Store(loaded)
	if *old.Security.AccountPolicy != oldPolicy || ac.Load().Security.AccountPolicy.SoftDelay != 17*time.Millisecond {
		t.Fatal("reload changed the old session policy or failed to publish the new policy")
	}
	next.Security.AccountPolicy.SoftDelay = 0
	updated, err = yaml.Marshal(&next)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, updated, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("invalid reload configuration was accepted")
	}
	if ac.Load() != loaded {
		t.Fatal("failed reload replaced active configuration")
	}
}

func TestAccountShadowEventSnapshotAndModes(t *testing.T) {
	for _, mode := range []OperatingMode{ModeTransparent, ModeLearning, ModeDefender} {
		cfg := modeConfig(mode)
		policy := AccountPolicyConfig(defaultAccountPolicy())
		policy.SoftDelay = 17 * time.Millisecond
		cfg.Security.AccountPolicy = &policy
		rt := &RedisTracker{eventQueue: make(chan authEvent, 2)}
		p := &IMAPProxy{tracker: rt}
		event := newAuthEvent(authResult{Username: "alice", UsernameKnown: true, Outcome: "NO"}, "ip", "IT", "fp")
		p.recordAuthEvent(cfg, event)
		if mode == ModeTransparent {
			if len(rt.eventQueue) != 0 {
				t.Fatal("Transparent persisted an event")
			}
			continue
		}
		policy.SoftDelay = time.Second
		queued := <-rt.eventQueue
		if queued.ShadowRisk != (mode == ModeDefender) {
			t.Fatalf("unexpected shadow flag in %s", mode)
		}
		if mode == ModeDefender && queued.ShadowPolicy.SoftDelay != 17*time.Millisecond {
			t.Fatal("queued event did not copy the session policy")
		}
		if mode == ModeLearning && queued.ShadowPolicy != (accountPolicy{}) {
			t.Fatal("Learning enabled a shadow policy")
		}
	}
}

func TestConfiguredAccountPolicyBoundaries(t *testing.T) {
	p := accountPolicy{
		SoftFailures: 2, HardFailures: 4, BlockGlobalFailures: 9,
		BlockCountryFailures: 5, SoftDelay: 17 * time.Millisecond, HardDelay: 150 * time.Millisecond,
	}
	for _, tt := range []struct {
		name    string
		signals accountSignals
		action  accountAction
		delay   time.Duration
	}{
		{"below soft", accountSignals{Known: true, GlobalFailures: 1}, accountAllow, 0},
		{"at soft", accountSignals{Known: true, GlobalFailures: 2}, accountPace, p.SoftDelay},
		{"below hard", accountSignals{Known: true, GlobalFailures: 3}, accountPace, p.SoftDelay},
		{"at hard", accountSignals{Known: true, GlobalFailures: 4}, accountPace, p.HardDelay},
		{"below global block", accountSignals{Known: true, GlobalFailures: 8, CountryFailures: 5, CountryValid: true}, accountPace, p.HardDelay},
		{"below country block", accountSignals{Known: true, GlobalFailures: 9, CountryFailures: 4, CountryValid: true}, accountPace, p.HardDelay},
		{"at block thresholds", accountSignals{Known: true, GlobalFailures: 9, CountryFailures: 5, CountryValid: true}, accountBlockCandidate, 0},
		{"unknown account", accountSignals{GlobalFailures: 9, CountryFailures: 5, CountryValid: true}, accountAllow, 0},
		{"unknown country", accountSignals{Known: true, GlobalFailures: 9, CountryFailures: 5}, accountPace, p.HardDelay},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := evaluateAccountRisk(tt.signals, p)
			if got.Action != tt.action || got.Delay != tt.delay {
				t.Fatalf("decision = %+v, want %s/%s", got, tt.action, tt.delay)
			}
		})
	}
}

func accountSignalReply(cmd []string) string {
	switch strings.ToLower(cmd[0]) {
	case "hexists":
		return ":0\r\n"
	case "get":
		if strings.Contains(cmd[1], ":country-failures:") {
			return "$1\r\n0\r\n"
		}
		return "$1\r\n3\r\n"
	}
	return ""
}

func TestConfiguredAccountShadowWorker(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(previous)
	addr, commands := testRedisPeer(t, 1, accountSignalReply)
	rt := NewRedisTracker(addr, 4)
	defer rt.Close()
	cfg := modeConfig(ModeDefender)
	policy := AccountPolicyConfig(defaultAccountPolicy())
	policy.SoftDelay = 17 * time.Millisecond
	cfg.Security.AccountPolicy = &policy
	p := &IMAPProxy{tracker: rt}
	p.recordAuthEvent(cfg, newAuthEvent(authResult{Method: "LOGIN", Username: "alice", UsernameKnown: true, Outcome: "NO"}, "192.0.2.1", "IT", "fp"))
	rt.Close()
	logs := output.String()
	if !strings.Contains(logs, "Account shadow decision") || !strings.Contains(logs, "action=PACE") || !strings.Contains(logs, "delay=17ms") {
		t.Fatalf("configured shadow decision missing: %s", logs)
	}
	for len(commands) > 0 {
		cmd := <-commands
		if strings.Contains(strings.Join(cmd, " "), "17ms") {
			t.Fatal("internal shadow policy was persisted")
		}
	}
}

func TestAccountSignalsReadFailOpen(t *testing.T) {
	addr, _ := testRedisPeer(t, 1, func(cmd []string) string {
		if strings.ToLower(cmd[0]) == "get" {
			return "-ERR unavailable\r\n"
		}
		return accountSignalReply(cmd)
	})
	rt := NewRedisTracker(addr, 1)
	defer rt.Close()
	signals, err := rt.ReadAccountSignals(context.Background(), "alice", "fp", "ip", "IT")
	if err == nil || signals != (accountSignals{}) {
		t.Fatalf("failed lookup returned usable signals: %+v, %v", signals, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := rt.ReadAccountSignals(ctx, "alice", "fp", "ip", "IT"); !errors.Is(err, context.Canceled) {
		t.Fatalf("lookup ignored cancellation: %v", err)
	}
}
