package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// AccountPacingConfig is opt-in. Zero-valued tuning fields use conservative
// defaults. Bounds apply even when disabled, so reload cannot publish bad policy.
type AccountPacingConfig struct {
	Enabled       bool          `yaml:"enabled"`
	SoftFailures  int64         `yaml:"soft_failures"`
	HardFailures  int64         `yaml:"hard_failures"`
	SoftDelay     time.Duration `yaml:"soft_delay"`
	HardDelay     time.Duration `yaml:"hard_delay"`
	MaxDelay      time.Duration `yaml:"max_delay"`
	MaxConcurrent int64         `yaml:"max_concurrent"`
}

func (c AccountPacingConfig) defaults() AccountPacingConfig {
	if c.SoftFailures == 0 {
		c.SoftFailures = 3
	}
	if c.HardFailures == 0 {
		c.HardFailures = 8
	}
	if c.SoftDelay == 0 {
		c.SoftDelay = 250 * time.Millisecond
	}
	if c.HardDelay == 0 {
		c.HardDelay = time.Second
	}
	if c.MaxDelay == 0 {
		c.MaxDelay = time.Second
	}
	if c.MaxConcurrent == 0 {
		c.MaxConcurrent = 64
	}
	return c
}

func validateAccountPacing(c AccountPacingConfig) error {
	c = c.defaults()
	if c.SoftFailures < 1 || c.HardFailures <= c.SoftFailures || c.HardFailures > 1000000 ||
		c.SoftDelay < time.Millisecond || c.HardDelay < c.SoftDelay || c.HardDelay > c.MaxDelay ||
		c.MaxDelay > 8*time.Second || c.MaxConcurrent < 1 || c.MaxConcurrent > 1024 {
		return fmt.Errorf("security.account_pacing requires 0 < soft_failures < hard_failures <= 1000000, 1ms <= soft_delay <= hard_delay <= max_delay <= 8s and 1 <= max_concurrent <= 1024")
	}
	return nil
}

// Blocks deliberately have no runtime action. Repeated failures continue to
// receive bounded pacing regardless of country; successful origins are signals,
// never exemptions. An unknown account or unusable snapshot always fails open.
func accountFailureDelay(s accountSignals, c AccountPacingConfig) time.Duration {
	c = c.defaults()
	if !s.Known || s.GlobalFailures < 0 || s.CountryFailures < 0 {
		return 0
	}
	if s.GlobalFailures >= c.HardFailures {
		return c.HardDelay
	}
	if s.GlobalFailures >= c.SoftFailures || !s.OriginSucceeded {
		return c.SoftDelay
	}
	return 0
}

type accountPaceLimiter struct{ active atomic.Int64 }

func (l *accountPaceLimiter) acquire(maximum int64) bool {
	for {
		n := l.active.Load()
		if n >= maximum {
			return false
		}
		if l.active.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

type accountResponsePacer struct {
	config  AccountPacingConfig
	limiter *accountPaceLimiter
	metrics *proxyMetrics
	// lookup must honor context cancellation. The production Redis implementation
	// has context-enabled network deadlines and no retries.
	lookup func(context.Context, authResult) (accountSignals, error)
}

type backendRead struct {
	data []byte
	err  error
}

// paceForwardState protects publication of client input without holding a lock
// over socket writes. A racing completion may pace only after a complete write.
type paceForwardState struct {
	writing  atomic.Bool
	failed   atomic.Bool
	closed   atomic.Bool
	activity chan struct{}
}

type pacedClientWriter struct {
	dst      net.Conn
	observer *authObserver
	state    *paceForwardState
}

func (w pacedClientWriter) Write(data []byte) (int, error) {
	w.state.writing.Store(true)
	select {
	case w.state.activity <- struct{}{}:
	default:
	}
	w.observer.observe(true, data)
	err := writeUnchanged(w.dst, data)
	if err != nil {
		w.state.failed.Store(true)
	}
	w.state.writing.Store(false)
	if err != nil {
		return 0, err
	}
	return len(data), nil
}

func (o *authObserver) canPace() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return !o.disabled && !o.gateUnsafe && len(o.activeTags) == 0 &&
		!o.client.inLine && o.client.literal == 0 && !o.client.continuation && o.saslTag == ""
}

// relayAccountPaced changes only the delivery time of a completion's final LF.
// Every preceding byte is streamed immediately, including partial physical
// lines and literal payloads. This is intentional: no complete response is
// delivered until LF, and unrelated pipelined bytes never sit behind a timer.
// On subsequent input in either direction, EOF, ambiguity, saturation or lookup
// failure the held LF is released immediately, preserving order and all bytes.
func relayAccountPaced(ctx context.Context, client, backend net.Conn, obs *authObserver, gate *accountResponsePacer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer obs.finish()
	obs.gateEnabled = true // before any goroutine can observe the session
	state := &paceForwardState{activity: make(chan struct{}, 1)}
	stop := context.AfterFunc(ctx, func() { _ = client.Close(); _ = backend.Close() })
	defer stop()
	reads := make(chan backendRead, 1)
	var readers sync.WaitGroup
	readers.Add(1)
	go func() {
		defer readers.Done()
		defer close(reads)
		for {
			data := make([]byte, 32*1024)
			n, err := backend.Read(data)
			if n > 0 || err != nil {
				select {
				case reads <- backendRead{data[:n], err}:
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	clientDone := make(chan error, 1)
	go func() {
		_, err := io.Copy(pacedClientWriter{backend, obs, state}, client)
		state.closed.Store(true)
		if err != nil {
			state.failed.Store(true)
			cancel()
		} else {
			// Preserve TCP half-close while bounding drain of an unresponsive backend.
			if cw, ok := backend.(interface{ CloseWrite() error }); ok {
				_ = cw.CloseWrite()
			}
			_ = backend.SetReadDeadline(time.Now().Add(5 * time.Second))
			select {
			case state.activity <- struct{}{}:
			default:
			}
		}
		clientDone <- err
	}()
	var lookups sync.WaitGroup
	serverErr := copyAccountResponses(ctx, client, obs, gate, state, reads, &lookups)
	cancel()
	_ = client.Close()
	_ = backend.Close()
	clientErr := <-clientDone
	readers.Wait()
	lookups.Wait()
	return errors.Join(serverErr, clientErr)
}

func copyAccountResponses(ctx context.Context, dst io.Writer, obs *authObserver, gate *accountResponsePacer, state *paceForwardState, reads <-chan backendRead, lookups *sync.WaitGroup) error {
	var queued *backendRead
	for {
		var read backendRead
		if queued != nil {
			read = *queued
			queued = nil
		} else {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case next, ok := <-reads:
				if !ok {
					return nil
				}
				read = next
			}
		}
		data := read.data
		for len(data) > 0 {
			n := len(data)
			if end := bytes.IndexByte(data, '\n'); end >= 0 {
				n = end + 1
			}
			part := data[:n]
			results := obs.capture(false, part)
			candidate := authResult{}
			for _, result := range results {
				if result.UsernameKnown && (result.Outcome == "NO" || result.Outcome == "BAD") {
					candidate = result
				}
			}
			// Additional bytes already in this read bypass pacing. A completion is
			// safe only when it is the sole outstanding command and framing is intact.
			eligible := candidate.UsernameKnown && part[len(part)-1] == '\n' && n == len(data) && read.err == nil && obs.canPace() && !state.failed.Load() && !state.closed.Load()
			if eligible {
				// Prefix delivery also lets a slow reader exert normal TCP backpressure.
				if err := writeUnchanged(dst, part[:len(part)-1]); err != nil {
					obs.dispatch(results)
					return err
				}
				queued = gate.holdCompletion(ctx, candidate, obs, state, reads, lookups)
				if err := writeUnchanged(dst, part[len(part)-1:]); err != nil {
					obs.dispatch(results)
					return err
				}
			} else if err := writeUnchanged(dst, part); err != nil {
				obs.dispatch(results)
				return err
			}
			// The current result is persisted AFTER the historical decision, so its
			// asynchronous write cannot make this account's first outcome look KNOWN.
			obs.dispatch(results)
			data = data[n:]
		}
		if read.err != nil {
			if read.err == io.EOF {
				return nil
			}
			return read.err
		}
	}
}

func (g *accountResponsePacer) holdCompletion(ctx context.Context, result authResult, obs *authObserver, state *paceForwardState, reads <-chan backendRead, lookups *sync.WaitGroup) *backendRead {
	c := g.config.defaults()
	if g.lookup == nil || g.limiter == nil || !g.limiter.acquire(c.MaxConcurrent) {
		if g.metrics != nil {
			g.metrics.accountPaceBypassed.Add(1)
		}
		return nil
	}
	transferred := false
	defer func() {
		if !transferred {
			g.limiter.active.Add(-1)
		}
	}()
	// Do not wait for a client socket write that has not committed yet. This
	// avoids holding a completion already racing a partial or failed command.
	if state.writing.Load() || state.failed.Load() || state.closed.Load() || !obs.canPace() {
		return nil
	}
	select {
	case <-state.activity:
	default:
	}
	if state.writing.Load() || !obs.canPace() {
		return nil
	}
	started := time.Now()
	readCtx, cancel := context.WithTimeout(ctx, min(200*time.Millisecond, c.MaxDelay))
	defer cancel()
	type lookupResult struct {
		signals accountSignals
		err     error
	}
	answer := make(chan lookupResult, 1)
	holdDone := make(chan struct{})
	defer close(holdDone)
	transferred = true
	lookups.Add(1)
	go func() {
		defer lookups.Done()
		defer func() { <-holdDone; g.limiter.active.Add(-1) }()
		signals, err := g.lookup(readCtx, result)
		answer <- lookupResult{signals, err}
	}()
	var historical lookupResult
	select {
	case next, ok := <-reads:
		if !ok {
			return &backendRead{err: io.EOF}
		}
		return &next
	case <-state.activity:
		return nil
	case <-readCtx.Done():
		if g.metrics != nil {
			g.metrics.accountPaceBypassed.Add(1)
		}
		return nil
	case historical = <-answer:
	}
	if historical.err != nil || state.failed.Load() || !obs.canPace() {
		if g.metrics != nil {
			g.metrics.accountPaceBypassed.Add(1)
		}
		return nil
	}
	delay := accountFailureDelay(historical.signals, c)
	if delay > c.MaxDelay {
		delay = c.MaxDelay
	}
	// Lookup time consumes the delay budget; no additive Redis penalty.
	remaining := delay - time.Since(started)
	if remaining <= 0 {
		return nil
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	if g.metrics != nil {
		g.metrics.accountPaceDelayed.Add(1)
		g.metrics.accountPaceActive.Add(1)
		defer g.metrics.accountPaceActive.Add(-1)
	}
	select {
	case next, ok := <-reads:
		if !ok {
			return &backendRead{err: io.EOF}
		}
		return &next
	case <-state.activity:
	case <-ctx.Done():
	case <-timer.C:
	}
	return nil
}
