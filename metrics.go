package main

import (
 "context"
 "fmt"
 "log/slog"
 "net"
 "net/http"
 "strconv"
 "strings"
 "sync"
 "sync/atomic"
 "time"
)

// proxyMetrics exposes bounded-cardinality Prometheus text metrics.
// No client identifiers or account names are used as labels.
type proxyMetrics struct {
 connectionsTotal atomic.Uint64
 connectionsActive atomic.Int64
 decisions [4]atomic.Uint64
 redisDropped atomic.Uint64
 tarpitMu sync.Mutex
 tarpitBuckets [7]uint64
 tarpitCount uint64
 tarpitSum float64
}

var tarpitBounds = [...]float64{0.1, 0.5, 1, 3, 5, 10, 15}

func (m *proxyMetrics) recordDecision(action string) {
 switch action {
 case "ALLOW": m.decisions[0].Add(1)
 case "TARPIT_SOFT": m.decisions[1].Add(1)
 case "TARPIT_HARD": m.decisions[2].Add(1)
 case "DROP": m.decisions[3].Add(1)
 }
}

func (m *proxyMetrics) observeTarpit(d time.Duration) {
 seconds := d.Seconds()
 m.tarpitMu.Lock()
 defer m.tarpitMu.Unlock()
 m.tarpitCount++
 m.tarpitSum += seconds
 for i, bound := range tarpitBounds {
  if seconds <= bound { m.tarpitBuckets[i]++ }
 }
}

func (m *proxyMetrics) handler(tracker *RedisTracker) http.Handler {
 return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
  if r.URL.Path != "/metrics" { http.NotFound(w, r); return }
  if r.Method != http.MethodGet { w.Header().Set("Allow", "GET"); http.Error(w, "method not allowed", http.StatusMethodNotAllowed); return }
  w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
  var b strings.Builder
  fmt.Fprintln(&b, "# HELP imap_connections_total Accepted TCP connections.")
  fmt.Fprintln(&b, "# TYPE imap_connections_total counter")
  fmt.Fprintf(&b, "imap_connections_total %d\n", m.connectionsTotal.Load())
  fmt.Fprintln(&b, "# HELP imap_connections_active Active TCP connections.")
  fmt.Fprintln(&b, "# TYPE imap_connections_active gauge")
  fmt.Fprintf(&b, "imap_connections_active %d\n", m.connectionsActive.Load())
  fmt.Fprintln(&b, "# HELP imap_risk_decisions_total Connection decisions by action.")
  fmt.Fprintln(&b, "# TYPE imap_risk_decisions_total counter")
  for i, action := range [...]string{"ALLOW", "TARPIT_SOFT", "TARPIT_HARD", "DROP"} {
   fmt.Fprintf(&b, "imap_risk_decisions_total{action=%q} %d\n", action, m.decisions[i].Load())
  }
  m.tarpitMu.Lock()
  buckets, count, sum := m.tarpitBuckets, m.tarpitCount, m.tarpitSum
  m.tarpitMu.Unlock()
  fmt.Fprintln(&b, "# HELP imap_tarpit_duration_seconds Actual elapsed tarpit duration, including cancellation.")
  fmt.Fprintln(&b, "# TYPE imap_tarpit_duration_seconds histogram")
  for i, bound := range tarpitBounds {
   fmt.Fprintf(&b, "imap_tarpit_duration_seconds_bucket{le=%q} %d\n", strconv.FormatFloat(bound, 'f', -1, 64), buckets[i])
  }
  fmt.Fprintf(&b, "imap_tarpit_duration_seconds_bucket{le=\"+Inf\"} %d\n", count)
  fmt.Fprintf(&b, "imap_tarpit_duration_seconds_sum %g\n", sum)
  fmt.Fprintf(&b, "imap_tarpit_duration_seconds_count %d\n", count)
  depth := 0
  if tracker != nil { depth = len(tracker.eventQueue) }
  fmt.Fprintln(&b, "# HELP imap_redis_queue_depth Pending asynchronous Redis events.")
  fmt.Fprintln(&b, "# TYPE imap_redis_queue_depth gauge")
  fmt.Fprintf(&b, "imap_redis_queue_depth %d\n", depth)
  fmt.Fprintln(&b, "# HELP imap_redis_events_dropped_total Redis events discarded because the queue was full.")
  fmt.Fprintln(&b, "# TYPE imap_redis_events_dropped_total counter")
  fmt.Fprintf(&b, "imap_redis_events_dropped_total %d\n", m.redisDropped.Load())
  _, _ = w.Write([]byte(b.String()))
 })
}

func startMetricsServer(ctx context.Context, address string, m *proxyMetrics, tracker *RedisTracker) error {
 listener, err := net.Listen("tcp", address)
 if err != nil { return err }
 server := &http.Server{Handler: m.handler(tracker), ReadHeaderTimeout: 5 * time.Second}
 go func() {
  <-ctx.Done()
  shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
  defer cancel()
  if err := server.Shutdown(shutdownCtx); err != nil { slog.Warn("Metrics shutdown failed", "error", err) }
 }()
 go func() {
  if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
   slog.Error("Metrics server stopped", "error", err)
  }
 }()
 return nil
}
