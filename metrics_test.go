package main

import (
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
 "time"
)

func TestMetricsHandler(t *testing.T) {
 m := &proxyMetrics{}
 m.connectionsTotal.Add(3)
 m.connectionsActive.Add(1)
 m.recordDecision("ALLOW")
 m.recordDecision("DROP")
 m.redisDropped.Add(2)
 m.observeTarpit(250 * time.Millisecond)
 request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
 response := httptest.NewRecorder()
 m.handler(nil).ServeHTTP(response, request)
 if response.Code != http.StatusOK { t.Fatalf("status = %d", response.Code) }
 body := response.Body.String()
 for _, expected := range []string{
  "imap_connections_total 3",
  "imap_connections_active 1",
  "imap_risk_decisions_total{action=\"ALLOW\"} 1",
  "imap_risk_decisions_total{action=\"DROP\"} 1",
  "imap_tarpit_duration_seconds_bucket{le=\"0.5\"} 1",
  "imap_tarpit_duration_seconds_count 1",
  "imap_redis_queue_depth 0",
  "imap_redis_events_dropped_total 2",
 } {
  if !strings.Contains(body, expected) { t.Errorf("missing %q", expected) }
 }
 if strings.Contains(body, "username") || strings.Contains(body, "remote_ip") {
  t.Fatal("sensitive metric label")
 }
}

func TestMetricsHandlerRejectsOtherPathsAndMethods(t *testing.T) {
 m := &proxyMetrics{}
 for _, tc := range []struct{ method, path string; status int }{
  {"GET", "/unknown", http.StatusNotFound},
  {"POST", "/metrics", http.StatusMethodNotAllowed},
 } {
  w := httptest.NewRecorder()
  m.handler(nil).ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
  if w.Code != tc.status { t.Errorf("%s %s: %d", tc.method, tc.path, w.Code) }
 }
}

func TestMetricsListenAddressValidation(t *testing.T) {
 cfg := &Config{
  Server: ServerConfig{ListenAddr: ":993", BackendIMAPAddr: "localhost:143", CertFile: "cert.pem", KeyFile: "key.pem"},
  Security: SecurityConfig{Thresholds: ThresholdConfig{TarpitSoft: 30, TarpitHard: 60, Drop: 90}},
  Metrics: MetricsConfig{ListenAddr: ":993"},
 }
 if err := validateConfig(cfg); err == nil { t.Fatal("expected port conflict") }
 cfg.Metrics.ListenAddr = "127.0.0.1:9090"
 if err := validateConfig(cfg); err != nil { t.Fatal(err) }
}
