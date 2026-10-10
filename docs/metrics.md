# Prometheus metrics

The proxy optionally serves Prometheus text exposition on a separate HTTP listener at `metrics.listen_addr`. The example config binds to `127.0.0.1:9090`; an empty address disables the endpoint. It is not exposed by Docker Compose by default.

To scrape from another container, explicitly configure a reachable container interface and restrict access to a trusted monitoring network. The endpoint has no authentication or TLS and **must not be exposed publicly**. Restart is required after changing the metrics address.

Example Prometheus scrape configuration:

```yaml
scrape_configs:
  - job_name: imap-defender
    static_configs:
      - targets: ['imap-proxy:9090']
```

Available metrics:

- `imap_connections_total`: accepted TCP connections.
- `imap_connections_active`: currently active TCP handlers.
- `imap_risk_decisions_total{action}`: connection decisions, including ALLOW, TARPIT_SOFT, TARPIT_HARD, DROP. ALLOW includes non-Defender modes and fail-open decisions.
- `imap_tarpit_duration_seconds`: histogram of elapsed tarpit wait, including interrupted waits.
- `imap_redis_queue_depth`: pending queued events (not including an event currently being written).
- `imap_redis_events_dropped_total`: events discarded when the Redis queue is full; not a count of failed Redis writes.

Metrics are process-local and reset on restart. They contain no client IP, JA4, username or account labels. The handler uses only Go standard-library packages and exposes the Prometheus text format without a third-party dependency.

Verification required before merge: `make test`, `make build-local`, `make build-linux`, `go vet ./...`, and `make bench`. These checks have not been run in the GitHub-only editing environment.
