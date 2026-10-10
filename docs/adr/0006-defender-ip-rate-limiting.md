# 0006 — Per-IP connection rate limiting in Defender

- Date: 2026-10-10
- Status: Proposed; implementation on `feat/defender-rate-limiter`
- Extends: [ADR 0002](0002-operating-modes.md) and [ADR 0005](0005-mode-runtime-and-learning.md)

## Decision and scope

Defender may apply an in-process token bucket keyed by the source IP address, after TLS handshake and before dialing the IMAP backend. `security.rate_limit.enabled` defaults to false. `per_minute` is the refill rate and `burst` the maximum token balance. Each accepted attempt consumes one token, including attempts that later fail authentication or are rejected by the Risk Engine. Rejected attempts close the connection without contacting the backend. Transparent and Learning do not enforce the limit.

`security.rate_limit.except_cidrs` accepts canonical IP prefixes, such as `192.0.2.0/24` or `2001:db8::/32`. An exception bypasses only the connection rate limiter: it does not bypass risk scoring, tarpit or DROP. Do not add exceptions based on JA4; TLS fingerprints can be shared across unrelated clients. Use the directly connected peer IP, not an untrusted client-supplied header.

The limiter is local to one process: it is not shared across replicas and its state is lost on restart. Reload changes thresholds and exceptions for new sessions without resetting existing buckets. A maximum of 100,000 IP buckets is maintained; idle buckets are periodically removed, and the oldest is evicted under pressure. This prevents unbounded memory use but may reset an evicted IP's allowance. The eviction scan is linear and requires load testing under high IP cardinality before production use.

## Limits and follow-up

This is connection-attempt limiting, not per-account or per-authentication-attempt limiting. NATs may group legitimate clients behind one IP. Thresholds must be calibrated from Learning telemetry before enabling Defender enforcement. The existing Redis lookup fail-open behavior for risk scoring remains unchanged; the local limiter is independent of Redis availability.

Verification required before merge: `make test`, `make build-local`, `make build-linux`, `make bench`, `go vet ./...`, reload tests and an end-to-end Dovecot/Redis exercise. Account-level policies and distributed rate limiting remain future work.
