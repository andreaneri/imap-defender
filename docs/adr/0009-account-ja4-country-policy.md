# 0009 — Account/JA4/country adaptive enforcement policy

- Date: 2026-10-11
- Status: Proposed; L1 JA4/IP opt-in and L2 Redis telemetry implemented on feature branch; enforcement not implemented
- Supersedes: [ADR 0008](0008-account-aware-response-pacing.md) for the account-aware policy; retains its protocol-safety requirements
- Extends: [ADR 0003](0003-backend-authentication-authority.md), [ADR 0004](0004-account-authentication-signals.md), [ADR 0007](0007-account-failure-counters.md)

## Decision and scope

Defender has two independent controls:

1. **L1 admission rate limiting** uses the pair (JA4, direct peer IP), limiting connection volume before an account is known. This is a **target design**, not the existing IP-only limiter in ADR 0006. Transparent and Learning never enforce it.
2. **L2 account-aware enforcement** uses authoritative backend authentication outcomes and the history of the exact declared authcid. An account with no historical outcomes is **UNKNOWN** and is observed without account-aware mitigation; after the first backend OK/NO/BAD it is **KNOWN**. Known does not mean legitimate or trusted. A failed login does not prove the account exists.

There is no third *knowledge* state. Redis timeout/unavailability or ambiguous protocol parsing is an operational failure: **fail open** for L2; do not infer account history or impose account-based restrictions.

## Reputation and enforcement scopes

- Maintain history for (account, JA4, IP), and aggregate failure signals for (account, JA4) across IPs. JA4 is a shared fingerprint, not a unique client identifier.
- A previously successful (account, JA4, IP) origin is a favorable signal, **not** a permanent allowlist or exemption from L1.
- For known accounts, a changed JA4 or IP may trigger **soft pacing of an authoritative negative response**, but never penalizes an OK response merely because the origin changed.
- Escalate delays on repeated authoritative authentication failures. Apply temporary blocks **only** to (account, JA4, country), independent of IP. No account-wide block, no global JA4 block, no block of other countries for the same account/JA4.
- Global (account, JA4) failures may increase suspicion in a new country but must not automatically propagate an existing country-specific block.
- A country-specific block needs local corroborating failures and an explicit threshold. Country ZZ/unknown is not a reliable location and must not be treated as a distinct trustworthy geography; do not issue country-scoped blocks without a valid GeoIP country.
- Blocking has a fixed, configurable TTL, without extension on denied attempts. After expiry, allow a fresh bounded evaluation. Limit concurrent tarpits to protect proxy capacity.

Initial thresholds, windows, delays and TTLs are **not decided**; choose conservative, opt-in values and validate with tests and telemetry before enabling blocks.

## Protocol and safety constraints

The backend remains the only authentication authority. Never verify passwords locally, synthesize an IMAP LOGIN/AUTHENTICATE result, change backend response bytes, or leak credentials. The response gate must preserve IMAP tagged correlation, literals, SASL exchanges, greeting, pipeline ordering and already-buffered bytes. Unknown or ambiguous framing bypasses L2 enforcement. Avoid blocking or sleeping under observer locks; use bounded Redis reads, cancellable timers and memory limits.

**Open implementation question:** a pre-backend account-specific block cannot be represented as a normal authentication rejection without violating ADR 0003. The eventual mechanism for enforcing a block (for example, closing the connection before forwarding a command) must be separately specified and tested for client compatibility. Until then, BLOCK is a *policy decision*, not an implemented action; response pacing of genuine backend NO/BAD is the first implementation stage.

## Storage and privacy

Hash exact account and origin components in Redis keys; never put plaintext credentials or auth commands in keys/logs. Keep separate bounded TTLs for account history, per-origin successes, (account, JA4) failures and (account, JA4, country) block state. Existing asynchronous event queue can lag or lose updates; do not treat counters as perfectly synchronized. A successful backend authentication should reduce suspicion for the corresponding origin without clearing unrelated suspicious histories.

## Verification requirements

Test unknown account first OK/NO, same and changed JA4/IP, changing country, shared JA4 across accounts, shared IP, distributed IP rotation, Redis failures, unknown GeoIP, fixed block expiry, backend OK unaffected, fragmented/pipelined IMAP, SASL, cancellation, and byte-for-byte forwarding. Dovecot/Redis end-to-end validation remains deferred until functional development is complete.

## Consequences

The policy reduces country-crossing collateral damage but cannot prevent false positives for two clients sharing account, JA4 and country. GeoIP can be inaccurate or evaded. The previous IP-only rate limiter and username/IP failure counter remain current runtime behavior until separately migrated; this ADR must not be described as implemented.

## Incremental implementation (feature branch)

The branch `feat/adr-0008-response-pacing` adds an opt-in `rate_limit.scope: ja4_ip` (with IP fallback if JA4 is absent), and writes account reputation through the existing asynchronous Redis pipeline. Keys use `proxy:account:v1:` plus a SHA-256 digest of JSON-encoded fields: `known(account)`, `origin(account,JA4,IP)`, `failures(account,JA4)`, and `country-failures(account,JA4,country)`. The account marker and origin record expire after 30 days; counters after 15 minutes of inactivity. Unknown country `ZZ` is excluded from country counters. OK updates the origin's last success but does not erase global failures. The original username/IP counters remain intact.

The reputation schema is telemetry only: no account-aware read is currently wired into the relay, no tarpit, no block key, and no account-level mitigation. The asynchronous queue can reorder observations under concurrent producers or lose events under pressure. The `AccountKnown` read returns errors separately; an error is not a knowledge state. Tests are committed but have not yet been executed in the required Go environment.

## Shadow decision engine (feature branch)

The internal `account_policy.go` adds `ReadAccountSignals` (read-only Redis pipeline with a 200 ms deadline) and a pure `evaluateAccountRisk` function returning ALLOW, PACE or BLOCK_CANDIDATE. Provisional thresholds are 3 global failures for 1 s pacing, 8 for 8 s pacing, and at least 20 global plus 12 country-local failures for a block candidate. These thresholds are not production-approved or configurable yet. Country-local corroboration is mandatory for block candidacy; unknown GeoIP cannot trigger it. Previous origin success is a signal, not a blanket exemption. Neither evaluation nor Redis lookup is called by the relay; no delay, denial, or block TTL is activated. A future integration must ensure pacing applies only to genuine backend-negative replies and enforce an explicit bounded concurrency policy.

## Asynchronous Defender shadow integration

The existing Redis event worker now evaluates the provisional account policy after a successful event write **only for Defender events**. The mode is captured per session in an internal `ShadowRisk` event flag. The worker performs a bounded read and logs action, reason, delay, outcome and country at debug level, without logging the account or changing client-visible behavior. Transparent does not persist and Learning persists without shadow evaluation. Redis failures skip shadow evaluation (fail open). This is diagnostic integration, **not** the protocol-aware response gate: the relay still forwards bytes without L2 pacing or account-specific blocking.

Shadow reads execute serially in the Redis worker and may reduce event-queue throughput under load; monitor queue drops before making them default in a production deployment. Redis pipeline reads are not atomic snapshots and counters may already include the event just written. The shadow classification must not be interpreted as the decision that would have been available before that event. Before activating enforcement, implement an independently bounded response gate with complete IMAP framing and regression tests.

## Inert response-gate primitives (feature branch)

`response_gate_primitives.go` introduces an intentionally **unwired** single-line tagged NO/BAD classifier, a cancellable wait, and a short-write-safe unchanged-byte forwarding helper, with unit tests. This is **not** a production IMAP response gate: it cannot by itself correlate the response with a LOGIN/AUTHENTICATE request, safely frame server literals, distinguish pipelined commands, or handle SASL/security layers. No actual response pacing is enabled. A future gate must process the complete bidirectional protocol stream and fail open on ambiguous framing; do not directly install these primitives as an `io.Copy` writer wrapper.
