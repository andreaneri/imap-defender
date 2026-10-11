# 0008 — Account-aware Defender enforcement at IMAP response boundary

- Date: 2026-10-11
- Status: Proposed; not implemented
- Extends: [ADR 0003](0003-backend-authentication-authority.md), [ADR 0004](0004-account-authentication-signals.md), [ADR 0007](0007-account-failure-counters.md)

## Problem

The existing relay uses two concurrent `io.Copy` calls. Its observer can recognize declared authcid and backend outcomes but must never fabricate tagged LOGIN/AUTHENTICATE replies or discard buffered IMAP bytes. An account identity is not available at connection admission. Redis counters are asynchronous, so an immediate read can lag the most recent authentication.

## Proposed boundary

Introduce an explicit, opt-in Defender-only response pacing policy after an authoritative backend NO/BAD. The backend must receive every command unmodified and produce the authoritative response. A protocol-aware forwarding stage may delay delivery of a complete tagged failure response, but must not change any bytes, reorder responses or withhold unrelated pipelined replies. A successful response is never penalized. Do not close a connection merely because a username is claimed by a remote client: this could allow targeted denial of service against legitimate users.

The policy should use an exact declared authcid plus directly connected peer IP, not JA4 alone. Unknown identities and unsupported/ambiguous framing fail open. Explicit maximum delay and a cancellable timer are required. Avoid sleeps under the observer mutex. Disable enforcement on COMPRESS or SASL security-layer negotiation if response boundaries cannot be reliably maintained.

## Required implementation prerequisites

1. Split passive observation from a bounded protocol-aware response gate. Preserve the existing reader's buffered bytes, literal handling, tagged correlation, greeting and pipelined responses.
2. Use the stored account/IP failure count only as a historical signal, with a bounded Redis read and explicit fail-open behavior; avoid trusting a client-supplied username as proof of account ownership.
3. Add opt-in config (disabled by default), metrics for delayed responses, and integration tests for fragmented/pipelined tagged responses, SASL, timeouts, cancellations and unchanged byte streams.
4. Confirm that backend NO/BAD semantics are retained and that legitimate shared-IP clients are not globally penalized.

Until these prerequisites are met, ADR 0007 counters are telemetry only. The per-IP admission rate limiter of ADR 0006 is the only newly implemented rate enforcement in PR #8.
