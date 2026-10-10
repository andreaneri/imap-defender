# 0007 — Scoped authentication failure counters

- Date: 2026-10-10
- Status: Proposed; initial counters implemented on `feat/defender-rate-limiter`
- Extends: [ADR 0004](0004-account-authentication-signals.md), [ADR 0005](0005-mode-runtime-and-learning.md)

## Decision

Learning and Defender asynchronously update a Redis failure streak for a pair of declared authentication username (authcid) and source IP. Keys are SHA-256 digests of JSON arrays, prefixed `proxy:auth:failure:`; no plaintext account appears in the key. Only a known nonempty username and an authoritative backend NO/BAD increment the counter. OK deletes that pair's counter; INDETERMINATE does nothing. Every failed event renews a 15-minute expiry. The existing asynchronous best-effort queue and its loss/error semantics apply.

These are **per-username/per-IP streaks**, not global account counters. A NO/BAD response does not prove that the password was incorrect or that the declared username exists. No account is blocked by this change: enforcement based on username cannot happen before the username is observed in the IMAP stream, and must not replace or forge backend responses. A future separate policy must handle this at the protocol-aware stage with bounded timeouts and explicit fail-open rules.

Transparent neither writes these counters nor consults Redis. No JA4 whitelist is introduced. The identity is deliberately not normalized because aliases and canonical backend account names are unknown.

## Limits

Redis values are simple integers, TTL is 15 minutes since the last observed failure. Counters may be lost when the telemetry queue fills or Redis is unavailable, and a process restart does not clear Redis keys. Because updates are asynchronous and independent across workers, counters are signals rather than authoritative security decisions. Avoid logging raw usernames in counter-related diagnostics. Verify Redis semantics and end-to-end Dovecot behavior in the deferred integration phase.
