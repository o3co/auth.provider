# @o3co/auth-provider-dpop

DPoP (RFC 9449) sender-constrained access token support for [@o3co/auth-provider].

## Status

Stage 1 (token-endpoint binding). See [the Phase 2 spec](https://github.com/o3co/auth.provider/blob/develop/.claude/superpowers/specs/2026-05-18-wave-2-phase-2-dpop-spec.md) for the scope boundary — Stage 2 will add nonce challenge (RFC 9449 §8) and the `dpop_jkt` query parameter at `/authorize` (RFC 9449 §10).

## Quick start

(Filled in by Sub-PR 2b/2c.)

## Operator requirements

- Express's `trust proxy` MUST be configured when the AS sits behind a TLS-terminating reverse proxy. Without it, `req.protocol` returns `http` and DPoP proof verification fails every request (`htu_mismatch`).
- For multi-process / clustered deployments (PM2 cluster, Kubernetes replicas, etc.), the Redis replay store adapter is required. The in-memory adapter is for single-process dev / test use only.
