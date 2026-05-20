# @o3co/auth-provider-dpop

DPoP (RFC 9449) sender-constrained access token support for [@o3co/auth-provider].

## Status

Stage 1 (token-endpoint binding). See [the Phase 2 spec](https://github.com/o3co/auth.provider/blob/develop/.claude/superpowers/specs/2026-05-18-wave-2-phase-2-dpop-spec.md) for the scope boundary — Stage 2 will add nonce challenge (RFC 9449 §8) and the `dpop_jkt` query parameter at `/authorize` (RFC 9449 §10).

## Quick start

```typescript
import { createApp } from "@o3co/auth-provider-core";
import { dpopModule } from "@o3co/auth-provider-dpop";

const handle = await createApp({
    modules: [dpopModule /* + your other modules */],
    bootstrapComponents: { config, /* ... */ },
});
```

Enable DPoP in your `application.conf`:

```hocon
oauth {
  dpop {
    enabled = true                  # default: false (secure-default opt-in)
    iat-window-seconds = 60
    alg-whitelist = ["ES256", "ES384", "EdDSA", "RS256"]
    replay-store = "memory"         # or "redis" for clustered deployments
    replay-store-ttl-seconds = 300
  }
  # Cross-mechanism dispatch policy (single source of truth in core):
  tokenBinding {
    dispatch-policy = "intent-explicit"   # or "strict-mutual-exclusion"
  }
}
```

Public-client tokens are bound to the DPoP JKT in both AT (`cnf.jkt`) and RT (`cnf.jkt`). Confidential clients get an AT-bound token + a plain RT (client_secret is the refresh-time authenticator per RFC 9449 §5). At refresh time the §9.2 5-row matrix enforces that the presented proof matches the persisted RT binding.

## Cross-mechanism dispatch (DPoP + mTLS)

When both `dpopModule` and `mtlsModule` are installed, the `oauth.tokenBinding.dispatch-policy` config key (owned by core's bundled `CoreConfigSchema`) decides what happens when both mechanisms succeed on the same request:

- `intent-explicit` (default) — DPoP wins because the DPoP header is explicit-intent; mTLS cert is ambient.
- `strict-mutual-exclusion` — both succeeding is rejected with HTTP 400 `invalid_request`.

See [the cross-mechanism dispatch refactor spec](../../.claude/superpowers/specs/2026-05-19-wave-2-cross-mechanism-dispatch-refactor-spec.md) for the design rationale and [packages/mtls/README.md](../mtls/README.md#cross-mechanism-dispatch-dpop--mtls) for the symmetric view from the mTLS side.

## Operator requirements

- Express's `trust proxy` MUST be configured when the AS sits behind a TLS-terminating reverse proxy. Without it, `req.protocol` returns `http` and DPoP proof verification fails every request (`htu_mismatch`).
- For multi-process / clustered deployments (PM2 cluster, Kubernetes replicas, etc.), the Redis replay store adapter is required. The in-memory adapter is for single-process dev / test use only.
