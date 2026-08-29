# @o3co/auth-provider-dpop

DPoP (RFC 9449) sender-constrained access token support for [@o3co/auth-provider].

## Status

Stage 1 (token-endpoint binding). Stage 2 will add nonce challenge (RFC 9449 §8) and the `dpop_jkt` query parameter at `/authorize` (RFC 9449 §10).

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

Public-client tokens are bound to the DPoP JKT in both AT (`cnf.jkt`) and RT (`cnf.jkt`). Confidential clients get an AT-bound token + a plain RT (client_secret is the refresh-time authenticator per RFC 9449 §5). At refresh time the refresh-time token-binding enforcement matrix (the "§9.2 matrix", core `confirmationMatch.mts`) enforces that the presented proof matches the persisted RT binding.

## Cross-mechanism dispatch (DPoP + mTLS)

When both `dpopModule` and `mtlsModule` are installed, the `oauth.tokenBinding.dispatch-policy` config key (owned by core's bundled `CoreConfigSchema`) decides what happens when both mechanisms succeed on the same request:

- `intent-explicit` (default) — DPoP wins because the DPoP header is explicit-intent; mTLS cert is ambient.
- `strict-mutual-exclusion` — both succeeding is rejected with HTTP 400 `invalid_request`.

See [ADR 2026-05-20-token-binding-first-class-abstraction.md](../core/docs/adr/2026-05-20-token-binding-first-class-abstraction.md) for the design rationale and [packages/mtls/README.md](../mtls/README.md#cross-mechanism-dispatch-dpop--mtls) for the symmetric view from the mTLS side.

## Discovery metadata

When `oauth.dpop.enabled = true`, this module contributes `dpop_signing_alg_values_supported` (RFC 9449 §5.1) to `/.well-known/openid-configuration`, carrying the configured `alg-whitelist` verbatim. It is the same read the proof verifier is constructed from, so an algorithm a client picks off discovery is one this deployment will accept.

Nothing is contributed while DPoP is disabled — a client then has no way to tell this module apart from an uninstalled one, which is accurate.

## Operator requirements

- **`oauth.jwt.issuer` MUST name the origin clients actually reach.** Since [#292](https://github.com/o3co/auth.provider/issues/292) the `htu` a proof is checked against is built from the configured issuer's origin plus the path of the request, *not* from `req.protocol` and the `Host` header. Those two read `X-Forwarded-Proto` / `X-Forwarded-Host` whenever Express `trust proxy` is on, which let a caller who could reach the AS past the edge choose the value its own proof had to match — satisfying both halves of the comparison at once. The issuer is a property of the deployment and no request can move it, which is the whole reason it is the right source.

  The practical consequence: a deployment whose issuer is `https://auth.example.com` verifies proofs whose `htu` names `https://auth.example.com/...` regardless of what the proxy forwards, and **regardless of whether `trust proxy` is set at all**. If clients reach the AS at some other origin, that origin — not the internal one — is the issuer you should have configured; DPoP is now one more thing that says so. A path prefix on the issuer is ignored: the path comes from the request, which already carries the prefix the AS is mounted under.

  `http.trustProxy` still matters for IP-keyed rate limiting and for the CSRF origin check — it is simply no longer load-bearing for DPoP.
- For multi-process / clustered deployments (PM2 cluster, Kubernetes replicas, etc.), the Redis replay store adapter is required. The in-memory adapter is for single-process dev / test use only.
