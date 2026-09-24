# @o3co/auth-provider-dpop

Last updated: 2026-09-24

DPoP ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)) sender-constrained
tokens for [`auth.provider`](../../README.md): a token issued against a DPoP
proof is bound to the client's key, and is refused from anyone who cannot sign
with it.

## Responsibility

**Role.** The DPoP mechanism behind core's token-binding slot. Core defines
what a sender-constraint mechanism is — `TokenBindingMechanism`, in
[`core/src/middleware/tokenBinding.mts`](../core/src/middleware/tokenBinding.mts)
— and the `TokenBinding` it produces
([`core/src/grants/tokenBinding.mts`](../core/src/grants/tokenBinding.mts)).
Core composes one `tokenBindingMw` at `/oauth/token` from every mechanism
installed, and one protected-resource check from the same list. `dpopModule`
contributes the DPoP mechanism to both.

**Owns:**

- verifying a DPoP proof — structure, the `alg` allowlist, the signature over
  the embedded key, `htm` / `htu`, the `iat` window, `jti` replay — and the
  proof's `ath` when it accompanies an access token;
- the key thumbprint that becomes the token's `cnf.jkt`;
- server-provided nonces (`use_dpop_nonce`, `DPoP-Nonce`);
- the `DPoPReplayStore` port, its in-process implementation, and the optional
  `dpopReplayStore` slot a shared one goes in;
- the `dpop_signing_alg_values_supported` discovery field.

**Does not own:**

- which mechanism wins when mTLS is installed too, and the error that answers
  a conflict — core's dispatch policy (`oauth.tokenBinding.dispatch-policy`);
- whether a grant stamps the binding on the tokens it mints, and which refresh
  tokens are bound — the grants, on core's rules
  (`oauth.tokenBinding.bindConfidentialClientRefreshTokens`);
- matching a presented proof against a refresh token's stored binding — core's
  refresh-time matrix, [`core/src/grants/confirmationMatch.mts`](../core/src/grants/confirmationMatch.mts);
- a shared replay store. [`@o3co/auth-provider-redis`](../redis/README.md#dpop-replay-store)
  has one; the composition root wires it.

**Why a separate package.** Sender-constraint mechanisms are plug-ins to one
core slot, not part of core: a deployment chooses DPoP by installing it, core
holds no DPoP vocabulary, and a new mechanism needs no core change. It is off
by default even when installed (`oauth.dpop.enabled = false`).

## Status

Implemented: proof verification at the token endpoint, binding at protected
resources (`ath`), and server-provided nonces at both. Not implemented: the
`dpop_jkt` authorization-request parameter at `/authorize` (RFC 9449 §10).

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
    replay-store = "memory"         # or "redis" — see Operator requirements
    replay-store-ttl-seconds = 300
  }
  # Cross-mechanism dispatch policy (owned by core):
  tokenBinding {
    dispatch-policy = "intent-explicit"   # or "strict-mutual-exclusion"
  }
}
```

The defaults are the ones shown; the module's schema applies them, and the
package ships them as HOCON in [`src/reference.conf`](src/reference.conf)
(exported as `@o3co/auth-provider-dpop/reference.conf`). The public exports are
listed in [`src/index.mts`](src/index.mts).

**Which tokens are bound.** A public client's access token and refresh token
both carry `cnf.jkt`. A confidential client's access token is bound and its
refresh token is not by default — its client secret is the refresh-time
authenticator (RFC 9449 §5) — unless the deployment sets
`oauth.tokenBinding.bindConfidentialClientRefreshTokens = true`. At refresh,
core's matrix ([`confirmationMatch.mts`](../core/src/grants/confirmationMatch.mts))
requires the presented proof to match the refresh token's stored binding.

## Cross-mechanism dispatch (DPoP + mTLS)

When both `dpopModule` and `mtlsModule` are installed, the `oauth.tokenBinding.dispatch-policy` config key (declared by core's config schema) decides what happens when both mechanisms succeed on the same request:

- `intent-explicit` (default) — DPoP wins because the DPoP header is explicit-intent; mTLS cert is ambient.
- `strict-mutual-exclusion` — both succeeding is rejected with HTTP 400 `invalid_request`.

See [ADR 2026-05-20-token-binding-first-class-abstraction.md](../core/docs/adr/2026-05-20-token-binding-first-class-abstraction.md) for the design rationale and [packages/mtls/README.md](../mtls/README.md#cross-mechanism-dispatch-dpop--mtls) for the symmetric view from the mTLS side.

## Discovery metadata

When `oauth.dpop.enabled = true`, this module contributes `dpop_signing_alg_values_supported` (RFC 9449 §5.1) to `/.well-known/openid-configuration`, carrying the configured `alg-whitelist` verbatim. It is the same read the proof verifier is constructed from, so an algorithm a client picks off discovery is one this deployment will accept.

Nothing is contributed while DPoP is disabled — a client then has no way to tell this module apart from an uninstalled one, which is accurate.

## Server-provided nonces (RFC 9449 §8 / §9)

Without a nonce the only freshness control on a proof is `iat` skew, which is weak for tokens that live longer than a few minutes: a proof minted ahead of time stays usable for the whole window. `oauth.dpop.nonce.required` turns nonces on:

- `"as"` — the token endpoint asks. A proof without a valid `nonce` claim gets `400 use_dpop_nonce` with a `DPoP-Nonce` header, and the client retries with that value in the proof.
- `"as+rs"` — protected resources (core's `protectedResourceBindingMw`) ask too: `401` with `WWW-Authenticate: DPoP error="use_dpop_nonce"` and the `DPoP-Nonce` header.
- `"never"` (the default) — no nonce.

The nonce is **stateless**: a time bucket and an HMAC under `oauth.dpop.nonce.secret` (`OAUTH_DPOP_NONCE_SECRET`, at least 32 bytes of key material measured on the decoded value as core's secret floor measures every operator secret — `openssl rand -base64 32`; shared by every replica). Nothing is stored and nothing is looked up on the proof path; a nonce minted by one replica verifies on every other, and the replay store is never consulted for a proof refused on its nonce — the client is about to present the same `jti` again with the nonce filled in. The bucket rotates every `ttl-seconds` (default 300) and the previous bucket stays accepted, so a client that received a nonce just before the boundary is not refused a moment later. Every accepted proof's answer carries the current nonce as well, so a client learns of a rotation before it needs to. A nonce is not single-use — replay of the *proof* is what `jti` and the replay store refuse; the nonce only bounds when the proof could have been made.

Boot refuses `required` without a `secret`: a per-replica random key would mint nonces no other replica could verify. There is no discovery-metadata flag for nonces — RFC 9449 signals the requirement at runtime with `use_dpop_nonce`, and a client that supports DPoP handles it there.

## Replay store

The port is `DPoPReplayStore` ([`src/replay-store.mts`](src/replay-store.mts)): `seen(jti, jkt, ttlSeconds)` records the pair and answers whether it had already been seen, as one atomic step — a check followed by a separate write would let two concurrent requests both accept the same proof. It is scoped by `jkt`, so the same `jti` under a different key is not a replay. The in-process implementation ([`src/memory/replay-store.mts`](src/memory/replay-store.mts)) is correct for one process; [`@o3co/auth-provider-redis/dpop`](../redis/README.md#dpop-replay-store) provides a shared one. There is no conformance suite for the port: each implementation is covered by its own tests.

## Operator requirements

- **`oauth.jwt.issuer` MUST name the origin clients actually reach.** The `htu` a proof is checked against is built from the configured issuer's origin plus the path of the request, *not* from `req.protocol` and the `Host` header ([#292](https://github.com/o3co/auth.provider/issues/292)). Those two read `X-Forwarded-Proto` / `X-Forwarded-Host` whenever Express `trust proxy` is on, which would let a caller who could reach the AS past the edge choose the value its own proof had to match — satisfying both halves of the comparison at once. The issuer is a property of the deployment and no request can move it, which is the whole reason it is the right source. Boot fails with DPoP enabled and no issuer.

  The practical consequence: a deployment whose issuer is `https://auth.example.com` verifies proofs whose `htu` names `https://auth.example.com/...` regardless of what the proxy forwards, and **regardless of whether `trust proxy` is set at all**. If clients reach the AS at some other origin, that origin — not the internal one — is the issuer you should have configured. A path prefix on the issuer is ignored: the path comes from the request, which already carries the prefix the AS is mounted under.

  `http.trustProxy` still matters for IP-keyed rate limiting and for the CSRF origin check — it is simply not load-bearing for DPoP.
- **Replay protection across replicas needs a shared store, and nothing enforces it for you.** The in-process replay store is per process: with several replicas, a proof replayed to a replica that did not see it is accepted. Wire a shared store in the `dpopReplayStore` slot — [`@o3co/auth-provider-redis/dpop`](../redis/README.md#dpop-replay-store) — and set `replay-store = "redis"`, which makes boot fail if the slot is empty. `replay-store = "memory"` (the default) boots under `deployment.mode = "multi"` too: `dpopModule` does not take part in core's replica-safety check.
