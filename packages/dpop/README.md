# @o3co/auth-provider-dpop

Last updated: 2026-09-26

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
  proof's `ath` when it accompanies an access token. `iat`, and an `exp` or
  `nbf` the proof carries, must be a NumericDate (core's `isNumericDate`:
  finite and within the Date range, a fraction allowed); JSON's `1e400` is a
  `malformed_proof`, not a clock outside the window;
- the key thumbprint that becomes the token's `cnf.jkt`;
- server-provided nonces (`use_dpop_nonce`, `DPoP-Nonce`);
- what a proof's replay record is: its `jti`, under a seen-set scope of its
  own per key (`dpop-proof:<jkt>`), kept for `replay-store-ttl-seconds`; and
  the boot refusal of an enabled mechanism with no seen-set to record in;
- the `dpop_signing_alg_values_supported` discovery field.

**Does not own:**

- which mechanism wins when mTLS is installed too, and the error that answers
  a conflict — core's dispatch policy (`oauth.tokenBinding.dispatch-policy`);
- whether a grant stamps the binding on the tokens it mints, and which refresh
  tokens are bound — the grants, on core's rules
  (`oauth.tokenBinding.bindConfidentialClientRefreshTokens`);
- matching a presented proof against a refresh token's stored binding — core's
  refresh-time matrix, [`core/src/grants/confirmationMatch.mts`](../core/src/grants/confirmationMatch.mts);
- where the replay records are kept. That is core's `ReplaySeenSet` port, the
  `replaySeenSet` slot that `private_key_jwt` client authentication and the
  WebAuthn challenge ceremony record in too;
  core's `memoryReplaySeenSetModule` and the replica-safety check that
  refuses it under `deployment.mode = "multi"`; and
  [`@o3co/auth-provider-redis`](../redis/README.md)'s `redisReplaySeenSetModule`,
  the one replicas share. The composition root installs one of them.

**Why a separate package.** Sender-constraint mechanisms are plug-ins to one
core slot, not part of core: a deployment chooses DPoP by installing it, core
holds no DPoP vocabulary, and a new mechanism needs no core change. It is off
by default even when installed (`oauth.dpop.enabled = false`).

## Status

Implemented: proof verification at the token endpoint, binding at protected
resources (`ath`), and server-provided nonces at both. Replay records are kept
in core's seen-set, so a deployment's replicas refuse each other's proofs
exactly when they share that set, and core's replica-safety check answers for
the memory one (see [Operator requirements](#operator-requirements)). Not
implemented: the `dpop_jkt` authorization-request parameter at `/authorize`
(RFC 9449 §10).

## Install

```sh
npm install @o3co/auth-provider-dpop @o3co/auth-provider-core
```

Peer dependency: `@o3co/auth-provider-core`. Optional peer dependency:
`express@^5.0.0`, whose types alone the package imports. The package depends
on `jose` and `zod`.

## Quick start

```typescript
import { createApp, memoryReplaySeenSetModule } from "@o3co/auth-provider-core";
import { dpopModule } from "@o3co/auth-provider-dpop";

const handle = await createApp({
    modules: [
        dpopModule,
        // Where each accepted proof is recorded. One replica: the memory
        // seen-set. Several: redisReplaySeenSetModule from
        // @o3co/auth-provider-redis, which every replica shares.
        memoryReplaySeenSetModule,
        /* + your other modules */
    ],
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
    replay-store-ttl-seconds = 300  # at least 2 × iat-window-seconds + 1
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
listed in [`src/index.mts`](src/index.mts). `oauth.dpop.replay-store` is
retired: the seen-set's own module chooses the backend, and a config that
still sets the key fails boot naming it.

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

A refused proof is a `DPoPError` with a `reason` (`DPoPReasonCode`) and this package's own fixed message; core's dispatcher logs it once, `token_binding_proof_invalid` / `protected_resource_binding_proof_invalid`, with the refusal's projection. The message never quotes what the client wrote — a `typ` that is not `dpop+jwt` is "typ is not dpop+jwt", an `alg` outside the allowlist "alg is not an accepted DPoP algorithm" — and `dpop_alg_not_allowed` (warn) names the refused `alg` only when it is a registered JWS algorithm, `unregistered` otherwise.

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

Every accepted proof is recorded in core's `ReplaySeenSet` — the
`replaySeenSet` slot, the same seen-set `private_key_jwt` client assertions
and consumed WebAuthn challenges are recorded in
([`core/src/replay-seen-set/types.mts`](../core/src/replay-seen-set/types.mts)).
The check is one `markSeen`, which records the value and answers whether this
call was the first to record it, as one atomic step: a check followed by a
separate write would let two concurrent requests both accept the same proof.
So of two requests carrying one proof, exactly one is accepted.

- **Key.** The proof's `jti`, under the scope `dpop-proof:<jkt>`. The same
  `jti` under another key is a different proof, not a replay, and the scope
  cannot collide with another consumer's (`client-assertion:<client_id>`,
  `webauthn:*`, or `jwt-bearer:id-jag:<issuer>` where a composition hands the
  jwt-bearer verifier the same set).
- **How long a `jti` may be.** At most 256 characters, and not empty (core's
  `MAX_JTI_LENGTH` / `isRecordableJti`, the bound `private_key_jwt` and ID-JAG
  apply too). The proof is checked before the client is authenticated, so
  whoever sends it chooses the key the seen-set keeps for
  `replay-store-ttl-seconds`; RFC 9449 §4.2 asks only that a `jti` be unique,
  which a UUID (36 characters) or 96 random bits (16 in base64url) already is.
  A longer one is `invalid_dpop_proof` (reason `malformed_proof`), refused in
  `parseProof` before the signature is checked and before the seen-set is
  consulted.
- **How long.** `replay-store-ttl-seconds` from the moment the proof is first
  accepted, which must be at least `2 × iat-window-seconds + 1` to outlive the
  proof's acceptance window; below that the mechanism logs
  `dpop_replay_ttl_below_window` (warn, `iatWindowSeconds`,
  `replayTtlSeconds`, `requiredTtlSeconds`; derivation: `replayTtlSeconds` in
  [`src/verifier.mts`](src/verifier.mts)). A value that is not a positive
  finite number is refused when the mechanism is built.
- **When the store fails.** A seen-set that cannot be reached refuses the
  request as the server's fault, not the proof's: `503 temporarily_unavailable`
  at the token endpoint and at a protected resource, with no
  `WWW-Authenticate` challenge (reason `replay_store_unavailable`). A seen-set
  that answers with its own contract error (a `RangeError`, or
  `expired-at-issue`) is broken rather than down: the same 503, with reason
  `replay_store_fault`, because the fix is in the composition, not in Redis.
  A seen-set that is full refuses the write the same way. Core's in-process
  set takes proofs only up to 90% of its cap (`replaySeenSet.memory.maxEntries`,
  a million records by default) and keeps the rest for its other consumers,
  so `private_key_jwt` and WebAuthn go on while DPoP is refused; that refusal
  is reason `replay_store_full` (`ReplaySeenSetFullError`, `reason: "full"`).
  A Redis at `maxmemory` under `noeviction` is `replay_store_unavailable`,
  and it refuses every consumer alike. Every proof is recorded before the
  token endpoint's rate limit and before a protected resource verifies the
  access token, so the rate that fills DPoP's share,
  `0.9 × maxEntries / replay-store-ttl-seconds`, is a rate anyone can send; a
  longer TTL lowers it in proportion. A Redis whose eviction policy deletes keys
  instead (`allkeys-*`, `volatile-*`) makes room by dropping replay records,
  and a dropped record is a proof that can be replayed within its window
  ([the redis package's Requirements](../redis/README.md#requirements)).
  Either way the mechanism hands the store's error upward as the refusal's
  `cause` and logs nothing itself: core's dispatcher that answers the 503
  writes the outage's one line at error level — `token_binding_unavailable`
  at the token endpoint, `protected_resource_binding_unavailable` at a
  protected resource — with `mechanism: "dpop"`, the `reason`, and core's
  [`loggableError`](../core/README.md#logger) projection of the store's
  error, never the error: ioredis puts the refused write — the record's key —
  on it. (These replace the mechanism's own `dpop_replay_store_unavailable`
  and `dpop_replay_store_fault` lines, which logged the same outage a second
  time.) A proof the signature step refuses is
  logged `dpop_signature_invalid` the same way, because jose puts the proof's
  whole payload on a claim failure. A proof is never accepted unrecorded,
  and it is not called invalid either — RFC 9449 keeps `invalid_dpop_proof`
  for a proof that failed its checks (§5, §7.1), and a resource's
  `401 invalid_token` would send the client to replace a token that is fine.
  The client retries later; the same answer `private_key_jwt` gives when its
  replay record cannot be written.
- **Ordering.** A proof refused for its nonce or its `ath` is refused before
  the seen-set is consulted, so it does not spend its `jti`.

The port has a conformance suite, and core's memory seen-set and the Redis one
both run it ([docs/adapter-surface.md](../../docs/adapter-surface.md)).

## Operator requirements

- **`oauth.jwt.issuer` MUST name the origin clients actually reach.** The `htu` a proof is checked against is built from the configured issuer's origin plus the path of the request, *not* from `req.protocol` and the `Host` header ([#292](https://github.com/o3co/auth.provider/issues/292)). Those two read `X-Forwarded-Proto` / `X-Forwarded-Host` whenever Express `trust proxy` is on, which would let a caller who could reach the AS past the edge choose the value its own proof had to match — satisfying both halves of the comparison at once. The issuer is a property of the deployment and no request can move it, which is the whole reason it is the right source. Boot fails with DPoP enabled and no issuer.

  The practical consequence: a deployment whose issuer is `https://auth.example.com` verifies proofs whose `htu` names `https://auth.example.com/...` regardless of what the proxy forwards, and **regardless of whether `trust proxy` is set at all**. If clients reach the AS at some other origin, that origin — not the internal one — is the issuer you should have configured. A path prefix on the issuer is ignored: the path comes from the request, which already carries the prefix the AS is mounted under.

  `http.trustProxy` still matters for IP-keyed rate limiting and for the CSRF origin check — it is simply not load-bearing for DPoP.
- **Replay protection across replicas needs a shared seen-set.** A per-process seen-set is per process: with several replicas, a proof replayed to a replica that did not see it is accepted. Install `redisReplaySeenSetModule` from [`@o3co/auth-provider-redis`](../redis/README.md) — `replaySeenSet.adapter = "redis"` in the standalone template — and every replica records in, and refuses from, the same set.

  With DPoP enabled and no seen-set wired, boot is refused in every `deployment.mode`: the mechanism would have nowhere to record a proof, so it could refuse no replay. There is no per-process fallback. Installed with `memoryReplaySeenSetModule`, the deployment gets core's replica-safety answer for that module, as for every other per-process store — DPoP adds no check of its own:

  | `deployment.mode` | What boot does |
  | --- | --- |
  | `"multi"` | Refuses: a `replica-unsafe-adapter` `BootError` naming `core-replay-seen-set-memory`, whose reason says a DPoP proof captured once can be replayed once against each replica. |
  | unset | Boots, and logs one `replica_unsafe_adapters` warning listing `core-replay-seen-set-memory` with every other per-process store. |
  | `"single"` | Silent: one replica, so the memory seen-set is correct. |

  The check reads the modules that are installed, so a per-process seen-set handed in as a bootstrap component (`createMemoryReplaySeenSet()`) is not seen by it and boots under `"multi"` without a warning. DPoP left disabled records nothing and needs no seen-set.

- **Installing a seen-set also turns on `private_key_jwt`.** The slot is shared, and a filled `replaySeenSet` is also where a `private_key_jwt` client assertion's `jti` is recorded — so filling it is what makes that method work. With the slot filled:
  - `@o3co/auth-provider-oauth` advertises `private_key_jwt`, with its signing algorithms, in `token_endpoint_auth_methods_supported` and in the introspection list (and in the revocation list while revocation is on), and accepts it at `/oauth/token`, `/oauth/introspect` and `/oauth/revoke` ([`oauth/src/module.mts`](../oauth/src/module.mts));
  - `@o3co/auth-provider-device-grant` accepts it at `POST /oauth/device_authorization` ([`device-grant/src/module.mts`](../device-grant/src/module.mts));
  - `@o3co/auth-provider-federation-grants` accepts it on every client route under `/oauth/federation-grants`: `POST /:grantId/token`, `/:grantId/status` and `/:grantId/revoke`, and, with acquisition on, `POST /` and `/:grantId/reauthorize` ([`federation-grants/src/routes.mts`](../federation-grants/src/routes.mts)).

  Without a seen-set, a client registered with `jwks` / `jwksUri` was refused `500 server_error` at every one of these. A composition that relied on DPoP's own store before v0.16.0, and now installs a seen-set for DPoP, turns all of them on. None is reachable without a client registered with keys, but the discovery document changes on its own, so check what it now offers.

- **Upgrading from a release with `oauth.dpop.replay-store`.** DPoP's Redis records move from `dpop:replay:<jkt>:<jti>` to the seen-set's `replay:…dpop-proof:<jkt>…` keys, and neither release reads the other's. While both serve against one Redis, a captured proof can be accepted once by an old replica and once by a new one. Each replica bounds a replay by its own `iat-window-seconds` (W): a proof the old release accepted can still be accepted by the new one for up to W<sub>old</sub> + W<sub>new</sub> + 1 seconds after the last old replica stops — 121 s at the default 60 on both — plus the largest clock skew between replicas. To avoid it:
  - cut over stop-then-start, starting the new release at least W<sub>old</sub> + W<sub>new</sub> + 1 seconds plus that skew after the last old replica stopped. No replica serves in the gap, so this is at least 121 s of downtime at the defaults, for every request, DPoP or not; or
  - run a lowered W on **both** releases for the roll: restart the old release with it first, then deploy the new release with it. With W = 5 on both, a proof has 11 s in which it can be replayed across releases, and the window closes 11 s after the last old replica stops. Lowering it on the old release alone is not enough: a replay to a new replica is bounded by the new release's W, so at 5 and 60 it stays open for 66 s after the last old replica stops. Put the full W back on the new release no earlier than W<sub>low</sub> + W<sub>full</sub> + 1 seconds after the last old replica stopped (66 s at 5 and 60): sooner reopens the window for proofs the old release accepted. Clients whose clocks are off by more than the lowered W are refused while it is lowered.

  The leftover `dpop:replay:*` keys expire by themselves within `replay-store-ttl-seconds` (300 s by default); nothing reads them and nothing needs deleting. Delete `oauth.dpop.replay-store` from the config **before** deploying: the new release refuses to boot while the key is set, and the old release reads its absence as its default `"memory"`, under which a wired `dpopReplayStore` is still the store it uses. Then deploy the new release with a seen-set module installed (`redisReplaySeenSetModule` for several replicas) and without the `dpopReplayStore` component, which is no longer read.
