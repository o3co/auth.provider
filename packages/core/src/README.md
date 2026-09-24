# core/src — directory map

Last updated: 2026-09-24

## Responsibility

`@o3co/auth-provider-core` is the provider's shared contracts and runtime: the ports every adapter implements, the domain rules every package agrees on, the in-process adapters a single replica can run on, and the boot planner that assembles a deployment. It is the one package every other package depends on, and it imports none of them. A contract several packages share lives here because those packages do not all depend on one another — `session` and `oauth` are independent, and `oauth-token-exchange` and `webauthn` do not depend on `oauth` — so core is the one place they all reach. Core owns no grant type, no durable adapter (`packages/redis`), no federation adapter (the `packages/federation-*` packages), no browser session (`packages/session`) and no `/oauth/*` endpoint (`packages/oauth`); the only route it mounts itself is the discovery document.

It stays one package on purpose (o3co/auth.provider#626). The directories below are its internal boundaries: this README says what each one owns, why it is separate, and which of those splits are enforced and which are a judgement kept by review. It also describes every directory that has no README of its own. How to use the package is [`../README.md`](../README.md).

## Rules for the whole tree

- Core imports no other `@o3co/auth-provider-*` package: its `package.json` names none, so such an import does not resolve. In product code the package's own name appears only in the `declare module "@o3co/auth-provider-core"` blocks that augment `ComponentMap`. `redis` / `ioredis` are never imported. `express` is an optional peer, imported for its types; at run time it is loaded only by `boot/` — `create-app.mts` imports it (`await import("express")`) for the router, and `assemble-app.mts` requires it (`createRequire`) for the `express()` factory `listen()` needs — and by `jwks/module.mts` (`createRequire`).
- No product code outside `boot/` imports `boot/` except the barrel (`index.mts`, `app.mts`) and `testing/`; tests elsewhere do, to boot a real app or to read `replicaUnsafeReason`. Product code never imports `testing/`.
- The contract directories (the first table below) and `config/` import one another, types and values, and the leaves. They import nothing from `boot/`, `routes/` or `testing/`. Three edges reach the HTTP group: `assertions/` and `config/` take values from `jwks/` (the remote key set; the JWKS path rule), and `modules/manifest/` takes the `TokenBindingMechanism` type from `middleware/`.
- `adapters/`, `logging/`, `errors/`, `net/` and `security/` are leaves: they import nothing else in core, except that `adapters/` takes types from `logging/` and `readiness/`.
- A directory that owns a storage port usually also owns its in-process adapter, an `AdapterFactory` with that adapter's builder registered, and — where core bundles one — the `memory…Module` that provides its slots. The exceptions: `mfa/` declares `MfaTransactionStore` and ships no adapter for it; `device-authorization/` has no `AdapterFactory`; `user-sessions/`'s factories register no builder, and its subject-keyed stores have no factory.
- Every bundled module whose name says `memory` declares `replicaSafety` on its manifest.

The first rule is enforced by the dependency graph, and the last by [`boot/__tests__/replica-safety.drift.test.mts`](./boot/__tests__/replica-safety.drift.test.mts), which checks the declaration and nothing else about a directory's layout. The others are not enforced by any test: they held when this README was written, and a change that breaks one states its reason here.

## Contracts and domain rules

The ports, the record types, and the rules every implementation must satisfy.

| Directory | Owns | Must not | Why it is separate |
| --- | --- | --- | --- |
| [`modules/manifest/`](./modules/manifest/README.md) | The manifest vocabulary: `defineModule`, `ModuleSpec`, `ComponentMap`, `ProviderDeps`, `ContributesMap`, `RouteContribution`, `AbsencePolicy`, `SYNTHETIC_COMPONENT_KEYS`. | Decide anything at run time; every check on a manifest is `boot/`'s. | It is its own package subpath (`./modules/manifest`), so a module is written against the vocabulary without the planner. |
| `modules/` | `PathResolver`; re-exports `manifest/`. | — | Not a boundary: it is the path bundled modules take `defineModule` from, and holds one type. |
| [`grants/`](./grants/README.md) | The grant-handler contract (`GrantHandler`, `GrantContext`), token minting, id_token / logout_token, the claim filter, policy evaluation, confirmation matching, and the internal `GrantRegistry`. | Own a grant type or an HTTP route; those are `packages/oauth` and the other grant packages. | Every grant package (`oauth`, `device-grant`, `oauth-token-exchange`, `webauthn`) implements this one contract, and they do not all depend on one another: `oauth-token-exchange` and `webauthn` depend only on core. |
| [`repositories/`](./repositories/README.md) | `ClientRepository`, `UserRepository`, `CodeRepository`, their records, the YAML / in-memory adapters, `createRepositoryFactories`, `isGrantTypeAllowed`. | Write to the Store; it is the system of record and core only reads it. | The Store's data model is read by `oauth`, `session`, `foundation` and `redis`; the records are where its semantics are written down, once. |
| [`user-sessions/`](./user-sessions/README.md) | The sid-keyed session stores, the subject-keyed index and revocation boundary, subject-wide revocation. | Own the browser cookie session (`packages/session`) or the per-session `cascadeLogout` (`packages/oauth`; injected). | Read by `oauth`, `session`, `redis` and `federation-grants`. The sid-keyed stores end with the session; the subject-keyed revocation boundary deliberately outlives it, for as long as the longest grant, token or session it covers. It reaches into `federation-grants/` for that grant lifetime ceiling and to end grants on a subject-wide revocation. |
| [`federations/`](./federations/README.md) | The federation adapter port: `FederationProvider`, `FederationProfile`, the capability interfaces with their guards, the reserved-parameter and identity-claim policy, the response-mode vocabulary, and the RFC 6749 scope and token-type grammar the federation paths share. | Own a route or a store; implement a federation. | The session router drives it, `oauth` reads it off `federationProviders`, `federation-grants` delegates through it and four adapter packages implement it. They do not all depend on one another — `session` and `oauth` are independent, and `federation-grants` depends on `oauth` but not on `session` — so the contract lives in core, which they all depend on. |
| [`federation-grants/`](./federation-grants/README.md) | Session-independent delegated access (#593): the grant and intent store ports, adapters, and the rules from lodging to retrieval and revocation. | Mount a route (`packages/federation-grants`) or call an upstream directly (the refresher is injected structurally). | A grant outlives the session it was agreed through; that lifetime is what separates it from `federation-tokens/`. The design record is its ADR. |
| `federation-tokens/` | The session-bound `(sid, federationName)` upstream token store, its memory adapter, factory and module, the optional lock capability, and `classifyFederationRefreshError`. See [its contract](#federation-tokens). | Let a record outlive its session. | Logout deletes these records — that is the boundary with `federation-grants/`. The refresh-error classifier is here because both token paths use it; whether it belongs to the adapter contract in `federations/` is a judgement call. |
| `token-exchange/` | `ExchangeTokenValidator` and `ValidatedToken`: the port a token-exchange validator implements. See [its contract](#token-exchange). | Own the token-exchange grant (`packages/oauth-token-exchange`). | That package registers validators as `tokenExchangeValidators` contributions and `boot/` collects them; core cannot import it, so the type both sides use is here. |
| `refresh-token-family/` | Refresh-token family rotation and revocation ports (RFC 6819 §5.2.2.3 replay detection), memory adapter, factory, module. | — | Each storage directory holds its own `ComponentMap` slots (here the store, rotation and revocation), its replica-safety declaration and — for all of these but `webauthn-credentials/` — a counterpart in `packages/redis`: port, adapter and module stay together. |
| `access-token-denylist/` | The revoked-`jti` port with its declared-absence policy, memory adapter, factory, module. | — | Its own slot. |
| `challenges/`, `replay-seen-set/` | Atomic challenge issue / consume and replay-detection primitives, the ceremony layered on them, memory adapters, factories, modules. | — | Their own slots (`challengeStore`, `challengeCeremony`, `replaySeenSet`). They share key canonicalisation and a storage error: the replay set's memory adapter imports `challenges/`, and the ceremony takes the `ReplaySeenSet` type. Whether they are one boundary is a judgement call. |
| `consents/` | The consent-record and pending-consent ports (#527), memory adapters, factory, module. | — | Its own slots (`consentStore`, `pendingConsentStore`). |
| `device-authorization/` | `DeviceCodeStore` (RFC 8628) as atomic operations, memory adapter, module, user-code helpers. | Expose `deviceCode` on the record. | Its own slot. It has no `AdapterFactory`: the slot is filled only by a module. |
| `webauthn-credentials/` | The WebAuthn credential store port, memory adapter, factory, module. | — | Its own slot. |
| `mfa/` | `MfaProvider` with its capability guards, the factory, the `MfaCoordinator` / `MfaTransactionStore` types, and `createMfaRouter` (`POST /auth/mfa/verify`). | Bundle a factor; none is here. | An extension point for a composition root; nothing in this repository wires it (see [the package README](../README.md#mfa)). It holds a router, which is HTTP — a judgement call. |
| `policy/` | `GrantPolicyHook` and its factory. | Evaluate a policy; `grants/grantPolicy.mts` does, with the ceiling rules. | The hook is a slot a consumer fills; its evaluation is shared grant logic and lives in `grants/`. |
| `audit/` | `AuditSink`, the pinned `BUILT_IN_AUDIT_EVENT_TYPES` inventory, factory, absence policy. | Block a flow; an emitter swallows sink failures. | Every package emits; the inventory is pinned in both directions by [`auditEventInventory.drift.test.mts`](./audit/__tests__/auditEventInventory.drift.test.mts). |
| `ratelimit/` | `RateLimiter`, memory adapter and module, the seeded limit specs and the guard. | — | Its own slot. The guard is an Express `RequestHandler` and the seeded specs name endpoints, which is HTTP — a judgement call. |
| `readiness/` | `ReadinessProbe`, the registrar builders register into, the runner. | Probe from the outside; only the builder holding a connection can register one. | Builders register through `BuilderContext` and `routes/Readiness.mts` runs what they registered; they meet here. |
| `assertions/` | jwt-bearer assertion verification and the issuer registry (#525). | Resolve identity; the Store does, from the opaque `subjectHandle`. | Possession is cryptography and is decided here; who the subject is belongs to the Store. It verifies third-party assertions with jose directly, and takes the remote key set from `jwks/`. |
| `keys/` | `KeyStore`, the local asymmetric / symmetric stores, `createRemoteSigningKeyStore`, the factory, the secret-entropy floor. | Bundle a vendor SDK. | One slot (`keyStore`), read by every package that signs or verifies. |
| `jwt/` | `verifyJwt`: verification of tokens this provider issued (`typ` pinning, denylist, subject boundary). | — | The surfaces that accept this provider's own tokens verify through it; third-party assertions are `assertions/`'s. |
| `issuer/` | Canonical validation of `oauth.jwt.issuer`. | Fall back to a request's `Host`. | Read by the config schema and by `oauth`'s re-check. |
| `discovery/` | `OidcDiscoveryContribution`, `buildDiscoveryDocument`, `discoveryPathsFor`, and the two hooks `boot/assemble-app.mts` calls: `planDiscoveryDocument` (whether a document is served, and the document, returning one that failed to validate as a value) and `discoveryRouteFor` (the route that serves it). | Mount anything itself, or import from `boot/`. | Keeps OIDC out of the generic planner: boot hands it values and gets an ordinary route contribution back. |
| `adapters/` | `AdapterFactory`, `BuilderContext`, `LifecycleRegistrar`. | — | A leaf every adapter-owning directory builds on. |
| `logging/` | `Logger` (pino-compatible), `EventLogger`, `consoleLogger`. | — | A leaf. |
| `errors/` | The RFC 6749 §5.2 error envelope. | — | A leaf. |
| `net/` | Loopback, origin, the redirect-URI grammar, canonical request URL, special-use addresses, trusted-proxy parsing. | — | A leaf: one home per network rule, most of them rows of the [design vocabulary](../../../docs/design-vocabulary.md). |
| `security/` | `constantTimeStringEqual`. | Be used where an input's length is itself secret (see its contract). | A leaf. |

### `federation-tokens/`

The port contract of the session-bound upstream token store, defined in [`federation-tokens/types.mts`](./federation-tokens/types.mts):

- Every field of `FederationTokens` is a required key — `expiresAt` holding `null` where the upstream named no finite expiry, the `string | undefined` fields holding `undefined` where there is nothing to record — so code that builds one and forgets a field fails to compile — [`record-fields.types.test.mts`](./federation-tokens/__tests__/record-fields.types.test.mts) (typecheck-included). That reaches a store's `get` and every caller of `attach` and `update`; it does not reach a store written in plain JavaScript or one that casts, which are held to the rules below alone.
- A store must round-trip every field through `attach`, `update` and `get`. A store that drops `tokenType` fails open — the record reads as one that named no type, and a sender-constrained token is handed on as a bearer one; a store that drops `grantedScope` loses the ceiling a refresh is bounded by. The memory adapter's defensive copy is pinned on it in [`memory.test.mts`](./federation-tokens/__tests__/memory.test.mts).
- `accessToken` is always a string. `expiresAt` is `Date | null`, and a store must hand `null` back as `null`: the token route reads it as "never refresh", and would throw on `undefined` — the memory adapter is pinned on it in `memory.test.mts`. The other fields are `string | undefined`; a store hands one with nothing recorded back as `undefined` or absent, never `null` — the token route refuses to disclose a token whose `tokenType` is `null`.
- A store must encrypt `refreshToken` at rest; plaintext is an explicit opt-in (the Redis adapter's `allow-plaintext`, with a warning), and the memory adapter is plaintext because the process boundary contains it.
- `update` replaces atomically; `delete` and `removeBySid` are idempotent. The lock is an optional capability (`SupportsLock`, detected with `supportsLock`) that both bundled stores implement.

What a store implementer has to change for the required keys is [docs/upgrading-required-record-keys.md](../../../docs/upgrading-required-record-keys.md).

### `token-exchange/`

The port a token-exchange validator implements, defined in [`token-exchange/validator.mts`](./token-exchange/validator.mts): one validator per `subject_token_type` / `actor_token_type` URI; `null` is a validation failure (`invalid_grant`), a throw is an infrastructure failure (`503 temporarily_unavailable`); a `ValidatedToken`'s structured fields are projections of its `claims`. The grant that consumes it is `packages/oauth-token-exchange`. The contract is pinned as the `tokenExchangeValidators` contribution type in [`__tests__/contributes-map-substitution.test.mts`](./__tests__/contributes-map-substitution.test.mts).

## Standard implementations

The in-process adapters live beside their port — `memory.mts`, `memory/`, `adapters/memory.mts` or `InMemory*.mts` in the directories above — usually with a `factory.mts` and, where a slot is provided, a `module.mts` exporting a `memory…Module`. Those modules are `REPLICA_UNSAFE_BUNDLED_MODULES` in [`boot/replica-safety.mts`](./boot/replica-safety.mts), and `deployment.mode = "multi"` refuses each of them by name. `repositories/InMemory*.mts` and `logging/consoleLogger.mts` are in-process too, but core ships no module for them: a composition root that provides them declares `replicaSafety` on its own module. `keys/` is not in this group — it holds the local key stores and `createRemoteSigningKeyStore`, a KMS/HSM-backed store. Durable adapters are `packages/redis`; the HTTP user repository is `packages/foundation`.

## HTTP

| Directory | Owns | Must not | Why it is separate |
| --- | --- | --- | --- |
| `middleware/` | `corsMw`, `tokenBindingMw` (composes the contributed mechanisms under the dispatch policy), `protectedResourceBindingMw`, and `express.mts` (the `./middleware/express.mjs` package subpath: the `Express.Request.tokenBinding` type augmentation). | Carry grant or route logic. | What `boot/assemble-app.mts` mounts ahead of every route: CORS when configured, token binding on `/oauth/token` when a mechanism was contributed, and the protected-resource check on every other path. |
| `routes/` | Healthcheck (liveness; never probes a dependency), Readiness, and the JWKS router that `jwks/module.mts` contributes. | — | Routers: a composition root mounts health and readiness itself, and the JWKS router arrives through `jwksModule`. |
| `jwks/` | Publishing this provider's key set (`jwksModule`, the path rule, `Cache-Control`) and fetching another party's (`createRemoteKeySetCache`, the one home for a `jwks_uri`). | Publish an empty or symmetric key set. | Two jobs under one name, a judgement call: the remote key set serves nothing, and is used by `assertions/` and by `oauth`'s client-assertion verifier. |

The `Authorization`-header parser that `protectedResourceBindingMw` and `packages/oauth` share sits at the `src/` root beside the barrel, not in a directory of its own.

## Where a boundary is a judgement call

None of these is enforced; each is recorded so a change can see it.

- `jwks/` and `routes/` import each other: `jwks/module.mts` contributes the JWKS router from `routes/`, and that router reads the path rule and `Cache-Control` from `jwks/`.
- `user-sessions/` and `federation-grants/` depend on each other at run time: subject-wide revocation ends grants through `federation-grants/`, and the grants' wiring rule reads a capability guard from `user-sessions/`. No import cycle crosses the two directories. The refresher and audit-event contract types sit in `federation-grants/retrieve.mts` rather than `federation-grants/types.mts`.
- `repositories/` imports `federation-grants/` for one reserved-parameter check, which loads the lodging module with it.
- In product code only `boot/` uses `grants/registry.mts`, wrapping it as the `grants` collector; `testing/` re-exports it for tests.
- `challenges/` / `replay-seen-set/`, `mfa/`, `ratelimit/`, `federation-tokens/` and `jwks/`: see their rows above.

## Boot

[`boot/`](./boot/README.md) is the six-stage planner behind `createApp`. `app.mts` re-exports it for import-path stability; `index.mts` is the public barrel. `package.json` exports `.`, `./modules/manifest`, `./testing`, `./middleware/express.mjs` and `./reference.conf`.

## Config

`config/` owns `AppConfigSchema` / `CoreConfigSchema` / `fullSectionsSchema`, `composeConfigSchema` (which stage 1 of boot runs over every module's schema), the removed-key refusals and the lifetime readers. It takes the issuer, secret-entropy, network and JWKS-path rules from their homes rather than restating them. Defaults live in [`../config/reference.conf`](../config/reference.conf), not in the schema (ADR [2026-04-30](../docs/adr/2026-04-30-config-schema-strict-defaults-from-hocon.md)). See [Configuration](../README.md#configuration).

## Testing support

`testing/` is the `@o3co/auth-provider-core/testing` subpath: `createTestApp`, `TestInspect`, the config fixtures, and the `GrantRegistry` re-export for tests that build a registry by hand. It is separate so that test helpers ship on their own subpath and product code never loads them. `__tests__/` at this level holds the package-wide tests: the barrel, the drift guards, and the compile-time contracts that span directories.
