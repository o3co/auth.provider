# core/src — responsibility map

`@o3co/auth-provider-core` is the provider's shared contracts and runtime: the ports every adapter implements, the domain rules every package agrees on, the in-process adapters a single replica can run on, and the boot planner that assembles a deployment. It stays one package on purpose (o3co/auth.provider#626, P3); this map says which directory owns which decision so the boundaries hold without a split.

Rules that hold for the whole tree (checked by grep at the time of writing; `__tests__/` pins several of them):

- No import statement in `src/` names a sibling `@o3co/auth-provider-*` package; the only `@o3co/auth-provider-core` mentions in code are the `declare module` augmentations of `ComponentMap` (plus three test files that import the package by its own name, in four import statements). A contract a sibling package needs lives here; core never reaches back into a sibling. `redis` / `ioredis` are never imported, and `express` is an optional peer used as a type; where a router is built it is loaded lazily — `await import("express")` in `boot/create-app.mts`, with `createRequire` as the fallback in `boot/assemble-app.mts` and the mechanism in `jwks/module.mts`.
- Product code never imports `testing/`; only `__tests__/` and downstream test code do.
- Outside `__tests__/`, nothing imports `boot/` except the barrel (`index.mts`, `app.mts`) and `testing/`; elsewhere, three wiring tests boot a real app through it and three adapter tests read `replicaUnsafeReason` from it. `discovery/planRoute.mts` was the one exception until #626 F4 took `BootError` out of it.
- A directory that owns a port also owns its in-process adapter, its `AdapterFactory` builder and, where there is one, the bundled `memory…Module` that provides the slot and declares `replicaSafety` (`boot/__tests__/replica-safety.drift.test.mts`).

Package-level documentation is [`../README.md`](../README.md). Directories with a README of their own are linked below; a small directory is described here by its parent rather than given one.

## Contracts and domain rules

The ports, the record types, and the rules every implementation must satisfy. These directories import one another's types plus `adapters/`, `config/`, `logging/`, `net/` and `security/`; none imports `routes/` or `testing/`, and one crosses the line drawn here: `modules/manifest/contributes-map.mts` takes the `TokenBindingMechanism` type from `middleware/tokenBinding.mts` (type-only). `discovery/planRoute.mts` was the second and the only one that took a VALUE — `BootError`, to raise one — until #626 F4 gave it its inputs instead and left the conversion to the stage that owns the taxonomy.

| Directory | Owns | Must not |
| --- | --- | --- |
| [`modules/manifest/`](./modules/manifest/README.md) | The manifest vocabulary: `defineModule`, `ModuleSpec`, `ComponentMap`, `ProviderDeps`, `ContributesMap`, `RouteContribution`, `AbsencePolicy`, `SYNTHETIC_COMPONENT_KEYS`. | Decide anything at runtime; every check on a manifest is `boot/`'s. |
| `modules/` | `PathResolver`; re-exports `manifest/`. | — |
| [`grants/`](./grants/README.md) | The grant-handler contract (`GrantHandler`, `GrantContext`), token minting, id_token / logout_token, the claim filter, policy evaluation, confirmation matching, the internal `GrantRegistry`. | Own a grant type or an HTTP route; those are `packages/oauth` and its siblings. |
| [`repositories/`](./repositories/README.md) | `ClientRepository`, `UserRepository`, `CodeRepository`, their records, the YAML / in-memory adapters, `createRepositoryFactories`, `isGrantTypeAllowed`. | Write to the Store; it is the system of record and core only reads it. |
| [`user-sessions/`](./user-sessions/README.md) | The sid-keyed session stores, the subject-keyed index and revocation boundary, subject-wide revocation. | Own the browser cookie session (`packages/session`) or the per-session `cascadeLogout` (`packages/oauth`; injected). |
| `federations/` | The federation adapter port: `FederationProvider`, `FederationProfile`, the capability interfaces (`SupportsLogout`, `SupportsRefresh`, `SupportsClaimMapping`, `SupportsDelegatedAuthorization`) with their guards, the reserved-parameter and identity-claim policy, and the response-mode vocabulary. It is here because the session router drives it, `oauth` reads it off `federationProviders` and `federation-grants` delegates through it — three packages that may not import one another (#626 P1). | Own a route or a store. It describes what the route layer does with a declaration — `responseMode` is meaningless otherwise — and `packages/session` is where that layer, its transaction cookie and `FederationResult` live. |
| [`federation-grants/`](./federation-grants/README.md) | Session-independent delegated access (#593): the grant and intent store ports, adapters, and the rules from lodging to retrieval and revocation. | Mount a route (`packages/federation-grants`) or call an upstream directly (the refresher is injected structurally). |
| `federation-tokens/` | The session-bound `(sid, federationName)` upstream token store, its memory adapter and module, the optional lock capability, `classifyFederationRefreshError`. Logout deletes these records — that is the boundary with `federation-grants/`. | Let a record outlive its session. |
| `refresh-token-family/` | Refresh-token family rotation and revocation ports (RFC 6819 §5.2.2.3 replay detection), memory adapter, factory, module. | — |
| `access-token-denylist/` | The revoked-`jti` port with its declared-absence policy, memory adapter, factory, module. | — |
| `challenges/`, `replay-seen-set/` | Atomic challenge issue / consume and replay-detection primitives (A1), the ceremony layered on them, memory adapters, modules. | — |
| `consents/` | The consent-record port (#527), memory adapter, module. | — |
| `device-authorization/` | `DeviceCodeStore` (RFC 8628) as atomic operations, memory adapter, module, user-code helpers. | Expose `deviceCode` on the record. |
| `webauthn-credentials/` | The WebAuthn credential store port, memory adapter, factory, module. | — |
| `mfa/` | `MfaProvider` with its capability guards, the factory, and `createMfaRouter` (`POST /auth/mfa/verify`). | Bundle a factor; none is here. |
| `policy/` | `GrantPolicyHook` and its factory. | Evaluate a policy; `grants/grantPolicy.mts` does, with the ceiling rules. |
| `audit/` | `AuditSink`, the pinned `BUILT_IN_AUDIT_EVENT_TYPES` inventory, factory, absence policy. | Block a flow; an emitter swallows sink failures. |
| `ratelimit/` | `RateLimiter`, memory adapter and module, the seeded limit specs and the guard. | — |
| `readiness/` | `ReadinessProbe`, the registrar builders register into, the runner. | Probe from the outside; only the builder holding a connection can register one. |
| `assertions/` | jwt-bearer assertion verification and the issuer registry (#525). | Resolve identity; the Store does, from the opaque `subjectHandle`. |
| `keys/` | `KeyStore`, the local asymmetric / symmetric stores, `createRemoteSigningKeyStore`, the factory, the secret-entropy floor. | Bundle a vendor SDK. |
| `jwt/` | `verifyJwt`, the one verifier every surface uses (`typ` pinning, denylist, subject boundary). | — |
| `issuer/` | Canonical validation of `oauth.jwt.issuer`. | Fall back to a request's `Host`. |
| `discovery/` | `OidcDiscoveryContribution`, `buildDiscoveryDocument`, `discoveryPathsFor`, and `planDiscoveryRoute` — the hook `boot/assemble-app.mts` calls, as a function of four values rather than of the boot world (#626 F4). | Mount anything itself, or import from `boot/`. |
| `adapters/` | `AdapterFactory`, `BuilderContext`, `LifecycleRegistrar`. | — |
| `logging/` | `Logger` (pino-compatible), `EventLogger`, `consoleLogger`. | — |
| `errors/` | The RFC 6749 §5.2 error envelope. | — |
| `net/` | Loopback, origin, the redirect-URI grammar, canonical request URL, special-use addresses, trusted-proxy parsing. | — |
| `security/` | `constantTimeStringEqual`. | Be used where an input's length is itself secret (see its contract). |

## Standard implementations

The in-process adapters live beside their port — `memory.mts`, `memory/`, `adapters/memory.mts` or `InMemory*.mts` in the directories above — each with a `factory.mts` and, where a slot is provided, a `module.mts` exporting a `memory…Module`. Those twelve modules are `REPLICA_UNSAFE_BUNDLED_MODULES` in `boot/replica-safety.mts`, and `deployment.mode = "multi"` refuses each of them by name. `repositories/InMemory*.mts` and `logging/consoleLogger.mts` are in-process too, but core ships no module for them: a composition root that provides them declares `replicaSafety` on its own module (#455). `keys/` is not in this group — it holds the local key stores and `createRemoteSigningKeyStore`, a KMS/HSM-backed store. Durable adapters are `packages/redis`; the HTTP user repository is `packages/foundation`.

## HTTP

| Directory | Owns | Must not |
| --- | --- | --- |
| `middleware/` | `corsMw`, `tokenBindingMw` (composes the contributed mechanisms under the dispatch policy), `protectedResourceBindingMw`, and `express.mts` (the `./middleware/express.mjs` package subpath: the `Express.Request.tokenBinding` type augmentation). The middleware is mounted by `boot/assemble-app.mts`. | Carry grant or route logic. |
| `routes/` | Healthcheck (liveness; never probes a dependency), Readiness, and the JWKS router that `jwks/module.mts` contributes. | — |
| `accessTokenHeader.mts` | Parsing the `Authorization` header into a scheme and token, shared by resource binding and `packages/oauth`. | — |
| `jwks/` | `jwksModule` (the route contribution), the remote key set with its cache, path resolution. | Publish an empty or symmetric key set. |

## Boot

[`boot/`](./boot/README.md) is the six-stage planner behind `createApp`. `app.mts` re-exports it for import-path stability; `index.mts` is the public barrel. `package.json` exports `.`, `./modules/manifest`, `./testing`, `./middleware/express.mjs` and `./reference.conf`.

## Config

`config/` owns `AppConfigSchema` / `CoreConfigSchema` / `fullSectionsSchema`, `composeConfigSchema` (what `boot/validate-manifests.mts` runs as its step 13), the removed-key refusals and the lifetime readers. Defaults live in [`../config/reference.conf`](../config/reference.conf), not in the schema (ADR [2026-04-30](../docs/adr/2026-04-30-config-schema-strict-defaults-from-hocon.md)). See [Configuration](../README.md#configuration).

## Testing support

`testing/` is the `@o3co/auth-provider-core/testing` subpath: `createTestApp`, `TestInspect`, the config fixtures, and the `GrantRegistry` re-export for tests that build a registry by hand. Product code must not import it (checked: no file under `src/` outside `testing/` and `__tests__/` does). `__tests__/` at this level holds the package-wide tests: the barrel, config composition, the drift tests (adapter surface, campaign and design vocabulary), the compile-time readonly contracts for `GrantContext` and the repository records, and the contributes-map substitution pins.
