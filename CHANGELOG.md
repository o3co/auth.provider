# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Breaking Changes (Phase 1-9 — Module System Redesign)

#### Module manifest pipeline (A2-α/β/γ)

- `createApp(options): { init, router, grantRegistry }` (sync) — **REPLACED** by
  `createApp(options): Promise<AppHandle>` (async). The two-phase
  `createApp(...); await init()` boot model is gone. (per A2-β §9, A2-γ §3.1)
- `AppOptions` interface — **DELETED**. Replaced by `CreateAppOptions<B extends BootstrapMap>`. (per A2-β §9)
- `AppResult` interface — **DELETED**. Replaced by `AppHandle`. (per A2-β §9)
- `Module` interface (with `name`, `configSchema?`, `init(ctx)`) — **REPLACED** by
  the A2-α `Module` (erased form of `ModuleSpec<R, O>`). The `init` callback is
  gone; `ModuleSpec` adds `requires` / `optional` / `provides` / `contributes` /
  `overrides` / `lifecycle`. Use `defineModule({...})` to author modules.
  (per A2-α §3, A2-γ §3.1)
- `ModuleContext` interface — **DELETED**. The v0.4.x god-bag's responsibilities are
  decomposed into the typed `ComponentMap` consumed via `requires`. (per A2-γ §3.1, A6+A7 §3.2)
- `GrantRegistry` class — **REMOVED** from `@o3co/auth-provider-core` public exports.
  The class survives as an internal boot-planner collector only. Consumers who
  called `new GrantRegistry()` / `register(...)` directly migrate to
  `defineModule({ contributes: { grants: { "my:grant": (deps) => ... } } })`.
  (per A2-γ §3.1, A6+A7 §3.5)
- `GrantModule` type (`{ grants: Record<string, GrantFactory> }`) — **DELETED**.
  Use the unified `defineModule({ contributes: { grants } })` shape. (per A2-γ §3.1)
- `addModule(GrantModule, deps)` — **DELETED**. Replaced by
  `createApp({ modules: [defineModule(...), ...] })`. (per A6+A7 §3.4, A2-γ §3.1)
- `FederationProviderHandle` interface — **DELETED**. `federationProviders` becomes a
  synthetic `ComponentMap` slot (`ReadonlyMap<string, FederationProvider>`) projected
  by the planner's `federations` collector. (per A2-γ §3.1)
- `LegacyModule` and `ModuleContext` types — **DELETED** from
  `@o3co/auth-provider-core`. v0.4.x modules (functions returning
  `{ name, init(context) }`) must be rewritten as v0.5.0 manifests via
  `defineModule({...})`. (per A2-γ §2.4, A2-γ §9.4)
- **No deprecation shim**: `createAppLegacy`, `registerGoogleFederation` /
  `registerGithubFederation` imperative wrappers, and `registerBuiltinAdapters`
  shims are all **explicitly rejected**. v0.5.0 is a clean break.
  (per A2-γ §9.4)
- `oauthModule({ clientRepository, codeRepository, express? })` factory signature
  changes to `oauthModule({ config })`. Deps flow through `requires`.
  (per A2-γ §3.2.1)
- `oauthAuthorizationModule({ codeRepository, clientRepository })` becomes
  `oauthAuthorizationModule({ config })`. `module.init(ctx)` and
  `ctx.grantRegistry.register(...)` calls are gone. (per A2-γ §3.2.2)
- `oauthSessionModule({ clientRepository })` becomes `oauthSessionModule({ config })`.
  `init` and `grantRegistry.register` are gone. (per A2-γ §3.2.3)
- `ExchangeTokenValidatorRegistry` class — **REMOVED** from
  `@o3co/auth-provider-oauth-token-exchange` public exports. The v0.4.x pattern
  of `new ExchangeTokenValidatorRegistry(); registry.register(...);
  addModule(tokenExchangeModule, { validatorRegistry })` is replaced by a consumer
  module: `defineModule({ contributes: { tokenExchangeValidators:
  { "urn:my:type": (deps) => myValidator } } })`. (per A2-γ §3.3)
- `registerBuiltinAdapters({ userFactory, codeFactory, pathResolver? })` from
  `@o3co/auth-provider-foundation` — **signature narrowed** to
  `registerBuiltinAdapters({ userFactory })`. The `codeFactory` and
  `pathResolver` parameters are removed; foundation only registers the `"http"`
  user-authentication adapter. The Redis `CodeRepository` was relocated to
  `@o3co/auth-provider-redis` (Phase 10). Consumers needing Redis code storage
  call `codeFactory.register("redis", redisCodeRepositoryBuilder)` directly
  after importing from `@o3co/auth-provider-redis`. (per Phase 10 + interface
  review pre-tag M3/M4)

#### Registry policy (A6+A7)

- `GrantRegistry.register(name, value)` — **semantics changed**: silent overwrite
  in v0.4.x → **throws** `BootError` on duplicate in v0.5.0. Use
  `overrides.grants` in a module manifest for intentional override.
  (per A6+A7 §2.1)
- `ExchangeTokenValidatorRegistry.register(name, value)` — **semantics changed**:
  silent overwrite pre-freeze → **throws** on duplicate (regardless of freeze state).
  (per A6+A7 §2.1)
- `AdapterFactory.replace(name, builder)` — **added** additively; `register`
  continues to throw on duplicate (no change). (per A6+A7 §2.2)
- Duplicate-on-`register` for `GrantRegistry` / `ExchangeTokenValidatorRegistry`
  now throws immediately; consumers depending on silent overwrite (e.g. test code
  that re-registered) migrate to `overrides` (manifest-level explicit replacement).
  (per A6+A7 §3.5)

#### Challenge store + replay-seen-set (A1)

- `ChallengeStore` and `ReplaySeenSet` are **net-additive** to v0.5.0 develop (PR
  #96 was closed unmerged; `SingleUseTokenStore` was never shipped). Consumers
  installing `@o3co/auth-provider-redis` for the redis adapters must add the
  package as a direct dependency; core's redis adapter is memory-only.
  (per A1 §4 "Breaking changes vs PR #96 spec")

#### Refresh-token family (A3)

- `RefreshTokenStoreBase` interface — **DELETED** from `@o3co/auth-provider-core`.
  Consumers who implemented it migrate as follows: (per A3 §4 "Breaking changes vs v0.4.x")
  - **Interface rename**: `RefreshTokenStoreBase` → `RefreshTokenFamilyStore`.
    Method shape changes drastically; not a transparent rename.
  - **Adapter responsibility narrows**: `rotate(...)`, `isFamilyRevoked(...)`, and
    `revokeFamily(...)` move out of the storage adapter and into wrapper interfaces
    (`RefreshTokenFamilyRotation`, `RefreshTokenFamilyRevocation`).
  - **Outcome union renamed and shifted**: `RefreshTokenRotateOutcome` →
    `RefreshTokenFamilyRotationOutcome`; the `unknown` variant is renamed `unknown_family`;
    the `replayed` variant loses its `familyId` field (the wrapper caller already has
    `familyId` in scope). (per A3 §4)
  - **`rotate(previousJti=null, ...)` overload deleted**: initial issue moves to
    `RefreshTokenFamilyRotation.register(jti, familyId, expiresAtMs)`. (per A3 §4)
  - **`expiresAt` parameter type changed** from `Date` to epoch-ms `number` in
    `RefreshTokenFamilyRotation.rotate(prev, new, familyId, expiresAtMs)` and
    `RefreshTokenFamilyRotation.register(jti, familyId, expiresAtMs)` — defence against
    `Date.setTime` mutation. (per A3 §5.1)
- All in-tree callers (`authorization.mts`, `refreshToken.mts`, `cascadeLogout.mts`,
  `userinfo.mts`, `federationToken.mts`) are rewired to the new wrapper interfaces
  in v0.5.0. (per A3 §4, §9)

#### User-session decomposition (A4)

- `UserSessionStoreBase` interface — **DELETED**. Split into four sibling stores:
  `UserSessionStore` (3 methods) + `SessionRPRegistry` + `SessionFamilyIndex` +
  `SessionFederationIndex`. (per A4 §4 "Breaking changes vs v0.4.x", item 1)
- Methods removed from `UserSessionStore`: `registerRP`, `linkFamily`,
  `updateClaims`, `removeFederation`. Each migrated to a sibling store
  (`updateClaims` deferred post-publish; no v0.5.0 surface). (per A4 §4, item 2)
- `UserSession` value type narrowed: `activeRPs`, `familyIds`, `federations` fields
  removed (now owned by sibling stores). (per A4 §4, item 3)
- `UserSessionStoreFactory` (alias for `AdapterFactory<UserSessionStoreBase>`) →
  four distinct factories: `UserSessionStoreFactory`, `SessionRPRegistryFactory`,
  `SessionFamilyIndexFactory`, `SessionFederationIndexFactory`. (per A4 §4, item 4)
- `CreateUserSessionInput.federations?: ReadonlyArray<string>` field removed.
  Federations are added separately via `SessionFederationIndex.addFederation` after
  session create. (per A4 §4, item 5)

#### Federation redirect-policy split (A5)

- `FederationProvider.validateRedirect` and
  `FederationProvider.resolveCallbackRedirect` — **removed** from the interface.
  Consumer-defined `FederationProvider` implementations MUST drop these two methods.
  (per A5 §4 "Breaking changes vs v0.4.x", items 1–2)
- New contribution kind `federationRedirectPolicies` is **required** for any
  federation that wants its callback flow to work — the boot planner throws
  `BootError` if a `federations[name]` contribution lacks a matching
  `federationRedirectPolicies[name]`. (per A5 §4, item 3)
- `registerGoogleFederation(factory)` — **DELETED** from
  `@o3co/auth-provider-session`. Consumers replace with
  `import { googleFederationModule } from "@o3co/auth-provider-federation-google"`
  and add it to the manifest list. (per A2-γ §3.5)
- `registerGithubFederation(factory)` — **DELETED** from
  `@o3co/auth-provider-session`. Same migration to `githubFederationModule`.
  (per A2-γ §3.5)
- `FederationProviderFactory` type and `createFederationProviderFactory()` from
  `@o3co/auth-provider-session` — **DELETED**. Custom federations now extend via
  `defineModule({ contributes: { federations: { myName: (deps) => provider } } })`.
  (per A2-γ §3.4, §3.5)

#### Issue #101 — A3 caller migration + boot validators

- `RefreshTokenStoreBase` — **removed** from `@o3co/auth-provider-core` (factory,
  types, and `__tests__/` under `packages/core/src/refresh/`). Consumers migrate to
  the A3 triple `RefreshTokenFamilyRotation` / `RefreshTokenFamilyRevocation` /
  `RefreshTokenFamilyStore` introduced in Phase 6.
- `RefreshTokenFamilyRotation.rotate(prev, new, familyId, expiresAtMs: number)` —
  `expiresAt` parameter changed from `Date` to epoch-ms `number` (defence against
  `Date.setTime` mutation per A3 §5.1).
- `RefreshTokenFamilyRotation.register(jti, familyId, expiresAtMs)` is the dedicated
  initial-issue method, replacing the v0.4.x `rotate(null, jti, ...)` trick.
- `ComponentMap.refreshTokenStore?` slot removed.
- `GrantContext.refreshTokenStore?` field removed.
- `oauthAuthorizationModule.optional` slot renamed
  `"refreshTokenStore"` → `"refreshTokenFamilyRotation"`.
- `oauthModule.optional` slot renamed
  `"refreshTokenStore"` → `"refreshTokenFamilyRevocation"`.
- `tokenExchangeModule.optional` slot renamed
  `"refreshTokenStore"` → `"refreshTokenFamilyRevocation"`.
- New `BootError` reasons: `"mfa-partial-wiring"` and
  `"federation-stores-incomplete"` — boot-time guards restored from v0.4.x
  `app-extensions.test.mts` after Phase 9 deletion.

### Breaking Changes (pre-tag interface review — Group A)

- **`createDefault*` factory prefix dropped** for all 5 factories. Use the
  unprefixed name; "Default" implied "1 of N" but only one implementation
  ships per name. Reference libraries (node-oidc-provider, NextAuth, Lucia)
  do not use this prefix:
  - `createDefaultChallengeCeremony` → `createChallengeCeremony`
  - `createDefaultRefreshTokenFamilyRotation` → `createRefreshTokenFamilyRotation`
  - `createDefaultRefreshTokenFamilyRevocation` → `createRefreshTokenFamilyRevocation`
  - `createDefaultFederationRedirectPolicy` → `createFederationRedirectPolicy`
  - `createDefaultFactories` → `createRepositoryFactories` (specifically
    repository factories, not generic "default factories")

  The companion parameter types lose the `Default` prefix in lockstep
  (consumers writing typed glue code update type imports too):

  - `DefaultChallengeCeremonyDeps` → `ChallengeCeremonyDeps`
  - `DefaultRefreshTokenFamilyRotationDeps` → `RefreshTokenFamilyRotationDeps`
  - `DefaultRefreshTokenFamilyRevocationDeps` → `RefreshTokenFamilyRevocationDeps`
  - `DefaultFederationRedirectPolicyConfig` → `FederationRedirectPolicyConfig`

  Module names retain the `default*Module` form where default-ness is the
  intended distinction.

- **`name` field removed from `GithubProviderConfig` / `GoogleProviderConfig`**.
  v0.5.0 is single-tenant: `provider.name` is fixed at `"github"` / `"google"`,
  matching the federation contribution key. The `name` config field was
  misleading because the const-module forced the contribution key regardless
  of consumer input. Multi-tenant support (multiple GitHub/Google apps in one
  provider) is deferred post-publish — when added, the Config shape will gain
  `name` back additively (backward-compatible).

- **`MutableUserSessionStore` interface removed** from
  `@o3co/auth-provider-core` public exports. The interface was pre-declared
  for v0.6+ federation re-link claim propagation but had no v0.5.0
  implementation, no v0.5.0 caller, and no test exercising the actual
  contract. Shipping a CAS callback shape without an implementation freezes
  the hardest part prematurely. The interface will be re-added when v0.6+
  ships an actual implementation.
  - Also removed: `mutableUserSessionStore` ComponentMap slot.

### Breaking Changes (pre-tag interface review — Group B)

- **Backing-client interfaces relocated** from `@o3co/auth-provider-core` to
  `@o3co/auth-provider-redis`. The shape (`hSet`, `zAdd`, `pttl`,
  `multi`/`watch`/`exec`, `pExpireAt`, etc.) is intrinsically Redis-flavoured;
  hosting it in core forced storage-agnostic consumers to mimic Redis
  semantics. Eleven types moved; consumers update type imports from
  `@o3co/auth-provider-core` to `@o3co/auth-provider-redis`:
  - `ChallengeStoreClient`
  - `ReplaySeenSetClient`
  - `RefreshTokenFamilyClient`
  - `RefreshTokenFamilyMultiClient`
  - `DisposableRefreshTokenFamilyClient`
  - `UserSessionStoreClient`
  - `SessionRPRegistryClient`
  - `SessionRPRegistryMultiClient`
  - `SessionSidSortedSetClient`
  - `SessionSidSortedSetMultiClient`
  - `FederationTokenStoreClient`
  - `RateLimiterClient`

  The matching ComponentMap slot augmentations (`challengeStoreClient`,
  `replaySeenSetClient`, `refreshTokenFamilyClient`, `userSessionStoreClient`,
  `sessionRPRegistryClient`, `sessionFamilyIndexClient`,
  `sessionFederationIndexClient`, `federationTokenStoreClient`,
  `rateLimiterClient`) move with the interfaces. The slot keys themselves are
  unchanged; the type augmentations now ship from
  `@o3co/auth-provider-redis`. Consumers wiring redis backends already import
  from `@o3co/auth-provider-redis` (or its `/ioredis` subpath), so the slot
  types remain visible.

  Custom non-Redis backends (DynamoDB, Postgres, etcd, ...) define their own
  client contracts; do NOT implement these Redis-shaped interfaces.

### Breaking Changes (Phase 10 — Redis Adapter Relocation)

- **`createRedisFederationTokenStore` moved**: from
  `@o3co/auth-provider-core` to `@o3co/auth-provider-redis`. Imports
  must update to
  `import { createRedisFederationTokenStore } from "@o3co/auth-provider-redis"`.
  The `"redis"` backend is no longer auto-registered by
  `registerBuiltinFederationTokenStores`; consumers register it
  explicitly via
  `factory.register("redis", redisFederationTokenStoreBuilder)`
  or use the new declarative `redisFederationTokenStoreModule`.
- **`createRedisLock` moved + scoped internal**: relocated from
  `@o3co/auth-provider-core` to `@o3co/auth-provider-redis/internal`.
  No longer exported (was never public-API stable; the lock interface
  embeds `sid` + `federationName` which is federation-tokens-specific).
  Consumers needing a generic redis lock should wait for a future
  version that publishes a backend-agnostic lock API.
- **AES-256-GCM token-field crypto helpers moved + scoped internal**:
  `encryptTokenField` / `decryptTokenField` relocated from
  `@o3co/auth-provider-core/federation-tokens/crypto` to
  `@o3co/auth-provider-redis/internal/crypto`. They were never publicly
  exported from core's index; the relocation is documented for
  completeness.
- **`"redis"` rate-limiter backend moved**: removed from
  `registerBuiltinRateLimiters`. Use
  `factory.register("redis", redisRateLimiterBuilder)` from
  `@o3co/auth-provider-redis`, or the declarative
  `redisRateLimiterModule`.
- **`RedisCodeRepository` moved**: from
  `@o3co/auth-provider-foundation` to `@o3co/auth-provider-redis`.
  Imports must update to
  `import { RedisCodeRepository, redisCodeRepositoryBuilder } from "@o3co/auth-provider-redis"`.
  Foundation no longer registers redis as a built-in code-repository
  backend; consumers use
  `codeFactory.register("redis", redisCodeRepositoryBuilder)`.
- **Foundation `redis` peer dependency removed**:
  `@o3co/auth-provider-foundation` no longer declares `redis` as an
  optional peer. Consumers that previously installed `redis` because
  of foundation now install it because of `@o3co/auth-provider-redis`
  instead. Net dependency cost is identical.
- **`RedisClient` super-type + `redisClient` ComponentMap slot REMOVED**.
  Replaced by 9 per-purpose backing-client interfaces
  (`ChallengeStoreClient`, `ReplaySeenSetClient`,
  `RefreshTokenFamilyClient`, `UserSessionStoreClient`,
  `SessionRPRegistryClient`, `SessionSidSortedSetClient` — reused for
  both `sessionFamilyIndexClient` and `sessionFederationIndexClient`
  slots — `FederationTokenStoreClient`, `RateLimiterClient`) and 9
  corresponding `xxxClient` ComponentMap slots, all declared in
  `@o3co/auth-provider-core` next to the adapter's responsibility.
  Each slot's type declares only the methods that adapter actually
  consumes (e.g. `RateLimiterClient` is `{ incr; expire }`, not the
  full redis surface). Consumers wiring redis: replace
  `bootstrapComponents: { redisClient: w }` with
  `bootstrapComponents: { ...makeIoredisClients(io) }` (new factory
  in `@o3co/auth-provider-redis`). Future memcached/postgres adapters
  can satisfy the same per-purpose interfaces with their own wrappers
  without touching the slot model. Rationale: the prior super-type
  could not honestly describe `federationTokenStore` (needs
  `scanIterator`) or `rateLimiter` (needs `incr` / `expire`) without
  polluting other adapters' contracts.
- **`RedisLikeClient` interface REMOVED** (was exported transiently by
  `@o3co/auth-provider-redis` between Phase 10 Task 2 commit and the
  per-purpose addendum; never published). Replaced by
  `FederationTokenStoreClient` from `@o3co/auth-provider-core`.
- **`makeIoredisRedisClient` test helper REMOVED**. Tests use
  `makeIoredisClients` from the production `@o3co/auth-provider-redis`
  surface.

### Added (Phase 10)

- **`memoryFederationTokenStoreModule`** in `@o3co/auth-provider-core` —
  declarative module wrapper for the in-memory FederationTokenStore
  (`federationTokenStore` ComponentMap slot).
- **`redisFederationTokenStoreModule`** in `@o3co/auth-provider-redis` —
  declarative module wrapper for the Redis FederationTokenStore.
- **`memoryRateLimiterModule`** in `@o3co/auth-provider-core` —
  declarative module wrapper for the in-memory RateLimiter
  (`rateLimiter` ComponentMap slot).
- **`redisRateLimiterModule`** in `@o3co/auth-provider-redis` —
  declarative module wrapper for the Redis RateLimiter.
- **`redisFederationTokenStoreBuilder`** / **`redisRateLimiterBuilder`** /
  **`redisCodeRepositoryBuilder`** in `@o3co/auth-provider-redis` —
  `AdapterBuilder` exports for AdapterFactory-style wiring.
- **9 per-purpose backing-client interfaces** in
  `@o3co/auth-provider-core` (one per redis adapter family). Each
  interface declares the minimal method set its adapter consumes;
  backend wrappers (today: redis; future: memcached, postgres)
  implement these interfaces independently:
  `ChallengeStoreClient`, `ReplaySeenSetClient`,
  `RefreshTokenFamilyClient` (+ `RefreshTokenFamilyMultiClient` +
  `DisposableRefreshTokenFamilyClient`), `UserSessionStoreClient`,
  `SessionRPRegistryClient` (+ `SessionRPRegistryMultiClient`),
  `SessionSidSortedSetClient` (+ `SessionSidSortedSetMultiClient`,
  shared by `sessionFamilyIndexClient` and
  `sessionFederationIndexClient` slots), `FederationTokenStoreClient`,
  `RateLimiterClient`. All slot identities live in
  `@o3co/auth-provider-core`'s `ComponentMap` via declaration-merge.
- **`makeIoredisClients(io)`** factory in `@o3co/auth-provider-redis` —
  returns the 9 typed wrappers from a single ioredis connection,
  spreadable into `bootstrapComponents`.
- **`RefreshTokenFamilyClient.duplicate` contract test** at
  `packages/redis/__tests__/adapters.refresh-token-family-client.contract.mts` —
  validates the WATCH-isolation MUSTs (independent socket per
  duplicate, `[Symbol.asyncDispose]` closes the connection) against
  any wrapper implementation. Replaces the deleted
  `adapters.redis-client.contract.mts` super-type contract.

### Added

- `@o3co/auth-provider-core/testing` subpath. Exposes the
  `makeValidCoreConfig` / `makeValidFullSections` / `makeValidAppConfig`
  fixture factories so sibling packages and downstream test suites can
  build a schema-valid config baseline without re-implementing it. The
  subpath is consumer-test-only — production runtime code MUST NOT
  import from it.
- **Typed ComponentMap slots** for the standard core components.
  Modules now declare `requires: ["..."]` against typed slots, and the
  DI graph types `deps.<slot>` accordingly. The Phase 9 augmentation
  added the following `declare module "@o3co/auth-provider-core"`
  blocks (each colocated next to its base type):
  - `keyStore: KeyStore` (required)
  - `clientRepository: ClientRepository` (required)
  - `userRepository: UserRepository` (required)
  - `codeRepository: CodeRepository` (required)
  - `auditSink?: AuditSinkBase` (optional)
  - `rateLimiter?: RateLimiterBase` (optional)
  - `federationTokenStore?: FederationTokenStoreBase` (optional)
  - `grantPolicy?: GrantPolicyHookBase` (optional)
  - `refreshTokenStore?: RefreshTokenStoreBase` (optional, transitional —
    see issue #101 for the migration to the A3 family triple).
  Consumer modules can list these in their `requires` / `optional`
  arrays without redeclaring the slot type.
- **Boot validator: CP-20 grantPolicy / jwt.issuer invariant** restored
  at validate-manifests step 13.5. When `grantPolicy` is wired through
  any of the three supported component sources — module `provides`,
  `bootstrapComponents`, or `overrideComponents` — `config.oauth.jwt.issuer`
  must be a non-empty string; otherwise `BootError` is thrown with reason
  `grant-policy-without-issuer`. Mirrors the v0.4.x guard removed when
  the legacy `createApp` body was deleted in commit fd22577e. Other
  v0.4.x guards (MFA partial-wiring, TODO-F-1 federation+stores) are
  tracked in #101 as follow-ups; the v0.4.x A4 four-store invariant is
  intentionally retired in v0.5.0 because the four user-session slots
  are now split across packages (`sessionModule` consumes 2, `oauthModule`
  consumes 2) and step 4 (`checkRequiresClosure`) enforces per-module
  wiring.
- `templates/standalone/src/buildModules.mts` — composition-root helper
  that gates federation modules on `config.federations.<name>.enabled`
  and accepts `BuildModulesOverrides` for tests. Replaces the inline
  module list in `app.mts`.
- `@o3co/auth-provider-federation-google` package with `createGoogleProvider()` and the const `googleFederationModule` that contributes `federations.google` + `federationRedirectPolicies.google` via the typed `googleFederationConfig` ComponentMap slot (per A5 §10.1).
- `@o3co/auth-provider-federation-github` package with `createGithubProvider()` and the const `githubFederationModule` (symmetric to Google).
- `extractFederationSection(federations, name)` exported from `@o3co/auth-provider-session` — pure utility that normalizes flat / nested / shorthand federation config slices for use by per-federation config-bridge modules.
- `validateRedirect` and `resolveCallbackRedirect` exports from `@o3co/auth-provider-session` for provider package implementations. (`codeChallenge` was already exported since v0.4.0.)
- `@o3co/create-auth-provider` scoped scaffolder package. Replaces the unscoped `create-o3co-auth-provider` so the scaffolder lives under the `@o3co` npm org alongside the runtime packages. Consumers should switch to `npx @o3co/create-auth-provider my-auth-app`. The old `create-o3co-auth-provider` package on npm is deprecated.

### Changed

- **Breaking**: `sessionModule` is now a const Module value rather than a factory function. Callers `import { sessionModule } from "@o3co/auth-provider-session"` and add it directly to the manifest list passed to `createApp({ modules: [...] })` — no factory call. Per-federation modules (e.g. `googleFederationModule`, `githubFederationModule`) are added alongside.
- **Breaking**: Google and GitHub federation providers are no longer bundled in `@o3co/auth-provider-session`. Consumers install the per-federation packages and add their const Modules (`googleFederationModule` / `githubFederationModule`) to the manifest, plus a small config-bridge module that supplies the typed `googleFederationConfig` / `githubFederationConfig` ComponentMap slot from `config.federations.<name>` via `extractFederationSection`.
- `templates/standalone` registers `@o3co/auth-provider-federation-google` explicitly for the default Google federation config.
- Scaffolder CLI renamed from `create-o3co-auth-provider` to `@o3co/create-auth-provider` (scoped). The `bin` entry is now `create-auth-provider`.

### Removed

- **Breaking**: The Route 1 federation factory surface is fully removed (issue #98). `createFederationProviderFactory()`, the `FederationProviderFactory` type, `registerGoogleFederation()`, `registerGithubFederation()`, `narrowGoogleConfig()`, `narrowGithubConfig()`, and `sessionModule({ federationProviderFactory })` are all deleted. Custom federations now extend via per-federation `defineModule(...)` (see `@o3co/auth-provider-federation-google` for the reference pattern).
- **Breaking**: `registerBuiltinFederations`, `createGoogleProvider`, and `createGithubProvider` are removed from `@o3co/auth-provider-session`.
- `openid-client` is no longer a runtime dependency of `@o3co/auth-provider-session`; it belongs to the concrete provider packages.
- **Breaking**: `@o3co/auth-provider-did` package. The DID authentication grant is no longer part of this project. The package is no longer maintained here.
- **Breaking**: `LegacyModule` and `ModuleContext` types are removed from `@o3co/auth-provider-core`. v0.4.x modules (functions returning `{ name, init(context) }`) must be rewritten as v0.5.0 manifests authored via `defineModule({...})` per A2-α §3 and migrated to use typed `ProviderDeps` instead of `ModuleContext`. `PathResolver` and `FederationProviderHandle` remain — `PathResolver` is the type for `bootstrapComponents.pathResolver`; `FederationProviderHandle` is the structural narrowing of the `federationProviders` synthetic key for core-adjacent route consumers.

### Fixed

- `oauthAuthorizationModule` now declares `refreshTokenStore` and
  `grantPolicy` in `optional`. Without them the boot planner dropped
  the components at the contribution-factory boundary, so refresh-
  token rotation persistence (`createRefreshTokenGrant`) and CP-18
  fail-closed grantPolicy enforcement were silently dead in v0.5.0
  consumers that wired either component.
- `tokenExchangeModule` now declares `refreshTokenStore` and
  `grantPolicy` in `optional`. Without `refreshTokenStore` the
  family-revocation path in the token-exchange grant and the built-in
  self-issued validator could not observe revocations even when a
  composition root provided the store, breaking RFC 8693 §7.2 state-1
  expectations. Without `grantPolicy` the token-exchange grant sat
  outside CP-18 fail-closed enforcement while sibling OAuth grants
  (auth-code, refresh-token) were gated — a structural inconsistency
  in policy coverage.
- `oauthModule`'s OIDC discovery contribution mounts the router at
  `/` instead of `/.well-known/openid-configuration`. The discovery
  router itself registers the spec-fixed absolute path, so the prior
  combination produced the double-pathed handler
  `/.well-known/openid-configuration/.well-known/openid-configuration`
  and returned 404 on standard discovery requests.
- `templates/standalone` now boots under the default
  `federations.google.enabled = false` config. The composition root
  gates `googleFederationModule` and `googleFederationConfigModule`
  on the enabled flag via the new `buildModules` helper; previously
  both were unconditionally included and the config-bridge module
  threw at boot when the section was absent or disabled.
- **Breaking (type-level)**: `refreshTokenStore` and `grantPolicy`
  ComponentMap slots are now declared `readonly … ?:` instead of
  `readonly …` to match their always-optional consumption contract.
  Both have always been optional at runtime — the prior non-optional
  declaration lied about the contract and would have surfaced a
  typecheck failure for any module that declared them in `optional`.
  External consumers who wrote `deps.refreshTokenStore.rotate(...)`
  without a guard need to add `if (deps.refreshTokenStore)` (or a
  non-null assertion) at the call site. v0.5.0 is breaking, so this
  semver-fits, but the user-visible surface narrows.

### Boot lifecycle

- **Recommended graceful-shutdown shape moves from `grantRegistry.cleanup()`
  to `handle.dispose()`.** The v0.4.x bridge
  `gracefulShutdown(server, () => grantRegistry.cleanup())` becomes
  `gracefulShutdown(server, () => handle.dispose())`, where `handle` is the
  awaited result of `createApp(...)`. `AppHandle.dispose()` runs
  per-component `lifecycle[K].cleanup` callbacks in reverse-topological
  order per A2-β §8.1. `GrantRegistry.cleanup()` itself remains in this
  release for backwards compatibility (it still iterates registered grants
  and calls each handler's optional `cleanup()`); a follow-up minor will
  remove it once all consumers and templates migrate to
  `handle.dispose()`.

- Per-contribution-kind disposal hooks (e.g. for grants holding owned
  resources) are NOT structurally supported by the new boot planner in
  v0.5.0. The `GrantHandler.cleanup` field on the type continues to be
  invoked by the legacy `GrantRegistry.cleanup()` path described above,
  but no v0.5.0 built-in grant declares it. A future minor (or A2-β
  reopening) may add per-contribution-kind disposal at the collector
  level — see A2-γ §5.3 for the structural-gap discussion.

### Breaking Changes

- **`createSelfIssuedAccessTokenValidator({ issuer })` requires a non-empty
  string `issuer`.** The `issuer` field on
  `CreateSelfIssuedAccessTokenValidatorOptions`
  (`@o3co/auth-provider-oauth-token-exchange`) is no longer optional.
  Constructing the validator with `undefined` or `""` now throws
  synchronously. Without an issuer, any `access_token`-typed JWT signed by
  the same KeyStore could pass validation, opening a token-type confusion
  vector (Copilot review on PR #100, Critical). Callers either pass
  `issuer` directly or rely on `tokenExchangeModule`'s `configSchema`
  which enforces `config.oauth.jwt.issuer: z.string().min(1)` at boot
  (intersected over `CoreConfigSchema`'s optional issuer via
  `composeConfigSchema`). External consumers who imported the validator
  factory directly need to start passing `issuer` (or migrate to consume
  `tokenExchangeModule` which wires it from config).
- **`oauthModule.configSchema` requires a non-empty
  `config.endpoints.login.url`.** The `/oauth/authorize` route reads
  `config.endpoints.login.url` unconditionally to redirect unauthenticated
  requests. The base `endpoints.login.url` is `z.string().optional()` in
  `CoreConfigSchema` (production defaults are supplied via HOCON env-var
  substitution `${?ENDPOINTS_LOGIN_URL}`); without
  `oauthModule.configSchema` tightening this to `z.string().min(1)`, a
  config that omits the env var booted cleanly and produced
  `undefined?redirect_to=...` redirects at request time. Boot now fails
  fast with `BootError(reason: "config-validation-failed")` when the
  field is missing or empty. Set `ENDPOINTS_LOGIN_URL` in production
  env, or pass `endpoints.login.url` explicitly in non-HOCON consumer
  configs (multi-agent review round 2 — Claude + Codex converged).
- **Config schema is strict; defaults live exclusively in HOCON.**
  `application.schema.mts` no longer carries `.default(X)` for fields
  that hocon already supplies. Operators see the same effective
  defaults at boot — `application.conf` continues to provide them —
  but the schema layer no longer fills in missing values. Two
  concrete operator-facing consequences:
  - **`federations.<name>.enabled` is strict.** Pre-PR the schema-side
    `enabled` carried `.default(false)`, but its composition with
    surrounding `z.preprocess` / `z.optional` was fragile: a bare
    federation entry sometimes parsed as `enabled = false` and
    sometimes caused boot to reject the entry (the trap that
    motivated this refactor). The schema-side default is now
    removed. Each federation entry must declare
    `enabled = true` / `enabled = false` explicitly, or be omitted
    from the config entirely. Bare `federations { google {} }`
    shapes will now fail validation at boot deterministically. If
    you want a federation provider to be active, write
    `enabled = true` in its entry; if you want it inactive, either
    write `enabled = false` or remove the entry.
  - **Library consumers** who construct `AppConfig` from a non-HOCON
    source (TOML, env-only, in-memory object, etc.) must now supply
    every required leaf themselves before calling `validate()` /
    `composeConfigSchema().parse()`. Previously, schema-side
    `.default()` masked missing leaves; that path is gone. See
    `packages/core/docs/adr/2026-04-30-config-schema-strict-defaults-from-hocon.md`
    (consequences I2 / I4) for the rationale and the
    `@o3co/auth-provider-core/testing` subpath for a reference
    fixture baseline. Note that the `testing` factory is intentionally
    a minimal schema-valid baseline rather than a hocon mirror —
    consumers that want the production hocon defaults should load
    `application.conf` directly.
- **`grant_type` wire values (RFC compliance + URN-ification):**
  - `grant_type=authorization` → `grant_type=authorization_code` (RFC 6749 §4.1.3)
  - `grant_type=session` unchanged
- **HOCON config keys + env vars:**
  - `oauth.grants.authorization { ... }` → `oauth.grants.authorization_code { ... }`
  - `OAUTH_GRANTS_AUTHORIZATION_ENABLED` → `OAUTH_GRANTS_AUTHORIZATION_CODE_ENABLED`
  - `OAUTH_GRANTS_AUTHORIZATION_PKCE_REQUIRE_S256` → `OAUTH_GRANTS_AUTHORIZATION_CODE_PKCE_REQUIRE_S256`
- **Grant policy interface (`GrantPolicyRequest.grantType`):**
  - `/oauth/authorize` flow now passes `"authorization_code"` (was `"authorization"`)
    to `grantPolicy.evaluate()`
  - `refresh_token` path unchanged

**Migration checklist:**

1. Update client requests:
   - `grant_type=authorization` → `authorization_code`
2. Update HOCON config / environment:
   - Rename `oauth.grants.authorization` → `oauth.grants.authorization_code`
   - Rename `OAUTH_GRANTS_AUTHORIZATION_*` → `OAUTH_GRANTS_AUTHORIZATION_CODE_*`
3. If implementing `GrantPolicyHookBase`:
   - Rename `case "authorization":` → `case "authorization_code":` in
     policy dispatch logic

## [0.4.1] - 2026-04-22

### Added

- `create-o3co-auth-provider` CLI scaffolder is now published to npm. Consumers can run `npx create-o3co-auth-provider my-auth-app` to generate a new `auth.provider` project from the standalone template. The package was previously built but held back (`private: true`) from npm publish; this release removes that flag and adds `description` + `repository` metadata.

### Notes

- No changes to `@o3co/auth-provider-core`, `@o3co/auth-provider-session`, `@o3co/auth-provider-oauth`, `@o3co/auth-provider-did`, or `@o3co/auth-provider-foundation`. These packages are re-published at `0.4.1` because the release pipeline bumps all workspace packages in lockstep; their runtime behaviour is identical to `0.4.0`. Consumers upgrading from `0.4.0` → `0.4.1` get an effective no-op reinstall.

## [0.4.0] - 2026-04-22

### Added

- `SupportsLogout` optional capability interface (`EndSessionRequest`, `EndSessionResult`, `SupportsLogout`) and `supportsLogout(provider)` type guard helper in `@o3co/auth-provider-session`. Detects providers whose IdP exposes an OIDC RP-Initiated Logout endpoint. `supportsLogout` accepts `FederationProvider | undefined | null` so it can be called directly on `Map.get(name)` lookups; returns `false` on nullish input. Built-in `google` / `github` providers do not implement this capability.
- `FederationProvider` pure-function interface for upstream OAuth 2 / OIDC identity providers: `buildAuthorizationUrl`, `exchangeCode`, `validateRedirect`, `resolveCallbackRedirect`. Replaces passport-middleware-shaped `setupPassportStrategy` (see Removed).
- `SupportsRefresh` optional capability with `refreshToken(refreshToken): Promise<RefreshedTokens>` and `supportsRefresh(provider)` type guard. `RefreshedTokens = Omit<FederationProfile, "issuer"|"sub"> & { issuer?: string; sub?: string }` reflects that refresh grants legitimately omit identity (Google/GitHub).
- `SupportsClaimMapping` optional capability with `mapClaims(profile): MappedClaims` and `supportsClaimMapping(provider)` type guard.
- `generateCodeVerifier()` / `codeChallenge(verifier)` helpers exported from `@o3co/auth-provider-session` for PKCE S256.
- `registerBuiltinFederations(registry)` one-shot registration + built-in `createGoogleProvider` / `createGithubProvider` (openid-client v6 backed).
- `createClientAuthMiddleware(clientRepository)` exported from `@o3co/auth-provider-oauth` — RFC 6749 §2.3.1 HTTP Basic + form-urlencoded `client_secret_basic` / `client_secret_post` for `/introspect`. Attaches validated `req.oauthClient` (global `Express.Request` namespace augmentation).
- `POST /oauth/federation/:name/token` endpoint (TODO-F-6) — federation token proxy with auto-refresh via `SupportsRefresh` + advisory lock via `SupportsLock`. Returns RFC 6749 §5.1 shape; `expires_in` omitted when upstream issues no finite expiry.
- `FederationTokenStore` optional `SupportsLock.acquireLock()` capability — built-in memory + redis implementations.
- CI vendor-leak guard: `.github/workflows/ci.yml` fails if `arctic|openid-client|oauth4webapi|passport` leaks into any public `.d.mts` / `.d.ts`.
- Per-environment HOCON config overlay for `templates/standalone`: `{ENV}.conf` overrides `application.conf`, with path-containment rejection of traversal env names.
- `KeyStore.sign(options: SignJwtOptions): Promise<string>` for remote-sign support (KMS/HSM).
- `KeyStore.getSigningKidFallback(): string` — cheap signing-kid accessor (fallback for legacy tokens missing `kid` header).
- `JWTPayload` type (RFC 7519, jose-independent) — exported from `@o3co/auth-provider-core` root.
- `SignJwtOptions` type for `sign()` input — exported from `@o3co/auth-provider-core` root.
- `Algorithm` type — promoted to root export.
- `KeyLike` type — promoted to root export.
- `MfaProviderBase` interface + optional `SupportsEnrollment` / `SupportsRevocation` capabilities + `supportsEnrollment()` / `supportsRevocation()` type guards.
- `MfaCoordinator`, `MfaTransactionStore`, `MfaPendingTransaction`, `MfaResumeState` types for MFA flow resume.
- `POST /auth/mfa/verify` route with server-side provider dispatch via `MfaPendingTransaction.providerKind`.
- `MfaProviderFactory = AdapterFactory<MfaProviderBase>` + `createMfaProviderFactory()` + `createMfaRouter()`.
- `AuditEvent` / `AuditSinkBase` interface + `AuditSinkFactory` + `createAuditSinkFactory()` for pluggable audit log sinks.
- Built-in `"console"` audit sink via `registerBuiltinAuditSinks()`.
- `emitAuditEvent(sink, event)` helper — fire-and-forget with error swallow.
- `RateLimitContext` / `RateLimitDecision` / `RateLimiterBase` + `RateLimitSpec` + `RateLimiterFactory` + `createRateLimiterFactory()`.
- Built-in `"memory"` and `"redis"` rate limiters via `registerBuiltinRateLimiters()`.
- `RefreshTokenRotateOutcome` / `RefreshTokenStoreBase` with atomic `rotate()` primitive + `RefreshTokenStoreFactory` + `createRefreshTokenStoreFactory()`.
- `GrantPolicyRequest` / `GrantPolicyContext` / `GrantPolicyDecision` / `GrantPolicyHookBase` + `GrantPolicyHookFactory` + `createGrantPolicyHookFactory()`.
- `family_id` claim added to all `rt+jwt` tokens (always emitted, for future-compatible rotation tracking).
- `grantedScope` / `grantedAudience` fields added to `Code` records (policy-narrowed values persisted at `/oauth/authorize` for later use at `/oauth/token`).

### Changed

- **Breaking**: Federation interface rewritten as a vendor-agnostic pure-function shape. `FederationProviderBase` is renamed back to `FederationProvider` (v0.3.x → interim `FederationProviderBase` → v0.4.0 `FederationProvider`), and the `setupPassportStrategy(passport, ctx)` method is replaced by `buildAuthorizationUrl({ redirectUri, state, codeVerifier })` + `exchangeCode({ code, codeVerifier, redirectUri })`. State (CSRF `state`) and PKCE `codeVerifier` are managed by the session route layer; providers never allocate them.
- **Breaking**: `FederationProfile.id` → `sub` (OIDC claim naming). `FederationProfile.expiresIn: number` → `expiresAt: Date | null` (required). `null` means the upstream provider issues no finite expiry (e.g. GitHub OAuth Apps classic tokens); consumers MUST reuse without refresh. The route layer no longer invents a fallback expiry.
- **Breaking**: `FederationProfile.raw` removed. OIDC-standard claims are first-class fields (`issuer`, `sub`, `email`, `emailVerified`, `name`, `picture`, `accessToken`, `refreshToken`, `idToken`, `expiresAt`). Provider-specific claims (Google `hd`, Microsoft `tid`) are carried by the index signature `[key: string]: unknown`.
- **Breaking**: `FederationProviderFactory` is now `AdapterFactory<FederationProvider>` (was `AdapterFactory<FederationProviderBase>`).
- **Breaking**: `FederationTokens.expiresAt: Date` → `Date | null` (required). Same contract as `FederationProfile.expiresAt`.
- **Breaking**: `UserSessionStore` and `FederationTokenStore` are now **required** at session-module init. Previously optional with a legacy fallback; the module now throws at `init()` time if either is absent from `ModuleContext`.
- **Breaking**: `/login` and `/introspect` error responses follow RFC 6749 §5.2 shape `{ error, error_description }`. Previous `{ message }` shape removed.
- **Breaking**: `createOAuthRouter` drops the `passport` option. Provide `clientRepository` directly; `/introspect` client auth is handled by the new built-in `createClientAuthMiddleware`.
- **Breaking**: `KeyStore.getVerificationKey(kid)` is now `Promise<KeyLike>` (was sync). Callers must `await`.
- **Breaking**: `KeyStore.getVerificationKeys()` is now `Promise<ManagedKey[]>` (was sync). Callers must `await`.
- `AppOptions` now accepts optional `mfaProviderFactory`, `mfaCoordinator`, `mfaTransactionStore`, `auditSink`, `rateLimiter`, `refreshTokenStore`, `grantPolicy`. `mfaCoordinator` setting requires both `mfaProviderFactory` and `mfaTransactionStore`; core throws at startup on misconfiguration.
- `refreshToken.mts` calls `refreshTokenStore.rotate()` atomically when a store is configured; otherwise unchanged (stateless fallback preserved).
- `/oauth/authorize` runs `grantPolicy.evaluate()` once at code issuance and persists narrowed values on the Code record. `/oauth/token` (authorization_code) honors persisted values without re-evaluating. Other grants evaluate at the token endpoint.
- `/oauth/token`, `/oauth/introspect`, `/oauth/authorize` now consult optional `rateLimiter` (returning 429 + `Retry-After` on denial) and emit audit events to the optional `auditSink` for success/failure transitions.

### Removed

- **Breaking**: `passport`, `passport-local`, `passport-google-oauth20`, `passport-github2`, `passport-oauth2`, `passport-oauth2-client-password`, `passport-http`, and all `@types/passport*` are removed as direct runtime dependencies from `@o3co/auth-provider-session`, `@o3co/auth-provider-oauth`, and `templates/standalone`. Built-in Google/GitHub providers are re-implemented on top of `openid-client` v6 (panva, OpenID Foundation Certified RP); vendor types stay inside each adapter and do not leak into the public `.d.mts` surface.
- **Breaking**: `createPassport()`, `SetupPassportContext`, and the `_createPassport` internal hook removed from `@o3co/auth-provider-session`. State (CSRF) and PKCE are managed by the route layer; providers are pure functions.
- **Breaking**: `VerifyUserContext` deprecated type alias in `@o3co/auth-provider-session`. The underlying `setupPassportStrategy(passport, ctx)` method is removed along with its context type.
- **Breaking**: `KeyStore.getSigningKey()`. Use `sign(options)` instead.
- **Breaking**: `KeyStore.current`. Use `getSigningKidFallback()` (kid only; private key is no longer exposed).
- **Breaking**: `KeyStore.previous`. Use `await getVerificationKeys()` (current + active previous unified).
- **Breaking**: `@o3co/auth-provider-oauth` no longer depends on `express-rate-limit`. The legacy `tokenRateLimit` / `authorizeRateLimit` middleware is removed from `createOAuthRouter`, along with the `config.rateLimit.{token,authorize}` schema fields. Consumers previously relying on the built-in middleware must configure `AppOptions.rateLimiter` with a `RateLimiterBase` adapter (built-in `"memory"` or `"redis"` available via `createRateLimiterFactory()` + `registerBuiltinRateLimiters()`).

### Migration

See `packages/session/README.md` and `packages/oauth/README.md` for full v0.3.x → v0.4.0 migration guide with before/after code samples.

#### Federation interface

```ts
// Before (v0.3.x)
const provider: FederationProviderBase = {
  setupPassportStrategy(passport, ctx) {
    passport.use(new GoogleStrategy({ /* ... */ }, ctx.verify));
  },
};

// After (v0.4.0)
const provider: FederationProvider = {
  name: "google",
  scope: ["openid", "email", "profile"],
  buildAuthorizationUrl({ redirectUri, state, codeVerifier }) {
    /* return URL */
  },
  async exchangeCode({ code, codeVerifier, redirectUri }) {
    /* return FederationProfile with expiresAt: Date | null */
  },
  validateRedirect(url) { /* ... */ },
  resolveCallbackRedirect(session) { /* ... */ },
};
```

#### `FederationProfile.expiresAt`

```ts
// Before: optional, route invented a 1h fallback when missing
const profile: FederationProfile = { /* expiresAt?: Date */ };

// After: required, null when provider issues no finite expiry (GitHub OAuth Apps classic)
const profile: FederationProfile = {
  issuer, sub, accessToken,
  expiresAt: expiresIn !== undefined
    ? new Date(Date.now() + expiresIn * 1000)
    : null,
};
```

#### Error response shape

```ts
// Before (/login, /introspect): { message: "..." }
// After: RFC 6749 §5.2 { error, error_description }
{ "error": "invalid_credentials", "error_description": "Incorrect username or password." }
```

#### Module wiring

`UserSessionStore` and `FederationTokenStore` are now required at session module init. Configure them in `AppOptions` before calling `createApp`. Core provides built-in memory + redis adapters via `createUserSessionStoreFactory()` and `createFederationTokenStoreFactory()`.

### KeyStore migration

JWT signing:

```ts
// Before
const { kid, privateKey } = keyStore.getSigningKey();
const token = await new SignJWT(claims)
  .setProtectedHeader({ alg: keyStore.algorithm, kid })
  .sign(privateKey);

// After
const token = await keyStore.sign({ claims });
```

Verification callers must now `await` `getVerificationKey(kid)` / `getVerificationKeys()`. Replace `keyStore.current.kid` with `keyStore.getSigningKidFallback()`.
