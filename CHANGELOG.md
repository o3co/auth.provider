# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added (Phase F — F9 PR5 AS-9 Redis session sub-adapter builders, v0.5.1)

- **Four new `*Builder` exports complete the tripartite
  `create* + *Builder + *Module` pattern for Redis session sub-adapters**
  (`@o3co/auth-provider-redis`, closes AS-9):
  - `redisSessionFamilyIndexBuilder`
  - `redisSessionFederationIndexBuilder`
  - `redisSessionRPRegistryBuilder`
  - `redisUserSessionStoreBuilder`

  Each builder follows the existing `redisChallengeStoreBuilder` /
  `redisRateLimiterBuilder` pattern: `(config, _ctx) => Adapter`, with a
  boot-time guard that throws when `config.client` is missing (TS-M2
  pattern from Wave 5g) instead of crashing at first Redis op. Default
  `keyPrefix` for each builder matches the production layout that
  `redisSessionStoresModule` produces (`ss:fi:`, `ss:fed:`, `ss:rp:`,
  `ss:us:`), so swapping between the bundled module and an individual
  builder does not change the keyspace.

  This is **purely additive** — the bundled `redisSessionStoresModule`
  remains the recommended wiring path for most consumers. The new builders
  are for consumers that need per-adapter `AdapterFactory` granularity
  (e.g., to substitute a custom adapter while keeping the others).

### Deprecated (Phase F — F9 PR5 AS-8 GrantRegistry public export, v0.5.1)

- **`GrantRegistry` and `GrantRegistryError` are deprecated as public
  exports** (`@o3co/auth-provider-core`, closes AS-8): `GrantRegistry`
  was historically exposed for v0.4.x consumers that registered grants by
  direct registry mutation. The v0.5.0 architecture migrated grant
  contribution to the module manifest pattern (`contributes.grants` on
  module definitions), and the boot planner is now the only intended
  caller of `register` / `replace` / `freeze`. The class itself is
  unchanged and continues to work for its internal callers; only its
  re-export from the package root is being withdrawn.

  Following A2-γ §3.3, the public re-export will be removed at 1.0 GA.
  The symmetric `ExchangeTokenValidatorRegistry` was already internalised
  in v0.5.0 — `GrantRegistry`'s deprecation closes the half-migration.

#### Migration

- Convert any `new GrantRegistry()` + `register(...)` wiring into a module
  definition with `contributes.grants: { [grantType]: factory }` and load
  the module via the standard composition path. The boot planner will
  invoke `register` / `freeze` on your behalf.
- The `@deprecated` JSDoc tag is now visible on the class itself and on
  the public export site, so IDEs / TypeScript surface the deprecation
  inline.

### Breaking (Phase F — F9 PR3 GrantPolicyHook manifest rename, v0.5.1)

- **Compile-time breaking change for deep manifest imports**: the manifest
  contributes-map placeholder previously exported as `GrantPolicyHook`
  from `@o3co/auth-provider-core/modules/manifest` has been renamed to
  `GrantPolicyHookContribution`. TypeScript code importing the old name
  from this entrypoint will fail to compile until the import is renamed.
  This is the only breaking part of F9 PR3; the rest is additive
  deprecation (see below).

#### Migration

- Replace `import type { GrantPolicyHook } from "@o3co/auth-provider-core/modules/manifest"`
  with `import type { GrantPolicyHookContribution } from "@o3co/auth-provider-core/modules/manifest"`.
- Imports of `GrantPolicyHook` from the package root
  (`@o3co/auth-provider-core`) keep working — the root export now resolves
  to the canonical policy alias (an alias of `GrantPolicyHookBase`),
  which has the same shape downstream code expected from the previous
  `unknown` placeholder for any structural use.
- The placeholder retains its `unknown` semantics under the new name
  (Phase 9 will substitute the concrete contribution type).
- No runtime behavior change.

### Deprecated (Phase F — F9 PR3 AS-7 + AS-10 naming consistency, v0.5.1)

- **Adapter primitive interfaces add canonical aliases without the `*Base`
  suffix; `*Base` forms are deprecated and will be removed at 1.0 GA**
  (`@o3co/auth-provider-core`, closes AS-7 + AS-10): the v0.5.1 canonical
  names are the new aliases. Existing code referencing `*Base` continues to
  compile (the aliases are type equivalences, not replacements). Update at
  your convenience before 1.0 GA.

| Deprecated | Canonical (v0.5.1) | Source |
|---|---|---|
| `FederationTokenStoreBase` | `FederationTokenStore` | `@o3co/auth-provider-core` |
| `RateLimiterBase` | `RateLimiter` | `@o3co/auth-provider-core` |
| `AuditSinkBase` | `AuditSink` | `@o3co/auth-provider-core` |
| `MfaProviderBase` | `MfaProvider` | `@o3co/auth-provider-core` |
| `GrantPolicyHookBase` | `GrantPolicyHook` | `@o3co/auth-provider-core` |

- **AS-10 documentation**: JSDoc on
  `ClientRepository.findById` and `CodeRepository.getByCode` documents the
  v0.5.1 naming convention (`findBy<Field>` for repository lookups; `get(<id>)`
  for single-object stores; operation-specific names like `consumeByCode`
  retain their semantic shape). `getByCode` will be normalized to
  `findByCode` at 1.0 GA. No code change.

#### Migration

- No action required for v0.5.x consumers — the `*Base` names are still
  exported and TypeScript treats the aliases as identical types. Migrate
  imports at your convenience.
- For the breaking manifest-path rename of the `GrantPolicyHook`
  placeholder, see the dedicated **Breaking** section above.
- No runtime behavior change.

### Breaking (Phase F — F9 PR2 AS-1 + AS-2 error envelope unification, v0.5.1)

- **All session and rate-limit error responses now use the RFC 6749 §5.2
  `{error, error_description}` envelope** (`@o3co/auth-provider-core`,
  `@o3co/auth-provider-session`, `@o3co/auth-provider-oauth`, closes AS-1
  + AS-2): six historically divergent error responses migrate to a single
  shape so consumer code can parse error bodies without per-route
  branching. New `errorEnvelope(error, description?, uri?)` helper
  exported from `@o3co/auth-provider-core` produces the canonical shape
  and omits absent optional fields.

| Site | Before | After |
|---|---|---|
| `Session.mts` CSRF origin mismatch (403) | `{message:"forbidden"}` | `{error:"access_denied", error_description}` |
| `Session.mts` regenerate failure (500) | `{message:"Error regenerating session"}` | `{error:"server_error", error_description}` |
| `Session.mts` logout failure (500) | `{message:"Error logging out"}` | `{error:"server_error", error_description}` |
| `Federation.mts` unknown provider on start (404) | `{message:"NotFound"}` | `{error:"not_found", error_description}` |
| `Federation.mts` unknown provider on callback (404) | `{message:"NotFound"}` | `{error:"not_found", error_description}` |
| `oauth/routes.mts` rate-limit (429) | `{error:"rate_limited", reason}` | `{error:"rate_limited", error_description}` |

#### Migration

- Replace `body.message` checks with `body.error_description` for the five
  session-router error responses, and replace `body.reason` with
  `body.error_description` for `429 rate_limited`.
- Replace `body.message === "forbidden"` with `body.error === "access_denied"`
  on CSRF-origin failures, `body.message === "NotFound"` with
  `body.error === "not_found"` on federation 404s, and the two 500-level
  `{message:"Error …"}` shapes with `body.error === "server_error"`.
- Consumer code building custom routes can import the helper as
  `import { errorEnvelope } from "@o3co/auth-provider-core"` to keep the
  shape consistent.
- Success 200 responses on `/session/login` and `/session/logout`
  (`{message:"Logged in successfully"}` / `{message:"Logged out successfully"}`)
  are intentionally left unchanged — RFC 6749 §5.2 governs error response
  shapes only.

### Breaking (Phase F — F9 PR1 CC-5 readonly Theme D, v0.5.1)

- **Public DTOs are now fully `readonly`** (`@o3co/auth-provider-core`,
  `@o3co/auth-provider-oauth-token-exchange`, closes CC-5 / AS-5 / AS-6 /
  AS-M2): `ValidatedToken`, `ExchangeTokenValidationContext`,
  `GrantContext`, `Client`, `User`, `CodeData`, and `Code` field declarations
  now carry `readonly` modifiers. Array-typed fields on `Client`
  (`allowedRedirectUris`, `allowedScopes`, `allowedAudiences`,
  `postLogoutRedirectUris`) are `readonly string[]` so element-level mutation
  (`.push`, index assignment) is rejected at compile time. `GrantContext.session`
  is `readonly` (wholesale `ctx.session = {…}` rejected); `SessionData`
  field-level writes (`ctx.session.isAuthenticated = true`) continue to
  compile so handlers writing through Express's `req.session` keep working.
  `selfIssuedAccessToken.mts` was refactored from sequential mutable-builder
  assignment to object-spread construction so it survives the new
  `readonly ValidatedToken` contract.

#### Migration

- Validator implementations using sequential `result.scope = …` builders
  must switch to object-spread (`{ sub, claims, ...(condition ? { x } : {}) }`).
- Custom code mutating `Client.allowedRedirectUris.push(…)` or assigning
  `Client.allowedScopes = […]` directly fails to compile — use the
  repository's create/upsert API to issue a new `Client` instead.
- Direct field assignments on `User`, `CodeData`, or `Code` instances
  (e.g. `user.id = "…"`, `codeData.client_id = "…"`, `code.code = "…"`)
  fail to compile. Replace with repository create / upsert calls so the
  store always issues a fresh record.
- No runtime behavior change: `readonly` is compile-time only; no
  `Object.freeze()` is applied. Existing valid call sites continue to work
  unchanged.

### Security (Phase F — F6 PR4 authorization-grant TOCTOU re-check, v0.5.1)

- **Authorization-code grant re-validates session liveness before linking the
  token family** (`@o3co/auth-provider-oauth`, closes CR-4): a second
  `userSessionStore.get(sid)` runs immediately before
  `sessionFamilyIndex.addFamilyId`, after the `clientRepository.findById`
  await that previously left a TOCTOU window open. If the session was
  invalidated by `cascadeLogout` during that window, the grant now returns
  `400 invalid_grant / session_invalidated` and emits the audit log
  `authorization_grant_rejected_session_invalidated_during_token_issuance`.
  Per Codex calibration, this **reduces** rather than eliminates the window
  — a logout interleaved between the second `get` and `addFamilyId` (sub-
  millisecond) is still possible. The fully-atomic
  `addFamilyIdIfSessionActive` Lua EVAL is deferred to a Phase F follow-up
  to avoid an interface change to `SessionFamilyIndex` for an already-narrow
  remaining window.

- **`cascadeLogout` defense-in-depth: post-step-4 `removeBySid` cleanup**
  (`@o3co/auth-provider-oauth`): a second
  `sessionFamilyIndex.removeBySid(sid)` runs AFTER
  `userSessionStore.delete(sid)` to clear any orphan family-index entry
  written into the index by an authorization grant racing through the
  remaining window described above. Idempotent per the
  `SessionFamilyIndex.removeBySid` contract (no-op when the sid has no
  entries) and best-effort: a failure here does not change the cascade
  outcome (orphan entries are bounded by the family-index TTL even
  without the second pass).

#### Migration

No public-API change. The new `session_invalidated` error from the
authorization code grant is a new behavior that surfaces only on the narrow
race path (logout completing between `findById` and `addFamilyId`); clients
that previously succeeded in this race window will now receive
`400 invalid_grant`. This is the correct behavior per RFC 6749 §5.2.

### Security (Phase F — F6 PR3 refresh-token grant hardening, v0.5.1)

- **Refresh-token reuse now revokes the entire family** (`@o3co/auth-provider-oauth`,
  closes PB-1): when `refreshTokenFamilyRotation.rotate` reports the
  `"replayed"` outcome, the grant handler now calls
  `refreshTokenFamilyRevocation.revokeFamily(familyId)` before returning
  `400 invalid_grant / replay_detected`. Pre-fix, only the present request
  was rejected — sibling refresh tokens issued from the same family
  remained valid, contradicting RFC 6819 §5.2.2 / OAuth 2.1 BCP §4.14.2.
  Fail-closed semantics: a rotation wired without a revocation dependency,
  or a `revokeFamily` call that throws, returns
  `503 temporarily_unavailable` rather than silently rejecting only the
  current request. Audit log
  `rt_reuse_detected_family_revoked { familyId, clientId }` is emitted
  on the success path; `rt_reuse_detected_but_no_revocation_dep` flags
  the misconfiguration case.

- **Unknown `family_id` is now rejected by default** (`@o3co/auth-provider-core` +
  `@o3co/auth-provider-oauth`, closes CC-2 / IH-3 / TD-2): a new
  `oauth.refreshToken.unknownFamilyPolicy` config key (default `"reject"`,
  defined in `application.conf`) replaces the v0.4.x implicit fall-through
  to success. An attacker presenting a refresh token whose `family_id`
  claim does not match any registered family now receives
  `400 invalid_grant / unknown_family` instead of fresh tokens. Operators
  migrating from v0.4.x in-memory family stores to Redis can opt into
  `"accept"` for a bounded migration window — that path emits the audit
  log `unknown_family_accepted_legacy_mode` so each acceptance is traceable.
  A defense-in-depth `familyId === null` guard hard-rejects regardless
  of policy (covered by SF-6's gate but kept for resilience).

- **Refresh tokens missing `jti` or `family_id` claims are rejected**
  (`@o3co/auth-provider-core` + `@o3co/auth-provider-oauth`, closes
  SF-6 / TD-7): when `refreshTokenFamilyRotation` is wired, refresh
  tokens MUST carry both claims to enter the rotation block. Pre-fix,
  the entire rotation block was skipped when `previousJti === null`,
  letting v0.4.x-shaped tokens bypass replay detection entirely. New
  `oauth.refreshToken.legacyRtPolicy` config key (default `"reject"`)
  hard-rejects such tokens with
  `400 invalid_grant / missing_jti_or_family_id`; the
  `"accept-with-warning"` opt-in skips rotation for a migration window
  and emits `legacy_rt_accepted_no_replay_protection`. Pair with
  `unknownFamilyPolicy = "accept"` for a one-refresh sliding bridge
  (the issued RT's fresh `family_id` is not registered in the store, so
  the next rotation hits `unknown_family`).

- **Rotation outcome handling is now an exhaustive switch**
  (`@o3co/auth-provider-oauth`): the four-outcome rotation union
  (`rotated | replayed | revoked | unknown_family`) is now classified by
  a `switch` with a `never`-typed default. A future addition to
  `RefreshTokenFamilyRotationOutcome` that forgets to update the handler
  produces a TypeScript compile error rather than silently falling
  through to token issuance — the failure mode that v0.4.x's implicit
  fall-through enabled for `unknown_family`.

#### Migration

**BREAKING** for deployments that previously relied on either of:

- A refresh token with an unknown `family_id` succeeding (rare; see CC-2
  rationale above) — set
  `OAUTH_REFRESH_TOKEN_UNKNOWN_FAMILY_POLICY=accept` for a bounded window.
- v0.4.x-shaped refresh tokens (no `jti` / `family_id`) succeeding while
  family rotation is wired — set
  `OAUTH_REFRESH_TOKEN_LEGACY_RT_POLICY=accept-with-warning` until all
  v0.4.x tokens have expired (≤ `OAUTH_REFRESH_TOKEN_EXPIRES_IN` seconds
  after deployment), and pair with `OAUTH_REFRESH_TOKEN_UNKNOWN_FAMILY_POLICY=accept`
  to bridge the next refresh.

Deployments without `refreshTokenFamilyRotation` wired are unaffected
(the gate only fires when rotation is present). Newly issued tokens
already carry both `jti` and `family_id` since v0.5.0, so the long-tail
exposure is bounded by `oauth.refreshToken.expiresIn`.

### Security (Phase F — F6 PR2 PKCE + RT family hardening, v0.5.1)

- **PKCE `code_verifier` comparison is now timing-safe** (`@o3co/auth-provider-oauth`,
  closes SF-3 + MIN-4): both the S256 and `plain` branches in the
  authorization-code grant now use `constantTimeStringEqual` (re-exported
  from `@o3co/auth-provider-core`), replacing JavaScript `!==` whose
  short-circuit on the first mismatched byte leaked progress information
  about how many bytes of a candidate verifier matched the stored challenge
  (RFC 7636 §4.1, OAuth 2.1 BCP §4.5). The helper encodes inputs to UTF-8
  buffers before the byte-length comparison so it is safe for any string
  including multi-byte Unicode.

- **`/authorize` bounds the OIDC `nonce` query parameter** (`@o3co/auth-provider-oauth`,
  closes IH-16): nonce values exceeding 256 characters or containing
  non-printable bytes are rejected via `redirectError invalid_request`.
  Pre-fix, an unbounded nonce was stored on the code record and echoed
  verbatim into the `id_token` payload — a malicious RP could exhaust
  per-request memory or amplify the JWT payload by several orders of
  magnitude. The ceiling is configurable via `oauth.nonce.maxLength`
  (env `OAUTH_NONCE_MAX_LENGTH`, default 256). Standard OIDC libraries
  generate 22–44 char nonces, so legitimate clients are unaffected.

- **Refresh-token family TTL is fixed at creation, no longer slides**
  (`@o3co/auth-provider-core`, closes IH-13): the rotation wrapper now
  applies `Math.min(requestedExpiresAtMs, current.expiresAtMs)` inside the
  CAS updater so subsequent rotations cannot extend the family's absolute
  ceiling. Before this fix, every rotation re-stamped `expiresAtMs` to
  `now + refreshToken.expiresIn`, letting an attacker who continuously
  rotated a stolen RT keep the family alive indefinitely (OAuth 2.1 BCP
  §4.14.1). The committed ceiling is exposed via the new optional
  `cappedExpiresAtMs` field on the `"rotated"` outcome — reserved for a
  Phase F follow-up that re-mints the issued JWT to match. For v0.5.1 the
  storage-level cap is the security primary; the issued refresh-token
  JWT's `exp` claim may still reflect `now + expiresIn` and the actual
  refresh-token lifetime is bounded by the server-side family TTL.

- **`pkceConfig.supportedMethods` element-type validation** (`@o3co/auth-provider-oauth`,
  closes TS-4): a new `resolvePkceSupportedMethods` helper replaces the
  duplicated `Array.isArray(...) ? (... as string[])` cast at
  `authorization.mts:57` and `routes.mts:431`. The cast was compile-time
  only — operator config such as `pkce.supportedMethods = [123, null, "S256"]`
  would have been accepted as `string[]` at the type level and the
  non-string elements silently relied on `.includes()` mismatch to be
  filtered. The helper performs per-element type narrowing, falls back to
  `["S256", "plain"]` on empty / non-array / all-non-string input, and
  emits a structured `pkce_supportedMethods_non_string_filtered` warn log
  when filtering occurs (logger plumbing at the call sites is deferred to
  D-4).

#### Migration

No client- or operator-visible behavioural changes for well-formed
configurations. Operators using `oauth.nonce.maxLength` env override should
note the field name (`OAUTH_NONCE_MAX_LENGTH`). Custom rotation-wrapper
implementations that destructure the `"rotated"` outcome remain
source-compatible because `cappedExpiresAtMs` is optional.

### BREAKING (Phase F — F6 PR1 D-6 PB-2 client authentication redesign, v0.5.1)

- **`Client` interface gains `tokenEndpointAuthMethod`** (`@o3co/auth-provider-core`)
  — REQUIRED discriminator with values
  `"client_secret_basic" | "client_secret_post" | "none"` (RFC 6749 §2.3 / RFC 7591 §2).
  Existing client configurations MUST add the field; `ClientEntrySchema` rejects
  entries that omit it. `clientSecret` is now `string | undefined` (optional)
  and a Zod `.superRefine` enforces "required iff method is `basic` / `post`,
  forbidden iff method is `"none"`". All `Client` fields are now `readonly`.

- **`/oauth/token` requires client authentication for every grant**: the
  built-in route now wires `clientAuthMw` ahead of the grant dispatcher.
  Calls without valid Basic credentials (or `client_id` body for public
  clients) receive `401 invalid_client`. Public clients (`tokenEndpointAuthMethod
  = "none"`) MUST send `client_id` in the form body and rely on PKCE/S256
  for authenticity.

- **PKCE/S256 is mandatory for public clients at `/authorize`** (RFC 9700
  §2.1.1): public-client requests without `code_challenge` or with
  `code_challenge_method != "S256"` are rejected via redirect-error
  `invalid_request`. The operator-level `pkce.required` config is no longer
  consulted for `"none"` clients.

- **`GrantContext.authenticatedClient: AuthenticatedClient | null`** is
  populated by `clientAuthMw` and consumed by the authorization-code and
  refresh-token grants. Custom grant handlers MUST update their
  `GrantContext` fixtures and rely on `ctx.authenticatedClient.clientId`
  rather than `body.client_id` for any identity decision.

- **Refresh-token grant binds RT to issuing client via `azp`**: the new
  binding gate compares `(claims.azp ?? aud) === ctx.authenticatedClient.clientId`.
  New tokens emit `azp` explicitly; legacy tokens (lacking `azp`) fall back
  to `aud` once. Body `client_id` is no longer destructured.

- **Authorization-code grant removes the in-grant `client_secret` check**
  (RFC 6749 §2.3 belongs at the route, not the handler) and replaces every
  raw-body `client_id` use that fed an identity sink (token `aud`/`azp`,
  ID-token `aud`/`azp`, grant-policy `clientId`, session RP registration,
  logout-metadata lookup) with `ctx.authenticatedClient.clientId`.
  `body.client_secret` is no longer destructured.

- **`clientAuthMw` enforces per-method transport (Codex M1)**: a client
  configured for `"client_secret_basic"` cannot succeed via body credentials
  (and vice versa) — wrong-transport attempts return `invalid_client`
  regardless of credential validity. Basic-header + body-credential
  conflict (Codex M4) is rejected with `invalid_client` before any
  repository lookup.

- **Token Exchange grant**: when dispatched via the standard `/token`
  route, `clientAuthMw` runs ahead of the grant; the grant retains its
  internal `client_secret_post` check as a no-op double-auth so consumers
  who wire it onto custom routes keep the same authenticity guarantee.

- **`InMemoryClientRepository.authenticate()` returns `null` for public
  clients** (`tokenEndpointAuthMethod = "none"`) without throwing —
  callers should dispatch to `findById` for public clients.

#### Migration

`config/clients.yaml`:

```yaml
# Confidential client (most common case)
my-app:
  tokenEndpointAuthMethod: "client_secret_basic"  # ADD THIS
  clientSecret: "..."
  # ... existing fields unchanged

# Public client (SPA / mobile)
my-spa:
  tokenEndpointAuthMethod: "none"                 # ADD THIS
  # clientSecret MUST be absent for "none"
  allowedRedirectUris:
    - "https://app.example/callback"
  allowedScopes: ["openid", "profile"]
```

Confidential client requests to `/oauth/token` MUST send credentials via
either HTTP Basic header or the body `client_id` + `client_secret` pair
(matching the configured `tokenEndpointAuthMethod`). Public client requests
MUST send `client_id` in the body and (at `/authorize`) include
`code_challenge` + `code_challenge_method = "S256"`.

### Changed (Phase F — F4 PR2 standalone wiring batch + IH-10/17/18, v0.5.1)

- **Single shared ioredis socket per replica** (`templates/standalone`):
  the standalone composition root now opens **one** ioredis connection
  and derives all per-purpose clients (refresh-token-family, 4 user-session
  stores, OAuth-endpoint rate limiter) via `makeIoredisClients(io)`. The
  F4 PR1 `refreshTokenFamilyClientModule` is replaced by a unified
  `standaloneRedisClientsModule` that provides all 6 client slots from the
  shared connection. Connection-pool pressure on the upstream Redis drops
  proportionally; lifecycle drains 1 socket instead of 3+. Memory-only
  deployments skip the shared module entirely so they don't open an unused
  socket.

- **OAuth-endpoint rate limiter is wired by default** (`templates/standalone`,
  closes IH-14 + OR-M1): `buildModules` now includes `memoryRateLimiterModule`
  by default. Pre-fix, no rate-limiter module was wired at all and
  `checkRateLimit` in `routes.mts` unconditionally fail-opened — production
  deployments had ZERO rate limiting on `/token` + `/authorize` despite
  having config for it. Set `rateLimiter.adapter = "redis"` (or
  `RATE_LIMITER_ADAPTER=redis`) for shared counters across replicas.

- **Multi-replica session stores via Redis** (`templates/standalone`,
  closes OR-4): `buildModules` now switches the four user-session stores
  (`userSessionStore`, `sessionRPRegistry`, `sessionFamilyIndex`,
  `sessionFederationIndex`) to `redisSessionStoresModule` when
  `userSessionStores.adapter = "redis"` (or
  `USER_SESSION_STORES_ADAPTER=redis`). Pre-fix, all four were unconditionally
  in-memory in production, losing state on restart and across replicas.

- **`AppConfigSchema` adapter selectors** (`@o3co/auth-provider-core`):
  `rateLimiter.adapter: "memory" | "redis"` and
  `userSessionStores.adapter: "memory" | "redis"` added as top-level
  optional sections on `fullSectionsSchema`. Defaults `"memory"` live in
  HOCON (`packages/core/config/application.conf` +
  `templates/standalone/config/application.conf`), per the project ADR
  ("schema is a pure type contract; defaults live in HOCON").

- **`BuildModulesOverrides.refreshTokenFamilyModules` semantics**
  (`templates/standalone`): the override now drops both the shared
  `standaloneRedisClientsModule` and the redis store module (was: dropped
  PR1's per-purpose `refreshTokenFamilyClientModule` + redis store). Smoke
  tests pass `[memoryRefreshTokenFamilyStoreModule]` here exactly as
  before — no test fixture change required.

### Bug Fixes (Phase F — IH-10 / IH-17, v0.5.1)

- **`AppConfigSchema.endpoints.client` and `endpoints.authCallback` removed**
  (closes IH-10): no production consumer reads either field. The pre-fix
  env-var-only HOCON lines (`client { url = ${?ENDPOINTS_CLIENT_URL} }` and
  the `authCallback` analogue) silently leaked values into `AppConfig` that
  nothing consumed. Federation provider callback URLs are configured
  per-provider (e.g. `federations.google.callbackURL`), not via a generic
  `endpoints.authCallback`.
  **Migration**: configs that wrote either field continue to validate (Zod
  strips unknown keys); the parsed `AppConfig.endpoints` no longer exposes
  the keys at the type level.

- **`endpoints.login.url` is now required at the base schema level**
  (closes IH-17): tightened from `z.string().optional()` to `z.string()`.
  The runtime invariant was already enforced by `oauthModule.configSchema`
  at boot time; the base schema now matches the contract so `AppConfig` no
  longer types the field as `string | undefined`. Default `"/login"` added
  to `packages/core/config/application.conf` so deployments that omit
  `ENDPOINTS_LOGIN_URL` boot successfully (previously: confusing late
  failure from `oauthConfigSchema`).

### Documentation (Phase F — IH-18, v0.5.1)

- **`rateLimit.login.windowMs` JSDoc clarification** (`@o3co/auth-provider-core`):
  the existing `rateLimit.login.windowMs` (express-rate-limit, milliseconds,
  governs session-route bruteforce protection) is intentionally distinct from
  the OAuth-endpoint `RateLimitSpec.windowSeconds` (seconds, governs the
  pluggable `RateLimiterBase` adapter). Inline JSDoc + HOCON comments now
  spell this out to prevent operator confusion. No code change.

### Changed (Phase F — D-2 v2 standalone ioredis unification, v0.5.1)

- **Multi-replica refresh-token persistence** (`templates/standalone`): the
  standalone composition root now wires
  `redisRefreshTokenFamilyStoreModule` (backed by a long-lived ioredis
  connection from the new `refreshTokenFamilyClientModule`) by default,
  replacing the in-memory `memoryRefreshTokenFamilyStoreModule`. This
  closes OR-1 — pre-fix, multi-replica deployments returned `invalid_grant`
  on every cross-replica refresh because each replica held RT families in
  its own process memory.
  **Migration**: set `REFRESH_TOKEN_FAMILY_STORE_REDIS_URL` to a shared
  Redis 7.2+ instance. Falls back to `redis://localhost:6379` if unset
  (which is correct for single-instance deployments and CI). The HOCON
  config gains a `refreshTokenFamilyStore.redis.{url, password}` block in
  both `packages/core/config/application.conf` and
  `templates/standalone/config/application.conf`. Module-internal config
  (`keyPrefix`, `casRetryLimit`) stays under the existing
  `redisRefreshTokenFamilyStore.*` top-level key.

- **`BuildModulesOverrides.refreshTokenFamilyModules`**
  (`templates/standalone`): new optional override that replaces BOTH the
  RT family client module AND the store module as a unit. Default is
  `[refreshTokenFamilyClientModule, redisRefreshTokenFamilyStoreModule]`.
  Smoke tests / unit tests pass `[memoryRefreshTokenFamilyStoreModule]`
  here to avoid opening an ioredis connection.

- **New runtime dependency** (`templates/standalone`): `ioredis ^5.4.1`
  added as a direct dependency for the RT family store client (the
  `makeIoredisClients` factory from
  `@o3co/auth-provider-redis/ioredis` returns the typed
  `RefreshTokenFamilyClient` shape including the `duplicate()` method
  required for WATCH/MULTI/EXEC CAS isolation). Existing Redis client
  dependencies (`redis ^5.10.0`, `connect-redis ^9.0.0`) are unchanged.

- **`AppConfigSchema`** (`@o3co/auth-provider-core`):
  `refreshTokenFamilyStore.redis.{url, password}` added to
  `fullSectionsSchema` as an optional section (defaults live in HOCON,
  not in the Zod schema, per ADR). Existing configs that omit this
  section continue to validate without change.

### Breaking Changes (Phase F — D-1 Code/CodeData identity binding, v0.5.1)

- **`CodeData.client_id` and `CodeData.redirect_uri` are now required fields**
  (`@o3co/auth-provider-core`): `CodeRepository.createCode(...)` requires
  `client_id: string` and `redirect_uri: string` on the params object. The
  compile-time guard `Parameters<CodeRepository["createCode"]>[0]` makes
  every implementation site fail typecheck when a field is added but not
  destructured. Custom `CodeRepository` implementations must accept and
  persist both fields.
  **Migration**: callers building a `CodeData` literal must add `client_id`
  and `redirect_uri`. The bundled `InMemoryCodeRepository` and
  `RedisCodeRepository` are updated; consumer composition roots that wire a
  custom repository must update its createCode signature.

- **`/oauth/authorize` no longer writes `req.session.code`,
  `req.session.code_client_id`, `req.session.code_redirect_uri`, or
  `req.session.granted_scopes`** (`@o3co/auth-provider-oauth`): the four
  session writes at the end of the GET `/authorize` handler are removed.
  Identity binding is embedded in the code record (`Code.client_id` /
  `Code.redirect_uri`) and is exchanged at `/token` exclusively via
  `consumeByCode` (atomic single-use). Custom middleware that read these
  session fields will no longer see them populated.
  **Migration**: rewrite middleware that observed `req.session.code*` to
  inspect the request body or the `codeRepository.getByCode` return value
  instead.

- **`/oauth/token` (authorization_code grant) drops the session-based
  identity gates** (`@o3co/auth-provider-oauth`): the previous
  `code !== session.code` and `client_id !== session.code_client_id`
  checks are removed. `consumeByCode` is the sole authenticity gate;
  `client_id` and `redirect_uri` are verified against `codeData.*` fields
  populated at `/authorize` time. The `redirect_uri` binding (RFC 6749
  §4.1.3) is now strictly enforced — when `codeData.redirect_uri` is
  absent (legacy/corrupt records), the request is rejected with
  `invalid_grant` rather than vacuously accepted.

- **`sessionMutation.clear` shrinks** (`@o3co/auth-provider-oauth`): the
  authorization grant's returned `sessionMutation.clear` list no longer
  contains `code_client_id`, `code_redirect_uri`, or `granted_scopes`
  (only `code` remains, to scrub residual values from sessions issued
  before v0.5.1 ships).

### Bug Fixes (Phase F — D-1, v0.5.1)

- **Redis deployments with `userSessionStore` could not complete a single
  authorization-code exchange** (`@o3co/auth-provider-redis`):
  `RedisCodeRepository.createCode` silently discarded `sid`, `nonce`,
  `redirect_uri`, `grantedScope`, and `grantedAudience`, causing every
  `/token` exchange to fail with `invalid_grant: code record is missing
  session identifier`. Fixed by persisting all fields in the Redis JSON
  payload (closes IH-2 / TS-1 / TD-1).

- **RFC 6749 §4.1.3 `redirect_uri` binding was silently skipped in Redis
  deployments** (`@o3co/auth-provider-oauth`): when `codeData.redirect_uri`
  was undefined (the IH-2 drop bug), the binding check at `/token` was
  guarded by `if (storedRedirectUri)` and skipped entirely. The check is
  now strict: absent or mismatched `redirect_uri` returns `invalid_grant`
  (closes IH-4).

- **Concurrent `/authorize` requests sharing an Express session could
  race** (`@o3co/auth-provider-oauth`): two simultaneous `/authorize` calls
  on the same session would clobber each other's `req.session.code`
  last-write-wins, leaving the losing request's code orphaned in the
  repository (unredeemable because the `code !== session.code` gate would
  reject it). Fixed by removing the four `req.session.code*` writes and
  binding identity to the code record (closes CR-2).

### Breaking Changes (Phase F — D-10 Redis 7.2 LTS minimum, v0.5.1)

- **Redis 7.2 LTS minimum required** (`@o3co/auth-provider-redis`): the Redis-backed
  session adapters (`createRedisSidSortedSet`, `createRedisSidHash`) now use
  `PEXPIREAT … NX` + `PEXPIREAT … GT` (Redis 7.0+ flags) on the per-sid TTL
  pipeline to prevent TTL truncation under concurrent writes (CR-3). The pair
  is required because Redis treats a non-volatile (no-TTL) key as having
  infinite TTL for the GT flag, so a bare `PEXPIREAT … GT` silently no-ops on
  the first write — the NX clause sets the TTL on first write, the GT clause
  raises it on subsequent writes only when the new ts is strictly greater.
  Redis 6.x servers do not support either flag and will return `ERR syntax
  error` at the first session write.
  **Migration**: upgrade your Redis server to 7.2 LTS or later before deploying
  v0.5.1. AWS ElastiCache for Redis 7.2, Upstash Redis, and Redis Cloud all
  support the GT/NX flags. See `SessionRPRegistryMultiClient.pExpireGT` JSDoc
  in `packages/redis/src/clients.mts` for the full semantics.

- **`engines.node >=18.19.0`** (all eight published packages): every
  `@o3co/auth-provider-*` package now declares `"engines": { "node": ">=18.19.0" }`.
  npm/pnpm prints a warning by default; **pnpm enables `engines-strict=true` by
  default in some configurations**, which causes a hard install failure on
  Node <18.19. Consumers on Node 18.0.0–18.18.x should upgrade to Node 18.19.0
  LTS or later before installing v0.5.1; Node 20 LTS and 22 LTS are unaffected.

- **`pExpireGT` added to `SessionRPRegistryClient`/`MultiClient` and
  `SessionSidSortedSetClient`/`MultiClient`** (`@o3co/auth-provider-redis`): the
  four backing-client interfaces gain a non-optional `pExpireGT(key, msTimestamp)`
  method (multi-client variant returns the chainable client for pipelining). The
  bundled `makeIoredisClients()` adapter implements the new method as a
  `pexpireat(k, ms, "NX")` + `pexpireat(k, ms, "GT")` pair (the bare GT form
  silently no-ops on a key with no existing TTL — see method JSDoc). Custom
  backing-client implementations (non-ioredis) must add `pExpireGT` to compile.

### Breaking Changes (Phase F — D-5 BuilderContext.lifecycle, v0.5.1)

- **Standalone session wiring moved into `sessionStoreModule`**
  (`@o3co/auth-provider-session`): the standalone composition root
  (`templates/standalone/src/app.mts`) no longer constructs the
  `express-session` middleware manually. The new `sessionStoreModule`
  contributes the middleware via the boot planner, so the underlying
  `connect-redis` client lifetime is owned by the new
  `BuilderContext.lifecycle` and drained on `handle.dispose()` (closes
  OR-M2 — connect-redis client never quit).
  **Migration**: operators who copied `templates/standalone/src/app.mts`
  into their own composition root must (1) remove the manual
  `app.use(session(...))` block and the surrounding session-store factory
  setup, (2) prepend `sessionStoreModule` to their `buildModules(...)`
  list (it MUST be ahead of every session-consuming module —
  declarationIndex order tie-breaks the route mount), (3) ensure their
  app declares `express-session` (now a peer dependency of
  `@o3co/auth-provider-session`).

- **`BuilderContext.lifecycle?: LifecycleRegistrar` slot added**
  (`@o3co/auth-provider-core`): `AdapterFactory` builders that create
  disposable sub-resources (Redis clients, interval timers) SHOULD now
  call `ctx.lifecycle?.register(async () => { await resource.close(); })`.
  The boot planner pre-seeds a `LifecycleRegistrar` instance into the
  bootstrap component map; modules forward it via
  `optional: ["lifecycleRegistrar"]` and `createAdapterFactory(kind, {
  lifecycle: deps.lifecycleRegistrar })`. `AppHandle.dispose()` drains the
  registrar in LIFO order after component-level cleanups.
  Existing builders that ignore `ctx` continue to work — the field is
  additive optional. The `lifecycleRegistrar` slot is reserved by the
  boot planner; `bootstrap-component-collision` /
  `synthetic-key-collision` errors fire if a consumer supplies it via
  `bootstrapComponents` / `overrideComponents`.

- **`@o3co/auth-provider-session` peerDependencies**: adds
  `express-session ^1.17.0`. Previously declared only via
  `@types/express-session`. Standalone consumers already have it
  installed transitively via `connect-redis`; the explicit declaration
  documents the requirement for module pattern users.

- **`RedisCodeRepository.[Symbol.asyncDispose]()` + `dispose()` added**
  (`@o3co/auth-provider-redis`): both methods call `quit()` on the
  underlying node-redis client (idempotent — safe to call twice).
  `redisCodeRepositoryBuilder` now registers `repo.dispose()` with
  `ctx.lifecycle` automatically (closes OR-2 — RedisCodeRepository
  never quit).

- **`InMemoryCodeRepository` `dispose()` registered automatically**
  (`@o3co/auth-provider-core`): the memory `codeRepository` adapter
  builder now registers the existing `repo.dispose()` (clears the
  periodic-GC `setInterval`) with `ctx.lifecycle`. Closes IH-11 —
  `setInterval` never cleared. The `setInterval` no longer keeps the
  Node.js event loop alive past `handle.dispose()`.

- **DEFERRED to a separate cross-repo PR**:
  `repos/auth.utils/src/shutdown.mts` `gracefulShutdown()` rewrite —
  await cleanup inside `server.close()` callback, add
  `closeAllConnections()`. This is required as a prerequisite to v0.5.1
  publish but ships as a `@o3co/auth.utils` patch release independent of
  auth.provider's release cadence. (Closes OR-3.)

### Breaking Changes (Phase F — D-9 federation-tokens lock CAS, v0.5.1)

- **`FederationTokenStoreClient.compareAndDelete` added** (`@o3co/auth-provider-redis`):
  the `FederationTokenStoreClient` interface gains a required
  `compareAndDelete(key, expectedValue): Promise<boolean>` method for atomic
  advisory-lock release (closes CR-1 / OR-13 / SF-4). The pre-D-9 release
  path was non-atomic GET+DEL, which had a race window during which a
  TTL-expired holder could evict a freshly-acquired lock owned by a different
  process. Lock semantics are now atomic via a server-side Lua compare-and-
  delete script.
  Custom implementations of `FederationTokenStoreClient` MUST add this method
  with atomic semantics. Implementation guide: run a Lua `EVAL` script
  `if redis.call("GET", KEYS[1]) == ARGV[1] then return redis.call("DEL", KEYS[1]) else return 0 end`
  with `keys=[key]`, `arguments=[expectedValue]`, returning `result === 1`.
  Redis Cluster-mode deployments with Lua scripting disabled require an
  alternative atomic strategy.
  The bundled `makeIoredisClients()` adapter implements this automatically
  via Lua `EVAL` with `EVALSHA` caching and `NOSCRIPT` fallback.

- **`RedisLockClient` interface narrowed** (`@o3co/auth-provider-redis`,
  internal): the lock's minimal client interface drops `get` and `del` in
  favor of the new `compareAndDelete`. The interface is not exported from
  the package index and only used internally by the federation-tokens lock
  bridge — no external impact.

### Bug Fixes (Phase F — v0.5.1)

- **federation-tokens lock release race**: federation-token refresh paths
  could spuriously evict a freshly-acquired lock held by a different process
  when the previous holder's TTL expired mid-call. The release path is now
  an atomic Lua compare-and-delete (D-9, closes CR-1 / OR-13 / SF-4). Custom
  `FederationTokenStoreClient` implementations must implement
  `compareAndDelete` with atomic semantics (see breaking-change entry above).

- **federation-tokens production guard for `allow-plaintext`**: the redis
  federation-token store builder (`redisFederationTokenStoreBuilder`) now
  refuses to construct a store with `encryption.mode = "allow-plaintext"`
  when `NODE_ENV` is `"production"` or `"staging"`, throwing a startup error
  unless the operator explicitly sets `FEDERATION_TOKENS_ALLOW_INSECURE=1`
  to opt in (with a CRITICAL `console.error` warning). Pre-fix the builder
  emitted a soft `console.warn` and continued, allowing federation tokens
  (long-lived IdP refresh tokens) to ship unencrypted to production by
  misconfiguration. Dev/test environments retain warn-only behavior. (OR-12,
  closes CC-3 residual.)

- **federation-refresh:** Fix Google (and other built-in) federation token refresh
  broken in v0.5.0. The route-side duck-type capability check in
  `packages/oauth/src/routes/federationToken.mts` probed for `refreshFederationToken`
  while the published `SupportsRefresh` interface (and all built-in providers,
  e.g. `@o3co/auth-provider-federation-google`) declare `refreshToken`. The
  mismatch caused every request that required an upstream token refresh to return
  `503 refresh_not_supported`, forcing users to re-authenticate with the identity
  provider on every new session. The route now probes the correct capability name.
  No changes to `SupportsRefresh`, `FederationProvider`, or any provider
  implementation; consumer-visible public API is unchanged. (Closes Area-4-NEW,
  D-8.)

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
  semantics. Twelve types moved; consumers update type imports from
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
