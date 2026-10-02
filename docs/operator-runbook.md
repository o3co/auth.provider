# Operator runbook

How to run `auth.provider` in production: what to set, what you will see, and
what to do when a dependency fails. Companion to
[release-runbook.md](release-runbook.md), which is about *cutting* a release,
and [release-policy.md](release-policy.md), which is about labelling one.

Written against `v0.11.0`. Every config key, route, status code, log event and
Redis key below was checked against source at that tag, and each claim names
the file it comes from in parentheses. When this document and the code
disagree, the code is right and this document has a bug — file it.

Environment-variable names are the standalone template's
(`templates/standalone/config/application.conf`, the template's own
`templates/standalone/config/reference.conf`, and the `reference.conf` of each
package it loads, core's among them). A composition root of your own reads
the same HOCON keys through whatever binding you gave them.

---

## 1. Deployment shapes

### `core.deployment.mode` — say how many replicas you run

`core.deployment.mode` (env `CORE_DEPLOYMENT_MODE`) has three states and **no default**
(`packages/core/config/reference.conf`, `packages/core/src/boot/replica-safety.mts`).
`deployment.mode`, at the top level, refuses boot naming this path
(`config-path-relocated`). `DEPLOYMENT_MODE` is declared renamed
`CORE_DEPLOYMENT_MODE`: set alone, or beside it at a different value, it refuses
boot (`environment-variable-renamed`); set beside it at the same value, it boots.

| Value | What boot does |
| --- | --- |
| `multi` | Refuses to boot if any module on the replica-unsafe list below is wired, naming every offender and what diverges per replica (`BootError` reason `replica-unsafe-adapter`). |
| `single` | Silent. You have declared one replica; in-process state is correct. |
| unset | Boots, and logs one `replica_unsafe_adapters` warning listing what is held in this process's memory and what each one costs when scaled. |

The guard reads the declaration each installed module carries on its own
manifest (`replicaSafety: { unsafe, reason }` on `defineModule`, read by
`checkReplicaSafety` in `packages/core/src/boot/replica-safety.mts`), not the
config, because a composition root can wire a module without going through the
adapter switches. A module that declares nothing is treated as replica-safe, so
a module of your own that holds per-process state must carry the declaration or
the guard will not see it (`replicaUnsafeReason(module)` reads any manifest).
Core's own in-memory modules declare it as follows
(`REPLICA_UNSAFE_BUNDLED_MODULES`; the names alone are exported as
`REPLICA_UNSAFE_MODULES`):

| Module name | What forks per replica |
| --- | --- |
| `core-session-stores-memory` | user sessions, RP registrations, family indexes and the subject-level revocation pair — back-channel logout reaches only the replica that received it; a credential change watermarks only the replica that handled it |
| `core-rate-limiter-memory` | rate-limit counters — every limit is multiplied by the replica count and resets on each deploy |
| `core-access-token-denylist-memory` | access-token revocation — a revoked token keeps working on every replica that did not receive the revocation |
| `core-replay-seen-set-memory` | single-use records — a `private_key_jwt` client assertion, the `jti` of an ID-JAG (jwt-bearer) assertion, a consumed WebAuthn challenge (the ceremony marks it seen here) or, with DPoP enabled, a DPoP proof captured once can be replayed once against each replica |
| `core-refresh-token-family-store-memory` | refresh-token families — rotation replay detection and cascade revoke see only this replica's history, and a restart forgets every revoked family while its access tokens are still valid |
| `core-challenge-store-memory` | WebAuthn challenges — a ceremony started on one replica cannot finish on another |
| `core-webauthn-credential-store-memory` | registered passkeys — a passkey registered on one replica does not exist on the others |
| `core-device-code-store-memory` | pending device authorizations — the human approves on one replica while the device polls another that has never heard of the code |
| `core-federation-token-store-memory` | upstream federation tokens — stored on one replica, missing on the others |
| `core-consent-store-memory` | consent records and parked consent requests — a consent granted on one replica is asked for again on every other, one revoked there stays granted here, and a consent challenge parked on one replica is unknown to every other |
| `core-federation-grant-store-memory` | federation grants — a grant lodged or authorized on one replica is unknown to every other, one revoked there still yields upstream tokens here, and a refresh token rotated on one replica leaves every other presenting the old one, which a reuse-detecting IdP answers by revoking the family |
| `core-federation-grant-intent-store-memory` | federation grant acquisition — an intent lodged on one replica is unknown to every other, so the consent page and the upstream callback answer as if the flow had expired whenever they land elsewhere, and the bound on live intents is counted per replica instead of per (client, subject). Established grants and revocations are unaffected, so this adapter beside a durable grant store is a single-replica configuration rather than a broken one |
| `core-mfa-factor-store-memory` | enrolled second factors — a factor enrolled on one replica is unknown to every other, and a restart empties every replica: each subject then reads as one with nothing enrolled |
| `core-mfa-transaction-store-memory` | MFA transactions and the lock state — a transaction started on one replica is unknown to the replica that receives the verification, and the attempt limits and the lockout are counted per replica. A restart also loses the email proof an operator reset required (`resetMfaForSubject` with `requireEmailProof: true`): beside a durable factor store, a password holder can then bind without it. Do not use it where operator resets are used. A restart also forgets every subject's generation and recovery-set floor: a write that captured 0 before a recovery is let through, and an older recovery-code set verifies again. At its cap (`maxEntries`) it refuses a new subject lease, so a recovery or a reset cannot proceed until room frees |
| `session-store` (only with `session-store.storage.type = "memory"`, `SESSION_STORE_STORAGE_TYPE=memory`; #474) | the express-session store — a login served by one replica is unknown to the others, so a browser whose next request lands elsewhere is logged out, and every session is lost on restart |

DPoP keeps no store of its own: every accepted proof is recorded in the
seen-set above (`dpop-proof:<jkt>`), so `core-replay-seen-set-memory` is what
refuses a DPoP deployment under `multi` and names it in the unset-mode
warning, and `redisReplaySeenSetModule` (`ADAPTERS_REPLAY_SEEN_SET=redis` in the
standalone) is what lets replicas refuse each other's proofs. With DPoP enabled
and no seen-set wired at all, `dpopModule` refuses to boot in every mode
(`packages/dpop/src/module.mts`); there is no per-process fallback.

A seen-set wired for DPoP is wired for `private_key_jwt` too: the slot is
where a client assertion's `jti` is recorded, so filling it is what makes
the method work. With the slot filled, a client registered with `jwks` /
`jwksUri` can authenticate with an assertion — it was refused
`500 server_error` without one — at `/oauth/token`, `/oauth/introspect` and
`/oauth/revoke` (`packages/oauth/src/module.mts`, which also starts
advertising the method and its signing algorithms in discovery), at
`POST /oauth/device_authorization` (`packages/device-grant/src/module.mts`),
and on every client route under `/oauth/federation-grants` — `POST
/:grantId/token`, `/:grantId/status`, `/:grantId/revoke`, and with
acquisition on `POST /` and `/:grantId/reauthorize`
(`packages/federation-grants/src/routes.mts`).

Three things the guard cannot do:

- **It cannot notice that you scaled without setting the mode.** A process
  whose state is all in its own memory has no shared medium through which to
  see peers. Set `CORE_DEPLOYMENT_MODE=multi` as part of scaling, not after
  something breaks.
- **It only sees modules that declare themselves.** The standalone template's
  own in-memory modules — `standalone-in-memory-session-stores`,
  `standalone-in-memory-code-repository` and
  `standalone-in-memory-federation-token-store`
  (`templates/standalone/src/modules.mts`) — carry the declaration since #455,
  so `multi` refuses them by name; before #455 they booted. Three more joined
  them in #474 and are refused the same way: express-session's own store under
  `SESSION_STORE_STORAGE_TYPE=memory`, and the login and WebAuthn-options rate
  limiters when no shared `rateLimiter` is wired, and so is the MFA routes'
  limiter when the MFA module is installed. With the mode **unset**
  express-session's store joins the single `replica_unsafe_adapters` warning,
  and the rate limiters warn on their own (`login_rate_limiter_not_shared`,
  `webauthn_authentication_options_rate_limiter_not_shared`,
  `mfa_rate_limiter_not_shared`, [§4](#4-alerts)).
- **It does not see state inside a component you build and hand in.** The
  jwt-bearer trust registry is one: `createMemoryAssertionIssuerRegistry` lives
  inside the `assertionVerifier` you pass as a bootstrap component, not in a
  module. Entries supplied when the registry is built are identical on every
  replica, which is safe. The admin surface is not: `add`, `remove` and
  `setExpiresAt` change this process's registry only, so an issuer revoked with
  `setExpiresAt` on the replica that took the call is still trusted by every
  other replica. A restart does not converge them: it rebuilds the registry
  from the composition's entries, which puts the revoked issuer back on that
  replica too. Under `multi`, change the entry list and redeploy, or implement
  `AssertionIssuerRegistry` over a shared store. A seen-set handed in the same
  way is another: `createMemoryReplaySeenSet()` passed as the `replaySeenSet`
  bootstrap component, rather than installed as `memoryReplaySeenSetModule`,
  is per-process and boots under `multi` without a word — for every consumer
  of the seen-set, DPoP included.

In the standalone, `CORE_DEPLOYMENT_MODE=multi` therefore boots only once every
store is on Redis: `ADAPTERS_USER_SESSION_STORES=redis`,
`ADAPTERS_CODE_REPOSITORY=redis`, `ADAPTERS_RATE_LIMITER=redis`,
`ADAPTERS_ACCESS_TOKEN_DENYLIST=redis`, `SESSION_STORE_STORAGE_TYPE=redis`, and
`ADAPTERS_FEDERATION_TOKEN_STORE=redis` together with
`REDIS_FEDERATION_TOKEN_STORE_ENCRYPTION_KEY` (canonical base64 of exactly 32
bytes — the AES-256 key, e.g. `openssl rand -base64 32`; the builder refuses
any other length, and a value with whitespace, the URL alphabet or missing
padding; `templates/standalone/src/buildModules.mts`,
`packages/redis/config/reference.conf`). The consent step for clients that are
not first-party is off by default (`ADAPTERS_CONSENT_STORE=none`); to serve such
clients under `multi`, set `ADAPTERS_CONSENT_STORE=redis` — `memory` is refused
there (#561; `packages/redis/src/consent-store.mts`).
A deployment that ran `multi` with the default in-memory federation-token store
before #455/#456 is refused at boot once they land — set the last pair before
upgrading. `adapters.federationTokenStore` is read in the template's first
configuration phase, with the template's own schema, and the store's own section, `redis-federation-token-store`,
key included, is parsed by its module.

### The standalone production compose

`templates/standalone/docker-compose.production.yml` is the deployable shape:
the `runtime` image target, no source mounts, `restart: unless-stopped`, a
Redis reachable only on the compose network and persisting to a volume
(`--appendonly yes`), a **required** `.env`, and the signing-key pair mounted as
compose secrets at `/run/secrets/jwt_private_key` / `jwt_public_key`. Its
`environment:` block pins `NODE_ENV=production`, `CORE_DEPLOYMENT_MODE=single`,
`SESSION_STORE_SECURE=true`, `SESSION_STORE_NAME=__Host-auth.session`,
`SESSION_STORE_STORAGE_TYPE=redis`, `ADAPTERS_USER_SESSION_STORES=redis`,
`ADAPTERS_RATE_LIMITER=redis`, and both Redis URLs to `redis://redis:6379`. The
app port is published on loopback only (`127.0.0.1:3000:3000`).

The user-session line is there for a reason the replica guard cannot supply.
Under `CORE_DEPLOYMENT_MODE=single` the guard is silent by design — it answers "can
these stores be shared", not "do these two stores have the same lifetime" — so
it said nothing when express-session was on Redis and the `UserSession` stores
were on their `memory` default. A provider restart then left every browser
holding a Redis-backed express-session that still read `isAuthenticated` with
no `UserSession` behind it: `/authorize` sends the browser to log in, the
surviving cookie puts it straight back, and the loop clears only when the user
deletes the cookie by hand. The compose now states every store's backend
explicitly rather than letting one inherit.

What it deliberately leaves to you (its own header says so): TLS termination in
front, the multi-replica steps above before any `--scale`, and every secret.
`HTTP_TRUST_PROXY` is now an explicit `${HTTP_TRUST_PROXY:?…}` entry rather
than an omission — compose refuses to start until you name the hop, because
there is no value that file could default to that would not silently trust one
you never chose. Put it in `.env` (there is an empty `HTTP_TRUST_PROXY=` in
`.env.example`) as your edge's address or CIDR range, not `true`.

It also leaves you the **trust boundary of the auth host's registrable
domain**. `__Host-auth.session` cannot be set by any other host, but a
`form_post` federation (Sign in with Apple) additionally issues a path-scoped
transaction cookie — `session-store.name` with any `__Host-` / `__Secure-` prefix
stripped, then `__Secure-` and `.federation` applied, so the default
`__Host-auth.session` yields `__Secure-auth.session.federation` — and
`__Secure-` does not stop another host under the same registrable domain (for
`auth.example.com`, any `*.example.com`) setting a cookie of that name with
`Domain=example.com`. A related-domain attacker — a forgotten staging host, a
dangling DNS record, XSS on a lower-trust app next door — can use that to log a
victim's browser into the attacker's own federated account. It reaches no
session and no credential, and there is nothing to configure: the mitigation is
that no untrusted content runs on any host under the auth host's registrable
domain. `session-store.domain = null` protects the session cookie, not this one.
Stated in full, with what the attacker needs and what it gets them, in
[`packages/session/README.md`](../packages/session/README.md#every-host-on-the-auth-hosts-registrable-domain-is-inside-the-trust-boundary)
(#502).

### Inputs with no default

Boot fails on each of these rather than guessing. All are validated at
config-parse time unless noted.

| Setting (env) | Rule | Where enforced |
| --- | --- | --- |
| `oauth.jwt.issuer` (`OAUTH_JWT_ISSUER`) | absolute `https` URL (`http` only for a loopback host), no query or fragment; never derived from `Host` | `packages/core/src/config/application.schema.mts` via `packages/core/src/issuer/canonical.mts` |
| Signing key material (`KEY_STORE_LOCAL_PRIVATE_KEY_PATH` + `KEY_STORE_LOCAL_PUBLIC_KEY_PATH`, or the inline `KEY_STORE_LOCAL_PRIVATE_KEY` / `KEY_STORE_LOCAL_PUBLIC_KEY`) | required for `EdDSA` (the default), `ES256`, `RS256`; the boot error prints the `openssl` commands | `packages/core/src/keys/factory.mts` |
| `KEY_STORE_LOCAL_SECRET` (only with `KEY_STORE_LOCAL_ALGORITHM=HS256`) | at least 32 bytes of key material, measured on the *decoded* length of hex/base64 | `packages/core/src/keys/secretEntropy.mts`, applied in `keys/factory.mts` |
| `session-store.secret` (`SESSION_STORE_SECRET`) | same 32-byte floor; no default, so the session store's module refuses to build without it, naming the variable | the session store's section schema (`sessionStoreConfigSchema`, `packages/session/src/modules/sessionStoreModule.mts`) |
| `session-store.name` / `session-store.secure` / `session-store.domain` / `session-store.sameSite` (`SESSION_STORE_NAME`, `SESSION_STORE_SECURE`, `SESSION_STORE_DOMAIN`, `SESSION_STORE_SAME_SITE`) | a `__Host-` cookie name (the default) requires `secure = true` and `domain = null`, and a `__Secure-` name `secure = true` (either prefix in any case); the name must be an RFC 6265 token — no space, `;` or other separator, not empty; `domain` must be a host name, one leading dot allowed — no scheme, port or path; `sameSite = "none"` requires `secure = true`. The session store's rules apply where its module is installed; the issue names the key | `packages/session/src/session-cookie-policy.mts`, the session store's section schema (`packages/session/src/modules/sessionStoreModule.mts`) |
| `repositories.user.http.authenticateUrl` / `authenticateByTokenUrl` (`REPOSITORIES_USER_HTTP_AUTHENTICATE_URL`, `REPOSITORIES_USER_HTTP_AUTHENTICATE_BY_TOKEN_URL`) | absolute `https` (loopback `http` only); `timeout` a positive integer ≤ 2147483647 ms. Whether an endpoint redirects cannot be checked at construction, so it is required all the same: each URL is the endpoint that answers — a `3xx` is not followed, so a URL that redirects fails every call ([foundation README](../packages/foundation/README.md#what-the-store-must-enforce-itself)) | `packages/foundation/src/repositories/HttpUserRepository.mts` |
| `repositories.user.http.bearerToken` (`REPOSITORIES_USER_HTTP_BEARER_TOKEN`) | optional — unset sends the Store no `Authorization` header. Set, including exported but empty, and `adapters.userRepository = "http"` (`ADAPTERS_USER_REPOSITORY`, the standalone's default; `yaml` never reads the `http` block): a bare RFC 6750 token (no `Bearer ` prefix, no whitespace) with at least 32 bytes of key material, measured like `SESSION_STORE_SECRET`; the message never quotes the value. One token goes to every Store endpoint configured — the user repository's URLs, `markMfaEnrolledUrl` among them, and the MFA factor endpoints — so they must be one trust domain. The Store should refuse every request without it, with `401` (or `403`) and a `Bearer` challenge; a token it refuses is not a boot failure but an outage on every Store call (see the Store row in [§3](#3-what-fail-closed-looks-like-on-each-path); [foundation README](../packages/foundation/README.md#what-the-store-must-enforce-itself)) | `packages/foundation/src/repositories/HttpUserRepository.mts`, with core's `keys/secretEntropy.mts` |
| `redis-clients.url` (`REDIS_CLIENTS_URL`) | required whenever any Redis adapter is selected — it is the one shared socket | `templates/standalone/src/modules.mts` (`standaloneRedisClientsModule`) |
| `redis-rate-limiter.failMode` (`REDIS_RATE_LIMITER_FAIL_MODE`) | `"open"` or `"closed"`; the Redis package's `reference.conf` ships `"closed"`. The outage policy of the limiter `redisRateLimiterModule` builds, which every guarded route applies while Redis cannot answer. It governs no other limiter: the in-process one has no backend to lose, and a limiter of the deployment's own answers its own policy. Its old path, `rateLimit.failMode`, and old variable, `RATE_LIMIT_FAIL_MODE`, refuse boot where the module is installed; elsewhere boot warns `rate_limit_fail_mode_not_applied` when the old path says `"open"` and the wired limiter does not. Written at this path without the module installed, it is reported by nothing: core's schema mirrors the Redis stores' sections, so `config_sections_ignored` counts `redis-rate-limiter` as owned and does not name it, and the warning reads the old path only | the module's section (`packages/redis/src/ratelimit.mts`), which refuses any other value |
| `adapters.auditSink` (`ADAPTERS_AUDIT_SINK`) | a registered sink name, with no `none`: an unknown sink fails boot naming the sinks that exist. A composition that runs without a sink declares it in `core.declaredAbsent = ["auditSink"]`; the standalone always wires one | `packages/core/src/audit/types.mts` (`AUDIT_SINK_ABSENCE_POLICY`); `templates/standalone/src/modules.mts` (`auditSinkModuleFor`) |
| `device-grant.verificationUri` | required once `device-grant.enabled = true`; the device displays it verbatim | `packages/device-grant/src/module.mts` |
| `mtls.fullPki.revocation.mode` / `.onUnavailable` / `.allowedHosts` | all three required under `mode = "full-pki"` with `revocation.mode` ∈ `"crl"`, `"ocsp"`, `"both"` (`allowedHosts` covers CRL distribution points and OCSP responders alike); there is no default for what an outage means | `packages/mtls/src/module.mts`, `packages/mtls/config/reference.conf` |
| `http.readinessTimeoutMs`, `session.csrf.ttlSeconds`, token lifetimes, `session-store.maxAge`, `session.rateLimit.login` | positive integers. An **exported-but-empty** variable is `""`, which coerces to `0` and is refused — the failure it prevents is a zero lifetime or a probe that always times out | `application.schema.mts`; the session package's section schemas for `session.*` and `session-store.*` |
| `oauth.accessToken.defaultExpiresIn` / `maxExpiresIn` (`OAUTH_ACCESS_TOKEN_DEFAULT_EXPIRES_IN` / `OAUTH_ACCESS_TOKEN_MAX_EXPIRES_IN`) | the default must not exceed the max; the message names both keys. An unset max is the default, and an unset default is the deprecated `oauth.accessToken.expiresIn` (shipped `3600`) — so a max below `3600` set on its own fails until the default is lowered too | `application.schema.mts` (`resolveAccessTokenLifetime`) |

### `core.outbound` — where the outbound fetch may connect

`createOutboundFetch` (core) is the fetch for URLs a client registration or a
request supplies. Its policy is `core.outbound`; the defaults need no setting.

| Setting (env) | Default | Rule |
| --- | --- | --- |
| `core.outbound.allowedHosts` / `deniedHosts` / `internalHosts` (`CORE_OUTBOUND_ALLOWED_HOSTS`, `CORE_OUTBOUND_DENIED_HOSTS`, `CORE_OUTBOUND_INTERNAL_HOSTS`) | `[]` | host names (letters, digits and hyphens once IDNA has run; no wildcard), IP addresses or `.suffix` entries, as a list or comma-separated. `deniedHosts` wins; a non-empty `allowedHosts` admits only what it lists. A non-empty `allowedHosts` also narrows `internalHosts`: an internal host must be listed in both. `internalHosts` admits a host at loopback, private or link-local addresses, for a registration's URL only, and plain `http` only to a loopback one. An entry that is not a bare host fails boot as `config-validation-failed`, naming its index |
| `core.outbound.timeoutMs` / `maxResponseBytes` (`CORE_OUTBOUND_TIMEOUT_MS`, `CORE_OUTBOUND_MAX_RESPONSE_BYTES`) | `5000` / `65536` | positive integers. The deadline covers the whole exchange. Both are ceilings: a caller may ask for a shorter deadline or a lower cap, never more |
| `core.outbound.egress` (`CORE_OUTBOUND_EGRESS`) | unset | `"direct"` only. A proxy or dispatcher installed in code is not consulted: outbound client-metadata fetches connect directly. While `HTTPS_PROXY` / `HTTP_PROXY` is set, building the fetch refuses until this is set |

Every address a host resolves to is checked, and the connection goes to the
checked address. Egress filtering at the network is still expected. IPv6-only
networks that reach IPv4 through NAT64 (`64:ff9b::/96`) are not supported:
those addresses are special-use, so an IPv4-only host is refused there.

### Boot refusals you will meet

Every boot-time failure is a `BootError` with a `reason` and a `stage`
(`packages/core/src/boot/types.mts`). The ones an operator meets, and the key
each names:

| `reason` | Trigger | What to change |
| --- | --- | --- |
| `module-factory-not-called` | a `modules` entry is a module factory listed without being called — `deviceGrantModule` for `deviceGrantModule({ config })`, `sessionStoreModuleFor` for `sessionStoreModuleFor(config)`. The compiler accepts it (a function has a `name`), and it used to boot as a module that did nothing (`packages/core/src/boot/validate-manifests.mts`) | the message names the entry and its index; call it with its arguments |
| `config-validation-failed` | a Zod issue from the table above, or a retired key still present (see [§7](#7-upgrading-and-rollback)) | the issue path names the key |
| `config-path-relocated` | the configuration still sets a key at a path its section moved from (#728; a loaded module's `section.relocatedFrom`) | the message names each key, the path it moved to and the environment variable that binds that, when one does (none binds `core.sessionRequirements.expected`, a key of `mtls` or `device-grant`, or a key of `dpop` outside `dpop.nonce`) — or says the key was removed. The sections moved under their modules' names: `oauth.dpop` → `dpop`, `oauth.mtls` → `mtls`, `oauth.deviceAuthorization` → `device-grant`, `oauth.tokenExchange` → `oauth-token-exchange`, each key camelCase (`cert-header` → `certHeader`); write it there (or drop it) and delete the old line, or unset the variable that sets it |
| `environment-variable-renamed` | the environment the configuration was resolved with sets a variable whose name changed when its key moved (a loaded module's or core's `renamedVariables`) while the new name is unset (`state: "unset"`), or set to a different value (`"different"`); or sets the variable of a key that was removed (`"removed"`); or the configuration does not capture the names at all (`"uncaptured"`: the `reference.conf` of the module's package, which captures them in `renamed-variables`, was not layered). A default at the new path does not count as the new name set: `OLD=true` alone is refused even where the new path defaults to `true` | the message names the old variable, the new one and the path the new one sets, never a value. The old name alone: set the new name instead and unset the old one. Different values: keep the value you mean in the new name and unset the old one. A removed key's variable: unset it. Uncaptured: layer the package's `reference.conf` beneath your own files (core's own for module `core`). Never write `renamed-variables` in your own files: a value written there overrides what the environment says, and the refusal it would have raised is lost. Both names set to the same value boot, so a deployment can export both while it moves; the new name alone boots as usual |
| `missing-required-component` | a module's `requires` has no provider. The standalone adds `redis-clients` whenever an adapter switch selects Redis, so there this only arises through `BuildModulesOverrides` (`templates/standalone/src/buildModules.mts`) | the message names the missing slot and the requiring module |
| `component-absence-undeclared` | an optional slot with an `AbsencePolicy` is unfilled and config does not declare it absent (`packages/core/src/modules/manifest/absence-policy.mts`, enforced by `checkDeclaredAbsence` in `boot/validate-manifests.mts`) | wire the component, or write the declaration: `core.declaredAbsent = ["auditSink"]` (auditSink), `oauth.revocation.accessToken = "unsupported"` (accessTokenDenylist), `oauth.revocation.subject = "unsupported"` (subjectRevocation + subjectSessionIndex), `device-grant.store = "unsupported"` (deviceCodeStore; only with the grant left off — an enabled grant needs a store) — sources: `core/src/audit/types.mts`, `core/src/access-token-denylist/types.mts`, `core/src/user-sessions/types.mts`, `packages/device-grant/config/reference.conf` |
| `replica-unsafe-adapter` | `core.deployment.mode = "multi"` with a listed module wired | the message lists every offender; switch the adapter or set `single` |
| `federation-stores-incomplete` | `core.federations.<name>.enabled = true` without all of `userSessionStore`, `sessionRPRegistry`, `sessionFamilyIndex`, `sessionFederationIndex`, `federationTokenStore`, `refreshTokenFamilyRevocation` | the message lists the missing slots |
| `grant-policy-without-issuer` | a `grantPolicy` is wired and `oauth.jwt.issuer` is empty | set the issuer |
| `session-requirement-missing` | `core.sessionRequirements.expected` names a session requirement no installed module registers — `mfa` without the MFA package, say — whether or not a module consults session admission (`packages/core/src/boot/apply-contributions.mts`). The standalone template adds `mfa` to the list when `mfa.mode` (`MFA_MODE`) is not `off`, and installs no MFA module, so there `MFA_MODE=optional` or `required` lands here with `missing: ["mfa"]`. | the message names each missing name and what registered: install the module that registers it, or remove the name — for `mfa` under the template, set `MFA_MODE=off` |
| `session-requirements-undeclared` | `core.sessionRequirements.expected` is written and leaves out a registered requirement, whether or not a module consults session admission; or it is unset while such a module is installed (`oauth` and `session` are). The standalone template's `config/application.conf` writes `[]`; a deployment that replaces that file rather than layering over it writes the key itself | the message names what is declared, what registered and the modules that consult admission: write the key naming exactly the registered requirements (`[]` for none) |
| `duplicate-second-factor-authority` | more than one installed session requirement declares the second-factor authority — the one requirement that may vouch for a second factor, the MFA package's `mfa` requirement among them — whatever their names (`packages/core/src/boot/apply-contributions.mts`) | the message and `details.requirements` name each requirement with the module that contributed it: install only one of those modules |
| `provides-factory-failed` / `contribute-factory-failed` | a module's own check threw; the module's message is the `cause` (`boot/materialize-components.mts`) | see the module messages below |

Module-level messages that arrive wrapped in a factory failure:

- Client registrations (the `yaml` / `static` client repository, which holds
  `allowedRedirectUris`, `postLogoutRedirectUris` and
  `federationGrantRedirectUris` to core's `checkRedirectUri`,
  `packages/core/src/net/redirect-uri.mts`): `Invalid entry "<client>" in
  <file>: …`, naming each bad entry by its list and position, never by the
  URI (a query can carry a token registered by mistake): the second entry of
  `allowedRedirectUris` is `allowedRedirectUris[1]`. Two of them are about
  the query: `allowedRedirectUris[0]: must not carry "iss" in its query
  (compared ignoring case, "_" and "-"): …` — the
  query names `code`, `state`, `iss`, `error` or `error_description`, the
  names an authorization response carries, in any case and with `_` or `-`
  anywhere in it (`_state`, `errorDescription`); and
  `allowedRedirectUris[0]: query parameter names may use only letters,
  digits, "_" and "-", each parameter
  must have a name, and the query must not contain ";": …` — a name outside
  `[A-Za-z0-9_-]`, a parameter with no name (`?=x`, `?a=1&&b=2`, a trailing
  `&`), or a `;` anywhere in the query, values included.
  `postLogoutRedirectUris` reads the same with its own field name;
  `federationGrantRedirectUris` reports the reason alone
  (`federationGrantRedirectUris[0]: reserved-parameter` or
  `… query-name-invalid`), and also refuses `grant_id`, compared the same
  way (`GRANT_ID`, `grantId`, `_grant_id`):
  `federationGrantRedirectUris[0]: already carries "grant_id" (compared
  ignoring case, "_" and "-"), …`. Rename or remove the parameter in
  the registration, and carry the client's own context in `state` or in the
  path. The comparison covers names as written and the common
  normalizations (case, `_`, `-`), not a mapping a client configures, such
  as an alias or a prefix its binder strips: a client must read the OAuth
  fields by their canonical names.
- Keys: `privateKey or privateKeyPath is required for EdDSA algorithm — no signing key is configured` (with the `openssl` commands); `Duplicate kid values: …`; `previousKeys is not valid for HS256 — use previousSecrets` and the mirror for asymmetric algorithms (`packages/core/src/keys/factory.mts`).
- Standalone Redis: `` `redis-clients.url` is required when any Redis-backed adapter is selected `` (`templates/standalone/src/modules.mts`).
- Standalone federation grant intents on Redis: `redis-federation-grant-store.keyPrefix
  (REDIS_FEDERATION_GRANT_STORE_KEY_PREFIX) is set off its default key prefix,
  and redis-federation-grant-intent-store.keyPrefix
  (REDIS_FEDERATION_GRANT_INTENT_STORE_KEY_PREFIX) is left at its default. …`,
  a `RangeError` before boot whenever the Redis intent store is installed,
  the grants on Redis or in memory (`templates/standalone/src/configPath.mts`).
  The intent store's prefix is its own key: set it too — to the grant store's
  prefix to keep acquisition's records beside the grants, or to one of its
  own. The check compares values, so an intent store prefix written as the
  default reads as left there. With the grants in memory,
  `redisFederationGrantStore.keyPrefix is set, and no installed module reads
  it: …` refuses that old key written at all, naming the intent store's key
  and variable: move the value there and delete the old line.
- Federation grants (#593): the same guard, the same environment variable, and
  the message names `[federation-grants]` rather than `[federation-tokens]`
  (`packages/redis/src/internal/encryption-mode.mts`). One more refusal of its
  own: `mode "required" needs at least one encryption key`, at construction
  rather than at the first write — a ring that cannot seal would otherwise be
  discovered after a user had already consented. The store's own refusals of
  `redis-federation-grant-store.encryptionKeys` arrive as a `RangeError` `cause`:
  `federation grant store: mode "required" needs at least one encryption key`,
  `federation grant store: redis-federation-grant-store.encryptionKeys[<i>].key must be
  canonical base64 of 32 bytes`, and, from core's ring rule,
  `federation grant store: redis-federation-grant-store.encryptionKeys has a duplicate
  encryption key id at index <i>` and `… has an encryption key id at index <i>
  that does not match ^[A-Za-z0-9_-]{1,64}$` — an entry is named by its
  index, never by its id, which could be a key written in the wrong place
  (`packages/redis/src/federation-grant-store.mts`,
  `packages/core/src/sealing/keyRing.mts`); so does
  `federation grant store: keyPrefix may not contain "{" or "}"`. A value the
  configuration schema refuses first — an empty `id` or `key`, a mode that is
  neither `required` nor `allow-plaintext` — is `config-validation-failed`
  instead. A read never re-seals, so
  dropping the key that sealed a grant makes it read `key_unavailable` until
  it is put back; the rotation procedure below says when a key may leave.
- Federation tokens: `mode "allow-plaintext" is refused because the environment is "production"` — the environment is the one the config was selected by (`CONFIG_ENV`, or `NODE_ENV`) *or* `NODE_ENV` itself — and `… because core.deployment.mode is "multi"` in every environment (#473); either way unless `FEDERATION_TOKENS_ALLOW_INSECURE=1`, which then logs `federation_store_plaintext_override` (error) on every boot (`packages/redis/src/internal/encryption-mode.mts`). That refusal, and `federationTokenStore.redis: encryption.key must be canonical base64 of 32 bytes (AES-256), or a Buffer of 32 bytes, when encryption.mode is 'required' (the default)` for a `redis-federation-token-store.encryptionKey` that is missing, the wrong length or not canonical base64, are the store's own and arrive as a `RangeError` `cause`, as does the same guard's refusal for federation grants; a mode outside the schema's two is `config-validation-failed`.
- MFA stores on Redis (the MFA ADR's D12): `redisMfaFactorStoreModule` and
  `redisMfaTransactionStoreModule` read the server's `maxmemory-policy` and
  persistence before they provide their stores — the enrolled factors, and the
  email proof an operator reset requires, must survive. An `allkeys-*` policy
  is refused with a `RedisMfaStoreEvictableError` `cause` whose `reason` is
  `mfa-factor-store-evictable` or `mfa-transaction-store-evictable` and whose
  message names the policy. **The MFA stores' Redis must run
  `maxmemory-policy` `noeviction`**, on a server of its own if the rest of
  your Redis may not. The policy is read from `INFO memory` (`CONFIG GET
  maxmemory-policy` only where INFO does not say), so a managed server that
  blocks `CONFIG` is still refused. A `volatile-*` policy boots, with a
  warning, but is not a supported setting: the factor store's keys carry no
  TTL, and the transaction store warns (§4) that it may evict a D21 hold, a
  first-binding mark, or a subject's lease — an evicted lease lets a second
  writer at the subject's factors. The subject's `recovery:` hash (its
  generation and recovery-set floor) carries no TTL once it holds either, so a
  `volatile-*` policy never picks it, and `allkeys-*` is refused at boot: the
  current checks already protect it. A
  question the server refuses (`NOPERM`, an unknown or renamed command) is a
  warning instead (§4); any other reply error (`BUSY`, `LOADING`, `NOAUTH`, …),
  and a server that cannot be reached, fails the boot with it as the `cause`. A `redis-mfa-factor-store.keyPrefix` or
  `redis-mfa-transaction-store.keyPrefix` that contains a brace is a `RangeError`
  `cause` (`packages/redis/src/internal/mfa-durability.mts`,
  `internal/mfa-keys.mts`).
- The Store as the MFA factor store (`foundationMfaFactorStoreModule`,
  `packages/foundation/src/mfa/module.mts`): `foundation-mfa-factor-store.listUrl
  (FOUNDATION_MFA_FACTOR_STORE_LIST_URL), … must be set: the Store keeps the MFA
  factors only with all four endpoints`, naming each URL left unset, whether or
  not anything requires the store; a URL that is not `https` or loopback `http`,
  or a key the section does not know, is `config-validation-failed` naming the
  key. The Store's credential, deadline and cap are the Store transport
  settings the composition root must hand the module — the user repository's
  HTTP settings: `foundation-mfa-factor-store: storeTransport, the Store
  transport settings, must be a section of keys ({} for none)` when they are
  left out or are anything else, and a `bearerToken`, `timeout` or
  `maxResponseBytes` the user repository would refuse is refused the same
  way, the message leading with `HttpMfaFactorStore`.
- The MFA module (`mfaModule`, `packages/mfa/src/module.mts` — private
  until the template wires it): `mfa.mode is "off" (or unset) while the MFA
  module is installed: remove the MFA module, or set mfa.mode to "required"
  or "optional"` — installed is on, so an MFA-off deployment does not install
  it; the package's settings, each a `RangeError` `cause` naming its key — the
  key ring and the development sample key as `packages/mfa/README.md` lists
  them, `mfa.transactionTtlSeconds` outside 60 to 1800 seconds,
  `mfa.maxAttemptsPerTransaction` outside 2 to 10, an
  `mfa.lockout` core's `checkConfiguredMfaLockoutPolicy` refuses
  (`mfa.lockout.hardLimit must be at least 10: …`, `mfa.lockout.hardLimit
  must be above mfa.lockout.threshold: …`, …), and an
  `mfa.enrollment.requireEmailProof` other than `when-mail`, `always` or
  `never`; `mfa.enrollment.requireEmailProof is "always" and no mail sender is
  wired` — nobody could give the account-email proof, so nobody could bind a
  factor: wire a mail sender, or set `MFA_ENROLLMENT_REQUIRE_EMAIL_PROOF` to
  `when-mail` or `never` (the MFA ADR's D20); `mfa.page.url is not set`
  (`MFA_PAGE_URL`, `/mfa` in the MFA package's reference.conf), the page a
  step-up starts on; and, from its routes' factory once every factor has registered,
  three `cause`s with a `reason`: `mfa-factor-kind-unhintable`
  (`the MFA factor of kind "<kind>" cannot be offered`) — an enabled factor
  whose kind is not a hint core admits (`^[a-z][a-z0-9_-]{0,63}$`), which a
  first binding's answer would list: contribute it under such a kind;
  `mfa-too-many-factors` — more than 16 enabled counting factors, the most a
  hint list carries: enable fewer; and
  an `MfaNoCountingFactorError` `cause` whose `reason` is
  `mfa-no-counting-factor` — `mfa.mode = "required"` with no counting factor
  enabled, which nobody could meet: turn on an installed counting factor
  through its module's `enabled` key (for the TOTP factor, when
  `mfaTotpFactorModule` is installed, `mfa-totp-factor.enabled` /
  `MFA_TOTP_FACTOR_ENABLED`), or set `optional`. The message names the enabled
  factor kinds. Without a `userSessionStore`, a `csrfGuard` or a
  `loginCompletion` — load the session package's `loginCompletionModule`
  beside `sessionModule` — the module is refused at the requires-closure
  (`missing-required-component`), naming the slot. The MFA requirement — the second-factor authority —
  whose reach is not what the enabled factors reach is core's refusal
  (`contribute-factory-failed`, naming the module).
- The WebAuthn second factor (`webauthnMfaFactorModule`,
  `packages/webauthn/src/mfaFactor/module.mts`): with
  `webauthn-mfa-factor.enabled` on and no relying party — the
  `webauthnConfig` slot the WebAuthn bootstrap module provides from
  `webauthn.rpId`, `rpName` and `origin` — `contribute-factory-failed`,
  naming the slot and those keys; off, the module boots without it. A
  `webauthn-mfa-factor` section its schema refuses — an `enabled` that is not
  a boolean, a `userVerification` other than `required`, `preferred` or
  `discouraged`, a key it does not know — is `config-validation-failed`
  naming the key, and the section missing altogether names the package's
  `reference.conf` to layer. Turn the factor on with
  `WEBAUTHN_MFA_FACTOR_ENABLED=true`; installed and off, it contributes no
  factor. Installed, on or off, while `webauthn.allowCredentialsForKnownUser`
  (`WEBAUTHN_ALLOW_CREDENTIALS_FOR_KNOWN_USER`) is on:
  `contribute-factory-failed`, naming both — with the flag on, a second
  factor's credential that returns no user handle, registered by another
  account through the grant, could sign its owner in as that account. Turn
  the flag off, or remove the module.
- The email factor (`mfaEmailFactorModule`,
  `packages/mfa/src/email/module.mts`): with `mfa-email-factor.enabled` on
  (`MFA_EMAIL_FACTOR_ENABLED=true`) and no module providing the `mailSender`
  slot, `contribute-factory-failed`, naming the switch, its variable and the
  slot — the factor could send no code. Wire a mail sender (your own, or
  `@o3co/auth-provider-standard`'s SMTP sender), or switch the factor off;
  off, the module boots without a sender.
- Per-process rate-limit fallbacks under `core.deployment.mode = "multi"` (#474): `core.deployment.mode is "multi" but no shared rateLimiter is wired for POST /session/login`, the same for `POST /oauth/webauthn/authentication/options`, and `… for the MFA routes` — a `replica-unsafe-adapter` BootError as the `cause`. Wire `adapters.rateLimiter = "redis"` or set `single` (`packages/session/src/routes/Session.mts`, `packages/webauthn/src/module.mts`, `packages/mfa/src/module.mts`).
- DPoP with no seen-set: `dpopModule: dpop.enabled = true requires a replaySeenSet component`, in every `core.deployment.mode`. Install `memoryReplaySeenSetModule` (one replica) or `redisReplaySeenSetModule`, or leave DPoP disabled (`packages/dpop/src/module.mts`). Under `multi` the memory one is then refused by the replica-safety guard, as `core-replay-seen-set-memory`.
- Device grant: the six refusals for `verificationUri`, the `session` slice, a `rateLimiter` component, a usable `device-grant.rateLimit` budget (#448), and — with the grant enabled — a `deviceCodeStore` component, which `device-grant.store = "unsupported"` does not stand in for (#626), and a `userSessionStore` component (`enabled = true requires a userSessionStore component`: the verification route approves only from the live `UserSession` behind the cookie; install `memorySessionStoresModule` on one replica or `redisSessionStoresModule`); and a seventh, `built from a configuration with the grant on, but the configuration createApp parsed has device-grant.enabled off` (or the reverse) — hand `deviceGrantModule({ config })` the configuration read from the same files and environment as `bootstrapComponents.config` (`packages/device-grant/src/module.mts`). The factory listed uncalled is `module-factory-not-called`, in the table above. There is no refusal for an enabled grant without `oauthModule`: it boots, but nothing can redeem the device codes it hands out, so compose it with the token endpoint. Enabled without a `csrfGuard` it is refused as `requires a csrfGuard component`, and with one filled by hand whose `middleware` is unusable as `csrfGuard.middleware is not a request handler` (or `could not be read`): install `sessionModule`'s guard, or one that keeps core's `CsrfGuard` contract.
- mTLS: `source = "header"` with empty `trustedProxies`; `mode = "pki"`/`"full-pki"` with empty `trustedCas`; `mode = "pki"` with `source = "tls-layer"`; `full-pki` without `fullPki.revocation.mode` + `onUnavailable`; `revocation.mode` ∈ `"crl"` / `"ocsp"` / `"both"` with empty `allowedHosts` (`packages/mtls/README.md` "Boot-time fail-loud invariants", `packages/mtls/src/module.mts`).
- Remote signing: `the signer's output does not verify against publicKeyPem for kid "…"` — the boot self-check in `createRemoteSigningKeyStore` (`packages/core/src/keys/remoteSigning.mts`).
- A library's refusal at boot — OIDC discovery (`discovery of <issuer> failed …`), a private key (`privateKey could not be parsed`, `privateKey cannot sign <alg>`), an mTLS trust anchor (`trustedCas[<i>] is not a parseable X.509 certificate`, `… failed to read file at <path>`) — says what failed in fixed words; the library's own error (openid-client's, OpenSSL's, jose's, the file read's `ENOENT`) is the error's `cause`, which Node prints below it (`packages/federation-oidc/src/oidc.mts`, `client-auth.mts`, `packages/mtls/src/extractor.mts`).
- The standalone's MFA posture: with `MFA_MODE` (`mfa.mode`) not `off`, a requirement registered as `mfa` that does not declare the second-factor authority refuses the boot before the server listens — `MfaRequirementNotAuthorityError`, `reason` `mfa-requirement-not-second-factor-authority`, not a `BootError` — after disposing what boot built; a cleanup that fails is its `cause` (`templates/standalone/src/secondFactorAuthority.mts`). Install the MFA package's modules, whose requirement declares the authority, or set `MFA_MODE=off`.
- The standalone's listener: a port it cannot bind (`EADDRINUSE`, `EACCES`) fails boot with that error; the process no longer announces a server it never started. A bound listener logs `server_listening` (info, `port`) once, and each later server error — an `accept` failing with `EMFILE`, say — as `server_error` (error, the error's projection), where it was lost and a second one crashed the process (`templates/standalone/src/listen.mts`).

Warnings that mean "fix before the next deploy" rather than "boot failed" are
listed in [§4](#4-alerts).

---

## 2. Probes

Two routes answer two different questions. Both are mounted on the host app
ahead of the composed auth router, so they keep answering while the auth
pipeline is degraded (`templates/standalone/src/app.mts`).

| Route | Question | Answer | Source |
| --- | --- | --- | --- |
| `GET /_healthcheck` | Is the process up and its event loop turning? | always `200 {"status":"ok"}`; touches no dependency | `packages/core/src/routes/Healthcheck.mts` |
| `GET /readyz` | Can this replica serve right now? | `200 {"status":"ready","checks":[…]}` or `503 {"status":"unready","checks":[…]}`, always `Cache-Control: no-store` | `packages/core/src/routes/Readiness.mts` |

**Wire liveness to `/_healthcheck` and readiness to `/readyz`, never the other
way round.** Pointing liveness at `/readyz` turns a Redis partition into a
cluster-wide restart loop, which reconnects nothing and adds cold starts to an
incident. The image's `HEALTHCHECK` probes `/_healthcheck` every 30 s (timeout
3 s, start period 10 s, 3 retries) for the same reason: Docker has one health
signal and Swarm/ECS *replace* an unhealthy container
(`templates/standalone/Dockerfile`).

```yaml
livenessProbe:
  httpGet: { path: /_healthcheck, port: 3000 }
readinessProbe:
  httpGet: { path: /readyz, port: 3000 }
```

### How readiness is assembled

Probes are registered by whichever builder *owns* a connection, through the
`readinessRegistrar` the boot planner pre-seeds
(`packages/core/src/readiness/types.mts`, `boot/create-app.mts`). They surface
on `handle.readinessProbes`, and the composition root feeds them to
`createReadinessRouter`. In the shipped standalone exactly two exist:

| `checks[].name` | What it pings | Registered in |
| --- | --- | --- |
| `redis` | the one shared ioredis socket (`io.ping()`) | `templates/standalone/src/modules.mts` |
| `session-store` | the node-redis client behind connect-redis (`client.ping()`) | `packages/session/src/store/factory.mts` |

A memory-only deployment registers none and is therefore always ready — there
is no dependency to be unready for (`packages/core/src/readiness/run.mts`).

What a `503` means: at least one probe rejected or did not settle within
`http.readinessTimeoutMs` (env `HTTP_READINESS_TIMEOUT_MS`, default `1000`;
`reference.conf`). Every probe runs; one failing does not hide the others.
The body carries only `name`, `ok` and `durationMs` per check. The failure
goes to the log as `readiness_probe_failed` (warn) with each failing check's
`name`, `durationMs` and `err` — the error's `loggableError` projection, the
driver's message in its `detail` — because a driver message like `connect ECONNREFUSED 10.0.3.14:6379`
names an internal host on an unauthenticated endpoint. `includeErrorDetail:
true` on `createReadinessRouter` puts it in the body; do that only when the
route is reachable solely from inside the deployment.

Two operational properties of the route (`packages/core/src/readiness/run.mts`):

- Concurrent and repeated scrapes **join** one in-flight check per probe rather
  than queueing a command each; during a partition the driver never answers,
  and without this every scrape would add a pending `PING` released as a burst
  on recovery.
- Keep `readinessTimeoutMs` **below** the orchestrator's own probe timeout, or
  an unreachable dependency reads as a slow replica instead of an unready one.

Keep `/readyz` and `/metrics` off the public listener: both sit ahead of the
auth router and therefore outside its rate limiter, and each request issues
one command per probe against the dependency being reported on
(`templates/standalone/README.md` "Health endpoints"). `GET /metrics` exposes
`auth_dependency_up{dependency="redis"|"session-store"}` from the same probes,
re-sampled per scrape (`templates/standalone/src/metrics.mts`).

---

## 3. What fail-closed looks like on each path

The product's stance is fail-closed: an unreachable store never reads as "not
revoked", "not rate limited" or "no session". What differs per path is the
status the client sees and whether the failure is bounded. `503
temporarily_unavailable` is the retryable answer; `400 invalid_grant` tells an
OAuth client to discard its refresh token (RFC 6749 §5.2), which is why the
refresh grant takes care to answer `503` for outages.

| Failure | Surface | Client sees | Log / audit | Bounded by |
| --- | --- | --- | --- | --- |
| Shared Redis down — **rate limiter**, `redis-rate-limiter.failMode = "closed"` (default) | `/oauth/token`, `/oauth/authorize`, `/oauth/introspect`, `/session/login`, `/oauth/device_authorization`, `/oauth/device/verification`, WebAuthn authentication options, the federation-grant client routes (`tag: "federation_grants"`) and the connect flow's pages (`federation_grants_browser`) | `503 service_unavailable` "Rate limiter temporarily unavailable" (the connect flow's pages: plain text at connect and the callback, `temporarily_unavailable` / `rate_limiter` at consent) | `rate_limiter_failed_closed` (error, with `tag`, `ip`, `error`); audit `rate_limit.unavailable` (`packages/core/src/ratelimit/guard.mts`) | one `commandTimeout` (1 s) per request in the standalone; see [§5](#failure-timing-on-the-shared-socket) |
| — same, `failMode = "open"` | same | request proceeds unlimited | `rate_limiter_failed_open` (error); audit `rate_limit.unavailable` | same |
| — **device verification** | `POST /oauth/device/verification` | the same policy, applied by the handler itself because its budget is keyed per subject rather than per IP (#457): `503 service_unavailable` under `closed`; under `open` the lookup / approval / denial proceeds. A limiter that *answers* "no" is not an outage — `429 slow_down` and `device.rate_limited` are unchanged under either mode | `rate_limiter_failed_closed` / `rate_limiter_failed_open` with `tag: "device_verification"`; audit `rate_limit.unavailable` (`packages/device-grant/src/verificationEndpoint.mts`, through core's `checkWithFailMode`) | `commandTimeout` |
| Shared Redis down — **refresh grant** | `grant_type=refresh_token` | `503 temporarily_unavailable` for a family-store, session-store, watermark or keystore outage (`packages/oauth/src/grants/refreshToken.mts`); the client keeps its token and retries | `token_verification_unavailable` (error, `site: "refresh_token"`, `reason`) for the watermark and keystore cases; `refresh_token_store_unavailable` (error, `store`, `step`: `rotate` / `revoke`) for the family store; `session_admission_unavailable` (error, `store: "user_session"`, `action: "oauth.refresh"`) for the session store the token's `sid` names | `commandTimeout`; CAS retries capped at `redis-refresh-token-family-store.casRetryLimit` (default 3) then `conflict-exhausted` (`packages/redis/src/refresh-token-family.mts`) |
| Refresh-token **replay** (not an outage) | same | `400 invalid_grant` `replay_detected`; the whole family is revoked inside the same compare-and-swap (`packages/core/src/refresh-token-family/rotation.mts`) | — | — |
| Shared Redis down — **authorization code** | `GET/POST /oauth/authorize` | redirect with `error=temporarily_unavailable` "authorization code store unavailable" — RFC 6749 §4.1.2.1's code for a temporary condition, not `server_error` (`packages/oauth/src/routes/authorizeIssuance.mts`) | `authorize_store_unavailable` (error, `store: "authorization_code"`, `step: "create"`, `clientId`, the error's projection) | `commandTimeout` |
| Shared Redis down — **session liveness at `/authorize`** (an authenticated browser session's `sid` cannot be checked) | `GET/POST /oauth/authorize` | fails closed, never a code: a redirect to the validated `redirect_uri` with `error=temporarily_unavailable` "session store unavailable", interactive or `prompt=none` alike — an interactive request used to be sent to the login page, whose forwarding of signed-in users looped on the flag the cookie kept, and `prompt=none` used to get `login_required`, which told the relying party nobody was signed in (`packages/oauth/src/routes/authorizeSession.mts`, through core's session admission) | `session_admission_unavailable` (error, `store: "user_session"`, `action: "oauth.authorize"`, the error's projection; never the `sid`) — it was `authorize_session_liveness_unavailable` | `commandTimeout` |
| | `grant_type=authorization_code` | `503 temporarily_unavailable` — "authorization code store unavailable" when the code cannot be consumed (it used to reach the terminal handler as a `500`), "session store unavailable" when the code's session cannot be read (`packages/oauth/src/grants/authorization.mts`). No tokens are issued, so nothing needs revoking. A retry redeems the code only if the store never ran the consume: when it ran it and the reply was lost (a `commandTimeout` after the delete), the code is spent, the retry gets `400 invalid_grant`, and the user restarts the authorization — as single-use codes require | `authorization_grant_store_unavailable` (error, `store: "authorization_code"`, `step: "consume"`) for the code; `session_admission_unavailable` (error, `store: "user_session"`, `action: "oauth.code_exchange"`) for the code's session | `commandTimeout` |
| Shared Redis down — **user session stores at login** | `POST /session/login` | `503 temporarily_unavailable` "Session store unavailable" when `userSessionStore.create` fails (it was answered but never logged), or when the cookie session cannot be regenerated (it was `500 server_error`, unlogged) or saved (it was a `200` whose session the next request could not find: the save now comes before the answer); after a failed regeneration or save the `UserSession` and its subject-index entry are rolled back best-effort. If only the subject index write fails, the login **succeeds** and that session is invisible to a later credential-change cascade (the rollback is `packages/session/src/establish-session.mts`, the login tail both `packages/session/src/routes/Session.mts` and the federation callback run; the log lines are the route's). Before anything is written the login asks the registered session requirements (core's `admitPrimary`); a requirement whose store cannot answer is `503 temporarily_unavailable` "session requirement unavailable" with nothing written. A login a requirement interrupts (the MFA package's) regenerates the cookie session, opens the requirement's ceremony and saves before answering the requirement's `403`: a regeneration, an `open` or a save that fails is the same `503`, the cookie session dropped, no `UserSession` written — after a failed save the requirement's record is left to its own expiry | `login_store_unavailable` (error, `store: "user_session"` / `step: "create"` with `sid` and `sub`, `store: "cookie_session"` / `step: "regenerate"` or `"save"`, or the interrupting requirement's name / `step: "open"`; the error's projection); `session_admission_unavailable` (error, `phase: "establishment"`, `store` the requirement's name) when a requirement could not be asked; `login_cleanup_failed` (warn) for each rollback step that fails; `subject_session_index_write_failed` (error) | `commandTimeout` |
| Shared Redis down — **MFA stores at the MFA routes** | `GET /session/mfa/transaction`, `POST /session/mfa/challenge`, `POST /session/mfa/verify` | `503 temporarily_unavailable` "MFA temporarily unavailable" when the transaction store or the factor store cannot answer, when a factor's data does not open under the key ring (a key left the ring: put it back), or when a factor throws — never "no factor" or a wrong code. A store that fails at the transaction read or the factor list spends nothing. From the attempt's reservation on the attempt is counted: a transaction store that fails at `reserveAttempt`, `takeChallenge` (a challenge taken is gone; the page asks for a new one) or `consume` leaves the transaction live for another attempt, unless the store ran the consume and only its reply was lost — then the transaction is spent and the user starts again from the password. A factor store that fails at `update` comes after the consume: the transaction is spent, the code's step unspent, and no session written. For a guessable proof the subject's attempt is reserved after the transaction's: a store that fails there is the same `503`, nothing checked; one that fails to settle it leaves the answer standing and the attempt counted (`mfa_subject_lock_unsettled`, warn). A store that answers outside its port's contract — a reservation that is not a whole count within the limit, a consumed transaction that is not the one read, a factor or transaction `update` that is not the record as written — is the same `503`, never read as a verdict. Every use of a login's transaction reads the subject's sessions boundary (`subjectRevocation`, when wired) first: a boundary that cannot be read is the same `503`, spending nothing. A first binding reads, then notes, the subject's first-binding mark in the transaction store before its factor is written: a store that cannot read it, or cannot note it — Redis down, or a memory store at its cap — is the same `503`, nothing written; the transaction is kept, the attempt its proof reserved spent. At the login's completion, a user-session or cookie-session store that fails is `503` "Session store unavailable", everything rolled back; a requirement's store asked as the login resumes is `503` "session requirement unavailable" (`packages/mfa/src/routes.mts`, `coordinator.mts`) | `mfa_store_unavailable` (error, `route`, `store` — `mfa_transaction`, `mfa_factor`, `revocation_boundary`, `user_session`, `cookie_session` or a requirement's name — `step`, the error's projection); `mfa_factor_unreadable` (error, `kind`, `factorId`, `state`, `keyId` when a key is missing); `mfa_factor_challenge_unavailable` (error, `kind`, `factorId`); `session_admission_unavailable` for a requirement's store; `mfa_login_cleanup_failed` (warn) for each rollback step that fails | `commandTimeout` |
| Shared Redis down — **session stores at the federation start, callback and link** | `GET /session/oauth/federation/:name`; its callback (`GET`, or `POST` for a `form_post` federation), a `?link=1` link included | `503 temporarily_unavailable` "Session store unavailable" when a store the leg cannot do without fails: the start's save or `form_post` transaction write; the callback's transaction read or delete, the envelope's retirement, the `UserSession` or federation-index write, the regeneration, the token attach or the regenerated session's save; the link's index read or write, or token attach — the link start's and the link callback's session reads are admission's, described by what failed — "session store unavailable", "revocation store unavailable" or "session requirement unavailable" (core's `describeAdmissionOutage`; `session_admission_unavailable`, below). The cookie-session and transaction failures, the regeneration and the post-regeneration writes used to be `500` (`server_error` / `session_create_failed`). Nothing is exchanged with the IdP once the ephemeral state cannot be retired; what the callback wrote is rolled back best-effort (the login's rollback is `packages/session/src/establish-session.mts`, with the federation index and token writes as the callback's own steps); a re-link whose index read failed rolls back nothing (`packages/session/src/routes/FederationLinkCallback.mts`) | `federation_start_store_unavailable`, `federation_callback_store_unavailable`, `federation_link_store_unavailable` (error, `store` ∈ `cookie_session`, `federation_transaction`, `user_session`, `session_federation_index`, `federation_token`, `user_repository`, with `step`; the link's with the `sid`; `session_admission_unavailable` (error, `action` `session.link` for the link start's own read, `session.link_callback` for the callback's, no `sid`) for the link's session reads; the error's projection — they were warns with sentence messages); `federation_cleanup_failed` (warn) for each rollback or discard step that fails | `commandTimeout` |
| Shared Redis down — **denylist / watermark at verification** | every surface that accepts an access token: `/oauth/introspect`, `/oauth/userinfo`, `POST /oauth/federation/:name/token`, token exchange, the refresh grant | `503 temporarily_unavailable` ("revocation store unavailable"; "subject_token validation store unavailable" at token exchange), with no `WWW-Authenticate` challenge at a protected resource — never `401 invalid_token` or introspection's `active: false`, which would tell the client to replace a token nobody could judge (`packages/core/src/jwt/verify.mts` `isVerificationUnavailable`, `packages/oauth/src/verificationUnavailable.mts`) | `jwt_verify_rejected` (warn) with `reason: "revocation_unavailable"` for either store — a denylist failure and a watermark failure are the same outage, and neither is reported as `revoked` (#408 / #459); `token_verification_unavailable` (error, `site`, `reason`, the error's projection); `token_exchange_validation_unavailable` (error); audit `introspect.store_unavailable` | `commandTimeout` |
| Shared Redis down — **access-token denylist / refresh-token family store at revocation** | `POST /oauth/revoke` for a token that verified and belongs to the calling client | `503 temporarily_unavailable` "token revocation is temporarily unavailable; retry the request" (RFC 7009 §2.2.1): the client must assume the token still exists and retry. A token that does not verify, or belongs to another client, never reaches the store and is still `200` (`packages/oauth/src/routes/revoke.mts`) | `revoke_store_unavailable` (error, `store` ∈ `accessTokenDenylist`, `refreshTokenFamilyRevocation`; `clientId`) | `commandTimeout` |
| Shared Redis down — **refresh-token family store or session store at a protected resource** | `/oauth/introspect`, `/oauth/userinfo`, `POST /oauth/federation/:name/token`, `POST /oauth/federation/:name/logout`, token exchange | `503 temporarily_unavailable` ("refresh token store unavailable" / "session store unavailable"), no challenge — not `401 invalid_token` or `active: false` (`packages/oauth/src/routes.mts`, `routes/introspectUnavailable.mts`, `routes/userinfo.mts`, `routes/federationToken.mts`, `routes/logout.mts`, `packages/oauth-token-exchange/src/grant.mts`) | `introspect_store_unavailable`, `userinfo_store_unavailable`, `federation_token_store_unavailable`, `federation_logout_store_unavailable`, `token_exchange_family_store_unavailable`, `token_exchange_session_store_unavailable` (error, with `store`, a `step` where the store has more than one operation, and the error's projection — one line per 503, never a warn); audit `introspect.store_unavailable` | `commandTimeout` |
| Shared Redis down — **session stores and federation token store at the federation routes** | `POST /oauth/federation/:name/token`, `POST /oauth/federation/:name/logout` | `503 temporarily_unavailable` ("session store unavailable" / "federation token store unavailable") (`packages/oauth/src/routes/federationToken.mts`, `routes/federationTokenStored.mts`, `routes/federationTokenRefresh.mts`, `routes/federationTokenRefreshRecord.mts`, `routes/logout.mts`) | `federation_token_store_unavailable` / `federation_logout_store_unavailable` (error) with `federation`, `store` ∈ `user_session`, `session_federation_index`, `federation_token`, and `step` (`get`, `list`, `acquire_lock`, `get_after_lock`, `update`, `delete`, `remove`) | `commandTimeout` |
| Shared Redis down — **session stores at RP-initiated logout** | `GET`/`POST /oauth/logout` | `503 temporarily_unavailable` ("session store unavailable"; "logout cascade failed" when the cascade stops), and the browser session is kept so a retry can finish (`packages/oauth/src/routes/logout.mts`, `logout/sessionEnd.mts`, `logout/cascadeLogout.mts`). A failure after the session's ended mark leaves the session half-ended — kept, its families unrevoked, its code exchanges refused — until a retry completes the logout or the mark lapses | `logout_store_unavailable` (error): `store: "user_session"`, `"session_family_index"` (`step: "endSession"`, the session's ended mark, written before the relying parties are read), `"session_rp_registry"` or `"session_federation_index"` with `step` (when both reverse-index reads fail, `store` names the registry and `alsoUnavailable` carries the federation index's projection), and `left` — what the failure left: `unchanged`, `half_ended` (marked, then a listing failed) or `unknown` (the mark's call failed; it may have been written); or `store: "logout_cascade"` with `cascadeStep` (1, 2 or 4), the number of `failures` and the first failure's projection. Each failed cascade operation also has its own `logout_cascade_operation_failed` (warn); audit `logout.cascade_failed` | `commandTimeout` |
| Shared Redis down — **session stores and family store at the code exchange and the session grant** | `grant_type=authorization_code`, `grant_type=session` | `503 temporarily_unavailable` ("session store unavailable", "refresh token store unavailable", "session linking unavailable") (`packages/oauth/src/grants/authorization.mts`, `grants/session.mts`) | `authorization_grant_store_unavailable` (error) with `store` ∈ `authorization_code`, `refresh_token_family`, `session_family_index`, `session_rp_registry` and `step`; a client lookup there is `client_repository_unavailable` with `site: "authorization_code"`; the session reads — the code's two, and the session grant's — are `session_admission_unavailable` (error, `store: "user_session"`, `action: "oauth.code_exchange"` / `"oauth.session_grant"`), which replaced `session_grant_store_unavailable` and the `user_session` case of `authorization_grant_store_unavailable` | `commandTimeout` |
| **Upstream IdP unreachable** during a federation token refresh | `POST /oauth/federation/:name/token` | `503 temporarily_unavailable` "upstream federation provider temporarily unavailable", and the session's upstream tokens are kept — an IdP that answered 5xx, whatever OAuth code its body names (but `too_many_requests`, which stays the `429`), did not answer in time, or could not be reached (core's `isFederationUpstreamOutage`, which the refresh-error classifier reads before the codes that reject a refresh token). A 5xx whose body said `invalid_grant` used to delete the tokens and unlink the federation (`410`), and a 5xx openid-client raised over the `Response` was `500 refresh_failed`. An upstream that answered but refused is its verdict — `410` (a structured `invalid_grant` / `invalid_token` only, never under a 429 and never a message's text) / `429` (whatever code a 429 names, with the upstream's `Retry-After` when it named one; the tokens are kept) / `500` (`packages/oauth/src/routes/federationTokenRefreshFailure.mts`) | `federation_token_upstream_unavailable` (error, `reason: "network"`); the refusals are `federation_token_refresh_failed` (warn, with `reason`) | the provider's HTTP timeout |
| Shared Redis down — **federation grant store, intent store or revocation boundary** (`federationGrantStore`, `federationGrantIntentStore`, the `subjectRevocation` boundaries) | the federation-grant client routes — `POST /oauth/federation-grants`, `/:grantId/token`, `/status`, `/revoke`, `/reauthorize` — and the connect flow — `/session/federation-grants/connect`, `/consent`, `/callback/:connection` | `503 temporarily_unavailable` / `storage` (`key_unavailable` for a credential sealed under a key not in the ring); connect answers a plain-text `503`; the consent describes an outage of session admission's reads — the user-session store, the sessions boundary — as every consumer of admission does (core's `describeAdmissionOutage`: `session store unavailable`, `revocation store unavailable`); the callback sends the browser back to the client with `error=temporarily_unavailable`. A consent answer the intent store cannot record is `503`, not the `500` it was (`packages/federation-grants/src/tokenRoute.mts`, `statusRoute.mts`, `revokeRoute.mts`, `lodgeRoute.mts`, and the connect flow's `browserConnect.mts`, `browserJudgement.mts`, `browserPendingConsent.mts`, `browserConsentAnswer.mts`, `browserUpstreamRedirect.mts`, `browserCallback.mts`) | `federation_grant_token_unavailable`, `federation_grant_status_unavailable`, `federation_grant_revoke_unavailable`, `federation_grant_lodge_unavailable`, `federation_grant_connect_unavailable`, `federation_grant_consent_unavailable`, `federation_grant_callback_unavailable` (error, `reason`, `store`, `step`, the error's projection) — one line per `503` or redirect, where each used to be a `federation grant operation failed` warn or nothing; on the connect flow, the user-session store and the sessions boundary are session admission's reads, logged as `session_admission_unavailable` (error, `store: "user_session"` / `"revocation_boundary"`, `action: "federation_grants.connect"` / `.consent` / `.callback`, `grantId`, `correlationId`, the error's projection) instead. At connect and the consent, every such `503` is also audited as `federation.grant.authorization_failed` with outcome `unavailable`, and at the callback every `temporarily_unavailable` redirect or `503` with outcome `temporarily_unavailable`; one whose handle, question, intent or transaction could not be read names no grant | `commandTimeout` |
| **Upstream IdP unreachable** for a federation grant | `POST /oauth/federation-grants/:grantId/token` (a refresh); the connect callback (the code exchange) | `503 temporarily_unavailable` / `upstream`, with `Retry-After` while a failed refresh's stamp stands; the callback redirects with `error=temporarily_unavailable` — a refresh or an exchange that got no answer or a 5xx, read off the error's name (`AbortError`, `TimeoutError`, as under openid-client's `OAUTH_TIMEOUT`), a connection code (`ECONNREFUSED`, `ECONNRESET`, `UND_ERR_SOCKET`, …) or a 5xx `status` on it or its causes (the `Response` an IdP answering 503 is raised over, a deployment's own `fetch` included), or a transport code on it or its causes — undici's (`UND_ERR_…`), llhttp's (`HPE_…`), Node's X509 verification codes, `ERR_TLS_…` / `ERR_SSL_…`, `ERR_INVALID_URL` — never its text or the IdP's parsed body (core's `isFederationUpstreamOutage`, which the refresh reads beside its own classifier's `network`, and before any OAuth code a 5xx's body names: a 503 saying `invalid_grant` or an interaction code does not end the credential or stand for the user). It used to answer a refresh against some of these — openid-client's 503 or `OAUTH_TIMEOUT`, undici's `ECONNRESET` or `UND_ERR_SOCKET` — `502 upstream_rejected` / `unknown` | `federation_grant_token_unavailable` / `federation_grant_callback_unavailable` (error, `reason: "upstream"`, `step`); a refresh the caller stopped waiting for at `upstreamTimeoutMs` is that line with no `err`, and the upstream call abandoned at `upstreamHardTimeoutMs` is a `federation_grant_token_step_failed` warn after it (`step: "upstream"`, "not answered in time"); an upstream that answered and refused is `federation_grant_token_step_failed` (warn, `step: "upstream"`) or `federation_grant_callback_exchange_refused` (warn) | `upstreamTimeoutMs` (answered at it), `upstreamHardTimeoutMs` (aborted at it) |
| **Keystore cannot answer a key lookup** — a `KeyStore` of your own whose `getVerificationKey` throws anything but `UnknownKidError` / `ExpiredKidError` (a remote key service timing out). The bundled stores hold their keys in memory, so a lookup of theirs ends only in one of those two findings. A `kid` header that is not a well-formed key id — not a string, empty, longer than `MAX_KID_LENGTH` (256), or carrying a control character (`isWellFormedKid`) — is refused as `kid_unknown` before any keystore is asked — it cannot be made to read as an outage; a configured kid of that shape is refused at boot, by `key-store` and by every bundled keystore — and a lookup error named `UnknownKidError` / `ExpiredKidError` is read as that finding even from another copy of core | every route that verifies a token this provider signed: introspection, userinfo, the federation token and logout routes, `/oauth/logout` (`id_token_hint`), `/oauth/revoke`, the refresh grant, token exchange | `503 temporarily_unavailable` ("verification key unavailable"; `/oauth/revoke`: "token revocation is temporarily unavailable; retry the request", RFC 7009 §2.2.1 — nothing was revoked; token exchange: "… validation store unavailable"). A kid the keystore does not hold is still the client's fault (`401` / `400` / `active: false` / revoke's `200`) | `jwt_verify_rejected` (warn) with `reason: "verification_key_unavailable"`; `token_verification_unavailable` (error) with `site`, and the keystore's error as the projected error's `cause`; `token_exchange_validation_unavailable` (error) | your keystore's own timeout |
| Shared Redis down — **replay seen-set** (`ADAPTERS_REPLAY_SEEN_SET=redis`) | a DPoP proof at `/oauth/token` or at a protected resource; a `private_key_jwt` client assertion (`/oauth/token`, `/oauth/introspect`, `/oauth/revoke`, `/oauth/device_authorization`, and the federation-grant client routes — `/oauth/federation-grants/:grantId/token`, `/status`, `/revoke`, and with acquisition on `POST /oauth/federation-grants` and `/:grantId/reauthorize`); an ID-JAG assertion (`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`) when the composition hands the jwt-bearer verifier this seen-set | `503 temporarily_unavailable`, with no `WWW-Authenticate` challenge at a protected resource: the proof or assertion is refused unrecorded, not judged invalid, so the client keeps its tokens and retries (`packages/dpop/src/verifier.mts`, `packages/core/src/middleware/tokenBinding.mts`, `protectedResourceBinding.mts`, `packages/oauth/src/middleware/clientAssertion.mts`, `packages/oauth/src/grants/jwtBearer.mts`) | `token_binding_unavailable` / `protected_resource_binding_unavailable` (error, `mechanism: "dpop"`, `reason: "replay_store_unavailable"`, the store error's projection) for DPoP — one line, from the dispatcher that answers the 503; `client_assertion_refused` (error, `reason: "replay_store_unavailable"`); `jwt_bearer_assertion_verifier_unavailable` (error) | `commandTimeout` |
| | the WebAuthn ceremony — `grant_type=urn:o3co:oauth:grant-type:webauthn` and `POST /oauth/webauthn/registration/verify` | `503 temporarily_unavailable` "challenge store unavailable" when the ceremony's `find` / `contains` / `consume` / `markSeen` fails — it used to reach the terminal handler as `500 server_error`. A `markSeen` failure comes after the challenge was consumed, so the retried assertion or response is `400 invalid_grant` / `400 challenge_invalid` and the user starts the ceremony again (`packages/webauthn/src/grant.mts`, `routes/registrationVerify.mts`) | `webauthn_grant_store_unavailable` / `webauthn_ceremony_store_unavailable` (error, `store: "challenge_ceremony"`, `step: "consume"`, the error's projection) | `commandTimeout` |
| Shared Redis down — **WebAuthn credential, challenge and refresh-token family stores** | `grant_type=urn:o3co:oauth:grant-type:webauthn`; `POST /oauth/webauthn/registration/options`, `/registration/verify`, `/authentication/options` | `503 temporarily_unavailable` ("credential store unavailable", "challenge store unavailable", "refresh token store unavailable") — the credential lookup, list, insert and sign-count update and the challenge write used to reach the terminal handler as `500 server_error`, and a family store that could not register the refresh token's family was a `503` nobody logged. No token is issued and no credential reported stored. What the client meets on retry: after the grant's credential lookup nothing is spent and the same assertion works within the challenge's lifetime; after the ceremony, the sign-count update or the family registration the challenge is spent, the retried assertion is `400 invalid_grant` and the user runs the ceremony again (a sign count written before a lost reply stays below the next assertion's). At `registration/verify` an insert whose reply was lost may have stored the credential: the next ceremony's `excludeCredentials` names it and the browser reports the authenticator as already registered — that passkey signs in (`packages/webauthn/src/grant.mts`, `src/routes/`) | `webauthn_grant_store_unavailable` (error, `store` ∈ `webauthn_credential`, `challenge_ceremony`, `refresh_token_family`, `step` ∈ `find`, `consume`, `update_sign_count`, `register`, `clientId` sanitised when a client authenticated, the error's projection); `webauthn_ceremony_store_unavailable` (error, `site` ∈ `registration_options`, `registration_verify`, `authentication_options`, `store` ∈ `webauthn_credential`, `challenge`, `challenge_ceremony`, `step` ∈ `list`, `issue`, `consume`, `register`). The family is registered under the refresh token's reserved `jti` and expiry before either token is signed (#449), so a family-store outage costs no signature | `commandTimeout` |
| **Cookie session store** (connect-redis, its own node-redis client) down | every request that carries the session cookie — the middleware is mounted at `/` | a session the store cannot load is answered `503 temporarily_unavailable` "Session store unavailable" before any route runs — it used to reach the terminal handler as `500 server_error`; a session it cannot save, or whose expiry it cannot refresh, after the route answered leaves that answer standing — the error used to reach Express's final handler, which printed its stack to stderr and dropped the connection (`packages/session/src/internal/cookieSession.mts`, mounted by `modules/sessionStoreModule.mts`). The session routes' own store calls — the login's regeneration and save, the logout's destroy, the federation start and callback saves, regeneration and `form_post` transaction — answer `503 temporarily_unavailable` "Session store unavailable" themselves (they were `500`, or for the login's save a `200` whose session was lost) and then drop the request's session, so express-session does not write to the failing store again as the response ends (`packages/session/src/routes/Session.mts`, `FederationStart.mts`, `FederationCallbackState.mts`, `Federation.mts`; the regeneration and the final save, `packages/session/src/establish-session.mts`) | `session_middleware_store_unavailable` (error, `store: "cookie_session"`, `step: "load"` or `"save"`, the error's projection) for the middleware's own; `session_store_redis_error` (error) on every client error event, including during reconnect (`packages/session/src/store/factory.mts`); `readiness_probe_failed` for `session-store`; the routes' own `login_store_unavailable`, `session_logout_store_unavailable`, `federation_start_store_unavailable`, `federation_callback_store_unavailable` (error, `store: "cookie_session"` or `"federation_transaction"`) | node-redis reconnects on its own; the provider no longer crashes on the `error` event |
| **KMS / remote signer** unavailable | any mint: `/oauth/token`, id tokens, logout tokens | nothing between `keyStore.sign` (`packages/core/src/grants/token.mts`) and the route catches a signer error, so it surfaces as `500 server_error` with `unhandled_request_error` — **except the `refresh_token` grant when a rotation was committed** (#449): there it is `503 temporarily_unavailable` plus a `refresh_token_rotation_orphaned` error log naming the family, and the client's retry presents a token that now reads as a replay, so that family is revoked and the user re-authenticates. Verification and `/.well-known/jwks.json` are **unaffected**: the public halves are imported at construction and served from memory (`packages/core/src/keys/remoteSigning.mts`) | `unhandled_request_error` | whatever timeout your `RemoteSigner` applies — the store applies none. Boot itself needs one signer call for the self-check unless `verifyOnConstruction: false` |
| **CRL distribution point or OCSP responder** unreachable or answering unusably, `full-pki`, `onUnavailable = "reject"` — unreachable, timed out, an HTTP error, a redirect, an answer too large, of the wrong type or not DER, `responder_error`, a `stale` list or answer, or a delegated responder whose own status could not be read for one of those reasons (`revocation.mode = "both"`: an outage only when every source the certificate names failed as one) | `/oauth/token` with a client certificate; a protected resource with an mTLS-bound token | `503 temporarily_unavailable` from the token-binding dispatchers, no challenge at a protected resource — the server's outage, not a verdict on the certificate; it was `400 invalid_certificate` (`packages/mtls/src/errors.mts` `revocation_unavailable`, `packages/mtls/src/fullPki/validate.mts`, `packages/core/src/middleware/tokenBinding.mts`, `protectedResourceBinding.mts`). A certificate that is revoked, or whose status is unavailable for its own reason — no or an unsupported distribution point, a URL outside `allowedHosts`, a CRL of a shape or algorithm not accepted, a bad signature, an OCSP `unknown` — is still `400 invalid_certificate`, and wins over another certificate's outage on the same path | `token_binding_unavailable` / `protected_resource_binding_unavailable` (error, `mechanism: "mtls"`, `code: "temporarily_unavailable"`, `reason: "revocation_unavailable"`, `err` = an `MtlsRevocationUnavailableError`: `err.detail` names every certificate on the path whose status could not be determined, and `err.aggregateErrors[]` has one `MtlsRevocationSourceError` per source that could not be used — every such certificate's, and the responder `both` fell back from for a certificate its CRL decided — in path order, leaf first, each certificate's OCSP responders before its CRL points; each `detail` is `<crl|ocsp> <url>: <reason> — <detail>; for <subject>` — `crl http://…/int.crl: fetch_failed — network_error (ECONNREFUSED); for CN=client`, `…: unparseable — not a DER CRL; for …` — with the library's error as its `cause`. The line keeps the first five members and counts the rest in `err.aggregateErrorsOmitted`: past five, the last certificate's last points are counted, not shown) — one line, from the dispatcher; `mtls_revocation_ocsp_fallback` (warn) when `both` fell back to the CRL, the CRL's answer was used (determined from every point, or partial under `allow`) and the whole path passed — a certificate the mechanism accepted on the fallback; the request can still be refused afterwards — a path refused for another certificate's outage names the responder among that line's members instead, and a certificate the CRL lists is a verdict with the verdict's lines; when the CRL does not answer either there is no fallback line, and the one line (the dispatcher's, or `mtls_revocation_unavailable_allowed` under `allow`) names both sources; `mtls_ocsp_responder_unchecked` (warn, once per responder) when a delegated responder lacks `nocheck` and nothing can check it. For a verdict: `mtls_revocation_unavailable_rejected` (warn, per certificate, `reason` ∈ `no_distribution_point`, `unsupported_distribution_point`, `fetch_failed` for a URL the guard will not fetch, `no_next_update`, `bad_signature`, `unsupported_critical_extension`, `unsupported_crl_scope`, `algorithm_not_permitted`, or OCSP's `no_responder`, `no_matching_response`, `unsupported_critical_extension`, `algorithm_not_permitted`, `bad_signature`, `nonce_mismatch`, `nonce_missing`, `not_yet_valid`, `unknown`, `responder_revoked` — `OcspUnavailableReason` in `packages/mtls/src/fullPki/ocspAnswer.mts`), `mtls_full_pki_validation_failed` (`step: "revocation status unavailable"`), `token_binding_proof_invalid`. Each revocation line's `detail` is the package's own words and, when a library threw (pkijs, WebCrypto, the fetch), the line carries its projection as `err` (`packages/mtls/README.md` "What a revocation line carries") | `fetchTimeoutMs` (default 3000) — lookups for a path run in parallel so latency is the largest, not the sum; one in-flight fetch per URL; a failed URL is not retried for 30 s (`CRL_NEGATIVE_CACHE_TTL_MS` / `OCSP_NEGATIVE_CACHE_TTL_MS`, not knobs; `bad_signature` exempt); an OCSP answer is cached per certificate until its `nextUpdate`, capped by `cacheTtlSeconds`, and an undated answer for at most 10 min (`OCSP_UNDATED_RESPONSE_MAX_AGE_MS`); `maxResponseBytes` (default 1048576); 256 cache entries (`packages/mtls/src/fullPki/crl.mts`, `fullPki/ocspCache.mts`, `fullPki/ocspStatus.mts`, `fullPki/validate.mts`, `packages/mtls/src/module.mts`) |
| — same, `onUnavailable = "allow"` | same | token issued | `mtls_revocation_unavailable_allowed` (warn) **per certificate waved through**, once the whole path has passed: a certificate the mechanism accepted (its whole path passed) on the soft-fail; the request can still be refused afterwards — by another mechanism's verdict or `strict-mutual-exclusion`, by the grant, or at a protected resource by `no_matching_binding`. A permanent soft-fail is an unrevocable PKI wearing a revocation configuration. A path refused for another certificate (an intermediate that is revoked) has the verdict's lines alone, and no allowed line | same |
| **Audit sink** failing | every audited route | nothing — `emitAuditEvent` dispatches without awaiting and swallows rejections (`packages/core/src/audit/factory.mts`) | nothing; drops are not counted (`templates/standalone/README.md` "Not published yet") | no latency is ever added |
| **Upstream IdP** down | the federation callback — `GET /session/oauth/federation/:name/callback`, or `POST` for a `form_post` federation such as Apple | `502 exchange_failed` "Token exchange with upstream IdP failed" (`packages/session/src/routes/FederationCallbackIdentity.mts`) | `federation_callback_exchange_failed` (warn, the provider bound on the line, the error's projection; it was the sentence `federation token exchange failed`) | the provider adapter's own fetch |
| | `POST /oauth/federation/:name/token` (upstream refresh) | `503 temporarily_unavailable` for a network failure, `429 rate_limited`, `410 re_authentication_required`, or `500 refresh_failed` (`packages/oauth/src/routes/federationTokenRefreshFailure.mts`) | audit `federation.token.reauthentication_required` / `federation.token.refresh_failed` | advisory lock in Redis (`ft:lock:`) |
| **Upstream IdP starts issuing sender-constrained tokens** | `POST /oauth/federation/:name/token` | `502 upstream_token_ineligible`, `error_description: token_type_unsupported`, `Retry-After: 300` — the token cannot be handed to a caller that holds no proof key, so it is refused rather than answered as `Bearer` (#645) | audit `federation.token.upstream_ineligible`, with `details.tokenType` naming what the record carried | not transient: it stands until the upstream client registration is changed back. After that, a record whose token has expired repairs itself on the next refresh, which re-records the type; one still inside its expiry stays refused until it expires, and a reconnect clears it at once |
| | `/oauth/federation/:name/logout` | `200 {"disconnected": true}` — local state is already cleared, the IdP session is orphaned (`packages/oauth/src/routes/logout.mts`) | audit `federation.logout.idp_unreachable` | — |
| **The Store** (user directory) down or slow, a configured Store URL answers with a redirect (no request follows one), or the Store refuses this deployment's `bearerToken` (`401` or `403` with `WWW-Authenticate: Bearer`) | `POST /session/login`; federation callback, a `?link=1` link included; jwt-bearer grant; the federation-grants connect callback (the identity lookup — its own row under [Acquisition refusals](#acquisition-refusals-an-operator-meets-593-slice-6-611)) | `503 temporarily_unavailable` "User directory temporarily unavailable" (`Session.mts`, `FederationCallbackIdentity.mts`, `FederationLinkCallback.mts`); `503 temporarily_unavailable` "identity resolution unavailable" from the jwt-bearer grant (`packages/oauth/src/grants/jwtBearer.mts`) | `login_store_unavailable`, `federation_callback_store_unavailable`, `federation_link_store_unavailable` (error, `store: "user_repository"`, `step` `authenticate` / `authenticate_by_token` / `link` — they were the warns `local login authenticate failed`, `user repository lookup failed`, `federation link: user repository failed`); `jwt_bearer_user_repository_unavailable` (error); `federation_grant_callback_unavailable` (error, `store: "user_directory"`) at the federation-grants callback. Each `<url>` below is the configured URL's origin and path — a query string or fragment is never quoted. A redirect is the case whose logged `err` reads `Unexpected HTTP status 30x from <url>`: set the URL to the endpoint that answers, not one that redirects. A refused token is the case whose logged `err` is a `StoreCredentialRefusedError` reading `the Store at <url> refused this deployment's credential (HTTP 401 with a Bearer challenge)` (or `403`) on the login, federation, jwt-bearer and federation-grants callback lines. Set `REPOSITORIES_USER_HTTP_BEARER_TOKEN` to a token the Store accepts. The token itself is never logged. A transport failure is a `StoreTransportError`: `request to <url> could not be reached` (refused, DNS, TLS — the network path or TLS), `the connection to <url> closed before a complete response arrived` (closed or reset first: an occasional one is a pooled keep-alive connection the Store, a proxy or an idle timeout closed between requests; a steady stream is the Store or a proxy closing mid-answer or restarting), `the Store at <url> answered with a malformed HTTP response` (the parser refused the status line or a header, or the head outgrew the size limit — a proxy or a wrong port), or `response from <url> could not be read` (the body broke mid-read), with at most a code such as `ECONNREFUSED` or `ERR_SSL_WRONG_VERSION_NUMBER` (an https URL on a plain-HTTP port) — never the transport's own error, which can quote what was sent. Two symptoms with no refused-credential line: **every login answers `401 invalid_credentials`** while the Store checks a token — `REPOSITORIES_USER_HTTP_BEARER_TOKEN` is unset (with no token sent, even a challenged `401` reads as "no such user"), or it is wrong and the Store refuses without a `Bearer` challenge; set the token, and have the Store send the challenge. **Refused-credential lines on some logins while correct passwords still succeed** — the token is fine; the Store is putting a `Bearer` challenge on user-level `401`s (a wrong password), which must carry none. Do not rotate the token for it | `repositories.user.http.timeout` (default 5000 ms) and `maxResponseBytes` (default 1048576) — a timeout is a thrown error, not a `null` user (`packages/foundation/src/repositories/HttpUserRepository.mts`) |
| **The Store as the MFA factor store** (`foundationMfaFactorStoreModule`) down or slow, answering a redirect or anything else outside its contract, or refusing this deployment's `bearerToken` | `POST /session/login` (the `mfa` requirement reads the subject's factors), and every MFA route that reads or writes a factor | `503 temporarily_unavailable`, never "no factors": a login under `mfa.mode = "optional"` is not let through without the second factor, and a subject with an unreadable record never opens a first binding. Nothing the Store sent — its status, text, headers or records — reaches the client | the caller's one error line — at login `session_admission_unavailable` (error, `store: "mfa"`) — whose `err` projection is what the adapter threw: `MfaStoreError` (`reason` `unexpected_status` with `storeStatus`, `malformed_answer`, `unreadable_record`, `version_skipped`; `operation`), `StoreTransportError`, a `TimeoutError`, `StoreCredentialRefusedError` (leading with `HttpMfaFactorStore`), an `Error` for an answer over the cap (`HttpMfaFactorStore: upstream <url> response exceeds the <n>-byte cap`), an `Error` for a `409` to a create (`an MFA factor record with this id already exists for the subject`), or a `RangeError` for a record or an update the wire codec would not read back, thrown before any request. `version_skipped` leads with the subject and the factor id (`packages/foundation/src/mfa/storeFailure.mts`) | the user repository's `timeout` (`repositories.user.http.timeout`) |
| **The mail sender** down, answering outside its port, or refusing at its limit | `POST /session/mfa/challenge` — a factor's login code (the email factor's six-digit code), the account-email proof (`factor_id: "account-email"`) — and `POST /session/mfa/enrollment` for a factor that mails its enrollment code (the email factor's) | `429 rate_limited` at the sender's limit; `503 temporarily_unavailable` "MFA temporarily unavailable" otherwise. Either way the pending code is cleared and nothing was "sent"; the transaction stands, and the page asks again. With no mail sender wired, a factor that asks for a mail is the same `503`; the account-email proof is `403 mfa_email_proof_unavailable` (`packages/mfa/src/mail.mts`, `proof.mts`) | `mfa_mail_unavailable` (error — `route`, `purpose`, `kind`, `reason` `outage` or `no_sender`, `cleared` when a pending code was to be cleared, and the sender's failure by its `name`, `code` and `status` alone — never its text, which may quote the address or the code); at the limit `mfa_mail_refused_at_limit` (warn — `route`, `purpose`, `kind`, `cleared`). `cleared: false` means the clear was not written: the kept code stands until the transaction ends | the sender's own |
| **The Store's enrollment witness** (`UserRepository.markMfaEnrolled`; foundation's at `REPOSITORIES_USER_HTTP_MARK_MFA_ENROLLED_URL`) failing its write — down, slow, or answering anything but `204` | a verification of a counting factor where the login's `User` does not say it enrolled — a login's, or a step-up's — and a first binding, at a login or in a signed-in session | nothing: the login completes and the factor stands — the witness is marked after the factor, so a failure leaves a factor without a witness, never the reverse, and the next such verification of a counting factor marks it again (the MFA ADR's D12) | `mfa_enrollment_witness_unwritten` (warn — `sub`, the error's projection) | the directory's |
| **A login's `User` says it enrolled, and no counting factor is on record** — the factor store lost its records; the Store answers `mfaEnrolled` wrongly or malformed; a removal from the account page left no record that may count and could not clear the witness (`mfa_enrollment_witness_uncleared`), or a store failed after removing the record and could not be read again (`503`, the witness left as it was); or a login's witness mark raced a removal's clear and its own clear after it failed | `POST /session/login`, under either mode; in a federated signed-in session whose login recorded it, every first binding — the link start, WebAuthn registration, `POST /session/mfa/enrollment`, `/step-up`, a rename or removal of a factor. A password session in that state is not answered so: its first bindings are sent to log in again (`401`), recording nothing, and the fresh login reads the `User` | `503 temporarily_unavailable` "session requirement unavailable", nothing written — never a first binding (D12). See the MFA ADR's D12 for recovering a lost factor store; after a removal, clear the subject's flag in the Store | `session_admission_unavailable` (error, `store: "mfa"`, `phase: "establishment"` at a login, the `action` in a session) whose `err` is `MfaEnrollmentStateInconsistentError` (`reason` `mfa_enrollment_state_inconsistent`); audit `mfa.enrollment_state_inconsistent` (`details.witness`: `enrolled` or `malformed`; `details.purpose` `login`, or `session` with `details.action` for a federated session) | — |
| **Client repository** lookup throws | client authentication on `/oauth/token`, `/oauth/introspect`, `/oauth/revoke`, device authorization and the federation-grant client routes — a secret (`findById` or `authenticate`) or a `private_key_jwt` assertion (`findById`) — the client lookup at `/authorize`, token exchange's own lookup, the federation token route's `azp` lookup, the code exchange's logout-metadata lookup, the consent page's and answer's lookup, the federation-grants connect and consent pages' lookup, and the two logout routes' check of a `post_logout_redirect_uri` against the client's registered list (`/oauth/logout`, `POST /oauth/federation/:name/logout` — asked only when the request names one and the hint names a session) | `503 temporarily_unavailable` "client repository unavailable" (`/oauth/consent`: "client registry unavailable") — except at the two logout routes, which complete the logout without the redirect, as if no `post_logout_redirect_uri` had been sent: an outage costs the redirect, never the logout (it used to be dropped without a log line), no `WWW-Authenticate` challenge — repository unavailability never admits a client, and is not answered `invalid_client` either: the client did nothing wrong, and a proxy holding client credentials would read `401 invalid_client` as its own misconfiguration. `/authorize` answers it as JSON (no redirect target is trusted yet); it was `500 server_error` "Failed to fetch client", unlogged. An unknown client or a wrong secret is still `401 invalid_client` (`400` at `/authorize`). A `client_id` that cannot name a client — a control character, or longer than 256 characters (`MAX_CLIENT_ID_LENGTH`) — is refused the same way before the repository is asked, so a store that throws on such input (a SQL driver refusing a NUL byte) cannot be made to answer `503` (`packages/oauth/src/middleware/clientAuth.mts`, `clientAssertion.mts`, `routes/authorizeClient.mts`; the check is core's `isWellFormedClientId`) | `client_repository_unavailable` (error, `step`: `find` / `authenticate`, `clientId` sanitised and capped at 200 characters, the error's projection; `site` where it is not client authentication: `authorize`, `token_exchange`, `federation_token`, `authorization_code`, `consent`, `federation_grant_connect`, `federation_grant_consent`, `logout`, `federation_logout` — and `federation_grants` for client authentication on the federation-grant client routes) — every client lookup in core, oauth, token exchange and federation grants writes this one line through core's `logClientRepositoryUnavailable` (the consent route's own `consent_client_repository_unavailable` is gone); `client_assertion_refused` (error, `reason: "client_repository_unavailable"`) for an assertion | the repository's own I/O |
| **`grantPolicy` hook** throws | the grants that consult it at `/oauth/token` — `client_credentials` (under `oauth.resourceIndicator.enabled`), jwt-bearer, `refresh_token`, the WebAuthn grant and token exchange — and `/oauth/authorize` for the code flow (the code exchange does not consult it again; the device grant never does) | `503 temporarily_unavailable` "policy evaluation unavailable" (`packages/core/src/grants/grantPolicy.mts`); redirect `error=temporarily_unavailable` at `/authorize` | `grant_policy_unavailable` (error, `grantType`, the policy's `kind`, `site: "authorize"` at `/authorize`, the error's projection) — from every token grant (oauth's, token exchange, webauthn) and `/authorize`; `evaluateGrantPolicy` takes the logger as a required option, so no grant can leave it out, and core writes the line on its console logger when the composition wires none | the hook's own |
| **`grantPolicy` hook** returns a decision that is neither allow nor deny — an `outcome` other than exactly `"allow"` or `"deny"` (another string or case), no `outcome`, a value that is not an object, or a field that throws when read | the grants that consult it at `/oauth/token` — `client_credentials` (under `oauth.resourceIndicator.enabled`), jwt-bearer, `refresh_token`, the WebAuthn grant and token exchange — and `/oauth/authorize` for the code flow (the code exchange does not consult it again; the device grant never does) | `500 server_error` `policy_decision_invalid`, never a token (`packages/core/src/grants/grantPolicy.mts`, `readGrantPolicyDecision`); redirect `error=server_error` at `/authorize`, never a code. Not `503`: the policy is misconfigured, and a retry gets the same answer | `grant_policy_decision_invalid` (error, `grantType`, the policy's `kind`, `site: "authorize"` at `/authorize`, never the decision; on core's console logger when the composition wires no logger); audit `token.issued.failure` / `authorize.rejected` with reason `policy_decision_invalid` | the hook's own |
| Shared Redis down — **consent step** (`ADAPTERS_CONSENT_STORE=redis`) | `GET/POST /oauth/authorize` for a client that is not first-party; `GET/POST /oauth/consent` | `/authorize` redirects with `error=temporarily_unavailable` "consent store unavailable" — never a code, never a refusal the user could act on (`packages/oauth/src/routes/authorizeConsent.mts`); `/oauth/consent` answers `503 temporarily_unavailable` "consent store unavailable" (`packages/oauth/src/routes/consent.mts`) | `authorize_consent_store_unavailable`, `authorize_pending_consent_store_unavailable`, `pending_consent_store_unavailable`, `consent_store_unavailable` (error) | `commandTimeout` |
| Shared Redis down — **device-code store** (`redisDeviceCodeStoreModule`, `packages/redis/src/device-code-store.mts`; the in-memory adapter has no outage mode, and `multi` refuses it) | `POST /oauth/device_authorization`; `POST /oauth/device/verification`; the device polling `/oauth/token` | `503 temporarily_unavailable` "the device authorization store is unavailable; retry later" on all three, at once: `/oauth/device_authorization` re-draws only on the store's own collision signal (`packages/device-grant/src/deviceAuthorizationEndpoint.mts`); `/oauth/device/verification` (`verificationEndpoint.mts`) — an approval or a denial may already be recorded, so a retry can answer `409 already_decided`, audited as `device.decision_outcome_unknown`; the device's poll at `/oauth/token` is answered by the grant (`grant.mts`), as every grant answers a store outage — an approval it read may already be consumed, and the device's retry is then `invalid_grant` | `device_authorization_store_unavailable`, `device_verification_store_unavailable`, `device_code_grant_store_unavailable` (error) | `commandTimeout` |
| Shared Redis down — **session liveness at `/oauth/consent`** (the user-session store cannot say whether the cookie's session is live) | `GET/POST /oauth/consent` | `503 temporarily_unavailable` "session store unavailable" — it used to be `401 login_required`, which sent a signed-in user to log in again for the server's fault. Nothing is shown or recorded; the parked request stays parked for a retry (`packages/oauth/src/routes/consent.mts`, through core's session admission) | `session_admission_unavailable` (error, `store: "user_session"`, `action: "oauth.consent"`, the error's projection; never the `sid`) — it was `consent_session_liveness_unavailable` | `commandTimeout` |
| Shared Redis down — **session liveness at device verification** (session admission — the user-session store, the subject's sessions boundary, or a session requirement — cannot say whether the cookie's session may act) | `POST /oauth/device/verification` | `503 temporarily_unavailable` for every action ("session store unavailable", "revocation store unavailable" or "session requirement unavailable" by what could not answer, core's `describeAdmissionOutage`), before the budget is spent or the code is read — never an approval on the cookie's word, and never `401 login_required`, which would send a signed-in user to log in again for the server's fault. The device keeps polling `authorization_pending` (`packages/device-grant/src/verificationEndpoint.mts`) | `session_admission_unavailable` (error, `store: "user_session"` / `"revocation_boundary"` / the requirement's name, `action: "device.lookup"` / `"device.approve"` / `"device.deny"`, the error's projection — never the `sid`) | `commandTimeout` |

Two cross-cutting facts about these rows:

- **Rate-limit `429`s carry `Retry-After` only when the adapter reports a
  reset time.** Both bundled adapters do: the memory adapter from its bucket,
  the Redis adapter from the counter key's PTTL, returned by the same Lua
  script as the count (`packages/redis/src/ratelimit.mts`, #458). A custom
  adapter whose decision has no `resetAt` — or a custom `RateLimiterClient`
  that implements only `incrementWithTtl` — still gets `RateLimit-Limit` /
  `RateLimit-Remaining` and no `Retry-After`
  (`packages/core/src/ratelimit/guard.mts`).
- **`/session/login`, the WebAuthn options route and the MFA routes never run unguarded.**
  With no `rateLimiter` wired they fall back to a per-process memory limiter
  and say so once at boot (`login_rate_limiter_not_shared`,
  `webauthn_authentication_options_rate_limiter_not_shared`,
  `mfa_rate_limiter_not_shared`) — when
  `core.deployment.mode` is unset. Under `"multi"` the fallback is refused at boot
  like every other per-process store (#474, see [Boot refusals you will meet](#boot-refusals-you-will-meet)); under
  `"single"` it is silent. The OAuth endpoints, by contrast, run with no
  limiter at all in that case (`packages/oauth/src/routes.mts`).

### Keeping MFA factors in the Store

With `foundationMfaFactorStoreModule` installed, the Store keeps every enrolled
factor, and the provider trusts it with their integrity and freshness: it
never rolls a factor back, hides one from a list, answers one it acknowledged
removing, or lets two updates at one version both succeed; a version never
goes back, and an acknowledged write is never lost across a restore or a
failover. The provider reads every answer strictly, but it cannot tell when
this breaks: a factor's older record opens as it did then — its sealed data
is bound to the subject, the factor id and the kind, not the version.

- **What breaking it opens.** An older record brings back a TOTP step
  already used, within its window, and a spent recovery code; a removed
  factor answered again works again. A Store that drops a subject's records
  lets a password-only login through under `mfa.mode = "optional"`, and
  opens a first binding to whoever holds the password under `required`. The
  enrollment witness, kept outside the factor store, is what stops that (the
  MFA ADR's D12): the MFA package's `mfa` requirement reads it at login, in
  `admitPrimary`, and answers a witness that says enrolled beside no counting
  factor `503`, never a first binding.
- **Failover and restore.** A failover to an asynchronous replica can lose
  the last acknowledged writes, and so can a restore from a backup. Replicate
  the factor records synchronously; or, after a failover or a restore and
  before authentication resumes, expire the MFA state written since — the
  users' factors and recovery codes — or have the affected users enroll again.
  Treat what was written since as lost, and tell the users whose factors it
  touched.
- **Reads that lag writes.** A list served from a replica that has not seen
  the last write answers an older version: serve the list endpoint from where
  the writes land.
- **Write order.** The Store keeps its write order: a write is visible to the
  read that follows it. A first binding relies on it — it writes the factor,
  then reads the subject's records again, and stands only when they show its
  own alone, dropping its own when another login's stands beside it — so a Store that answers a read without a write
  it acknowledged lets two logins that bind at once both keep a first factor.
- **Where to keep them.** The MFA ADR's O6 recommends the factors in Redis
  and the witness in the Store. Keeping both in one Store weakens this
  protection: what drops or rolls back the one can do the same to the other.

### Which logout endpoint invalidates what

There are two, they differ, and the difference is one you have to choose
against — a session logged out at the wrong endpoint keeps a live credential.

| | `POST /session/logout` | `POST /oauth/logout` |
|---|---|---|
| Who calls it | the browser; the BFF / `auth.proxy` injection topology | an RP, with an `id_token_hint` |
| express-session cookie | destroyed | destroyed, but only when the request's own cookie names the `sid` being logged out |
| `UserSession` record | deleted | deleted |
| subject index | entry removed | removed via the cascade |
| federation tokens + index | removed | removed |
| **refresh-token families** | **not revoked** | revoked |
| RP registry / back-channel `logout_token` fanout | not run | run, after the session is marked ended, so an RP a code exchange registers during the logout is in the fanout or its exchange is refused (under the preconditions the oauth README lists; delivery stays best-effort) |
| On store failure | logged, still `200` — the cookie is destroyed either way | `503 temporarily_unavailable`, cascade retryable |

Deleting the `UserSession` record is what makes `/oauth/introspect` answer
`active: false` and `/oauth/userinfo` refuse, so both endpoints stop an access
token that carries a `sid`. Only `/oauth/logout` stops a **refresh** token: if
the session completed an `/authorize` → `authorization_code` flow, call that
one. The `session` grant issues no refresh token, so a deployment whose tokens
all come from it is fully served by `/session/logout`.

Neither endpoint reaches a resource server that validates the JWT offline —
signature and `exp`, no introspection call. Such a consumer cannot observe a
logout at all, and the only lever is a short access-token lifetime:
`oauth.accessToken.defaultExpiresIn`, and `oauth.accessToken.maxExpiresIn` for a
token a token-exchange request asked to live longer (unset, the max is the
default).

The asymmetry is structural: `cascadeLogout` lives in
`@o3co/auth-provider-oauth` and `@o3co/auth-provider-session` cannot import it.
It is recorded here because it changes an operator's choice, not because it is
expected to change.

### Replica clocks and subject revocation

**Keep the replicas' clocks, and the Redis servers', within 1 second of each
other (NTP).** The Redis factor store sets each write's deadline on the
replica's clock and Redis judges it on its own, so its write lifetime (2 s)
allows that 1 second between them: half 2 of the bound holds while the app's
and Redis's clocks agree within the declared skew. A late command, whether
resent, queued or stalled, writes nothing. A Redis clock ahead of the
replicas' by close to the second refuses factor-set writes that reach it
late in their window, as an outage (`mfa_store_unavailable`), never a write
past its lifetime.

A credential change, or any other call to `revokeAllForSubject`, sets a boundary
for the subject when a subject revocation store is installed and the write
succeeds (a failed write is reported as `tokensRevoked: false`). A sign-in dated no later than the boundary plus an allowance is refused: a
token by its `iat`, a session by its `authTime`. The comparison is inclusive,
with an allowance of
`DEFAULT_SUBJECT_REVOCATION_SKEW_MS` = 1 s (`packages/core/src/jwt/verify.mts`;
for sessions, `coveredByRevocationBoundary` in
`packages/core/src/federation-grants/effective-status.mts`).

The two sides are dated by different replicas. The replica that revokes dates
the boundary, and the replica that made the sign-in dates the sign-in. When
their clocks disagree:

| The sign-in replica's clock is | Effect | Kind |
| --- | --- | --- |
| behind the revoking replica's | A legitimate sign-in made just after the revocation is dated no later than 1 s after the boundary, and is refused. The user signs in again. | availability |
| ahead of the revoking replica's by more than 1 s | A token or session made just before the revocation is dated more than 1 s after the boundary, and survives it. | security |

A boundary later than the subject revocation store's clock plus 5 minutes
(`DEFAULT_CLOCK_SKEW_MS`) is recorded as that clock plus 5 minutes. A revoking
replica that far ahead leaves the tokens it minted just before the revocation
uncovered, and the store says so at warn (`subject_revocation_boundary_clamped`).

The allowance stays at 1 s, not the 5 minutes (`DEFAULT_CLOCK_SKEW_MS`) allowed
elsewhere. Each second of allowance refuses another second of sign-ins after
the boundary, so 5 minutes would refuse the first logins after a password
change for up to 5 minutes.

The same 1 s allowance, and the same dependence on the replicas' clocks, apply
where the boundary is compared with a federation grant's consent, an MFA
continuation, or a device authorization.

**`auth_time` is never later than the clock that mints it.** A session's
`authTime` carries the clock of the replica that signed the user in. The
`authorization_code` exchange and the `session` grant stamp it as the minting
replica's clock when it is ahead by up to 5 minutes (`DEFAULT_CLOCK_SKEW_MS`),
so `now − auth_time` is never negative — within the skew the age it shows can
be understated by up to the skew. A session dated further ahead is refused:
the exchange and the session grant answer `400 invalid_grant`
`session_invalid` before anything is signed, warned as
`auth_time_ahead_of_clock`. The remedy is the signing-in replica's clock
(NTP), not the user: until it is fixed, an RP that sends neither
`prompt=login` nor `max_age` is not sent to log in by `/authorize`, so the
same session keeps being refused at `/token`. A refresh caps the `auth_time`
it carries at the presented token's `iat` and its own issuance, and
introspection answers a token's `auth_time` no later than its `iat`.

---

### Linking a second federation to an account (#482)

A federated identity is `<provider>:<sub>`; the Store is the only place that
says which account it belongs to, and the provider never infers a match from
an e-mail. Linking is an explicit, authenticated action — the browser holds a
session and starts the federation with `?link=1` — and it fails closed at every
step: `400 link_unsupported` when the Store client has no
`linkFederatedIdentityUrl` (`REPOSITORIES_USER_HTTP_LINK_FEDERATED_IDENTITY_URL`),
answered before the session is read; then the start reads the live session
through session admission (`session.link`) and answers `401 login_required`
without a session, for a `UserSession` that is gone, expired or another
subject's, and — with `subjectRevocation` wired — for a session the
subject-revocation boundary covers, so a user whose sessions were revoked
signs in again before linking; `403 step_up_required` (with `requirement` and
the requirement's `page`) when a registered session requirement asks for a
step-up first — the MFA module does, under `mfa.mode` `optional` and
`required` alike, unless a second factor was verified in the session within
`mfa.manage.maxAgeSeconds`; for an account that holds no counting factor it
asks for a sign-in that recent instead, and answers an older one
`401 login_required` — and, as the account's first binding, the
account-email proof given in that session where the first-binding gate asks
it (`403 step_up_required` until then; see "The first binding" under the MFA
section) — (under `required`, only for a session that already meets the
baseline: a password session without a second factor is stepped up first
when its account holds a counting factor, and otherwise sent to log in
again — `401 login_required` — where the login binds the first factor, as
every consumer answers it);
`409 identity_conflict` when the identity is already another account's (the
Store is not consulted), `403 link_refused` / `409 identity_conflict` when
the Store says so, `503 temporarily_unavailable` when the session store, the
revocation boundary, a requirement or the Store is down (the session read's
line is `session_admission_unavailable`). The callback reads the session
again the same way (`session.link_callback`) and answers every refusal
`401 login_required`.
The link is bound to the session that started it — recorded in the
transaction — so a `form_post` federation (Apple) links the same way as a
`query` one, and a callback presented by a different authenticated session
is `401 login_required`.
Recent MFA bounds the start, not the write: the callback writes the identity
up to the federation transaction's lifetime (10 minutes) after the start was
admitted. Hosts' clocks must agree within `DEFAULT_CLOCK_SKEW_MS` (5
minutes): a session's `mfaAt` carries the clock of the replica that recorded
it, so a replica whose clock runs ahead stretches recent MFA by its lead.
A user who holds a counting factor and is answered `403 step_up_required`
steps up on the MFA page — `POST /session/mfa/step-up`, then one of their
factors verified on its transaction — which records recent MFA on the
session; the start is then admitted. Where no second factor can be recorded
on the session, the user signs in again instead: session admission says so
(`SessionView.secondFactorRecordable`) when the session store cannot record a
step-up, and when the session's record is not in a shape one can be recorded
on. It fails closed.
Successes and refusals are audited (`federation.identity.linked`,
`federation.identity.link_refused`, `subject` = the account,
`details.reason` on a refusal).

The rules a Store must apply before it links — never on an unverified or
relay address, never by e-mail alone, `sub` verbatim — are in
[`packages/session/README.md`](../packages/session/README.md#account-linking-across-federations-482).

### Trusting an upstream IdP's `amr`, and withdrawing that trust

What an upstream IdP says about its own login — `mfa`, `hwk`, … on the
profile it hands the federation callback — counts only for a federation
configured with `core.federations.<name>.trustUpstreamAmr = true`, beside its
`enabled` (the MFA ADR's D13). Otherwise the session records `amr` `["fed"]`
and keeps the IdP's values in `authentication.upstreamAmr`, where no token and
no `acr_values` entry sees them. None of the bundled adapters surfaces an
upstream `amr` (`profile.amr`); a custom adapter may.

- **Switching it on** applies to logins from then on. Entries of
  `oauth.authorize.acrValues` that only the IdP's values meet come back into
  `acr_values_supported` at the next boot (`acr_value_unsatisfiable` stops
  naming them).
- **Switching it off** also applies to logins from then on, and does not reach
  what was already written: a session recorded while it was on keeps the
  IdP's values in its `amr` and goes on stamping them; its refresh tokens
  carry them forward until their family ends — `oauth.refreshToken.expiresIn`
  after the login that began it, a day by default — and a code `/authorize`
  issued keeps the `acr` it chose. To withdraw at once, call
  `revokeAllForSubject` for the subjects who signed in through that
  federation. It stamps their revocation boundary and ends their sessions, and with them the refresh families and codes minted from them and every access token this provider itself verifies — at introspection, `/oauth/userinfo`, the federation-token route, token exchange and the refresh grant. An access token a resource server validates offline lives until its `exp` ([Which logout endpoint invalidates what](#which-logout-endpoint-invalidates-what)). It needs `subjectRevocation` and `subjectSessionIndex` wired; without them it reports itself `incomplete`. The users log in again under the new
  setting.
- **A switch in the wrong place** — inside a nested section's sub-section,
  `core.federations.<name>.<type>.trustUpstreamAmr` — refuses boot, saying it
  belongs beside `enabled`.

### Multi-factor authentication: the lock, mail and notices

What a composition that installs the MFA package owns beside it (the MFA
ADR's D5, D21, D24). The package is private until the standalone template
wires it.

- **The lock on guessable proofs.** Five attempts per transaction. From the
  fifth consecutive failure a lock of 15 minutes, doubling to 24 hours. Ten
  failures in any seven days hold guessable proofs (TOTP, an emailed code)
  for the subject, whatever succeeds between them, from every browser.
  The `mfa.lockout.hardLimit`-th attempt since the last success (100; at
  least 10 and above `threshold`) holds them with no time to come back
  (`mfa.lockout`), whatever its outcome. An
  exempt proof (a recovery code, WebAuthn) passes during every lock and
  ends a consecutive run before the hard hold; it lifts no hard hold and
  refunds no weekly failure. The hard hold is fixed the moment the run,
  attempts in flight counted, reaches the limit: no later success, exempt
  proof or raised `hardLimit` lifts it. So the attempt that is the
  hardLimit-th since the last success holds, whatever its outcome. This is
  one stricter than NIST's '100 failed attempts': a correct hardLimit-th
  attempt still signs in, but guessable factors stay held until
  re-enrolled. The account-email proof is never held, and ends nothing. **A held subject can still be
  mailed an email code**: the challenge does not read the lock, so a code
  goes out up to the mail sender's limit (`429 rate_limited` beyond it), and
  is refused where it is verified (`429 mfa_locked`, spending one of the
  transaction's attempts). How many codes a password holder can have sent
  during a hold is that limit: set it on your mail sender (see **Mail**).
  `@o3co/auth-provider-standard`'s SMTP sender has no limit setting of its
  own: with it, the cap is your relay's quota. Apart from the sender,
  `mfa.rateLimit.routes` bounds the MFA requests of each client address
  (`mfa:ip:<ip>`), challenges included. A held proof is answered
  `429 {"error":"mfa_locked","hold":…,"usable_kinds":[…],"attempts_remaining":…}`
  — `Retry-After` in whole seconds, none for the hard hold. `usable_kinds`
  names the exempt kinds the subject holds, whether or not each still works:
  a recovery set with no code left is named, and refuses at its verification.
  So a TOTP-only user whose password an attacker holds needs a recovery code
  at every login while a hold stands. A password change, like any
  revocation, locks out whoever held the old password and is still the
  advice, but it clears no hold (D21): made without MFA, it proves nothing.
  The lock is cleared only by an authorized recovery, which the MFA
  transaction store applies once, under the subject's lease: a `recover`
  after a recent exempt proof gives the week back only when the subject's
  sessions were revoked after the attack's first failure, by more than five
  minutes (`DEFAULT_CLOCK_SKEW_MS`) — when a release is refused although the
  user changed the password, the change came within those five minutes:
  have them change it again — and lifts the hard hold once every guessable
  factor bound before it has been rebound, more than five minutes after the
  hold began; the operator reset ends every hold. The MFA module mints the
  authorization when a recovery code or a passkey verifies — at a login, or a
  step-up — for that session, lasting `mfa.manage.maxAgeSeconds`, and the
  user's page releases it with `POST /session/mfa/lock/release` (the MFA
  package README, "The lock's release"). The page's order is: change the
  password, sign in with a recovery code or a passkey, replace every TOTP or
  email factor where the hard hold stands, then release — one code spent. A
  release before the replacement gives the week back and answers that the
  hard hold stands; the next release needs another code. Without a sessions
  boundary wired (`subjectRevocation`; the boot warns once,
  `mfa_lock_release_unavailable`) a release can lift the hard hold on a
  rebind but never give the week or a backoff back early: those end on their
  own time, or at the operator reset. A host that lets a session that has
  not passed its second factor sign out everywhere hands whoever holds the
  password the boundary a release asks for; require the second factor for it.
  **The operator reset** — after confirming the account holder out of band,
  as the reset is the account-takeover path otherwise: install
  `mfaResetModule` beside `mfaModule` (with the oauth package's
  `subjectRevocationServiceModule`) and call `handle.components.mfaReset.resetMfaForSubject(subject, { requireEmailProof?, federationGrants?, requestedBy? })`.
  It ends all of the user's logins — every session and token, and the
  federation grants as `federationGrants` asks and policy allows — then,
  under the subject's lease (sixteen `mfa.storeTimeoutMs`, as every MFA write
  holds it, waited for up to two of them), sets D25's
  flag when asked, resets the lock state whole, removes every factor record
  and clears the enrollment witness, in that order, sets D25's flag again
  when asked (a binding's consume of it that timed out and landed during the
  reset would otherwise clear it), and then ends all of the
  user's logins again, so a login made with a factor before its removal ends
  too. Tell the user they will sign in again and enroll again. It answers a
  report: `complete: false` names where it stopped (`stoppedAt`: `sessions`,
  `lease`, `email_proof`, `lock`, `factors`, `witness`), or says `overran`
  (its lease ended before it released it, so a binding may have run beside
  it) — fix what it names and run it again; it is idempotent. `removed` is
  reported only once the removal succeeded. `requireEmailProof: true` needs a mail sender (else a
  `RangeError`, nothing done) and an account with an address, which the
  provider cannot read by subject: check the address in the Store first.
  Audited `mfa.reset`; logged `mfa_reset`, or `mfa_reset_incomplete` at warn.
  An `mfa_subject_lease_overrun` line for the same `sub` with
  `route: "enrollment"` around the reset is a binding whose write stalled past
  its lease and may have landed after the reset: run the reset again.
  A report with `witness: "unwritable"` is complete, but the directory has
  no `markMfaEnrolled`: clear the subject's enrollment witness in the Store
  yourself, or the subject's next password login is answered `503`.
  The reset needs `mfaModule` installed: under `mfa.mode = "off"` it is not,
  and the reset is unavailable (the boot refuses `mfaResetModule` without it,
  naming `mfaSubjectLeases`). With MFA off, nothing asks a second factor:
  end the subject's logins with the Store's password change and a direct
  call to `subjectRevocationService.revokeAllForSubject`. The subject's
  factor records, lock state and D25 flag are then inert until MFA is turned
  on; make the reset the first thing done after the boot that turns it on.
  The reset leaves D25's email-proof flag (`proof:{<s>}`) to the next first
  binding. On the in-process memory store a restart forgets every subject's
  lock — and every MFA transaction, generation and recovery-set floor — as
  well as that flag (a retired recovery set still stored verifies again once
  its floor is forgotten): do not use it where operator resets are used. A right
  code whose write was lost, or that met a store outage after it was checked,
  never counts; an outage before a code is checked does — a sustained
  transaction-store outage can push users toward a hold, fail-closed.
- **Recovery codes.** Each is spent once; the login answer says how many
  are left (`recovery_codes_remaining`), and `mfa.recovery_code.used`
  records it. A set's codes are kept as digests under the key ring's key of
  the day they were made, and cannot be made again: removing that key from
  `mfa.encryptionKeys` makes the whole set `503` (`mfa_factor_unreadable`,
  `state: "key_unavailable"`, naming the `keyId`) until the key is put back
  or the user regenerates the set from the account page
  (`POST /session/mfa/recovery-codes`, with recent MFA). Keep a key in the
  ring until no set made under it is left (the MFA package README, "Key ids
  and rotation"). A regeneration — and a first binding by the account-email
  proof — writes its set one generation past the subject's newest and
  raises the subject's recovery-set floor (`MfaTransactionStore`) to it:
  every older set is retired at once, its codes refused even while its
  record is still stored, and then removed. A set is written unshown and
  marked shown just before its codes are answered — at a login's first
  binding, once the session is established, so a login answered otherwise
  (another requirement's interruption, `401`, `503`) leaves it unshown: the
  account page's list says `recovery_codes_shown: false` for a set whose
  codes never reached the user, who should regenerate it.
  The same holds for the email factor's address digests: each login records
  the digest again under the ring's first key, but a record unused since its
  key left the ring answers `503` (`mfa_factor_unreadable`,
  `state: "key_unavailable"`) at its challenge until the key is put back or
  the factor is enrolled again. `mfa_digest_made_with_retired_key` counts
  both kinds of digest.
- **Mail.** The provider hands the `mailSender` slot what a code means — its
  purpose, the account, the address on the account's user record at that
  moment, the code and its expiry — and nothing rendered. The text and its
  language, delivery, and any limit on sending — per recipient, per account
  or overall — are the sender's: your mail system's, or
  `@o3co/auth-provider-standard`'s SMTP sender's. A sender answers a refusal
  at a limit, which the provider answers `429`, apart from an outage, `503`;
  a delivery that fails leaves the ceremony standing. The package's
  development sender logs each code, and installs only where the name the
  configuration was selected by, and `CONFIG_ENV` and `NODE_ENV` wherever
  they are set, each read `development` or `test`.
- **Mail failures: `429` and `503`.** `429` means the sender was refused at
  a limit: the user may try again later, and a steady rate of them means the
  relay's quota is too small for your sign-ins. `503` means the code did not
  leave for another reason; a steady rate of them is an outage of your mail
  path. With `@o3co/auth-provider-standard`'s SMTP sender, a limit is
  only a relay reply `421`, `450`, `451` or `452` carrying the enhanced code
  `4.7.1`, `4.7.28` or `4.5.3`, to the sender, the recipient or the message;
  every other failure is a `MailTransportError`, whose message names the
  stage, the relay's reply codes (`SMTP 550 5.1.1`) and the connection's
  failure (`ECONNREFUSED`, `ENOTFOUND`, `EAI_AGAIN`, `EHOSTUNREACH`,
  `ENETUNREACH`, `ECONNRESET`), never the reply's text, and whose `reason`
  says where to look:
  - `unreachable`: the network or the relay's name, where the message says
    it could not be reached (its code says how); or TLS, where it says the
    connection could not be secured — a certificate that does not name
    `standard-smtp-mail-sender.host` or chains to no CA the process trusts
    (add yours with `NODE_EXTRA_CA_CERTS`; `NODE_TLS_REJECT_UNAUTHORIZED`
    does not turn the check off), or a relay that does not offer STARTTLS
    under `secure = "starttls"`; or, under `none`, a host that reached an
    address that is not loopback;
  - `auth_failed`: the account (`STANDARD_SMTP_MAIL_SENDER_USER`, `_PASSWORD`);
  - `rejected`: the relay's policy — the sender address (`_FROM`), the
    recipient, the message — or a transient refusal that is not a limit
    (`421 4.3.2`, the relay going down); or an address the transport cannot
    send to as written — one beyond ASCII to a relay that does not offer
    SMTPUTF8, or an angle bracket in a quoted local part;
  - `timeout`: no TCP connection in 10 seconds, no implicit TLS handshake in
    another 10, no greeting in 10, 20 seconds without an answer, or no
    answer to the message within 40 seconds in all, however the relay spaces
    its bytes. A delivery the relay confirmed stays delivered, whatever
    comes of the `QUIT` after it.

  The SMTP sender's module needs `STANDARD_SMTP_MAIL_SENDER_HOST` and `_FROM`
  only where something reads the `mailSender` slot; there it refuses the boot
  without them, and with only one of `_USER` and `_PASSWORD` (an empty
  password is none). It sends each code to the one address the Store holds, and
  to nobody else.
- **The email factor's address.** Off by default; switch it on with
  `MFA_EMAIL_FACTOR_ENABLED=true` beside a mail sender. It mails a six-digit
  code at each challenge and a long code to enroll, each living
  `MFA_EMAIL_FACTOR_CODE_TTL_SECONDS` (600), capped at the transaction's
  life. It counts, and adds `mfa` only with `MFA_EMAIL_FACTOR_ADDS_MFA=true`.
  The factor keeps no address: only a keyed
  digest of the one its enrollment code went to. A login code goes to the
  account's current address only while that digest matches, so **a change of
  the address in the Store makes the email factor unusable until the user
  enrolls it again**, after recent MFA; the provider records
  `mfa.email_address_mismatch` when it refuses the factor for it. A user with
  no other factor needs a recovery code or an operator reset. The stale
  record stays — listed, refused at each challenge, and counted toward
  `mfa.maxFactorsPerSubject` — until it is removed: the account page's list
  says `address_changed` and the user removes it
  (`POST /session/mfa/factors/remove`), or an operator resets the subject
  (step 12). A session begun before the address changed lists, and mails a
  step-up's code, against the old address until the user signs in again. Changing the
  address is the Store's: ask for recent authentication, and tell the old
  address. **The Store must hold one mailbox per account**: the provider
  reads the address as one addr-spec alone, and an account whose address is
  a list, an angle address or carries a comment has no address to it. So do
  some spellings a mail system may deliver to, which the provider refuses on
  purpose: a zero-width non-joiner or joiner (U+200C, U+200D) in a local
  part or in a Unicode domain label; an emoji or another symbol beyond ASCII
  in a local part; a quoted local part with a space in it; an underscore in
  a domain; a local part a relay could route onward — a `%` or a `!`, or a
  quoted local part holding an `@`, a `%` or a `!` (`"a@b"@example.com`); an
  encoded word (`=?utf-8?q?…?=`), which a mail program decodes into other
  text; and a `<` or `>` in a quoted local part, which an SMTP envelope
  refuses. **Such an account has no email factor and no account-email
  proof.** A login records its address as `unreadable` in the session's
  enrollment facts (`none` for an account with no address, `address` for one
  the provider reads): no proof can be sent to it, so wherever a first
  binding asks for the proof — `mfa.enrollment.requireEmailProof` `always`,
  `when-mail` with a mail sender wired, or an operator reset's flag — it is
  refused (`mfa_email_proof_unprovable`, `reason: "unreadable_address"`) and
  cannot bind a first factor until its address is fixed in the Store, and
  under `mfa.mode = "required"` it cannot log in. Under `never` it binds
  without the proof. After an operator reset with `requireEmailProof` (`mfa.reset`), it
  cannot give the proof its next first binding asks for, and needs another
  way back — a recovery code, or the operator; give it an address the
  provider reads before you reset it.
- **The first binding.** Under `mfa.mode = "required"` a subject with no
  factor binds one at its next password login: a counting factor it may
  enroll (TOTP), and beside it a set of recovery codes the answer carries
  once — the page shows them and asks the user to keep them. If the codes
  cannot be written the binding stands and the answer says none were issued
  (`recovery_codes_issued: false`, one `mfa_recovery_codes_unwritten` line).
  With a mail sender wired and `mfa.enrollment.requireEmailProof = "when-mail"`
  (the default), an account with an address gives the account-email proof
  first — a long code mailed to the address the login's `User` carried; with
  no mail sender the boot says once that first bindings go without it
  (`mfa_first_binding_without_email_proof`), and `always` refuses the boot.
  Where no proof is asked — `requireEmailProof = "never"`, or `when-mail`
  with no sender or no address — whoever holds the password and one
  recovery code of a user whose counting factor is gone binds the first
  factor, by `password`, at the login the code reopens. The owner keeps
  their remaining codes and still signs in with them; the factor stands
  until the owner removes it (`POST /session/mfa/factors/remove`) or an
  operator does. The trail is
  `mfa.recovery_code.used`, then `mfa.factor.enrolled {purpose: "login",
  binding: "password"}`, then `mfa.recovery_codes.generated {regenerated:
  true, binding: "password", kept: "password_binding"}`; a Store that keeps
  the witness (`markMfaEnrolled`) refuses it (D12).
  The provider marks the enrollment witness (`markMfaEnrolled`) after the
  factor is written; a directory without it is said once at boot
  (`mfa_enrollment_witness_unwritable`), and D12's defence is then what the
  Store answers on `authenticate` and `authenticateByToken`. Foundation's
  user repository writes it with `REPOSITORIES_USER_HTTP_MARK_MFA_ENROLLED_URL`
  set, and the Store must then answer `mfaEnrolled` on both reads: a
  federated session records the witness from `authenticateByToken`. A
  subject that enrolled before the variable was set has no witness until its
  next counting verification, and a lost factor store reads it as never
  enrolled until then: when you set it, backfill `mfaEnrolled = true` in the
  Store for every subject that holds a counting factor. In a signed-in session, a subject with no
  counting factor makes its first binding the same way whatever it binds —
  a factor from the account page, a passkey, a linked identity — through one
  gate: the session must have signed in within `mfa.manage.maxAgeSeconds`,
  and where the proof is asked the MFA page's step-up
  (`POST /session/mfa/step-up`) mails it to the address the login's `User`
  carried; the proof, once given, is kept for that session alone for
  `mfa.manage.maxAgeSeconds` (`mfat:session-proof:`), and lost with the
  store it is simply given again. A session written before the facts were
  recorded (`enrollmentFacts`), or by a session store of your own that does
  not round-trip them, is sent to log in again for any first binding.
  Every first binding, once its proof is checked, and every verification
  that marks the witness (where the directory can write it), first notes
  the subject's first-binding mark in the MFA transaction store
  (`mfat:first-binding:`): a session, or a login, authenticated no later
  than it plus `DEFAULT_CLOCK_SKEW_MS` (5 minutes) may have recorded the
  account as not enrolled before it enrolled, so it binds no first factor —
  `401 login_required` wherever the first binding would open or complete,
  nothing spent, one `mfa_first_binding_distrusted` line at info; the MFA
  routes' answer carries `Retry-After`. A mark the store cannot note
  refuses the binding (`503`, nothing written; the attempt the proof
  reserved stays spent, so outages that outlast the transaction's attempts
  end it); a store at its cap or down therefore stops first bindings, never
  lets one through unmarked. **The re-login wait.** Any noted mark — a
  first binding that stands, one refused or failed after its note (a lost
  race, a factor store failing at the write), or a login that marked the
  witness — refuses a first binding to every sign-in up to the skew after
  it: fresh logins too, for 5 minutes, up to 10 across replicas whose
  clocks differ by the skew. Under `mfa.mode = "required"`, a factor-store
  blip at a first binding keeps that subject from logging in for that long;
  a Store that keeps the witness answers such a login `503` first (D12).
  It fails closed by design: tell users to wait the `Retry-After`. **Keep
  the replicas' clocks within `DEFAULT_CLOCK_SKEW_MS` of each other (NTP)**:
  they date both the sign-ins and the mark. The mark stands
  `max(mfa.manage.maxAgeSeconds, 2 × mfa.transactionTtlSeconds)` plus
  10 minutes and one factor-set lease (31 minutes 20 seconds by default).
  **What the mark leaves open.** The stretch between a mark's note and the
  witness's mark is a documented residual (the MFA ADR's D12): the mark is
  noted once, so a sign-in past it can make a first binding only when all
  three hold — a request stalled past `DEFAULT_CLOCK_SKEW_MS` between its
  note and its witness's mark; another sign-in of the same subject in that
  stretch; and a lost factor-store record, the one that request wrote. A
  durable factor store (AOF on, no eviction) stands against the third.
  A login whose subject's sessions were revoked, or whose password changed,
  after it began is `401 login_required` at its next call on the MFA
  routes (`mfa_login_revoked`, info), and binds and spends nothing; with
  `subjectRevocation` wired, an outage of the boundary is `503`. The
  boundary is read once per call: a revocation that lands during one call
  can still let that call bind, and the session it makes is dead at its
  first admission.
  A subject holds at most `mfa.maxFactorsPerSubject` records (10; its
  recovery codes are one): an enrollment from its session past that is
  `409 mfa_factor_limit`, enrollments made at once included. After
  switching `mfa.mode` from `optional` to `required`, a live password
  session of a user not yet enrolled is asked to log in again at its next
  action, and binds its first factor at that login. Under `required` such a
  session's actions read the factor store once each (whether the subject
  holds a counting factor), so a factor store outage answers them `503`.
- **Renewing the session id after an escalation.** A session whose
  authentication is raised in place — a step-up of its second factor, or a
  factor bound in it from the account page — is
  first moved to a new express session id (the session package's
  `renewSession`, through the `loginCompletion` slot; the MFA ADR's D27):
  `isAuthenticated`, `user` and `sid` carried over, a fresh renewal nonce
  written beside them, every other field dropped, the old id destroyed in
  the cookie store. The escalation is recorded with that nonce on the
  `UserSession`, and admission answers any other cookie session on the same
  `sid` `not_live` — so a browser tab, or a request in flight, that still
  holds the old cookie is sent to sign in again, even when its own save put
  the old id back in the cookie store after the renewal (express-session
  saves unconditionally). Both bundled user-session stores round-trip
  `renewalNonce`; a store of your own that drops it leaves escalated
  sessions unbound. Of two step-ups completed from one cookie session, the
  later one is answered as stale and signs in again. A stale copy's
  `POST /session/logout` ends only its own cookie session once the
  escalation is recorded; one whose read of the record ran before the
  record landed deletes the record, ending the renewed session too —
  availability only: the user signs in again. During a rolling
  upgrade, a replica on a release before the nonce does not compare it. What is bound to the old id is orphaned and
  starts again: a
  consent `/authorize` parked, a federation-grant browser binding, and the
  session's other open MFA transactions — a consent or connect flow left
  open in another tab is lost. The cookie store failing at the renewal is
  its outage (`store: "cookie_session"`, `step` `regenerate` or `save`):
  nothing is recorded, and the request's cookie session is dropped. At
  `save` the old id is already destroyed and the user signs in again; at
  `regenerate` the old id keeps what it held. A factor bound in a session
  is answered with its recovery codes whatever its escalation came to: they
  are shown once. A record that fails after the renewal leaves the cookie
  session holding a nonce the record does not: a session never escalated
  before stays as it was and is answered `401` at its next step-up, and one
  escalated before keeps the earlier nonce on its record, so it is
  `not_live` at once — either way the user signs in again; reading the expected
  nonce from the record admission read
  ([#940](https://github.com/o3co/auth.provider/issues/940)) removes this.
  A store that answers the escalated record without the new nonce has the
  session ended (`mfa_escalation_unbound`). A step-up's email code goes to
  the address the session's `User` carried at its sign-in: after the
  account's address changes in the Store, a login refuses the old address,
  while a step-up mails it until the user signs in again. Audit
  `mfa.verified` with `purpose: "step_up"` is the verification, recorded
  before the escalation; whether the escalation landed is in the
  `mfa_escalation_*` and `mfa_store_unavailable` lines.
  An authorization code keeps the `amr` its `/authorize` decided: one
  minted just before the user's own step-up stays password-only, and the
  MFA page's return to `/authorize` mints a fresh one.
- **The return to `/authorize`.** The MFA page returns the browser to the
  `redirect_to` it was handed, verbatim: the authorize request with its
  re-authentication ask (`reauth_ask`), a record in the express-session
  store beside the sessions. `/authorize` reads the ask on every pass of
  the request — after a login trip, the step-up, consent — and spends it
  on the pass that mints the code; one record stands for a request, each
  write lives ten minutes, and a chain of trips ends 30 minutes after its
  first ask, after which the request starts over. Within the ask's window
  a login made after the ask counts as fresh even once `max_age` has since
  passed; `auth_time` is still that login's true time, so a client that
  needs a tighter bound decides on it. A session that comes back
  from a trip it was already sent on is refused at the client's
  `redirect_uri`, never sent again. Where the user-session store cannot
  record a step-up (`mfa_step_up_unsupported`), an `acr_values` step-up is
  one login trip instead: a login that carries the factor gets the code,
  and one that does not — a user with no factor, a federated session — is
  answered `unmet_authentication_requirements`. A browser that is not
  signed in and sends `prompt=login` has the ask recorded before its
  login, so it logs in once — only for a request within 8 KB that names a
  well-formed `client_id` (a check of its shape: the client is looked up
  later); any other gets the plain login redirect and no record. On
  `session-store.storage.type = "memory"` such an ask whose browser never
  returns stays until the process restarts — express-session's memory store
  reaps a record only when it is read — bounded by the `/authorize` rate
  limit and the 8 KB cap. The ask's store failing is
  `authorize_reauth_ask_store_unavailable`. During a rolling upgrade from a
  release that spent the ask when it read it, a replica on that release
  can spend it before consent resumes the request: the user is asked to
  log in again once.
- **Notices to the account holder: required, and yours.** The provider sends
  none. It records audit events (`auditSink`), and the deployment reads them
  and tells the account holder — by mail, a chat message, anything — of every
  factor enrolled (`mfa.factor.enrolled`) or removed (`mfa.factor.removed`),
  recovery codes regenerated (`mfa.recovery_codes.generated`,
  `regenerated: true`; with `kept: "password_binding"` the older codes still
  work — word the notice "new recovery codes were issued; your earlier codes
  still work until you regenerate them", never "your old codes no longer
  work"; otherwise, `unreplaced: true` included, the older codes no longer
  work),
  an operator reset (`mfa.reset`), the first lock of
  an episode (`mfa.locked.first`) and an email factor refused at a changed
  address (`mfa.email_address_mismatch`). Wire it: it is how a user learns that a
  leaked password bound a factor first (D24). Route one event to an operator
  as well: `mfa.first_binding_conflict` with `removed: false`, a first factor
  that may be a password holder's and could not be removed — the
  Investigate row for it says what to do. To keep the audit trail and
  notify at once, contribute the notifier as `auditHooks` from a module of
  your own: core hands every event to the `auditSink` and to each hook.
  Boot names each hook's position and module (`audit_hooks_registered`,
  info); a sink that fails one event is `audit_sink_failed` (error) with
  that position (`sink`, 0 for the `auditSink`) and the event's `type`; an
  event a hook records while it runs reaches only the `auditSink`
  (`audit_sink_reentered`, warn — see Investigate). With hooks, the
  `auditSink` is handed a frozen copy, so a sink that changes its event
  now fails with `audit_sink_failed` alone, and
  `federation_grant_audit_failed` no longer fires: alert on
  `audit_sink_failed` instead. The loop guard is best effort, and its
  limits are the hook author's: it ends a loop through an awaited record,
  a detached `emitAuditEvent`, a timer or a promise chain started inside a
  hook's `record`, and through another module's component; it does not see
  work the hook hands to a queue consumer, a `setInterval`, a `MessagePort`
  or worker, or a promise continuation created outside the hook, nor work
  run through `AsyncLocalStorage.snapshot()` or
  `AsyncResource.runInAsyncScope`. The `auditSink` must not record into
  the slot, and a logger that turns `audit_sink_*` lines into audit events
  loops without bound: do neither.

### Federation grants — what each answer means (#593)

`POST /oauth/federation-grants/:grantId/token` hands a client an **upstream**
access token on a user's standing consent. The user is not present, so the
question an operator asks about any failure is *"does this need me, or does it
need them?"* — and the status says which.

| What you see | What it is | What to do |
| --- | --- | --- |
| `503 temporarily_unavailable` / `storage` | The revocation boundary, the store, or the backstop write failed. Fails closed deliberately: without the boundary there is no way to know the subject's grants were not revoked, and D13 does not read an unknown answer as "nothing was revoked". Logged once at error — `federation_grant_<route>_unavailable` — with the `store` and `step` that failed. | Restore the store. No grant is lost and nothing has to be re-consented. |
| `503 temporarily_unavailable` / `key_unavailable` | The credential is sealed under a key id that is not in the ring. Logged once at error with `reason: "key_unavailable"` and no `err`: nothing was thrown. | Put the key back. The records and the credentials are untouched — this is recoverable, which is why it is a 503 and not a 410. |
| `410 reauthorization_required` / `credential_unreadable` | The credential is there and does not authenticate under any key in the ring. | Investigate the key material first, and restore it if it was replaced rather than rotated. Only ask the user again once you are sure the material is right: consent you spend needlessly is consent you cannot get back. |
| `503 temporarily_unavailable` / `lock_timeout` or `concurrent_update` | Another replica is refreshing, or this call's write lost. Contention, not an outage: `federation_grant_token_contended` (warn). | Retry, at the client. Do NOT add a retry inside the route — a second attempt can cost a second upstream rotation. |
| `502 upstream_rejected` | The upstream refused with a code this provider knows. `Retry-After` is present when the answer came from a stamped failure. | Read the reason. `invalid_client` is your configuration; `invalid_grant` ends the credential and arrives as `410 reauthorization_required` instead. |
| `502 upstream_token_ineligible` | The upstream answered with a token that may not be handed on: no finite lifetime, a lifetime over the connection's `maxAccessTokenLifetime`, scopes beyond the consent, a token type that is not bearer, or an answer that could not be read. | The reason names it. All but the last are a connection setting against an upstream policy — raise the maximum deliberately, or ask for fewer scopes. Except at an IdP that accumulates consent (Entra): there a narrower grant is broadened by a wider one on the same registration, and asking for less does not help — one registration per scope set is the rule (D19, `docs/offline-access.md`). |
| `400 invalid_request` / `malformed_path` | A grant id in the path that Express could not percent-decode (`%zz`). Refused before the throttle and client authentication for `token`, `revoke` and — when acquisition is configured — `reauthorize`; for `status` only after client authentication, so an unauthenticated request gets `401` first. The browser callback (`/session/federation-grants/callback/%zz`) answers it as JSON too. | Nothing, server-side: the caller built a bad URL. |
| `500 server_error` / `unexpected_error`, with log `federation_grants_unexpected_error` (error) | An error escaped every handler. The line carries `site` — the handler that caught it (`token`, `status`, `revoke`, `create`, `reauthorize`, `connect`, `consent`, `callback`), or the router whose last error handler did (`federation_grants`, `federation_grants_browser`) — `correlationId` and the error's projection, `err` (`packages/federation-grants/src/routes.mts`, `log.mts`). | A bug or a dependency failure no handler expected: correlate by time and `x-request-id`, and report it. |
| `429 rate_limited` / `provider` | This deployment's own throttle, keyed `federation_grants:ip:<ip>`. | Configure `limits.federation_grants` on the limiter adapter if the budget is genuinely too small. |
| `429 rate_limited` / `upstream` | The IdP throttled us. `Retry-After` when it said when. | Back off at the client. |
| `503 service_unavailable` / `shutting_down` | The process has begun draining and will not start work nothing will wait for. | Normal during a rolling restart. Size the host's cleanup allowance at **45 seconds or more** — a ten-second drain is shorter than the upstream hard timeout plus the persist budget, so a shutdown under it abandons exactly the rotation the drain exists to wait for. The standalone gives cleanup the configured refresh tail plus a margin — 45 s under the shipped budgets, more when `upstreamHardTimeoutMs`, `persistRetryBudgetMs` or `lockWaitMs` is raised — and its compose files give the process 60; a Kubernetes deployment sets `terminationGracePeriodSeconds: 60` itself (the default is 30, below drain + cleanup). |
| `503 service_unavailable`, "Rate limiter temporarily unavailable" | The limiter backend is down and `redis-rate-limiter.failMode = "closed"`. | The limiter's policy, not this route's. |
| `federation.grant.refresh_persist_failed` (`storage`, `write_in_flight`, `hard_timeout`) | A refresh succeeded upstream and this process could not write down what it got. | A rotation may be lost: the IdP has moved to a refresh token this deployment does not have. Reconnect the grant only if subsequent calls actually answer `410 reauthorization_required`; an IdP with a rotation grace period often does not. |
| `federation_grant_token_unavailable`, `federation_grant_status_unavailable`, `federation_grant_revoke_unavailable`, `federation_grant_lodge_unavailable`, `federation_grant_connect_unavailable`, `federation_grant_consent_unavailable`, `federation_grant_callback_unavailable` (error) | One line per `503`, or per `temporarily_unavailable` redirect at the callback: `reason` — what the caller was answered (`storage`, `key_unavailable`, `upstream`, `connection_not_configured`, `upstream_unavailable`) — and, where a store failed, `store` (`federation_grant`, `federation_grant_intent`, `revocation_boundary`, `user_directory`; the connect flow's user-session store and sessions boundary are session admission's line, `session_admission_unavailable`) and `step` (on the token route, core's own: `open`, `boundary`, `status`, `backstop_revoke`, `lock`, `write`, `mark`, `upstream`, `refresh`), with `grantId` and `correlationId` where they are known and the error's projection as `err` — its name, message (capped at 256 characters: the store's or the library's own text reaches the line), code and causes, never what a library put beside them. A store or an upstream that did not answer in time is `err` "not answered in time; no longer waited for" (a credential write, a reauthorization mark); a credential write retried within `persistRetryBudgetMs` is one line with `attempts`. A lodging's `connection_not_configured` names the `connection` it asked for; a renewal on a removed connection is `403 access_denied` / `connection_not_permitted` and writes no line. No `err` where nothing was thrown: a key missing from the ring, an upstream that did not answer before the caller stopped waiting, a failed refresh's backoff still standing, a store's refusal (`refusal`). | Restore what `store` names, or the upstream. Correlate by `correlationId`, which is the `x-request-id` the response was answered under — the caller's own when it was sent once and matches `[A-Za-z0-9._:+/=#-]{1,128}`, otherwise one generated for the request, which the response header carries — and is the same on events written after the response. |
| `federation_grant_token_step_failed`, `federation_grant_status_step_failed`, `federation_grant_lodge_step_failed`, `federation_grant_consent_step_failed`, `federation_grant_callback_step_failed`, `federation_grant_callback_exchange_refused` (warn) | A failure that changed no answer, with the same fields: a boundary the answer did not need, a failed refresh's stamp, a lock release, a use record, an audit, a refresh that failed or was still persisting after the caller was answered, the upstream call the hard deadline abandoned, a different kind of failure an earlier credential-write attempt met, a lodging's store errors the answer does not stand for (a second write that threw and landed all the same — on a `201` too —, a question after it that could not be asked, a pointer write whose re-read decided the answer, an intent it could not close), a renewal's pointer that could not be retired, an upstream that answered with a refusal (`step: "upstream"` on the token route; `exchange_refused` at the callback). | Nothing waits on it. A sustained rate is the store or the upstream it names; a refresh that could not be persisted also emits `federation.grant.refresh_persist_failed`. |

A failed audit, touch or lock release does not change an answer that has
already been decided; it is logged as `federation_grant_token_step_failed`
(warn) and nothing waits for it.

### Ending a grant (#593, D13)

Three ways, and they end different amounts of what a user has.

| You want to | Call | What ends |
| --- | --- | --- |
| let a client disconnect its own integration | `POST /oauth/federation-grants/:grantId/revoke` | That one grant. 204, and 204 again on a retry. Ownership is the only check: a grant whose connection you removed, whose key is out of the ring, or which expired last week can still be ended. |
| end one grant, or show a user their connected applications | `revokeFederationGrant(deps, grantId, by)` / `listFederationGrantsForSubject(deps, subject)` | That one grant, on the Store's authority. There is no admin route: authenticating the person and checking the grant is theirs belongs to the Store, which has both. |
| end everything one subject holds | the `subjectRevocationService` component | Sessions, tokens and grants. This is what a credential change calls. |

The service takes `federationGrants: "revoke" | "keep"`, default `"revoke"`.
`"keep"` — end the sessions and the tokens, leave the established grants —
is an **operator allowance**, `federation-grants.allowKeepOnSubjectRevocation`,
default `false`, and not something a caller may switch on. Turning it on needs
a `subjectRevocation` adapter carrying both boundaries; boot refuses the
pairing rather than revoking silently.

Read `requested`, `applied` and `reason` together. **`complete: true` means
the applied action completed, not that the requested one was honoured**: a
Store that asked for `"keep"`, was refused by policy, and reads only
`complete` will believe the subject's grants survived when every one of them
was revoked.

When `"keep"` is sound: a change the signed-in user made after proving their
current credential. When it is not: a reset, a forced change, a suspected
compromise, a disablement — those are `"revoke"`. In between, pass
`revokeGrantsConsentedSince` with the instant you suspect, and everything
consented at or after it is ended anyway.

Two things `"keep"` does not keep, on purpose: a `pending` grant, which is a
consent the user had not finished giving, and any reauthorization in flight,
whose pointer is retired so it cannot widen the grant afterwards. One window
stays open: the gap between a callback's final re-read and its activation
write, which exists with perfectly agreeing clocks and closes only with write
fencing, which is not built (D13). A renewal that passed its re-read before
the revocation landed can activate after it.

If a subject-wide revocation reports `complete: false`, **retry it**, and
which failure you are looking at decides how much the retry matters:

- **`"revoke"`** — the grants boundary was stamped before anything was
  enumerated, so it is the backstop meanwhile: a grant consented before it is
  refused at `/token` and revoked durably there, even if the pass that should
  have ended it never ran. The retry tidies up; it is not what makes the
  revocation hold.
- **`"keep"`** — there is **no grants boundary behind it**, by design: the
  whole point of the mode is not to advance one. So a grant in `grantsFailed`
  — one that `revokeGrantsConsentedSince` selected, whose write threw — is
  **still usable** until the retry succeeds. Nothing else will end it. Treat
  that `complete: false` as an open incident rather than as bookkeeping, and
  if you cannot retry promptly, run a plain `"revoke"` instead: it stamps the
  boundary and covers every grant at once.

`grantsFailed` and `grantsRetireFailed` want different retries. The first is a
revocation that did not happen; the second is a grant your policy **kept**
whose in-flight reauthorization could not be ended — revoking it on retry
would destroy exactly what the policy chose to keep.

**A grant needs a federation that is enabled**, and enabling a federation
brings the session-federation stores with it. A deployment that wants offline
delegation and nothing else still wires those.

### Acquisition refusals an operator meets (#593 slice 6, #611)

| What you see | What it is | What to do |
| --- | --- | --- |
| boot: `… the userRepository has no findSubjectByFederatedIdentity`, or `… has no supportsFederatedIdentityLookup` | Under `identityLookup = "required"` (the default) the repository must have the lookup and say what it covers. The HTTP repository has it once `REPOSITORIES_USER_HTTP_FIND_SUBJECT_BY_FEDERATED_IDENTITY_URL` is set (#613). | Set the URL to your Store's lookup endpoint (foundation README, "The identity lookup"), or set `federation-grants.identityLookup = "unsupported"` — the recorded decision not to refuse an upstream account another local user holds. |
| boot: `federation-grants.connections.<name>: the userRepository does not cover the registration …`, or `… threw when asked whether it covers …` | The Store must say, per connection, that it can place an upstream identity from that registration with the claims the connection names. For the HTTP repository that is `repositories.user.http.federatedIdentityLookupCoverage`: no entry equals this connection's `{ provider, issuer, clientId }`, or the entry's `requiredClaims` names one the connection's `identityClaims` does not. The bundled in-memory repository covers none. | Declare the registration (exactly as configured) with the claims your Store's strategy needs, and name them in the connection's `identityClaims`; or `"unsupported"`. |
| redirect `error=temporarily_unavailable` at the callback, with `federation_grant_callback_unavailable` (error, `store: "user_directory"`, `step: "find_subject_by_federated_identity"`) | The lookup could not be made: the Store answered anything but a `2xx` with one of the three answers (a `404` is not "nobody"), timed out, redirected, or exceeded the body cap. With `err.name: "StoreCredentialRefusedError"` (`storeStatus` `401` or `403`), the Store answered with a `Bearer` challenge: it refused this deployment's `REPOSITORIES_USER_HTTP_BEARER_TOKEN`, not the user. With `StoreTransportError`, it could not be reached or answered something unreadable; with `TimeoutError`, it did not answer in time. A `TypeError` is a repository that no longer has the lookup — a composition fault. | Fix the Store; the flow can be started again. Never map an HTTP failure to `unlinked` on the Store side either. For a `StoreCredentialRefusedError`, set `REPOSITORIES_USER_HTTP_BEARER_TOKEN` to a token the Store accepts; for a `StoreTransportError`, the line's `err.reason` and `err.detail` say which transport failure it was, as on the login, federation and jwt-bearer lines (§3, Store row): `could not be reached` (`unreachable`) is the network path or TLS to the Store — DNS, a firewall, a certificate, `ERR_SSL_SSL/TLS_ALERT_HANDSHAKE_FAILURE` for a Store expecting a client certificate; `closed before a complete response arrived` (`connection_closed`) is a connection closed under the request — occasionally a keep-alive race with the Store's or a proxy's idle timeout, persistently the Store or a proxy closing or restarting; `answered with a malformed HTTP response` (`malformed_response`) or `could not be read` (`unreadable`) is the Store, or a proxy in front of it, answering badly — the URL's port and path, the proxy, the Store's own health. |
| redirect `error=identity_unverifiable` | The Store could not establish who holds the upstream account (`indeterminate`), or a claim the connection's `identityClaims` names was not in the id_token — the audit outcome says which. Not transient: asking again does not change it. | For a missing claim, the upstream does not issue it for this registration (Entra's `oid` needs `profile` in the scopes); for `identity_not_resolvable`, the person is not in the Store's directory. |
| redirect `error=identity_conflict` | The upstream account is another local user's. | Working as designed; the user signed in upstream as someone else. |
| redirect `error=grant_not_authorizable` at the callback, after a config change | The connection moved (issuer, client, scopes, resource, boundary, callback or federation name) between the consent and the callback; the flow ends before any code is exchanged. | Start the flow again. |

### Rotating the federation-grant key ring (#593, D16)

`redis-federation-grant-store.encryptionKeys` is a ring: **the first key seals** every
credential written from then on — activation and every refresh — and
**every listed key opens**, the envelope naming the key that sealed it. A
read never re-seals, so a paused grant stays under the key it was written
with until its next refresh, and inactivity is no evidence that a key is
unused. The ring is read once, at construction: changing it means a restart.

1. **Add the new key at the end** of the ring on every replica, and deploy.
   Every replica can now open what the new key seals; none seals with it yet.
2. **Move it to the first position** on every replica, and deploy. New
   writes seal under it. Keep the old key listed.
3. **Record when the last replica that sealed with the old key stopped**,
   and prevent a rollback to a ring that has the old key first.
4. **Keep the old key listed for 365 days after that instant** — the code's
   lifetime ceiling (`FEDERATION_GRANT_LIFETIME_CEILING_MS`), which is the
   longest any credential sealed under it can still be live. Not
   `maxExpiresIn`: lowering it does not shorten grants already written, and
   raising it later would make them usable again. Earlier only with
   evidence: every grant that was active at step 3 has since been replaced
   by a refresh, revoked, or passed its stored `expiresAt`. `tombstoneRetention`
   adds nothing — a credential past its stored expiry is refused, sealed or
   not.
5. **Remove it from every replica together**, with the rollback configuration.
   Never reuse an id with different material: that is not rotation, it is a
   credential nobody can open, read as `credential_unreadable`.

A key dropped too early reads as `503 key_unavailable` on every grant it
sealed — recoverable by putting it back, which is why the store never deletes
on that answer.

The credential's extension (`ext` in the grant hash, which holds the token's
`effectiveExpiresAt`) is sealed under the same ring at the same write, and
needs no step of its own. One that names a key not in the ring reads as
absent, never as `key_unavailable`.

### Upgrading the Redis federation-grant store to a release that keeps a token's end (#1037)

A refresh stores when the upstream said the token ends (`effectiveExpiresAt`),
and the Redis store keeps it in the grant hash's `ext` field, beside a
credential that every earlier release still reads. No migration, and a
rolling upgrade or a rollback is safe. Until the last replica runs the new
release:

- **A replica on an earlier release serves a token to the released end**
  (`obtainedAt + issuedLifetime`), as that release always did. A token whose
  upstream said it ends sooner can be handed out after that, and the upstream
  answers it with `401`: availability, not wider access.
- **A credential written by an earlier replica orphans the `ext` beside it**
  (under `allow-plaintext`, unless it is byte for byte the credential already
  there), and the new release reads it as absent: that token, too, ends at the
  released end, until the next refresh on a new replica writes `ext` again.
- **A `FederationGrantStoreClient` of your own** that ignores the new
  `extension` input never writes `ext`. Its grants stay on the released end
  indefinitely, which is the behaviour before this release.

---

## 4. Alerts

Alert on the **event name**, never on message text. Application logs and
audit events share one pino stream in the standalone, separated by `name`
(`"provider"` vs `"audit"`); the audit event type doubles as `msg`
(`templates/standalone/src/logger.mts`). `LOGGING_LEVEL` does not gate the audit
stream — its level is fixed at `info`.

### Page — a dependency is down or a guarantee is not being met

| Event | Where | Why it pages |
| --- | --- | --- |
| `session_admission_unavailable` (error — `store`, `action` or `phase: "establishment"`, `err`) | `core/src/session-admission/admit.mts` (a session), `core/src/session-admission/establishment.mts` (`phase: "establishment"`, a login) | a consumer of an authenticated session — `/authorize`, consent, the session-bound grants, device verification, the federation-grants browser half, the federation `?link=1` start and callback, WebAuthn registration through `webauthnSessionSubjectModule`, a login — met an outage in the session store, the revocation boundary, or a registered requirement (`store` names which — `mfa` when the MFA requirement could not list the subject's factor records, at a login or, at any use, for an action that adds a way into the account: the link start, WebAuthn registration), and answered fail-closed (`503`, or the grant's `temporarily_unavailable`). Never carries the `sid`. `action` names the consumer: from `packages/oauth`, `oauth.authorize` (`/authorize` answers `temporarily_unavailable` at the `redirect_uri`, no code), `oauth.consent` (`/oauth/consent` answers `503`, nothing shown or recorded, the parked request kept for a retry), `oauth.session_grant`, `oauth.code_exchange` and `oauth.refresh` (`503` at `/oauth/token`); it replaced `authorize_session_liveness_unavailable`, `consent_session_liveness_unavailable`, `session_grant_store_unavailable` and the `store: "user_session"` cases of `authorization_grant_store_unavailable` and `refresh_token_store_unavailable` |
| `authorize_cookie_session_unavailable` (error — `store: "cookie_session"`, `step: "regenerate"`, `err`) | `oauth/src/routes/authorizeSession.mts` | `/authorize` refused a session — dead, expired or revoked — and could not regenerate the cookie session before sending the browser to log in, so it answered `temporarily_unavailable` at the `redirect_uri` rather than leave the refused session's flag behind. The express-session store is failing its writes; logins fail with it |
| `authorize_reauth_ask_store_unavailable` (error — `err`) | `oauth/src/routes/authorizeAsk.mts` | the express-session store could not read, record or spend a re-authentication ask: `/authorize` answered `temporarily_unavailable` at the `redirect_uri`, and minted no code where it could not spend the ask the request presented. For a browser that is not signed in and sent `prompt=login`, the login redirect went out without an ask instead, and the user is asked to log in again on the way back. The express-session store is failing; logins fail with it |
| `authorize_step_up_page_off_origin` (error — `requirement`) | `oauth/src/routes/authorizeAsk.mts` | a session requirement's step-up page is not on the issuer's origin, so `/authorize` answered `server_error` at the `redirect_uri` instead of sending the browser there. A composition fault: registration refuses such a page when it is given the issuer, so a resolver was built without one — fix the requirement's `stepUpPage` or the resolver's construction |
| `federation_grant_step_up_page_off_origin` (error — `requirement`, `grantId`, `correlationId`) | `federation-grants/src/browserConnect.mts` | a session requirement's step-up page is not on the issuer's origin, so the federation-grants connect answered a plain `500` instead of sending the browser there. A composition fault, as for `authorize_step_up_page_off_origin`: fix the requirement's `stepUpPage` or the resolver's construction |
| `mfa_store_unavailable`, `mfa_factor_unreadable`, `mfa_factor_challenge_unavailable`, `mfa_factor_enrollment_unavailable` (error) | `mfa/src/routes.mts` | a login's second factor, or its first binding, or an enrollment or the account-email proof in a signed-in session (`route: "step-up"` among them; a session's escalation after a step-up or a binding in it, with its `sid`: `store: "cookie_session"` with `step` `regenerate` or `save`, the renewal, `store: "cookie_session"` with `step: "renewSession"`, a renewal answered without a renewal nonce, or `store: "user_session"` with `step: "recordSecondFactor"`, the record called once, or `step: "delete"`, an unbound session that could not be ended — a step-up answers `503` (`500` for `delete`) and is given again, a binding is answered as bound; a session's proof's `step` is `sessionEmailProofAt` or `recordSessionEmailProof`; the first-binding mark's, `firstBindingAt` or `noteFirstBinding` — a first binding is refused, nothing written, until the transaction store notes the mark; `store: "revocation_boundary"` with `step: "revokedBefore"` is a login's transaction whose subject's sessions boundary could not be read), could not be read, checked or completed: each answers `503` and cannot finish. `mfa_factor_unreadable` with `state: "key_unavailable"` names the `keyId` the ring no longer holds — put that key back (see the MFA package README, "Key ids and rotation"); `state: "unreadable"` is a record no key opens, sealed for another subject, id or kind; `state: "challenge"` is a pending challenge's kept state that does not open (with `keyId` when its key left the ring) — the verification's attempt is spent and the page asks for a new challenge; `state: "enrollment"` is a first binding's pending enrollment that does not open, or a factor that threw completing it; `state: "verification"` of `kind: "recovery_code"` is a recovery code whose set was digested under a key the ring no longer holds — put the key back: a set cannot be digested again, only regenerated. `mfa_factor_enrollment_unavailable` (`kind`) is a factor that could not start an enrollment — the WebAuthn factor for an account whose username is not well-formed text, say |
| `mfa_mail_unavailable` (error — `route`, `purpose`, `kind`, `reason`, `cleared`) | `mfa/src/routes.mts` | a code could not be mailed — `reason: "outage"`, the sender's; `no_sender`, a factor that mails with no sender wired — and the user was answered `503`: nobody receives login codes or the account-email proof while it lasts |
| `mfa_first_binding_factor_standing` (error — `sub`, `kind`, the removal's failure) | `mfa/src/routes.mts` | a first binding that could not stand — its records read again did not show its own as the only one that may count (another login of the subject bound one at once), or could not be read to tell — could not remove its own factor after three tries: the factor may be a password holder's, and it stands. Beside audit `mfa.first_binding_conflict` with `removed: false` (Investigate): remove the subject's factors, or set D25's flag and reset them |
| `mfa_enrollment_factor_standing` (error — `sub`, `kind`, the removal's failure) | `mfa/src/routes.mts` | another factor added from the account page found the subject's records past `mfa.maxFactorsPerSubject` — enrollments made at once — or could not read them again, and could not be removed after three tries: it **stands and is usable**, and the user was answered `503`. Its enrollment is audited (`mfa.factor.enrolled`, `binding: "mfa"`), so the account holder's notice goes out as for any factor added; a failed read is the `mfa_store_unavailable` line beside it. The subject holds one record past the limit until a factor is removed. Sustained, the factor store is refusing removals |
| `mfa_recovery_codes_unwritten` (error — `sub`, the error's projection) | `mfa/src/routes.mts`, `mfa/src/recoveryCodes.mts` | a first binding wrote its factor, or a regeneration ran, and the recovery codes could not be written or marked shown: no codes were answered, and the user was told so (a binding's `recovery_codes_issued: false`, a regeneration's `503`); a set left unshown is listed `recovery_codes_shown: false`. Once the factor store answers, have them regenerate their codes. When the cause reads "the set changed before it was marked shown", another writer (a regeneration, a recovery or an operator reset) replaced or removed the set between the binding and the login's answer: nothing is out, and the codes that stand are that writer's — check the subject's factors before asking for another regeneration |
| `mfa_recovery_codes_conflict` (warn — `sub`) | `mfa/src/recoveryCodes.mts` | a regeneration read, after its write, another writer's set at its generation or a later one, and yielded (two writers the lease let in together — an evicted lease, a store slower than `mfa.storeTimeoutMs`): it removed its own and answered `409`, its codes never shown. The other set's codes were answered to whoever wrote it; if the account holder did not regenerate twice, look for the other session |
| `mfa_recovery_set_floor_unread` (warn — `sub`, the error's projection) | `mfa/src/factorSet.mts`, `mfa/src/requirement.mts` | a reading of a subject's records — a password login's ask, a transaction's offers, the account page's list, a step-up — found a recovery set and could not read the subject's recovery-set floor within `mfa.storeTimeoutMs`: every set was read as without it, so a retired set may be offered or listed usable (its codes are still refused: a verification reads the floor itself and answers `503` while it cannot). Only subjects holding a recovery set pay the read. Sustained, the MFA transaction store is out — see its row |
| `mfa_recovery_codes_unreplaced` (error — `sub`, the error's projection) + audit `mfa.recovery_codes.generated` with `unreplaced: true` | `mfa/src/routes.mts`, `mfa/src/recoveryCodes.mts` | a first binding by the account-email proof, or a regeneration, over a subject's standing recovery codes wrote the new set and raised the recovery-set floor, and could not list or remove the old one: the old record is still stored, **retired** — its codes are refused, no transaction offers it, and the account page lists it `retired`. Once the factor store answers, remove the subject's older `recovery_code` record (the one created before), or let the next regeneration remove it. The audit's `unreplaced: true` **without** this line, and with `kept: "password_binding"`, is on purpose: a first binding by `password` (no account-email proof was asked) — at a login reopened after a recovery code, or from the account page — kept the owner's set, so the owner's remaining codes stay usable. If the account holder did not bind that factor, the password and one of their codes are in other hands: remove the factor (or reset the subject) and have them change the password |
| `mfa_enrollment_state_inconsistent` (error — `route`, `sub`, `witness`) + audit `mfa.enrollment_state_inconsistent` (`purpose: "login"`) | `mfa/src/routes.mts` | a recovery code was verified for a subject with no record that may count while the login's `User` says it enrolled (`witness: "enrolled"`) or says nothing readable (`malformed`): answered `503`, the code and the transaction unspent — never a first binding (D12). The factor store lost the subject's records, or the Store answers `mfaEnrolled` wrongly: see the row for the same audit event at a login |
| `rate_limiter_failed_closed` / `rate_limiter_failed_open` (error) + audit `rate_limit.unavailable` | `core/src/ratelimit/guard.mts` | the limiter backend is erroring; closed means you are shedding login/token traffic, open means brute-force protection is off |
| `standalone_redis_clients_error` (error) | `templates/standalone/src/modules.mts` | the shared socket's `error` events — fires during reconnects too, so alert on rate or duration, not on one line |
| `session_store_redis_error` (error) | `session/src/store/factory.mts` | the cookie-session client; same reconnect caveat |
| `redis_duplicate_connection_error` (error) | `redis/src/ioredis/clients/refresh-token-family.mts` | a per-rotation duplicate connection failed; sustained means refresh rotations are failing |
| `readiness_probe_failed` (warn), sustained; `auth_dependency_up == 0` | `core/src/routes/Readiness.mts`, `templates/standalone/src/metrics.mts` | a replica is out of rotation |
| `unhandled_request_error` (error) | `core/src/middleware/terminalError.mts` — at the end of the composed router, and again after the template's host routes (health, readiness, metrics; `templates/standalone/src/routes.mts`) | a `500` you did not plan for — includes a signer (KMS) failure. A cookie-store failure is no longer one of them: it is `session_middleware_store_unavailable`. A body parser's refusal (`400` / `413` / `415`) is not logged |
| `server_error` (error), sustained | `templates/standalone/src/listen.mts` | the bound listener failed an `accept` — `EMFILE` / `ENFILE` (the process or the host is out of file descriptors), or `ECONNABORTED`. One line per failed `accept`, so fd exhaustion is a burst: alert on the rate, not on one line. The listener stays open and serves what it can still accept, but a sustained rate means fd exhaustion — check `ulimit -n` (the container's `nofile`) against the connection count, and look for connection leaks (keep-alives a proxy never closes, Redis clients, outbound fetches left open). Once nothing can be accepted `/_healthcheck` fails too and liveness restarts the process; this line says why. A bind failure (`EADDRINUSE`, `EACCES`) is not this line: it fails boot (§1, "Boot refusals") |
| `device_route_unexpected_error`, `federation_grants_unexpected_error` (error) | `device-grant/src/module.mts`, `federation-grants/src/routes.mts` | a `500` on the device-grant or federation-grants routes. Answered inside those routers, so `unhandled_request_error` does not fire for them — an alert on that event alone misses these — except for an error that arrives after a response's headers went out: those routers pass it on, and core's terminal handler logs it as `unhandled_request_error` with `headersSent: true` |
| `device_authorization_store_unavailable`, `device_verification_store_unavailable`, `device_code_grant_store_unavailable` (error) | `device-grant/src/deviceAuthorizationEndpoint.mts`, `verificationEndpoint.mts`, `grant.mts` | the device-code store is down or timed out: the device could not start (`device_authorization`, no code re-drawn), the user's lookup, approval or denial got no answer (`device/verification`), or the device's poll got none (`/oauth/token`). Each answered `503 temporarily_unavailable`. The same outage as the shared-Redis row above. An approval or a denial may nonetheless have been recorded before the reply was lost: a retry then answers `409 already_decided`, and the audit event `device.decision_outcome_unknown` marks the attempt. A poll's approval may likewise have been consumed, and the device's retry answers `invalid_grant`; the device starts again |
| `token_verification_unavailable` (error) by `site` and `reason` | `oauth/src/verificationUnavailable.mts`, `oauth/src/grants/refreshToken.mts`, `oauth/src/routes/revoke.mts` | a route (`site`: `introspect`, `userinfo`, `federation_token`, `federation_logout`, `logout`, `revoke`, `refresh_token`) is answering `503` because it could not verify tokens: `reason: "verification_key_unavailable"` = the keystore did not answer (the projected error's `cause` names it); `"revocation_unavailable"` = the denylist or the watermark store is unreachable. Replaces `refresh_token_revocation_store_unavailable` |
| `token_exchange_validation_unavailable` (error) | `oauth-token-exchange/src/tokenValidation.mts` | token exchanges are answering `503` because a validator could not reach an answer — for the built-in one, the keystore or a revocation store; `role` says which token |
| `client_repository_unavailable` (error); `client_assertion_refused` (error) with `reason: "client_repository_unavailable"` | `core/src/repositories/clientRepositoryUnavailable.mts`, written by `oauth/src/middleware/clientAuth.mts`, `routes/authorizeClient.mts`, `routes/federationToken.mts`, `grants/authorization.mts`, `routes/consent.mts`, `routes/logout.mts`, `oauth-token-exchange/src/clientAuthentication.mts`, `federation-grants/src/browserJudgement.mts` and `federation-grants/src/browserPendingConsent.mts` (`site` names each but client authentication, which carries `site: "federation_grants"` on the federation-grant client routes); `clientAssertion.mts` | a client lookup is answering `503` because the client repository cannot answer — every client-authenticated endpoint is down for confidential clients, and no authorization request starts. With `site` `logout` / `federation_logout` nothing is refused: the logout completed without the RP's redirect |
| `refresh_token_store_unavailable` (error) | `oauth/src/grants/refreshToken.mts` | refreshes are answering `503` because the refresh-token family store (`store: "refresh_token_family"`, `step: "rotate"` or `"revoke"`) cannot answer; the session store's outage at a refresh is `session_admission_unavailable` |
| `federation_token_store_unavailable`, `federation_logout_store_unavailable` (error) by `store` and `step` | `oauth/src/routes/federationToken.mts`, `oauth/src/routes/federationTokenContext.mts`, `oauth/src/routes/logout.mts` | the federation token or logout route is answering `503` because a store cannot answer: `refresh_token_family`, `user_session`, `session_federation_index` or `federation_token` |
| `federation_token_upstream_unavailable` (error); `federation_token_refresh_failed` (warn) by `reason` | `oauth/src/routes/federationTokenRefreshFailure.mts` | the upstream IdP could not be reached for a refresh (`503`); or it answered and refused (`410` / `429` / `500`) |
| `federation_grant_token_unavailable`, `federation_grant_status_unavailable`, `federation_grant_revoke_unavailable`, `federation_grant_lodge_unavailable` (error) by `reason` and `store` | `federation-grants/src/tokenRoute.mts`, `statusRoute.mts`, `revokeRoute.mts`, `lodgeRoute.mts` | the federation-grant client routes are answering `503`: a grant store, intent store or revocation boundary that cannot answer (`store`, `step`), a credential sealed under a key not in the ring (`key_unavailable`), an upstream that could not be reached for a refresh (`upstream`), or a connection a client may use that the deployment does not configure, named at lodging (`connection_not_configured`; a renewal's removed connection is a `403`, not an outage). Each used to be a `federation grant operation failed` warn, or nothing |
| `federation_grant_connect_unavailable`, `federation_grant_consent_unavailable`, `federation_grant_callback_unavailable` (error) by `store` | `federation-grants/src/browserConnect.mts` (connect); `browserPendingConsent.mts`, `browserConsentAnswer.mts` and `browserUpstreamRedirect.mts` (consent); `browserCallback.mts` (callback); `browserJudgement.mts` (a store the connect or consent judgement could not read) | users cannot connect a grant: the connect page, the consent page or the upstream's callback cannot reach a store (`store`, `step` — the user-session store and the sessions boundary are `session_admission_unavailable`'s, with `action: "federation_grants.*"`), the Store's identity lookup (`store: "user_directory"`), or the upstream's token endpoint (`reason: "upstream"`); the callback sends the user back to the client with `error=temporarily_unavailable` |
| `federation_grant_token_contended` (warn), sustained; `federation_grant_token_step_failed`, `federation_grant_status_step_failed`, `federation_grant_lodge_step_failed`, `federation_grant_consent_step_failed`, `federation_grant_callback_step_failed`, `federation_grant_callback_exchange_refused` (warn) | `federation-grants/src/tokenRoute.mts`, `statusRoute.mts`, `lodgeRoute.mts`, `browserConsentAnswer.mts` (`consent_step_failed`), `browserCallback.mts` (`callback_step_failed`, `callback_exchange_refused`) | `contended`: refreshes of one grant keep waiting on each other's lock or losing the write and answering `503 lock_timeout` / `concurrent_update`. The others: a failure that changed no answer — a best-effort write, work after the answer, an upstream that refused — with the `step` and the error's projection; a steady rate is the store or upstream they name |
| `authorize_store_unavailable` (error) by `store` | `oauth/src/routes/authorizeIssuance.mts` | `/authorize` could not store the authorization code and redirected `temporarily_unavailable`: no authorization request completes while it lasts. (The consent, pending-consent and re-authentication stores have their own events: `authorize_consent_store_unavailable`, `authorize_pending_consent_store_unavailable`, `authorize_reauth_ask_store_unavailable`.) |
| `device_code_grant_revocation_unavailable` (error) | `device-grant/src/grant.mts` | a device's poll could not read the subject's sessions boundary to hold its approval against (`store: "revocation_boundary"`) and was answered `503` "the revocation boundary is unavailable; start a new device authorization request"; the approval it read is consumed, so the device starts again |
| `federation_token_keep_rotated_failed` (warn) by `step`; `federation_token_keep_rotated_skipped` (warn) by `reason` | `oauth/src/routes/federationTokenRefreshRecord.mts` | a refresh the upstream refused still rotated the refresh token, and the route tried, best effort, to keep the rotated one. `keep_rotated_failed`: the federation token store could not re-read the record (`step: "get"`) or write it (`step: "update"`), with the error's projection. The upstream has invalidated the refresh token the record still holds (RFC 6749 §6), so the next refresh of that connection fails and the user has to connect the federation again. `keep_rotated_skipped`: nothing was written on purpose, because a concurrent logout removed the record (`reason: "record_gone"`) or a concurrent refresh already rotated it (`"rotated_concurrently"`). The client got the refresh's own refusal either way, never a `503` |
| `federation_token_jwt_verify_failed`, `federation_logout_jwt_verify_failed` (warn) by `reason` | `oauth/src/routes/federationTokenCaller.mts`, `oauth/src/routes/logout.mts` | an access token presented to the federation token or federation logout route was refused (`401 invalid_token`). The line carries the verifier's `reason` alone, never what the token carries; the verifier's own `jwt_verify_rejected` has the rest. A keystore or revocation-store outage is not this line but `token_verification_unavailable` |
| `federation_token_index_self_heal_failed`, `federation_token_cleanup_failed` (warn) by `store` and `step`; `federation_token_lock_release_failed` (warn) | `oauth/src/routes/federationTokenUnlinked.mts`, `oauth/src/routes/federationTokenRefreshFailure.mts`, `oauth/src/routes/federationTokenRefresh.mts` | a best-effort write on the federation token route failed, with the error's projection; the client got the answer it would have got. `index_self_heal_failed`: a federation link with no token record, or with one holding no usable access token, could not be removed from the session's index (`404 federation_not_linked` either way; the next request tries again). `cleanup_failed`: after an upstream `invalid_grant`, the token record (`store: "federation_token"`, `step: "delete"`) or the link (`store: "session_federation_index"`, `step: "remove"`) was left behind (`410` either way). `lock_release_failed`: the refresh lock could not be released and holds until its TTL, so refreshes of that record wait (`federation_token_lock_timeout`) until then |
| `federation_token_record_unusable` (warn) | `oauth/src/routes/federationTokenSuccess.mts` | the federation token store handed back a record with no usable access token, which the route answers as no record (`404 federation_not_linked`, the link removed from the session's index). The line carries `federation` alone. A store that judges its records (the Redis one) never hands such a record back; seen with another store, that store is writing or keeping unusable records |
| `federation_token_lock_timeout` (warn), sustained | `oauth/src/routes/federationTokenRefresh.mts` | refreshes of one federation record keep waiting on each other's advisory lock and answering `503 lock_timeout`: a slow IdP refresh holding the lock, or a lock TTL shorter than the IdP's refresh time |
| `federation_token_refresh_unsupported` (error) | `oauth/src/routes/federationTokenRefresh.mts` | a federation whose provider cannot refresh is answering every expired token `503 refresh_not_supported`: configure the provider |
| `logout_federation_token_read_failed` (warn) | `oauth/src/routes/logout.mts` | RP-initiated logout could not read the first federation's token record (`store: "federation_token"`, `step: "get"`, the error's projection) before redirecting to that IdP's end-session endpoint. The logout proceeds; what is lost is the `id_token_hint` on the upstream call, so the IdP may ask the user to confirm the logout or to pick the account, or may not end the upstream session at all. The same outage as the other federation-token-store lines |
| `logout_registered_redirect_uri_refused` (warn) | `oauth/src/routes/logout.mts` | a logout's `post_logout_redirect_uri` matched an entry of the client's `postLogoutRedirectUris` that fails core's `checkRedirectUri` — not a URL, or an executable scheme such as `javascript:`, or any other shape `ClientEntrySchema` refuses at boot. Only a custom `ClientRepository`, which bypasses that schema, can hold one. The logout completed without the redirect. With `site` (`logout` / `federation_logout`), the sanitised `clientId` and the rejection's `reason`; fix the registration |
| `logout_frontchannel_uri_refused` (warn) by `site` and `reason` | `oauth/src/logout/frontchannelLogoutUri.mts` | a registered RP's `frontchannelLogoutUri` was not used at logout: its parsed protocol is not `http:` or `https:` (`not-http`), `URL` cannot parse it (`unparsable`), it is not a string (`not-a-string`), or reading it threw (`unreadable`). `site: "logout"`: the logout skipped that RP's iframe, and with no RP left the response is the one without front-channel logout. Only an entry a custom session RP registry answers, which bypasses `ClientEntrySchema`, can hold such a value. With the sanitised `clientId`, never the URI. The logout completes; that RP is not told about the logout through the front channel. Fix the registration. `site: "authorization_code"` is not reached: the code exchange reads the client record through core's client-record boundary first, which refuses a record holding such a value (`client_record_refused`; the exchange answers as for an unknown client, its RP registered with no logout metadata) and lets a read that throws through as an outage (`client_repository_unavailable`, `503`, no RP registered) |
| `logout_frontchannel_redirect_refused` (warn) by `reason` | `oauth/src/logout/renderFrontchannel.mts` | the front-channel logout page was handed a `postLogoutRedirect` whose `uri` core's `checkRedirectUri` refuses as written (`reason` is the rejection's reason; `reserved-parameter` for one that already carries `state`), that is a joined string rather than its parts (`not-an-object`), whose `uri` or `state` is not a string (`not-a-string`, `state-not-a-string`), or whose read threw (`unreadable`). The page was served with its iframes and without the redirect, so the browser stays on the sign-out page. The bundled logout route only hands it a registered URI that passed the same check, so a line here points at another caller of `renderFrontchannelLogoutHtml`; pass the registered URI and the RP's `state` as separate parts. Never the URI |
| `authorize_registered_redirect_uri_refused` (warn) | `oauth/src/routes/authorizeClient.mts` | an `/oauth/authorize` request's `redirect_uri` (GET or POST) matched an entry of the client's `allowedRedirectUris`, and the presented value fails core's `checkRedirectUri`. The registered entry itself passed it (core's client-record boundary, or the document's own check, holds every entry to it); the presented value differs from it only in a loopback port, which is matched as raw text, so this is a control character or other malformed text there. The client was answered `400 invalid_request` (`redirect_uri not allowed`) and the browser was not redirected. With `site: "authorize"`, the sanitised `clientId` and the rejection's `reason`; a client presenting such a URI is broken or probing |
| `client_record_refused` (warn) by `step` | `core/src/repositories/clientRepositoryBoundary.mts`, installed by `oauth/src/clients/clientBoundary.mts` (from `oauth/src/routerSettings.mts`, `oauth/src/middleware/clientAuth.mts` and `oauth/src/grants/authorization.mts`) and, with Client ID Metadata Documents on, by the document fallback in `oauth/src/clients/clientIdMetadataDocument.mts` | a client record the `ClientRepository` answered failed the registration schema — any rule `ClientEntrySchema` holds a `yaml` / `static` entry to at boot, an `allowedRedirectUris` entry `checkRedirectUri` refuses included — or named another id. The `/oauth` router and the client authentication read every registered client through core's client-record boundary, so the client was answered as unknown: `400 invalid_client` at `/oauth/authorize` with no redirect, `401 invalid_client` where a client authenticates, `400 invalid_request` at consent. At the code exchange the RP is registered for logout with no logout metadata, and the tokens are still issued. With `step` (`find` or `authenticate`), the sanitised `clientId` and the `reasons`, each naming a field and an entry's position, never a URI; fix the record |
| `federation_logout_end_session_failed`, `logout_federation_end_session_failed` (warn) | `oauth/src/routes/logout.mts` | the upstream IdP's end-session call failed after this server's own state was cleared: the user is logged out here but may still be signed in at the IdP (an orphan IdP session). With the error's projection and the sanitised `federation`. The federation logout route also emits audit `federation.logout.idp_unreachable`. Not every line involved an IdP: an Apple federation with no `endSessionEndpoint` refuses locally whenever it is handed no `post_logout_redirect_uri` — including one the request named but the client has not registered, which the routes drop — and that refusal is logged, and audited, the same way. Read those with the error's projection (a plain `Error`, no status) before paging anyone about the IdP |
| `logout_backchannel_rejected` (warn) by `status`; `logout_backchannel_failed` (warn) by `step`; `logout_frontchannel_iframe_skipped` (warn) | `oauth/src/logout/broadcastBackchannel.mts`, `oauth/src/logout/renderFrontchannel.mts`, `oauth/src/logout/frontchannelLogoutUri.mts` | an RP was not told about a logout, by `clientId` (sanitised, capped at 200 characters). `rejected`: its back-channel endpoint answered a non-2xx `status` (the RP's own status text is not logged). `failed`: the POST failed (`step: "post"`) or the logout token could not be built or signed (`"logout_token"`), with the error's projection. `iframe_skipped`: its front-channel URI could not be turned into an iframe URL, or its `frontchannelLogoutSessionRequired` could not be read. Logout proceeds either way; that RP's session may outlive it |
| `logout_store_unavailable` (error) by `store`; `logout_cascade_operation_failed`, `logout_cascade_cleanup_failed` (warn) | `oauth/src/routes/logout.mts`, `oauth/src/logout/sessionEnd.mts`, `oauth/src/logout/cascadeLogout.mts` | RP-initiated logout is answering `503` because a session store could not be read or marked (`left` says what that left: `unchanged`, `half_ended`, `unknown`) or the cascade stopped (`store: "logout_cascade"`, `cascadeStep`); the warn lines name each operation that failed. A listing that failed after the ended mark (`left: "half_ended"`), a mark whose outcome is `unknown`, or a cascade that stopped after step 1 may leave the session half-ended: it still exists, but the family index has marked it ended, so its code exchanges are refused (`session_invalidated`) until a retry of the logout completes or the mark lapses at the session's `expiresAt` plus five minutes (fail-closed) |
| `authorization_grant_store_unavailable` (error) by `store` and `step` | `oauth/src/grants/authorization.mts` | code exchanges are answering `503` because the code store, the family store or a session-linking store cannot answer; a session store's outage at a code exchange or the session grant is `session_admission_unavailable` |
| `authorization_grant_refused_family_revocation_failed` (error — `sid`, `clientId`, `familyId`, the error's projection) | `oauth/src/grants/authorization.mts` | a code exchange a logout ended mid-issue was refused (`400 invalid_grant` / `session_invalidated`), and the family store could not revoke the family it had registered. No token of that family was served, so nothing is exposed and the answer stands; the family store is failing, so read its other lines |
| `grant_policy_unavailable` (error) | `core/src/grants/grantPolicy.mts` (every grant through `evaluateGrantPolicy`, webauthn's included), `oauth-token-exchange/src/grant.mts`, `oauth/src/routes/authorize.mts` | the `grantPolicy` hook threw: every grant it gates is answering `503`, and `/authorize` redirects `temporarily_unavailable` |
| `grant_policy_decision_invalid` (error — `grantType`, the policy's `kind`, `site` at `/authorize`) | `core/src/grants/grantPolicy.mts` (`readGrantPolicyDecision`, which every grant through `evaluateGrantPolicy`, token exchange and `/authorize` read the decision with) | the `grantPolicy` hook returned a decision whose `outcome` is neither exactly `"allow"` nor exactly `"deny"`, or a field of which throws when read: every request it decides so is answered `500 server_error`, and `/authorize` redirects `server_error`. A fault in the policy, not an outage — fix the policy. The line never carries the decision |
| `jwks_unavailable` (error) | `core/src/jwks/router.mts` | the JWKS endpoint is answering `503`: the keystore returned no publishable key (`keys: 0`), or could not answer at all (the error's projection) — relying parties cannot fetch a key to verify with |
| `userinfo_store_unavailable`, `introspect_store_unavailable` (error) | `oauth/src/routes/userinfo.mts`, `oauth/src/routes/introspectUnavailable.mts` | userinfo or introspection is answering `503` because the refresh-token family store (`store: "refresh_token_family"`) or the session store (`store: "user_session"`) is unreachable |
| `token_exchange_family_store_unavailable` (error) | `oauth-token-exchange/src/grant.mts` | token exchanges are answering `503` because the refresh-token family store is unreachable (`store: "refresh_token_family"`); `role` says whether the `subject_token`'s or the `actor_token`'s family could not be read |
| `token_exchange_session_store_unavailable` (error) | `oauth-token-exchange/src/grant.mts` | token exchanges of session-bound tokens are answering `503` because the user-session store is unreachable; `role` says whether the `subject_token`'s or the `actor_token`'s session could not be read |
| `revoke_all_for_subject_incomplete`, `revoke_all_watermark_failed`, `revoke_all_list_sids_failed`, `revoke_all_cascade_failed`, `revoke_all_remove_sid_failed` (error) | `core/src/user-sessions/revokeAllForSubject.mts` | a credential change did **not** fully invalidate what was issued. `incomplete` means a store was not wired (composition gap); the others mean a wired store threw (outage — retry) |
| `session_middleware_store_unavailable` (error) by `step` | `session/src/internal/cookieSession.mts` | the cookie-session store (connect-redis) cannot answer express-session: `step: "load"` — requests carrying a session cookie are answered `503` before any route runs, so every browser session is unusable while it lasts; `step: "save"` — a route answered, but the session it changed (or its refreshed expiry) was not written, so the browser's next request sees the session as it was. The same Redis as `session_store_redis_error`. Replaces `unhandled_request_error` 500s and stack traces on stderr |
| `login_store_unavailable`, `session_logout_store_unavailable` (error) by `store` and `step` | `session/src/routes/Session.mts` | password logins (`store`: `user_repository`, `user_session`, `cookie_session`; or an interrupting session requirement's name with `step: "open"` — it could not open its ceremony, its own store's outage) or browser logouts (`cookie_session`, `step: "destroy"`) are answering `503` because a store cannot answer. `login_cleanup_failed` (warn) is a rollback step after a failed regeneration or save that failed too: an orphan `UserSession` or subject-index entry, bounded by its TTL. Replaces the warn `local login authenticate failed` |
| `federation_start_store_unavailable`, `federation_callback_store_unavailable`, `federation_link_store_unavailable` (error) by `store` and `step` | `session/src/routes/FederationLog.mts`, from the start (`FederationStart.mts`), the callback (`FederationCallbackState.mts`, `FederationCallbackIdentity.mts`, the login in `Federation.mts`) and the link (`FederationLinkCallback.mts`) | federated logins, or `?link=1` links, are answering `503` because a store cannot answer — the cookie session or a `form_post` transaction, the user directory, the `UserSession`, the federation index or the federation token store (a link's read of its session is `session_admission_unavailable`). `federation_cleanup_failed` (warn) is a rollback or discard step that failed too, by `store`. Replaces the warns `user repository lookup failed`, `userSession create failed`, `sessionFederationIndex.addFederation failed`, `federation transaction lookup failed` / `delete failed` / `save failed`, `reuse-prevention session save failed`, `federation start session save failed`, `federation link: …`, and the errors `session regeneration failed after userSessionStore.create`, `session post-create failed` |
| `federation_misconfigured` (error) by `reason` | `session/src/routes/FederationLog.mts`, from `FederationStart.mts`, `FederationCallbackIdentity.mts` and `FederationRedirectAnswer.mts` (the start's and the callbacks' `no_redirect_policy`) | a federation start or callback is answering `500` for a composition fault: no express-session store mounted on a `form_post` federation's requests (`no_session_store`), a callback URL with no path to scope its transaction cookie to (`no_callback_path`), a provider with no callback URL (`no_callback_url`) or no redirect policy (`no_redirect_policy`). Fix the composition; a retry cannot. The `form_post` case replaces a sentence-long message; the others were not logged |
| `webauthn_session_subject_invalid` (error — `reason`: `threw` with `err`, or `shape`) | `webauthn/src/sessionSubject.mts` | the `subjectFor` given to `webauthnSessionSubjectModule` threw, answered a subject whose fields throw when read (`threw`), or answered something that is not a WebAuthn subject (`shape`: an object with a non-empty string `userId`, and string `userName` / `userDisplayName` when present — synchronously, not a Promise) for an admitted session, so passkey registration answers `500 server_error`. The line never carries the answer. Fix the mapper |
| `webauthn_subject_user_handle_invalid` (error) by `site` | `webauthn/src/routes/registrationOptions.mts`, `registrationVerify.mts` | the `subjectFor` given to `webauthnSessionSubjectModule` — or the deployment's own middleware that sets `req.webauthnSubject` — hands the registration routes a `userId` outside WebAuthn's 1–64-byte user handle, and they answer `500 server_error`: the line carries the `byteLength`, never the value. Map the account to an opaque handle (see the webauthn README) |
| `webauthn_grant_store_unavailable`, `webauthn_ceremony_store_unavailable` (error) by `store`, `step` and `site` | `webauthn/src/grant.mts`, `webauthn/src/internal/storeUnavailable.mts` | passkey sign-ins at `/oauth/token`, or the ceremony routes, are answering `503` because the credential store, the challenge store or ceremony, or the refresh-token family store cannot answer. These used to be `unhandled_request_error` 500s, or (the family) nothing |
| `subject_session_index_write_failed` (error) | `session/src/routes/Session.mts`, `Federation.mts` | a login succeeded that a later credential-change cascade will not find |
| `logout_user_session_delete_failed` (error) | `session/src/routes/Session.mts` | **alert on this.** `POST /session/logout` destroyed the cookie but could not delete the `UserSession` record, so an access token minted by the `session` grant keeps introspecting `active: true` until it expires. The user is out of the browser; the token is not. Same store outage the introspection liveness check fails closed on, so the exposure is bounded by whether the store recovers |
| `logout_user_session_read_failed` (error — `sid`, the error's projection) | `session/src/routes/Session.mts` | `POST /session/logout` could not read the `UserSession` record to tell whether the cookie is a copy the record was renewed away from (the MFA ADR's D27). The logout goes on and invalidates the record as it would anyway, so a stale copy's logout during the outage ends the renewed session too. Same store outage as the rows around it |
| `logout_subject_session_index_remove_failed`, `logout_federation_token_remove_failed`, `logout_session_federation_index_remove_failed` (error) | `session/src/routes/Session.mts` | a logout left bookkeeping behind. Lower severity than the row above: the `UserSession` record is already gone, so the orphans are unreachable and bounded by TTL — but upstream-IdP tokens stay at rest for that window |
| audit `introspect.store_unavailable`, `logout.cascade_failed` | `oauth/src/routes/introspectUnavailable.mts`, `oauth/src/routes/logout.mts` | introspection is answering `503` for an outage — the keystore, a revocation store, the family store or the session store (`details` names which); a logout left state behind: `logout.cascade_failed` carries the `sid` and the cascade's `step` — `1` for the logout's first step, the ended mark and the listings, with the `store` and what it `left` (`half_ended` or `unknown`; a begin that left the session unchanged is not audited) |
| `token_binding_unavailable` / `protected_resource_binding_unavailable` (error) with `mechanism: "mtls"`, `reason: "revocation_unavailable"`, sustained | `core/src/middleware/*.mts`, `mtls/src/fullPki/validate.mts` | your CRL distribution point or OCSP responder is down (or answering unusably) under `onUnavailable = "reject"`, and mTLS clients get `503` — the line's `err.aggregateErrors[].detail` names each source, its URL and the certificate it was asked about, for every certificate on the path, so every source down shows at once; past five the rest are counted in `err.aggregateErrorsOmitted`. Some of these clear on their own (a refused connection, a timeout, a 5xx, `tryLater`); others need you — a 404 or 410 (the CA moved or dropped its list), an answer larger than `maxResponseBytes`, a redirect (never followed), the wrong media type (a proxy or portal in the path), a responder answering `malformedRequest`, `sigRequired` or `unauthorized`. None is the client's doing. It was `mtls_revocation_unavailable_rejected` (warn) and a `400` |
| `mtls_revocation_unavailable_rejected` (warn), sustained | `mtls/src/fullPki/validate.mts` | certificates are refused because their revocation cannot be checked for a reason of their own — no or an unsupported distribution point, a URL outside `allowedHosts`, a CRL signed outside the algorithm policy: a CA or `allowedHosts` configuration to fix, not an outage |
| `mtls_revocation_unavailable_allowed` (warn), **any**, if you chose `allow` | same | each line is a certificate the mechanism accepted (its whole path passed) without a revocation check — the request can still be refused afterwards; a steady rate means the PKI is effectively unrevocable |
| `mtls_ocsp_responder_unchecked` (warn, once per responder) | `mtls/src/fullPki/validate.mts` | a delegated OCSP responder carries no `id-pkix-ocsp-nocheck` and nothing can check its own revocation — under `mode = "ocsp"`, or under `"both"` when its certificate names no CRL. Its answers are trusted for the responder certificate's whole lifetime. The fix depends on the mode: under `"ocsp"` no CRL is ever fetched, so only `nocheck` on the responder certificate clears it; under `"both"`, `nocheck` or a CRL named on the responder certificate does |
| `jwt_bearer_assertion_verifier_unavailable`, `jwt_bearer_user_repository_unavailable` (error) | `oauth/src/grants/jwtBearer.mts` | the attestation service or the Store is down (`503` to devices) |
| `jwt_bearer_policy_audience_refused` (warn) | `oauth/src/grants/jwtBearer.mts` | your `grantPolicy` returned an audience outside the client's `allowedAudiences`, or one with no authenticated client to supply that ceiling. Devices get `500 server_error`; the policy, not the device, is what to fix (#520, #521) |
| `token_error_code_malformed`, `authorize_policy_deny_error_malformed`, `token_exchange_policy_deny_error_malformed` (warn) | `oauth/src/routes/token.mts`, `oauth/src/routes/authorize.mts`, `oauth-token-exchange/src/grant.mts` | a grant, or your `grantPolicy`'s deny, returned an `error` code outside RFC 6749's `1*NQSCHAR` (empty, or carrying `"`, `\`, a control or non-ASCII character). Clients get `invalid_request` from `/oauth/token` and `access_denied` from `/oauth/authorize` instead; the logged `error` is the code, sanitised and capped at 200 characters. Fix the code |
| `error_envelope_code_malformed`, `error_envelope_uri_malformed` (warn, through the console logger) | `core/src/errors/envelope.mts` | a module handed core's `errorEnvelope` an `error` code outside RFC 6749's `1*NQSCHAR` (empty, or carrying `"`, `\`, a control or non-ASCII character), or an `error_uri` that is neither an `http(s)` URI nor a relative reference RFC 3986's grammar parses, or that carries a userinfo (`user@`). The client got `server_error` with the status the module chose, or the answer without `error_uri`; the logged value is sanitised and capped at 200 characters. Nothing in this repository sends either, so the module is a contributed one or a custom composition's: fix what it answers with |
| `redirect_policy_server_fault` (error) | `session/src/internal/refusalEnvelope.mts` | a federation redirect policy answered a `5xx`, relayed to the browser as the policy worded it: the default policy's `500 misconfiguration` when a callback needs `authCallbackUrl` (the start carried a `redirect_to`) or `clientUrl` (it did not) and the federation has none — set the one the line's `errorDescription` names — or a contributed policy's own failure. With `status`, the policy's `error` and `errorDescription` (sanitised, capped at 200 characters), and `provider` at the start leg. Was not logged |
| `redirect_policy_error_malformed` (warn) | `session/src/internal/refusalEnvelope.mts` | a federation redirect policy refused a `redirect_to` with a 4xx and an `error` code outside RFC 6749's `1*NQSCHAR`. The client got `invalid_request` with the policy's status and description; the logged `error` is the code, sanitised and capped. Fix the code your contributed policy answers with |
| `token_exchange_policy_scope_refused`, `token_exchange_policy_audience_refused` (warn) | `oauth-token-exchange/src/grant.mts` | your `grantPolicy` returned, for a token exchange, a scope outside the subject token's scope and the client's `allowedScopes`, or an audience outside the subject token's audience and the client's `allowedAudiences`. Clients get `500 server_error`; the policy, not the client, is what to fix. A client asking for such an audience itself is `400 invalid_target`, logged as `token_exchange_audience_widening_rejected` |
| `jwt_bearer_issuer_audience_mismatch` (warn) | `oauth/src/grants/jwtBearer.mts` | the presenting client's `allowedAudiences` and the assertion issuer's `allowedAudiences` (its trust-registry entry) admit no audience in common, so no token could name one both stand behind. Devices get `invalid_grant`; compare the two registrations (#525) |
| `cimd_document_rejected`, `cimd_document_fetch_failed`, `cimd_host_not_allowed` (warn) | `oauth/src/clients/clientIdMetadataDocument.mts` | a Client ID Metadata Document client (#529) was refused: the reason names what failed (a redirect, a byte cap, a special-use address, a document that does not match its URL). The client sees `invalid_client`; a steady rate from one host is a misconfigured client or a probe |
| `revoke_store_unavailable` (error) | `oauth/src/routes/revoke.mts` | `/oauth/revoke` is answering `503`: a client's revocation was not recorded, so the token it asked to end is still valid until it expires. `store` says whether the access-token denylist or the refresh-token family store failed, and `clientId` whose revocation was lost. A client that ignores the `503` keeps a live token it believes revoked — retries succeed once the store is back |
| `token_binding_unavailable`, `protected_resource_binding_unavailable` (error) by `mechanism` and `reason` | `core/src/middleware/tokenBinding.mts`, `protectedResourceBinding.mts` | a token-binding mechanism could not reach a verdict, and requests at `/oauth/token` (`token_binding_unavailable`) or at protected resources (`protected_resource_binding_unavailable`) are answering `503 temporarily_unavailable`. The dispatcher that answers owns the one line, with the mechanism's `reason` and its `cause`'s projection when it gives them. For DPoP: `reason: "replay_store_unavailable"` = the seen-set is unreachable, or refused the write (a Redis at `maxmemory` under `noeviction`); `reason: "replay_store_full"` = core's in-process set holds DPoP's share of its cap (`err.name: "ReplaySeenSetFullError"`, `err.reason: "full"`; see Sizing) — a flood of fresh proofs, or a cap too small for the traffic; `reason: "replay_store_fault"` = it answered with its own contract error (a `RangeError` or `expired-at-issue`) — a broken or hand-built seen-set, whose fix is in the composition, not in Redis. These replace DPoP's own `dpop_replay_store_unavailable` / `dpop_replay_store_fault` lines and the dispatchers' former warn lines |
| `shutdown_drain_deadline_exceeded`, `shutdown_cleanup_failed`, `shutdown_cleanup_timed_out`, `shutdown_server_close_failed` (error) + non-zero exit — formerly `graceful shutdown: drain deadline exceeded, closing remaining connections`, `…: cleanup failed`, `…: cleanup timed out`, `…: server close failed`; the drain starts with `shutdown_draining` (info, `drainTimeoutMs`, and `cleanupTimeoutMs`, the cleanup budget this shutdown will allow) and ends with `shutdown_complete` (info, `reason`, `drain`, `exitCode`) | `templates/standalone/src/shutdown.mts` | a replica did not drain within `drainTimeoutMs` (default 10 s), its cleanup did not finish within the allowance (45 s or more with federation grants on — a rotated upstream credential may be unwritten), or it could not release its connections |
| `adapter_lifecycle_cleanup_failed` (error) with `phase`, `cleanupIndex` and `err` | `core/src/adapters/AdapterFactory.mts` | an adapter's own cleanup — typically the close of a connection its builder opened — threw while `handle.dispose()` drained them (`phase: "dispose"`) or while a failed boot did (`phase: "boot_failure"`). One line per failed cleanup, through the deployment's logger — the `logger` component at dispose, the logger the composition root handed in (bootstrap or override) when boot failed; the standalone passes one — and to stderr only when there is none; the drain goes on to the rest, even when the logger itself throws. A dispose then rejects, which the standalone reports as `graceful shutdown: cleanup failed`; a failed boot rethrows the error that failed it (a `BootError` for every refusal) |

### Investigate — security signals worth a dashboard and a threshold

| Event | Where | Meaning |
| --- | --- | --- |
| `session_admission_subject_mismatch` (warn — `action`) + audit `session.admission.subject_mismatch` (`sid`, `carrier`, `claimedSubject`, `recordSubject`) | `core/src/session-admission/live-session.mts` | a claim named a subject that is not the live record's — a cookie, a link transaction, a token or a code's second read against a session the record says belongs to someone else. Answered `not_live`; the identifiers are in the audit event alone. Sustained, with `carrier: "cookie"`, a login of the deployment's own writes the cookie session's `user.id` and `sid` from different sources: the cookie and the store disagree about who is signed in |
| `login_claim_dropped` (warn — `claim`, the custom claim's key; `reason: "unserialisable"`; never the value) | `core/src/session-admission/login-claims.mts`, said by `admitPrimary` and `resumePrimary` (`core/src/session-admission/admit.mts`) and by `establishWithoutAsking` when it is handed a logger | a login's claims envelope held a custom claim whose JSON form could not be taken — a bigint, a cycle, a `toJSON` or a getter that threw — so the claim was left out of the session and the login went on; ID tokens and userinfo do not carry it. Find what put it in the envelope and have it answer JSON data: the bundled password route puts only declared claims there, so with the bundled routes it is `federated` — the IdP adapter's `mapClaims` answer, recorded under `claims.federated` — or a route of your own. Declared claims (`email`, `emailVerified`, `name`, `picture`, `groups`) are never dropped: one of the wrong type refuses the login |
| `session_admission_no_subject` (warn — `action`) | `core/src/session-admission/live-session.mts` | a cookie session says it is authenticated and names no user: not a session this provider wrote. Answered `not_live`, nothing read, nothing audited |
| `mfa_enrollment_witness_unwritten` (warn — `sub`, the error's projection) | `mfa/src/routes.mts` | the Store could not write the enrollment witness after a counting factor was bound or verified — or, for a verification's mark, the subject's lease stood in the way past its wait (busy), a recovery or a reset moved the subject's generation since the proof was checked (changed), the mark ran past its lease (overrun), the transaction store could not give the lease (outage), or the records could not be read before the mark: the login completed, and the next verification of a counting factor where the login's `User` does not say it enrolled — at a login, or a step-up — marks it again. Sustained, the Store's endpoint at `REPOSITORIES_USER_HTTP_MARK_MFA_ENROLLED_URL` is failing, and a lost factor store would read those accounts as never enrolled |
| `mfa_subject_lease_overrun` (error — `route`, `sub`; no `route` from the operator reset) | `mfa/src/management.mts`, `mfa/src/routes.mts` (`route: "enrollment"`, a binding), `mfa/src/recoveryCodes.mts` (`route: "recovery-codes"`), `mfa/src/reset.mts` (the reset) | a removal from the account page (`route: "factors"`), a binding (`route: "enrollment"`), a regeneration of recovery codes (`route: "recovery-codes"`; codes it marked shown are still answered) or the operator reset (no `route`) ran past the subject's lease — sixteen `mfa.storeTimeoutMs`, 80 s by default — or its release found another holder, or it ran out of the lease's time after it wrote (the witness then not cleared). Said whatever the removal answered: a removal it made stands, is audited and is answered `409 mfa_factors_changed`; a `400` or a `503` is answered as itself. A recovery or a reset may have run beside it: check the subject's factors and the Store's witness. Sustained, a store is slower than `mfa.storeTimeoutMs`, which must be at least every store's own per-call timeout |
| `mfa_factor_removal_unread` (warn — `sub`, the error's projection) | `mfa/src/management.mts` | after a removal from the account page the factor store could not answer a read of the subject's records: the records read before the removal, less the removed one, decided whether to clear the enrollment witness. The removal stands. Sustained, the factor store is failing |
| `mfa_enrollment_witness_uncleared` (warn — `sub`, the error's projection) | `mfa/src/management.mts` | a removal from the account page left the subject no factor record that may count, and the Store could not clear the enrollment witness (`markMfaEnrolled(subject, false)`): the removal stands, and the witness still says enrolled beside no counting record, so the subject's next password login is `503` with `mfa.enrollment_state_inconsistent`. Clear the flag in the Store for that subject; sustained, the endpoint at `REPOSITORIES_USER_HTTP_MARK_MFA_ENROLLED_URL` is failing |
| `mfa_transaction_evict_failed` (warn — the error's projection) | `redis/src/mfa-transaction-store.mts` | a create past its session's cap of five MFA transactions (`MFA_MAX_TRANSACTIONS_PER_BINDING`) could not end the session's oldest (`LUA_MFA_TX_EVICT`): the new transaction stands and the create answers; the one not ended stays, one past the cap, until it expires. Sustained, the Redis behind `mfaTransactionStoreClient` is failing |
| `mfa_transaction_unindex_failed` (warn — `operation`: `consume` or `reserveAttempt`, the error's projection) | `redis/src/mfa-transaction-store.mts` | a consumed transaction, or one ended by its attempts, could not be taken out of its session's `mfat:binding:` index: the operation answered as usual, and the member counts toward the session's cap until it is taken out: while the session's live ceremonies expire sooner, a later create ends one of them first, so a live ceremony may end early; once the gone transaction's expiry has passed, its member goes first. Sustained, the Redis is failing |
| `mfa_first_binding_unnoted` (warn — `sub`, `store`, `step: "noteFirstBinding"`, the error's projection) | `mfa/src/routes.mts` | a verification of a counting factor, for a login whose `User` does not say it enrolled, could not note the subject's first-binding mark in the MFA transaction store, so it left the enrollment witness unmarked: a witness marked without the mark would leave the sessions signed in before it trusted. The login completed, and the next such verification notes the mark and marks the witness. Sustained, the transaction store is failing or full (a memory store at its cap: `MfaTransactionStoreFullError` in the error's projection) |
| `mfa_login_revoked` (info — `sub`, `route`) | `mfa/src/routes.mts` | a call on a login's MFA transaction whose sign-in is at or before the subject's sessions boundary (a revocation or a password change since the login began): answered `401 login_required`, nothing spent. Expected after a password change; a burst for one subject is someone holding an old login open |
| `mfa_first_binding_distrusted` (info — `sub`, and `route`, or `action` from a session's admission) | `mfa/src/routes.mts`, `mfa/src/requirement.mts`, `mfa/src/recoveryCodes.mts` (`route: "recovery-codes"`) | a first binding — or a regeneration of recovery codes — refused by the subject's first-binding mark: its sign-in is no later than a mark noted within `DEFAULT_CLOCK_SKEW_MS` before it (the re-login wait, under "The first binding"). A regeneration checks it so that a session admitted on a recent primary while no factor stood cannot get codes once the owner binds one. A regeneration's distrust is widened by one factor-set lease past the skew (the owner's factor may land up to a lease after its mark), and every mark distrusts the same way, so a regeneration is also refused, until the sign-in is later than the mark plus 5 minutes and a lease (6 minutes 20 seconds by default), for: the session that bound the first factor (it got codes then); one whose login reconciled the witness; one signed in before a binding that stepped up after it; and a fresh MFA login on another device within the skew. A step-up in a session whose witness is not `enrolled` notes the mark again, arming it again. A regeneration that reached its lease longer after it began than the mark's lifetime less the skew and a lease is `409 mfa_request_stale`. The user signs in again after the `Retry-After`; repeated for one subject, its factors vanish right after binding — look for `mfa_store_unavailable` around the mark |
| audit `mfa.first_binding_conflict` (`subject`, `details.kind`, `details.removed`) | `mfa/src/routes.mts` | two first bindings of one subject — at a login or from a signed-in session — stood at once, and this one dropped its own: both may, each answered — at a login `401 login_required`, from a signed-in session `409 mfa_enrollment_conflict`, the session standing — or `503` when it could not remove its factor. Once is a user with two tabs; a run for one `subject` is whoever holds that user's password racing the owner's first binding. It gains no way in, but it hinders the owner's: the remedy is a password change, which is the Store's. **`removed: false`** means the factor could not be removed after three tries, so a factor of a third party who holds the password may still stand. Pick it up through the notice wiring (the audit event to an operator — see "Notices to the account holder" under the MFA section), then remove the subject's factors, or set D25's flag and reset them (the operator reset, `resetMfaForSubject` with `requireEmailProof: true`). The same factor is logged `mfa_first_binding_factor_standing` |
| `mfa_email_proof_unprovable` (warn — `sub`, `reason`: `no_sender`, `no_address` or `unreadable_address`; per such login, per admission of a first binding in a session, and per login reopened for a first binding after a recovery code) | `mfa/src/requirement.mts`, `mfa/src/routes.mts` | a first binding asks the account-email proof and nobody can give it — no mail sender (`always`, or D25's flag), an account without an address (`always`, or the flag), or one whose address the provider cannot read (any of those, or `when-mail` with a sender; see the spellings refused on purpose, under "The email factor's address"): the user cannot bind — a factor, a passkey or a linked identity — and cannot sign in under `required`. Fix the account's address in the Store, or wire a mail sender |
| `mfa_mail_refused_at_limit` (warn — `route`, `purpose`, `kind`, `cleared`) | `mfa/src/routes.mts` | the mail sender refused a code at its limit, and the user was answered `429`. A run for one account, or overall, is the limit working — or a user resending — and the sender's to tune |
| audit `mfa.locked` (`details.kind`, `purpose`, `hold`) and `mfa.locked.first` (with `binding`) | `mfa/src/routes.mts` | a guessable second factor was held by the subject lock (`429 mfa_locked`): someone holding the account's password is guessing its second factor, or the user mistyped often. `mfa.locked.first` is the first refusal of an episode — notify the account holder of it (the MFA ADR's D24). Tell them to sign in with a recovery code or a passkey, and to change the password. That locks out whoever holds it, but does not end the hold (D21): a backoff or the week ends on its own time, or at the user's release after the password change and a recovery code or a passkey; the hard hold at the user's release once every guessable factor is replaced, or at the operator reset (`resetMfaForSubject`). `hold: "hard"` is `mfa.lockout.hardLimit` failures in a row. Many subjects at once is a credential-stuffing run that got past the passwords |
| audit `mfa.lock.recovered` (`details.operation: "recover"`, `generation`, `cleared`), `mfa_lock_released` and `mfa_lock_release_held` (info — `sub`, `generation`, `applied`; `hold` on the second) | `mfa/src/lockRelease.mts` | the user released their own lock after a recovery code or a passkey: `cleared.week` and `cleared.run` the attempts given back, `cleared.hard` the hard hold lifted on a rebind. Notify the account holder: a release they did not make means someone holds their password and an exempt factor. `mfa_lock_release_held` means the hard hold still stands — the user has not yet replaced every TOTP or email factor, or a factor of a kind no longer installed still stands from before the hold: remove it from the account page |
| `mfa_lock_release_refused` (info — `sub`, `reason`) | `mfa/src/lockRelease.mts` | a release refused: `exempt_proof_required` (no recovery code or passkey verified in that session within `mfa.manage.maxAgeSeconds`), `not_revoked_since` (no revocation of the subject's sessions more than five minutes after the attack's first failure — have the user change the password again), `no_revocation_boundary` (no `subjectRevocation` wired: only time or the operator reset gives the week back) |
| `mfa_lock_recovery_unauthorized` (warn — `route`, `sub`, the error's projection) | `mfa/src/routes.mts` | a recovery code or a passkey verified, and the transaction store did not record the authorization a release takes: the login or step-up stood, and that session's release is `403`. Repair the transaction store (the MFA stores' outage row); the user verifies again |
| `mfa_lock_release_unavailable` (warn — `slot: "subjectRevocation"`, once at boot) | `mfa/src/module.mts` | no subjects' sessions boundary is wired, so no release can show a revocation came after an attack: a user's release lifts the hard hold on a rebind but never gives the week or a backoff back early. Wire `subjectRevocation`, and have the Store call `revokeAllForSubject` on every password change |
| audit `mfa.reset` (`details.by: "operator"`, `kinds`, `count`, `requireEmailProof`, `sessions`, `sessionsAgain`, `complete`, `requestedBy`), `mfa_reset` (info) and `mfa_reset_incomplete` (warn — `sub`, `stoppedAt`, the error's projection) | `mfa/src/reset.mts` | an operator reset ran (see "The operator reset" under "Multi-factor authentication"). Notify the account holder from `mfa.reset`. `complete: false` / `mfa_reset_incomplete`: it stopped at `stoppedAt` — `sessions`, a revocation not complete, the first or the one after the removal (the sessions' reports say which store); `lease`, another write held the subject's factors past its wait, the transaction store could not give the lease, or too little of it was left before the first write; `email_proof`, D25's flag could not be set (unanswered within `mfa.storeTimeoutMs`, or failed); `lock`, its authorization or the lock state's reset could not be written; `factors`, the removal failed or records still stood after it; `witness`, the directory refused `markMfaEnrolled` — fix it and run the reset again. `overran` alone: its lease ended before it released it — run it again |
| `mfa_subject_lock_unsettled` (warn — `sub`, `kind`, `step`: `settleSubjectAttempt` or `noteExemptSuccess`, `outcome`, the error's projection) | `mfa/src/module.mts` (the lock in `mfa/src/lock.mts`) | the transaction store did not take how a second-factor attempt ended: the answer stood, and the attempt still counts as a failure — or an exempt proof did not end the run. Each one is a counted failure, the user's own successes included: a run of them holds healthy users after `mfa.lockout.threshold` logins, and the week after `weeklyBudget`. **Alert on its rate**, not on single lines. Remedy: repair the transaction store (see the MFA stores' outage row); then lift the holds it caused with the operator reset under "Multi-factor authentication" (each `sub` named), or let each user release theirs |
| `mfa_email_proof_flag_uncleared` (warn — `sub`, the error's projection) | `mfa/src/routes.mts` | a first binding given with the account-email proof could not clear the operator reset's flag (`requireEmailProof`): the binding stands, and the flag asks for the proof at that subject's next first binding too |
| audit `device.rate_limited`; log `device_verification_rate_limited` (warn) | `device-grant/src/verificationEndpoint.mts` | an **account** (the key is the authenticated subject) is guessing device codes |
| audit `device.decision_outcome_unknown` | `device-grant/src/verificationEndpoint.mts` | an approval or a denial met a device-code store outage and was answered `503`, but the store may have recorded it before the reply was lost. It carries the subject who decided and the `action`, but no client: the record could not be read. Read beside `device_verification_store_unavailable`: a device polling afterwards may have received tokens that no `device.approved` accounts for |
| audit `mfa.verify.failure` with `kind: "webauthn"`, `reason: "sign_count_regression"` and `factorId` — the clone event | `mfa/src/routes.mts`, the refusal the WebAuthn factor answers (`webauthn/src/mfaFactor/factor.mts`) | a WebAuthn second factor's assertion whose signature verified — made with the credential's private key — carried a counter that did not increase over the one stored: the authenticator may have been cloned, or two copies of one credential are in use (WebAuthn §6.1.1). An assertion whose signature does not verify is `invalid`, never this, so the event cannot be raised with the password alone. The assertion was refused and nothing was written. An authenticator that keeps no counter (`0` on both sides) never raises it, and neither does a lost compare-and-set, which is read again. Two verifications with one authenticator at once can raise it too — the earlier assertion checked after the later one's count was written — so a single event beside another `mfa.verified` of the same `subject` within seconds is most likely that. `details.factorId` is the record id of the factor whose credential asserted — the one a clone would be of, which is not always the one the page asked for, since an assertion may answer with any of the subject's WebAuthn factors; it is an opaque id, never a credential id, key or handle. Reach the user out of band, and confirm with them which authenticator that record is — by its label (until the account page exists, the plaintext `label` on its record in the MFA factor store), or by which of their authenticators they still hold — before that enrollment is removed |
| `mfa_refusal_factor_id_dropped` (warn — `kind`; per such refusal) | `mfa/src/routes.mts` | a second factor of `kind` refused a proof naming, as the factor it concerns, an id that is none of the subject's factors of that kind — a factor answering outside core's `MfaVerification` contract. The refusal stands and is audited without `factorId`; the value named is never logged. For `webauthn`, the clone event then names no factor: confirm with the user which of their authenticators it is before any enrollment is removed, and report the defect to the factor's author |
| `jwt_verify_rejected` (warn) by `reason` | `core/src/jwt/verify.mts` | `kid_unknown` = a fabricated key id; `kid_expired` = a token signed with a key whose overlap window closed (see [§6](#6-key-rotation)); `revoked` = a revocation finding, or a fail-closed refusal when the watermark cannot be compared: a denylist hit, a token predating the subject's watermark, or a token with no `iat` while a watermark is in force (#376); `revocation_unavailable` = the denylist or the watermark store was unreachable — an outage, not a finding (#408 / #459); `verification_key_unavailable` = the keystore could not answer the lookup — an outage, answered `503`, never reported as `kid_unknown`; `signature` / `alg` / `iss` / `aud` / `typ` = malformed or foreign tokens |
| `jwt_bearer_assertion_expired` (info) | `oauth/src/grants/jwtBearer.mts` | a jwt-bearer assertion verified but had no whole second of lifetime left when its token would have been minted — past its `exp` inside the issuer entry's `clockToleranceSeconds` (default 60), or run out while the Store answered. Devices get `invalid_grant`. The issued access token **never outlives the assertion**: `expires_in` is `min(oauth.accessToken.defaultExpiresIn, exp − now)`, so a short-lived assertion gives a short-lived token — an ID-JAG's `iat` is at most an hour old and it often lives minutes — and, with no refresh token issued, the client re-exchanges a fresh assertion. A steady rate from one `issuer` is that issuer's clock running behind this server's, or clients presenting assertions at the last moment (auth.proxy#90) |
| `auth_time_ahead_of_clock` (warn — `sid`, `clientId`, `aheadMs`) | `oauth/src/grants/authorization.mts`, `oauth/src/grants/session.mts`, `device-grant/src/verificationEndpoint.mts`, `device-grant/src/grant.mts` | the `authorization_code` exchange or the `session` grant refused a session whose `authTime` is more than `DEFAULT_CLOCK_SKEW_MS` (5 minutes) ahead of this replica's clock (`aheadMs`), with `400 invalid_grant` `session_invalid` and nothing signed. Device verification refuses such a session's `approve` with `401 login_required` (`sid`, `aheadMs`) and decides nothing; the device-code poll refuses an approval whose recorded `authTimeMs` it cannot read with `400 invalid_grant` (`clientId`, and `aheadMs` for an instant), nothing signed, and the device starts again: one that far ahead means the approving replica's clock ran ahead of the polling replica's (fix the clock), while one before the epoch, not whole milliseconds or unreadable means a defect in a custom `DeviceCodeStore`, not a clock problem. The replica that signed the user in runs ahead: fix its clock (NTP). Until then the session keeps being refused; an RP that sends neither `prompt=login` nor `max_age` is not sent to log in |
| `subject_revocation_boundary_clamped` (warn — `store`, `subject`, `requestedBefore`, `recordedBefore`) | `core/src/user-sessions/memory/subjectRevocation.mts`, `redis/src/subjectRevocation.mts` | a revocation asked for a boundary later than the store's clock plus 5 minutes, and the store recorded that bound instead: the revoking replica's clock runs ahead of the store's. The revocation stands; tokens that replica minted just before it, past the recorded boundary, are not covered. Fix that replica's clock (NTP) |
| `csrf_origin_rejected`, `csrf_token_rejected` (warn) | `session/src/csrf.mts` | cross-site POSTs to login/logout/device verification, or a UI on an origin you forgot to list in `session.csrf.trustedOrigins` |
| `federation_grant_consent_csrf_refused` (warn) by `reason` (`foreign_origin`, `token_absent`, `token_invalid`, `unrecognized`), with `correlationId` and `origin` | `federation-grants/src/browserConsentAnswer.mts` | a federation-grant consent answer the deployment's CSRF policy refused (`403 invalid_request`). A cross-site post; or, when every answer is refused, the consent page is served with `Referrer-Policy: no-referrer` (`origin: "null"` — the standalone's `helmet()` sends it unless the page's route sets `same-origin`), or the proxy does not give the request the origin the browser addressed (`HTTP_TRUST_PROXY`, `X-Forwarded-Proto` / `X-Forwarded-Host`); `unrecognized` is a `csrfGuard` that answered outside its contract |
| `mtls_untrusted_proxy_rejected` (warn) | `mtls/src/extractor.mts` | a forwarded certificate header from a peer not in `trustedProxies` — a missing allowlist entry or a forgery attempt |
| `mtls_chain_validation_failed`, `mtls_full_pki_validation_failed` (warn) | `mtls/src/extractor.mts` | certificate refused; `step` says why (`certificate revoked`, `no path to trust anchor`, …) |
| `sender_constraint_rejected` (warn, `rejection` ∈ `compound_cnf`, `scheme_mismatch`, `proof_invalid`, `no_matching_binding`; `scheme`; `site: "protected_resource_binding"`) | `core/src/middleware/protectedResourceBinding.mts` | a protected resource refused a sender-constrained access token (`401 invalid_token`): a token with an ambiguous `cnf`, presented under the wrong scheme, with an invalid proof, or with no proof matching its binding — a stolen-token replay, or a client that does not present its proof. The field was `reason`; it is `rejection` so that it does not share a name with the verdict line's `reason` beside a `proof_invalid` |
| `token_binding_proof_invalid`, `protected_resource_binding_proof_invalid`, `dpop_signature_invalid`, `dpop_alg_not_allowed` | `core/src/middleware/*.mts`, `dpop/src/verifier.mts` | bad proof-of-possession material. The two dispatcher lines carry the `mechanism`, the `code`, the refusal's `reason` (mTLS: `malformed_header`, `cert_decode_failed`, `chain_validation_failed`, …; DPoP: its `DPoPReasonCode`) and the refusal's projection as `err`, whose `cause` is the parser's or library's error behind it. No refusal quotes a value the client wrote; `dpop_alg_not_allowed` names the refused `alg` only when it is a registered JWS algorithm, `unregistered` otherwise |
| `token_binding_ambiguous` (warn — `tier` ∈ `explicit-intent`, `ambient`; `mechanisms`, the kinds that succeeded) | `core/src/middleware/tokenBinding.mts` | under `core.tokenBinding.dispatchPolicy = "intent-explicit"`, more than one mechanism succeeded at the tier that decides — the explicit-intent ones when any did, else the ambient ones — on one `/oauth/token` request, which was answered `400 invalid_request` and bound to none. `ambient`: two transport signals arrived together — a mechanism installed beside mTLS fires on the same requests, and since a client does not choose an ambient signal, every such client is refused until the deployment stops presenting both; marking one of them explicit-intent is not the fix, since it would then win over mTLS on every request carrying both. `explicit-intent`: a client built two proofs on one request (an ambient success beside them is not named) — the client's doing |
| `introspect_non_access_token`, `introspect_compound_cnf_rejected` (warn) | `oauth/src/routes.mts`, `oauth/src/routes/introspectCaller.mts` | a refresh/id token presented as a bearer credential; a token with two bindings, which this server never mints |
| audit `authorize.rejected`, `token.issued.failure` (by `details.reason` — the route's own refusals carry a code such as `grant_type_not_allowed`; at `/authorize`, the grant policy's refusals carry `policy_denied` (with the redirect's code as `details.error`), `policy_out_of_bounds` (a decision past the client's ceiling) or `policy_decision_invalid`; a grant handler's carries its `error_description`, sanitised and capped at 200 characters, beside `details.error`; some descriptions quote what the client sent — a scope, an audience, a token type — so group those by the text before the quoted value, e.g. `scope '…' is not in subject_token scope`), `introspect.family_revoked`, `logout.family_revoked`, `federation.token.forbidden`, `federation.token.family_revoked` | `oauth/src/routes.mts`, `routes/token.mts`, `routes/authorizeAnswers.mts`, `routes/logout.mts`, `routes/federationToken.mts` | refusals and revocations; a spike in `token.issued.failure` with one `reason` is either an attack or a broken client |
| `http_request_duration_seconds{status="429"}` | `templates/standalone/src/metrics.mts` | rate limiting engaged; correlate with `HTTP_TRUST_PROXY` — one bucket for everyone is a misconfiguration that reads like an attack |
| `audit_sink_reentered` (warn — `type`, the event's type when it is a string) | `core/src/audit/factory.mts` | an event recorded while an `auditHooks` hook's `record` ran, in its async context: it reached the `auditSink` alone, or, without one, no sink — the line is then its only trace. Either a hook that emits (a loop the fan-out ended), or a hook that created a long-lived resource — a timer, a pool, a client — inside `record`, whose later work carries the hook's context, so its events skip every hook. Fix the hook: emit nothing from `record`, and create such resources at factory time |

### Configuration drift — emitted once, at boot or on first use

| Event | Where | What to do |
| --- | --- | --- |
| `mfa_enrollment_witness_unwritable` (warn — `slot: "userRepository"`; once at boot) | `mfa/src/module.mts` | the composition's directory has no `markMfaEnrolled` (core's `supportsMfaEnrollmentWitness`), so the MFA package cannot write the enrollment witness, and a lost factor store is caught only if the Store answers `mfaEnrolled` on `authenticate` and `authenticateByToken` by other means (the MFA ADR's D12). With foundation's user repository, set `REPOSITORIES_USER_HTTP_MARK_MFA_ENROLLED_URL` (`repositories.user.http.markMfaEnrolledUrl`) to the Store's witness endpoint; the line is then not said |
| `mfa_first_binding_without_email_proof` (warn — `setting: "mfa.enrollment.requireEmailProof"`, `value: "when-mail"`; once at boot) | `mfa/src/module.mts` | no mail sender is wired, so a first binding asks for no account-email proof: whoever holds a user's password before the user enrolls can bind the first factor (the MFA ADR's D24). Wire a mail sender; and notify account holders of `mfa.factor.enrolled` from the audit events (above), which is how a user learns of a binding they did not make — and whoever holds the password and one recovery code of a user whose counting factor is gone (a lost or retired authenticator, or recovery codes alone) binds the first factor at a login reopened after the code, unless the Store keeps the witness (D12). The owner keeps their remaining codes and signs in with them; the factor stands until the owner removes it (step 12) or you do. The trail: `mfa.recovery_code.used`, then `mfa.factor.enrolled {purpose: "login", binding: "password"}`, then `mfa.recovery_codes.generated {regenerated: true, binding: "password", kept: "password_binding"}`. The same holds under `mfa.enrollment.requireEmailProof = "never"` |
| `refresh_token_family_rotation_without_revocation` (warn — `slot: "refreshTokenFamilyRevocation"`, `grant: "authorization_code"`; once at boot) | `oauth/src/oauthAuthorization.mts` | the `authorization_code` grant registers families through a `refreshTokenFamilyRotation` and no `refreshTokenFamilyRevocation` is wired (a valid authorization_code-only composition): a code exchange refused because a logout ended its session leaves the family it registered active. No token of that family was served. Wire core's `defaultRefreshTokenFamilyRevocationModule` to have it revoked |
| `session_family_index_without_session_end` (warn — `slot: "sessionFamilyIndex"`, the index's `kind`; once at boot) | `oauth/src/oauthAuthorization.mts` | the `authorization_code` grant links families to sessions through an index without core's session-end capability (`supportsSessionEnd`), so a logout that runs while a code is exchanged can miss the family the exchange opens, and its tokens outlive the logout. Both bundled indexes have it, the Redis one over a client with `writeEndedMark` and `hasEndedMark` (`makeIoredisClients` has them); `redisSessionFamilyIndexBuilder` given a `keyPrefix` of its own needs an `endedKeyPrefix` too. Give a custom index `endSession` and `addFamilyIdUnlessEnded` |
| `session_admission_remediation_undeclared` (warn — `action`, the remediation's name; once per process per name) | `core/src/session-admission/requirement-verdict.mts` | a route presented a remediation core issued to a requirement this composition does not hold — one another boot registered; it was treated as `credential_change`, so every requirement was asked. Have the route take the remediation its own requirement was issued in this boot, `issuedRemediationActions(requirement)[route]`. A literal or a copy is refused with a `RangeError` rather than logged |
| `session_admission_step_up_without_page` (warn — `requirement`; once per process per name) | `core/src/session-admission/requirement-verdict.mts` | a requirement answered `step_up` while it registered no `stepUpPage`; taken as `unmet`. Register the page, or answer `unmet` |
| `session_admission_step_up_without_session` (warn — `requirement`; once per process per name) | `core/src/session-admission/requirement-verdict.mts` | a requirement answered `step_up` over no live session (no store, or a token without a record); taken as `reauthenticate`. A step-up needs a session to add to |
| `session_requirements_registered` (info — `requirements: [{ name, module, remediations, secondFactorAuthority }]`, once at boot) | `core/src/boot/apply-contributions.mts` | not drift: the one boot line saying which session requirements this composition registered, in order, and which one is the second-factor authority — the one that vouches for a second factor (`secondFactorAuthority: true`), whatever its name. Compare it with `core.sessionRequirements.expected` when a boot refuses `session-requirement-missing` or `session-requirements-undeclared` |
| `admission_actions_registered` (info — `actions: [{ name, grade, module }]`, once at boot when any action is registered) | `core/src/boot/apply-contributions.mts` | not drift: the one boot line saying which admission actions this composition registered, in order, each with its grade and the module that declared it. A grade is that module's own statement: an action graded `grants_nothing` is exempt from the MFA requirement's baseline — met on any live session a cookie, a code or a link carries, without a second factor; a token is still judged on its own `amr` — so check that every `grants_nothing` action is one you expect, from the module you expect (the bundled ones are `device.lookup` and `device.deny`, from `device-grant`) |
| `rate_limit_budgets_registered` (info — `limiter: { kind, failMode } \| null`, `budgets: [{ prefix, budget, module, by }]`, once at boot) | `core/src/boot/apply-contributions.mts` | not drift: the wired limiter and the outage policy the guard applies for it, and each prefix a module claims, with its contributed budget (`null`: the limiter's `limits` entry or its `defaultLimit` applies) and the module that set it, by `contribution` or `override`. A limiter's own `limits` entry for a prefix wins over the contributed budget and is not shown. An override may only tighten, and a budget's window is at most a year; either refused boots `contribute-factory-failed` |
| `rate_limit_fail_mode_not_applied` (warn — `configured`, `limiter`) | `core/src/boot/apply-contributions.mts` | `rateLimit.failMode` — the old path of `redis-rate-limiter.failMode`, which only the Redis limiter's module refuses — says `"open"` and the wired limiter applies another policy. Give the deployment's limiter the policy itself, or remove the key. The new path, `redis-rate-limiter.failMode`, written without the Redis limiter's module, is reported by nothing: `config_sections_ignored` does not name it, as core's schema mirrors the Redis stores' sections and counts them as owned. Nor is `RATE_LIMIT_FAIL_MODE`, the old variable: it no longer binds `rateLimit.failMode`, so with a limiter other than Redis's it does not trigger this warning, and only the Redis limiter's module refuses it |
| `replica_unsafe_adapters` (warn) | `core/src/boot/replica-safety.mts` | `core.deployment.mode` is unset; set it |
| `dpop_replay_ttl_below_window` (warn, `iatWindowSeconds`, `replayTtlSeconds`, `requiredTtlSeconds`) | `dpop/src/verifier.mts` | `dpop.replayStoreTtlSeconds` is below `2 × iatWindowSeconds + 1`: a proof can outlive its replay record and be replayed while still inside its acceptance window. Raise it to `requiredTtlSeconds` or more. It was a sentence, with `reason: "replay_ttl_below_iat_window"` |
| `login_rate_limiter_not_shared`, `webauthn_authentication_options_rate_limiter_not_shared` (warn) | `session/src/routes/Session.mts`, `webauthn/src/module.mts` | no shared `rateLimiter` and `core.deployment.mode` unset; the guard is per-process (`"multi"` refuses boot instead, `"single"` is silent — #474) |
| `webauthn_authentication_options_budget_mismatch` (warn — `key`, `contributed`, `webauthnConfig`) | `webauthn/src/module.mts` | a shared `rateLimiter` is wired, and the contributed budget for `webauthn-authentication-options` (`contributed`: the one the module contributes from `webauthn.rateLimit.authenticationOptions`, or an override's; `null` when there is none) differs from the `webauthnConfig` slot (what the per-process fallback is built from, and what backs the `RateLimit-*` headers only for an adapter that reports no `limit`). The route runs on an explicit `limits.webauthn-authentication-options` in the limiter's section if there is one, otherwise on the contributed budget, otherwise on the limiter's default. An explicit `limits` entry is not compared. Set `key` to the slot's values (the line names both), and check `rate_limit_budgets_registered` for a module that overrode it |
| `jwt_verify_aud_skipped`, `jwt_verify_iss_skipped` (warn, once per logger) | `core/src/jwt/verify.mts` | a verification surface is not pinning `aud`/`iss` |
| `jwt_verify_legacy_typ` (warn) | `core/src/jwt/verify.mts` | `OAUTH_JWT_LEGACY_TYP_ACCEPT=true` is admitting typ-less tokens; close the window |
| `federationTokenStore: in-memory adapter is for dev/test only …` (warn) | `core/src/federation-tokens/factory.mts` | the standalone builds this store in memory unless `adapters.federationTokenStore = "redis"` (`ADAPTERS_FEDERATION_TOKEN_STORE=redis`) is set (#456) |
| `federation_store_plaintext_override` (error, `store`, `mode`, the `environment` or `deploymentMode` that would have refused it, `override`) | `redis/src/internal/encryption-mode.mts` | `FEDERATION_TOKENS_ALLOW_INSECURE=1` is set where plaintext is refused — a production/staging environment or `core.deployment.mode = "multi"` (#473); `store` is `federation-tokens` or `federation-grants`. It was a `[federation-tokens] CRITICAL: …` console line |
| `federation_store_plaintext` (warn, `store`, `mode`) | `redis/src/internal/encryption-mode.mts` | a sealing store runs `allow-plaintext` where that is allowed (development); set `mode = "required"` and a key before it leaves development |
| `config_key_deprecated` (warn, `key`, `env`, `replacement`, `replacementEnv`) | `templates/standalone/src/buildModules.mts` | `key = "oauth.accessToken.expiresIn"`: the deprecated key decides the access-token default; move the value to `oauth.accessToken.defaultExpiresIn` (`OAUTH_ACCESS_TOKEN_DEFAULT_EXPIRES_IN`). It was a `[buildModules] … is deprecated` console line |
| `adapter_builder_deprecated` (warn, `builder`, `replacement`) | `redis/src/code-repository.mts` | a composition registers `redisCodeRepositoryBuilder`; wire `redisCodeRepositoryModule` instead |
| `acr_value_unsatisfiable` (warn, or info — `acr`, `unproducible`, `unproducibleCount` when the list was cut, and `emptyAlternative: true` when an alternative requires nothing — a hand-built table only — which is never met) | `oauth/src/acrValues.mts` | an `oauth.authorize.acrValues` entry nothing this composition installs can satisfy was dropped: it is not advertised in `acr_values_supported`, and `/authorize` answers it `unmet_authentication_requirements`. `unproducible` names the values nothing records — `fed` without a federation installed, a second factor's values (`otp`, `hwk`, `swk`, `email`, `recovery`, `mfa`) while no registered session requirement reaches them, anything else always. `info` when only a second factor is missing and no requirement reaches one (the composition's choice: installing MFA would meet it — `mfa.mode` does not enter into it); `warn` otherwise. Remove the entry, or install what produces its values (a federation, or MFA). An installed federation adds `fed` alone unless `core.federations.<name>.trustUpstreamAmr = true`, which counts whatever its IdP asserts (the MFA ADR's D13): an entry that only an upstream IdP's `mfa` or `hwk` met before that switch existed is dropped until one trusted federation is installed. One line per dropped entry per process |
| `mfa_factor_store_lossy`, `mfa_transaction_store_lossy` (warn, `store`, `adapter: "redis"`, once at boot) | `redis/src/internal/mfa-durability.mts` | the MFA store's Redis takes RDB snapshots and has no AOF: a crash loses what was written since the last snapshot — enrollments, whose accounts then read as never enrolled, or an operator reset's email-proof requirement (D12). Turn AOF on (`appendonly yes`, `appendfsync everysec`) |
| `mfa_factor_store_volatile`, `mfa_transaction_store_volatile` (warn, `store`, `adapter: "redis"`, once at boot) | same | the MFA store's Redis has no persistence at all: a restart empties it. Turn AOF on |
| `mfa_factor_store_durability_unchecked`, `mfa_transaction_store_durability_unchecked` (warn, `store`, `adapter: "redis"`; `unread` — the parts it could not read: `maxmemory-policy`, `appendonly`, `save`; `maxmemoryPolicy` — a policy it does not know, neither `noeviction`, a `volatile-*` nor an `allkeys-*` one; `err` — the first refusal's projection; once at boot) | same | part of the check could not run, and the store booted: the server refused a question — `INFO` or `CONFIG` renamed, disabled, or not permitted to the connection's user — or answered without the value, or reports a policy the check does not know. Confirm the rest where the server is configured (`noeviction`, AOF on), or let the user run `INFO` and `CONFIG GET` |
| `mfa_transaction_store_lock_evictable` (warn, `store`, `adapter: "redis"`, `maxmemoryPolicy`, `evictableFamilies`, once at boot) | same | the MFA transaction store's Redis runs a `volatile-*` policy. A subject's lock and weekly window (`mfat:lock:`, `mfat:week:`) carry a TTL once no run of failures is counted, so at `maxmemory` the server may evict them, and a weekly hold on guessable proofs ends early (D21). A subject's first-binding mark (`mfat:first-binding:`) always carries one, and an evicted mark fails open: a session whose recorded enrollment witness may be stale is no longer refused a first binding (D12). A subject's lease (`mfat:lease:`) always carries one, and an evicted lease lets a second writer at the subject's factors. At `maxmemory`, `volatile-lru` and `volatile-random` were seen to evict nearly every mark; `volatile-lfu` and `volatile-ttl` spared them in the same probe. `evictableFamilies` names the four: `lock`, `week`, `first-binding`, `lease`. The MFA stores require `maxmemory-policy` `noeviction`: set it, on a Redis of their own if need be |
| `mfa_factor_store_in_memory` (warn, `store`, `adapter`) | `core/src/mfa/factory.mts` (`memoryMfaFactorStoreModule`, the `memory` builder) | enrolled second factors are kept in process: a restart empties them, and every subject then reads as never enrolled (D12). Unlike `replica_unsafe_adapters` it warns under `core.deployment.mode = "single"` too — the loss is at restart, not across replicas. Development only; the standalone template installs no MFA store |
| `mfa_rate_limiter_not_shared` (warn — `limit`, `windowSeconds`; once at boot) | `mfa/src/module.mts` | no `rateLimiter` is wired, so the MFA routes limit through a per-process limiter over `mfa.rateLimit.routes`: with several replicas each counts apart. Wire `adapters.rateLimiter = "redis"`, or set `core.deployment.mode = "single"` if one replica is the deployment |
| `mfa_digest_made_with_retired_key` (info — `keyId`; once per key id per process) | `mfa/src/sealing.mts` | a stored digest (a recovery code's, an email code's) matched under a key that is no longer the ring's first: that key is still needed. Beside `mfa_factor_sealed_with_retired_key`, it is what to count before retiring a key |
| `mfa_login_not_resumed` (warn — the error's projection; per such verification) | `mfa/src/routes.mts` | a verified second factor's login could not be resumed — its transaction's continuation names a requirement this deployment no longer registers, typically after a deploy removed one mid-login. The user is answered `401 login_required` and logs in again |
| `mfa_development_sample_key_in_use` (warn — `setting: "mfa.encryptionKeys"`, `variable: "MFA_ENCRYPTION_KEY"`; once at boot) | `mfa/src/module.mts` | the MFA key ring carries the published development sample key (`MFA_DEVELOPMENT_SAMPLE_KEY`), which the settings accept only outside production and staging and under one replica: every factor's data is sealed from nobody. Set `MFA_ENCRYPTION_KEY` to a key of your own (`openssl rand -base64 32`) before the deployment leaves development |
| `mfa_step_up_unsupported` (warn — `store: "userSessionStore"`, `kind` the adapter's; once at boot) | `mfa/src/module.mts` | the user-session store has no `recordSecondFactor` (core's `supportsSecondFactorUpdate`), so a verified step-up could not be written into a session: the MFA requirement sends a session to log in again where it would step it up — a password session without a second factor under `mfa.mode = "required"`, and, under either mode, one without recent MFA at an action that adds a way into the account (the link start, WebAuthn registration) (the MFA ADR's D20); the step-up of a counting factor answers `401`, and a factor bound in a session records nothing on the session; an `acr_values` step-up at `/authorize` is one login trip instead, then `unmet_authentication_requirements` when that login carries no factor. Use a store with the capability — both bundled ones have it — or implement it in yours |
| `mfa_escalation_unbound` (error — `route`, `sub`) | `mfa/src/escalation.mts` | the user-session store recorded a session's step-up, or a binding in it, but answered the session without the renewal nonce it was handed: the escalation would stand bound to no cookie session, so the session was ended and the user signs in again (a removal that failed is also `mfa_store_unavailable` `user_session` `delete` — then the record stands escalated and unbound until it expires or the subject's sessions are revoked: revoke them). The step-up answered `500`. A store of your own drops `renewalNonce` — fix it to round-trip the field and to honour `expectedRenewalNonce` |
| `mfa_escalation_invalid` (error — `route`, `sub`, and the error's projection for a store's refusal) | `mfa/src/escalation.mts` | a session's escalation could not be recorded as asked: what the verification adds is outside the `mfa` requirement's sealed reach (a factor that changed what it declares after boot — nothing renewed), or the user-session store refused the event (`RangeError`), most often an `at` further ahead of the store's clock than `DEFAULT_CLOCK_SKEW_MS` — the replicas' clocks disagree. The step-up answered `500`, the session not raised; nothing is retried |
| `mfa_escalation_not_recorded` (info — `route`, `sub`) | `mfa/src/escalation.mts` | a session's escalation found nothing to record: the session ended, another completion from the same cookie session was recorded first, or the record predates how a session was established. The step-up answered `401`; the user signs in again. Occasional lines are a user's two tabs; a burst is worth a look |
| `mfa_enrollment_nothing_enrollable` (warn — `kinds`, the counting factors' kinds; once per such login) | `mfa/src/requirement.mts` | a password login under `required` asked a subject with no factor for a first binding, and every counting factor refused that user (`enrollable(user)` — an email factor for an account without an address): the answer lists nothing to enroll, and the user cannot finish. Enable a factor every user can enroll (TOTP), or give the accounts what the factor needs |

### Data corruption — a stored record could not be read

`user_session_corrupt_envelope` and `session_rp_registry_corrupt_envelope`
(warn, `sid`, `reason` `json_parse` with the parser's projection as `err`, or
`shape_invalid`; `packages/redis/src/userSessionStore.mts`,
`sessionRPRegistry.mts`) — the record is treated as absent (fail-closed). A
session envelope whose `authentication` is not a well-formed object — `null`
included — is `shape_invalid`: it is never read as a session from before the
key, which would split it again and forget a verified second factor.
`authorization_code_corrupt_record` (error, `codeHash`, `reason` `json_parse`
with `err`, or `identity_fields_missing`;
`packages/redis/src/code-repository.mts`) — the code is refused. They were
`user_session_corrupt_envelope: JSON.parse failed` (and `: shape invalid`), the
same for the RP registry, `RedisCodeRepository: corrupted data for code` and
`… legacy/corrupted code record missing required identity fields`; the session
stores' lines now reach the deployment's logger (they were written only by a
store built with one, which the module never did).
A federation-token envelope that fails to decrypt is **deleted** and the user is
sent to re-authenticate (`packages/redis/src/federation-tokens.mts` `get`).
An enrolled MFA factor the Redis store cannot read back refuses its subject's
whole list with an error that quotes nothing it read — never "no factor",
which would open a first binding (D12); an MFA transaction it cannot read back
is answered as absent, and the user starts the ceremony again; a subject's
lock state a script cannot read refuses the attempt (`MFA subject state: …`)
rather than let it through (`packages/redis/src/mfa-factor-store.mts`,
`mfa-transaction-store.mts`). None writes a line of its own: its caller
answers it as an outage. The Store-backed factor store refuses a subject's
whole list the same way for a record it cannot read, one of another subject
or an id listed twice (`unreadable_record`;
`packages/foundation/src/mfa/HttpMfaFactorStore.mts`).
A watermark that is not a number throws rather than reading as "not revoked"
(`packages/redis/src/subjectRevocation.mts`). A cookie-session record the
store holds but cannot read — not JSON, or not a session record — is read as
absent, so express-session starts a fresh session for the request:
`session_cookie_record_unreadable` (warn, `store: "cookie_session"`, never the
record's text; `packages/session/src/store/factory.mts`). It is not the `503` a
cookie store that cannot answer gives. The record is not deleted and the
browser keeps its cookie, so each of its requests reads the record again and
logs again, until the user signs in (a new cookie) or the record's TTL passes:
a stream of these from one browser is one record. The same store's `form_post`
federation transactions (`fedtx:`) and oauth re-authentication asks
(`reauth:`) are read the same way and warn the same way — an unreadable
transaction makes its callback `400 invalid_session` (the user starts the
federation again), an unreadable ask is no ask (`/authorize` asks again). Any of these at a steady rate
after a deploy means a key or an encoding changed under live data — see
[§7](#7-upgrading-and-rollback).

### The audit-event inventory

`BUILT_IN_AUDIT_EVENT_TYPES` (`packages/core/src/audit/types.mts`) is pinned
to the emission sites in both directions by a drift test, so **that constant**
is the complete list. This is a copy of it for reading; the test does not
check this page, so when the two disagree, the constant is right:

`authorize.granted`, `authorize.rejected`, `consent.denied`, `consent.granted`,
`device.approved`, `device.decision_outcome_unknown`, `device.denied`,
`device.rate_limited`,
`federation.grant.authorization_failed`, `federation.grant.authorized`,
`federation.grant.reauthorization_required`, `federation.grant.reauthorized`,
`federation.grant.refresh_failed`, `federation.grant.refresh_persist_failed`,
`federation.grant.refreshed`, `federation.grant.request.denied`,
`federation.grant.requested`, `federation.grant.revoke.denied`,
`federation.grant.revoked`,
`federation.grant.token.denied`, `federation.grant.token.success`,
`federation.identity.link_refused`, `federation.identity.linked`,
`federation.logout.idp_unreachable`,
`federation.logout.success`, `federation.token.family_revoked`,
`federation.token.forbidden`, `federation.token.reauthentication_required`,
`federation.token.refresh_failed`, `federation.token.success`,
`federation.token.upstream_ineligible`,
`introspect.family_revoked`, `introspect.session_invalid`,
`introspect.store_unavailable`,
`logout.cascade_failed`, `logout.family_revoked`, `logout.success`,
`mfa.challenge.sent`, `mfa.email_address_mismatch`,
`mfa.enrollment_state_inconsistent`,
`mfa.factor.enrolled`, `mfa.factor.removed`, `mfa.first_binding_conflict`,
`mfa.lock.recovered`, `mfa.locked`,
`mfa.locked.first`, `mfa.recovery_code.used`,
`mfa.recovery_codes.generated`, `mfa.reset`, `mfa.verified`,
`mfa.verify.failure`,
`rate_limit.unavailable`, `session.admission.subject_mismatch`,
`token.issued`, `token.issued.failure`.

The `mfa.*` events are the multi-factor authentication package's (the MFA
ADR's D28). The MFA package is private until the standalone template wires
it, so no released composition emits them. Its routes emit
`mfa.challenge.sent`, `mfa.verified` and `mfa.verify.failure` (`reason`:
`invalid`, `expired`, `replayed`, `malformed`, `sign_count_regression`, or
`exhausted` for a verification that arrives after the transaction's attempts
are spent, which is refused unchecked and ends the transaction) — the
account-email proof's among them, with `kind: "account-email"`;
`mfa.email_address_mismatch` (`kind`) for a factor whose recorded address no
longer matches the login's; `mfa.factor.enrolled` (`binding`: `password` or
`email_proof` at a first binding, `mfa` beside another factor; `purpose`
`login` or `enroll`; `by: "user"`) and `mfa.recovery_codes.generated`
(`regenerated: true` when a set stood, or may have; `unreplaced: true` when
an older set is still stored beside the new one — kept and usable, with
`kept: "password_binding"`, or retired and not removed) at a first binding —
once the answer carrying the codes was sent; a login's `mfa.factor.enrolled`
with no `generated` after it means its set was written and never shown
(bound by `email_proof`, the sets that stood are retired; the account page
lists it `recovery_codes_shown: false`) or not written
(`mfa_recovery_codes_unwritten`) —
and at a regeneration from the account page (`binding: "mfa"`, no
`purpose`), and `mfa.first_binding_conflict`
(`kind`) for one dropped because another binding of the subject stood at
once; `mfa.locked` (`hold`) for each proof the subject lock held, and
`mfa.locked.first` (`hold`, `binding`) for the first of an episode;
`mfa.recovery_code.used` (`remaining`) for each recovery code spent — a
code that reopens a login for a binding included. The `mfa` requirement
emits `mfa.enrollment_state_inconsistent` (`witness`; `purpose` `login`, or
`session` with the admitted `action`), and so do the routes for a recovery
code that would reopen a login for a first binding (`purpose: "login"`).
`mfa.verified` for a recovery code that reopens a login for a binding
carries `reopened: true`. `mfa.factor.removed` (`kind`, `factorId`,
`binding`, `by: "user"`) is a removal from the account page. The rest are declared ahead
of the build steps that emit them. `sign_count_regression` is
the WebAuthn factor's clone event, and names the factor's record id as
`factorId` — see
[Investigate](#investigate--security-signals-worth-a-dashboard-and-a-threshold). `mfa.verified` is audited
when the factor is verified, before the login resumes: a resumption refused
(`mfa_login_not_resumed`), interrupted by another requirement, or failing at
a store leaves an `mfa.verified` with no session. A run of
`mfa.verify.failure` for one `subject` is someone guessing the second factor
of an account whose password they hold.

None of the device events carries the user code or the device code
(`packages/device-grant/README.md`).

The three events that report an error — `rate_limit.unavailable`,
`introspect.store_unavailable`, `federation.logout.idp_unreachable` — carry it
as `details.cause = { name, code?, cause?: { name, code? } }`, and never its
message: a store's or an IdP's message is their text (a Redis reply quotes the
command it refused, a JSON parse error its input). The message is in the
paired log line, read through `loggableError`. Group outages by
`details.cause.name` and `details.cause.code`, or `details.cause.cause.code`
for a wrapped network error (`fetch failed` over `ECONNREFUSED`).

Every `details` key keeps one type across events, so a sink that fixes a
field's type on first sight (Elasticsearch / OpenSearch dynamic mapping, a
BigQuery schema, a Datadog facet) never drops an event for disagreeing:
`details.error` is a string wherever it appears — an OAuth code on
`token.issued.failure` — and the codes inside `details.cause` are strings.
`AuditEventDetails` (`packages/core/src/audit/types.mts`) types both keys, and
the inventory's drift test reads every emission for them.

An event's `ip` is always an IPv4 or IPv6 address (an IPv6 zone stripped), or
absent. An event with no `ip` means the request's address was not an address:
behind `trust proxy`, `req.ip` came from an `X-Forwarded-For` that held
something else — check that `HTTP_TRUST_PROXY` trusts only the hop that sets
the header. Its `userAgent` is the header sanitised and capped at 200
characters.

---

## 5. Redis

### Two connections, not one

| Connection | Configured by | Serves | Probe name |
| --- | --- | --- | --- |
| the shared **ioredis** socket, one per replica | `redis-clients.url` / `.password` (`REDIS_CLIENTS_URL`, `REDIS_CLIENTS_PASSWORD`) | every `makeIoredisClients` purpose: refresh-token families, the six user-session stores, rate limiter, authorization codes, access-token denylist, federation tokens and the consent stores when Redis-backed (`templates/standalone/src/modules.mts`, `packages/redis/src/ioredis.mts`) | `redis` |
| a **node-redis** client via connect-redis | `session-store.storage.redis.url` / `.password` (`SESSION_STORE_STORAGE_REDIS_URL`, `…_PASSWORD`) | the express-session cookie store only; its key layout and TTL are connect-redis's own — this repo passes it nothing but the client (`packages/session/src/store/factory.mts`) | `session-store` |

Plus one short-lived **duplicate** of the shared socket per refresh rotation:
`WATCH` is connection-scoped in Redis, so `updateFamily` opens `client.duplicate()`
for its compare-and-swap and closes it on exit
(`packages/redis/src/refresh-token-family.mts`). Under refresh-heavy load
against a managed Redis with TLS/AUTH this is connection churn — tracked as
`#293` item 7, undecided at `v0.11.0`.

Requirements (`packages/redis/README.md`): Redis **7.2 LTS or later** — the
session adapters issue `PEXPIREAT … NX` + `PEXPIREAT … GT`, `PEXPIRETIME` backs
the monotonic watermark, `GETDEL` backs code consumption; and **Lua** — the
lock release, the watermark write, the subject sweep and every other store
script run `EVALSHA`-first with a `NOSCRIPT` fallback to `EVAL` that re-loads
after a `SCRIPT FLUSH` or a failover (`runScript` in
`packages/redis/src/ioredis/commands.mts`); the rate-limit increment is a plain
`EVAL` every time. Redis
Cluster with Lua disabled is not supported by `makeIoredisClients`. Nothing in
the key layout groups a session's keys into one slot: the only Cluster-safety
claim the code makes is for `sAddWithTtl`, a single-key `MULTI`.

### Key families

Prefixes are the shipped defaults; every one is overridable so two deployments
can share a database (`REDIS_SESSION_STORES_KEY_PREFIX`,
`REDIS_REFRESH_TOKEN_FAMILY_STORE_KEY_PREFIX`, `REDIS_CODE_REPOSITORY_KEY_PREFIX`,
`REDIS_ACCESS_TOKEN_DENYLIST_KEY_PREFIX`, `REDIS_FEDERATION_TOKEN_STORE_KEY_PREFIX`,
`REDIS_CONSENT_STORE_KEY_PREFIX`, `REDIS_MFA_FACTOR_STORE_KEY_PREFIX`,
`REDIS_MFA_TRANSACTION_STORE_KEY_PREFIX`, `REDIS_FEDERATION_GRANT_STORE_KEY_PREFIX`,
`REDIS_FEDERATION_GRANT_INTENT_STORE_KEY_PREFIX`; each store's own section in
`packages/redis/config/reference.conf`).

| Key | Type / value | TTL comes from | Source |
| --- | --- | --- | --- |
| `rtfam:<familyId>` | string, JSON `{familyId, activeJti, revoked, expiresAtMs}` | the family's `expiresAtMs` (`oauth.refreshToken.expiresIn`, default 86400 s). Set once at creation; rotation **never extends** it (`Math.min` in `rotate`). Revocation — by `/oauth/revoke`, a logout, or a replay — **does**: a revoked family is kept until the later of that expiry and the revocation plus `oauth.accessToken.maxExpiresIn`, plus about five minutes (the verifier's clock tolerance), so its access tokens cannot outlive it; a family revoked after its key expired gets a revoked key again | `packages/redis/src/refresh-token-family.mts`, `core/src/refresh-token-family/rotation.mts`, `revocation.mts`, `retention.mts` |
| `oauth:code:<code>` | string, JSON code record | `redis-code-repository.defaultExpiresIn` (`REDIS_CODE_REPOSITORY_DEFAULT_EXPIRES_IN`, default 600 s) or the per-call `expiresIn`; consumed with `GETDEL` | `packages/redis/src/code-repository.mts` |
| `atdeny:<jti>` | string `"1"` | the revoked access token's **remaining** lifetime plus about five minutes (`REVOCATION_RETENTION_ALLOWANCE_MS` — the verifier accepts a token that long past its `exp`); a token already past that writes nothing | `packages/redis/src/access-token-denylist.mts`, `packages/oauth/src/routes/revoke.mts` |
| `<tag>:ip:<ip>` — `token`, `authorize`, `introspect`, `login`, `device_authorization`, `webauthn-authentication-options`; `device_verification:user:<subject>` | integer counter | the prefix's `windowSeconds`: `redis-rate-limiter.limits.<prefix>` when declared, else the budget the prefix's owning module contributes — `login` 20 per 900 s from `session.rateLimit.login` (the session module), `device_verification` 5 per 300 s from `device-grant.rateLimit` (the device grant), `webauthn-authentication-options` 30 per 60 s from `webauthn.rateLimit.authenticationOptions` (WebAuthn), `mfa` 60 per 300 s from `mfa.rateLimit.routes` (the MFA module) — else `defaultLimit` 60/60 s. The expiry is set atomically with the increment and only when missing, so a steady stream cannot hold a window open | `packages/redis/src/ratelimit.mts`, `ioredis/scripts/rate-limiter.mts` (`LUA_INCREMENT_WITH_TTL`), `core/src/ratelimit/budgetLookup.mts` |
| `ss:us:<sid>` | string, JSON `{sid, sub, authTimeMs, createdAtMs, expiresAtMs, claims, amr?, authentication?, enrollmentFacts?, renewalNonce?}` — `amr` (RFC 8176, #481) is left out when the login path recorded none; `authentication` (`{primary, federation?, upstreamAmr?, mfaAtMs?}`, the MFA ADR's D9) is left out by a release before it, and such a session is read as one to split — a federated one vouches for `fed` alone; `enrollmentFacts` (`{witness, mailAddress}`: the login's MFA enrollment witness and what its address is — none, one the provider reads, or one it cannot (`mailAddress`: `none`, `address`, `unreadable`), never the address; the MFA ADR's D12, D24) is left out by a release before it; such a session recorded nothing, which the MFA ADR's D12 has the `mfa` requirement send to log in before a first binding; `renewalNonce` (22 base64url characters, the MFA ADR's D27) is written by a verified second factor that carries one, binding the session to the one cookie session renewed for it, and left out until then — any other value reads the envelope as corrupt | the session's `expiresAt` (`SET … PX … NX`); a verified second factor rewrites the value with `KEEPTTL` | `packages/redis/src/userSessionStore.mts` |
| `ss:rp:<sid>` | hash, field = `clientId`, value = RP envelope | `session.expiresAt`, raised but never truncated (`PEXPIREAT NX` + `GT`) | `packages/redis/src/sessionRPRegistry.mts`, `internal/redisSidHash.mts` |
| `ss:fi:<sid>`, `ss:fed:<sid>` | sorted sets of family ids / federation names | same rule | `packages/redis/src/sessionFamilyIndex.mts`, `sessionFederationIndex.mts`, `internal/redisSidSortedSet.mts` |
| `ss:fi-ended:<sid>` | string `"1"`, the session's "ended" mark (`endSession`): an `addFamilyIdUnlessEnded` after it answers `"ended"` | the session's `expiresAt` plus the clock-skew allowance, five minutes (`DEFAULT_CLOCK_SKEW_MS`; `SET … PXAT`), so a replica whose clock is behind still sees it; written even by an end after `expiresAt`; `removeBySid` leaves it | `packages/redis/src/sessionFamilyIndex.mts` |
| `ss:sub:<subject>` | sorted set of sids, **score = each session's expiry** | key TTL raised to the latest member expiry; members pruned on read against the server's `TIME` | `packages/redis/src/subjectSessionIndex.mts` |
| `ss:rev:<subject>` | string, epoch-ms watermark | the caller's `watermarkTtlMs` — sized to the **longest refresh token**, monotonic on both value and expiry | `packages/redis/src/subjectRevocation.mts`, `core/src/user-sessions/revokeAllForSubject.mts` |
| `ft:<sid>:<federation>` | string, AES-256-GCM-encrypted envelope | `redis-federation-token-store.ttl` (default 86400 s) — the store lifetime, deliberately **not** the upstream access token's expiry | `packages/redis/src/federation-tokens.mts` |
| `ft:idx:<sid>` | set of federation names | same, raised with each write | same |
| `ft:lock:<sid>:<federation>` | string, advisory lock token | the lock's own | `packages/redis/src/internal/lock.mts` |
| `chal:…`, `replay:…` | strings `"1"` | the challenge / replay window, `SET … PX … NX`. A DPoP proof's record is `replay:<len>:dpop-proof:<jkt>\|<len>:<jti>`, kept `dpop.replayStoreTtlSeconds` (default 300 s) | `packages/redis/src/challenges.mts`, `replay-seen-set.mts`, `packages/dpop/src/verifier.mts` |
| `consent:rec:<len>:<sub>\|<len>:<clientId>` | hash `{scopes (JSON array), grantedAt, expiresAt?}` | **none** for a consent recorded until revoked — which is what `POST /oauth/consent` writes; for a record carrying `expiresAt`, that expiry plus 5 minutes' slack (`CONSENT_EXPIRY_SLACK_MS`). Expiry is judged by `expiresAt` on the reading replica's clock; the TTL only reclaims records nobody reads again | `packages/redis/src/consent-store.mts`, `ioredis/scripts/consent.mts` (`LUA_CONSENT_GRANT`) |
| `consent:{pending}:ch:<challenge>` | hash `{record (JSON), sessionId, expiresAt}` | the parked request's `expiresAt` (10 minutes, `PENDING_CONSENT_TTL_MS`) plus the same slack; consumed with its index entry in one script | `packages/redis/src/consent-store.mts`, `ioredis/scripts/consent.mts` (`LUA_PENDING_CONSENT_*`) |
| `consent:{pending}:sess:<sessionId>` | sorted set of challenges, score = the order they were parked | raised to its longest-lived member's; at most `PENDING_CONSENT_PER_SESSION_LIMIT` (16) members, the first-parked evicted past it. `{pending}` is a Cluster hash tag: every parked request shares one slot | same |
| `mfaf:{<subject>}` | hash — one field per enrolled second factor (its id), value `<version>\n<fixed JSON>\n<mutable JSON>`; the factor's `data` sealed by the MFA package before it arrives (D11); and `~g`, the factor set's generation, which every membership write moves. `<subject>` and the id are base64url of their JSON | **none** while it holds a factor: an enrolled factor does not expire, and losing one lets whoever holds the password bind their own (D12). Holding `~g` alone, after the last factor's removal or a reset, it is the set's tombstone, kept 24 hours from that write so a first binding read before it cannot land after it; losing it sooner (a `volatile-*` eviction — the module warns, `mfa_factor_store_tombstone_evictable` — or a flush) reopens that. Keep it where nothing evicts it and a restart keeps it — `noeviction` for every MFA key family, AOF on, preferably a database or instance of its own; the module refuses an `allkeys-*` policy at boot and warns without AOF. The store assumes acknowledged writes are not rolled back: a failover that loses them may restore a removed factor. At `maxmemory` under `noeviction`, factors can still be removed and the operator reset still runs, but no factor can be enrolled (`OOM`, `mfa_store_unavailable`) until memory is freed or `maxmemory` raised | `packages/redis/src/mfa-factor-store.mts`, `ioredis/scripts/mfa.mts` (`LUA_MFA_FACTOR_*`) |
| `mfaf:{<subject>}:w:<generation>` | string — one factor-set write's answer, so a copy the Redis driver resends after a reconnect answers it and writes nothing | the declared clock skew (1 second) past the write's deadline, on the server's clock (`SET … PXAT`), about two seconds in all. Evicting one early (`volatile-*`; the module warns) lets a resent copy apply again: run `noeviction` | same |
| `mfat:tx:{<id>}` | hash — one MFA ceremony: `version`, `attempts`, `enrollment`, `emailProof`, `challenge` and `pendingEnrollment` when set, `record` (the rest as JSON, the login's continuation among it), `incarnation` and `index` (its binding's digest) | its `expiresAtMs` (`mfa.transactionTtlSeconds`, 600 s), rounded up, set when it is created and moved by nothing; consumed by one verification, or ended when its binding opens one more past `MFA_MAX_TRANSACTIONS_PER_BINDING` (5) — the ceremony that expires first goes | `packages/redis/src/mfa-transaction-store.mts`, `ioredis/scripts/mfa.mts` (`LUA_MFA_TX_*`) |
| `mfat:binding:{<digest>}` | sorted set — one binding's transactions (a browser session's, for the session kind), one member `<incarnation>:<id>` per transaction, score = its `expiresAtMs`; `<digest>` is base64url of the SHA-256 of the binding's kind and id, so the express session id is in no key. At most five members: a create past them takes out those that expire soonest, and each is deleted only while it holds the incarnation its member names, so no other binding's transaction is ever ended | set at each create and each removal to the latest expiry it holds, rounded up, so it never outlives the transactions it names; a consume or a reservation past `max` removes the member, and the key goes with its last. The transactions sit on slots of their own, so the index and they change in separate steps: while creates are in flight a binding may hold more than five; only a step that failed leaves an excess, until it expires. A failed eviction is warned (`mfa_transaction_evict_failed`) and the create still answers; a member that cannot leave is warned (`mfa_transaction_unindex_failed`) and counts toward the cap until it is taken out: while live ones expire sooner, a later create ends one of them first; once its transaction's expiry has passed, it goes first. A Redis clock ahead of the replicas' by more than `mfa.transactionTtlSeconds` expires what it is written at once: on one server the transaction too, so nothing stands; on Cluster, an index node ahead of the transactions' nodes drops each index while the transactions stand, so sessions go unbounded while that lasts (keep NTP). Losing the key (a `volatile-*` eviction, a flush) loses only the bound: the next create starts it again. During a rolling deploy from a release without the cap, old instances neither index nor unindex: their transactions are not counted and their consumes leave members behind, an effect bounded by `mfa.transactionTtlSeconds` | same (`LUA_MFA_BINDING_INDEX`, `LUA_MFA_BINDING_UNINDEX`, `LUA_MFA_TX_EVICT`) |
| `mfat:lock:{<subject>}`, `mfat:week:{<subject>}` | hash (the consecutive run of guessable-proof failures, the reservations in flight) and sorted set (the weekly window, one member per failure, scored by its time), under one hash tag | **none** while a run is counted or the hard hold stands (the hash's `hard` field) — a run ends only at a success, an exempt success before the hard hold, or an applied recovery, and D21's hard limit counts it across weeks; the hard hold ends only at an applied recovery; otherwise a day past the last failure to stop counting, on the server's clock. A `volatile-*` policy may evict them then, which lifts a weekly hold early — the module warns (`mfa_transaction_store_lock_evictable`); run `noeviction` | same (`LUA_MFA_SUBJECT_*`) |
| `mfat:recovery:{<subject>}` | hash — the subject's generation (`g`), moved by every applied recovery and reset; its recovery-set floor (`floor`), below which no recovery-code set verifies; one field per recovery authorization, `a:<operation>:<sid>` | **none** once it holds a generation or a floor: losing the generation refuses a write in flight and lets through a writer that captured 0 before a recovery, losing the floor brings an older recovery-code set back; before that, a day past its latest authorization's end. Keep it where nothing evicts it, as `mfaf:` | same (`LUA_MFA_SUBJECT_RECOVERY_*`, `LUA_MFA_RECOVERY_SET_FLOOR_RAISE`) |
| `mfat:lease:{<subject>}` | string — the token of the writer holding the subject's lease over its factor set | the lease's end on the server's clock (`SET … NX PX`, sixteen of `mfa.storeTimeoutMs`); its holder deletes it when done. Evicting it lets a second writer in: run `noeviction` | same (`LUA_MFA_SUBJECT_LEASE_ACQUIRE`) |
| `mfat:proof:{<subject>}` | string `"1"` — an operator reset's `requireEmailProof: true` (D25) | **none**, until the subject's next first binding consumes it; no revocation touches it, and an applied recovery, the reset included, leaves it. As durable as `mfaf:` (D12's step-3 amendment): the transaction store's module runs the same boot check | same |
| `mfat:session-proof:{<subject>}:<sid>` | string, JSON `{provedAtMs, untilMs}` — the account-email proof (D24) given in one session of a subject: written when the MFA page's step-up proof is verified, `untilMs` `mfa.manage.maxAgeSeconds` later; read by the `mfa` requirement at each first binding in that session that asks the proof | `untilMs` less the store's clock (`SET … PX`), set when it is recorded; a later proof for the session replaces it. Losing one fails closed — the user proves again — so no durability is required of it, and a `volatile-*` policy evicting one costs only a re-proof | same |
| `mfat:first-binding:{<subject>}` | string, JSON `{atMs, untilMs}` — the subject's first-binding mark (D12): when a first counting factor was last bound for the subject, or its witness marked. A session or a login continuation authenticated no later than it may hold a stale enrollment witness; the mark does not stand in for the witness, and covers only the window in which one can be stale | its `untilMs` on the server's clock (`SET … PXAT`), which alone judges the mark: one script keeps the later time and the later end of the mark held and the one noted, so a note never moves it back or shortens it. A mark the store cannot read back is an outage, never absent — `DEL` the key, as for the lock keys, and the next first binding notes it again. Losing it together with the subject's `mfaf:` records — one Redis flushed inside its lifetime — reopens that window, so it is kept as `mfat:proof:` is, under the same boot check; it always carries a TTL, so a `volatile-*` policy may evict it, and an evicted mark fails open — the module warns (`mfa_transaction_store_lock_evictable`). At `maxmemory`, `volatile-lru` and `volatile-random` were seen to evict nearly every mark, while `volatile-lfu` and `volatile-ttl` spared them in the same probe; run `noeviction` | same (`LUA_MFA_FIRST_BINDING_*`) |

The MFA transaction store judges when a subject's lock state stops counting
on the time each caller passes, but what it reclaims — the TTL on
`mfat:lock:` and `mfat:week:`, and the prune inside its scripts — on the Redis
server's clock, so keep every replica and the server clock-synced (NTP, as
D22 already requires): a replica whose clock runs more than a day behind the
server's may find subject state reclaimed that it still counts
(`packages/redis/src/mfa-transaction-store.mts`).

### Sizing

There is no background sweeper anywhere in this package; **Redis expiry is the
entire garbage-collection strategy**, so resident size is (write rate ×
lifetime) per family:

- **Sessions** — per live browser session: one `ss:us:` envelope (the JSON
  above plus your claims), up to three sid-keyed structures, one member in
  the subject's `ss:sub:` set, and one connect-redis record. Lifetime =
  `session-store.maxAge` (default 3 600 000 ms).
- **Refresh families** — one small JSON string per family for
  `oauth.refreshToken.expiresIn` (default 86 400 s) from first issuance; a
  logged-out or replayed family stays resident, marked `revoked`, until that
  TTL passes or until `oauth.accessToken.maxExpiresIn` plus about five
  minutes after the revocation, whichever is later.
- **Authorization codes** — one record per `/authorize` for ≤ 600 s; consumed
  codes are deleted on redemption.
- **Denylist** — one tiny key per revoked access token for its remaining
  lifetime plus about five minutes (≤ `oauth.accessToken.maxExpiresIn`, which
  defaults to `defaultExpiresIn`, 3 600 s, plus that). A deployment
  that never calls `/oauth/revoke` holds none.
- **Rate limits** — one counter per (prefix, client IP) per window. Behind a
  misconfigured `HTTP_TRUST_PROXY` every client shares one key, which is
  small and wrong.
- **Federation tokens** — one encrypted envelope per (session, federation)
  for 24 h plus one index set per session, only when federation is enabled.
- **MFA** — only with the MFA stores on Redis. Per enrolled subject, one
  `mfaf:` hash, kept for good. Per second-factor ceremony, one `mfat:tx:` hash
  carrying the login's user snapshot, for at most `mfa.transactionTtlSeconds`,
  at most five live per session; per session holding one, one small
  `mfat:binding:` sorted set for as long as its latest lives.
  Per session whose subject proved the account's address before a first
  binding, one small `mfat:session-proof:` string until the proof ends.
  Per subject that bound a first factor or had its witness marked, one
  small `mfat:first-binding:` string until the mark ends.
  Per subject with guessable-proof failures, one
  `mfat:lock:` / `mfat:week:` pair; a subject whose run of failures was never
  ended keeps its pair until one is — where the Store lets anyone sign up,
  anyone can mint such subjects (`packages/core/src/mfa/transactionStore.mts`).
  Per subject that had a recovery applied or a recovery-code set issued, one
  small `mfat:recovery:` hash, kept for good; per subject whose factors are
  being written, one `mfat:lease:` string for at most the lease.
- **Consent** — one small hash per (subject, client that is not first-party)
  the user has consented to, until revoked; one parked request per consent
  page shown, for at most 15 minutes (10 plus the slack), 16 per session at
  most. Only with `ADAPTERS_CONSENT_STORE=redis`.
- **Replay records** — one per DPoP proof for
  `dpop.replayStoreTtlSeconds` (default 300 s), and one per
  `private_key_jwt` assertion, ID-JAG and consumed WebAuthn challenge for its
  window. A DPoP proof is recorded at the token endpoint before its rate
  limit runs and at a protected resource before the access token is verified,
  so this family grows with whatever request rate anyone sends. Give Redis a
  `maxmemory` with the `noeviction` policy: a full server then refuses the
  write, and the request is answered `503` (fail closed). An evicting policy
  (`allkeys-lru` and the other `allkeys-*`, and `volatile-*`, since every
  replay record has a TTL) makes room by deleting keys, and a deleted replay
  record is a proof or assertion that can be replayed within its window
  (`packages/redis/README.md`, Requirements).

The standalone does not mount the device grant, so it holds no device-code
keys. A deployment that adds it with `redisDeviceCodeStoreModule` holds, per
pending authorization, `devauth:{devauth}:code:<device_code>` (a hash) and
`devauth:{devauth}:user:<user_code>` (a string), both expiring at the
authorization's deadline (`device-grant.codeLifetimeSeconds`,
default 600 s) and all on one Cluster slot (`packages/redis/src/device-code-store.mts`).
The memory adapter instead caps itself at 10 000 records "at a few hundred
bytes each" (`packages/core/src/device-authorization/memory.mts`).

Core's in-process challenge store and replay seen-set, on a single replica,
hold their live entries plus at most those that expired since the last sweep:
each sweeps on its writes, at most once per 1000 writes and once per ten
seconds (`packages/core/src/single-use/sweep.mts`), so a WebAuthn ceremony
the user abandons, or an options request repeated in a loop, costs an entry
for its lifetime and not until the process restarts. The replay seen-set is
also capped at a million records (`core-replay-seen-set-memory.maxEntries`;
`packages/core/src/replay-seen-set/adapters/memory.mts`): about 200 MB with
the UUID `jti`s clients send, up to about 725 MB if every `jti` is a
256-character one outside Latin-1. DPoP proofs — recorded before any rate
limit or token check, so anyone can send them — may fill only 90% of the
cap, and always at least one record less than it (a cap of 1 has no
reserve): past that a new proof is refused and the rest is kept for the
other consumers. DPoP's share fills at `0.9 × maxEntries /
dpop.replayStoreTtlSeconds` records a second — about 3 000 fresh
proofs a second at the default 300 s, roughly what one process can verify
— and a longer TTL lowers that rate in proportion. At a limit the set
reclaims what has expired, at most once per ten seconds, and otherwise
refuses the new record rather than evict a live one. A DPoP flood therefore
refuses DPoP proofs, `503 temporarily_unavailable` at the token endpoint and
at protected resources, logged as `token_binding_unavailable` /
`protected_resource_binding_unavailable` with `reason: "replay_store_full"`,
while client authentication goes on. Only a set that is full to its cap
refuses the other consumers too — `private_key_jwt`, ID-JAG and WebAuthn,
logged as
`client_assertion_refused`, `jwt_bearer_assertion_verifier_unavailable`,
`webauthn_ceremony_store_unavailable` (registration) and
`webauthn_grant_store_unavailable` (the passkey grant at `/oauth/token`,
`store: "challenge_ceremony"`, `step: "consume"`) — each with
`err.name: "ReplaySeenSetFullError"`. A WebAuthn ceremony consumes its
challenge before it records it as seen, so the one that met a full set has
already lost its challenge: its retry is `400 invalid_grant`
(`challenge_unknown`), and the user starts the ceremony again from the
options request. Sustained, that is a flood of fresh
DPoP proofs, or more traffic than one replica's seen-set should carry: move
to `ADAPTERS_REPLAY_SEEN_SET=redis`. The challenge store is capped the same
way at a million challenges (`core-challenge-store-memory.maxEntries`;
`packages/core/src/challenges/adapters/memory.mts`, about 180 MB). It fills
at `maxEntries / webauthn.challengeTtlMs` — over 8 000 options requests a
second at the default 120 s, behind the options routes' rate limit — and at
the cap refuses a new challenge rather than evict one a user is completing:
the WebAuthn options routes answer `503 temporarily_unavailable`, logged as
`webauthn_ceremony_store_unavailable` (`store: "challenge"`, `step:
"issue"`) with `err.name: "ChallengeStoreFullError"`.

Core's in-process MFA transaction store (`memoryMfaTransactionStoreModule`,
`adapters.mfaTransactionStore = "memory"`; nothing installs it while
`mfa.mode` is `"off"`) sweeps the same way and is capped at a hundred
thousand entries — transactions and the account-email proofs sessions gave,
together (`core-mfa-transaction-store-memory.maxEntries`;
`packages/core/src/mfa/memoryTransactionStore.mts`). A proof is two numbers,
far smaller than a transaction. A transaction carries
the login's user snapshot, so it is larger than a challenge: about 1.1 KB
with a small `User`, so about 110 MB at the cap, growing with what the
Store answers on `authenticate`. At the default ten-minute lifetime the cap
is about 170 new transactions a second on one replica. At the cap it
reclaims what has expired and otherwise refuses a new transaction or proof
with `MfaTransactionStoreFullError` rather than end a ceremony in flight or
drop a proof a user gave. One session holds at most five live transactions
(`MFA_MAX_TRANSACTIONS_PER_BINDING`): a sixth ends the session's ceremony that
expires first, and is no new entry against the cap, so it is many sessions,
not one, that fill it. The
subject lock state is not counted: it is kept per subject a login created,
and a subject's consecutive run is kept until a success ends it.

**Heap headroom for the caps.** A process that keeps the memory stores at
their defaults needs room for them to fill: about 725 MB for the seen-set at
its worst and about 180 MB for the challenge store, so about 1 GB of heap
beyond everything else — and about 110 MB more, scaled by the `User` the
Store answers, when the MFA transaction store is in memory too. Node sizes its default V8 heap from the memory the
process can see, and in a small container that limit is well under 1 GB, so
a flood fills the heap and the process dies before a cap refuses anything.
Either give the process the room (`--max-old-space-size`, and a container
limit above it) or lower the caps to what it has:
`core-replay-seen-set-memory.maxEntries`, `core-challenge-store-memory.maxEntries` and
`core-mfa-transaction-store-memory.maxEntries` (HOCON; a string of digits is
accepted). Each module refuses to boot, with a
RangeError naming its key, a value that is not a positive whole number or is
above 16 777 216 (2^24, the most entries a `Map` holds). A
lower cap lowers the rate that fills the store in proportion.

### Failure timing on the shared socket

The standalone constructs the shared socket with these options
(`SHARED_REDIS_TIMEOUTS` in `templates/standalone/src/modules.mts`, `#286`):

| Option | Value | Why |
| --- | --- | --- |
| `commandTimeout` | 1000 ms | the only bound on a command that never reaches the wire: ioredis arms it before the writability check, so it covers the offline queue and a zombie socket where no `close` ever fires. Without it a fail-closed rate limiter never gets an error to fail on |
| `maxRetriesPerRequest` | 3 | fails the whole offline queue on the fourth reconnect attempt instead of the driver's twentieth; bounds queue **depth** where `commandTimeout` bounds per-command latency. Three so a sub-second failover blip is ridden out silently |
| `connectTimeout` | 5000 ms | half the driver default; only a black-holed SYN reaches it |
| `enableOfflineQueue` | `true` (default, declared) | `false` would reject instantly while the socket is down — sharper for the rate limiter, but the option is per **connection** and this socket carries sessions, codes and refresh rotation too, where a routine failover blip would become a forced re-login |
| `lazyConnect` | `false` | connect at boot, so a wrong URL fails there |

The trade this buys: during a partition the rate limiter takes up to one
`commandTimeout` per request before shedding, and the pile-up is bounded at
(request rate × 1 s) and self-draining. A deployment that wants the limiter to
reject immediately gives it its own `Redis` instance with
`enableOfflineQueue: false` in its own composition root — the per-purpose
client interfaces exist for that (`packages/redis/README.md` "Failure timing").
If you build the socket yourself, attach an `error` listener: an `EventEmitter`
`error` with no listener throws and takes the process down.

### Operational notes

- **`scanFallback` is a migration flag, not a tuning knob.** With it on (the
  default), every federation-token `removeBySid` still runs one `SCAN` of the
  keyspace after the index-driven removal. Set
  `redis-federation-token-store.scanFallback = false` once no session that
  predates the index (v0.10) can still exist — that is, once `ttl` has elapsed
  since the last pre-v0.10 replica stopped writing (`packages/redis/README.md`
  "Federation-token keys and logout").
- Removals during logout use `UNLINK` in batches of 100 keys and paged
  `SSCAN`/`HSCAN`/`ZRANGE` reads, so one heavily-linked session does not block
  the shared connection (`packages/redis/src/federation-tokens.mts`,
  `clients/federation-tokens.mts`).
- A `MULTI`/`EXEC` reply with a per-command error is surfaced as a thrown
  error rather than reported as success — a refused `PEXPIRE` would otherwise
  strand a key with no TTL (`assertPipelineSucceeded`, `ioredis/commands.mts`). The
  error's message names the operation (`<client>.<method>: a queued command
  failed inside MULTI/EXEC`); Redis's reply (`WRONGTYPE …`, `OOM …`) is its
  `cause`, which a log line's `err.cause` carries.

---

## 6. Key rotation

### Where keys live

`key-store.provider` has one built-in value, `"local"`
(`packages/core/src/keys/factory.mts`). Under `local`:

| Key | Meaning |
| --- | --- |
| `algorithm` (`KEY_STORE_LOCAL_ALGORITHM`) | `EdDSA` (shipped default), `ES256`, `RS256`, `HS256`. No implicit fallback |
| `kid` (`KEY_STORE_LOCAL_KID`) | the key id stamped in every token header; default `v0`. A string of 1 to 256 characters with no control character (`isWellFormedKid`); anything else fails boot — a `KEY_STORE_LOCAL_KID` that is exported but empty included |
| `privateKeyPath` / `publicKeyPath` (or inline `privateKey` / `publicKey`) | PEM pair for the asymmetric algorithms; the file path wins when both are given |
| `secret` (`KEY_STORE_LOCAL_SECRET`) | HS256 only, ≥ 32 bytes decoded |
| `previousKeys = [ { kid, publicKeyPath, expiresAt } ]` (or inline `publicKey` instead of `publicKeyPath`) | asymmetric only — additional **verification** keys, published in JWKS until `expiresAt` (an ISO date; invalid fails boot) |
| `previousSecrets = [ { kid, secret, expiresAt } ]` | HS256 only — each secret clears the same 32-byte floor |

The two rotation shapes are a discriminated union in the schema
(`packages/core/src/config/application.schema.mts`): `previousKeys` under
`HS256`, or `previousSecrets` under an asymmetric algorithm, fails boot rather
than being dropped. `kid` values must be unique across the current key and
every previous entry (`Duplicate kid values`). Before the kid shape check, an
`KEY_STORE_LOCAL_KID` exported but empty signed and verified under the kid `""`; it
now fails boot. Tokens already issued under `""` are refused as `kid_unknown`
once the kid is corrected, so their users sign in again. There is no env binding for
`previousKeys` / `previousSecrets` — they are written in your HOCON layer.

Keys are read **once, at boot** (`keyStoreModule`,
`templates/standalone/src/modules.mts`). Rotation is a config change plus a
rolling restart; nothing watches the files.

A KMS/HSM deployment builds `createRemoteSigningKeyStore` in its composition
root and supplies it as the `keyStore` component
(`packages/core/src/keys/remoteSigning.mts`). `kid`, `publicKeyPem` and
`previousKeys` are constructor options with the same semantics as above; only
`sign` calls the provider, `getSigningKidFallback`, `getVerificationKeys` and
`getVerificationKey` are served from the public halves held in process. HS256
is deliberately not offered there.

### What the JWKS publishes and how it is cached

`GET /.well-known/jwks.json` (`jwks.path`, env `JWKS_PATH`, to move it) publishes the
current key plus every `previousKeys` entry whose `expiresAt` has not passed
(`getVerificationKeys`, `packages/core/src/keys/KeyStore.mts`). The route
(`packages/core/src/jwks/router.mts`):

- serialises the set **once per key set** and answers with a strong `ETag`
  (SHA-256 of the body); a poller sending `If-None-Match` gets `304` until the
  set changes — which includes a previous key dropping out on its own clock;
- sets `Cache-Control: public, max-age=<jwks.cacheMaxAge>` (env
  `JWKS_CACHE_MAX_AGE`), default **300 s** (`packages/core/src/jwks/cache.mts`);
- answers `404 jwks_not_published` for HS256 and `503 jwks_unavailable` when
  an asymmetric store yields nothing exportable — both `no-store`, so a
  misconfiguration is never pinned in a shared cache.

Every token this server mints carries `kid` in its header
(`KeyStore.sign` injects it). On verification the header's `kid` is looked up;
an unknown kid raises `UnknownKidError` → `jwt_verify_rejected` `reason:
"kid_unknown"`, and a known-but-expired previous kid raises `ExpiredKidError`
→ `reason: "kid_expired"` (`packages/core/src/jwt/verify.mts`). A token with
no `kid` at all is tried against the current signing kid only.

What a verifier on the other side does with the JWKS is its own configuration.
For `auth.policy-verifier` the relevant knobs are `oauth.jwt.jwksTimeoutMs`
(default 5 000 ms), `jwksCooldownMs` — "minimum spacing between JWKS fetches",
default 30 000 ms — and `jwksCacheMaxAgeMs` — "how long a fetched JWKS is
served from cache", default 600 000 ms
(`auth.policy-verifier/packages/server/src/jwt/jwks.mts`,
`config/defaults.mts`); it refuses a plaintext `jwksUri` except on loopback.

### The overlap window

A key must stay in the JWKS until the **last token signed with it has
expired**, plus the time a verifier may serve a cached set. With the shipped
defaults:

- longest-lived token: the refresh token, `oauth.refreshToken.expiresIn`
  = 86 400 s (access tokens live at most `oauth.accessToken.maxExpiresIn`,
  which defaults to `defaultExpiresIn` = 3 600 s — raise the max past the
  refresh token's lifetime and the access token becomes the longest-lived; id
  tokens default to 3 600 s, `packages/core/src/grants/idToken.mts`);
- provider-side cache: `jwks.cacheMaxAge` = 300 s;
- verifier-side cache: e.g. `jwksCacheMaxAgeMs` = 600 s.

Keep `jwks.cacheMaxAge` well below the overlap window
(`packages/core/src/jwks/cache.mts`) — a freshly published kid must reach
caching verifiers before tokens signed with it arrive.

### Walkthrough — asymmetric, in-config, rolling restart

`previousKeys` entries are verification keys with an expiry; nothing requires
them to be *older* than the signing key. That is what makes a two-phase
rotation possible on a fleet where replicas restart one at a time.

1. **Generate** the new pair and deliver it the same way as the current one
   (compose secrets, a mounted volume — never `config/`, which the image
   `COPY`s):

   ```bash
   openssl genpkey -algorithm ed25519 -out jwt-private-v1.pem
   openssl pkey -in jwt-private-v1.pem -pubout -out jwt-public-v1.pem
   ```

2. **Pre-publish** `v1` as a verification key while `v0` keeps signing, and
   roll every replica:

   ```hocon
   key-store.local {
     kid = "v0"
     privateKeyPath = "/run/secrets/jwt_private_key"
     publicKeyPath  = "/run/secrets/jwt_public_key"
     previousKeys = [
       { kid = "v1", publicKeyPath = "/run/secrets/jwt_public_key_v1", expiresAt = "2027-01-01T00:00:00Z" }
     ]
   }
   ```

   Confirm `GET /.well-known/jwks.json` lists both kids and its `ETag`
   changed, then wait at least `jwks.cacheMaxAge` + the largest verifier cache
   (300 s + 600 s with the defaults) so every verifier has seen `v1`.
   Restarting a replica mid-roll with `v1` signing *before* this step would
   have verifiers fetching the JWKS from a not-yet-restarted replica and
   rejecting `v1` tokens with `kid_unknown`.

3. **Flip** signing to `v1` and demote `v0` with an expiry that covers the
   overlap window, then roll again:

   ```hocon
   key-store.local {
     kid = "v1"
     privateKeyPath = "/run/secrets/jwt_private_key_v1"
     publicKeyPath  = "/run/secrets/jwt_public_key_v1"
     previousKeys = [
       # now + refreshToken.expiresIn + both JWKS caches, rounded up
       { kid = "v0", publicKeyPath = "/run/secrets/jwt_public_key", expiresAt = "2026-09-05T00:00:00Z" }
     ]
   }
   ```

   From here every mint uses `v1`; refresh rotations re-mint under `v1`, so
   the population of `v0` tokens only shrinks.

4. **Retire.** When `v0`'s `expiresAt` passes it drops out of the JWKS on
   its own and any straggler is refused with `kid_expired` — the reason exists
   precisely so a SIEM can tell "rotation window closed" from "fabricated
   kid". Delete the entry and the old private key at the next config change.

### HS256

Same shape with `previousSecrets` (`packages/core/src/keys/KeyStore.mts`
`createSymmetricKeyStore`): issuance always uses the current `secret`/`kid`,
verification resolves by `kid` and never trial-verifies across secrets. There
is no JWKS, so every relying party has to be handed the new secret out of band
before you flip — and a relying party holding the secret can also mint.

### Two other secrets that do not rotate gracefully

- **`session-store.secret`** is a single string in the schema and is passed to
  express-session as one value (`packages/session/src/modules/sessionStoreModule.mts`),
  so there is no overlap window: rotating `SESSION_STORE_SECRET` invalidates every
  browser session at once.
- **The federation-token encryption key** (`redis-federation-token-store.encryptionKey`
  under `mode = "required"`): an envelope written under the old key fails to
  decrypt, is **deleted**, and the user is asked to re-authenticate with the
  upstream IdP (`packages/redis/src/federation-tokens.mts` `get`). Rotating
  it is a mass upstream re-login, by design rather than a migration.

---

## 7. Upgrading and rollback

### Before you upgrade

1. Read the release's section in `CHANGELOG.md` — entries that start
   **`BREAKING:`** and every **Migration:** paragraph. Between cuts there is no
   pending section — the release-cut PR writes the section from the commit log
   — and no entry ever predicts a future version
   ([release-policy.md](release-policy.md) R1/R2), so what a release removed is
   stated only once it is cut.
2. Grep your config for the keys the release retired. A retired key does not
   get ignored — it fails boot naming the key and the release that removed it
   (`withRemovedKeys`, `packages/core/src/config/removed-keys.mts`; the
   decision rule is [release-policy.md §Retiring a config key](release-policy.md#retiring-a-config-key-366)).
   The keys retired so far:

   | Key | Mechanism | What you see |
   | --- | --- | --- |
   | `oauth.refreshToken.legacyTokenCompat` | removed | `oauth.refreshToken.legacyTokenCompat was removed in v0.6.0 (Phase G / M4); see CHANGELOG.` |
   | `oauth.authorize.allowUnmarkedClients` (and the env tombstone `OAUTH_AUTHORIZE_ALLOW_UNMARKED_CLIENTS`, any value) | removed | boot error with migration instructions: mark every client `firstParty: true`, then delete the key and the variable |
   | `oauth.dpop.replay-store` (any value) | removed | `oauth.dpop.replay-store was removed. …` (`config-path-relocated`, wherever the DPoP module is installed): DPoP records its proofs in the `replaySeenSet` component, whose module chooses the backend (`adapters.replaySeenSet` in the standalone); delete the key. A `dpopReplayStore` bootstrap component is no longer read either — see the DPoP note below |
   | `oauth.refreshToken.legacyRtPolicy = "accept-with-warning"` | enum shrunk to `"reject"` | Zod `invalid_enum_value` naming the survivors |
   | flat `oauth.jwt.algorithm` / `kid` / `secret` / key fields | moved | `oauth.jwt has legacy flat fields (…). Migrate to the key store's section: key-store.local.<field>.` |
   | `oauth.grants.authorization_code.pkce.*` (and `OAUTH_GRANTS_AUTHORIZATION_CODE_PKCE_REQUIRE_S256`, any value) | removed | `oauth.grants.authorization_code.pkce.<key> was removed` (`config-path-relocated`), and the variable set at all `environment-variable-renamed`, wherever `oauthAuthorizationModule` is installed: S256 is mandatory regardless (`packages/oauth/src/grants/pkce.mts`); delete the key and the variable |
   | `repositories.code.type` (and `CLIENT_CODE_TYPE`) | moved to `adapters.codeRepository` | refused before boot, naming `adapters.codeRepository` and `ADAPTERS_CODE_REPOSITORY` (step 6) |
   | `oauth.accessToken.expiresIn` (and `OAUTH_ACCESS_TOKEN_EXPIRES_IN`) | deprecated alias of `oauth.accessToken.defaultExpiresIn`, read only while that key is unset — set both and the new key wins | the standalone logs `config_key_deprecated` (warn, `key = "oauth.accessToken.expiresIn"`) at boot when the old key carries anything but the shipped `3600`; `resolveAccessTokenLifetime` is the reader for every composition |

   **DPoP moving onto the replay seen-set.** DPoP's Redis records move from
   `dpop:replay:<jkt>:<jti>` to the seen-set's `replay:…dpop-proof:<jkt>…`
   keys, and neither release reads the other's. While both serve against one
   Redis, a captured proof can be accepted once by an old replica and once by
   a new one. Each replica bounds a replay by its own
   `oauth.dpop.iat-window-seconds` (W), so a proof the old release accepted
   can still be accepted by the new one for up to `W_old + W_new + 1` seconds
   after the last old replica stops (121 s at the default 60 on both), plus
   the largest clock skew between replicas. To avoid the window, either:

   - cut over stop-then-start, starting the new release at least
     `W_old + W_new + 1` seconds plus that skew after the last old replica
     stopped. No replica serves in the gap: at least 121 s of downtime at the
     defaults, for every request, DPoP or not; or
   - run a lowered W on **both** releases for the roll — restart the old
     release with it first, then deploy the new release with it. At W = 5 on
     both, a proof has 11 s in which it can be replayed across releases, and
     the window closes 11 s after the last old replica stops. Lowering it on
     the old release alone is not enough: a replay to a new replica is
     bounded by the new release's W, so at 5 and 60 the window stays open
     66 s after the last old replica stops. Restore the full W on the new
     release no earlier than `W_low + W_full + 1` seconds after the last old
     replica stopped (66 s at 5 and 60); sooner reopens the window for
     proofs the old release accepted. Clients whose clocks are off by more
     than the lowered W are refused while it is lowered.

   The leftover `dpop:replay:*` keys expire by themselves within
   `oauth.dpop.replay-store-ttl-seconds` (300 s by default); nothing reads
   them. Order: delete `oauth.dpop.replay-store` from the config **first** —
   the old release reads its absence as `"memory"`, under which a wired
   `dpopReplayStore` is still the store it uses, and the new release refuses
   to boot while it is set — then deploy the new release with a seen-set
   installed (`ADAPTERS_REPLAY_SEEN_SET=redis` in the standalone). Installing
   one also turns on `private_key_jwt` wherever client authentication runs
   ([§1](#1-deployment-shapes)).

   **The MFA hard hold during a rolling deploy.** v0.16.0 ships no
   subject-lock scripts, so an upgrade from it has nothing to drain; this
   concerns pre-release builds only. A replica of a build that does not
   write the lock hash's `hard` field neither reads nor keeps it: it can
   end a run at the limit at an exempt success, let attempts through below
   the limit, set a deadline on the keys, and — its `keep()` finding no run
   and no week — delete both keys, the hold with them. A new replica refuses
   a held subject whatever an old one did to the run, and its refusal takes
   off a deadline the held hash carries; a hold already deleted is not
   restored. Drain the old replicas before relying on the hard hold.

3. **The upstream `amr` split (the MFA ADR's D13).** From this release an
   upstream IdP's `amr` counts only for a federation with
   `core.federations.<name>.trustUpstreamAmr = true`; decide it per federation
   before you upgrade ([§3](#trusting-an-upstream-idps-amr-and-withdrawing-that-trust)).
   A session written by an older release that carries `fed` is read as
   vouching for `fed` alone, whatever the switch. What sessions already
   minted is not re-read:

   - an authorization code issued before the upgrade — or by a replica still
     on the older release during a rolling one — keeps the `acr` its
     `/authorize` chose, possibly met by an IdP's value this release would
     not count, and `/token` stamps it as it is;
   - a refresh token issued before the upgrade, or by an older replica, keeps
     its `amr` and `acr` — upstream values included — and the refresh grant
     carries them forward at every refresh until the token's family ends:
     `oauth.refreshToken.expiresIn` after the login that began it (a day by
     default). Under `oauth.refreshToken.unknownFamilyPolicy = "accept"` a
     token with no family record has no such bound.

   A deployment for which that matters calls `revokeAllForSubject` for the
   subjects who signed in through an untrusted federation (or revokes a known
   token's family) once the fleet is on the new release; the rest waits a
   family lifetime. What that call reaches, and what it cannot — an access
   token a resource server validates offline — is in
   [§3](#trusting-an-upstream-idps-amr-and-withdrawing-that-trust).

4. Note the migration windows that are **still open** at `v0.11.0`, each of
   which you should be able to close after the upgrade rather than leave on:
   `redis-federation-token-store.scanFallback` ([§5](#operational-notes)),
   `oauth.jwt.legacyTypAccept` (`OAUTH_JWT_LEGACY_TYP_ACCEPT`), and
   `oauth.refreshToken.unknownFamilyPolicy = "accept"`
   (`packages/core/config/reference.conf`). That last one does not close by
   waiting: under `"accept"` a refresh token with no family record is
   redeemed with a new one of the full `oauth.refreshToken.expiresIn`, in the
   same family and still with no record, so a client that keeps refreshing
   holds a chain that never expires and is never replay-checked. Setting
   `"reject"` ends it, and signs out every holder of such a chain at that
   moment — plan it as a forced re-login.

5. **The oauth and session settings at their modules' sections.** Each path
   and variable that moved refuses boot naming the new one; the paths are in
   the [oauth](../packages/oauth/README.md#which-grants-are-on) and
   [session](../packages/session/README.md#configuration) READMEs. Three
   changes go further than the rename:

   - **The grant switches read the boolean vocabulary every other switch
     reads. Check the value each grant's `enabled` is set to before
     upgrading.** `oauth-session.enabled` and
     `oauth-authorization.grants.<grant>.enabled`, and the variables that set
     them, go through core's `coerceBooleanFromEnv`, which trims the value and
     ignores case:

     | Value | Reads as |
     | --- | --- |
     | `true`, `"true"`, `"1"` | on |
     | `false`, `"false"`, `"0"`, `""` (an exported-but-empty variable) | off |
     | anything else — `"yes"`, `"no"`, `"on"`, `"off"`, `"2"`, a number, `null` | refused: boot fails (`config-validation-failed`, naming the key) |

     Before, a grant was on only for the boolean `true` or the exact string
     `"true"`, and every other value left it off without a word — `"TRUE"`,
     `"1"` and `" true "` among them. A grant set to one of those, which you
     believed was off, comes on after the upgrade.
   - **A missing `SESSION_STORE_SECRET` is refused by the session store's
     module**, naming the variable: `provides-factory-failed` where the
     session module is installed (the standalone template), as the CSRF
     token's signer is built from the secret, and `contribute-factory-failed`
     where the session store's module is installed alone. It was
     `config-validation-failed`, from core's schema. An alert or a runbook
     step that matches the reason code needs the new one. A secret that is
     set but below the 256-bit floor is still `config-validation-failed`,
     naming `session-store.secret`.
   - **The PKCE key and variable refuse boot.** `oauth.grants.authorization_code.pkce.*`
     is refused as removed (`config-path-relocated`), and
     `OAUTH_GRANTS_AUTHORIZATION_CODE_PKCE_REQUIRE_S256`, set to any value, as
     removed (`environment-variable-renamed`). They used to log
     `pkce_config_ignored_s256_is_mandatory` once and be ignored. Delete both
     before you upgrade (the table in step 2).

6. **The template's own settings, the adapter selections, the repositories,
   the audit sink's declared absence and the federations at their new
   sections.** Each path and variable that moved refuses to start naming the
   new one while the module that owns it is loaded, and an old variable
   beside its new name at the same value is accepted, so a fleet can carry
   both through a rolling upgrade. A setting judged by a module is judged
   only while that module is loaded: `redisCodeRepository.*` and
   `CLIENT_CODE_KEY_PREFIX` are refused under the Redis code repository and
   go unread under the in-process one, and `REFRESH_TOKEN_FAMILY_STORE_REDIS_*`
   likewise without `redis-clients` (a composition with no Redis-backed
   module):

   | Old | New |
   | --- | --- |
   | `logging.level` (`LOG_LEVEL`) | `logging.level` (`LOGGING_LEVEL`) |
   | `cors.allowedOrigins` (`CORS_ALLOWED_ORIGINS`) | `http.cors.allowedOrigins` (`HTTP_CORS_ALLOWED_ORIGINS`) |
   | `oauth.jwt.signingKey.*` (`OAUTH_JWT_SIGNING_KEY_PROVIDER`, `OAUTH_JWT_ALGORITHM`, `OAUTH_JWT_KID`, `OAUTH_JWT_SECRET`, `OAUTH_JWT_PRIVATE_KEY[_PATH]`, `OAUTH_JWT_PUBLIC_KEY[_PATH]`) | `key-store.*` (`KEY_STORE_PROVIDER`, `KEY_STORE_LOCAL_*`) |
   | `refreshTokenFamilyStore.redis.*` (`REFRESH_TOKEN_FAMILY_STORE_REDIS_URL`, `…_PASSWORD`) | `redis-clients.*` (`REDIS_CLIENTS_URL`, `REDIS_CLIENTS_PASSWORD`) |
   | `rateLimiter.adapter`, `userSessionStores.adapter`, `accessTokenDenylist.adapter`, `replaySeenSet.adapter`, `consentStore.adapter`, `federationTokenStore.type`, `federationGrantStore.adapter`, `federationGrantIntentStore.adapter`, `mfaFactorStore.adapter`, `mfaTransactionStore.adapter`, `oauth.code.adapter` / `repositories.code.type`, `repositories.client.type`, `repositories.user.type`, `audit.sink.type` (and `RATE_LIMITER_ADAPTER` … `CLIENT_CODE_TYPE`, `CLIENT_TYPE`, `CLIENT_USER_TYPE`, `AUDIT_SINK_TYPE`) | `adapters.<slot>` (`ADAPTERS_<SLOT>`): the composition root's own section, in the standalone template |
   | `repositories.*` variables (`CLIENT_PATH`, `CLIENT_USER_*`) | the same paths under `repositories` (`REPOSITORIES_CLIENT_YAML_PATH`, `REPOSITORIES_USER_YAML_PATH`, `REPOSITORIES_USER_HTTP_*`) |
   | `repositories.code.memory.*`, `redisCodeRepository.*` (`CLIENT_CODE_DEFAULT_EXPIRES_IN`, `CLIENT_CODE_KEY_PREFIX`) | `standalone-in-memory-code-repository.*` (`STANDALONE_IN_MEMORY_CODE_REPOSITORY_DEFAULT_EXPIRES_IN`), `redis-code-repository.*` (`REDIS_CODE_REPOSITORY_DEFAULT_EXPIRES_IN`, `REDIS_CODE_REPOSITORY_KEY_PREFIX`) |
   | `repositories.code.redis.*` (`CLIENT_CODE_ENDPOINT_URI`, `CLIENT_CODE_PASSWORD`) | removed: the Redis code repository runs on `redis-clients`; set at all, refused |
   | `audit.sink.<sink>` | `audit-sink.<sink>` |
   | `federations.<name>.*` (the template's `FEDERATIONS_GOOGLE_*`, `FEDERATIONS_OIDC_*`) | `core.federations.<name>.*` (`CORE_FEDERATIONS_<NAME>_<KEY>`) |

   What goes further than the rename:

   - **The adapter selections are refused before boot, not by it.** The
     template's phase one reads `adapters` before it chooses its modules, so
     an old selection path or variable, or a value the template does not know
     (`ADAPTERS_RATE_LIMITER=memcached`), fails the start with a
     `RangeError` naming `adapters.<slot>`, where it used to be a
     `config-validation-failed` or `config-path-relocated` BootError. So do
     the template's own `FEDERATIONS_*` variables. An alert that matches the
     boot error's reason sees neither.
   - **`repositories.code.type` (`CLIENT_CODE_TYPE`) is refused.** It used to
     be read with a `config_key_deprecated` warning while `oauth.code.adapter`
     was unset; move the value to `ADAPTERS_CODE_REPOSITORY`.
   - **The repository selections name the adapters the template's schema
     lists.** `adapters.clientRepository` takes `yaml` or `static`,
     `adapters.userRepository` `yaml`, `static` or `http`; `static`, core's
     alias of `yaml`, reads its path from a block of its own
     (`repositories.client.static.path`, `repositories.user.static.path`),
     which has no default. Another adapter you register in the template is
     added to its schema (`src/sections.mts`) with it.
   - **`REPOSITORIES_USER_YAML_PATH` is read.** `CLIENT_USER_PATH` was not:
     the shipped `application.conf` set `repositories.user.yaml.path`
     literally over it. Following the refusal by moving an old, ignored value
     to the new name changes the users file the `yaml` user repository reads.
   - **A bad in-process code-repository lifetime is refused as config.**
     `standalone-in-memory-code-repository.defaultExpiresIn` that is not a
     positive whole number fails boot as `config-validation-failed`, naming
     the path.
   - **Unset `CLIENT_CODE_ENDPOINT_URI` and `CLIENT_CODE_PASSWORD` first.** A
     `.env` copied from the old `.env.example` sets `CLIENT_CODE_ENDPOINT_URI`;
     both were removed, and set at all they refuse to start, even beside the
     new names.
   - **`audit.sink.type = "none"` no longer declares the audit sink absent.**
     A composition that runs without a sink on purpose lists it in core's own
     section, `core.declaredAbsent = ["auditSink"]`; the standalone template
     always wires one.
   - **The template's sections are strict.** A key `logging`, `http`,
     `key-store`, `redis-clients`, `repositories`, `adapters` or a code
     repository's section does not declare is refused, naming it — a block
     for a key store of your own beside `key-store.local` among them.
   - **Core reads no `cors` section.** It reads CORS origins from the
     `httpSettings` slot alone. A composition of your own that still writes
     `cors.allowedOrigins` refuses to start, naming `cors` and the slot,
     unless a loaded module relocates it (the standalone template's `http`
     module names `http.cors.allowedOrigins`); one with no `httpSettings`
     provider mounts no CORS. The `cors_allowed_origins_unreadable` warning
     is gone, as the module that provides the slot refuses such a value at
     boot.
   - **Messages name the new paths.** `core.federations.<name>…` for the
     federation checks, `key-store.local.*` and `KEY_STORE_LOCAL_*` for the key
     store's, `REPOSITORIES_USER_HTTP_BEARER_TOKEN` for the Store credential's:
     a log alert matching the old text needs the new one.

7. **Registered redirect URIs: query names.** Check every
   `allowedRedirectUris`, `postLogoutRedirectUris` and
   `federationGrantRedirectUris` entry, and every Client ID Metadata Document
   you depend on, and every entry a custom `ClientRepository` returns. Three
   cases:

   - **Newly refused registrations.** A query name outside `[A-Za-z0-9_-]`
     (`?filter[x]=1`, `?a.b=1`), a parameter with no name, a `;` anywhere in
     the query, or one of `code`, `state`, `iss`, `error` and
     `error_description` (compared ignoring case, `_` and `-`), on any of the
     three lists; and, on `federationGrantRedirectUris`, `grant_id` under
     another case or separators (`GRANT_ID`, `grantId`, `_grant_id`,
     `grant-id`). Such an entry used to be accepted. Now a `yaml` / `static`
     client fails boot, with the messages in
     [§1](#boot-refusals-you-will-meet); a CIMD client cannot be resolved
     (`400 invalid_client` at `/authorize`, with the
     `cimd_document_rejected` warning); and a federation-grant return URI
     held by a custom `ClientRepository`, which bypasses that check, is
     refused when a grant is lodged: `400 invalid_request` with
     `redirect_uri_invalid` (`redirect_uri_reserved_parameter` for a
     `grant_id` spelling).
   - **Refusals whose reason changed.** A `federationGrantRedirectUris`
     entry carrying `state` or `error` was already refused, at boot and at
     lodging. Boot still refuses it. Lodging now answers
     `redirect_uri_invalid` where it answered
     `redirect_uri_reserved_parameter`; both are `400 invalid_request`, so
     only an alert or client keyed on the `error_description` text sees the
     difference.
   - **A custom `ClientRepository`'s entries.** Such a repository bypasses
     the boot check. The `/oauth` router and the client authentication read
     its records through core's client-record boundary, which holds them to
     the same schema: a record with an `allowedRedirectUris` or
     `postLogoutRedirectUris` entry that `checkRedirectUri` refuses — any
     shape, the query rules included — is refused whole, and its client is
     unknown. `/oauth/authorize` answers `400 invalid_client` with no
     redirect, after the login step; logout drops the redirect; and the
     boundary warns `client_record_refused` ([§4](#4-alerts)). A consent
     request parked for such a client before the upgrade is answered
     `400 invalid_request` and dropped.

   Rename or remove such parameters, and carry the client's context in
   `state` or in the path. The rule covers names as written and the common
   normalizations, not a mapping a client configures (an alias, a stripped
   prefix): make sure each client reads the OAuth fields by their canonical
   names.

### Rolling out

- The image is `node:26-alpine`, digest-pinned, with `tini` and a `runtime`
  stage that carries compiled JS and production dependencies only
  (`templates/standalone/Dockerfile`). `pnpm install --frozen-lockfile` means
  a committed `pnpm-lock.yaml` and `pnpm-workspace.yaml` are build inputs.
- CI builds the template against packed tarballs on Node 24 and runs every
  package's suite. It also builds the Dockerfile's `node-base` stage from the
  pinned digest and, inside that image, installs the same tarball-wired
  dependency set frozen, builds it, and loads `bcrypt` — so a broken digest, a
  corepack pin that no longer installs, or a native addon without a musl
  prebuild for the pinned Node fails there, not in your first `docker build`
  (`.github/workflows/ci.yml`, publish-readiness). The `runtime` stage's
  assembly is not run in CI; your image build is still the first place a
  problem in that stage shows up.
- A replica drains for `drainTimeoutMs` (default 10 s) on `SIGTERM` and exits
  non-zero if it ran out of time; keep that below the orchestrator's kill grace
  period (`templates/standalone/src/shutdown.mts`).
- Under `CORE_DEPLOYMENT_MODE=multi`, a mixed fleet during the roll is fine for
  every Redis-backed store — the schemas below are what decide whether the
  *older* release can read what the *newer* one wrote. The one exception is
  v0.16.0, which moves DPoP onto the replay seen-set: its replay records
  change keys, so a mixed fleet opens a replay window (see the DPoP note in
  [Before you upgrade](#before-you-upgrade)).
- An authorization code carries the `amr` its `/authorize` vouched for, and
  `/token` stamps that, not the session record's. A mixed fleet issues and
  redeems codes across releases for at most one code lifetime
  (`redis-code-repository.defaultExpiresIn`, 600 s by default) after the
  roll, but what those codes mint outlives them:

  - a code an older replica issued, redeemed by this release, yields tokens
    without `amr`, and the refresh grant carries none forward at every
    refresh until the token's family ends — `oauth.refreshToken.expiresIn`
    after the login that began it (a day by default) — or the user signs in
    again. Under `mfa.mode = "required"` such a family is refused at its
    first refresh (`400 invalid_grant`), and the relying party authorizes
    again;
  - a code this release issued, redeemed by an older replica, is stamped
    with the session record's `amr`, as before — which differs only for a
    session that recorded a second factor between `/authorize` and `/token`
    — and the refresh grant carries that forward the same way.

  Under `oauth.refreshToken.unknownFamilyPolicy = "accept"` a token with no
  family record has no such bound. A deployment for which that matters
  revokes the families issued during the roll, or calls
  `revokeAllForSubject` for the subjects concerned, once the fleet is on the
  new release; the rest waits a family lifetime.
- **Do not turn `mfa.mode` on until no replica older than the release in
  which an authorization code carries its own `amr` remains.** A session's
  step-up raises its record in place: an older replica redeeming a code
  stamps the record's `amr` — the step-up's, for a code minted before it —
  and a replica older than the renewal nonce admits an old cookie put back
  after a step-up. Roll the whole fleet first, then switch the mode.

### Rolling back — state written by a newer release

- **Refresh-token families** are parsed with a `.strict()` schema: a record
  carrying a field the reading release does not know is `corrupt-data` and the
  refresh is refused (`packages/redis/src/refresh-token-family.mts`). If a
  release note says the family record gained a field, a rollback across it
  forces a re-login for every family written by the newer code. No release up
  to `v0.11.0` has changed that record.
- **Authorization codes** written before v0.5.1 lack `client_id`/`redirect_uri`
  and are treated as corrupt by every later release
  (`packages/redis/src/code-repository.mts`); they are ≤ 600 s old anyway.
- **New key families** (`ft:idx:` since v0.10; `ss:sub:` / `ss:rev:` since
  v0.11.0, `#321`) are never read by a release that predates them and expire
  on their own TTLs. Rolling back across v0.11.0 loses subject-level
  revocation on the Redis branch — the older release answers `unavailable`
  for it — and rolling back across v0.10 leaves logout on the keyspace scan.
- **Config keys the older release does not declare** do not fail its boot: a
  key inside a declared section is stripped by that release's Zod schema, and
  an unknown top-level section is carried through unread
  (`validateAndComposeConfig`, `packages/core/src/boot/validate-manifests.mts`).
  Either way the older release stops reading it. Retired-key tombstones, by
  contrast, fire in the forward direction only.
- **Signing keys** need nothing: `previousKeys` entries are plain config, and
  a rolled-back release verifies whatever kids it is configured with.
