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
(`templates/standalone/config/application.conf` and core's
`packages/core/config/reference.conf`). A composition root of your own reads
the same HOCON keys through whatever binding you gave them.

---

## 1. Deployment shapes

### `deployment.mode` — say how many replicas you run

`deployment.mode` (env `DEPLOYMENT_MODE`) has three states and **no default**
(`packages/core/config/reference.conf`, `packages/core/src/boot/replica-safety.mts`):

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
| `memorySessionStores` | user sessions, RP registrations, family indexes and the subject-level revocation pair — back-channel logout reaches only the replica that received it; a credential change watermarks only the replica that handled it |
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
| `sessionStoreModule` (only with `session.storage.type = "memory"`, `SESSION_STORAGE_TYPE=memory`; #474) | the express-session store — a login served by one replica is unknown to the others, so a browser whose next request lands elsewhere is logged out, and every session is lost on restart |

DPoP keeps no store of its own: every accepted proof is recorded in the
seen-set above (`dpop-proof:<jkt>`), so `core-replay-seen-set-memory` is what
refuses a DPoP deployment under `multi` and names it in the unset-mode
warning, and `redisReplaySeenSetModule` (`REPLAY_SEEN_SET_ADAPTER=redis` in the
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
  see peers. Set `DEPLOYMENT_MODE=multi` as part of scaling, not after
  something breaks.
- **It only sees modules that declare themselves.** The standalone template's
  own in-memory modules — `standalone:in-memory-session-stores`,
  `standalone:in-memory-code-repository` and
  `standalone:in-memory-federation-token-store`
  (`templates/standalone/src/modules.mts`) — carry the declaration since #455,
  so `multi` refuses them by name; before #455 they booted. Three more joined
  them in #474 and are refused the same way: express-session's own store under
  `SESSION_STORAGE_TYPE=memory`, and the login and WebAuthn-options rate
  limiters when no shared `rateLimiter` is wired. With the mode **unset**
  express-session's store joins the single `replica_unsafe_adapters` warning,
  and the two rate limiters warn on their own (`login_rate_limiter_not_shared`,
  `webauthn_authentication_options_rate_limiter_not_shared`, [§4](#4-alerts)).
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

In the standalone, `DEPLOYMENT_MODE=multi` therefore boots only once every
store is on Redis: `USER_SESSION_STORES_ADAPTER=redis`,
`OAUTH_CODE_ADAPTER=redis`, `RATE_LIMITER_ADAPTER=redis`,
`ACCESS_TOKEN_DENYLIST_ADAPTER=redis`, `SESSION_STORAGE_TYPE=redis`, and
`FEDERATION_TOKEN_STORE_TYPE=redis` together with
`REDIS_FEDERATION_TOKEN_STORE_ENCRYPTION_KEY` (a base64 string that decodes to
exactly 32 bytes — the AES-256 key, e.g. `openssl rand -base64 32`; the builder
refuses any other length; `templates/standalone/src/buildModules.mts`,
`packages/core/config/reference.conf`). The consent step for clients that are
not first-party is off by default (`CONSENT_STORE_ADAPTER=none`); to serve such
clients under `multi`, set `CONSENT_STORE_ADAPTER=redis` — `memory` is refused
there (#561; `packages/redis/src/consent-store.mts`).
A deployment that ran `multi` with the default in-memory federation-token store
before #455/#456 is refused at boot once they land — set the last pair before
upgrading. `federationTokenStore.type` and `redisFederationTokenStore.*` are
declared in the standalone's config schema since #456, so the switch and the key
survive `AppConfigSchema` and reach `buildModules`.

### The standalone production compose

`templates/standalone/docker-compose.production.yml` is the deployable shape:
the `runtime` image target, no source mounts, `restart: unless-stopped`, a
Redis reachable only on the compose network and persisting to a volume
(`--appendonly yes`), a **required** `.env`, and the signing-key pair mounted as
compose secrets at `/run/secrets/jwt_private_key` / `jwt_public_key`. Its
`environment:` block pins `NODE_ENV=production`, `DEPLOYMENT_MODE=single`,
`SESSION_SECURE=true`, `SESSION_NAME=__Host-auth.session`,
`SESSION_STORAGE_TYPE=redis`, `USER_SESSION_STORES_ADAPTER=redis`,
`RATE_LIMITER_ADAPTER=redis`, and both Redis URLs to `redis://redis:6379`. The
app port is published on loopback only (`127.0.0.1:3000:3000`).

The user-session line is there for a reason the replica guard cannot supply.
Under `DEPLOYMENT_MODE=single` the guard is silent by design — it answers "can
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
transaction cookie — `session.name` with any `__Host-` / `__Secure-` prefix
stripped, then `__Secure-` and `.federation` applied, so the default
`__Host-auth.session` yields `__Secure-auth.session.federation` — and
`__Secure-` does not stop another host under the same registrable domain (for
`auth.example.com`, any `*.example.com`) setting a cookie of that name with
`Domain=example.com`. A related-domain attacker — a forgotten staging host, a
dangling DNS record, XSS on a lower-trust app next door — can use that to log a
victim's browser into the attacker's own federated account. It reaches no
session and no credential, and there is nothing to configure: the mitigation is
that no untrusted content runs on any host under the auth host's registrable
domain. `session.domain = null` protects the session cookie, not this one.
Stated in full, with what the attacker needs and what it gets them, in
[`packages/session/README.md`](../packages/session/README.md#every-host-on-the-auth-hosts-registrable-domain-is-inside-the-trust-boundary)
(#502).

### Inputs with no default

Boot fails on each of these rather than guessing. All are validated at
config-parse time unless noted.

| Setting (env) | Rule | Where enforced |
| --- | --- | --- |
| `oauth.jwt.issuer` (`OAUTH_JWT_ISSUER`) | absolute `https` URL (`http` only for a loopback host), no query or fragment; never derived from `Host` | `packages/core/src/config/application.schema.mts` via `packages/core/src/issuer/canonical.mts` |
| Signing key material (`OAUTH_JWT_PRIVATE_KEY_PATH` + `OAUTH_JWT_PUBLIC_KEY_PATH`, or the inline `OAUTH_JWT_PRIVATE_KEY` / `OAUTH_JWT_PUBLIC_KEY`) | required for `EdDSA` (the default), `ES256`, `RS256`; the boot error prints the `openssl` commands | `packages/core/src/keys/factory.mts` |
| `OAUTH_JWT_SECRET` (only with `OAUTH_JWT_ALGORITHM=HS256`) | at least 32 bytes of key material, measured on the *decoded* length of hex/base64 | `packages/core/src/keys/secretEntropy.mts`, applied in `keys/factory.mts` |
| `session.secret` (`SESSION_SECRET`) | same 32-byte floor | `application.schema.mts` (`fullSectionsSchema.session.secret`) |
| `session.name` / `session.secure` / `session.domain` | a `__Host-` cookie name (the default) requires `secure = true` and `domain = null` (checked when the session route is built, not at config parse); `sameSite = "none"` requires `secure = true` | `packages/session/src/modules/sessionStoreModule.mts`; `application.schema.mts` |
| `repositories.user.http.authenticateUrl` / `authenticateByTokenUrl` (`CLIENT_USER_AUTHENTICATE_URL`, `CLIENT_USER_AUTHENTICATE_BY_TOKEN_URL`) | absolute `https` (loopback `http` only); `timeout` a positive integer ≤ 2147483647 ms. Whether an endpoint redirects cannot be checked at construction, so it is required all the same: each URL is the endpoint that answers — a `3xx` is not followed, so a URL that redirects fails every call ([foundation README](../packages/foundation/README.md#what-the-store-must-enforce-itself)) | `packages/foundation/src/repositories/HttpUserRepository.mts` |
| `repositories.user.http.bearerToken` (`CLIENT_USER_BEARER_TOKEN`) | optional — unset sends the Store no `Authorization` header. Set, including exported but empty, and `repositories.user.type = "http"` (`CLIENT_USER_TYPE`; the standalone's default — core's `reference.conf` defaults to `yaml`, which never reads the `http` block): a bare RFC 6750 token (no `Bearer ` prefix, no whitespace) with at least 32 bytes of key material, measured like `SESSION_SECRET`; the message never quotes the value. One token goes to all four Store URLs, so they must be one trust domain. The Store should refuse every request without it, with `401` (or `403`) and a `Bearer` challenge; a token it refuses is not a boot failure but an outage on every Store call (see the Store row in [§3](#3-what-fail-closed-looks-like-on-each-path); [foundation README](../packages/foundation/README.md#what-the-store-must-enforce-itself)) | `packages/foundation/src/repositories/HttpUserRepository.mts`, with core's `keys/secretEntropy.mts` |
| `refreshTokenFamilyStore.redis.url` (`REFRESH_TOKEN_FAMILY_STORE_REDIS_URL`) | required whenever any Redis adapter is selected — it is the one shared socket | `templates/standalone/src/modules.mts` (`standaloneRedisClientsModule`) |
| `rateLimit.failMode` (`RATE_LIMIT_FAIL_MODE`) | `"open"` or `"closed"`; `reference.conf` ships `"closed"` | `application.schema.mts`; read by every guarded route |
| `audit.sink.type` (`AUDIT_SINK_TYPE`) | a registered sink name. Core accepts `"none"` as a declaration; the standalone registers no `"none"` builder, so there an unknown type (including `none`) fails boot naming the sinks that exist | `packages/core/src/audit/types.mts` (`AUDIT_SINK_ABSENCE_POLICY`); `templates/standalone/src/modules.mts` (`auditSinkModule`) |
| `oauth.deviceAuthorization.verification-uri` | required once `oauth.deviceAuthorization.enabled = true`; the device displays it verbatim | `packages/device-grant/src/module.mts` |
| `oauth.mtls.full-pki.revocation.mode` / `.on-unavailable` / `.allowed-hosts` | all three required under `mode = "full-pki"` with `revocation.mode` ∈ `"crl"`, `"ocsp"`, `"both"` (`allowed-hosts` covers CRL distribution points and OCSP responders alike); there is no default for what an outage means | `packages/mtls/src/module.mts`, `packages/mtls/src/reference.conf` |
| `http.readinessTimeoutMs`, `session.csrf.ttlSeconds`, token lifetimes, `session.maxAge` | positive integers. An **exported-but-empty** variable is `""`, which coerces to `0` and is refused — the failure it prevents is a zero lifetime or a probe that always times out | `application.schema.mts` |
| `oauth.accessToken.defaultExpiresIn` / `maxExpiresIn` (`OAUTH_ACCESS_TOKEN_DEFAULT_EXPIRES_IN` / `OAUTH_ACCESS_TOKEN_MAX_EXPIRES_IN`) | the default must not exceed the max; the message names both keys. An unset max is the default, and an unset default is the deprecated `oauth.accessToken.expiresIn` (shipped `3600`) — so a max below `3600` set on its own fails until the default is lowered too | `application.schema.mts` (`resolveAccessTokenLifetime`) |

### Boot refusals you will meet

Every boot-time failure is a `BootError` with a `reason` and a `stage`
(`packages/core/src/boot/types.mts`). The ones an operator meets, and the key
each names:

| `reason` | Trigger | What to change |
| --- | --- | --- |
| `module-factory-not-called` | a `modules` entry is a module factory listed without being called — `deviceGrantModule` for `deviceGrantModule({ config })`, `sessionStoreModuleFor` for `sessionStoreModuleFor(config)`. The compiler accepts it (a function has a `name`), and it used to boot as a module that did nothing (`packages/core/src/boot/validate-manifests.mts`) | the message names the entry and its index; call it with its arguments |
| `config-validation-failed` | a Zod issue from the table above, or a retired key still present (see [§7](#7-upgrading-and-rollback)) | the issue path names the key |
| `missing-required-component` | a module's `requires` has no provider. The standalone adds `standalone:redis-clients` whenever an adapter switch selects Redis, so there this only arises through `BuildModulesOverrides` (`templates/standalone/src/buildModules.mts`) | the message names the missing slot and the requiring module |
| `component-absence-undeclared` | an optional slot with an `AbsencePolicy` is unfilled and config does not declare it absent (`packages/core/src/modules/manifest/absence-policy.mts`, enforced by `checkDeclaredAbsence` in `boot/validate-manifests.mts`) | wire the component, or write the declaration: `audit.sink.type = "none"` (auditSink), `oauth.revocation.accessToken = "unsupported"` (accessTokenDenylist), `oauth.revocation.subject = "unsupported"` (subjectRevocation + subjectSessionIndex), `oauth.deviceAuthorization.store = "unsupported"` (deviceCodeStore; only with the grant left off — an enabled grant needs a store) — sources: `core/src/audit/types.mts`, `core/src/access-token-denylist/types.mts`, `core/src/user-sessions/types.mts`, `packages/device-grant/src/reference.conf` |
| `replica-unsafe-adapter` | `deployment.mode = "multi"` with a listed module wired | the message lists every offender; switch the adapter or set `single` |
| `federation-stores-incomplete` | `federations.<name>.enabled = true` without all of `userSessionStore`, `sessionRPRegistry`, `sessionFamilyIndex`, `sessionFederationIndex`, `federationTokenStore`, `refreshTokenFamilyRevocation` | the message lists the missing slots |
| `grant-policy-without-issuer` | a `grantPolicy` is wired and `oauth.jwt.issuer` is empty | set the issuer |
| `provides-factory-failed` / `contribute-factory-failed` | a module's own check threw; the module's message is the `cause` (`boot/materialize-components.mts`) | see the module messages below |

Module-level messages that arrive wrapped in a factory failure:

- Keys: `privateKey or privateKeyPath is required for EdDSA algorithm — no signing key is configured` (with the `openssl` commands); `Duplicate kid values: …`; `previousKeys is not valid for HS256 — use previousSecrets` and the mirror for asymmetric algorithms (`packages/core/src/keys/factory.mts`).
- Standalone Redis: `` `refreshTokenFamilyStore.redis.url` is required when any Redis-backed adapter is selected `` (`templates/standalone/src/modules.mts`).
- Federation grants (#593): the same guard, the same environment variable, and
  the message names `[federation-grants]` rather than `[federation-tokens]`
  (`packages/redis/src/internal/encryption-mode.mts`). One more refusal of its
  own: `mode "required" needs at least one encryption key`, at construction
  rather than at the first write — a ring that cannot seal would otherwise be
  discovered after a user had already consented. A read never re-seals, so
  dropping the key that sealed a grant makes it read `key_unavailable` until
  it is put back; the rotation procedure below says when a key may leave.
- Federation tokens: `mode "allow-plaintext" is refused because the environment is "production"` — the environment is the one the config was selected by (`CONFIG_ENV`, or `NODE_ENV`) *or* `NODE_ENV` itself — and `… because deployment.mode is "multi"` in every environment (#473); either way unless `FEDERATION_TOKENS_ALLOW_INSECURE=1`, which then logs a `CRITICAL` line on every boot (`packages/redis/src/federation-tokens.mts`).
- Per-process rate-limit fallbacks under `deployment.mode = "multi"` (#474): `deployment.mode is "multi" but no shared rateLimiter is wired for POST /session/login` and the same for `POST /oauth/webauthn/authentication/options` — a `replica-unsafe-adapter` BootError as the `cause`. Wire `rateLimiter.adapter = "redis"` or set `single` (`packages/session/src/routes/Session.mts`, `packages/webauthn/src/module.mts`).
- DPoP with no seen-set: `dpopModule: oauth.dpop.enabled = true requires a replaySeenSet component`, in every `deployment.mode`. Install `memoryReplaySeenSetModule` (one replica) or `redisReplaySeenSetModule`, or leave DPoP disabled (`packages/dpop/src/module.mts`). Under `multi` the memory one is then refused by the replica-safety guard, as `core-replay-seen-set-memory`.
- Device grant: the six refusals for `verification-uri`, the `session` slice, `rateLimit.failMode`, a `rateLimiter` component, a usable `oauth.deviceAuthorization.rateLimit` budget (#448), and — with the grant enabled — a `deviceCodeStore` component, which `oauth.deviceAuthorization.store = "unsupported"` does not stand in for (#626); and a seventh, `built from a config with the grant on, but the config createApp validated has oauth.deviceAuthorization.enabled off` (or the reverse) — hand `deviceGrantModule({ config })` the same config as `bootstrapComponents.config` (`packages/device-grant/src/module.mts`). The factory listed uncalled is `module-factory-not-called`, in the table above. There is no refusal for an enabled grant without `oauthModule`: it boots, but nothing can redeem the device codes it hands out, so compose it with the token endpoint.
- mTLS: `source = "header"` with empty `trusted-proxies`; `mode = "pki"`/`"full-pki"` with empty `trusted-cas`; `mode = "pki"` with `source = "tls-layer"`; `full-pki` without `revocation.mode` + `on-unavailable`; `revocation.mode` ∈ `"crl"` / `"ocsp"` / `"both"` with empty `allowed-hosts` (`packages/mtls/README.md` "Boot-time fail-loud invariants", `packages/mtls/src/module.mts`).
- Remote signing: `the signer's output does not verify against publicKeyPem for kid "…"` — the boot self-check in `createRemoteSigningKeyStore` (`packages/core/src/keys/remoteSigning.mts`).

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
**message** goes to the log as `readiness_probe_failed` (warn) with the failing
checks, because a driver message like `connect ECONNREFUSED 10.0.3.14:6379`
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
| Shared Redis down — **rate limiter**, `rateLimit.failMode = "closed"` (default) | `/oauth/token`, `/oauth/authorize`, `/oauth/introspect`, `/session/login`, `/oauth/device_authorization`, `/oauth/device/verification`, WebAuthn authentication options | `503 service_unavailable` "Rate limiter temporarily unavailable" | `rate_limiter_failed_closed` (error, with `tag`, `ip`, `error`); audit `rate_limit.unavailable` (`packages/core/src/ratelimit/guard.mts`) | one `commandTimeout` (1 s) per request in the standalone; see [§5](#failure-timing-on-the-shared-socket) |
| — same, `failMode = "open"` | same | request proceeds unlimited | `rate_limiter_failed_open` (error); audit `rate_limit.unavailable` | same |
| — **device verification** | `POST /oauth/device/verification` | the same policy, applied by the handler itself because its budget is keyed per subject rather than per IP (#457): `503 service_unavailable` under `closed`; under `open` the lookup / approval / denial proceeds. A limiter that *answers* "no" is not an outage — `429 slow_down` and `device.rate_limited` are unchanged under either mode | `rate_limiter_failed_closed` / `rate_limiter_failed_open` with `tag: "device_verification"`; audit `rate_limit.unavailable` (`packages/device-grant/src/verificationEndpoint.mts`, through core's `checkWithFailMode`) | `commandTimeout` |
| Shared Redis down — **refresh grant** | `grant_type=refresh_token` | `503 temporarily_unavailable` for a family-store, session-store, watermark or keystore outage (`packages/oauth/src/grants/refreshToken.mts`); the client keeps its token and retries | `token_verification_unavailable` (error, `site: "refresh_token"`, `reason`) for the watermark and keystore cases; `refresh_token_store_unavailable` (error, `store`, `step`: `rotate` / `revoke`) for the family and session stores | `commandTimeout`; CAS retries capped at `redisRefreshTokenFamilyStore.casRetryLimit` (default 3) then `conflict-exhausted` (`packages/redis/src/refresh-token-family.mts`) |
| Refresh-token **replay** (not an outage) | same | `400 invalid_grant` `replay_detected`; the whole family is revoked inside the same compare-and-swap (`packages/core/src/refresh-token-family/rotation.mts`) | — | — |
| Shared Redis down — **authorization code** | `GET/POST /oauth/authorize` | redirect with `error=server_error` "Failed to create authorization code" (`packages/oauth/src/routes/authorize.mts`) | — | `commandTimeout` |
| | `grant_type=authorization_code` | `503 temporarily_unavailable` "session store unavailable" when the code's session cannot be read (`packages/oauth/src/grants/authorization.mts`) | — | `commandTimeout` |
| Shared Redis down — **user session stores at login** | `POST /session/login` | `503 temporarily_unavailable` "Session store temporarily unavailable" when `userSessionStore.create` fails. If only the subject index write fails, the login **succeeds** and that session is invisible to a later credential-change cascade (`packages/session/src/routes/Session.mts`) | `subject_session_index_write_failed` (error) | `commandTimeout` |
| Shared Redis down — **denylist / watermark at verification** | every surface that accepts an access token: `/oauth/introspect`, `/oauth/userinfo`, `POST /oauth/federation/:name/token`, token exchange, the refresh grant | `503 temporarily_unavailable` ("revocation store unavailable"; "subject_token validation store unavailable" at token exchange), with no `WWW-Authenticate` challenge at a protected resource — never `401 invalid_token` or introspection's `active: false`, which would tell the client to replace a token nobody could judge (`packages/core/src/jwt/verify.mts` `isVerificationUnavailable`, `packages/oauth/src/verificationUnavailable.mts`) | `jwt_verify_rejected` (warn) with `reason: "revocation_unavailable"` for either store — a denylist failure and a watermark failure are the same outage, and neither is reported as `revoked` (#408 / #459); `token_verification_unavailable` (error, `site`, `reason`, the error's projection); `token_exchange_validation_unavailable` (error); audit `introspect.store_unavailable` | `commandTimeout` |
| Shared Redis down — **access-token denylist / refresh-token family store at revocation** | `POST /oauth/revoke` for a token that verified and belongs to the calling client | `503 temporarily_unavailable` "token revocation is temporarily unavailable; retry the request" (RFC 7009 §2.2.1): the client must assume the token still exists and retry. A token that does not verify, or belongs to another client, never reaches the store and is still `200` (`packages/oauth/src/routes/revoke.mts`) | `revoke_store_unavailable` (error, `store` ∈ `accessTokenDenylist`, `refreshTokenFamilyRevocation`; `clientId`) | `commandTimeout` |
| Shared Redis down — **refresh-token family store or session store at a protected resource** | `/oauth/introspect`, `/oauth/userinfo`, `POST /oauth/federation/:name/token`, `POST /oauth/federation/:name/logout`, token exchange | `503 temporarily_unavailable` ("refresh token store unavailable" / "session store unavailable"), no challenge — not `401 invalid_token` or `active: false` (`packages/oauth/src/routes.mts`, `routes/userinfo.mts`, `routes/federationToken.mts`, `routes/logout.mts`) | `introspect_store_unavailable`, `userinfo_store_unavailable`, `federation_token_store_unavailable`, `federation_logout_store_unavailable`, `token_exchange_family_store_unavailable` (error, with `store`, a `step` where the store has more than one operation, and the error's projection — one line per 503, never a warn); audit `introspect.store_unavailable` | `commandTimeout` |
| Shared Redis down — **session stores and federation token store at the federation routes** | `POST /oauth/federation/:name/token`, `POST /oauth/federation/:name/logout` | `503 temporarily_unavailable` ("session store unavailable" / "federation token store unavailable") (`packages/oauth/src/routes/federationToken.mts`, `routes/logout.mts`) | `federation_token_store_unavailable` / `federation_logout_store_unavailable` (error) with `federation`, `store` ∈ `user_session`, `session_federation_index`, `federation_token`, and `step` (`get`, `list`, `acquire_lock`, `get_after_lock`, `update`, `delete`, `remove`) | `commandTimeout` |
| Shared Redis down — **session stores at RP-initiated logout** | `GET`/`POST /oauth/logout` | `503 temporarily_unavailable` ("session store unavailable"; "logout cascade failed" when the cascade stops), and the browser session is kept so a retry can finish (`packages/oauth/src/routes/logout.mts`, `logout/cascadeLogout.mts`) | `logout_store_unavailable` (error): `store: "user_session"`, `"session_rp_registry"` or `"session_federation_index"` with `step`; or `store: "logout_cascade"` with `cascadeStep` (1, 2 or 4), the number of `failures` and the first failure's projection. Each failed cascade operation also has its own `logout_cascade_operation_failed` (warn); audit `logout.cascade_failed` | `commandTimeout` |
| Shared Redis down — **session stores and family store at the code exchange and the session grant** | `grant_type=authorization_code`, `grant_type=session` | `503 temporarily_unavailable` ("session store unavailable", "refresh token store unavailable", "session linking unavailable") (`packages/oauth/src/grants/authorization.mts`, `grants/session.mts`) | `authorization_grant_store_unavailable` (error) with `store` ∈ `user_session`, `refresh_token_family`, `session_family_index`, `session_rp_registry` and `step`; a client lookup there is `client_repository_unavailable` with `site: "authorization_code"`; `session_grant_store_unavailable` (error, `store: "user_session"`) | `commandTimeout` |
| **Upstream IdP unreachable** during a federation token refresh | `POST /oauth/federation/:name/token` | `503 temporarily_unavailable` "upstream federation provider temporarily unavailable"; an upstream that answered but refused is its verdict — `410` / `429` / `500` (`packages/oauth/src/routes/federationToken.mts`) | `federation_token_upstream_unavailable` (error, `reason: "network"`); the refusals are `federation_token_refresh_failed` (warn, with `reason`) | the provider's HTTP timeout |
| **Keystore cannot answer a key lookup** — a `KeyStore` of your own whose `getVerificationKey` throws anything but `UnknownKidError` / `ExpiredKidError` (a remote key service timing out). The bundled stores hold their keys in memory, so a lookup of theirs ends only in one of those two findings. A `kid` header that is not a well-formed key id — not a string, empty, longer than `MAX_KID_LENGTH` (256), or carrying a control character (`isWellFormedKid`) — is refused as `kid_unknown` before any keystore is asked — it cannot be made to read as an outage; a configured kid of that shape is refused at boot, by `oauth.jwt.signingKey` and by every bundled keystore — and a lookup error named `UnknownKidError` / `ExpiredKidError` is read as that finding even from another copy of core | every route that verifies a token this provider signed: introspection, userinfo, the federation token and logout routes, `/oauth/logout` (`id_token_hint`), `/oauth/revoke`, the refresh grant, token exchange | `503 temporarily_unavailable` ("verification key unavailable"; `/oauth/revoke`: "token revocation is temporarily unavailable; retry the request", RFC 7009 §2.2.1 — nothing was revoked; token exchange: "… validation store unavailable"). A kid the keystore does not hold is still the client's fault (`401` / `400` / `active: false` / revoke's `200`) | `jwt_verify_rejected` (warn) with `reason: "verification_key_unavailable"`; `token_verification_unavailable` (error) with `site`, and the keystore's error as the projected error's `cause`; `token_exchange_validation_unavailable` (error) | your keystore's own timeout |
| Shared Redis down — **replay seen-set** (`REPLAY_SEEN_SET_ADAPTER=redis`) | a DPoP proof at `/oauth/token` or at a protected resource; a `private_key_jwt` client assertion (`/oauth/token`, `/oauth/introspect`, `/oauth/revoke`, `/oauth/device_authorization`, and the federation-grant client routes — `/oauth/federation-grants/:grantId/token`, `/status`, `/revoke`, and with acquisition on `POST /oauth/federation-grants` and `/:grantId/reauthorize`); an ID-JAG assertion (`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`) when the composition hands the jwt-bearer verifier this seen-set | `503 temporarily_unavailable`, with no `WWW-Authenticate` challenge at a protected resource: the proof or assertion is refused unrecorded, not judged invalid, so the client keeps its tokens and retries (`packages/dpop/src/verifier.mts`, `packages/core/src/middleware/tokenBinding.mts`, `protectedResourceBinding.mts`, `packages/oauth/src/middleware/clientAssertion.mts`, `packages/oauth/src/grants/jwtBearer.mts`) | `token_binding_unavailable` / `protected_resource_binding_unavailable` (error, `mechanism: "dpop"`, `reason: "replay_store_unavailable"`, the store error's projection) for DPoP — one line, from the dispatcher that answers the 503; `client_assertion_refused` (error, `reason: "replay_store_unavailable"`); `jwt_bearer_assertion_verifier_unavailable` (error) | `commandTimeout` |
| | the WebAuthn ceremony — `grant_type=urn:o3co:oauth:grant-type:webauthn` and `POST /oauth/webauthn/registration/verify` | the ceremony's `contains` / `markSeen` error is not caught on the way out (`packages/core/src/challenges/ceremony.mts`), so the request ends in the terminal handler: `500 server_error` in the standalone (`templates/standalone/src/terminalError.mts`). A `markSeen` failure comes after the challenge was consumed, so the user starts the ceremony again | `unhandled_request_error` (error) | `commandTimeout` |
| **Cookie session store** (connect-redis, its own node-redis client) down | every browser-session route | express-session hands a store error to `next(err)`, which the standalone's terminal handler answers as `500 server_error` (`templates/standalone/src/terminalError.mts`); the federation start/callback session saves answer `500 server_error` "Session store unavailable" themselves (`packages/session/src/routes/Federation.mts`) | `session_store_redis_error` (error) on every client error event, including during reconnect (`packages/session/src/store/factory.mts`); `readiness_probe_failed` for `session-store` | node-redis reconnects on its own; the provider no longer crashes on the `error` event |
| **KMS / remote signer** unavailable | any mint: `/oauth/token`, id tokens, logout tokens | nothing between `keyStore.sign` (`packages/core/src/grants/token.mts`) and the route catches a signer error, so it surfaces as `500 server_error` with `unhandled_request_error` — **except the `refresh_token` grant when a rotation was committed** (#449): there it is `503 temporarily_unavailable` plus a `refresh_token_rotation_orphaned` error log naming the family, and the client's retry presents a token that now reads as a replay, so that family is revoked and the user re-authenticates. Verification and `/.well-known/jwks.json` are **unaffected**: the public halves are imported at construction and served from memory (`packages/core/src/keys/remoteSigning.mts`) | `unhandled_request_error` | whatever timeout your `RemoteSigner` applies — the store applies none. Boot itself needs one signer call for the self-check unless `verifyOnConstruction: false` |
| **CRL distribution point or OCSP responder** unreachable, `full-pki`, `on-unavailable = "reject"` (`revocation.mode = "both"` asks OCSP first and falls back to the CRL — for an OCSP `unknown` the CRL is asked but may only refuse, since it cannot list a never-issued serial and so cannot clear one (#471); otherwise only when both fail is the status unavailable) | `/oauth/token` with a client certificate | `400 invalid_certificate` from the token-binding middleware (`packages/mtls/src/errors.mts`, `packages/core/src/middleware/tokenBinding.mts`) | `mtls_revocation_unavailable_rejected` (warn, per certificate, with the CRL `reason` ∈ `no_distribution_point`, `fetch_failed`, `unparseable`, `no_next_update`, `stale`, `bad_signature`, `unsupported_critical_extension`, `unsupported_crl_scope`, `algorithm_not_permitted`, or the OCSP `reason` ∈ `no_responder`, `fetch_failed`, `unparseable`, `responder_error`, `no_matching_response`, `unsupported_critical_extension`, `algorithm_not_permitted`, `bad_signature`, `nonce_mismatch`, `nonce_missing`, `not_yet_valid`, `stale`, `unknown`, `responder_revoked`, `responder_status_unavailable` (a delegated responder without `id-pkix-ocsp-nocheck`, checked against the CRL its certificate names under `both`, #468) (`OcspUnavailableReason` in `packages/mtls/src/fullPki/ocsp.mts`); `mtls_revocation_ocsp_fallback` (warn) when `both` moves on to the CRL; `mtls_ocsp_responder_unchecked` (warn, once per responder) when a delegated responder lacks `nocheck` and nothing can check it — under `ocsp`, or under `both` when its certificate names no CRL); `mtls_full_pki_validation_failed` (`step: "revocation status unavailable"`); `token_binding_proof_invalid` | `fetch-timeout-ms` (default 3000) — lookups for a path run in parallel so latency is the largest, not the sum; one in-flight fetch per URL; a failed URL is not retried for 30 s (`CRL_NEGATIVE_CACHE_TTL_MS` / `OCSP_NEGATIVE_CACHE_TTL_MS`, not knobs; `bad_signature` exempt); an OCSP answer is cached per certificate until its `nextUpdate`, capped by `cache-ttl-seconds`, and an undated answer for at most 10 min (`OCSP_UNDATED_RESPONSE_MAX_AGE_MS`); `max-response-bytes` (default 1048576); 256 cache entries (`packages/mtls/src/fullPki/crl.mts`, `fullPki/ocsp.mts`, `fullPki/validate.mts`, `packages/mtls/src/module.mts`) |
| — same, `on-unavailable = "allow"` | same | token issued | `mtls_revocation_unavailable_allowed` (warn) **per certificate waved through** — a permanent soft-fail is an unrevocable PKI wearing a revocation configuration | same |
| **Audit sink** failing | every audited route | nothing — `emitAuditEvent` dispatches without awaiting and swallows rejections (`packages/core/src/audit/factory.mts`) | nothing; drops are not counted (`templates/standalone/README.md` "Not published yet") | no latency is ever added |
| **Upstream IdP** down | the federation callback — `GET /session/oauth/federation/:name/callback`, or `POST` for a `form_post` federation such as Apple | `502 exchange_failed` "Token exchange with upstream IdP failed" (`packages/session/src/routes/Federation.mts`) | `federation token exchange failed` (warn) | the provider adapter's own fetch |
| | `POST /oauth/federation/:name/token` (upstream refresh) | `503 temporarily_unavailable` for a network failure, `429 rate_limited`, `410 re_authentication_required`, or `500 refresh_failed` (`packages/oauth/src/routes/federationToken.mts`) | audit `federation.token.reauthentication_required` / `federation.token.refresh_failed` | advisory lock in Redis (`ft:lock:`) |
| **Upstream IdP starts issuing sender-constrained tokens** | `POST /oauth/federation/:name/token` | `502 upstream_token_ineligible`, `error_description: token_type_unsupported`, `Retry-After: 300` — the token cannot be handed to a caller that holds no proof key, so it is refused rather than answered as `Bearer` (#645) | audit `federation.token.upstream_ineligible`, with `details.tokenType` naming what the record carried | not transient: it stands until the upstream client registration is changed back. After that, a record whose token has expired repairs itself on the next refresh, which re-records the type; one still inside its expiry stays refused until it expires, and a reconnect clears it at once |
| | `/oauth/federation/:name/logout` | `200 {"disconnected": true}` — local state is already cleared, the IdP session is orphaned (`packages/oauth/src/routes/logout.mts`) | audit `federation.logout.idp_unreachable` | — |
| **The Store** (user directory) down or slow, a configured Store URL answers with a redirect (no request follows one), or the Store refuses this deployment's `bearerToken` (`401` or `403` with `WWW-Authenticate: Bearer`) | `POST /session/login`; federation callback, a `?link=1` link included; jwt-bearer grant; the federation-grants connect callback (the identity lookup — its own row under [Acquisition refusals](#acquisition-refusals-an-operator-meets-593-slice-6-611)) | `503 temporarily_unavailable` "User directory temporarily unavailable" (`Session.mts`, `Federation.mts`); `503 temporarily_unavailable` "identity resolution unavailable" from the jwt-bearer grant (`packages/oauth/src/grants/jwtBearer.mts`) | `local login authenticate failed`, `user repository lookup failed`, `federation link: user repository failed` (warn); `jwt_bearer_user_repository_unavailable` (error). A redirect is the case whose logged `err` reads `Unexpected HTTP status 30x from <url>`: set the URL to the endpoint that answers, not one that redirects. A refused token is the case whose logged `err` is a `StoreCredentialRefusedError` reading `the Store at <url> refused this deployment's credential (HTTP 401 with a Bearer challenge)` (or `403`) on the login, federation and jwt-bearer lines; the federation-grants callback logs no error message, only `federation_grant.failure` with `classification: "store_credential_refused"`. Set `CLIENT_USER_BEARER_TOKEN` to a token the Store accepts. The token itself is never logged. A transport failure is a `StoreTransportError`: `request to <url> could not be reached` (refused, DNS, TLS — the network path or TLS), `the connection to <url> closed before a complete response arrived` (closed or reset first: an occasional one is a pooled keep-alive connection the Store, a proxy or an idle timeout closed between requests; a steady stream is the Store or a proxy closing mid-answer or restarting), `the Store at <url> answered with a malformed HTTP response` (the parser refused the status line or a header, or the head outgrew the size limit — a proxy or a wrong port), or `response from <url> could not be read` (the body broke mid-read), with at most a code such as `ECONNREFUSED` or `ERR_SSL_WRONG_VERSION_NUMBER` (an https URL on a plain-HTTP port) — never the transport's own error, which can quote what was sent; the federation-grants callback classifies it `store_transport_failed`. Two symptoms with no refused-credential line: **every login answers `401 invalid_credentials`** while the Store checks a token — `CLIENT_USER_BEARER_TOKEN` is unset (with no token sent, even a challenged `401` reads as "no such user"), or it is wrong and the Store refuses without a `Bearer` challenge; set the token, and have the Store send the challenge. **Refused-credential lines on some logins while correct passwords still succeed** — the token is fine; the Store is putting a `Bearer` challenge on user-level `401`s (a wrong password), which must carry none. Do not rotate the token for it | `repositories.user.http.timeout` (default 5000 ms) and `maxResponseBytes` (default 1048576) — a timeout is a thrown error, not a `null` user (`packages/foundation/src/repositories/HttpUserRepository.mts`) |
| **Client repository** lookup throws | client authentication on `/oauth/token`, `/oauth/introspect`, `/oauth/revoke`, device authorization and the federation-grant client routes — a secret (`findById` or `authenticate`) or a `private_key_jwt` assertion (`findById`) — the client lookup at `/authorize`, token exchange's own lookup, the federation token route's `azp` lookup and the code exchange's logout-metadata lookup | `503 temporarily_unavailable` "client repository unavailable", no `WWW-Authenticate` challenge — repository unavailability never admits a client, and is not answered `invalid_client` either: the client did nothing wrong, and a proxy holding client credentials would read `401 invalid_client` as its own misconfiguration. `/authorize` answers it as JSON (no redirect target is trusted yet); it was `500 server_error` "Failed to fetch client", unlogged. An unknown client or a wrong secret is still `401 invalid_client` (`400` at `/authorize`). A `client_id` that cannot name a client — a control character, or longer than 256 characters (`MAX_CLIENT_ID_LENGTH`) — is refused the same way before the repository is asked, so a store that throws on such input (a SQL driver refusing a NUL byte) cannot be made to answer `503` (`packages/oauth/src/middleware/clientAuth.mts`, `clientAssertion.mts`, `routes/authorize.mts`; the check is core's `isWellFormedClientId`) | `client_repository_unavailable` (error, `step`: `find` / `authenticate`, `clientId` sanitised and capped at 200 characters, the error's projection; `site` where it is not client authentication: `authorize`, `token_exchange`, `federation_token`, `authorization_code`) — every client lookup writes this one line through core's `logClientRepositoryUnavailable`; `client_assertion_refused` (error, `reason: "client_repository_unavailable"`) for an assertion | the repository's own I/O |
| **`grantPolicy` hook** throws | every grant; `/oauth/authorize` | `503 temporarily_unavailable` "policy evaluation unavailable" (`packages/core/src/grants/grantPolicy.mts`); redirect `error=temporarily_unavailable` at `/authorize` | `grant_policy_unavailable` (error, `grantType`, the policy's `kind`, `site: "authorize"` at `/authorize`, the error's projection) — from every oauth grant, token exchange and `/authorize`; a grant that evaluates the policy without passing its logger (webauthn today) stays silent | the hook's own |
| Shared Redis down — **consent step** (`CONSENT_STORE_ADAPTER=redis`) | `GET/POST /oauth/authorize` for a client that is not first-party; `GET/POST /oauth/consent` | `/authorize` redirects with `error=temporarily_unavailable` "consent store unavailable" — never a code, never a refusal the user could act on (`packages/oauth/src/routes/authorize.mts`); `/oauth/consent` answers `503 temporarily_unavailable` "consent store unavailable" (`packages/oauth/src/routes/consent.mts`) | `authorize_consent_store_unavailable`, `authorize_pending_consent_store_unavailable`, `pending_consent_store_unavailable`, `consent_store_unavailable` (error) | `commandTimeout` |
| Shared Redis down — **device-code store** (`redisDeviceCodeStoreModule`, `packages/redis/src/device-code-store.mts`; the in-memory adapter has no outage mode, and `multi` refuses it) | `POST /oauth/device_authorization`; `POST /oauth/device/verification`; the device polling `/oauth/token` | `503 temporarily_unavailable` "the device authorization store is unavailable; retry later" on all three, at once: `/oauth/device_authorization` re-draws only on the store's own collision signal (`packages/device-grant/src/deviceAuthorizationEndpoint.mts`); `/oauth/device/verification` (`verificationEndpoint.mts`) — an approval or a denial may already be recorded, so a retry can answer `409 already_decided`, audited as `device.decision_outcome_unknown`; the device's poll at `/oauth/token` is answered by the grant (`grant.mts`), as every grant answers a store outage — an approval it read may already be consumed, and the device's retry is then `invalid_grant` | `device_authorization_store_unavailable`, `device_verification_store_unavailable`, `device_code_grant_store_unavailable` (error) | `commandTimeout` |

Two cross-cutting facts about these rows:

- **Rate-limit `429`s carry `Retry-After` only when the adapter reports a
  reset time.** Both bundled adapters do: the memory adapter from its bucket,
  the Redis adapter from the counter key's PTTL, returned by the same Lua
  script as the count (`packages/redis/src/ratelimit.mts`, #458). A custom
  adapter whose decision has no `resetAt` — or a custom `RateLimiterClient`
  that implements only `incrementWithTtl` — still gets `RateLimit-Limit` /
  `RateLimit-Remaining` and no `Retry-After`
  (`packages/core/src/ratelimit/guard.mts`).
- **`/session/login` and the WebAuthn options route never run unguarded.**
  With no `rateLimiter` wired they fall back to a per-process memory limiter
  and say so once at boot (`login_rate_limiter_not_shared`,
  `webauthn_authentication_options_rate_limiter_not_shared`) — when
  `deployment.mode` is unset. Under `"multi"` the fallback is refused at boot
  like every other per-process store (#474, see [Boot refusals you will meet](#boot-refusals-you-will-meet)); under
  `"single"` it is silent. The OAuth endpoints, by contrast, run with no
  limiter at all in that case (`packages/oauth/src/routes.mts`).

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
| RP registry / back-channel `logout_token` fanout | not run | run |
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

---

### Linking a second federation to an account (#482)

A federated identity is `<provider>:<sub>`; the Store is the only place that
says which account it belongs to, and the provider never infers a match from
an e-mail. Linking is an explicit, authenticated action — the browser holds a
session and starts the federation with `?link=1` — and it fails closed at every
step: `401 login_required` without a session, `400 link_unsupported` when the
Store client has no `linkFederatedIdentityUrl`
(`CLIENT_USER_LINK_FEDERATED_IDENTITY_URL`), `409 identity_conflict` when the
identity is already another account's (the Store is not consulted),
`403 link_refused` / `409 identity_conflict` when the Store says so,
`503 temporarily_unavailable` when the session store or the Store is down.
The link is bound to the session that started it — recorded in the
transaction — so a `form_post` federation (Apple) links the same way as a
`query` one, and a callback presented by a different authenticated session
is `401 login_required`.
Successes and refusals are audited (`federation.identity.linked`,
`federation.identity.link_refused`, `subject` = the account,
`details.reason` on a refusal).

The rules a Store must apply before it links — never on an unverified or
relay address, never by e-mail alone, `sub` verbatim — are in
[`packages/session/README.md`](../packages/session/README.md#account-linking-across-federations-482).

### Federation grants — what each answer means (#593)

`POST /oauth/federation-grants/:grantId/token` hands a client an **upstream**
access token on a user's standing consent. The user is not present, so the
question an operator asks about any failure is *"does this need me, or does it
need them?"* — and the status says which.

| What you see | What it is | What to do |
| --- | --- | --- |
| `503 temporarily_unavailable` / `storage` | The revocation boundary, the store, or the backstop write failed. Fails closed deliberately: without the boundary there is no way to know the subject's grants were not revoked, and D13 does not read an unknown answer as "nothing was revoked". | Restore the store. No grant is lost and nothing has to be re-consented. |
| `503 temporarily_unavailable` / `key_unavailable` | The credential is sealed under a key id that is not in the ring. | Put the key back. The records and the credentials are untouched — this is recoverable, which is why it is a 503 and not a 410. |
| `410 reauthorization_required` / `credential_unreadable` | The credential is there and does not authenticate under any key in the ring. | Investigate the key material first, and restore it if it was replaced rather than rotated. Only ask the user again once you are sure the material is right: consent you spend needlessly is consent you cannot get back. |
| `503 temporarily_unavailable` / `lock_timeout` or `concurrent_update` | Another replica is refreshing, or this call's write lost. | Retry, at the client. Do NOT add a retry inside the route — a second attempt can cost a second upstream rotation. |
| `502 upstream_rejected` | The upstream refused with a code this provider knows. `Retry-After` is present when the answer came from a stamped failure. | Read the reason. `invalid_client` is your configuration; `invalid_grant` ends the credential and arrives as `410 reauthorization_required` instead. |
| `502 upstream_token_ineligible` | The upstream answered with a token that may not be handed on: no finite lifetime, a lifetime over the connection's `maxAccessTokenLifetime`, scopes beyond the consent, a token type that is not bearer, or an answer that could not be read. | The reason names it. All but the last are a connection setting against an upstream policy — raise the maximum deliberately, or ask for fewer scopes. Except at an IdP that accumulates consent (Entra): there a narrower grant is broadened by a wider one on the same registration, and asking for less does not help — one registration per scope set is the rule (D19, `docs/offline-access.md`). |
| `400 invalid_request` / `malformed_path` | A grant id in the path that Express could not percent-decode (`%zz`). Refused before the throttle and client authentication for `token`, `revoke` and — when acquisition is configured — `reauthorize`; for `status` only after client authentication, so an unauthenticated request gets `401` first. The browser callback (`/session/federation-grants/callback/%zz`) answers it as JSON too. | Nothing, server-side: the caller built a bad URL. |
| `500 server_error` / `unexpected_error`, with log `federation_grants_unexpected_error` (error) | An error escaped every handler. The line carries `event: federation_grant.unexpected_error`, a `classification` and the error's numeric `status` — nothing of its text (`packages/federation-grants/src/routes.mts`, `report.mts`). | A bug or a dependency failure no handler expected: correlate by time and `x-request-id`, and report it. |
| `429 rate_limited` / `provider` | This deployment's own throttle, keyed `federation_grants:ip:<ip>`. | Configure `limits.federation_grants` on the limiter adapter if the budget is genuinely too small. |
| `429 rate_limited` / `upstream` | The IdP throttled us. `Retry-After` when it said when. | Back off at the client. |
| `503 service_unavailable` / `shutting_down` | The process has begun draining and will not start work nothing will wait for. | Normal during a rolling restart. Size the host's cleanup allowance at **45 seconds or more** — a ten-second drain is shorter than the upstream hard timeout plus the persist budget, so a shutdown under it abandons exactly the rotation the drain exists to wait for. The standalone gives cleanup the configured refresh tail plus a margin — 45 s under the shipped budgets, more when `upstreamHardTimeoutMs`, `persistRetryBudgetMs` or `lockWaitMs` is raised — and its compose files give the process 60; a Kubernetes deployment sets `terminationGracePeriodSeconds: 60` itself (the default is 30, below drain + cleanup). |
| `503 service_unavailable`, "Rate limiter temporarily unavailable" | The limiter backend is down and `rateLimit.failMode = "closed"`. | The product-wide policy, not this route's. |
| `federation.grant.refresh_persist_failed` (`storage`, `write_in_flight`, `hard_timeout`) | A refresh succeeded upstream and this process could not write down what it got. | A rotation may be lost: the IdP has moved to a refresh token this deployment does not have. Reconnect the grant only if subsequent calls actually answer `410 reauthorization_required`; an IdP with a rotation grace period often does not. |
| `federation_grant.failure` (warn) | The sanitized report core makes for every cause it turns into an answer. Carries `during`, `grantId`, `correlationId` and a classification — never the error, its message, its stack or anything an upstream echoed. The classification is one of `timeout`, `aborted`, `type_error`, `range_error`, `syntax_error`, `store_credential_refused` (the user Store refused this deployment's `CLIENT_USER_BEARER_TOKEN`), `store_transport_failed` (the user Store could not be reached or answered unreadably) or `unknown`. | Correlate by `correlationId`, which is the `x-request-id` the response was answered under — the caller's own when it was sent once and matches `[A-Za-z0-9._:+/=#-]{1,128}`, otherwise one generated for the request, which the response header carries — and is the same on events written after the response. |

A failed audit, touch or lock release does not change an answer that has
already been decided; it is reported through `federation_grant.failure` and
nothing waits for it.

### Ending a grant (#593, D13)

Three ways, and they end different amounts of what a user has.

| You want to | Call | What ends |
| --- | --- | --- |
| let a client disconnect its own integration | `POST /oauth/federation-grants/:grantId/revoke` | That one grant. 204, and 204 again on a retry. Ownership is the only check: a grant whose connection you removed, whose key is out of the ring, or which expired last week can still be ended. |
| end one grant, or show a user their connected applications | `revokeFederationGrant(deps, grantId, by)` / `listFederationGrantsForSubject(deps, subject)` | That one grant, on the Store's authority. There is no admin route: authenticating the person and checking the grant is theirs belongs to the Store, which has both. |
| end everything one subject holds | the `subjectRevocationService` component | Sessions, tokens and grants. This is what a credential change calls. |

The service takes `federationGrants: "revoke" | "keep"`, default `"revoke"`.
`"keep"` — end the sessions and the tokens, leave the established grants —
is an **operator allowance**, `federationGrants.allowKeepOnSubjectRevocation`,
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
| boot: `… the userRepository has no findSubjectByFederatedIdentity`, or `… has no supportsFederatedIdentityLookup` | Under `identityLookup = "required"` (the default) the repository must have the lookup and say what it covers. The HTTP repository has it once `CLIENT_USER_FIND_SUBJECT_BY_FEDERATED_IDENTITY_URL` is set (#613). | Set the URL to your Store's lookup endpoint (foundation README, "The identity lookup"), or set `federationGrants.identityLookup = "unsupported"` — the recorded decision not to refuse an upstream account another local user holds. |
| boot: `federationGrants.connections.<name>: the userRepository does not cover the registration …`, or `… threw when asked whether it covers …` | The Store must say, per connection, that it can place an upstream identity from that registration with the claims the connection names. For the HTTP repository that is `repositories.user.http.federatedIdentityLookupCoverage`: no entry equals this connection's `{ provider, issuer, clientId }`, or the entry's `requiredClaims` names one the connection's `identityClaims` does not. The bundled in-memory repository covers none. | Declare the registration (exactly as configured) with the claims your Store's strategy needs, and name them in the connection's `identityClaims`; or `"unsupported"`. |
| redirect `error=temporarily_unavailable` at the callback, with a `callback_identity_lookup` report | The lookup could not be made: the Store answered anything but a `2xx` with one of the three answers (a `404` is not "nobody"), timed out, redirected, or exceeded the body cap. With `classification: "store_credential_refused"`, the Store answered `401` or `403` with a `Bearer` challenge: it refused this deployment's `CLIENT_USER_BEARER_TOKEN`, not the user. With `store_transport_failed`, it could not be reached or answered something unreadable; with `timeout`, it did not answer in time. | Fix the Store; the flow can be started again. Never map an HTTP failure to `unlinked` on the Store side either. For `store_credential_refused`, set `CLIENT_USER_BEARER_TOKEN` to a token the Store accepts; for `store_transport_failed`, the classification does not say which transport failure it was — the same Store's failures on the login, federation and jwt-bearer lines do, by message and `reason` (§3, Store row): `could not be reached` (`unreachable`) is the network path or TLS to the Store — DNS, a firewall, a certificate, `ERR_SSL_SSL/TLS_ALERT_HANDSHAKE_FAILURE` for a Store expecting a client certificate; `closed before a complete response arrived` (`connection_closed`) is a connection closed under the request — occasionally a keep-alive race with the Store's or a proxy's idle timeout, persistently the Store or a proxy closing or restarting; `answered with a malformed HTTP response` (`malformed_response`) or `could not be read` (`unreadable`) is the Store, or a proxy in front of it, answering badly — the URL's port and path, the proxy, the Store's own health. |
| redirect `error=identity_unverifiable` | The Store could not establish who holds the upstream account (`indeterminate`), or a claim the connection's `identityClaims` names was not in the id_token — the audit outcome says which. Not transient: asking again does not change it. | For a missing claim, the upstream does not issue it for this registration (Entra's `oid` needs `profile` in the scopes); for `identity_not_resolvable`, the person is not in the Store's directory. |
| redirect `error=identity_conflict` | The upstream account is another local user's. | Working as designed; the user signed in upstream as someone else. |
| redirect `error=grant_not_authorizable` at the callback, after a config change | The connection moved (issuer, client, scopes, resource, boundary, callback or federation name) between the consent and the callback; the flow ends before any code is exchanged. | Start the flow again. |

### Rotating the federation-grant key ring (#593, D16)

`federationGrants.encryptionKeys` is a ring: **the first key seals** every
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

---

## 4. Alerts

Alert on the **event name**, never on message text. Application logs and
audit events share one pino stream in the standalone, separated by `name`
(`"provider"` vs `"audit"`); the audit event type doubles as `msg`
(`templates/standalone/src/logger.mts`). `LOG_LEVEL` does not gate the audit
stream — its level is fixed at `info`.

### Page — a dependency is down or a guarantee is not being met

| Event | Where | Why it pages |
| --- | --- | --- |
| `rate_limiter_failed_closed` / `rate_limiter_failed_open` (error) + audit `rate_limit.unavailable` | `core/src/ratelimit/guard.mts` | the limiter backend is erroring; closed means you are shedding login/token traffic, open means brute-force protection is off |
| `standalone_redis_clients_error` (error) | `templates/standalone/src/modules.mts` | the shared socket's `error` events — fires during reconnects too, so alert on rate or duration, not on one line |
| `session_store_redis_error` (error) | `session/src/store/factory.mts` | the cookie-session client; same reconnect caveat |
| `redis_duplicate_connection_error` (error) | `redis/src/ioredis.mts` | a per-rotation duplicate connection failed; sustained means refresh rotations are failing |
| `readiness_probe_failed` (warn), sustained; `auth_dependency_up == 0` | `core/src/routes/Readiness.mts`, `templates/standalone/src/metrics.mts` | a replica is out of rotation |
| `unhandled_request_error` (error) | `templates/standalone/src/terminalError.mts` | a `500` you did not plan for — includes a signer (KMS) failure and a cookie-store failure |
| `device_route_unexpected_error`, `federation_grants_unexpected_error` (error) | `device-grant/src/module.mts`, `federation-grants/src/routes.mts` | a `500` on the device-grant or federation-grants routes. Answered inside those routers, so `unhandled_request_error` does not fire for them — an alert on that event alone misses these |
| `device_authorization_store_unavailable`, `device_verification_store_unavailable`, `device_code_grant_store_unavailable` (error) | `device-grant/src/deviceAuthorizationEndpoint.mts`, `verificationEndpoint.mts`, `grant.mts` | the device-code store is down or timed out: the device could not start (`device_authorization`, no code re-drawn), the user's lookup, approval or denial got no answer (`device/verification`), or the device's poll got none (`/oauth/token`). Each answered `503 temporarily_unavailable`. The same outage as the shared-Redis row above. An approval or a denial may nonetheless have been recorded before the reply was lost: a retry then answers `409 already_decided`, and the audit event `device.decision_outcome_unknown` marks the attempt. A poll's approval may likewise have been consumed, and the device's retry answers `invalid_grant`; the device starts again |
| `token_verification_unavailable` (error) by `site` and `reason` | `oauth/src/verificationUnavailable.mts`, `oauth/src/grants/refreshToken.mts`, `oauth/src/routes/revoke.mts` | a route (`site`: `introspect`, `userinfo`, `federation_token`, `federation_logout`, `logout`, `revoke`, `refresh_token`) is answering `503` because it could not verify tokens: `reason: "verification_key_unavailable"` = the keystore did not answer (the projected error's `cause` names it); `"revocation_unavailable"` = the denylist or the watermark store is unreachable. Replaces `refresh_token_revocation_store_unavailable` |
| `token_exchange_validation_unavailable` (error) | `oauth-token-exchange/src/grant.mts` | token exchanges are answering `503` because a validator could not reach an answer — for the built-in one, the keystore or a revocation store; `role` says which token |
| `client_repository_unavailable` (error); `client_assertion_refused` (error) with `reason: "client_repository_unavailable"` | `core/src/repositories/clientRepositoryUnavailable.mts`, written by `oauth/src/middleware/clientAuth.mts`, `routes/authorize.mts`, `routes/federationToken.mts`, `grants/authorization.mts` and `oauth-token-exchange/src/grant.mts` (`site` names each but client authentication); `clientAssertion.mts` | a client lookup is answering `503` because the client repository cannot answer — every client-authenticated endpoint is down for confidential clients, and no authorization request starts |
| `refresh_token_store_unavailable` (error) | `oauth/src/grants/refreshToken.mts` | refreshes are answering `503` because the refresh-token family store (`store: "refresh_token_family"`, `step: "rotate"` or `"revoke"`) or the session store (`store: "user_session"`) cannot answer |
| `federation_token_store_unavailable`, `federation_logout_store_unavailable` (error) by `store` and `step` | `oauth/src/routes/federationToken.mts`, `oauth/src/routes/logout.mts` | the federation token or logout route is answering `503` because a store cannot answer: `refresh_token_family`, `user_session`, `session_federation_index` or `federation_token` |
| `federation_token_upstream_unavailable` (error); `federation_token_refresh_failed` (warn) by `reason` | `oauth/src/routes/federationToken.mts` | the upstream IdP could not be reached for a refresh (`503`); or it answered and refused (`410` / `429` / `500`) |
| `federation_token_lock_timeout` (warn), sustained | `oauth/src/routes/federationToken.mts` | refreshes of one federation record keep waiting on each other's advisory lock and answering `503 lock_timeout`: a slow IdP refresh holding the lock, or a lock TTL shorter than the IdP's refresh time |
| `federation_token_refresh_unsupported` (error) | `oauth/src/routes/federationToken.mts` | a federation whose provider cannot refresh is answering every expired token `503 refresh_not_supported`: configure the provider |
| `logout_store_unavailable` (error) by `store`; `logout_cascade_operation_failed`, `logout_cascade_cleanup_failed` (warn) | `oauth/src/routes/logout.mts`, `oauth/src/logout/cascadeLogout.mts` | RP-initiated logout is answering `503` because a session store could not be read or the cascade stopped (`store: "logout_cascade"`, `cascadeStep`); the warn lines name each operation that failed |
| `authorization_grant_store_unavailable`, `session_grant_store_unavailable` (error) by `store` and `step` | `oauth/src/grants/authorization.mts`, `grants/session.mts` | code exchanges or session-grant token requests are answering `503` because a session store or the family store cannot answer |
| `grant_policy_unavailable` (error) | `core/src/grants/grantPolicy.mts`, `oauth-token-exchange/src/grant.mts`, `oauth/src/routes/authorize.mts` | the `grantPolicy` hook threw: every grant it gates is answering `503`, and `/authorize` redirects `temporarily_unavailable` |
| `jwks_unavailable` (error) | `core/src/routes/Jwks.mts` | the JWKS endpoint is answering `503`: the keystore returned no publishable key — relying parties cannot fetch a key to verify with |
| `userinfo_store_unavailable`, `introspect_store_unavailable` (error) | `oauth/src/routes/userinfo.mts`, `oauth/src/routes.mts` | userinfo or introspection is answering `503` because the refresh-token family store (`store: "refresh_token_family"`) or the session store (`store: "user_session"`) is unreachable |
| `token_exchange_family_store_unavailable` (error) | `oauth-token-exchange/src/grant.mts` | token exchanges are answering `503` because the refresh-token family store is unreachable; `role` says whether the `subject_token`'s or the `actor_token`'s family could not be read |
| `revoke_all_for_subject_incomplete`, `revoke_all_watermark_failed`, `revoke_all_list_sids_failed`, `revoke_all_cascade_failed`, `revoke_all_remove_sid_failed` (error) | `core/src/user-sessions/revokeAllForSubject.mts` | a credential change did **not** fully invalidate what was issued. `incomplete` means a store was not wired (composition gap); the others mean a wired store threw (outage — retry) |
| `subject_session_index_write_failed` (error) | `session/src/routes/Session.mts`, `Federation.mts` | a login succeeded that a later credential-change cascade will not find |
| `logout_user_session_delete_failed` (error) | `session/src/routes/Session.mts` | **alert on this.** `POST /session/logout` destroyed the cookie but could not delete the `UserSession` record, so an access token minted by the `session` grant keeps introspecting `active: true` until it expires. The user is out of the browser; the token is not. Same store outage the introspection liveness check fails closed on, so the exposure is bounded by whether the store recovers |
| `logout_subject_session_index_remove_failed`, `logout_federation_token_remove_failed`, `logout_session_federation_index_remove_failed` (error) | `session/src/routes/Session.mts` | a logout left bookkeeping behind. Lower severity than the row above: the `UserSession` record is already gone, so the orphans are unreachable and bounded by TTL — but upstream-IdP tokens stay at rest for that window |
| audit `introspect.store_unavailable`, `logout.cascade_failed` | `oauth/src/routes.mts`, `oauth/src/routes/logout.mts` | introspection is answering `503` for an outage — the keystore, a revocation store, the family store or the session store (`details` names which); a logout left state behind |
| `mtls_revocation_unavailable_rejected` (warn), sustained | `mtls/src/fullPki/validate.mts` | your CRL distribution point or OCSP responder is down and mTLS clients cannot get tokens |
| `mtls_revocation_unavailable_allowed` (warn), **any**, if you chose `allow` | same | each line is a certificate that was not revocation-checked; a steady rate means the PKI is effectively unrevocable |
| `mtls_ocsp_responder_unchecked` (warn, once per responder) | `mtls/src/fullPki/validate.mts` | a delegated OCSP responder carries no `id-pkix-ocsp-nocheck` and nothing can check its own revocation — under `mode = "ocsp"`, or under `"both"` when its certificate names no CRL. Its answers are trusted for the responder certificate's whole lifetime. The fix depends on the mode: under `"ocsp"` no CRL is ever fetched, so only `nocheck` on the responder certificate clears it; under `"both"`, `nocheck` or a CRL named on the responder certificate does |
| `jwt_bearer_assertion_verifier_unavailable`, `jwt_bearer_user_repository_unavailable` (error) | `oauth/src/grants/jwtBearer.mts` | the attestation service or the Store is down (`503` to devices) |
| `jwt_bearer_policy_audience_refused` (warn) | `oauth/src/grants/jwtBearer.mts` | your `grantPolicy` returned an audience outside the client's `allowedAudiences`, or one with no authenticated client to supply that ceiling. Devices get `500 server_error`; the policy, not the device, is what to fix (#520, #521) |
| `token_error_code_malformed`, `authorize_policy_deny_error_malformed`, `token_exchange_policy_deny_error_malformed` (warn) | `oauth/src/routes.mts`, `oauth/src/routes/authorize.mts`, `oauth-token-exchange/src/grant.mts` | a grant, or your `grantPolicy`'s deny, returned an `error` code outside RFC 6749's `1*NQSCHAR` (empty, or carrying `"`, `\`, a control or non-ASCII character). Clients get `invalid_request` from `/oauth/token` and `access_denied` from `/oauth/authorize` instead; the logged `error` is the code, sanitised and capped at 200 characters. Fix the code |
| `error_envelope_code_malformed`, `error_envelope_uri_malformed` (warn, through the console logger) | `core/src/errors/envelope.mts` | a module handed core's `errorEnvelope` an `error` code outside RFC 6749's `1*NQSCHAR` (empty, or carrying `"`, `\`, a control or non-ASCII character), or an `error_uri` that is neither an `http(s)` URI nor a relative reference RFC 3986's grammar parses, or that carries a userinfo (`user@`). The client got `server_error` with the status the module chose, or the answer without `error_uri`; the logged value is sanitised and capped at 200 characters. Nothing in this repository sends either, so the module is a contributed one or a custom composition's: fix what it answers with |
| `redirect_policy_error_malformed` (warn) | `session/src/internal/refusalEnvelope.mts` | a federation redirect policy refused a `redirect_to` with a 4xx and an `error` code outside RFC 6749's `1*NQSCHAR`. The client got `invalid_request` with the policy's status and description; the logged `error` is the code, sanitised and capped. Fix the code your contributed policy answers with |
| `token_exchange_policy_scope_refused`, `token_exchange_policy_audience_refused` (warn) | `oauth-token-exchange/src/grant.mts` | your `grantPolicy` returned, for a token exchange, a scope outside the subject token's scope and the client's `allowedScopes`, or an audience outside the subject token's audience and the client's `allowedAudiences`. Clients get `500 server_error`; the policy, not the client, is what to fix. A client asking for such an audience itself is `400 invalid_target`, logged as `token_exchange_audience_widening_rejected` |
| `jwt_bearer_issuer_audience_mismatch` (warn) | `oauth/src/grants/jwtBearer.mts` | the presenting client's `allowedAudiences` and the assertion issuer's `allowedAudiences` (its trust-registry entry) admit no audience in common, so no token could name one both stand behind. Devices get `invalid_grant`; compare the two registrations (#525) |
| `cimd_document_rejected`, `cimd_document_fetch_failed`, `cimd_host_not_allowed` (warn) | `oauth/src/clients/clientIdMetadataDocument.mts` | a Client ID Metadata Document client (#529) was refused: the reason names what failed (a redirect, a byte cap, a special-use address, a document that does not match its URL). The client sees `invalid_client`; a steady rate from one host is a misconfigured client or a probe |
| `revoke_store_unavailable` (error) | `oauth/src/routes/revoke.mts` | `/oauth/revoke` is answering `503`: a client's revocation was not recorded, so the token it asked to end is still valid until it expires. `store` says whether the access-token denylist or the refresh-token family store failed, and `clientId` whose revocation was lost. A client that ignores the `503` keeps a live token it believes revoked — retries succeed once the store is back |
| `token_binding_unavailable`, `protected_resource_binding_unavailable` (error) by `mechanism` and `reason` | `core/src/middleware/tokenBinding.mts`, `protectedResourceBinding.mts` | a token-binding mechanism could not reach a verdict, and requests at `/oauth/token` (`token_binding_unavailable`) or at protected resources (`protected_resource_binding_unavailable`) are answering `503 temporarily_unavailable`. The dispatcher that answers owns the one line, with the mechanism's `reason` and its `cause`'s projection when it gives them. For DPoP: `reason: "replay_store_unavailable"` = the seen-set is unreachable; `reason: "replay_store_fault"` = it answered with its own contract error (a `RangeError` or `expired-at-issue`) — a broken or hand-built seen-set, whose fix is in the composition, not in Redis. These replace DPoP's own `dpop_replay_store_unavailable` / `dpop_replay_store_fault` lines and the dispatchers' former warn lines |
| `graceful shutdown: drain deadline exceeded, closing remaining connections`, `graceful shutdown: cleanup failed`, `graceful shutdown: cleanup timed out`, `graceful shutdown: server close failed` (error) + non-zero exit | `templates/standalone/src/shutdown.mts` | a replica did not drain within `drainTimeoutMs` (default 10 s), its cleanup did not finish within the allowance (45 s or more with federation grants on — a rotated upstream credential may be unwritten), or it could not release its connections |

### Investigate — security signals worth a dashboard and a threshold

| Event | Where | Meaning |
| --- | --- | --- |
| audit `device.rate_limited`; log `device_verification_rate_limited` (warn) | `device-grant/src/verificationEndpoint.mts` | an **account** (the key is the authenticated subject) is guessing device codes |
| audit `device.decision_outcome_unknown` | `device-grant/src/verificationEndpoint.mts` | an approval or a denial met a device-code store outage and was answered `503`, but the store may have recorded it before the reply was lost. It carries the subject who decided and the `action`, but no client: the record could not be read. Read beside `device_verification_store_unavailable`: a device polling afterwards may have received tokens that no `device.approved` accounts for |
| `jwt_verify_rejected` (warn) by `reason` | `core/src/jwt/verify.mts` | `kid_unknown` = a fabricated key id; `kid_expired` = a token signed with a key whose overlap window closed (see [§6](#6-key-rotation)); `revoked` = a revocation finding, or a fail-closed refusal when the watermark cannot be compared: a denylist hit, a token predating the subject's watermark, or a token with no `iat` while a watermark is in force (#376); `revocation_unavailable` = the denylist or the watermark store was unreachable — an outage, not a finding (#408 / #459); `verification_key_unavailable` = the keystore could not answer the lookup — an outage, answered `503`, never reported as `kid_unknown`; `signature` / `alg` / `iss` / `aud` / `typ` = malformed or foreign tokens |
| `jwt_bearer_assertion_expired` (info) | `oauth/src/grants/jwtBearer.mts` | a jwt-bearer assertion verified but had no whole second of lifetime left when its token would have been minted — past its `exp` inside the issuer entry's `clockToleranceSeconds` (default 60), or run out while the Store answered. Devices get `invalid_grant`. The issued access token **never outlives the assertion**: `expires_in` is `min(oauth.accessToken.defaultExpiresIn, exp − now)`, so a short-lived assertion gives a short-lived token — an ID-JAG's `iat` is at most an hour old and it often lives minutes — and, with no refresh token issued, the client re-exchanges a fresh assertion. A steady rate from one `issuer` is that issuer's clock running behind this server's, or clients presenting assertions at the last moment (auth.proxy#90) |
| `csrf_origin_rejected`, `csrf_token_rejected` (warn) | `session/src/csrf.mts` | cross-site POSTs to login/logout/device verification, or a UI on an origin you forgot to list in `session.csrf.trustedOrigins` |
| `mtls_untrusted_proxy_rejected` (warn) | `mtls/src/extractor.mts` | a forwarded certificate header from a peer not in `trusted-proxies` — a missing allowlist entry or a forgery attempt |
| `mtls_chain_validation_failed`, `mtls_full_pki_validation_failed` (warn) | `mtls/src/extractor.mts` | certificate refused; `step` says why (`certificate revoked`, `no path to trust anchor`, …) |
| `token_binding_proof_invalid`, `protected_resource_binding_proof_invalid`, `dpop_signature_invalid`, `dpop_alg_not_allowed` | `core/src/middleware/*.mts`, `dpop/src/verifier.mts` | bad proof-of-possession material |
| `introspect_non_access_token`, `introspect_compound_cnf_rejected` (warn) | `oauth/src/routes.mts` | a refresh/id token presented as a bearer credential; a token with two bindings, which this server never mints |
| audit `authorize.rejected`, `token.issued.failure` (by `details.reason` — the route's own refusals carry a code such as `grant_type_not_allowed`; a grant handler's carries its `error_description`, sanitised and capped at 200 characters, beside `details.error`; some descriptions quote what the client sent — a scope, an audience, a token type — so group those by the text before the quoted value, e.g. `scope '…' is not in subject_token scope`), `introspect.family_revoked`, `logout.family_revoked`, `federation.token.forbidden`, `federation.token.family_revoked` | `oauth/src/routes.mts`, `routes/authorize.mts`, `routes/logout.mts`, `routes/federationToken.mts` | refusals and revocations; a spike in `token.issued.failure` with one `reason` is either an attack or a broken client |
| `http_request_duration_seconds{status="429"}` | `templates/standalone/src/metrics.mts` | rate limiting engaged; correlate with `HTTP_TRUST_PROXY` — one bucket for everyone is a misconfiguration that reads like an attack |

### Configuration drift — emitted once, at boot or on first use

| Event | Where | What to do |
| --- | --- | --- |
| `replica_unsafe_adapters` (warn) | `core/src/boot/replica-safety.mts` | `deployment.mode` is unset; set it |
| `login_rate_limiter_not_shared`, `webauthn_authentication_options_rate_limiter_not_shared` (warn) | `session/src/routes/Session.mts`, `webauthn/src/module.mts` | no shared `rateLimiter` and `deployment.mode` unset; the guard is per-process (`"multi"` refuses boot instead, `"single"` is silent — #474) |
| `webauthn_authentication_options_budget_mismatch` (warn) | `webauthn/src/module.mts` | a shared `rateLimiter` is wired, and the app config's `webauthn.rateLimit.authenticationOptions` (what the limiter module seeded) is missing or differs from the `webauthnConfig` slot (what the per-process fallback is built from, and what backs the `RateLimit-*` headers only for an adapter that reports no `limit`). The route runs on an explicit `limits.webauthn-authentication-options` in the limiter's section if there is one, otherwise on the key's values, otherwise on the limiter's default. The warning compares the key with the slot only; an explicit `limits` entry is not compared. Set the key to the slot's values (the line names both) |
| `pkce_config_ignored_s256_is_mandatory` (warn) | `oauth/src/grants/pkce.mts` | a retired PKCE key (or `OAUTH_GRANTS_AUTHORIZATION_CODE_PKCE_REQUIRE_S256`) is still set; delete it |
| `jwt_verify_aud_skipped`, `jwt_verify_iss_skipped` (warn, once per logger) | `core/src/jwt/verify.mts` | a verification surface is not pinning `aud`/`iss` |
| `jwt_verify_legacy_typ` (warn) | `core/src/jwt/verify.mts` | `OAUTH_JWT_LEGACY_TYP_ACCEPT=true` is admitting typ-less tokens; close the window |
| `federationTokenStore: in-memory adapter is for dev/test only …` (warn) | `core/src/federation-tokens/factory.mts` | the standalone builds this store in memory unless `federationTokenStore.type = "redis"` (`FEDERATION_TOKEN_STORE_TYPE=redis`) is set (#456) |
| `[federation-tokens] CRITICAL: running with mode="allow-plaintext" …` (console) | `redis/src/federation-tokens.mts` | `FEDERATION_TOKENS_ALLOW_INSECURE=1` is set where plaintext is refused — a production/staging environment or `deployment.mode = "multi"` (#473) |
| `` [buildModules] `repositories.code.type = "redis"` is deprecated `` (console) | `templates/standalone/src/buildModules.mts` | move to `oauth.code.adapter = "redis"` (`OAUTH_CODE_ADAPTER`) |
| `` [buildModules] `oauth.accessToken.expiresIn` (OAUTH_ACCESS_TOKEN_EXPIRES_IN) is deprecated `` (console) | `templates/standalone/src/buildModules.mts` | the deprecated key decides the access-token default; move the value to `oauth.accessToken.defaultExpiresIn` (`OAUTH_ACCESS_TOKEN_DEFAULT_EXPIRES_IN`) |

### Data corruption — a stored record could not be read

`user_session_corrupt_envelope: …` and `session_rp_registry_corrupt_envelope: …`
(warn; `packages/redis/src/userSessionStore.mts`, `sessionRPRegistry.mts`) —
the record is treated as absent (fail-closed). `RedisCodeRepository: corrupted
data for code` / `… legacy/corrupted code record missing required identity
fields` (error; `packages/redis/src/code-repository.mts`) — the code is refused.
A federation-token envelope that fails to decrypt is **deleted** and the user is
sent to re-authenticate (`packages/redis/src/federation-tokens.mts` `get`).
A watermark that is not a number throws rather than reading as "not revoked"
(`packages/redis/src/subjectRevocation.mts`). Any of these at a steady rate
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
`rate_limit.unavailable`, `token.issued`, `token.issued.failure`.

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

---

## 5. Redis

### Two connections, not one

| Connection | Configured by | Serves | Probe name |
| --- | --- | --- | --- |
| the shared **ioredis** socket, one per replica | `refreshTokenFamilyStore.redis.url` / `.password` (`REFRESH_TOKEN_FAMILY_STORE_REDIS_URL`, `…_PASSWORD`) | every `makeIoredisClients` purpose: refresh-token families, the six user-session stores, rate limiter, authorization codes, access-token denylist, federation tokens and the consent stores when Redis-backed (`templates/standalone/src/modules.mts`, `packages/redis/src/ioredis.mts`) | `redis` |
| a **node-redis** client via connect-redis | `session.storage.redis.url` / `.password` (`SESSION_STORAGE_REDIS_URL`, `…_PASSWORD`) | the express-session cookie store only; its key layout and TTL are connect-redis's own — this repo passes it nothing but the client (`packages/session/src/store/factory.mts`) | `session-store` |

Plus one short-lived **duplicate** of the shared socket per refresh rotation:
`WATCH` is connection-scoped in Redis, so `updateFamily` opens `client.duplicate()`
for its compare-and-swap and closes it on exit
(`packages/redis/src/refresh-token-family.mts`). Under refresh-heavy load
against a managed Redis with TLS/AUTH this is connection churn — tracked as
`#293` item 7, undecided at `v0.11.0`.

Requirements (`packages/redis/README.md`): Redis **7.2 LTS or later** — the
session adapters issue `PEXPIREAT … NX` + `PEXPIREAT … GT`, `PEXPIRETIME` backs
the monotonic watermark, `GETDEL` backs code consumption; and **Lua** — the
rate-limit increment, the lock release, the watermark write and the subject
sweep are `EVALSHA`/`EVAL` scripts with a `NOSCRIPT` fallback that re-loads
after a `SCRIPT FLUSH` or a failover (`packages/redis/src/ioredis.mts`). Redis
Cluster with Lua disabled is not supported by `makeIoredisClients`. Nothing in
the key layout groups a session's keys into one slot: the only Cluster-safety
claim the code makes is for `sAddWithTtl`, a single-key `MULTI`.

### Key families

Prefixes are the shipped defaults; every one is overridable so two deployments
can share a database (`REDIS_SESSION_STORES_KEY_PREFIX`,
`REFRESH_TOKEN_FAMILY_STORE_KEY_PREFIX`, `CLIENT_CODE_KEY_PREFIX`,
`REDIS_ACCESS_TOKEN_DENYLIST_KEY_PREFIX`, `REDIS_FEDERATION_TOKEN_STORE_KEY_PREFIX`,
`REDIS_CONSENT_STORE_KEY_PREFIX`; `packages/core/config/reference.conf`).

| Key | Type / value | TTL comes from | Source |
| --- | --- | --- | --- |
| `rtfam:<familyId>` | string, JSON `{familyId, activeJti, revoked, expiresAtMs}` | the family's `expiresAtMs` (`oauth.refreshToken.expiresIn`, default 86400 s). Set once at creation; rotation **never extends** it (`Math.min` in `rotate`). Revocation — by `/oauth/revoke`, a logout, or a replay — **does**: a revoked family is kept until the later of that expiry and the revocation plus `oauth.accessToken.maxExpiresIn`, plus about five minutes (the verifier's clock tolerance), so its access tokens cannot outlive it; a family revoked after its key expired gets a revoked key again | `packages/redis/src/refresh-token-family.mts`, `core/src/refresh-token-family/rotation.mts`, `revocation.mts`, `retention.mts` |
| `oauth:code:<code>` | string, JSON code record | `redisCodeRepository.defaultExpiresIn` (`CLIENT_CODE_DEFAULT_EXPIRES_IN`, default 600 s) or the per-call `expiresIn`; consumed with `GETDEL` | `packages/redis/src/code-repository.mts` |
| `atdeny:<jti>` | string `"1"` | the revoked access token's **remaining** lifetime plus about five minutes (`REVOCATION_RETENTION_ALLOWANCE_MS` — the verifier accepts a token that long past its `exp`); a token already past that writes nothing | `packages/redis/src/access-token-denylist.mts`, `packages/oauth/src/routes/revoke.mts` |
| `<tag>:ip:<ip>` — `token`, `authorize`, `introspect`, `login`, `device_authorization`, `webauthn-authentication-options`; `device_verification:user:<subject>` | integer counter | the prefix's `windowSeconds`: `defaultLimit` 60/60 s unless `redisRateLimiter.limits.<prefix>` is declared; `login` seeded 20 per 900 s from `rateLimit.login`; `device_verification` seeded 5 per 300 s from `oauth.deviceAuthorization.rateLimit`. The expiry is set atomically with the increment and only when missing, so a steady stream cannot hold a window open | `packages/redis/src/ratelimit.mts`, `ioredis.mts` (`LUA_INCREMENT_WITH_TTL`), `core/src/ratelimit/seededSpecs.mts` |
| `ss:us:<sid>` | string, JSON `{sid, sub, authTimeMs, createdAtMs, expiresAtMs, claims, amr?}` — `amr` (RFC 8176, #481) is left out when the login path recorded none | the session's `expiresAt` (`SET … PX … NX`) | `packages/redis/src/userSessionStore.mts` |
| `ss:rp:<sid>` | hash, field = `clientId`, value = RP envelope | `session.expiresAt`, raised but never truncated (`PEXPIREAT NX` + `GT`) | `packages/redis/src/sessionRPRegistry.mts`, `internal/redisSidHash.mts` |
| `ss:fi:<sid>`, `ss:fed:<sid>` | sorted sets of family ids / federation names | same rule | `packages/redis/src/sessionFamilyIndex.mts`, `sessionFederationIndex.mts`, `internal/redisSidSortedSet.mts` |
| `ss:sub:<subject>` | sorted set of sids, **score = each session's expiry** | key TTL raised to the latest member expiry; members pruned on read against the server's `TIME` | `packages/redis/src/subjectSessionIndex.mts` |
| `ss:rev:<subject>` | string, epoch-ms watermark | the caller's `watermarkTtlMs` — sized to the **longest refresh token**, monotonic on both value and expiry | `packages/redis/src/subjectRevocation.mts`, `core/src/user-sessions/revokeAllForSubject.mts` |
| `ft:<sid>:<federation>` | string, AES-256-GCM-encrypted envelope | `redisFederationTokenStore.ttl` (default 86400 s) — the store lifetime, deliberately **not** the upstream access token's expiry | `packages/redis/src/federation-tokens.mts` |
| `ft:idx:<sid>` | set of federation names | same, raised with each write | same |
| `ft:lock:<sid>:<federation>` | string, advisory lock token | the lock's own | `packages/redis/src/internal/lock.mts` |
| `chal:…`, `replay:…` | strings `"1"` | the challenge / replay window, `SET … PX … NX`. A DPoP proof's record is `replay:<len>:dpop-proof:<jkt>\|<len>:<jti>`, kept `oauth.dpop.replay-store-ttl-seconds` (default 300 s) | `packages/redis/src/challenges.mts`, `replay-seen-set.mts`, `packages/dpop/src/verifier.mts` |
| `consent:rec:<len>:<sub>\|<len>:<clientId>` | hash `{scopes (JSON array), grantedAt, expiresAt?}` | **none** for a consent recorded until revoked — which is what `POST /oauth/consent` writes; for a record carrying `expiresAt`, that expiry plus 5 minutes' slack (`CONSENT_EXPIRY_SLACK_MS`). Expiry is judged by `expiresAt` on the reading replica's clock; the TTL only reclaims records nobody reads again | `packages/redis/src/consent-store.mts`, `ioredis.mts` (`LUA_CONSENT_GRANT`) |
| `consent:{pending}:ch:<challenge>` | hash `{record (JSON), sessionId, expiresAt}` | the parked request's `expiresAt` (10 minutes, `PENDING_CONSENT_TTL_MS`) plus the same slack; consumed with its index entry in one script | `packages/redis/src/consent-store.mts`, `ioredis.mts` (`LUA_PENDING_CONSENT_*`) |
| `consent:{pending}:sess:<sessionId>` | sorted set of challenges, score = the order they were parked | raised to its longest-lived member's; at most `PENDING_CONSENT_PER_SESSION_LIMIT` (16) members, the first-parked evicted past it. `{pending}` is a Cluster hash tag: every parked request shares one slot | same |

### Sizing

There is no background sweeper anywhere in this package; **Redis expiry is the
entire garbage-collection strategy**, so resident size is (write rate ×
lifetime) per family:

- **Sessions** — per live browser session: one `ss:us:` envelope (the JSON
  above plus your claims), up to three sid-keyed structures, one member in
  the subject's `ss:sub:` set, and one connect-redis record. Lifetime =
  `session.maxAge` (default 3 600 000 ms).
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
- **Consent** — one small hash per (subject, client that is not first-party)
  the user has consented to, until revoked; one parked request per consent
  page shown, for at most 15 minutes (10 plus the slack), 16 per session at
  most. Only with `CONSENT_STORE_ADAPTER=redis`.

The standalone does not mount the device grant, so it holds no device-code
keys. A deployment that adds it with `redisDeviceCodeStoreModule` holds, per
pending authorization, `devauth:{devauth}:code:<device_code>` (a hash) and
`devauth:{devauth}:user:<user_code>` (a string), both expiring at the
authorization's deadline (`oauth.deviceAuthorization.code-lifetime-seconds`,
default 600 s) and all on one Cluster slot (`packages/redis/src/device-code-store.mts`).
The memory adapter instead caps itself at 10 000 records "at a few hundred
bytes each" (`packages/core/src/device-authorization/memory.mts`).

Core's in-process challenge store and replay seen-set, on a single replica,
hold their live entries plus at most those that expired since the last sweep:
each sweeps on its writes, at most once per 1000 writes and once per ten
seconds (`packages/core/src/challenges/sweep.mts`), so a WebAuthn ceremony
the user abandons, or an options request repeated in a loop, costs an entry
for its lifetime and not until the process restarts.

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
  `redisFederationTokenStore.scanFallback = false` once no session that
  predates the index (v0.10) can still exist — that is, once `ttl` has elapsed
  since the last pre-v0.10 replica stopped writing (`packages/redis/README.md`
  "Federation-token keys and logout").
- Removals during logout use `UNLINK` in batches of 100 keys and paged
  `SSCAN`/`HSCAN`/`ZRANGE` reads, so one heavily-linked session does not block
  the shared connection (`packages/redis/src/federation-tokens.mts`,
  `clients.mts`).
- A `MULTI`/`EXEC` reply with a per-command error is surfaced as a thrown
  error rather than reported as success — a refused `PEXPIRE` would otherwise
  strand a key with no TTL (`assertPipelineSucceeded`, `ioredis.mts`).

---

## 6. Key rotation

### Where keys live

`oauth.jwt.signingKey.provider` has one built-in value, `"local"`
(`packages/core/src/keys/factory.mts`). Under `local`:

| Key | Meaning |
| --- | --- |
| `algorithm` (`OAUTH_JWT_ALGORITHM`) | `EdDSA` (shipped default), `ES256`, `RS256`, `HS256`. No implicit fallback |
| `kid` (`OAUTH_JWT_KID`) | the key id stamped in every token header; default `v0`. A string of 1 to 256 characters with no control character (`isWellFormedKid`); anything else fails boot — an `OAUTH_JWT_KID` that is exported but empty included |
| `privateKeyPath` / `publicKeyPath` (or inline `privateKey` / `publicKey`) | PEM pair for the asymmetric algorithms; the file path wins when both are given |
| `secret` (`OAUTH_JWT_SECRET`) | HS256 only, ≥ 32 bytes decoded |
| `previousKeys = [ { kid, publicKeyPath, expiresAt } ]` (or inline `publicKey` instead of `publicKeyPath`) | asymmetric only — additional **verification** keys, published in JWKS until `expiresAt` (an ISO date; invalid fails boot) |
| `previousSecrets = [ { kid, secret, expiresAt } ]` | HS256 only — each secret clears the same 32-byte floor |

The two rotation shapes are a discriminated union in the schema
(`packages/core/src/config/application.schema.mts`): `previousKeys` under
`HS256`, or `previousSecrets` under an asymmetric algorithm, fails boot rather
than being dropped. `kid` values must be unique across the current key and
every previous entry (`Duplicate kid values`). Before the kid shape check, an
`OAUTH_JWT_KID` exported but empty signed and verified under the kid `""`; it
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

`GET /.well-known/jwks.json` (`oauth.jwt.jwksPath` to move it) publishes the
current key plus every `previousKeys` entry whose `expiresAt` has not passed
(`getVerificationKeys`, `packages/core/src/keys/KeyStore.mts`). The route
(`packages/core/src/routes/Jwks.mts`):

- serialises the set **once per key set** and answers with a strong `ETag`
  (SHA-256 of the body); a poller sending `If-None-Match` gets `304` until the
  set changes — which includes a previous key dropping out on its own clock;
- sets `Cache-Control: public, max-age=<oauth.jwt.jwksCacheMaxAge>`, default
  **300 s** (`packages/core/src/jwks/cache.mts`);
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
- provider-side cache: `jwksCacheMaxAge` = 300 s;
- verifier-side cache: e.g. `jwksCacheMaxAgeMs` = 600 s.

Keep `jwksCacheMaxAge` well below the overlap window
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
   oauth.jwt.signingKey.local {
     kid = "v0"
     privateKeyPath = "/run/secrets/jwt_private_key"
     publicKeyPath  = "/run/secrets/jwt_public_key"
     previousKeys = [
       { kid = "v1", publicKeyPath = "/run/secrets/jwt_public_key_v1", expiresAt = "2027-01-01T00:00:00Z" }
     ]
   }
   ```

   Confirm `GET /.well-known/jwks.json` lists both kids and its `ETag`
   changed, then wait at least `jwksCacheMaxAge` + the largest verifier cache
   (300 s + 600 s with the defaults) so every verifier has seen `v1`.
   Restarting a replica mid-roll with `v1` signing *before* this step would
   have verifiers fetching the JWKS from a not-yet-restarted replica and
   rejecting `v1` tokens with `kid_unknown`.

3. **Flip** signing to `v1` and demote `v0` with an expiry that covers the
   overlap window, then roll again:

   ```hocon
   oauth.jwt.signingKey.local {
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

- **`session.secret`** is a single string in the schema and is passed to
  express-session as one value (`packages/session/src/modules/sessionStoreModule.mts`),
  so there is no overlap window: rotating `SESSION_SECRET` invalidates every
  browser session at once.
- **The federation-token encryption key** (`redisFederationTokenStore.encryptionKey`
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
   | `oauth.dpop.replay-store` (any value) | removed | `oauth.dpop.replay-store was removed in …`: DPoP records its proofs in the `replaySeenSet` component, whose module chooses the backend (`replaySeenSet.adapter` in the standalone); delete the key. A `dpopReplayStore` bootstrap component is no longer read either — see the DPoP note below |
   | `oauth.refreshToken.legacyRtPolicy = "accept-with-warning"` | enum shrunk to `"reject"` | Zod `invalid_enum_value` naming the survivors |
   | flat `oauth.jwt.algorithm` / `kid` / `secret` / key fields | moved | `oauth.jwt has legacy flat fields (…). Migrate to nested shape: oauth.jwt.signingKey.local.<field>` |
   | `oauth.grants.authorization_code.pkce.*` (and `OAUTH_GRANTS_AUTHORIZATION_CODE_PKCE_REQUIRE_S256`) | warn and ignore | one `pkce_config_ignored_s256_is_mandatory` line; S256 is mandatory regardless (`packages/oauth/src/grants/pkce.mts`) |
   | `repositories.code.type = "redis"` | deprecated alias of `oauth.code.adapter` | a `[buildModules] … is deprecated` console line at boot |
   | `oauth.accessToken.expiresIn` (and `OAUTH_ACCESS_TOKEN_EXPIRES_IN`) | deprecated alias of `oauth.accessToken.defaultExpiresIn`, read only while that key is unset — set both and the new key wins | the standalone prints a `[buildModules] … is deprecated` console line at boot when the old key carries anything but the shipped `3600`; `resolveAccessTokenLifetime` is the reader for every composition |

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
   installed (`REPLAY_SEEN_SET_ADAPTER=redis` in the standalone). Installing
   one also turns on `private_key_jwt` wherever client authentication runs
   ([§1](#1-deployment-shapes)).

3. Note the migration windows that are **still open** at `v0.11.0`, each of
   which you should be able to close after the upgrade rather than leave on:
   `redisFederationTokenStore.scanFallback` ([§5](#operational-notes)),
   `oauth.jwt.legacyTypAccept` (`OAUTH_JWT_LEGACY_TYP_ACCEPT`), and
   `oauth.refreshToken.unknownFamilyPolicy = "accept"`
   (`packages/core/config/reference.conf`).

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
- Under `DEPLOYMENT_MODE=multi`, a mixed fleet during the roll is fine for
  every Redis-backed store — the schemas below are what decide whether the
  *older* release can read what the *newer* one wrote. The one exception is
  the release that moves DPoP onto the replay seen-set: its replay records
  change keys, so a mixed fleet opens a replay window (see the DPoP note in
  [Before you upgrade](#before-you-upgrade)).

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
