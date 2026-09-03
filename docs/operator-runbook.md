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

The guard is keyed on **module name**, not on config, because a composition
root can wire a module without going through the adapter switches. The list it
refuses, verbatim (`REPLICA_UNSAFE_MODULE_REASONS` in
`packages/core/src/boot/replica-safety.mts`):

| Module name | What forks per replica |
| --- | --- |
| `memorySessionStores` | user sessions, RP registrations, family indexes and the subject-level revocation pair — back-channel logout reaches only the replica that received it; a credential change watermarks only the replica that handled it |
| `core-rate-limiter-memory` | rate-limit counters — every limit is multiplied by the replica count and resets on each deploy |
| `core-access-token-denylist-memory` | access-token revocation — a revoked token keeps working on every replica that did not receive the revocation |
| `core-replay-seen-set-memory` | DPoP proof-replay detection — a captured proof replays once per replica |
| `core-refresh-token-family-store-memory` | refresh-token families — rotation replay detection and cascade revoke see only this replica's history |
| `core-challenge-store-memory` | WebAuthn challenges — a ceremony started on one replica cannot finish on another |
| `core-webauthn-credential-store-memory` | registered passkeys — a passkey registered on one replica does not exist on the others |
| `core-device-code-store-memory` | pending device authorizations — the human approves on one replica while the device polls another that has never heard of the code |
| `core-federation-token-store-memory` | upstream federation tokens — stored on one replica, missing on the others |

Two things the guard cannot do:

- **It cannot notice that you scaled without setting the mode.** A process
  whose state is all in its own memory has no shared medium through which to
  see peers. Set `DEPLOYMENT_MODE=multi` as part of scaling, not after
  something breaks.
- **It only knows the names above.** The standalone template's own in-memory
  modules are named `standalone:in-memory-session-stores` and
  `standalone:in-memory-code-repository` (`templates/standalone/src/modules.mts`),
  and its federation-token store module builds the in-memory adapter when no
  `federationTokenStore` section is configured — none of those three names is
  on the list, so `multi` does not refuse them. In the standalone, set the
  adapter switches yourself rather than relying on the refusal:
  `USER_SESSION_STORES_ADAPTER=redis`, `OAUTH_CODE_ADAPTER=redis`,
  `RATE_LIMITER_ADAPTER=redis`, `ACCESS_TOKEN_DENYLIST_ADAPTER=redis`
  (`templates/standalone/src/buildModules.mts`).

### The standalone production compose

`templates/standalone/docker-compose.production.yml` is the deployable shape:
the `runtime` image target, no source mounts, `restart: unless-stopped`, a
Redis reachable only on the compose network and persisting to a volume
(`--appendonly yes`), a **required** `.env`, and the signing-key pair mounted as
compose secrets at `/run/secrets/jwt_private_key` / `jwt_public_key`. Its
`environment:` block pins `NODE_ENV=production`, `DEPLOYMENT_MODE=single`,
`SESSION_SECURE=true`, `SESSION_NAME=__Host-auth.session`,
`SESSION_STORAGE_TYPE=redis`, `RATE_LIMITER_ADAPTER=redis`, and both Redis
URLs to `redis://redis:6379`. The app port is published on loopback only
(`127.0.0.1:3000:3000`).

What it deliberately leaves to you (its own header says so): TLS termination
in front plus `HTTP_TRUST_PROXY` naming that hop; the multi-replica steps above
before any `--scale`; and every secret.

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
| `repositories.user.http.authenticateUrl` / `authenticateByTokenUrl` (`CLIENT_USER_AUTHENTICATE_URL`, `CLIENT_USER_AUTHENTICATE_BY_TOKEN_URL`) | absolute `https` (loopback `http` only); `timeout` a positive integer ≤ 2147483647 ms | `packages/foundation/src/repositories/HttpUserRepository.mts` |
| `refreshTokenFamilyStore.redis.url` (`REFRESH_TOKEN_FAMILY_STORE_REDIS_URL`) | required whenever any Redis adapter is selected — it is the one shared socket | `templates/standalone/src/modules.mts` (`standaloneRedisClientsModule`) |
| `rateLimit.failMode` (`RATE_LIMIT_FAIL_MODE`) | `"open"` or `"closed"`; `reference.conf` ships `"closed"` | `application.schema.mts`; read by every guarded route |
| `audit.sink.type` (`AUDIT_SINK_TYPE`) | a registered sink name. Core accepts `"none"` as a declaration; the standalone registers no `"none"` builder, so there an unknown type (including `none`) fails boot naming the sinks that exist | `packages/core/src/audit/types.mts` (`AUDIT_SINK_ABSENCE_POLICY`); `templates/standalone/src/modules.mts` (`auditSinkModule`) |
| `oauth.deviceAuthorization.verification-uri` | required once `oauth.deviceAuthorization.enabled = true`; the device displays it verbatim | `packages/device-grant/src/module.mts` |
| `oauth.mtls.full-pki.revocation.mode` / `.on-unavailable` / `.allowed-hosts` | all three required under `mode = "full-pki"` with `revocation.mode = "crl"`; there is no default for what an outage means | `packages/mtls/src/module.mts`, `packages/mtls/src/reference.conf` |
| `http.readinessTimeoutMs`, `session.csrf.ttlSeconds`, token lifetimes, `session.maxAge` | positive integers. An **exported-but-empty** variable is `""`, which coerces to `0` and is refused — the failure it prevents is a zero lifetime or a probe that always times out | `application.schema.mts` |

### Boot refusals you will meet

Every boot-time failure is a `BootError` with a `reason` and a `stage`
(`packages/core/src/boot/types.mts`). The ones an operator meets, and the key
each names:

| `reason` | Trigger | What to change |
| --- | --- | --- |
| `config-validation-failed` | a Zod issue from the table above, or a retired key still present (see [§7](#7-upgrading-and-rollback)) | the issue path names the key |
| `missing-required-component` | a module's `requires` has no provider. The standalone adds `standalone:redis-clients` whenever an adapter switch selects Redis, so there this only arises through `BuildModulesOverrides` (`templates/standalone/src/buildModules.mts`) | the message names the missing slot and the requiring module |
| `component-absence-undeclared` | an optional slot with an `AbsencePolicy` is unfilled and config does not declare it absent (`packages/core/src/modules/manifest/absence-policy.mts`, enforced by `checkDeclaredAbsence` in `boot/validate-manifests.mts`) | wire the component, or write the declaration: `audit.sink.type = "none"` (auditSink), `oauth.revocation.accessToken = "unsupported"` (accessTokenDenylist), `oauth.revocation.subject = "unsupported"` (subjectRevocation + subjectSessionIndex), `oauth.deviceAuthorization.store = "unsupported"` (deviceCodeStore) — sources: `core/src/audit/types.mts`, `core/src/access-token-denylist/types.mts`, `core/src/user-sessions/types.mts`, `packages/device-grant/src/reference.conf` |
| `replica-unsafe-adapter` | `deployment.mode = "multi"` with a listed module wired | the message lists every offender; switch the adapter or set `single` |
| `federation-stores-incomplete` | `federations.<name>.enabled = true` without all of `userSessionStore`, `sessionRPRegistry`, `sessionFamilyIndex`, `sessionFederationIndex`, `federationTokenStore`, `refreshTokenFamilyRevocation` | the message lists the missing slots |
| `grant-policy-without-issuer` | a `grantPolicy` is wired and `oauth.jwt.issuer` is empty | set the issuer |
| `provides-factory-failed` / `contribute-factory-failed` | a module's own check threw; the module's message is the `cause` (`boot/materialize-components.mts`) | see the module messages below |

Module-level messages that arrive wrapped in a factory failure:

- Keys: `privateKey or privateKeyPath is required for EdDSA algorithm — no signing key is configured` (with the `openssl` commands); `Duplicate kid values: …`; `previousKeys is not valid for HS256 — use previousSecrets` and the mirror for asymmetric algorithms (`packages/core/src/keys/factory.mts`).
- Standalone Redis: `` `refreshTokenFamilyStore.redis.url` is required when any Redis-backed adapter is selected `` (`templates/standalone/src/modules.mts`).
- Federation tokens: `mode "allow-plaintext" is not allowed in NODE_ENV="production"` unless `FEDERATION_TOKENS_ALLOW_INSECURE=1`, which then logs a `CRITICAL` line on every boot (`packages/redis/src/federation-tokens.mts`).
- Device grant: the four refusals for `verification-uri`, the `session` slice, `rateLimit.failMode` and a `rateLimiter` component (`packages/device-grant/src/module.mts`).
- mTLS: `source = "header"` with empty `trusted-proxies`; `mode = "pki"`/`"full-pki"` with empty `trusted-cas`; `mode = "pki"` with `source = "tls-layer"`; `full-pki` without `revocation.mode` + `on-unavailable`; `revocation.mode = "crl"` with empty `allowed-hosts`; `revocation.mode = "ocsp"` is refused, not ignored (`packages/mtls/README.md` "Boot-time fail-loud invariants", `packages/mtls/src/module.mts`).
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
| Shared Redis down — **rate limiter**, `rateLimit.failMode = "closed"` (default) | `/oauth/token`, `/oauth/authorize`, `/oauth/introspect`, `/session/login`, `/oauth/device_authorization`, WebAuthn authentication options | `503 service_unavailable` "Rate limiter temporarily unavailable" | `rate_limiter_failed_closed` (error, with `tag`, `ip`, `error`); audit `rate_limit.unavailable` (`packages/core/src/ratelimit/guard.mts`) | one `commandTimeout` (1 s) per request in the standalone; see [§5](#failure-timing-on-the-shared-socket) |
| — same, `failMode = "open"` | same | request proceeds unlimited | `rate_limiter_failed_open` (error); audit `rate_limit.unavailable` | same |
| — **device verification** | `POST /oauth/device/verification` | the handler calls `rateLimiter.check` directly, outside `createRateLimitGuard`, so `failMode` does not apply: the rejection propagates as an unhandled error, `500 server_error` in the standalone | `unhandled_request_error` (`templates/standalone/src/terminalError.mts`) | `commandTimeout` |
| Shared Redis down — **refresh grant** | `grant_type=refresh_token` | `503 temporarily_unavailable` for a family-store, session-store or watermark outage (`packages/oauth/src/grants/refreshToken.mts`); the client keeps its token and retries | `refresh_token_revocation_store_unavailable` (error) for the watermark case | `commandTimeout`; CAS retries capped at `redisRefreshTokenFamilyStore.casRetryLimit` (default 3) then `conflict-exhausted` (`packages/redis/src/refresh-token-family.mts`) |
| Refresh-token **replay** (not an outage) | same | `400 invalid_grant` `replay_detected`; the whole family is revoked inside the same compare-and-swap (`packages/core/src/refresh-token-family/rotation.mts`) | — | — |
| Shared Redis down — **authorization code** | `GET/POST /oauth/authorize` | redirect with `error=server_error` "Failed to create authorization code" (`packages/oauth/src/routes/authorize.mts`) | — | `commandTimeout` |
| | `grant_type=authorization_code` | `503 temporarily_unavailable` "session store unavailable" when the code's session cannot be read (`packages/oauth/src/grants/authorization.mts`) | — | `commandTimeout` |
| Shared Redis down — **user session stores at login** | `POST /session/login` | `503 temporarily_unavailable` "Session store temporarily unavailable" when `userSessionStore.create` fails. If only the subject index write fails, the login **succeeds** and that session is invisible to a later credential-change cascade (`packages/session/src/routes/Session.mts`) | `subject_session_index_write_failed` (error) | `commandTimeout` |
| Shared Redis down — **denylist / watermark at verification** | every surface that accepts an access token; introspection | verification fails closed. Introspection answers `200 {"active": false}` (RFC 7662 has no outage slot); a family-revocation lookup failure there is audited (`packages/oauth/src/routes.mts`) | `jwt_verify_rejected` with `reason: "revocation_unavailable"` for either store — a denylist failure and a watermark failure are the same outage, and neither is reported as `revoked` (`packages/core/src/jwt/verify.mts`, #408 / #459); audit `introspect.store_unavailable` | `commandTimeout` |
| **Cookie session store** (connect-redis, its own node-redis client) down | every browser-session route | express-session hands a store error to `next(err)`, which the standalone's terminal handler answers as `500 server_error` (`templates/standalone/src/terminalError.mts`); the federation start/callback session saves answer `500 server_error` "Session store unavailable" themselves (`packages/session/src/routes/Federation.mts`) | `session_store_redis_error` (error) on every client error event, including during reconnect (`packages/session/src/store/factory.mts`); `readiness_probe_failed` for `session-store` | node-redis reconnects on its own; the provider no longer crashes on the `error` event |
| **KMS / remote signer** unavailable | any mint: `/oauth/token`, id tokens, logout tokens | nothing between `keyStore.sign` (`packages/core/src/grants/token.mts`) and the route catches a signer error, so it surfaces as `500 server_error` with `unhandled_request_error`. Verification and `/.well-known/jwks.json` are **unaffected**: the public halves are imported at construction and served from memory (`packages/core/src/keys/remoteSigning.mts`) | `unhandled_request_error` | whatever timeout your `RemoteSigner` applies — the store applies none. Boot itself needs one signer call for the self-check unless `verifyOnConstruction: false` |
| **CRL distribution point** unreachable, `full-pki`, `on-unavailable = "reject"` | `/oauth/token` with a client certificate | `400 invalid_certificate` from the token-binding middleware (`packages/mtls/src/errors.mts`, `packages/core/src/middleware/tokenBinding.mts`) | `mtls_revocation_unavailable_rejected` (warn, per certificate, with `reason` ∈ `no_distribution_point`, `fetch_failed`, `unparseable`, `no_next_update`, `stale`, `bad_signature`); `mtls_full_pki_validation_failed` (`step: "revocation status unavailable"`); `token_binding_proof_invalid` | `fetch-timeout-ms` (default 3000) — lookups for a path run in parallel so latency is the largest, not the sum; one in-flight fetch per URL; a failed URL is not retried for 30 s (`CRL_NEGATIVE_CACHE_TTL_MS`, not a knob; `bad_signature` exempt); `max-response-bytes` (default 1048576); 256 cache entries (`packages/mtls/src/fullPki/crl.mts`, `fullPki/validate.mts`, `packages/mtls/src/module.mts`) |
| — same, `on-unavailable = "allow"` | same | token issued | `mtls_revocation_unavailable_allowed` (warn) **per certificate waved through** — a permanent soft-fail is an unrevocable PKI wearing a revocation configuration | same |
| **Audit sink** failing | every audited route | nothing — `emitAuditEvent` dispatches without awaiting and swallows rejections (`packages/core/src/audit/factory.mts`) | nothing; drops are not counted (`templates/standalone/README.md` "Not published yet") | no latency is ever added |
| **Upstream IdP** down | `GET /session/oauth/federation/:name/callback` | `502 exchange_failed` "Token exchange with upstream IdP failed" (`packages/session/src/routes/Federation.mts`) | `federation token exchange failed` (warn) | the provider adapter's own fetch |
| | `POST /oauth/federation/:name/token` (upstream refresh) | `503 temporarily_unavailable` for a network failure, `429 rate_limited`, `410 re_authentication_required`, or `500 refresh_failed` (`packages/oauth/src/routes/federationToken.mts`) | audit `federation.token.reauthentication_required` / `federation.token.refresh_failed` | advisory lock in Redis (`ft:lock:`) |
| | `/oauth/federation/:name/logout` | `200 {"disconnected": true}` — local state is already cleared, the IdP session is orphaned (`packages/oauth/src/routes/logout.mts`) | audit `federation.logout.idp_unreachable` | — |
| **The Store** (user directory) down or slow | `POST /session/login`; federation callback; jwt-bearer grant | `503 temporarily_unavailable` "User directory temporarily unavailable" (`Session.mts`, `Federation.mts`); `503` with `jwt_bearer_user_repository_unavailable` (`packages/oauth/src/grants/jwtBearer.mts`) | `local login authenticate failed` (warn) | `repositories.user.http.timeout` (default 5000 ms) and `maxResponseBytes` (default 1048576) — a timeout is a thrown error, not a `null` user (`packages/foundation/src/repositories/HttpUserRepository.mts`) |
| **Client repository** lookup throws | client authentication on `/oauth/token`, `/oauth/introspect`, `/oauth/revoke`, device authorization | `401` — repository unavailability never admits a client (`packages/oauth/src/middleware/clientAuth.mts`) | `client lookup failed` / `client credential lookup failed` (warn) | the repository's own I/O |
| **`grantPolicy` hook** throws | every grant; `/oauth/authorize` | `503 temporarily_unavailable` "policy evaluation unavailable" (`packages/oauth/src/grants/_grantPolicy.mts`); redirect `error=temporarily_unavailable` at `/authorize` | — | the hook's own |
| **Device code store** | device flow | only the in-memory adapter ships (`packages/device-grant/README.md` "Storage"); there is no Redis outage mode to describe, and `multi` refuses it | — | store bounded at 10 000 records (`packages/core/src/device-authorization/memory.mts`) |

Two cross-cutting facts about these rows:

- **Rate-limit `429`s carry `Retry-After` only when the adapter reports a
  reset time.** The memory adapter does; the Redis adapter reports `remaining`
  and `limit` but no `resetAt` (`packages/redis/src/ratelimit.mts`), so behind
  Redis the client gets `RateLimit-Limit` / `RateLimit-Remaining` and no
  `Retry-After` (`packages/core/src/ratelimit/guard.mts`).
- **`/session/login` and the WebAuthn options route never run unguarded.**
  With no `rateLimiter` wired they fall back to a per-process memory limiter
  and say so once at boot (`login_rate_limiter_not_shared`,
  `webauthn_authentication_options_rate_limiter_not_shared`). The OAuth
  endpoints, by contrast, run with no limiter at all in that case
  (`packages/oauth/src/routes.mts`).

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
| `refresh_token_revocation_store_unavailable` (error) | `oauth/src/grants/refreshToken.mts` | refreshes are answering `503` because the watermark store is unreachable |
| `revoke_all_for_subject_incomplete`, `revoke_all_watermark_failed`, `revoke_all_list_sids_failed`, `revoke_all_cascade_failed`, `revoke_all_remove_sid_failed` (error) | `core/src/user-sessions/revokeAllForSubject.mts` | a credential change did **not** fully invalidate what was issued. `incomplete` means a store was not wired (composition gap); the others mean a wired store threw (outage — retry) |
| `subject_session_index_write_failed` (error) | `session/src/routes/Session.mts`, `Federation.mts` | a login succeeded that a later credential-change cascade will not find |
| audit `introspect.store_unavailable`, `logout.cascade_failed` | `oauth/src/routes.mts`, `oauth/src/routes/logout.mts` | introspection is answering `active: false` for outages; a logout left state behind |
| `mtls_revocation_unavailable_rejected` (warn), sustained | `mtls/src/fullPki/validate.mts` | your CRL distribution point is down and mTLS clients cannot get tokens |
| `mtls_revocation_unavailable_allowed` (warn), **any**, if you chose `allow` | same | each line is a certificate that was not revocation-checked; a steady rate means the PKI is effectively unrevocable |
| `jwt_bearer_assertion_verifier_unavailable`, `jwt_bearer_user_repository_unavailable` (error) | `oauth/src/grants/jwtBearer.mts` | the attestation service or the Store is down (`503` to devices) |
| `dpop_replay_store_unavailable` | `dpop/src/verifier.mts` | DPoP proofs cannot be checked for replay |
| `graceful shutdown: drain deadline exceeded, closing remaining connections`, `graceful shutdown: cleanup failed`, `graceful shutdown: server close failed` (error) + non-zero exit | `templates/standalone/src/shutdown.mts` | a replica did not drain within `drainTimeoutMs` (default 10 s) or could not release its connections |

### Investigate — security signals worth a dashboard and a threshold

| Event | Where | Meaning |
| --- | --- | --- |
| audit `device.rate_limited`; log `device_verification_rate_limited` (warn) | `device-grant/src/verificationEndpoint.mts` | an **account** (the key is the authenticated subject) is guessing device codes |
| `jwt_verify_rejected` (warn) by `reason` | `core/src/jwt/verify.mts` | `kid_unknown` = a fabricated key id; `kid_expired` = a token signed with a key whose overlap window closed (see [§6](#6-key-rotation)); `revoked` = a revocation finding, or a fail-closed refusal when the watermark cannot be compared: a denylist hit, a token predating the subject's watermark, or a token with no `iat` while a watermark is in force (#376); `revocation_unavailable` = the denylist or the watermark store was unreachable — an outage, not a finding (#408 / #459); `signature` / `alg` / `iss` / `aud` / `typ` = malformed or foreign tokens |
| `csrf_origin_rejected`, `csrf_token_rejected` (warn) | `session/src/csrf.mts` | cross-site POSTs to login/logout/device verification, or a UI on an origin you forgot to list in `session.csrf.trustedOrigins` |
| `mtls_untrusted_proxy_rejected` (warn) | `mtls/src/extractor.mts` | a forwarded certificate header from a peer not in `trusted-proxies` — a missing allowlist entry or a forgery attempt |
| `mtls_chain_validation_failed`, `mtls_full_pki_validation_failed` (warn) | `mtls/src/extractor.mts` | certificate refused; `step` says why (`certificate revoked`, `no path to trust anchor`, …) |
| `token_binding_proof_invalid`, `protected_resource_binding_proof_invalid`, `dpop_signature_invalid`, `dpop_alg_not_allowed` | `core/src/middleware/*.mts`, `dpop/src/verifier.mts` | bad proof-of-possession material |
| `introspect_non_access_token`, `introspect_compound_cnf_rejected` (warn) | `oauth/src/routes.mts` | a refresh/id token presented as a bearer credential; a token with two bindings, which this server never mints |
| audit `authorize.rejected`, `token.issued.failure` (by `details.reason`), `introspect.family_revoked`, `logout.family_revoked`, `federation.token.forbidden`, `federation.token.family_revoked` | `oauth/src/routes.mts`, `routes/authorize.mts`, `routes/logout.mts`, `routes/federationToken.mts` | refusals and revocations; a spike in `token.issued.failure` with one `reason` is either an attack or a broken client |
| `http_request_duration_seconds{status="429"}` | `templates/standalone/src/metrics.mts` | rate limiting engaged; correlate with `HTTP_TRUST_PROXY` — one bucket for everyone is a misconfiguration that reads like an attack |

### Configuration drift — emitted once, at boot or on first use

| Event | Where | What to do |
| --- | --- | --- |
| `replica_unsafe_adapters` (warn) | `core/src/boot/replica-safety.mts` | `deployment.mode` is unset; set it |
| `login_rate_limiter_not_shared`, `webauthn_authentication_options_rate_limiter_not_shared` (warn) | `session/src/routes/Session.mts`, `webauthn/src/module.mts` | no shared `rateLimiter`; the guard is per-process |
| `pkce_config_ignored_s256_is_mandatory` (warn) | `oauth/src/grants/pkce.mts` | a retired PKCE key (or `OAUTH_GRANTS_AUTHORIZATION_CODE_PKCE_REQUIRE_S256`) is still set; delete it |
| `jwt_verify_aud_skipped`, `jwt_verify_iss_skipped` (warn, once per logger) | `core/src/jwt/verify.mts` | a verification surface is not pinning `aud`/`iss` |
| `jwt_verify_legacy_typ` (warn) | `core/src/jwt/verify.mts` | `OAUTH_JWT_LEGACY_TYP_ACCEPT=true` is admitting typ-less tokens; close the window |
| `federationTokenStore: in-memory adapter is for dev/test only …` (warn) | `core/src/federation-tokens/factory.mts` | the standalone builds this store in memory unless a `federationTokenStore` section is configured |
| `[federation-tokens] CRITICAL: running with mode="allow-plaintext" …` (console) | `redis/src/federation-tokens.mts` | `FEDERATION_TOKENS_ALLOW_INSECURE=1` is set in production |
| `` [buildModules] `repositories.code.type = "redis"` is deprecated `` (console) | `templates/standalone/src/buildModules.mts` | move to `oauth.code.adapter = "redis"` (`OAUTH_CODE_ADAPTER`) |

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
to the emission sites in both directions by a drift test, so this list is
complete for `v0.11.0`:

`authorize.granted`, `authorize.rejected`, `device.approved`, `device.denied`,
`device.rate_limited`, `federation.logout.idp_unreachable`,
`federation.logout.success`, `federation.token.family_revoked`,
`federation.token.forbidden`, `federation.token.reauthentication_required`,
`federation.token.refresh_failed`, `federation.token.success`,
`introspect.family_revoked`, `introspect.store_unavailable`,
`logout.cascade_failed`, `logout.family_revoked`, `logout.success`,
`rate_limit.unavailable`, `token.issued`, `token.issued.failure`.

None of the device events carries the user code or the device code
(`packages/device-grant/README.md`).

---

## 5. Redis

### Two connections, not one

| Connection | Configured by | Serves | Probe name |
| --- | --- | --- | --- |
| the shared **ioredis** socket, one per replica | `refreshTokenFamilyStore.redis.url` / `.password` (`REFRESH_TOKEN_FAMILY_STORE_REDIS_URL`, `…_PASSWORD`) | every `makeIoredisClients` purpose: refresh-token families, the six user-session stores, rate limiter, authorization codes, access-token denylist, federation tokens when Redis-backed (`templates/standalone/src/modules.mts`, `packages/redis/src/ioredis.mts`) | `redis` |
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
`REDIS_ACCESS_TOKEN_DENYLIST_KEY_PREFIX`; `packages/core/config/reference.conf`).

| Key | Type / value | TTL comes from | Source |
| --- | --- | --- | --- |
| `rtfam:<familyId>` | string, JSON `{familyId, activeJti, revoked, expiresAtMs}` | the family's `expiresAtMs` (`oauth.refreshToken.expiresIn`, default 86400 s). Set once at creation; rotation **never extends** it (`Math.min` in `rotate`) | `packages/redis/src/refresh-token-family.mts`, `core/src/refresh-token-family/rotation.mts` |
| `oauth:code:<code>` | string, JSON code record | `redisCodeRepository.defaultExpiresIn` (`CLIENT_CODE_DEFAULT_EXPIRES_IN`, default 600 s) or the per-call `expiresIn`; consumed with `GETDEL` | `packages/redis/src/code-repository.mts` |
| `atdeny:<jti>` | string `"1"` | the revoked access token's **remaining** lifetime; an already-expired token writes nothing | `packages/redis/src/access-token-denylist.mts` |
| `<tag>:ip:<ip>` — `token`, `authorize`, `introspect`, `login`, `device_authorization`, `webauthn-authentication-options`; `device_verification:user:<subject>` | integer counter | the prefix's `windowSeconds`: `defaultLimit` 60/60 s unless `redisRateLimiter.limits.<prefix>` is declared; `login` seeded 20 per 900 s from `rateLimit.login`; `device_verification` seeded 5 per 300 s from `oauth.deviceAuthorization.rateLimit`. The expiry is set atomically with the increment and only when missing, so a steady stream cannot hold a window open | `packages/redis/src/ratelimit.mts`, `ioredis.mts` (`LUA_INCREMENT_WITH_TTL`), `core/src/ratelimit/seededSpecs.mts` |
| `ss:us:<sid>` | string, JSON `{sid, sub, authTimeMs, createdAtMs, expiresAtMs, claims}` | the session's `expiresAt` (`SET … PX … NX`) | `packages/redis/src/userSessionStore.mts` |
| `ss:rp:<sid>` | hash, field = `clientId`, value = RP envelope | `session.expiresAt`, raised but never truncated (`PEXPIREAT NX` + `GT`) | `packages/redis/src/sessionRPRegistry.mts`, `internal/redisSidHash.mts` |
| `ss:fi:<sid>`, `ss:fed:<sid>` | sorted sets of family ids / federation names | same rule | `packages/redis/src/sessionFamilyIndex.mts`, `sessionFederationIndex.mts`, `internal/redisSidSortedSet.mts` |
| `ss:sub:<subject>` | sorted set of sids, **score = each session's expiry** | key TTL raised to the latest member expiry; members pruned on read against the server's `TIME` | `packages/redis/src/subjectSessionIndex.mts` |
| `ss:rev:<subject>` | string, epoch-ms watermark | the caller's `watermarkTtlMs` — sized to the **longest refresh token**, monotonic on both value and expiry | `packages/redis/src/subjectRevocation.mts`, `core/src/user-sessions/revokeAllForSubject.mts` |
| `ft:<sid>:<federation>` | string, AES-256-GCM-encrypted envelope | `redisFederationTokenStore.ttl` (default 86400 s) — the store lifetime, deliberately **not** the upstream access token's expiry | `packages/redis/src/federation-tokens.mts` |
| `ft:idx:<sid>` | set of federation names | same, raised with each write | same |
| `ft:lock:<sid>:<federation>` | string, advisory lock token | the lock's own | `packages/redis/src/internal/lock.mts` |
| `chal:…`, `replay:…` | strings `"1"` | the challenge / replay window, `SET … PX … NX` | `packages/redis/src/challenges.mts`, `replay-seen-set.mts` |
| `dpop:replay:<jkt>:<jti>` | string `"1"` | the proof's `ttlSeconds` | `packages/redis/src/dpop-replay-store.mts` |

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
  TTL passes.
- **Authorization codes** — one record per `/authorize` for ≤ 600 s; consumed
  codes are deleted on redemption.
- **Denylist** — one tiny key per revoked access token for its remaining
  lifetime (≤ `oauth.accessToken.expiresIn`, default 3 600 s). A deployment
  that never calls `/oauth/revoke` holds none.
- **Rate limits** — one counter per (prefix, client IP) per window. Behind a
  misconfigured `HTTP_TRUST_PROXY` every client shares one key, which is
  small and wrong.
- **Federation tokens** — one encrypted envelope per (session, federation)
  for 24 h plus one index set per session, only when federation is enabled.

The device-code store is not Redis: the memory adapter caps itself at 10 000
records "at a few hundred bytes each"
(`packages/core/src/device-authorization/memory.mts`).

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
  "Logout keys").
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
| `kid` (`OAUTH_JWT_KID`) | the key id stamped in every token header; default `v0` |
| `privateKeyPath` / `publicKeyPath` (or inline `privateKey` / `publicKey`) | PEM pair for the asymmetric algorithms; the file path wins when both are given |
| `secret` (`OAUTH_JWT_SECRET`) | HS256 only, ≥ 32 bytes decoded |
| `previousKeys = [ { kid, publicKeyPath, expiresAt } ]` (or inline `publicKey` instead of `publicKeyPath`) | asymmetric only — additional **verification** keys, published in JWKS until `expiresAt` (an ISO date; invalid fails boot) |
| `previousSecrets = [ { kid, secret, expiresAt } ]` | HS256 only — each secret clears the same 32-byte floor |

The two rotation shapes are a discriminated union in the schema
(`packages/core/src/config/application.schema.mts`): `previousKeys` under
`HS256`, or `previousSecrets` under an asymmetric algorithm, fails boot rather
than being dropped. `kid` values must be unique across the current key and
every previous entry (`Duplicate kid values`). There is no env binding for
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
  = 86 400 s (access tokens are `oauth.accessToken.expiresIn` = 3 600 s; id
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
   **`BREAKING:`** and every **Migration:** paragraph. Between cuts the pending
   entries sit under `## [Unreleased]`; no entry ever predicts a future version
   ([release-policy.md](release-policy.md) R1/R2), so what a release removed is
   stated only once it is cut.
2. Grep your config for the keys the release retired. A retired key does not
   get ignored — it fails boot naming the key and the release that removed it
   (`withRemovedKeys`, `packages/core/src/config/removed-keys.mts`; the
   decision rule is [release-policy.md §Retiring a config key](release-policy.md#retiring-a-config-key-366)).
   At `v0.11.0`:

   | Key | Mechanism | What you see |
   | --- | --- | --- |
   | `oauth.refreshToken.legacyTokenCompat` | removed | `oauth.refreshToken.legacyTokenCompat was removed in v0.6.0 (Phase G / M4); see CHANGELOG.` |
   | `oauth.authorize.allowUnmarkedClients` (and the env tombstone `OAUTH_AUTHORIZE_ALLOW_UNMARKED_CLIENTS`, any value) | removed | boot error with migration instructions: mark every client `firstParty: true`, then delete the key and the variable |
   | `oauth.refreshToken.legacyRtPolicy = "accept-with-warning"` | enum shrunk to `"reject"` | Zod `invalid_enum_value` naming the survivors |
   | flat `oauth.jwt.algorithm` / `kid` / `secret` / key fields | moved | `oauth.jwt has legacy flat fields (…). Migrate to nested shape: oauth.jwt.signingKey.local.<field>` |
   | `oauth.grants.authorization_code.pkce.*` (and `OAUTH_GRANTS_AUTHORIZATION_CODE_PKCE_REQUIRE_S256`) | warn and ignore | one `pkce_config_ignored_s256_is_mandatory` line; S256 is mandatory regardless (`packages/oauth/src/grants/pkce.mts`) |
   | `repositories.code.type = "redis"` | deprecated alias of `oauth.code.adapter` | a `[buildModules] … is deprecated` console line at boot |

3. Note the migration windows that are **still open** at `v0.11.0`, each of
   which you should be able to close after the upgrade rather than leave on:
   `redisFederationTokenStore.scanFallback` ([§5](#operational-notes)),
   `oauth.jwt.legacyTypAccept` (`OAUTH_JWT_LEGACY_TYP_ACCEPT`), and
   `oauth.refreshToken.unknownFamilyPolicy = "accept"`
   (`packages/core/config/reference.conf`).

### Rolling out

- The image is `node:24-alpine`, digest-pinned, with `tini` and a `runtime`
  stage that carries compiled JS and production dependencies only
  (`templates/standalone/Dockerfile`). `pnpm install --frozen-lockfile` means
  a committed `pnpm-lock.yaml` and `pnpm-workspace.yaml` are build inputs.
- CI builds the template against packed tarballs on Node 24 and runs every
  package's suite; it does **not** build or run the Docker image
  (`.github/workflows/ci.yml`). Your image build is the first place a
  base-image or native-addon (`bcrypt`) problem shows up.
- A replica drains for `drainTimeoutMs` (default 10 s) on `SIGTERM` and exits
  non-zero if it ran out of time; keep that below the orchestrator's kill grace
  period (`templates/standalone/src/shutdown.mts`).
- Under `DEPLOYMENT_MODE=multi`, a mixed fleet during the roll is fine for
  every Redis-backed store — the schemas below are what decide whether the
  *older* release can read what the *newer* one wrote.

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
