# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- **Observability: a `/metrics` endpoint, JSON logging, and a log-level threshold (`@o3co/auth-provider-core`, standalone template).** There were no metrics, no tracing hooks and no request logging anywhere in the repo. When token latency degraded or the fail-closed rate limiter began 503ing `/token`, the only signals were stderr lines and the load balancer's 5xx graph — no rate, latency or dependency-health series to alert on, and no way to tell "rate limiter failing closed" from "Redis-backed code repository gone" without grepping container logs.

  **`GET /metrics`** serves the Prometheus text format: `http_request_duration_seconds` (histogram by method / route / status — rate, errors and latency in one series), `auth_dependency_up` (1/0 per dependency), and Node process defaults under `auth_provider_`. The dependency gauge is sampled from the **readiness probes**, so it reflects what this deployment actually wired instead of a second list that drifts; it is re-sampled per scrape, because a cached verdict reports healthy for exactly as long as an incident lasts, and in-flight probes are joined rather than re-issued so a scrape loop cannot stack commands on a dependency already in trouble. Both labels an attacker can influence are bounded: route labels use the Express route **pattern** with unmatched requests collapsing to `route="unmatched"`, and the method label is an allowlist with everything else as `"other"` — Node's HTTP parser accepts any valid token, so `req.method` is as attacker-controlled as the path. Either left unbounded mints a fresh histogram child per distinct value, which is how a metrics endpoint takes down the monitoring meant to watch it, and neither requires access to `/metrics` to exploit. Requests are observed on `close` as well as `finish` behind a once-guard: a client that disconnects mid-handler emits only `close`, and those are disproportionately the slow and failing requests the series exist to surface.

  **`consoleLogger` gained a level threshold.** The interface has carried six levels since D-4 but the console-backed default emitted all of them unconditionally, so `trace` and `debug` fired in production. `createConsoleLogger(bindings, { level })` now filters, defaulting to `info`, with `silent` available for tests; children inherit the threshold rather than reverting to the default, which would have leaked debug output from exactly the request-scoped loggers most likely to carry request detail. New export: the `LogLevel` type.

  **The standalone template logs JSON through pino and fills the `logger` slot.** The slot was never filled before, and only a value satisfying core's `Logger` can occupy it — the logger the template used exposes four methods with a narrower call shape, so every module declaring `optional: ["logger"]` (oauth, session, dpop, mtls, token-exchange) silently fell back to its own `consoleLogger` and nothing configured in the composition root reached any of them. `Logger` was modelled on pino's two-overload signature, so a pino instance satisfies it with no adapter. `logging.level` (env `LOG_LEVEL`, default `info`) sets the threshold, and pino drops sub-threshold calls before formatting.

  **Deliberately deferred:** rate-limiter fail-closed counts and audit-sink drops. Both happen inside core and are not observable from the composition root; counting them needs a metrics hook in core (`BuilderContext` reserves `metrics` for it) rather than something the template can reach. Until then they remain visible as the `rate_limiter_failed_closed` and `rate_limit.unavailable` log events.

  **Migration:** `CoreConfigSchema` gains a required `logging.level`; deployments resolving config through the shipped `reference.conf` pick up the default. Anything relying on `trace`/`debug` reaching the console must now set `LOG_LEVEL`. `/metrics` and `/readyz` are both unauthenticated and mounted ahead of the auth router, so keep them off the public listener.

- **`GET /readyz` — a readiness endpoint that actually probes the backing connections (`@o3co/auth-provider-core`, standalone template).** `/_healthcheck` was the only health surface and it is a static `200` that never touches anything; the Docker `HEALTHCHECK` probed exactly that route. With Redis load-bearing for sessions, authorization codes and refresh-token families in the deployable defaults, a Redis partition left every login and token flow failing while the orchestrator and load balancer went on calling the pod healthy — nothing restarted, nothing paged, and traffic kept landing on a dead IdP.

  The two questions are now separate. `/_healthcheck` stays liveness — a static 200 proving the process is up, and deliberately so: restarting a container does not reconnect Redis, so a partition must not read as "kill this pod". `/readyz` answers whether the replica can serve, returning `503 {"status":"unready", …}` naming each failing dependency. Under Kubernetes wire `/readyz` to `readinessProbe` and `/_healthcheck` to `livenessProbe`. The image's `HEALTHCHECK` deliberately stays on `/_healthcheck`: Docker has one health signal, and on Swarm and ECS an unhealthy container is stopped and replaced, so pointing it at `/readyz` would reintroduce exactly the restart loop that keeping liveness static avoids.

  The response body carries `{ name, ok, durationMs }` and omits the failure message by default. This endpoint is unauthenticated by construction — an orchestrator has no credentials — and driver errors name internal topology (`connect ECONNREFUSED 10.0.3.14:6379`). The message goes to the log, where the reader has already authenticated; `includeErrorDetail: true` opts back in for endpoints reachable only from inside the deployment. For the same reason, keep `/readyz` off the public listener: it is mounted ahead of the auth router and so sits outside that router's rate limiter.

  Probes are registered by the builder that **opened** the connection, because that is the only place holding it — the adapters these builders return expose narrow command surfaces (`get` / `set` / `del`) with no `ping`, so a composition root cannot construct a probe from the outside. `BuilderContext` gains an optional `readiness` registrar alongside the existing `lifecycle` one, fed by a boot-planner-owned `readinessRegistrar` bootstrap slot (reserved, like `lifecycleRegistrar`, against consumer override — a second registrar would collect probes the planner never reads, and `/readyz` would answer ready with nothing probed). Collected probes surface on `AppHandle.readinessProbes`.

  Two probes ship: `redis` for the shared ioredis connection (one probe for the one socket, not one per consumed slot) and `session-store` for the connect-redis session client. A memory-only deployment registers neither and is always ready — absence of a wired dependency is not evidence of a broken one. Probes run concurrently under a per-probe deadline (`http.readinessTimeoutMs`, env `HTTP_READINESS_TIMEOUT_MS`, default `1000`); a partitioned Redis accepts the command and never answers, so without a deadline the endpoint would hang rather than report.

  Probes coalesce: a check that has not settled is joined by the next scrape rather than re-issued. Abandoning a check at the deadline does not cancel it, and against a partitioned Redis the driver holds the `PING` in its offline queue until reconnect — so without this every scrape adds a pending command, unbounded across a long outage and released as a burst on recovery. Each request still applies its own deadline, so a joining request does not inherit how long the shared check has already waited.

  `http.readinessTimeoutMs` is validated as a **positive integer no greater than 2,147,483,647**, which is load-bearing rather than decorative: HOCON substitutes a blank environment variable as `""` — a very ordinary shape in a `.env` file, a compose `environment:` entry, or an empty ConfigMap key — and `z.coerce.number()` turns `""` into `0`, which `setTimeout` clamps to 1ms. Every probe against a perfectly healthy Redis would then time out and the replica would answer 503 forever, draining all traffic with nothing actually wrong. Boot now rejects it loudly instead. The upper bound closes the same failure from the other direction: `setTimeout` silently clamps a delay above Node's timer range to 1ms, so an operator writing a large number meaning "be patient" would get the most impatient deadline possible.

  `createRouter as createHealthcheckRouter` is exported alongside it, and the standalone template now mounts both from core rather than hand-writing the liveness route. The healthcheck router previously existed in `packages/core/src/routes/` unexported and unreferenced, returning a different body (`{code, message}`) from the one the template served; it now returns `{"status":"ok"}`, matching what the template always sent.

  New exports: `createHealthcheckRouter`, `createReadinessRouter`, `runReadinessProbes`, the `ReadinessProbe` / `ReadinessRegistrar` / `ReadinessReport` / `ProbeResult` types, and `EventLogger` — the narrow logger shape injection seams accept, since a host logger that omits `trace` / `fatal` / `child` cannot satisfy `Logger` and, because narrowing preserves the full two-overload shape, cannot satisfy `Pick<Logger, "error">` either.

  Design rationale is recorded in `packages/core/docs/adr/2026-08-26-readiness-probes-registered-by-connection-owners.md`, and `CONTRIBUTING.md` gains "Writing an adapter builder that opens a connection" covering the listener / cleanup / probe trio.

  **Migration:** `CoreConfigSchema` gains the required `http.readinessTimeoutMs`. Deployments that resolve config through the shipped `reference.conf` (the standard 3-tier HOCON merge) pick up the default and need no change; a composition root that hand-builds a config object must add the key. `AppHandle` gains `readinessProbes` — additive, but a consumer asserting on `keyof AppHandle` will see six keys rather than five.

- **RFC 8707 Stage 2: resource → audience binding is now derived and enforced (`@o3co/auth-provider-oauth`).** Stage 1 (v0.6.x) forwarded the `resource` parameter to `GrantPolicyHook.evaluate` and stopped there — nothing bound the token to the requested resource, so a policy that allowed the request without narrowing the audience produced a token whose `aud` was the `allowedAudiences[0]` / issuer / client-id fallback, silently. With `oauth.resourceIndicator.enabled = true`, `client_credentials`, `refresh_token` and `authorization_code` now **derive** `aud` from a single requested resource when no policy narrows one — bounded by the client's `allowedAudiences` plus its own id, so naming a resource is not by itself enough to be issued a token for it — and return `400 invalid_target` (`requested_resources_not_in_audience: …`) when the resulting audience still does not represent every requested resource. This matches what `oauth-token-exchange` has enforced since v0.5.3, and means RFC 8707 works without a policy hook being wired.

  **`authorization_code` splits the two halves across endpoints** to preserve evaluate-once-at-authorize: `/authorize` forwards `resource` to the policy hook so the audience it narrows is persisted on the code — and rejects with an `invalid_target` redirect rather than issuing a code the token endpoint could never honour — while `/token` performs enforcement ONLY, comparing against the persisted audience with no policy invocation. See the ADR `packages/core/docs/adr/2026-07-31-rfc8707-resource-audience-binding.md`.

  Two behaviours worth calling out, both consequences of `aud` being a single string rather than choices made here: **two distinct resources are rejected** (one `aud` cannot represent both — issuing several tokens would change the token-endpoint response shape and is not required by §2), and a **repeated identical resource is accepted** (naming one target twice is not a widening). Enforcement is gated on the flag **alone**, not on a policy hook being wired, since a flag-on deployment without a policy still derives an audience.

  **Migration:** with `enabled = false` (the default) there is no behaviour change. Deployments already running `enabled = true` with a policy that does not narrow `grantedAudience` will begin seeing `invalid_target` where tokens were previously issued — that is the correction the flag was staged for. Stage 3 (`resource` MUST be present) remains a separate, unshipped toggle.

### Security

- **Sender-constrained access tokens are now enforced at protected resources, not only at `/oauth/token` (`@o3co/auth-provider-core`, `@o3co/auth-provider-dpop`, `@o3co/auth-provider-oauth`).** `tokenBindingMw` was mounted on `/oauth/token` alone. It establishes the binding a grant stamps into the issued token's `cnf` and says nothing about any later request — so `/oauth/userinfo`, `POST /oauth/federation/:name/token`, `/oauth/logout` and bearer self-introspection accepted a `cnf`-bearing access token as an ordinary Bearer JWT, with no proof-of-possession check anywhere. A stolen DPoP- or mTLS-bound token replayed as a plain Bearer at every one of them, which is precisely what binding it was supposed to prevent. The federation-token endpoint is the sharpest case: it dispenses the user's **upstream Google / GitHub access token**, so the replay leaks third-party credentials.

  **`protectedResourceBindingMw`** (new, core) now guards those surfaces. For a token carrying a `cnf` it requires two things: the wire scheme matches the binding — `cnf.jkt` REQUIRES the `DPoP` auth scheme per RFC 9449 §7.1, `cnf["x5t#S256"]` keeps `Bearer` because RFC 8705 does not redefine the wire-level token type — and a mechanism **of the kind that owns that `cnf` variant** validated the material presented on this request and produced the same confirmation value. Gating on the mechanism's `kind` rather than on the confirmation's shape is the same stance `grants/refreshToken.mts` already takes: `Confirmation` is a mechanism-extensible union, so a third-party mechanism emitting `{ jkt }` without ever validating a DPoP proof would otherwise be handed a bound token. Selecting by `cnf` variant also means an ambient mTLS mechanism — which fires on every request behind a proxy that injects a client certificate — cannot shadow the DPoP binding the token actually names. A compound `cnf` (both members) is refused rather than narrowed; this AS never mints one, so it indicates a forged token.

  **DPoP proofs are now bound to the token they accompany.** `parseProof` surfaces the RFC 9449 §4.2 `ath` claim and `computeAth` / `athMatches` implement the digest and its comparison, pinned against the worked example in §4.2 rather than against their own output. At a protected resource the claim is REQUIRED and verified against the presented token; without it a proof captured alongside one request authorises any *other* stolen token presented with it, since `htm` / `htu` / `iat` say nothing about which token a proof is for. The check is ordered **before** the replay check so a mismatched pair does not consume the proof's replay slot — otherwise an attacker who intercepts a proof could burn its `jti` and have the client's own request rejected as a replay. At the token endpoint there is no access token yet, so `ath` is not required there and a stray one is ignored.

  The mechanism contract gained an **optional** second `extract` parameter (`TokenBindingExtractContext`, carrying the presented access token) rather than having mechanisms sniff the `Authorization` header to infer which profile they are in. Every existing mechanism keeps compiling and behaving identically; the difference is that the `ath` requirement is now stated by the caller instead of depending on the middleware rejecting the wrong scheme first.

  The middleware is mounted **unconditionally**, deliberately unlike the `/oauth/token` mount which is skipped when no mechanisms are contributed. Access tokens outlive a config change, so a deployment that removes its DPoP module still has bound tokens in the wild; skipping the middleware there would let exactly those tokens silently downgrade to Bearer. With no mechanisms wired it admits every unbound token unchanged and refuses every bound one.

  New exports: `protectedResourceBindingMw`, `ProtectedResourceBindingOptions`, `TokenBindingExtractContext` (core); `computeAth`, `athMatches` (dpop).

  **Breaking:** a DPoP-bound access token must now be presented as `Authorization: DPoP <token>` with a matching, `ath`-bearing proof. Clients sending `Authorization: Bearer <dpop-bound-token>` to `/userinfo`, the federation-token endpoint, `/logout` or bearer self-introspection will receive `401 invalid_token` — that acceptance was the vulnerability. Those four endpoints now accept both the `Bearer` and `DPoP` schemes (matched case-insensitively per RFC 9110 §11.1, and as a whole scheme token rather than a prefix); unbound tokens are unaffected in every respect. Deployments that never enabled DPoP or mTLS see no behaviour change.

- **Token exchange no longer launders a sender-constrained token into an unbound one (`@o3co/auth-provider-oauth-token-exchange`).** The RFC 8693 grant did no `cnf` handling whatsoever — a DPoP- or mTLS-bound `subject_token` was accepted with **no proof-of-possession check**, and the issued token dropped the binding entirely. The whole value of binding a token is that stealing it is not enough without the key; exchange handed an attacker a conversion from "bound token I cannot use" to "ordinary bearer token for my own client". Scope-widening and audience-widening were already prevented, so the laundering was bounded to exactly this: the loss of the sender constraint.

  The grant now runs the same two 5-row matrices `packages/oauth/src/grants/refreshToken.mts` established for the refresh path, row for row:

  | subject `cnf.jkt` | proof JKT | outcome |
  | --- | --- | --- |
  | no | no | issue plain Bearer (unchanged) |
  | no | yes | issue DPoP-bound AT (opt-in upgrade) |
  | yes | no | reject `invalid_grant` |
  | yes | yes, differs | reject `invalid_grant` |
  | yes | yes, equal | issue DPoP-bound AT, binding preserved |

  The mTLS matrix is identical over `cnf["x5t#S256"]` and the presented client certificate. A compound `cnf` (both members) is rejected before either matrix runs — this AS never mints one, so it indicates a forged token. Each matrix reads only its own confirmation member and is gated on `ctx.tokenBinding.kind`: `Confirmation` is a mechanism-extensible union, so a third-party mechanism emitting `{ jkt }` without ever validating a DPoP proof would otherwise satisfy a DPoP-bound subject token.

  The checks run after subject validation but **before** policy evaluation, store I/O and the keystore signature, so a rejection short-circuits ahead of the expensive work. `invalid_grant` is the error rather than `invalid_dpop_proof`: the proof or certificate is well-formed and it is the grant that cannot be honoured, which is both more caller-actionable and what the refresh path already returns for the same rows.

  Enforcement covers `subject_token` only. A request carries exactly one `ctx.tokenBinding` — one DPoP proof, one client certificate — so a subject and an actor token bound to different keys could not both be satisfied by any caller, and requiring it would break legitimate delegation. The residual `actor_token` gap is tracked in #309.

  **Migration:** a client exchanging a bound `subject_token` must now present the matching DPoP proof or client certificate on the exchange request; without it the exchange returns `400 invalid_grant`. Deployments that never enabled DPoP or mTLS are unaffected — an unbound subject token with no binding presented behaves exactly as before.

- **`allowedGrantTypes` is now enforced for every grant, not just two of them (`@o3co/auth-provider-core`, `@o3co/auth-provider-oauth`).** The field was consulted only by `client_credentials` and the WebAuthn grant. `authorization_code`, `refresh_token`, token-exchange and the session grant never looked at it, so a client registered for one grant could exercise all the others — a client provisioned for machine-to-machine access could redeem authorization codes, refresh tokens and perform RFC 8693 exchanges, and the registration's restriction was silently void.

  The check moved to **grant dispatch** in `/oauth/token`, alongside the sender-constraint check that already sat there for the same reason: it runs once per request before the concrete handler, so every grant — including one registered later through `GrantFactory` — inherits it without opting in. `/authorize` gets the same check against `authorization_code`, so a client that may not use the code flow is turned away before the user authenticates and a code is minted rather than after. Both reject with `unauthorized_client` (RFC 6749 §5.2 / §4.1.2.1) and emit a `token.issued.failure` audit event carrying `reason: "grant_type_not_allowed"`.

  The central rule, exported as `isGrantTypeAllowed`:

  - **absent → unrestricted.** Absence means the registration declared no policy, not an empty one. The grants that ignored this field predate it, so denying on absence would revoke every grant from every registration written before it existed.
  - **declared → allowed iff the `grant_type` string appears in it**, compared exactly (`grant_type` is case-sensitive, and extension grants are URIs where a prefix match would be a namespace confusion).

  `client_credentials` and the WebAuthn grant keep their stricter **deny-by-absence** rule on top, so machine-to-machine access is still never acquired by omission. The two rules compose to the stricter of the pair: either can reject, and only the absent case distinguishes them.

  There is no deployment-level switch to make deny-by-absence the central rule; that posture is tracked in #311.

  **Migration:** a client with a declared `allowedGrantTypes` can now only use the grants it names. Audit registrations before upgrading — a client whose list was written when only `client_credentials` read it may be relying on other grants that the list does not mention, and those stop working. In particular **`allowedGrantTypes: []` now denies every grant**, where previously it denied only `client_credentials`; a registration that used `[]` to mean "not a machine client" while relying on `authorization_code` must list its grants explicitly. Clients that omit the field entirely are unaffected.



### Fixed

- **The Redis rate limiter's increment and expiry are now one atomic operation — a failed `EXPIRE` no longer 429s a client forever (`@o3co/auth-provider-redis`).** `check` ran `INCR`, then a separate `EXPIRE` **only when the count came back as 1**. A process death or an `EXPIRE` error in between left the key with no TTL at all, so its counter never reset: every later window saw a count above the limit and that key's client was rate-limited permanently. `failMode` could not rescue it either — the check itself succeeded, it just kept answering "denied" — so the deployment had a silently, indefinitely blocked client and a limiter that looked healthy.

  `RateLimiterClient`'s `incr` + `expire` pair collapses into a single `incrementWithTtl(key, ttlSeconds)`, moving atomicity out of the caller's discipline and into the contract, where an implementation cannot get it wrong by omission. The ioredis client implements it with a Lua script, alongside the compare-and-delete script already in that file:

  ```lua
  local count = redis.call('INCR', KEYS[1])
  if redis.call('TTL', KEYS[1]) < 0 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
  end
  return count
  ```

  The expiry is established whenever the key has **none**, rather than only on the first hit. That is what **repairs** a key already stranded without a TTL by the previous implementation — a count-based guard never fires for one, because its count never returns to 1 — so a deployment upgrading into this fix unsticks its blocked clients within one window instead of needing the keys deleted by hand. An existing expiry is left alone, so a steady stream of requests cannot hold a window open by refreshing it. `TTL < 0` rather than `EXPIRE ... NX` because the NX flag is Redis 7.0+ and this package runs against whatever Redis the consumer has.

  The check also costs **one** round trip now instead of two on a window's first request.

  Adjacent hardening in the same function: `limit` and `windowSeconds` are screened as positive integers, and a spec failing that falls back to `defaultLimit`. `rateLimitSpecSchema` already required it, but `redisRateLimiterBuilder` accepts a config object that never passed the schema — and `windowSeconds: 0` reaches `EXPIRE key 0`, which *deletes* the key, so every request would see a count of 1 and the limiter would silently never limit anything. `defaultLimit` is screened the same way, being the fallback every unmatched key lands on.

  **Migration:** breaking for anyone with a **custom** `RateLimiterClient` implementation — implement `incrementWithTtl` in place of `incr`/`expire`. The contract requires the operation to be indivisible but not to use Lua; `SET key 0 EX ttl NX` followed by `INCR`, or a `WATCH`/`MULTI` transaction, satisfies it equally. Deployments using the bundled ioredis client (`makeIoredisClients`) need no change.

- **`/session/login`'s brute-force guard runs on the shared rate limiter instead of a per-process one (`@o3co/auth-provider-session`, `@o3co/auth-provider-core`, `@o3co/auth-provider-redis`).** The login limiter was `express-rate-limit` with its default MemoryStore, keyed by `req.ip`. Two failures compounded: `http.trustProxy` defaults to `false`, so behind a load balancer `req.ip` is the *balancer's* address and the configured 20 / 15 min became **one bucket shared by every user** — 20 attempts from anyone and everybody else gets `429`, an outage that reads like an attack. And even with `trustProxy` set correctly, a per-process store means the real limit is 20 × replicas and resets on every deploy. The OAuth endpoints already had a Redis-backed limiter; this route could not reach it.

  The route now uses the `rateLimiter` component the OAuth endpoints use, keyed `login:ip:<ip>` — the example key in `RateLimiter.check`'s own contract. Point `rateLimiter.adapter` at Redis and both surfaces are covered by one setting. `express-rate-limit` is gone from the package's dependencies: the product had two unrelated rate-limiting mechanisms, and the one without a Redis adapter was guarding the password endpoint.

  Failure handling matches the OAuth endpoints exactly — same `rateLimit.failMode` key, same `rate_limiter_failed_open` / `_closed` events, 503 when closed — so a Redis outage no longer means "login sheds load" in one place and "login lets everything through" in another.

  **The window and limit stay configured at `rateLimit.login`.** Adapters resolve a spec by key prefix from their own `limits` map, so a `login:` key would otherwise have fallen through to the adapter's `defaultLimit` of 60/60s — silently *weaker* than the documented 20 / 15 min, on the one endpoint whose job is resisting password guessing. Both bundled adapters now seed `limits.login` from `rateLimit.login` (`resolveLoginLimitSpec`, new export), keeping one source of truth rather than two numbers that must agree. An operator-declared `limits.login` still wins, and `reference.conf` documents the seeding beside both blocks.

  **A composition that wires no limiter keeps its protection.** The router builds a private in-memory limiter with the same spec and logs `login_rate_limiter_not_shared`. Leaving the route unguarded would have turned weak protection into none; the warning states the weakness instead of implying safety. `RateLimit-*` response headers are preserved, since this route emitted them before.

  `createMemoryRateLimiter`, `DEFAULT_MEMORY_RATE_LIMITER_MAX_BUCKETS`, `MemoryRateLimiterOptions` and `resolveLoginLimitSpec` are now exported from core.

  **Migration:** no config change is required, but two settings decide whether this is actually fixed for you, and the standalone README's multi-replica section now says so first: set **`HTTP_TRUST_PROXY=true`** behind anything that terminates TLS or proxies — without it every IP-keyed limit still shares one bucket — and set **`rateLimiter.adapter = "redis"`** for more than one replica. A consumer that constructs the session router directly should pass the new optional `rateLimiter`; omitting it keeps today's per-process behaviour with a warning.


- **A Redis blip no longer crashes the process — the node-redis session client and every duplicated ioredis connection now have `error` listeners (`@o3co/auth-provider-session`, `@o3co/auth-provider-redis`).** node-redis emits `error` on socket failures even while it is happily auto-reconnecting, and an EventEmitter `error` with no listener throws. The session store's client was created and connected with no listener anywhere, and `session.storage.type = "redis"` is the shipped default — so a Redis failover or maintenance blip took down the identity provider, and the restart reconnected into the same flapping Redis. The listener is now attached **before** `connect()`, since a connection failing during the handshake emits while `connect()` is still in flight.

  The same crash class was open on a hotter path. `refreshTokenFamilyClient.duplicate()` opens a fresh ioredis connection per refresh rotation, and ioredis `duplicate()` copies options but **not** event listeners — every duplicate started with zero `error` listeners. Those connections never leave the wrapper, so `makeIoredisClients` now attaches the listener itself; the connection the caller passes in stays the caller's to instrument.

  Both report through a structured logger rather than dropping the event. The session client reads `BuilderContext.logger` — the same context that already carries `lifecycle` and `readiness`, because a builder that opens a connection owns its cleanup, its probe **and** its error listener, and three arrival routes is how one gets forgotten. `makeIoredisClients(io, { logger })` takes one too, typed `EventLogger`. Both default to `consoleLogger`, so existing call sites compile unchanged. The standalone template's own ioredis handler moves off `console.error` onto the same channel, closing its `TODO(D-4)`.

  Worth being precise about what that buys today: **no module in this repo or in the standalone template actually provides the `logger` ComponentMap slot**, so in the shipped scaffold the session client's errors still land on `consoleLogger`. The plumbing is in place and correct; wiring a structured logger into the composition root is tracked separately. The template's ioredis path does get the structured logger, because the template passes its own logger directly.

  `Symbol.asyncDispose` on a duplicated connection no longer lets `quit()` reject. That disposal runs on an `await using` binding around a refresh rotation: a rejection there reports failure for a rotation that already committed, the client retries with the old refresh token, replay detection fires, and the entire family is revoked — the user is forced to re-login. When the body already threw, a rejecting disposal also buries the original error inside a `SuppressedError`. It now falls back to `disconnect()`, which tears the socket down synchronously and cannot reject.

  The standalone template's source also moves off the `#/logger.mjs` subpath alias onto a relative import. `#/*` maps to `./dist/*` under the default condition, so running the scaffold from source before its first build resolved to a file that does not exist yet — the same class of breakage #255 fixed for `@o3co/auth-provider-session`, and what AGENTS.md's module-resolution rule exists to prevent.

  The `@o3co/auth-provider-redis` README's composition example showed `new Redis(...)` with no `error` listener — the crashing shape, on the *shared* socket, for anyone following it. It now shows the listener and says the connection stays the caller's responsibility.

  Worth recording, since the original report assumed otherwise: with node-redis 6 a **boot-time** connection failure does not crash — `connect()` rejects cleanly and no `error` event fires unhandled — so the failure mode is a blip on an already-established connection, not the initial dial. Reconnection policy is left to node-redis's default; the handler's job is to make the event observed rather than fatal.
- **Access and refresh tokens from `authorization_code` carry a `sub` again — it now comes from the code-bound `UserSession` (`@o3co/auth-provider-oauth`).** The grant read the subject from the Express session attached to the `/token` request. For a confidential client that request is back-channel and carries no end-user cookie, so `session.user` was `undefined` and the access and refresh tokens were minted with **no `sub` claim at all**; the id_token was unaffected because it has always resolved the `UserSession` through the code's `sid`. Downstream, `/oauth/userinfo` answered `401 invalid_token: "missing sub claim"`, introspection exposed no subject so ABAC could not identify the user, and the `refresh_token` grant rejected its own refresh token with `invalid_grant: "refresh token has no subject"` — the canonical confidential-client deployment could not refresh. In a same-origin/BFF topology where `/token` *does* carry cookies the claim was present but could name a **different user** than the id_token if the browser session changed between `/authorize` and `/token`.

  The subject is now taken from the `UserSession` resolved via `codeData.sid` — the same source the id_token uses, so all three tokens agree — and falls back to the request session only for deployments that wire no `userSessionStore` and therefore have no `sid` to resolve. The fallback is gated on the store being **absent**, not on `sub` being nullish: a wired store that returns a record without a usable `sub` is refused with `invalid_grant` rather than quietly reverting to the cookie-derived identity, which would reintroduce the mismatch in the one topology where `/token` does carry cookies. Resolving the session before minting also means a session deleted between `/authorize` and `/token` is rejected before anything is signed; the store is still read exactly twice (initial check plus the CR-4 re-check before `addFamilyId`).

  Because the access and refresh tokens are signed from the first read and the id_token from the re-check, the grant now also refuses when those two reads disagree about `sub`. A subject change under a fixed `sid` is a store invariant violation, and reconciling it would mean handing back tokens that disagree about who the user is.

  One observable ordering change: a request that is both session-invalid and carries an unrepresentable RFC 8707 `resource` now answers `invalid_grant` where it previously answered `invalid_target`, because the session check moved ahead of the resource check.

  Every unit test for the grant injected `session: { user: { id: "u1" } }`, covering only the same-browser topology, which is why this survived. An end-to-end test now exercises a cookie-less exchange straight into `/oauth/userinfo`.

- **Published `@o3co/auth-provider-session` dist no longer breaks under `--conditions=development`.** `routes/Session.mts` and `routes/Federation.mts` imported the internal `extractUserClaims` via the `#/internal/extractUserClaims.mjs` subpath, and the package's `imports` map resolves `#/*` to `./src/*` under the `development` condition. Because Node applies runtime conditions to every package, a consumer that enables `--conditions=development` for its own hot-reload (Vitest, `tsx watch`) made the *shipped* dist resolve `#/internal/…` to `./src/internal/…`, which is not in the published tarball (`files` ships `dist`, `README.md` and `LICENSE` — never `src`) — so importing any session route threw `ERR_MODULE_NOT_FOUND`. The two imports are now relative (`../internal/extractUserClaims.mjs`), matching every other package in the workspace (none of which use `#/` subpath imports in shipped source), so the dist no longer depends on the `development` condition mapping. Session was the only package that exercised this path, and `publish-readiness` now asserts that no `#/` subpath specifier survives in any published tarball's `dist/`, so the class of bug cannot come back unnoticed.

- **`replayTtlSeconds` guidance corrected — it must be at least `2 × iatWindowSeconds + 1`, not `1 ×` (`@o3co/auth-provider-dpop`).** The JSDoc advised a TTL "at least `iatWindowSeconds`", which is not enough. The `iat` check is `Math.abs(floor(now) - iat) > W`, so it is both symmetric around `iat` and truncated to whole seconds: a proof with `iat = T` keeps being accepted until real time `T + W + 1` (exclusive). Its replay entry is written only after the window check passes, so the earliest it exists is `T - W`, and it expires half-open at `firstSeen + TTL`. Covering the accepted interval therefore needs `TTL >= 2W + 1`; below that — including at exactly `2W` — a proof outlives its own replay entry and can be replayed while still inside its acceptance window. `createDPoPMechanism` now also warns at construction (`reason: "replay_ttl_below_iat_window"`, carrying `requiredTtlSeconds`) rather than leaving this to documentation. The shipped defaults (`iatWindowSeconds` 60 / `replayTtlSeconds` 300) always satisfied the real requirement — only a deployment that raised `iatWindowSeconds` without raising the TTL was exposed.

### Added

- **Boot warning for a partly-migrated token-binding composition (`@o3co/auth-provider-core`).** A composition that contributes `tokenBindingMechanisms` **and** still mounts a `tokenBindingMw` through the legacy v0.7 `grantMiddleware` slot now logs a warning at boot (`reason: "token_binding_surface_overlap"`) naming the modules involved. `assembleApp` mounts the composed middleware first and `grantMiddleware` after, and `tokenBindingMw` assigns `req.tokenBinding` unguarded — so the leftover legacy middleware runs last and **always** overrides the composed surface, leaving the configured `dispatch-policy` inert. Nothing fails in that state: no error, no changed response shape, and the new surface still looks wired, which is why it is reported at boot. **If you upgraded from v0.7.x and adopted `tokenBindingMechanisms`, remove your own `grantMiddleware`-mounted `tokenBindingMw`** — otherwise you are still running v0.7 binding behavior. The warning stays silent for an un-migrated deployment (legacy surface only) and for ordinary `grantMiddleware` such as rate limiters. `grantMiddleware` itself is not deprecated; only its use as the mounting point for a token-binding mechanism is superseded. New export: `isTokenBindingMw`, the brand check driving the detection, for composition roots that mount `grantMiddleware` themselves.

- **`isCompoundConfirmation` (`@o3co/auth-provider-oauth`).** Predicate reporting whether a raw `cnf` claim carries BOTH a well-formed `jkt` and a well-formed `x5t#S256`. Member validation matches `extractConfirmation`, so a `cnf` whose second member is empty-string or non-string counts as single-mechanism-with-junk, not as compound. Exported for composition roots that build their own introspection surface and need the same admission check the bundled handler applies.

### Security

- **BREAKING: `oauth.jwt.issuer` is required, and `iss` is never derived from the request (`@o3co/auth-provider-core`, `@o3co/auth-provider-oauth`).** `/oauth/token` computed `config.oauth.jwt.issuer ?? req.get("host")`, so a deployment that had not configured an issuer minted **access and refresh tokens whose `iss` came from the `Host` header** — a value the caller controls behind a proxy the deployment trusts, and one that is a bare host rather than a URL. Any resource server that pins `iss` (the paired policy-verifier does, once it validates RFC 9068 §4) could be fed a token minted with an attacker-chosen issuer via `Host` / `X-Forwarded-Host`. The id_token path already refused the fallback for exactly this reason; AT and RT did not.

  The issuer is now a property of the deployment with no request-derived path to it at all. `oauth.jwt.issuer` is **required** by `CoreConfigSchema` and validated as a canonical issuer: an absolute `https` URL (`http` accepted only for a loopback host, so local development needs no TLS), with no query string, fragment, or embedded credentials — RFC 8414 §2 and OIDC Discovery require a stable absolute URL, and OIDC derives the metadata URL from the issuer, so a query or fragment would name a document the provider does not serve. `createOAuthRouter` re-checks and throws, because it also accepts hand-built config objects that never passed the schema. New exports from core: `checkCanonicalIssuer`, `isCanonicalIssuer`, `describeIssuerRejection`, and the `IssuerRejection` type.

  **Migration:** set `OAUTH_JWT_ISSUER` (or `oauth.jwt.issuer`) to your canonical provider URL. A deployment that omits it no longer boots — deliberately, because the alternative is minting tokens whose issuer a caller chooses. The standalone template moves the variable from its optional block to its required one.

  Two things stop being reachable as a result. `oauth.jwt.issuer` no longer doubles as the "this deployment is an OpenID Provider" signal — **`oauth.oidcMode` is now that signal on its own**, so an OAuth-only deployment that relied on leaving the issuer unset to avoid `openid`-required `/authorize` must set `oidcMode = "dual"` explicitly. And OIDC discovery, which mounts when an issuer is configured *and* a module contributes `providerRoot: true`, is now gated on the contribution alone: a composition wiring the OAuth provider surface without a module owning `jwks_uri` fails boot on the discovery document's presence contract where it previously mounted nothing.

- **The `session` grant now authorizes against the authenticated client, closing a scope self-elevation (`@o3co/auth-provider-oauth`).** The grant looked for the client in `body.client_id` and, when it was absent, accepted the requested scopes verbatim and minted a token with `aud: null` and `azp: null`. A confidential client authenticating with HTTP Basic — the canonical transport, and the one the shipped scaffold uses — sends its `client_id` in the `Authorization` header and *not* in the body, so that unchecked branch was the normal path rather than an edge case: any client that reached the grant could request `scope=admin:*` and be issued a validly-signed, audience-less token carrying it. Since the policy-verifier authorizes on the `scope` claim, the client's registered `allowedScopes` were not a ceiling on anything.

  Authorization now reads `ctx.authenticatedClient`, which `clientAuthMw` populates from RFC 6749 §2.3 token-endpoint authentication: its `allowedScopes` bound the request, `aud` comes from its `allowedAudiences[0]` (falling back to the client id, so no issued token can lack an audience), and `azp` names the client that asked. A request that somehow reaches the grant without client authentication answers `401 invalid_client`, matching `client_credentials` and `authorization_code`. `body.client_id` is no longer read at all, keeping the grant on the same "no identity decision reads the raw body" invariant as its siblings.

  **Migration:** a client whose registered `allowedScopes` do not cover what it asks for now receives `400 invalid_scope` where it previously received a token — widen the client's `allowedScopes` to the set it legitimately needs. An omitted `scope` still produces a token with no `scope` claim; it does not widen to the client's full allowlist.

  The `aud` change breaks in the direction that is easy to get backwards. These tokens previously carried **no** `aud` at all (`generateToken` omits the claim when it is null), so a resource server using the common lenient check — `if (payload.aud && payload.aud !== expected) reject` — accepted them by default. They now always carry one, so that same check starts **rejecting** them unless the audience matches. Give the client an `allowedAudiences` entry naming the resource server and its tokens are addressed to that server, which is the intended configuration; with no `allowedAudiences` the audience falls back to the client id and the resource server's expectation has to be updated instead. Per-client `allowedGrantTypes` remains unenforced for this grant — that is tracked separately in #268.

- **`/oauth/introspect` no longer vouches for a token carrying a compound `cnf` (`@o3co/auth-provider-oauth`).** An access token presenting BOTH `cnf.jkt` and `cnf.x5t#S256` was narrowed to the intent-explicit winner (`jkt`) and reported with `active: true`, advertising a binding the AS never issued. This provider cannot mint such a token — a grant emits exactly one mechanism's confirmation — so it indicates a forged token or a bug, and the handler now answers `active: false` before building a response. This matches the refresh path, which already rejects a compound `cnf` with `invalid_grant`, and it closes the gap between the two surfaces described in the token-binding ADR.

  Not an exploit fix: minting a compound `cnf` requires forging a JWT, and an attacker holding the signing key can mint a clean single-mechanism token regardless. The change is about consistency and about not masking evidence of a malformed token.

  **Note for anyone applying the same fix downstream:** rejecting inside `extractConfirmation` (so that `cnf` is dropped from the response) is *not* equivalent and is unsafe — `active` would stay `true` with no `cnf`, and a resource server would then treat a bound token as a plain bearer token and enforce no proof-of-possession. `extractConfirmation`'s narrowing behavior is deliberately unchanged; the rejection lives at the endpoint, via `isCompoundConfirmation`.

- **The `WWW-Authenticate` realm on the sender-constrained 401 is no longer request-derived (`@o3co/auth-provider-oauth`).** The sender-constrained reject path at `/oauth/token` built its challenge from a per-request local whose fallback is `req.get("host")`, and interpolated it into the `realm` quoted-string with no character filtering — every other emission site in the package runs the value through `SAFE_REALM_CHARS`, whose exclusion of `"` is what keeps the value from terminating that quoted-string. A deployment with `oauth.jwt.issuer` unset, behind a proxy it trusts, therefore let the caller append arbitrary auth-params to the header via the `Host` header (not response splitting — Node rejects CR/LF in outgoing header values). The realm now comes from the router-scope configured issuer only, through the filter. Exposure was bounded: production providers set `oauth.jwt.issuer`, since it is the `iss` claim and is required for OIDC and federation.

  **Behavior change for issuer-less deployments:** this path previously advertised the request Host as the realm when no issuer was configured; it now emits `realm="oauth"`, matching what `clientAuthMw` already emitted for the same deployment. Deployments that configure `oauth.jwt.issuer` — i.e. every production one — see no change. (Superseded within this same unreleased window: `oauth.jwt.issuer` is now required, so an issuer-less deployment does not boot and the realm is always the configured issuer.)

  Realm resolution now has a single definition (`resolveRealm`) shared by `clientAuthMw` and the reject path, so a future third emission site cannot reintroduce the gap. It is internal to the package: the public export surface is unchanged.

### Changed

- **BREAKING: minimum Node raised to `>=22.0.0` for every published package.** All published packages — the `@o3co/auth-provider-*` libraries and the `@o3co/create-auth-provider` scaffolder — previously declared `engines.node >=18.19.0` (`@o3co/auth-provider-webauthn` `>=20.0.0`); they now uniformly require Node `>=22.0.0`. Node 18 (EOL 2025-04) and Node 20 (EOL 2026-04) are past end-of-life; 22 and 24 are the supported LTS lines. Consumers on Node <22 get an install warning — and a hard failure under `engines-strict=true` — and must upgrade Node. The repo now pins its dev/CI toolchain to Node 24 via `.nvmrc`/`.node-version` (CI already ran on 24). The TypeScript emit target is lowered from `esnext` to `es2023` (lib stays `esnext`) so any syntax newer than the Node 22 floor is downleveled into inlined helpers rather than emitted verbatim — this fixes `@o3co/auth-provider-redis`, whose `await using` (explicit resource management) previously emitted as-is and would `SyntaxError` at module load on any Node before 24, despite the advertised floor. The deployable standalone template's own `tsconfig.json` gets the same `es2023` target so scaffolded projects downlevel identically, and `@types/node` is pinned to `^22` workspace-wide (pnpm `overrides`) so every package — not just the four that declared it directly — type-checks against the Node 22 floor deterministically. The exported `KeyLike` type in `@o3co/auth-provider-core` now references `webcrypto.CryptoKey` (from `node:crypto`) rather than the ambient global `CryptoKey`: both denote the same Web Crypto key shape, so the public type is unchanged for consumers — this only aligns the source with `@types/node@22` (which the codebase now type-checks against to enforce the Node 22 floor), where the key type is exposed via the `webcrypto` namespace instead of a bare global.

## [0.9.0] - 2026-07-01

### Added

- **`jwksModule` (`@o3co/auth-provider-core`).** A route-contributing module that publishes the provider's verification keys at the JWKS endpoint. It depends only on the `keyStore` and is mounted unconditionally — a provider that signs tokens must publish its keys regardless of whether an OIDC issuer is configured, so (unlike issuer-gated `oidc-discovery`) it is a key-management concern owned by core, not the `oauth` module. The standalone scaffold wires it alongside `oauthModule`. `createJwksRouter` remains exported for direct composition.
- **Configurable JWKS path via `oauth.jwt.jwksPath`.** `jwks_uri` is operator-choosable per OIDC Discovery; it now defaults to `/.well-known/jwks.json` and can be overridden (must be an absolute path). The JWKS route and the discovery `jwks_uri` both resolve the path through the new exported `resolveJwksPath` helper (with `DEFAULT_JWKS_PATH`), so the registered path and the advertised URI cannot drift.
- **JWKS responses now send `Cache-Control: public, max-age=<N>`.** JWKS is the most-polled verifier endpoint, so the response is now cacheable; `max-age` defaults to 300s and is operator-tunable via `oauth.jwt.jwksCacheMaxAge` (keep it well below the key-overlap window so a rotated kid propagates in time). New exports: `DEFAULT_JWKS_CACHE_MAX_AGE`, `resolveJwksCacheMaxAge`. `createJwksRouter`'s third argument is now an options object (`{ path?, cacheMaxAgeSeconds? }`).
- **OIDC discovery aggregation (`@o3co/auth-provider-core`).** New `discoveryMetadata` contribution kind: each endpoint-owning module contributes the issuer-relative endpoints + literal metadata it wants advertised (`OidcDiscoveryContributionFactory<Deps>` → `OidcDiscoveryContribution`), and core's discovery subsystem aggregates every contribution into the single `/.well-known/openid-configuration` document via the new exported `buildDiscoveryDocument` (+ `OidcDiscoveryContribution` type and `DiscoveryDocumentError`). The aggregator owns `issuer` (trailing-slash normalized) and `id_token_signing_alg_values_supported` (from `keyStore.algorithm`); array metadata is concatenated + de-duplicated across contributions and scalar conflicts fail the boot. Emission is activated by an EXPLICIT `providerRoot: true` marker on a contribution (set by `oauthModule` — the authorization-server surface owner), NOT inferred from a field name, so a provider without `authorization_endpoint` (CIBA, device flow) still activates discovery and a JWKS-only deployment stays inert. The document is validated at boot (required fields present AND non-empty; endpoint fields — by name OR by issuer-relative value shape — rejected from the literal `metadata` bucket); any invalidity surfaces as a `BootError` (`reason: "discovery-document-invalid"`, wrapping the `DiscoveryDocumentError`). Internally the document is emitted as an ordinary (synthesized) route contribution, so it flows through the standard route collision-check + mount-order pipeline — a module contributing a colliding `/.well-known/openid-configuration` route fails the boot fast. `jwksModule` contributes `jwks_uri`; `oauthModule` contributes its endpoints + capabilities (plus the logout fields when the session-store cascade is wired).

### Changed

- **BREAKING (behavioral): OIDC discovery is now synthesized by core, not the `oauth` module.** Previously `oauthModule` mounted an issuer-gated `oidc-discovery` route that built the whole document itself; now it contributes a `discoveryMetadata` slice (with `providerRoot: true`) and core aggregates + mounts the document. Aggregation activates only when (a) an issuer is configured AND (b) a contribution declares `providerRoot: true`, so a key-publishing deployment can still mount `jwksModule` alone (with or without an issuer) without being treated as an OpenID Provider. **Migration impact:** a composition that wires `oauthModule` with an issuer MUST now also install `jwksModule` — it contributes the OIDC-required `jwks_uri`, so an issuer-enabled OAuth provider that omits it now fails fast at boot with a `BootError` (`reason: "discovery-document-invalid"`) instead of silently serving a document whose `jwks_uri` points at an unmounted route. The served document is field-equivalent to the previous output for any composition that already wired both modules (pinned by an equivalence test). The standalone scaffold already wires `jwksModule` alongside `oauthModule`, so it is unaffected.

### Removed

- **Internal `routes/OpenidConfiguration` (`createRouter`) in `@o3co/auth-provider-oauth`.** The monolithic discovery-document builder is superseded by the core aggregator. It was never part of the package's public `exports` surface (reachable only via the internal `#/` import alias), so external consumers of `@o3co/auth-provider-oauth` are unaffected.

### Fixed

- **JWKS endpoint is now mounted.** `@o3co/auth-provider-core` shipped `routes/Jwks.mts` but no module mounted it, so OIDC discovery advertised `jwks_uri` while `GET /.well-known/jwks.json` returned 404 — verifiers (BFFs, RPs) had no key source for offline asymmetric-token validation. The new `jwksModule` mounts the route; an integration test pins that the advertised `jwks_uri` always resolves to the mounted route (including under a `jwksPath` override).
- **`jwksModule` now advertises `GET <jwksPath>` as a route.** Previously the JWKS route carried no `routes` advertisement, so the boot collision checker could not detect a second module claiming the same path — the JWKS route could be silently shadowed and the advertised `jwks_uri` broken. It now advertises the effective path (resolved once, shared with the router registration), so a collision fails the boot fast.

### Security

- **JWKS route sanitizes exported JWKs (defense-in-depth).** The `KeyStore` is a public extension point; a third-party / KMS adapter that mistakenly returns a private (or symmetric) key as its `publicKey` would previously have had `exportJWK`'s private components (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k`) spread straight into the JWKS response. The route now strips private JWK members and drops `kty:"oct"` keys entirely. Built-in key stores were never affected (they hold public material only).
- **`oauth.jwt.jwksPath` validation hardened.** Was `startsWith("/")` only, which admitted values (`/../keys`, `//x`, `/keys?x=1`, `/keys#f`, backslashes, `%2e%2e`, control/whitespace) that Express could normalize to a different dereferenced path than the route registers — breaking the route ↔ `jwks_uri` single-source guarantee. A single shared `isValidJwksPath` rule (config schema + `resolveJwksPath` + `createJwksRouter`) now rejects them.

## [0.8.0] - 2026-05-20

v0.8.0 ships **Wave 2 Token-binding Cluster** — sender-constrained access tokens via DPoP (RFC 9449) and mTLS (RFC 8705) as a first-class extension surface. Two new OSS packages (`@o3co/auth-provider-dpop`, `@o3co/auth-provider-mtls`), a new core abstraction (`TokenBindingMechanism` + `TokenBindingMechanismFactory<Deps>` + `tokenBindingMechanisms` contribution slot), grant-side `cnf` claim emission, and a §9.2 5-row refresh-time enforcement matrix per mechanism. Plus ADR `2026-05-20-token-binding-first-class-abstraction.md` documenting the design.

Zero behavior change for any v0.7.x consumer that does not opt into the cluster: both mechanism modules default to disabled (`oauth.dpop.enabled = false` / `oauth.mtls.enabled = false`); without opt-in, `req.tokenBinding` stays `undefined`, no `cnf` claim is emitted, and introspect responses are byte-identical to v0.7.x for tokens without `cnf`.

### Added (Wave 2 Phase 4 — end-to-end polish)

- **End-to-end integration test** pairing the issuance side (DPoP / mTLS bound AT) with `/oauth/introspect` — first test exercising both code paths on the same access token.
- **ADR `2026-05-20-token-binding-first-class-abstraction.md`** documents the Wave 2 design rationale (why `TokenBindingMechanism` is a first-class extension surface, what `Confirmation`'s narrowness buys, why the grant gate uses a mechanism allowlist, why cross-mechanism dispatch lives in core).
- **README updates** across `@o3co/auth-provider-core` ("Token-binding mechanisms" section under "Public API"), `@o3co/auth-provider-oauth` ("Token-binding cnf flow" section + refresh-time matrix), `@o3co/auth-provider-dpop` (quick-start + cross-mechanism dispatch), and `@o3co/auth-provider-mtls` (Phase 3 completion status).

### Added (Wave 2 Phase 3 — mTLS RFC 8705)

- **New OSS package `@o3co/auth-provider-mtls`** — RFC 8705 sender-constrained access tokens via mTLS. Ships `createMtlsMechanism` (header / tls-layer sources, envoy + plain-pem dialects), narrow-mode PKI chain validation with explicit cryptographic signature verification at every hop, and `mtlsModule` wiring via the core `tokenBindingMechanisms` contribution slot.
- **Grant-side `cnf.x5t#S256` emission** for both AT and RT (public clients per RFC 8705 §4 SHOULD). The §9.1 RT-emission gate widened from `bindingIsDpop && isPublicClient` to `(bindingIsDpop || bindingIsMtls) && isPublicClient`, structurally preserving the PR #185 mechanism allowlist (custom mechanisms emitting `{ jkt }` or `{ "x5t#S256" }` cannot satisfy a bound RT).
- **mTLS §9.2 refresh-time enforcement matrix** in the `refresh_token` grant, parallel to the existing DPoP matrix. Row 3 (cert absent) and row 4 (thumbprint mismatch) carry distinct error descriptions so SIEMs can distinguish "stolen RT replayed without cert" from "mid-rotation / multi-cert attack".
- **Compound-`cnf` pre-matrix reject** — an RT carrying BOTH `cnf.jkt` AND `cnf.x5t#S256` is rejected with `invalid_grant` BEFORE either matrix runs. Stage 1 supports single-mechanism bindings only; the runtime check is the cross-layer defense for JWT-decoded payloads (Phase 1's narrow `Confirmation` union is the TypeScript-layer defense).
- **Security fix in PKI chain validation** — `validateCertChain` now requires explicit cryptographic signature verification at every hop. The previous implementation used only `X509Certificate.checkIssued()` which performs DN / AKID / SKID / CA-bit matching but does NOT verify the signature (OpenSSL `X509_check_issued` documents this limitation). Pinned by a regression test with a committed attacker-leaf fixture (same DN as the legit root, different signing key).

See [packages/mtls/CHANGELOG.md](packages/mtls/CHANGELOG.md) for full Phase 3 detail.

### Changed (Wave 2 Cross-mechanism dispatch refactor)

- **New `tokenBindingMechanisms` contribution kind in `@o3co/auth-provider-core`.** Modules now ship a `TokenBindingMechanismFactory<Deps>` returning a raw `TokenBindingMechanism | null`; core's `assembleApp` collects all contributions, filters null returns, and composes ONE `tokenBindingMw` mounted on `/oauth/token` so the configured `DispatchPolicy` arbitrates cross-mechanism (resolves the §11.4 known limitation from Sub-PR 3b where each module mounted its own middleware and the second silently overwrote `req.tokenBinding`).
- **`oauth.tokenBinding.dispatch-policy` config key** moved to core's bundled `CoreConfigSchema` + `reference.conf` as the single source of truth. `dpop` and `mtls` modules no longer redeclare it. Env override: `OAUTH_TOKEN_BINDING_DISPATCH_POLICY`.
- **`dpopModule` and `mtlsModule` migrated** from the `grantMiddleware` slot to `tokenBindingMechanisms`. Mechanism internals (`createDPoPMechanism`, `createMtlsMechanism`) unchanged.

### Added (Wave 2 Token-binding Cluster — Phase 2 Sub-PR 2c)

- **RFC 7800 `cnf` claim emission in the 3 OAuth grants.** `client_credentials`, `authorization_code`, and `refresh_token` now propagate `ctx.tokenBinding?.confirmation` into the issued access-token's `cnf` claim, and set the response `token_type` to `"DPoP"` when the binding kind is `"dpop"` (mechanism-agnostic — mTLS keeps `"Bearer"` per RFC 8705 §3). Confidential clients (`tokenEndpointAuthMethod !== "none"`) get plain refresh tokens regardless of proof presence; **public clients with a DPoP binding** additionally receive a `cnf.jkt`-bound refresh token so the binding survives rotations. RT binding is DPoP-only in Phase 2 — mTLS public clients keep plain refresh tokens (Phase 3 will add mTLS RT-binding together with mTLS-aware refresh-time enforcement). Per Wave 2 Phase 2 spec §9.1 + RFC 9449 §5.
- **DPoP refresh-token binding matrix in the `refresh_token` grant** (spec §9.2, 5 rows). The grant correlates the RT's persisted `cnf.jkt` claim with the request-time DPoP proof BEFORE policy evaluation and token issuance. The 5 rows: (1) RT plain + no proof → issue plain Bearer (legacy preserved); (2) RT plain + proof → opt-in upgrade, bind new AT (public clients also get a bound RT); (3) RT bound + no proof → reject `invalid_grant` "refresh_token requires a DPoP proof"; (4) RT bound + proof JKT mismatch → reject `invalid_grant` "DPoP proof does not match refresh_token binding"; (5) RT bound + proof JKT match → rotation preserves binding (AT + RT for public clients). Error code is `invalid_grant` (RFC 6749 §5.2) — at refresh time the RT IS the grant, so a missing/mismatched proof is a grant-level failure, not a proof-level failure. JKT comparison uses plain string equality because the thumbprint is a hash of a public key (no secret material → no timing-side-channel exposure).

**Phase 2 of Wave 2 Token-binding Cluster (DPoP — RFC 9449 Stage 1) is now complete.** The skeleton (Phase 1) + `@o3co/auth-provider-dpop` package (Phase 2a/2b) + grant integration (Phase 2c) compose into a working DPoP-enabled OAuth provider. Phase 3 will add mTLS (RFC 8705) as a sibling `TokenBindingMechanism`.

### Added (Wave 2 Token-binding Cluster — Phase 2 Sub-PR 2b)

- **`createDPoPMechanism` factory** producing a `TokenBindingMechanism` for use with `tokenBindingMw`. Implements the RFC 9449 §6 15-step proof validation sequence: header presence, single-value guard, structural validation via `parseProof`, alg allowlist, signature verification, `htm` / `htu` match, `iat` acceptance window, replay check, return `{ kind: "dpop", confirmation: { jkt } }`. The `htu` comparison normalizes both sides via `normalizeHtu` (RFC 3986 §6.2.2: scheme + host lowercase, default-port stripping, dot-segment removal, unreserved decode, userinfo rejection). The replay-check catch is narrowed so transport faults surface as the distinct `replay_store_unavailable` audit signal, while programming-contract violations (`RangeError` on non-positive TTL, `DPoPError` from a future implementation that shapes replay errors directly) propagate unchanged so operator triage points at the right layer (Redis health vs. config bug).
- **`dpopModule` declarative manifest** wiring the mechanism into the `grantMiddleware` slot. Default-off (`oauth.dpop.enabled = false` per `feedback_secure_default_opt_in`); when `enabled = true`, mounts `tokenBindingMw` wrapping the DPoP mechanism BEFORE grant dispatch on `/oauth/token`. Boot fails loudly when `oauth.dpop.replay-store = "redis"` is configured but the `dpopReplayStore` ComponentMap slot is not wired — silently falling back to per-process in-memory state would bypass cross-replica replay protection.
- **`ComponentMap.dpopReplayStore` slot augmentation** so consumers wire a Redis-backed adapter (`@o3co/auth-provider-redis/dpop`) via `provides` without modifying the dpop package. Optional slot — absent = memory fallback (dev/test only). Mirrors the pattern established by `webauthnCredentialStore` (core) and `accessTokenDenylist` (Wave 1).
- **Zod schema for `oauth.dpop` config slice** (`dpopConfigSchema`) — kebab-case keys matching reference.conf verbatim, with secure defaults: 60-second `iat-window-seconds`, 300-second replay TTL, ES256/ES384/EdDSA/RS256 alg allowlist.

### Added (Wave 2 Token-binding Cluster — Phase 2 Sub-PR 2a)

- `@o3co/auth-provider-dpop` package skeleton (publishes as new opt-in OSS package).
- `DPoPReplayStore` interface with in-memory implementation (dev/test only — multi-process deployments require the Redis adapter).
- `@o3co/auth-provider-redis` Redis-backed `createRedisDPoPReplayStore` adapter using `SET NX PX` for atomic check-and-mark.
- `parseProof` JOSE-shape validator + `DPoPProof` / `DPoPProofClaims` types.
- `computeJkt` RFC 7638 SHA-256 thumbprint helper.
- `DPoPError` with hard-coded `code: "invalid_dpop_proof"` + granular `reason` for audit emission.

### Added (Wave 2 Token-binding Cluster — Phase 1 retro)

- **`ContributesMap.grantMiddleware` contribution kind in `@o3co/auth-provider-core`.** Modules may now contribute Express middleware that mounts on the OAuth token endpoint (`/oauth/token` with the bundled `oauthModule`) BEFORE grant dispatch — the declarative composition surface for `tokenBindingMw` (Phase 1) and the DPoP / mTLS mechanism packages (Phase 2 / 3). Factories that return `null` (disabled-by-config path — e.g. `oauth.dpop.enabled = false`) are skipped at mount time so the kind doubles as the on/off switch. Existing modules see zero behavior change (the field is optional and no shipped module contributes it yet). Mirrors the session package's A5 Phase 7 augmentation of `federationRedirectPolicies`.

### Added (Wave 2 Token-binding Cluster — Phase 1c)

- **`SenderConstraint = { required: boolean; methods: readonly string[] }`** in `@o3co/auth-provider-core`. Method-agnostic per-client requirement; handles DPoP + mTLS + future binding mechanisms symmetrically (replaces the originally-considered per-grant `dpopRequired` field).
- **3-layer propagation:** `Client.senderConstrained` → `PublicClient.senderConstrained` (auto via `Omit<Client, "clientSecret">`) → `AuthenticatedClient.senderConstrained` (via the `/token` route projection). `ClientEntrySchema` accepts the new optional field at config-load time so registered clients round-trip persist → load → projection cleanly.
- **Shared grant-dispatch enforcement on `/token`** (spec §4.8 step 2). Clients that set `senderConstrained.required = true` must present a binding whose `kind` is in `senderConstrained.methods`. Two-step reject — no binding → `invalid_client` (401); wrong kind → `unauthorized_client` (400) — runs once per request *before* the concrete grant handler. Custom grants registered via `GrantFactory` inherit the enforcement for free, with no per-grant code. Both reject paths emit `token.issued.failure` audit events with structured `details.reason` so operators can monitor sender-constraint misconfigurations / probe attempts.

**Phase 1 of Wave 2 Token-binding Cluster (skeleton) is now complete.** Phase 2 will ship `@o3co/auth-provider-dpop` (RFC 9449); Phase 3 will ship the mTLS support (RFC 8705). Both plug into this skeleton as `TokenBindingMechanism` implementations registered via `tokenBindingMw`.

### Added (Wave 2 Token-binding Cluster — Phase 1b)

- **`tokenBindingMw` middleware factory in `@o3co/auth-provider-core`.** Validates presented binding material via a pluggable set of `TokenBindingMechanism` implementations and resolves a single `TokenBinding` per the configured `DispatchPolicy`. The result is written to `req.tokenBinding` (ambient `Express.Request` augmentation shipped alongside) and copied into `GrantContext.tokenBinding` by the `/token` route. With no mechanisms registered (Phase 1b default), behavior is identical to v0.7.x — zero behavior change for any consumer that has not opted into the cluster.
- **`DispatchPolicy` enum** — `"intent-explicit"` (DPoP-class explicit wins over mTLS-class ambient when both succeed; ≥2 explicit succeeding → 400 `invalid_request`, per spec §3.5) and `"strict-mutual-exclusion"` (any 2+ succeeding mechanisms → 400 `invalid_request`, for high-security profiles). Closed union by design — adding a new strategy is a core semver-minor change; downstream consumers that need a different rule today compose a thin wrapper around `tokenBindingMw` post-dispatch.
- **`TokenBindingMechanism` plugin interface** — downstream packages register custom binding methods by implementing this interface and passing it to `tokenBindingMw`. Mechanism-thrown errors with snake_case OAuth-shaped `code` field are forwarded to the public `error` response; non-OAuth-shaped codes (e.g. Node `ECONNREFUSED`) fall back to `invalid_<kind>_proof` so infrastructure topology does not leak through the public envelope.
- **Ambient `Express.Request.tokenBinding?: TokenBinding` augmentation** shipped from `@o3co/auth-provider-core/middleware/express.mjs` (transitive import via the middleware module — no extra wiring needed).

### Added (Wave 2 Token-binding Cluster — Phase 1a)

- **`TokenBinding` base interface + `Confirmation` union in `@o3co/auth-provider-core`.** Cross-cutting types for the Wave 2 Token-binding Cluster (DPoP + mTLS in Phases 2/3). `TokenBinding` is an extensible base shape (`{ kind: string; confirmation: Confirmation }`) — mechanism packages and downstream users extend it with their own evidence fields. `Confirmation` is a narrow readonly union (`{ jkt } | { "x5t#S256" }`) covering the RFC 7800 / IANA-registry-domain claim variants this library ships in Stage 1; adding a new variant is a core semver-minor change.
- **`GrantContext.tokenBinding?: TokenBinding`** optional readonly field. Populated by `tokenBindingMw` (Phase 1b) before grant dispatch; `undefined` when no binding mechanism is enabled.
- **`GenerateTokenOptions.confirmation`** drives the JWT `cnf` claim. When set, `generateToken` emits `cnf` matching the provided `Confirmation`; when absent, claims are byte-identical to v0.7.x. `Token.confirmation` echoes the value back to callers for audit purposes.
- **`generateTokenResponse(tokens, { tokenType?: "Bearer" | "DPoP" })`** — second optional parameter for the wire-level `token_type`. Defaults to `"Bearer"`, matching existing behavior. The function body was refactored to spread construction so the new `readonly Token.confirmation` field can be set at construction without a cast.
- **`IntrospectResponse` interface + `extractConfirmation` helper in `@o3co/auth-provider-oauth`.** The introspect endpoint's inline JSON shape is now typed and re-exported from the package barrel for consumers (e.g. `auth.proxy` validation layer). The endpoint also reports `token_type: "DPoP"` when the introspected token carries a `cnf.jkt` claim per RFC 9449 §5 (mTLS bindings keep `"Bearer"` per RFC 8705 §3) and mirrors any valid `cnf` claim per RFC 7662 §2.2. `extractConfirmation(unknown): Confirmation | undefined` validates that cnf member values are non-empty strings (rejects malformed `{ jkt: 123 }`, `{ jkt: "" }`, etc.) before they reach the wire response.

Zero behavior change for any v0.7.x consumer that does not opt into the Wave 2 cluster (every existing consumer): `tokenBinding` stays `undefined`, no `cnf` claim is emitted, and the introspect endpoint produces byte-identical responses for tokens that lack `cnf`. See [the Wave 2 Token-binding Cluster spec](./.claude/superpowers/specs/2026-05-18-wave-2-token-binding-cluster-spec.md) for the full design (note: spec is internal — link kept for the in-repo reader).

## [0.7.0] - 2026-05-15

v0.7.0 ships **Wave 1** of the auth-provider passkey-native auth toolkit roadmap: a new `@o3co/auth-provider-webauthn` package, the `client_credentials` grant, RFC 7009 Token Revocation, RFC 8707 Stage 1 resource-indicator plumbing, and the library `reference.conf` shipping pattern.

### Added

- **`@o3co/auth-provider-webauthn` package — WebAuthn first slice (Wave 1 Phase 4, spec §2.4).** New OSS package providing:
  - `urn:o3co:oauth:grant-type:webauthn` grant — exchanges a verified WebAuthn assertion for an access token. Primary-login mode (passkey IS the authentication event, not a follow-up MFA factor). No refresh token in Wave 1 (deferred to a future minor).
  - `POST /oauth/webauthn/registration/options` — generates `PublicKeyCredentialCreationOptions` for the registration ceremony. Requires authenticated subject (upstream session / bearer middleware sets `req.webauthnSubject`).
  - `POST /oauth/webauthn/registration/verify` — verifies the attestation response and persists the new `WebAuthnCredential`. Single-use challenge consumed atomically via `ChallengeCeremony`.
  - `POST /oauth/webauthn/authentication/options` — generates `PublicKeyCredentialRequestOptions`. Unauthenticated; supports allow-list (`{userId}` body) and discoverable flows.
  - `WebAuthnCredentialStore` interface in `@o3co/auth-provider-core` — adapter contract for credential persistence with atomic-insert semantics: `registerCredential(record)` throws `WebAuthnCredentialStorageError({reason: "duplicate-credential"})` on collision (mirrors the established `RefreshTokenFamilyStore.registerFamily` / `ChallengeStore.issue` pattern). Includes atomic compare-and-set `updateSignCount` for WebAuthn §2.4 clone-detection.
  - `createMemoryWebAuthnCredentialStore` + `memoryWebAuthnCredentialStoreModule` — dev/test adapter shipped from core. Production deployments swap in their own Redis/Postgres adapter.
  - Wraps `@simplewebauthn/server@13.1.1` (exact-pinned) for attestation + assertion verification. Multi-origin support via `config.origin: string[]`. `attestationPreference` defaults to `"none"` (S11 — platform-authenticator friendly).
  - `webauthnModule` declares `grantPolicy` as optional in the type signature, but **enforces it at boot**: wiring `webauthnModule` without `grantPolicy` throws a fail-fast error during `createApp`. Unlike `client_credentials` (which narrows the requested scope through `client.allowedScopes` before policy runs) and `authorization_code` (narrowed at `/authorize`), the webauthn grant has no library-side scope ceiling — without policy, an attacker can request any scope and receive it verbatim.
- **`client_credentials` grant (Wave 1 Phase 2, spec §4).** New OAuth 2.0 RFC 6749 §4.4 grant for machine-to-machine credentials. Default-disabled at the library layer (`oauth.grants.client_credentials.enabled = false` in `reference.conf`); deployments needing M2M opt in per the `feedback_secure_default_opt_in` discipline. Implements CP-18 fail-closed scope/audience validation: scope is first narrowed to `requested ∩ client.allowedScopes` (the **effective request set**); when `grantPolicy` narrows further via `grantedScope`, the policy's returned set MUST be a subset of the effective request set (NOT the full `client.allowedScopes` ceiling — policy may not re-expand scope back to the client's allowlist). Empty `grantedScope: []` is honored as strip-all. Policy-returned audiences are validated against the full `client.allowedAudiences` ceiling (not narrowed by request — audience is a server-derived authorization decision, not a caller-narrowing parameter). The grant mints an access token with `client_id` and `authorizedParty` (azp) claims so `/oauth/revoke` can resolve token ownership.
- **`AccessTokenDenylist` interface + RFC 7009 `POST /oauth/revoke` endpoint (Wave 1 Phase 1).** Token revocation per RFC 7009: clients can revoke their own access tokens or refresh tokens. The endpoint always returns 200 per RFC 7009 §2.2 (fail-closed regarding token existence). For access tokens, ownership is resolved via `client_id ?? azp ?? aud` matching the revoking client; mismatch silently no-ops. `AccessTokenDenylist` is the optional persistence slot — when wired, revoked AT `jti` values are added to a denylist with expiry; the central JWT verifier consults it on every token validation. `createMemoryAccessTokenDenylist` + `memoryAccessTokenDenylistModule` ship from core; production deployments swap in a Redis adapter. Denylist consultation is gated on operator wiring (no implicit denylist = no behavior change for v0.6.0 consumers).
- **RFC 8707 Resource Indicator opt-in plumbing (`oauth.resourceIndicator.enabled`, default `false`)** (Wave 1 §5 — Stage 1).
  When opted in, `body.resource` (string or array of strings) is forwarded to the
  `GrantPolicyHook.evaluate(...)` request for `client_credentials` and `refresh_token`
  grants. The policy hook may use the parameter to narrow `grantedScope` or
  `grantedAudience`; both grants now also fail-closed on policy-returned scope or
  audience that is not a subset of the request / `client.allowedAudiences`
  respectively. The library does NOT itself enforce RFC 8707 §2 resource-to-audience
  binding at this stage — that is **Stage 2 (Wave 2)** scope (per spec §5.6). When
  `oauth.resourceIndicator.enabled` is absent or `false`, the entire path is a no-op
  and consumer behavior is byte-equivalent to v0.6.0.
  - **`authorization_code` deferred to Wave 2**: at the token endpoint, scope is
    already locked by the authorization-endpoint policy (C-2 / D-1 evaluate-once-at-`/authorize`).
    Plumbing resource into the auth_code grant requires a Wave 2 design that
    respects this invariant; for Wave 1 the auth_code token endpoint silently
    ignores `body.resource`. Token-exchange retains its independent RFC 8693 + 8707
    enforcement (§5.2 non-goal, unchanged).

### Changed

- **`@o3co/auth-provider-core` now ships `reference.conf` as a declarative defaults layer.**
  The package exposes `./reference.conf` via the `exports` field; the standalone composition
  root (`templates/standalone/src/app.mts`) chains it as the bottom-of-stack HOCON fallback.
  Consumers writing their own composition root should follow the same 3-tier
  `parseFile(env).withFallback(parseFile(application)).withFallback(parseFile(reference))`
  pattern. See ADR `packages/core/docs/adr/2026-05-13-reference-conf-shipping.md`.
- **All built-in OAuth grants now default `enabled = false` at the library layer.** The
  standalone template enables `session`, `authorization_code`, and `refresh_token` explicitly
  in its `application.conf`. `client_credentials` remains off by default — deployments needing
  M2M credentials opt in per the `feedback_secure_default_opt_in` discipline
  (`enabled = true` in `application.conf` or `OAUTH_GRANTS_CLIENT_CREDENTIALS_ENABLED=true`).
- **`rateLimit.failMode` library default flipped from `"open"` to `"closed"`.** Secure-by-default
  load shedding: when the rate-limiter backend errors, requests are rejected rather than passed
  through. Deployments that prefer fail-open override in their own `application.conf`.
- **`oauthAuthorizationModule` and `oauthSessionModule` grant registration is now strict opt-in.**
  Each grant is registered only when `oauth.grants.<name>.enabled` is explicitly truthy (boolean
  `true` or the string `"true"` produced by HOCON env-var substitution). All other values — absent,
  `false`, the string `"false"`, or unrelated truthy strings like `"yes"` / `"1"` — are treated as
  not-enabled. This restores correct env-disable behavior (under the previous check, `"false"` was
  silently treated as enabled) and keeps env-enable working via the documented
  `OAUTH_GRANTS_*_ENABLED=true` operator pattern. `GrantRegistry.addModule` (the internal
  legacy-init path) follows the same rule for symmetry.
- **Deprecation warning text generalization (R5/R6 hygiene).** The runtime deprecation
  warnings emitted by `redisCodeRepositoryBuilder` (`@o3co/auth-provider-redis`) and the
  standalone template's `buildModules` legacy `repositories.code.type = "redis"` path no
  longer name a specific removal version. Operators now see "see CHANGELOG for the removal
  version" instead of the stale "will be removed in v0.6" forward-promise (carried over
  from before v0.6.0 cut). The matching `@deprecated` JSDoc on `redisCodeRepositoryBuilder`
  and the inline R-9 comment in `buildModules` are similarly cleaned — these are
  consumer-visible via IDE hover tooltips and `tsserver` deprecated-symbol warnings, so
  R6 step 4 (JSDoc / code comments) covers them. Aligns with
  [`docs/release-policy.md`](docs/release-policy.md) R3 (`@deprecated since X` only,
  not `removed in Y`), R5 (operator-facing message strings use released version names
  only), and R6 step 4 (release-cut audit of JSDoc / code-comment forward-version refs).

### Security

- **WebAuthn grant `registerCredential` atomic-insert contract.** The `WebAuthnCredentialStore.registerCredential` contract requires N concurrent inserts of the same `credentialId` to result in exactly one success and N-1 throws of `WebAuthnCredentialStorageError({reason: "duplicate-credential"})`. The memory adapter enforces this via synchronous `Map.has`-then-`Map.set` (no `await` between them); SQL adapters MUST use a `UNIQUE` constraint; Redis adapters MUST use `SET NX`. The contract test suite (`runWebAuthnCredentialStoreContract`) includes a `Promise.allSettled(N=50)` test that falsifies non-atomic upsert implementations.
- **WebAuthn grant fail-fast on unwired `grantPolicy`.** The webauthn grant has no library-side scope ceiling — without `grantPolicy`, the caller-requested scope flows verbatim into the issued AT. `webauthnModule` therefore throws at boot if `grantPolicy` is not wired. Deployments intentionally accepting unbounded scope (NOT recommended) must wire an explicit no-op policy returning `{outcome: "allow"}`.
- **WebAuthn AT revocability requires authenticated client.** Webauthn-issued access tokens are revocable via `POST /oauth/revoke` only when the grant was invoked with an authenticated client (the AT carries `client_id` and `azp` claims). Unauthenticated webauthn mode mints tokens with no client binding; the revoke endpoint's ownership check (`client_id ?? azp ?? aud` must match the revoking client) cannot match, and revoke silently no-ops. Operators relying on AT revocation MUST require client auth on the webauthn grant path.
- **`webauthnConfigSchema.origin` URL-parse-based gate.** Each origin is parsed with `new URL()` and validated against an exact-match loopback allow-list (`localhost` / `127.0.0.1` / `[::1]`) for `http://`, plus `https://` for everything else. Wildcards (`*` in URL) are rejected. URL userinfo (`user@host`) is rejected. Prevents textual-prefix bypasses like `http://127.0.0.1.evil.com` or `http://127.0.0.1@evil.com`.
- **`WebAuthnSubject.userId` byte-length enforcement (WebAuthn §5.4.3).** Both registration endpoints validate `req.webauthnSubject.userId` is 1..64 bytes (UTF-8) — the W3C user-handle constraint. Consumer misconfiguration (e.g., passing `req.user.email` as userId) fails loudly with 500 `server_error` rather than silently leaking PII to the authenticator's user-handle.

### Migration notes

- **Standalone template upgrade**: consumers whose composition root was derived from `templates/standalone/src/app.mts` pre-v0.6.0 must adopt the new 3-tier `withFallback` chain at the same time they pick up the new template `application.conf` delta-form (otherwise the resolved config will be missing fields). The new template ships the chain inline; copy `resolveLibraryReferenceConfPath()` + the 3-tier `withFallback` block from `templates/standalone/src/app.mts` into your composition root. See ADR `packages/core/docs/adr/2026-05-13-reference-conf-shipping.md`.
- **`@o3co/auth-provider-webauthn` requires Node ≥ 20.0.0.** The package transitively depends on `@simplewebauthn/server@13.1.1` which requires Node 20+. Other auth-provider packages remain at Node ≥ 18.19. Consumers on Node 18.19.x must upgrade Node before installing `@o3co/auth-provider-webauthn`; the package will not run on older runtimes.
- **`webauthnModule` wiring requires `grantPolicy`.** Consumers adding `webauthnModule` to a composition root MUST wire `grantPolicy` via `@o3co/auth-provider-policy` or a custom `GrantPolicyHook` implementation. Boot fails fast with a clear error message naming the missing dependency.
- Consumers running the standalone template inherit the new default-off baseline automatically
  through the `withFallback` chain. If your `application.conf` already opts in to `session` /
  `authorization_code` / `refresh_token`, no change is needed.
- **`oauthSessionModule` silent behavior change**: previously the session grant was registered
  unless `oauth.grants.session.enabled === false`. Custom composition roots that omitted
  `oauth.grants.session` entirely (or shape-only without `enabled`) silently lose the session
  grant on upgrade. Add `oauth.grants.session = { enabled = true }` to your `application.conf`,
  or set `OAUTH_GRANTS_SESSION_ENABLED=true`. The standalone template ships this opt-in
  explicitly, so standalone deployments are unaffected.
- If you wrote a custom composition root (not the standalone template), add the library
  reference as the bottom-of-stack fallback:
  `parseFile(env).withFallback(parseFile(application)).withFallback(parseFile(libraryRef))`,
  where `libraryRef = fileURLToPath(import.meta.resolve("@o3co/auth-provider-core/reference.conf"))`.
- `packages/core/config/application.conf` has been renamed to `reference.conf`. Custom tooling
  or scripts that read that path need to be updated.

## [0.6.0] - 2026-05-12

### "1.0 GA" planning-label retirement

Pre-v0.6.0, the auth scope used "1.0 GA" as a planning anchor for a
batch of breaking removals and renames across `auth.provider`. As
release cuts diverged from plan, the label drifted: the v0.5.2 and
v0.5.3 CHANGELOG entries below reference "removal at 1.0 GA" for
changes that, in fact, **land in v0.6.0**. There is no
separate "1.0 GA" release — v0.6.0 supersedes that framing.

Concretely, the changes promised at "1.0 GA" in v0.5.x CHANGELOG
entries are realized here:

- `GrantRegistry` / `GrantRegistryError` public re-export removal (Phase G / M1)
- `*Base` interface aliases removal (Phase G / M2)
- `oauth.tokenExchange.allowPolicyWidening` flag removal (Phase G / M3)
- `oauth.refreshToken.legacyTokenCompat` flag removal (Phase G / M4)
- `oauth.refreshToken.legacyRtPolicy = "accept-with-warning"` enum value removal (Phase G / M6)
- `CodeRepository.getByCode` → `findByCode` rename (Phase G / M5)
- `oauth.jwt.legacyTypAccept` default `true → false` (Phase G / S2)

For the reasoning behind the label retirement and the going-forward
labeling discipline that prevents this from happening again, see
[`docs/release-policy.md`](docs/release-policy.md).

### Security (Phase G — S2 `legacyTypAccept` default flipped `true → false`)

- **BREAKING**: `oauth.jwt.legacyTypAccept` default flipped from `true`
  (v0.5.x) to `false`. The central JWT verifier now rejects
  tokens whose `typ` header is absent **by default**. Previously,
  typ-less tokens were accepted with a `jwt_verify_legacy_typ`
  deprecation warning so v0.4.x tokens (issued before the
  `at+jwt`/`rt+jwt`/`id+jwt` convention) kept verifying through the
  v0.5.x migration window.
- **Why this is a security tightening**: an absent `typ` header is a
  hard signal of either operator misconfiguration or a downgrade attack
  attempting to repurpose a non-JWT token as a JWT. Rejecting by default
  closes the acceptance window operationally; the flag stays as an
  explicit operator opt-in for deployments still completing their v0.4.x
  rollover.
- **Migration**: operators with v0.4.x tokens still in circulation can
  set `OAUTH_JWT_LEGACY_TYP_ACCEPT=true` (or `oauth.jwt.legacyTypAccept
  = true` in HOCON) to opt back into legacy acceptance for their own
  bounded migration window. The recommended path is to ensure all
  in-flight tokens were minted by v0.5.x or newer (which emit
  `header.typ` per type) before upgrading, then leave the new default
  in place.
- **Code-level default match**: every `?? true` fallback in routes,
  grants, and validators is flipped to `?? false` so that partial-config
  test fixtures and edge code paths behave consistently with HOCON.
- Affected sites: `packages/core/config/application.conf`,
  `templates/standalone/config/application.conf`,
  `packages/core/src/jwt/verify.mts` (default arg + JSDoc), and the
  `?? false` fallbacks in `packages/oauth-token-exchange/src/validator/selfIssuedAccessToken.mts`,
  `packages/oauth/src/routes.mts`,
  `packages/oauth/src/grants/refreshToken.mts`,
  `packages/oauth/src/routes/{federationToken,logout,userinfo}.mts`.

### Changed (Phase G — M5 `CodeRepository.getByCode` → `findByCode` rename)

- **BREAKING**: `CodeRepository.getByCode(code)` renamed to
  `findByCode(code)`. The signature (`Promise<Code | null>`) and
  semantics (returns `null` when no record matches; never throws on
  absence) are unchanged.
- Rationale: aligns with the `findBy<Field>` repository-method
  convention introduced in v0.5.2 — `findBy*` for optional lookups
  (`null` on absence), `get(<id>)` for single-object stores, and
  operation-specific names like `consumeByCode` (atomic single-use) for
  non-lookup operations. `get*` idiomatically implies throw-on-missing,
  which mismatches this method's nullable return. The v0.5.2 JSDoc
  (AS-10) flagged this for renaming.
- Migration: consumers implementing `CodeRepository` (custom storage
  adapters) must rename their `getByCode` method to `findByCode`. The
  in-memory adapter (`InMemoryCodeRepository`) and Redis adapter
  (`@o3co/auth-provider-redis`) are updated by v0.6.0.
- Affected APIs: `CodeRepository.getByCode` (removed) →
  `CodeRepository.findByCode` (added). No transitional alias.

### Security (Phase G — M6 `legacyRtPolicy = "accept-with-warning"` removed)

- **BREAKING**: The `accept-with-warning` value of
  `oauth.refreshToken.legacyRtPolicy` was removed. Under SF-6, refresh
  tokens lacking `jti` or `family_id` claims (when family rotation is
  wired) are now **always** rejected with `invalid_grant` /
  `missing_jti_or_family_id`. The migration-window opt-in that skipped
  replay detection and emitted an audit log no longer exists.
- Closes a `family_id`-absent acceptance window that allowed legacy
  refresh tokens to bypass rotation entirely under operator opt-in.

### Removed (Phase G — M6 `legacyRtPolicy = "accept-with-warning"` enum value)

- **BREAKING**: `oauth.refreshToken.legacyRtPolicy` Zod schema tightened
  from `z.enum(["reject", "accept-with-warning"])` to
  `z.enum(["reject"])`. The `OAUTH_REFRESH_TOKEN_LEGACY_RT_POLICY`
  env-var override line was also removed from `application.conf` — with
  only one valid value, there is nothing to override.
- Operators upgrading from v0.5.x who still set
  `legacyRtPolicy = "accept-with-warning"` get a Zod
  `invalid_enum_value` error pointing at the field, instead of having
  the legacy path silently honored.
- Migration: ensure all in-flight refresh tokens carry both `jti` and
  `family_id` claims (true for tokens minted by v0.5.x or newer) before
  upgrading. Remove any `legacyRtPolicy = "accept-with-warning"` line
  from your HOCON. SF-6 (v0.5.1) documented this migration plan; 1.0
  GA finalizes the cutover.
- Affected APIs/config (removed): `accept-with-warning` enum value,
  `OAUTH_REFRESH_TOKEN_LEGACY_RT_POLICY` env-var override, the
  `legacy_rt_accepted_no_replay_protection` audit log event in
  `packages/oauth/src/grants/refreshToken.mts` (the legacy branch
  that emitted it is gone).

### Removed (Phase G — M4 `legacyTokenCompat` migration flag)

- **BREAKING**: Removed the `oauth.refreshToken.legacyTokenCompat` config
  flag (HOCON `application.conf` + Zod schema in `application.schema.mts`)
  and the `OAUTH_REFRESH_TOKEN_LEGACY_TOKEN_COMPAT` env-var override. The
  flag was introduced in v0.5.2 (AS-12) with default `true` to accept
  v0.4.x refresh-token shapes during the migration window. v0.5.x is now
  out of the bounded window; v0.6.0 enforces the strict shape
  unconditionally.
  - Refresh-grant rejection gate now accepts **only** `header.typ ===
    "rt+jwt"` as the refresh marker. Tokens carrying the legacy
    `payload.type === "refresh"` substitute (no `rt+jwt` typ header) are
    rejected with `invalid_grant` / `invalid refresh_token`.
  - The legacy `claims.user.id` subject-fallback path is removed. Refresh
    tokens MUST carry a top-level standard `sub` claim; tokens without
    one are rejected with `invalid_grant` / `refresh token has no
    subject`.
  - AT-as-RT defense (RT-OC invariant) is preserved and now structurally
    guaranteed by the single-marker requirement.
  - Migration: operators must ensure all in-flight refresh tokens were
    minted by v0.5.x or newer (which emit both `header.typ = "rt+jwt"`
    and a top-level `sub`) before upgrading. v0.5.2 documented this
    migration plan in its Migration note; v0.6.0 finalizes the cutover.
  - Affected APIs/config (removed):
    `oauth.refreshToken.legacyTokenCompat`,
    `OAUTH_REFRESH_TOKEN_LEGACY_TOKEN_COMPAT`,
    `RefreshTokenConfig.legacyTokenCompat` (Zod schema field).

### Removed (Phase G — M3 `allowPolicyWidening` migration flag)

- **BREAKING**: Removed the `allowPolicyWidening?: boolean` field from
  `TokenExchangeDependencies` (RFC 8693 Token Exchange grant). The
  fail-closed boundary check that rejects policy hook scope/audience
  outputs exceeding the validated `subject_token` boundary is now
  unconditional. Introduced as a deprecated migration escape hatch in
  v0.5.3 (F10 Token Exchange hardening), it shipped only with `@deprecated`
  JSDoc and was never wired into module-based boot.
  - Migration: callers of `createTokenExchangeGrant()` that still pass
    `allowPolicyWidening: true` must update their `GrantPolicyHook`
    implementations so that `grantedScope` ⊆ `subject_token.scope` and
    every entry of `grantedAudience` is contained in the subject token's
    `aud` (when present), or equals `client.clientId` when the subject
    token has no usable `aud`. `client.allowedAudiences` is **not** part
    of the policy-output boundary — that allowlist is enforced earlier
    on the `audience` request parameter, not on policy outputs. There is
    no opt-in to bypass this check.
  - Affected APIs:
    `TokenExchangeDependencies.allowPolicyWidening` (removed).

### Removed (Phase G — M2 *Base interface aliases)

- **BREAKING**: Removed the `*Base` suffix from the 5 extension-point
  interfaces (closes AS-7). The canonical names without the suffix were
  added as type aliases in v0.5.1; both names coexisted with `@deprecated`
  JSDoc on the `*Base` form. In v0.6.0 the canonical names ARE the
  interfaces; the `*Base` aliases are removed.
  - `AuditSinkBase` → `AuditSink`
  - `FederationTokenStoreBase` → `FederationTokenStore`
  - `MfaProviderBase` → `MfaProvider`
  - `GrantPolicyHookBase` → `GrantPolicyHook`
  - `RateLimiterBase` → `RateLimiter`
  - Migration: search-and-replace `XxxBase` → `Xxx` across consumer
    source. All five interfaces have stable structural shapes;
    only the names change. `AdapterFactory<XxxBase>` becomes
    `AdapterFactory<Xxx>`, declaration-merged `ComponentMap` slot types
    use `Xxx`, and any extension implementation `class Foo implements
    XxxBase` becomes `class Foo implements Xxx`.
  - Coordination with AS-M1: the manifest's `contributes-map.mts` carried
    a `GrantPolicyHook = unknown` placeholder that collided with the
    canonical policy interface name. AS-M1 (v0.5.1) renamed the
    placeholder to `GrantPolicyHookContribution`; M2 keeps that name and
    drops the `GrantPolicyHookBase` form. `GrantPolicyHookFactory<Deps>`
    in the manifest still produces a `GrantPolicyHookContribution`.

### Removed (Phase G — M1 GrantRegistry public export)

- **BREAKING**: Removed `GrantRegistry` and `GrantRegistryError` from
  `@o3co/auth-provider-core`'s public exports (closes AS-8). Both were
  deprecated as public re-exports in v0.5.1 per A2-γ §3.3; the classes
  remain as internal implementation detail of the boot planner.
  - Migration: consumer code that previously instantiated
    `new GrantRegistry()` or caught `GrantRegistryError` should declare
    grants on a module via `contributes.grants` instead. The boot planner
    (`createApp`) handles register / replace / freeze internally and
    propagates registration failures as `BootError` (A2-β) rather than
    `GrantRegistryError`.
  - Affected APIs (no longer importable from
    `@o3co/auth-provider-core`): `GrantRegistry`, `GrantRegistryError`.

## [0.5.3] — 2026-05-09

### Security (Phase F — F10 Token Exchange hardening)

- Token Exchange now rejects policy hook scope/audience widening by default,
  enforces `may_act` actor constraints when present, bounds nested RFC 8693
  actor chains via `oauth.tokenExchange.maxActorChainDepth`, and requires
  requested RFC 8707 resources to be represented in the effective issued-token
  audience.

### Security (Phase F — F12a rate limiter hardening)

- The built-in in-memory OAuth endpoint rate limiter now bounds its bucket map
  with `memoryRateLimiter.maxBuckets` (default `10000`, env override
  `MEMORY_RATE_LIMITER_MAX_BUCKETS`) and evicts expired or earliest-reset
  buckets when the cap is reached.

### Security (Phase F — F12b user repository timing)

- `InMemoryUserRepository.authenticate()` now performs a bcrypt comparison
  on every authentication attempt — including unknown usernames and
  plain-text password entries — equalizing timing across all paths so
  username-enumeration signals are reduced regardless of whether deployments
  use bcrypt-hashed or plain-text password entries.

### Fixed (Phase F — F11a OIDC discovery/UserInfo compliance)

- OIDC discovery now always advertises `jwks_uri`, with symmetric HS256-only
  deployments serving an empty JWK Set instead of a 404 so the advertised
  endpoint remains dereferenceable without exposing shared secrets.
- The OIDC UserInfo endpoint now accepts both GET and POST requests with the
  same bearer-token validation, cache-control headers, session liveness checks,
  and scope-filtered claim response.

### Fixed (Phase F — F11b OIDC authorize/logout compliance)

- `/oauth/authorize` now rejects requests that omit the `openid` scope when
  `oauth.jwt.issuer` is configured and `oauth.oidcMode = "oidc-required"`
  (default). Operators can set `OAUTH_OIDC_MODE=dual` to keep accepting
  OAuth-only authorization requests on the same endpoint.
- The OIDC `end_session_endpoint` now supports GET as well as POST. GET with
  a valid fresh `id_token_hint` performs the existing logout cascade; GET
  without a valid hint renders a confirmation page instead of triggering
  logout.

### Changed (Phase F — F13a cleanup/operational hardening)

- Standalone session cookies now default to `SESSION_NAME=__Host-auth.session`,
  with boot-time validation that `__Host-` names are only used with
  `SESSION_SECURE=true` and no `SESSION_DOMAIN`.
- Redis session-store key namespacing is documented and preserved through
  config validation via `REDIS_SESSION_STORES_KEY_PREFIX`.
- The standalone Dockerfile now runs install/build steps as the `node` user,
  declares `EXPOSE 3000`, and includes a Docker-native healthcheck for
  `/_healthcheck`.
- Added a developer cleanup note for stale untracked `packages/did/` artifacts
  left in local workspaces after the DID grant package was removed from git.

### Fixed (Phase F — F13b residual test coverage + sessionRPRegistry hardening)

- Added regression coverage: testcontainers integration for `RedisCodeRepository`
  TTL / extended-field round-trip (TD-4), residual OAuth route + introspection-
  cascade tests (TD-5 / TD-10), and unit tests for the `SessionRPRegistry`
  envelope guard.
- `RedisSessionRPRegistry` now validates JSON envelope shape (rejecting array
  payloads + non-finite `registeredAtMs`) and logs corrupt records with the
  structured `{ sid, reason, cause? }` shape used by the sibling
  `UserSessionStore` adapter. The previous `{ json: ... }` snippet field is
  dropped to avoid leaking sensitive payloads on log sinks. The Redis
  adapter builder now forwards optional `logger` so the corrupt-envelope
  warn path is reachable from the builder construction route.

## [0.5.2] — 2026-05-09

### Changed (auth.utils dependency bump, v0.5.2)

- **`@o3co/auth.utils` minimum version bumped from `^0.0.3` to
  `^0.0.4`** in `templates/standalone/package.json`. The 0.0.4 release
  rewrites `gracefulShutdown` so the cleanup callback is awaited
  (`() => void | Promise<void>`) inside `server.close()` after in-flight
  requests drain, plus an idempotent guard against repeated SIGTERM /
  SIGINT delivery. The `templates/standalone/src/app.mts` call
  `gracefulShutdown(server, () => handle.dispose())` was already passing
  an async `dispose()` that the previous sync impl silently dropped;
  with `auth.utils@0.0.4` the lifecycle drain in `auth.provider` v0.5.x
  is properly awaited before the process exits. Cross-repo upstream
  PR: o3co/auth.utils#7. No changes to consumer call sites in this
  template are required.

### Changed (SC residual batch — supply-chain hygiene, v0.5.2)

- **`pnpm.onlyBuiltDependencies` allowlist added at the workspace root
  AND in `templates/standalone/package.json`** (closes SC-4). pnpm 10
  gates native build scripts behind explicit operator approval; without
  the allowlist a fresh `pnpm install` printed `Ignored build scripts:
  bcrypt` and skipped the native binary compilation, which on platforms
  without a matching prebuild would cause `bcrypt.hash()` to throw
  `MODULE_NOT_FOUND` at runtime. Both `package.json` files allowlist
  `bcrypt` (the only direct production dependency that may require
  native compilation) — the workspace root entry covers monorepo
  installs, and the standalone-template entry covers projects scaffolded
  by `@o3co/create-auth-provider`, which install from their own
  `package.json` and do not inherit the workspace root's allowlist.
  Operator impact: when the install resolves to a prebuild (most
  supported platforms), no extra toolchain is needed; on platforms with
  no matching prebuild, the standard Node.js native-addon toolchain
  (Python + C++ compiler) is required during `pnpm install`. The
  standalone template README documents both the prebuild platform list
  and the toolchain fallback.

- **`templates/standalone` `redis` range bumped from `^5.10.0` to
  `^5.12.1`** (closes SC-5) to align with `packages/session`'s pin so
  `pnpm-lock.yaml` cannot resolve two divergent redis versions over time.
  No API behavior change between redis 5.11 and 5.12.

- **`@o3co/auth-provider-oauth` `accepts` direct dependency upgraded from
  `^1.3.8` to `^2.0.0`** (closes SC-6) to match the version Express 5
  brings in transitively, eliminating a duplicate `accepts` resolution in
  the lockfile. The `accepts(req).type([...])` API used at
  `packages/oauth/src/routes/logout.mts:581` is unchanged across the
  major bump (per upstream HISTORY.md the v2.0.0 changes are limited to
  `mime-types@^3.0.0` and `negotiator@^1.0.0`; the effective Node 18
  floor it carries is a transitive constraint from those deps, not a
  manifest-level `engines.node` change on `accepts` itself). The package
  already requires Node `>=18.19.0`. `@types/accepts@^1.3.7` is retained
  because workspace typecheck passes and no `@types/accepts@^2` is
  published on npm; it can be revisited if a v2-compatible types package
  ships.

- **Root `audit` script tightened from
  `pnpm audit --audit-level=high` to
  `pnpm audit --prod --audit-level=moderate`** (closes SC-7). The
  `--prod` flag scopes the audit to production dependencies, matching the
  evidence used in the supply-chain audit (devDependency-only advisories
  do not reach deployed services). The `moderate` threshold catches
  CVSS 4.0–6.9 advisories that the previous `high` threshold passed
  silently. Verification at the time of this change: 0 advisories under
  the new gate.

### Added (Phase F — F9 PR7 AS-12 legacyTokenCompat config flag, v0.5.2)

- **`oauth.refreshToken.legacyTokenCompat` controls refresh-grant acceptance
  of v0.4.x token shapes** (`@o3co/auth-provider-core` config,
  `@o3co/auth-provider-oauth`, closes AS-12): default is `true`, preserving
  current compatibility for tokens that use `payload.type = "refresh"` as a
  header-typ substitute or `claims.user.id` as the subject fallback.

- Setting `legacyTokenCompat = false` requires v0.5.x refresh-token shape for
  the refresh grant: `payload.type = "refresh"` no longer substitutes for
  missing `header.typ`, and `claims.user.id` is no longer accepted when
  top-level `sub` is absent. This is opt-in and non-breaking while the default
  remains `true`.

- The pre-AS-12 strict marker requirement is preserved: a refresh token MUST
  declare itself via either `header.typ === "rt+jwt"` or (when
  `legacyTokenCompat = true`) `payload.type === "refresh"`. A typ-less JWT
  with no `payload.type` is rejected at the refresh-grant gate regardless of
  `legacyTokenCompat`, even when `oauth.jwt.legacyTypAccept = true` allows
  it through SF-1's central verifier. This defends against AT-as-RT confusion
  in deployments running `legacyTypAccept = true` during the v0.5.x transition
  window.

#### Migration

Upgrade to v0.5.2 with the default `legacyTokenCompat = true`, wait for all
v0.4.x refresh tokens to expire or be rotated into v0.5.x tokens, then set
`oauth.refreshToken.legacyTokenCompat = false` and monitor for `invalid_grant`
responses from clients still presenting legacy refresh tokens.

#### Cross-spec coordination

AS-12 is orthogonal to SF-1's `oauth.jwt.legacyTypAccept`: SF-1 owns whether
missing `header.typ` is accepted by central JWT verification; AS-12 owns only
the refresh-grant payload-level compatibility paths.

### Documentation (Phase F — F9 PR7 AS-4 expiresAt two-tier design rationale, v0.5.2)

- Added JSDoc explaining the intentional A4 `expiresAt: Date` / A3
  `expiresAtMs: number` two-tier expiry design at all AS-4-listed sites:
  `UserSession`, `CreateUserSessionInput`, `SessionRPRegistry.registerRP`,
  `SessionFamilyIndex.addFamilyId`, `SessionFederationIndex.addFederation`,
  `FederationTokens.expiresAt`, `MfaChallenge.expiresAt`, and
  `MfaPendingTransaction.expiresAt`. Documentation-only; no runtime or type
  behavior changes.

### Changed (Phase F — F9 PR4 AS-3 + AS-11 BREAKING method renames, v0.5.2)

- **`FederationTokenStoreBase.deleteBySession(sid)` is renamed to
  `removeBySid(sid)`** (`@o3co/auth-provider-core`, closes AS-3): aligns the
  verb with the four sibling session stores (`UserSessionStore.removeBySid`,
  `SessionRPRegistry.removeBySid`, `SessionFamilyIndex.removeBySid`,
  `SessionFederationIndex.removeBySid`), which all use `removeBySid` for the
  same "bulk-remove records scoped to a session id" responsibility. Callers
  that previously mixed both verbs in adjacent lines (notably the logout
  cascade) now read uniformly.

- **`MfaTransactionStore.save(tx)` and `MfaTransactionStore.load(transactionId)`
  are renamed to `set(tx)` and `get(transactionId)`** (`@o3co/auth-provider-core`,
  closes AS-11): aligns the verbs with map-like store semantics
  (`UserSessionStore`, `KeyStore` patterns); replaces the orphan `save` /
  `load` verbs that did not appear on any peer store.

#### BREAKING — migration

The v0.5.2 hotfix policy explicitly permits these renames because both
interfaces were new in v0.5.0 and have had no external consumers (the v0.5.0
publish-to-hotfix window is days). No deprecation aliases are added.

Downstream implementers of either interface must rename methods:

| Interface | Old name | New name |
|---|---|---|
| `FederationTokenStoreBase` (and its canonical alias `FederationTokenStore`) | `deleteBySession(sid)` | `removeBySid(sid)` |
| `MfaTransactionStore` | `save(tx)` | `set(tx)` |
| `MfaTransactionStore` | `load(transactionId)` | `get(transactionId)` |

Callers must update method names accordingly. The built-in adapters in
`@o3co/auth-provider-core` and `@o3co/auth-provider-redis` are already
migrated; consumers using only those adapters need no changes beyond
upgrading to v0.5.2.

#### Cross-spec coordination

The `*Base` interface aliases added in F9 PR3 (AS-7) —
`FederationTokenStore`, `RateLimiter`, `AuditSink`, `MfaProvider`,
`GrantPolicyHook` — automatically pick up the AS-3 method rename through the
underlying type alias. No additional action is required for consumers using
the canonical names.

### Improved (Phase F — F9 PR6 AS-M1 contributes-map concrete-type substitution, v0.5.2)

- **The four same-package contributes-map placeholders are now concrete
  types instead of `unknown`** (`@o3co/auth-provider-core/modules/manifest`,
  closes AS-M1):

  | Manifest type | Pre-v0.5.2 | v0.5.2 (substituted) |
  |---|---|---|
  | `GrantHandler` | `unknown` | `GrantHandler` from `grants/types.mts` |
  | `AuditHook` | `unknown` | `AuditSink` (canonical alias of `AuditSinkBase`) |
  | `MfaFactor` | `unknown` | `MfaProvider` (canonical alias of `MfaProviderBase`) |
  | `GrantPolicyHookContribution` | `unknown` | `GrantPolicyHook` (canonical alias of `GrantPolicyHookBase`) |

  Module authors now get real type-checking on contribution factory
  return values — a typo or shape mismatch in
  `contributes.grants["x"] = (deps) => myHandler` is caught at compile
  time instead of at runtime when the boot pipeline invokes the factory.

#### Cross-package types still deferred

- `FederationProvider` and `ExchangeTokenValidator` remain `unknown`
  pending Phase F resolution of a circular package import (`session`
  and `oauth-token-exchange` are downstream of `core`, so importing
  their concrete types from the manifest would create a package-level
  cycle). A new typecheck assertion in
  `packages/core/src/__tests__/contributes-map-substitution.test.mts`
  pins both as `unknown` so any premature substitution is caught.

#### Compatibility scope

- **Public direction (additive)**: consumers passing concrete factory
  return values into the manifest get tighter type checking. No code
  change required for code that was already returning concrete types.
- **Test scaffolding (breaking-internal)**: the boot-pipeline tests in
  `packages/core/src/boot/__tests__/{apply-contributions, plan-boot,
  integration}.test.mts` were written against the `unknown` placeholder
  and used inline literals or `as unknown` casts that no longer satisfy
  the narrowed types. v0.5.2 migrates these fixtures to typed `fakeGrantHandler` /
  `fakeAuditSink` factories; downstream consumers who copied this
  pattern will need similar updates.

#### Internal: collector factory generic-ification

- `mergeWithBuiltins` in `packages/core/src/boot/create-app.mts` now
  parameterises its three built-in collector factories
  (`makeGrantCollector`, `makeMapNameKeyedCollector<T>`,
  `makeIdentityDedupListCollector<T>`) so they produce typed collectors
  matching the narrowed contributes-map slots. Internal-only; no public
  API change.

### Added (Phase F — F9 PR5 AS-9 Redis session sub-adapter builders, v0.5.2)

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

### Deprecated (Phase F — F9 PR5 AS-8 GrantRegistry public export, v0.5.2)

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

### Breaking (Phase F — F9 PR3 GrantPolicyHook manifest rename, v0.5.2)

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

### Deprecated (Phase F — F9 PR3 AS-7 + AS-10 naming consistency, v0.5.2)

- **Adapter primitive interfaces add canonical aliases without the `*Base`
  suffix; `*Base` forms are deprecated and will be removed at 1.0 GA**
  (`@o3co/auth-provider-core`, closes AS-7 + AS-10): the v0.5.2 canonical
  names are the new aliases. Existing code referencing `*Base` continues to
  compile (the aliases are type equivalences, not replacements). Update at
  your convenience before 1.0 GA.

| Deprecated | Canonical (v0.5.2) | Source |
|---|---|---|
| `FederationTokenStoreBase` | `FederationTokenStore` | `@o3co/auth-provider-core` |
| `RateLimiterBase` | `RateLimiter` | `@o3co/auth-provider-core` |
| `AuditSinkBase` | `AuditSink` | `@o3co/auth-provider-core` |
| `MfaProviderBase` | `MfaProvider` | `@o3co/auth-provider-core` |
| `GrantPolicyHookBase` | `GrantPolicyHook` | `@o3co/auth-provider-core` |

- **AS-10 documentation**: JSDoc on
  `ClientRepository.findById` and `CodeRepository.getByCode` documents the
  v0.5.2 naming convention (`findBy<Field>` for repository lookups; `get(<id>)`
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

### Breaking (Phase F — F9 PR2 AS-1 + AS-2 error envelope unification, v0.5.2)

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

### Breaking (Phase F — F9 PR1 CC-5 readonly Theme D, v0.5.2)

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

### Security (Phase F — F6 PR4 authorization-grant TOCTOU re-check, v0.5.2)

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

### Security (Phase F — F6 PR3 refresh-token grant hardening, v0.5.2)

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

### Security (Phase F — F6 PR2 PKCE + RT family hardening, v0.5.2)

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
  Phase F follow-up that re-mints the issued JWT to match. For v0.5.2 the
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

### BREAKING (Phase F — F6 PR1 D-6 PB-2 client authentication redesign, v0.5.2)

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

### Changed (Phase F — F4 PR2 standalone wiring batch + IH-10/17/18, v0.5.2)

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

### Bug Fixes (Phase F — IH-10 / IH-17, v0.5.2)

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

### Documentation (Phase F — IH-18, v0.5.2)

- **`rateLimit.login.windowMs` JSDoc clarification** (`@o3co/auth-provider-core`):
  the existing `rateLimit.login.windowMs` (express-rate-limit, milliseconds,
  governs session-route bruteforce protection) is intentionally distinct from
  the OAuth-endpoint `RateLimitSpec.windowSeconds` (seconds, governs the
  pluggable `RateLimiterBase` adapter). Inline JSDoc + HOCON comments now
  spell this out to prevent operator confusion. No code change.

### Changed (Phase F — D-2 v2 standalone ioredis unification, v0.5.2)

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

### Breaking Changes (Phase F — D-1 Code/CodeData identity binding, v0.5.2)

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
  before v0.5.2 ships).

### Bug Fixes (Phase F — D-1, v0.5.2)

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

### Breaking Changes (Phase F — D-10 Redis 7.2 LTS minimum, v0.5.2)

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
  v0.5.2. AWS ElastiCache for Redis 7.2, Upstash Redis, and Redis Cloud all
  support the GT/NX flags. See `SessionRPRegistryMultiClient.pExpireGT` JSDoc
  in `packages/redis/src/clients.mts` for the full semantics.

- **`engines.node >=18.19.0`** (all eight published packages): every
  `@o3co/auth-provider-*` package now declares `"engines": { "node": ">=18.19.0" }`.
  npm/pnpm prints a warning by default; **pnpm enables `engines-strict=true` by
  default in some configurations**, which causes a hard install failure on
  Node <18.19. Consumers on Node 18.0.0–18.18.x should upgrade to Node 18.19.0
  LTS or later before installing v0.5.2; Node 20 LTS and 22 LTS are unaffected.

- **`pExpireGT` added to `SessionRPRegistryClient`/`MultiClient` and
  `SessionSidSortedSetClient`/`MultiClient`** (`@o3co/auth-provider-redis`): the
  four backing-client interfaces gain a non-optional `pExpireGT(key, msTimestamp)`
  method (multi-client variant returns the chainable client for pipelining). The
  bundled `makeIoredisClients()` adapter implements the new method as a
  `pexpireat(k, ms, "NX")` + `pexpireat(k, ms, "GT")` pair (the bare GT form
  silently no-ops on a key with no existing TTL — see method JSDoc). Custom
  backing-client implementations (non-ioredis) must add `pExpireGT` to compile.

### Breaking Changes (Phase F — D-5 BuilderContext.lifecycle, v0.5.2)

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
  `closeAllConnections()`. This is required as a prerequisite to v0.5.2
  publish but ships as a `@o3co/auth.utils` patch release independent of
  auth.provider's release cadence. (Closes OR-3.)

### Breaking Changes (Phase F — D-9 federation-tokens lock CAS, v0.5.2)

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

### Bug Fixes (Phase F — v0.5.2)

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

### Added (Phase 10 — Redis adapter relocation, v0.5.2)

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

### Added (Phase 1-9 — Module System Redesign, v0.5.2)

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

### Changed (Phase 1-9 — Module System Redesign, v0.5.2)

- **Breaking**: `sessionModule` is now a const Module value rather than a factory function. Callers `import { sessionModule } from "@o3co/auth-provider-session"` and add it directly to the manifest list passed to `createApp({ modules: [...] })` — no factory call. Per-federation modules (e.g. `googleFederationModule`, `githubFederationModule`) are added alongside.
- **Breaking**: Google and GitHub federation providers are no longer bundled in `@o3co/auth-provider-session`. Consumers install the per-federation packages and add their const Modules (`googleFederationModule` / `githubFederationModule`) to the manifest, plus a small config-bridge module that supplies the typed `googleFederationConfig` / `githubFederationConfig` ComponentMap slot from `config.federations.<name>` via `extractFederationSection`.
- `templates/standalone` registers `@o3co/auth-provider-federation-google` explicitly for the default Google federation config.
- Scaffolder CLI renamed from `create-o3co-auth-provider` to `@o3co/create-auth-provider` (scoped). The `bin` entry is now `create-auth-provider`.

### Removed (Phase 1-9 — Module System Redesign, v0.5.2)

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

### Added (v0.4.1)

- `create-o3co-auth-provider` CLI scaffolder is now published to npm. Consumers can run `npx create-o3co-auth-provider my-auth-app` to generate a new `auth.provider` project from the standalone template. The package was previously built but held back (`private: true`) from npm publish; this release removes that flag and adds `description` + `repository` metadata.

### Notes

- No changes to `@o3co/auth-provider-core`, `@o3co/auth-provider-session`, `@o3co/auth-provider-oauth`, `@o3co/auth-provider-did`, or `@o3co/auth-provider-foundation`. These packages are re-published at `0.4.1` because the release pipeline bumps all workspace packages in lockstep; their runtime behaviour is identical to `0.4.0`. Consumers upgrading from `0.4.0` → `0.4.1` get an effective no-op reinstall.

## [0.4.0] - 2026-04-22

### Added (v0.4.0)

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

### Changed (v0.4.0 — Federation interface + session store redesign)

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

### Removed (v0.4.0 — Passport.js exit + federation redesign)

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
