# @o3co/auth-provider-session

Last updated: 2026-09-25

Browser login, logout and upstream-IdP federation routes for
[auth.provider](../../README.md), the redirect policy every federation adapter
package contributes beside its provider, and the express-session store those
routes — and every other route that reads `req.session` — run over.

## Responsibility

**Role.** The browser-facing half of authentication. Core owns the ports this
package uses (`UserRepository`, `UserSessionStore`, `FederationTokenStore`,
`SessionFederationIndex`, and the federation adapter contract) and implements no
route; this package is the driver of those ports for a browser. It has three
responsibilities:

1. **The `/session` routes** — `sessionModule`: password login, logout, the CSRF
   token route, and the federation start and callback routes. They turn a
   password check or an upstream IdP's answer into a `UserSession` record and an
   authenticated express session, and undo it at logout.
2. **The federation-adapter toolkit** — what an adapter package imports from
   the router it plugs into: `createFederationRedirectPolicy` and the allowlist
   rules it is built from, and `extractFederationSection`. The helpers an
   adapter builds its upstream requests with — `codeChallenge`,
   `callbackUrlForExchange`, `FederationClientSecret` / `resolveClientSecret` —
   are core's.
3. **The browser session store** — `sessionStoreModule` / `sessionStoreModuleFor`
   and `createSessionStoreFactory` / `registerBuiltinSessionStores`: the
   express-session middleware, its cookie and its store (memory, or Redis through
   `connect-redis`).

**Owns:**

- the `/session` routes and their answers; the CSRF policy for them
  (`session.csrf.*`, and the exported guard `@o3co/auth-provider-device-grant`
  reuses); the login rate-limit guard's wiring (`rateLimit.login`); the redirect
  allowlists (`session.redirectAllowlist`, `federations.<name>.redirectAllowlist`);
- how a federation is driven: `state`, PKCE and `nonce`, the `form_post`
  transaction and its cookie, claim precedence, the `amr` a login records, and
  what a callback writes to the stores;
- the `federationRedirectPolicies` contribution kind and the
  `federationRedirectPolicyResolver` slot it declares on core
  ([`src/federations/contributes.mts`](src/federations/contributes.mts)), and
  [`FederationResult`](src/federations/types.mts);
- the express-session middleware, its cookie and its store (`session.*`,
  `session.storage.*`).

**Does not own:**

- the federation adapter contract — `FederationProvider`, `FederationProfile`
  and the capabilities — and the pure helpers adapters build their requests
  with (`codeChallenge`, `callbackUrlForExchange`, `resolveClientSecret`), which
  are core's ([`core/src/federations`](../core/src/federations/README.md));
- any adapter: [`federation-google`](../federation-google/README.md),
  [`federation-github`](../federation-github/README.md),
  [`federation-apple`](../federation-apple/README.md),
  [`federation-oidc`](../federation-oidc/README.md);
- the stores it writes (core ports; memory adapters in core, Redis ones in
  [`@o3co/auth-provider-redis`](../redis/README.md)) and who a user is (the
  Store behind `UserRepository`, e.g.
  [`@o3co/auth-provider-foundation`](../foundation/README.md));
- token issuance, `POST /oauth/logout`'s cascade, upstream logout
  (`SupportsLogout`) and federation token refresh (`SupportsRefresh`) —
  [`@o3co/auth-provider-oauth`](../oauth/README.md);
- delegated authorization (`SupportsDelegatedAuthorization`) —
  [`@o3co/auth-provider-federation-grants`](../federation-grants/README.md);
- any HTML: the login page and the account page are the deployment's.

**Why a separate package.** From core: core is the contract every package
depends on and implements no route, and a deployment that issues tokens without
a browser login (client credentials, token exchange) installs no route it does
not use. From `@o3co/auth-provider-oauth`: the two are siblings over core and
neither imports the other, so a deployment can install either without the
other's routes — though `oauth`'s `/authorize` reads `req.session`, so a
deployment that uses it mounts an express-session middleware, normally this
package's store module. What the split costs is stated in
[What `POST /session/logout` invalidates](#what-post-sessionlogout-invalidates).

**Why the three live together.** Each of the other two exists for the routes.

- The toolkit: the redirect policy is a contribution kind this package declares
  and its router consumes, and `extractFederationSection` reads the config shape
  the router reads callback URLs from. Both are the router's, which is why
  every adapter package takes this package as a peer dependency. The pure
  request helpers are not here: the router uses none of them, so they live in
  core beside the contract that tells adapters to use them.
- The store: it is what `req.session` is, and the routes here are what write it;
  the federation router also keeps `form_post` transactions in it. It is a
  module of its own, apart from `sessionModule`, because other packages read
  `req.session` without these routes — `oauth`'s `/authorize`, consent and
  logout, `device-grant`'s verification page, `federation-grants`' browser
  routes — so a deployment with a login of its own installs the store alone.

**Source layout.** [`src/routes/`](src/routes/) holds the two routers;
[`src/federations/`](src/federations/) the toolkit and the router's federation
parts (claim precedence, consented scope, the transaction store, the redirect
policy); [`src/modules/`](src/modules/) and [`src/store/`](src/store/) the
browser session store; [`src/internal/`](src/internal/) cookie reading and the
claims read off a `User`; [`src/csrf.mts`](src/csrf.mts) the CSRF rule; and
[`src/redirect-allowlist.mts`](src/redirect-allowlist.mts) the allowlist rule
the login and federation routes share. What each file does is in its header
comment.

## Install

```sh
npm install @o3co/auth-provider-session @o3co/auth-provider-core express express-session
# and, for session.storage.type = "redis" (the default in core's reference.conf):
npm install redis@^6.2.1 connect-redis@^10.0.0
```

Peer dependencies: `@o3co/auth-provider-core`, `express@^5.0.0` and
`express-session@^1.17.0`. Optional peer dependencies: `redis@^6.2.1` and
`connect-redis@^10.0.0`, the Redis session store's libraries. The package has
no dependencies of its own.

Core is a peer because this package augments it (the
`federationRedirectPolicies` contribution kind and its slot), and an
augmentation reaches only the copy of core it resolves: as a peer, that is
your composition's one copy. A deployment on `session.storage.type = "memory"`
installs neither Redis library; nothing imports them until the Redis store is
built. On `"redis"` — the default — install both: with either missing, boot
fails naming it and the install command.

## Composition

```ts
import { createApp } from "@o3co/auth-provider-core";
import { sessionModule, sessionStoreModuleFor } from "@o3co/auth-provider-session";
import { googleFederationModule } from "@o3co/auth-provider-federation-google";

const handle = await createApp({
  modules: [
    sessionStoreModuleFor(config), // first, so every module after it can read req.session
    sessionModule,                 // a const Module, not a factory
    googleFederationModule,        // contributes federations.google + federationRedirectPolicies.google
    // ... modules providing userRepository, userSessionStore, federationTokenStore,
    //     sessionFederationIndex and googleFederationConfig
  ],
  bootstrapComponents: { config, pathResolver },
});
```

The standalone template's
[`buildModules.mts`](../../templates/standalone/src/buildModules.mts) is the
complete composition.

## Browser session store

`sessionStoreModuleFor(config)` — or the static `sessionStoreModule` — contributes
one route, `session-middleware`, mounted at `/`: express-session with its cookie
built from `session.*` (`HttpOnly`, `Path=/`, `session.secure`,
`session.sameSite`, `session.domain`, `Max-Age` = `session.maxAge`) and its store
built from `session.storage.*`. Every `req.session` in a deployment is this one.
Defaults and environment variables are in
[`reference.conf`](../core/config/reference.conf); `session.storage.type` is
`redis` by default, `memory` is the alternative, and any other value fails boot.

What holds:

- **Mount order is list order, except where a route names this one.** The
  route declares no `before` / `after`, because naming a route a deployment may
  not include (an `oauth`-only deployment has no `sessionModule`) fails boot
  with `route-order-target-missing`. So list it **ahead of every module that
  reads `req.session`**; a module listed before it reads no session, and
  nothing checks that at boot. The standalone template lists it first. The
  exception is the other direction: when federation grants are enabled, their
  browser route declares `after: ["session-middleware"]`, so it mounts after
  this route wherever either is listed, and a composition without a route of
  that id fails boot with `route-order-target-missing`.
- **A `__Host-` cookie name needs `session.secure = true` and
  `session.domain = null`**, or boot fails. `__Host-auth.session` is the default
  name.
- **`memory` is refused under `deployment.mode = "multi"`.** express-session's
  `MemoryStore` forks per replica: a login served by one replica is unknown to
  the others, logout clears only the replica it lands on, and a restart loses
  every session. `sessionStoreModuleFor(config)` reads the storage type and
  declares the module replica-unsafe when it is `memory`, so core's
  replica-safety guard refuses it at boot by name with the other offenders,
  warns when `deployment.mode` is unset, and says nothing under `"single"`. The
  static `sessionStoreModule` cannot know the type, so the guard cannot name it;
  its route factory refuses the same combination when it runs
  (`replica-unsafe-adapter`) and never warns. Prefer `sessionStoreModuleFor`
  wherever the config is in hand.
- **The Redis store opens its own connection.** A `redis` (node-redis) client to
  `session.storage.redis.url` (with `password` when set), under `connect-redis`'s
  `RedisStore`. With a readiness registrar wired it registers the probe
  `session-store` (a `PING`), so a replica that has lost Redis stops receiving
  traffic; with a lifecycle registrar wired, `AppHandle.dispose()` quits the
  client. Client `error` events are logged as `session_store_redis_error`
  rather than crashing the process; reconnecting is node-redis's job. A missing
  `url` fails boot, and so does a missing `redis` or `connect-redis` package
  (see [Install](#install)).
- **Federation transactions share the store**, under the `fedtx:` key prefix —
  see [the transaction cookie](#the-transaction-cookie).
- **A store that cannot answer is an outage, not a `500`.** When the store
  cannot load a request's session (it is unreachable, or times out) the
  request is answered `503 temporarily_unavailable` before any route runs; when it cannot save a session, or refresh its expiry, after the
  route answered, that answer stands. Either way it is logged once at error
  level as `session_middleware_store_unavailable` (`store: "cookie_session"`,
  `step`: `load` or `save`, the error's projection) and goes no further —
  express-session would have handed it to `next(err)`, the terminal handler's
  `500` before the route, Express's final handler after it
  ([`src/internal/cookieSession.mts`](src/internal/cookieSession.mts)). This
  package's routes save the session themselves before they answer where it
  matters — the login and the federation start and callback — so a failed save
  there is their own `503`, and a route that answers a cookie-store outage drops
  the request's session so express-session does not write to the failing store
  again as the response ends.
- **A record that cannot be read is absent, not an outage.** A record the Redis
  store answers with but that is not JSON, or not a session record (a plain
  object, not an array, whose `cookie` is a plain object too), is read as no
  session: express-session starts a
  fresh one for the request. It is logged once per read as a warn,
  `session_cookie_record_unreadable` (`store: "cookie_session"`), without the
  record's text. The record is not deleted and the browser keeps its cookie —
  a fresh, unmodified session sets no new one — so every request from that
  browser reads it again and logs again, until the user signs in (which sets a
  new cookie) or the record's TTL passes: a stream of these warns from one
  browser is one record. Answered as an outage it would instead have failed
  every one of those requests. A `form_post` transaction (`fedtx:`) or an oauth
  re-authentication ask (`reauth:`) in the same store is read the same way:
  absent, so the callback answers `400 invalid_session` or `/authorize` asks
  again ([`src/store/factory.mts`](src/store/factory.mts)).

**Not `@o3co/auth-provider-redis`.** That package's `UserSessionStore` holds the
`UserSession` record behind a `sid` — what introspection, `/userinfo` and
`/authorize` resolve — and its other adapters hold other core ports, through
clients that package's modules create. This store holds express-session's own
records: what this package's routes keep in the session (`isAuthenticated`,
`user`, `sid`, the login's `redirectTo`, a `query` federation's in-flight
envelope), what other packages keep there (`oauth` declares `client` and
`code`), and the `fedtx:` federation transactions. They are different records
over different connections, configured separately.

**Another store.** The module registers only `memory` and `redis`. A composition
that needs another express-session `Store` builds the middleware itself —
`createSessionStoreFactory(ctx)`, `registerBuiltinSessionStores(factory)`,
`factory.register("<type>", builder)` ([`src/store/factory.mts`](src/store/factory.mts))
— mounts it first, and does not install the module. If it enables federation
grants, it contributes that middleware as a route with the id
`session-middleware`, or boot fails as above.

## Routes

`sessionModule` contributes two routers, both mounted at `/session`:

| Method | Path | |
| --- | --- | --- |
| GET | `/session/csrf` | Issue a double-submit CSRF token |
| POST | `/session/login` | Password login |
| POST | `/session/logout` | End the browser session — see [what it invalidates](#what-post-sessionlogout-invalidates) |
| GET | `/session/oauth/federation/:name` | Start a federation (`?redirect_to=`, `?link=1`) |
| GET | `/session/oauth/federation/:name/callback` | Callback of a `query` federation; `405` (`Allow: POST`) for a `form_post` one |
| POST | `/session/oauth/federation/:name/callback` | Callback of a `form_post` federation; `405` (`Allow: GET`) for a `query` one |

`:name` is the federation's name; a name no module contributed is `404`.

The manifest ([`src/module.mts`](src/module.mts)):

- `requires`: `config`, `userRepository`, `userSessionStore`,
  `federationTokenStore`, `sessionFederationIndex`, and the synthetic
  `federationProviders` and `federationRedirectPolicyResolver`, which the boot
  planner builds from per-federation modules' `federations.<name>` and
  `federationRedirectPolicies.<name>` contributions. `sessionRPRegistry` and
  `sessionFamilyIndex`, the other two session stores, are `oauth`'s.
- `optional`: `logger`, `rateLimiter`, `auditSink`, `subjectSessionIndex`.
  `auditSink` unwired must be declared with `audit.sink.type = "none"`, and
  `subjectSessionIndex` unwired with `oauth.revocation.subject = "unsupported"`,
  or boot refuses.

### Password login

`POST /session/login` takes `username` and `password` (JSON or form).

- `400 invalid_request` when either is missing; `401 invalid_credentials` when
  `UserRepository.authenticate` answers `null`; `503 temporarily_unavailable`
  when a store the login needs cannot answer — the `UserRepository` throws,
  the `UserSession` write throws, or the express session cannot be
  regenerated (its store failed to destroy the old record) or saved. Each is
  logged once at error level as `login_store_unavailable`, with `store`
  (`user_repository`, `user_session`, `cookie_session`), `step`
  (`authenticate`, `create`, `regenerate`, `save`) and the error's projection,
  never the username. After a failed regeneration or save the `UserSession`
  and its subject-index entry are rolled back best-effort; a rollback step
  that fails is one `login_cleanup_failed` warn.
- On success it creates a `UserSession` (`amr: ["pwd"]`, lifetime
  `session.maxAge`), records it in `subjectSessionIndex` when that is wired,
  regenerates the express session and saves it, and answers `200` with a fresh
  CSRF cookie. The save comes before the answer: a store that cannot save it is
  `503`, not a `200` for a session the next request would not find.
- `redirect_to`, when sent, must be on `session.redirectAllowlist` (see
  [Redirect allowlists](#redirect-allowlists)) and is stored as
  `req.session.redirectTo`; nothing in this package redirects to it.
- The brute-force guard runs on the shared `rateLimiter` (prefix `login`, keyed
  by client IP) with `rateLimit.login`'s window and limit, answering `429` when
  it denies and following `rateLimit.failMode` when the limiter fails. With no
  `rateLimiter` wired the route falls back to a per-process limiter: boot is
  refused under `deployment.mode = "multi"`, a `login_rate_limiter_not_shared`
  warning is logged when the mode is unset, and nothing is said under
  `"single"`.

### What `POST /session/logout` invalidates

This provider has **two** logout endpoints and they do not invalidate the same
things. Pick by what the session holds.

`POST /session/logout` — the browser's own logout, and the one a BFF /
`auth.proxy` injection topology calls. It answers `200 {"message": "Logged out
successfully"}` and invalidates:

| What | Effect |
|------|--------|
| the express session | destroyed |
| the `UserSession` record for the session's `sid` | deleted — this is what makes `/oauth/introspect` report `active: false` and `/oauth/userinfo` refuse a token minted by the `session` grant |
| the `subjectSessionIndex` entry | removed, so `revokeAllForSubject` stops enumerating a dead `sid` |
| `federationTokenStore` + `sessionFederationIndex` entries for the `sid` | removed, so upstream-IdP tokens are not left at rest |
| **refresh-token families bound to the `sid`** | **not revoked** |

That last row is the one to read twice. A browser that logged in here and then
completed an `/authorize` → `authorization_code` flow holds a refresh token
whose family this endpoint does **not** revoke; the refresh token keeps working
until it expires. Use `POST /oauth/logout` with an `id_token_hint` for that
session — it runs the full cascade (refresh-family revoke, RP registry,
federation, session delete) and ends the browser session too.

The boundary is structural: the cascade
(`packages/oauth/src/logout/cascadeLogout.mts`) needs
`refreshTokenFamilyRevocation`, `sessionFamilyIndex` and `sessionRPRegistry`,
which this module declares none of, and `@o3co/auth-provider-session` does not
import `@o3co/auth-provider-oauth` — they are siblings over core.

The `session` grant issues no refresh token, so a deployment whose tokens all
come from that grant has no family to revoke and `/session/logout` is
sufficient on its own.

**Failure modes.** Every records step in the table above is best-effort and
logged, never propagated: an outage of those stores must not turn a logout
into a `5xx` that leaves the user holding a live cookie. The `UserSession` delete runs **first**, before the
express session is destroyed and before the best-effort hygiene, so a
federation-store outage cannot prevent the invalidation that matters. Failures
are logged as `logout_user_session_delete_failed`,
`logout_subject_session_index_remove_failed`,
`logout_federation_token_remove_failed` and
`logout_session_federation_index_remove_failed` — alert on the first. The one
exception is the express session itself: if destroying it fails — the cookie
store's outage — the user is not logged out, so the response is
`503 temporarily_unavailable`, logged once at error level as
`session_logout_store_unavailable` (`store: "cookie_session"`, `step:
"destroy"`, the `sid`), and the client retries; by then the records are
already gone, so `/authorize` refuses the surviving cookie on its own account. A session carrying no `sid` has no records to invalidate
and only the express session is destroyed.

### CSRF on the state-changing routes

`POST /session/login` and `POST /session/logout` accept a request that carries
**either** a same-origin (or explicitly trusted) `Origin` / `Referer`, **or** a
valid double-submit CSRF token. A request carrying neither is rejected with
`403 access_denied`.

- **Browsers** need nothing extra: the browser sets `Origin` on a same-origin
  `fetch` / form post, and that satisfies the check on its own.
- **Header-less clients** (curl, server-side agents, test harnesses) call
  `GET /session/csrf`, which sets a JS-readable `<session.name>.csrf` cookie
  and returns the same value as `csrf_token`. Send both back: the cookie plus
  either an `x-csrf-token` header or a `csrf_token` form field.
- A **foreign** `Origin` is rejected even when a token is present, since it is
  positive evidence of a cross-site request.
- A successful login returns a **fresh** CSRF cookie, so the follow-up logout
  needs no extra round trip.

The token is a signed, stateless HMAC over a random nonce and an expiry
(`session.csrf.ttlSeconds`), keyed by an HKDF expansion of `session.secret` — a
subdomain able to write the parent-domain cookie still cannot forge one.
Cross-origin login UIs list their origin on `session.csrf.trustedOrigins`;
`cors.allowedOrigins` grants no CSRF trust.

`checkRequestOrigin`, `createCsrfProtection`, `createCsrfProtectionFromConfig`,
`createCsrfGuard` and `createCsrfIssueHandler` are exported
([`src/csrf.mts`](src/csrf.mts)) for compositions that mount their own login
page or protect their own routes; `@o3co/auth-provider-device-grant` guards its
verification page with them.

### What a session records about the authentication

Every session carries `authTime` and `amr` — RFC 8176 values naming how the user
authenticated — so `/authorize` can honour `max_age`, `prompt=login` and
`acr_values`, and the id_token can say `auth_time`, `amr` and `acr` (the whole
picture is in the [oauth package README](../oauth/README.md)):

| login path | `amr` |
| --- | --- |
| `POST /session/login` | `["pwd"]` |
| federation callback | the upstream IdP's `amr` when the provider surfaces it on the profile (`profile.amr`, a string array), plus `fed` — the deployment-defined marker for "through a federation", exported as `FEDERATED_AMR`. RFC 8176 has no value for it, and OIDC Core leaves `amr` values to the deployment. |
| a resumed MFA login (`POST /auth/mfa/verify`, composed by the deployment) | whatever the deployment's resume handler records: the first factor's value plus `mfa`, and the factor's own (`otp`, …). `CreateUserSessionInput.amr` is the seam. |
| account linking (`?link=1`) | unchanged — a link is not a login |

Re-authentication is a *new* session: `POST /session/login` and the federation
callback always create one with a fresh `authTime`, which is what `max_age` and
`prompt=login` measure. A login page that bounces an already-authenticated
browser straight back to `/authorize` is answered `login_required` there, not
looped.

### Account linking across federations (#482)

A federated identity is `<provider>:<sub>` — the federation's name and the IdP's opaque, stable subject — and that string is what the callback hands to `UserRepository.authenticateByToken`. **The Store decides who that is.** The session package never links by e-mail: the same person signing in with Google on the web and with Apple on iOS is two identities, and whether they are one account is the Store's record, not an inference from an address an IdP asserted.

An account gains a second identity through an explicit, authenticated action:

1. The browser already holds a session (`isAuthenticated`, a live `UserSession`).
2. It starts the federation with `?link=1`: `GET /session/oauth/federation/<name>?link=1`, **from a link or a form on the deployment's own pages**. The start is a GET and the session cookie is `SameSite=Lax`, so without a check any page could send a signed-in user there, and paired with a login CSRF at the IdP the attacker's identity would be linked to the victim's account. The start therefore needs positive evidence: `Sec-Fetch-Site: same-origin`, or `none` (a typed URL or bookmark). `cross-site` is refused. `same-site` is not enough on its own — it covers every host on the registrable domain, including a user-controlled `blog.example.com` — so it, and a request with no `Sec-Fetch-Site` (an older browser), must name this origin or one on `session.csrf.trustedOrigins` in its `Referer`; a missing `Referer` is refused, because the navigating page picks its own referrer policy. An account page on a sibling host is therefore listed in `session.csrf.trustedOrigins`, and must not send `Referrer-Policy: no-referrer`. A refusal is `403 link_requires_trusted_origin`. Without an authenticated session it is `401 login_required`; when the Store's repository does not implement `linkFederatedIdentity`, `400 link_unsupported` — all before the browser is sent anywhere.
3. On the callback, after `state`, PKCE and `nonce` are checked exactly as for a login, the identity is resolved:
   - **nobody** → `userRepository.linkFederatedIdentity(currentUserId, { provider, sub, token, claims })`. `ok` links it; the Store's `refused` is `403 link_refused`, its `conflict` is `409 identity_conflict`, each with the Store's `description` when it gives one, sent within RFC 6749's characters (`?` for any other).
   - **another account** → `409 identity_conflict`; the Store is not asked. Linking never merges accounts.
   - **this account** → nothing to link; the callback proceeds.
4. The federation is attached to the **live** session — `sessionFederationIndex` and `federationTokenStore` under the current `sid` — and the browser is redirected as after a login. No new `UserSession` is minted and the express session is not regenerated: a link is not a login, and the session's claims envelope is unchanged (the next login through the new provider builds one the usual way).

The transaction records the session that asked (`link: { sid }`), and the callback links to *that* session's account. A `form_post` federation's callback is a cross-site POST the application session cookie (`SameSite=Lax`) does not accompany, so the record is what binds it — Sign in with Apple links exactly as a `query` federation does — and a browser that presents a different authenticated session at the callback is refused `401 login_required`: the identity is never linked to whichever session the browser holds now. If attaching to the live session fails after the Store has linked, the half-attached federation is removed from the session best-effort (one the session already carried is left as it was, and nothing is removed when the session's federation list could not be read at all) and the callback answers `503`; the Store's link stands, and the next login through that federation lands on the account. Every store the link needs that cannot answer — the session read, the Store's `linkFederatedIdentity`, the index read or write, the token attach — is `503 temporarily_unavailable`, logged once at error level as `federation_link_store_unavailable` with `store`, `step`, the linking `sid` and the error's projection; a rollback step that fails is one `federation_cleanup_failed` warn.

Without `link=1`, an authenticated session that completes a federation whose identity the Store does not know is `401 unknown_user`. **There is no implicit linking** — a session cookie plus a stray identity is the login-CSRF shape, and `link=1` on an authenticated session is what makes the action the user's.

Two audit events: `federation.identity.linked` and `federation.identity.link_refused` (`details.reason`: `conflict` or `refused`), both with `subject` = the account.

**What a Store must check before it links.** The seam receives `claims` as the provider mapped them — the IdP's assertions, nothing more:

- **Never bind on an e-mail alone.** An address the IdP did not verify (`emailVerified !== true` — [absent is not `false`, and a string is absent](#emailverified-is-a-boolean-whatever-the-idp-sent)), a relay address (Apple's `@privaterelay.appleid.com`, surfaced as `isPrivateEmail`), or an IdP that lets a user change their address must never be matched against an existing account. The classic account takeover is exactly that match.
- The link request is already authenticated — that is what `link=1` on a live session guarantees — so a matching address is not what authorises the link; the session is. A Store may still refuse: one identity per provider per account, a maximum re-authentication age, a verified address required on the new identity.
- `sub` is opaque and stable per issuer. Store `<provider>:<sub>` verbatim; never derive an identity from `email`.

`@o3co/auth-provider-foundation`'s `HttpUserRepository` implements the seam when `linkFederatedIdentityUrl` is configured (`CLIENT_USER_LINK_FEDERATED_IDENTITY_URL`): see [its README](../foundation/README.md) for the wire contract. Core's in-memory repository links in memory only — development, not persistence.

## Driving a federation adapter

The adapter contract — `FederationProvider`, `FederationProfile`, the optional
capabilities and their guards, the response-mode vocabulary — is defined and
documented in core: [`core/src/federations/README.md`](../core/src/federations/README.md),
with the definitions in [`types.mts`](../core/src/federations/types.mts) and
[`response-mode.mts`](../core/src/federations/response-mode.mts). Import those
names from `@o3co/auth-provider-core`; this package does not re-export them.
This section is what the session router does with an adapter.

Of the contract, the router drives `buildAuthorizationUrl`, `exchangeCode`,
`responseMode` and `SupportsClaimMapping`. The other capabilities are driven
elsewhere: `SupportsLogout` by `oauth`'s `/oauth/logout` and
`POST /oauth/federation/:name/logout`, `SupportsRefresh` by `oauth`'s
`POST /oauth/federation/:name/token`, and `SupportsDelegatedAuthorization` by
`federation-grants`.

### The start leg

`GET /session/oauth/federation/:name` mints `state` (128 bits), a PKCE
`codeVerifier` and a `nonce` (128 bits) for every federation, whether or not its
IdP uses a nonce, and persists them — with `redirect_to` and the link intent —
**before** redirecting: in the express session for a `query` federation, in a
[federation transaction](#the-transaction-cookie) for a `form_post` one. A store
that cannot persist them is `503 temporarily_unavailable` and redirects nobody,
logged once at error level as `federation_start_store_unavailable` (`store`:
`cookie_session` or `federation_transaction`). A `form_post` federation with no
express-session store on the request, or whose callback URL has no path, is the
composition's fault: `500 misconfiguration`. Every composition fault these
routes meet — that one, a provider with no callback URL, one with no redirect
policy — is logged once at error level as `federation_misconfigured` with the
`reason` (`no_session_store`, `no_callback_path`, `no_callback_url`,
`no_redirect_policy`). The
`redirect_uri` handed to `buildAuthorizationUrl` is the federation's
`callbackURL` from config. For a `form_post` federation the router appends
`response_mode=form_post` to the URL the adapter returned; for a `query` one the
URL is exactly what the adapter returned.

### What the callback does with the profile

1. **The adapter sees `callbackParams`** — the callback's string parameters
   minus `code` and `state`, which the router has already bound. They are
   relayed through the user agent and unsigned; an adapter forwards the RFC 9207
   `iss` from them through core's `callbackUrlForExchange`.
2. **`exchangeCode` throwing is `502 exchange_failed`.** Every refusal inside an
   adapter — a wrong `iss`, a bad id_token, a UserInfo mismatch — surfaces this
   way and never reaches the Store. A profile without `sub` is
   `400 invalid_profile`. The warning, `federation_callback_exchange_failed`
   (the provider bound on the line), carries core's `loggableError(err)`,
   never the error itself: an OAuth
   library puts the token response it refused, access and refresh token
   included, on the error's cause chain, and a logger that serialises the
   whole error would write them out. Every other failure these routes log —
   a store's, a repository's, express-session's — is projected the same way
   (a Redis store's error carries the refused command's arguments; under
   `allow-plaintext`, a token record).
3. **The Store resolves the identity.** `<name>:<sub>` goes to
   `UserRepository.authenticateByToken`; a throw is `503 temporarily_unavailable`,
   `null` is `401 unknown_user` (unless the start asked to link).
4. **Claims** are the local `User`'s, merged with `mapClaims` under
   [claim precedence](#claim-precedence-local-wins-federated-is-namespaced); `amr`
   is `profile.amr` plus `fed`.
5. **The session** is a new `UserSession` (lifetime `session.maxAge`), a
   `subjectSessionIndex` entry when that is wired, a `sessionFederationIndex`
   entry, and a regenerated express session. Any store the callback cannot do
   without that fails — the Store's lookup, the `UserSession` or
   `sessionFederationIndex` write, regenerating or saving the express session,
   attaching the tokens below, and before all of them retiring the ephemeral
   state (see [When a transaction is spent](#when-a-transaction-is-spent)) — is
   `503 temporarily_unavailable`, logged once at error level as
   `federation_callback_store_unavailable` with `store`, `step` and the error's
   projection. What was written is rolled back best-effort, in reverse order;
   a rollback step that fails is one `federation_cleanup_failed` warn. A
   `subjectSessionIndex` write that fails is logged
   (`subject_session_index_write_failed`) and the login proceeds.
6. **Tokens** are attached to `federationTokenStore` under the new `sid` only
   when the profile carries an `accessToken`:
   - `accessToken`, `refreshToken`, `idToken` and `expiresAt` as the adapter
     returned them — `expiresAt: null` is stored as `null` ("do not refresh"),
     and the router never invents an expiry;
   - `scope` and `grantedScope`: `profile.scope` when the adapter returned one
     (an empty or unusable string names nothing), otherwise the provider's
     requested `scope` — RFC 6749 §3.3 reads an absent answer as "as requested"
     ([`src/federations/consented-scope.mts`](src/federations/consented-scope.mts));
   - `tokenType`: `profile.tokenType` verbatim, `""` when it is not a string,
     `undefined` when the adapter returned none (`oauth` reads that as `Bearer`).

   `profile.expiresIn` is not read here.
7. **The redirect** is the federation's redirect policy's
   `resolveCallbackRedirect`. The default policy answers its `authCallbackUrl`
   with `redirect_to` appended when the start carried one, otherwise its
   `clientUrl`.

### Response modes: `query` and `form_post`

Most IdPs redirect the browser back with the authorization response in the
query string. Sign in with Apple does not: whenever the requested `scope`
includes `name` or `email`, Apple **POSTs** an
`application/x-www-form-urlencoded` body to the callback. A provider declares
this with `responseMode: "form_post"` (absent means `query`), and the
declaration changes three things in the router and nothing in the adapter:

1. **The start route appends `response_mode=form_post`.** The parameter is
   written once, in the router, rather than in every adapter.
2. **`POST /session/oauth/federation/<name>/callback` accepts the form body.** It
   is the same handler as the GET callback over a different parameter source:
   same envelope lookup, same `state` comparison, same retire-before-any-async-work
   reuse prevention, same PKCE verifier and nonce read from the stored envelope
   rather than from the request, same rollback. **Each response mode accepts
   exactly one method**: a `query` federation answers a POST with
   `405 method_not_allowed` (`Allow: GET`), so no `query` federation has a POST
   surface, and a `form_post` federation answers a GET with
   `405 method_not_allowed` (`Allow: POST`) before its transaction cookie is
   read, so a third party's `<img src=".../callback">` cannot reach the flow.
3. **That federation's ephemeral state lives in a federation transaction**, with
   a cookie of its own, instead of in the session.

#### The transaction cookie

A `form_post` callback arrives as a **cross-site POST** from the IdP's origin,
and a `SameSite=Lax` cookie — the deployment default, and the right default — is
not sent on one, so a callback relying on the session cookie would arrive with
no `state` to compare and no PKCE verifier. The flow needs *a* cookie that
survives a cross-site POST; it must not be the session cookie. The start route is
unauthenticated and a `SameSite=Lax` cookie **is** sent on a top-level GET, so
anything the start leg changed about the session cookie would be changeable by
any third party who could make a browser follow a link there — permanently,
because express-session serialises `req.session.cookie` into the store and
rebuilds it from there on every later request.

So the cross-site part has its own cookie and its own record:

| | value |
|---|---|
| cookie name | `__Secure-<session.name, minus any prefix>.federation` — e.g. `__Host-auth.session` and `auth.session` both give `__Secure-auth.session.federation` |
| attributes | `HttpOnly; Secure; SameSite=None`, `Path` scoped to that provider's callback URL, `Max-Age` = the transaction lifetime (10 minutes) |
| contents | an opaque 256-bit id, and nothing else |
| record | `state`, `codeVerifier`, `nonce`, `redirectTo`, the link intent and the provider name, in the express-session store under a `fedtx:` key prefix |

The name is derived from `session.name` the way the CSRF cookie's is. The prefix
is the one deviation, and it is applied **unconditionally**: `__Secure-` rather
than `__Host-` because `__Host-` requires `Path=/` and this cookie is
path-scoped to the callback, so a `__Host-` name would be dropped by every
browser; and unconditionally because this cookie is `SameSite=None` and
therefore always `Secure` (browsers drop a `SameSite=None` cookie that is not).
A deployment with a `form_post` federation therefore serves the callback over
HTTPS — which Apple requires of its return URL anyway.

**The application session cookie keeps the attributes the deployment
configured**, on every session, whether or not it ever started a `form_post`
federation; `session.sameSite` is never touched.

The transaction binds the callback to the browser that started it. The `state`
comparison still runs; the transaction cookie is an addition to it, never a
replacement. A caller who presents a stolen `state` without the matching
transaction cookie is refused (`400 invalid_session`) before `state` is read.

If no express-session store is reachable on the request — the store module is
missing or mounted after `sessionModule` — a `form_post` start answers
`500 misconfiguration` instead of starting a flow it could not finish.

An abandoned flow leaves only the short-lived cookie, and the record expires with
it: the expiry is written into the record as `cookie.expires`, which is what
`MemoryStore` reaps on read and what `connect-redis` turns into the key's `EX`.

#### Every host on the auth host's registrable domain is inside the trust boundary

`__Host-` is what pins a cookie to exactly one host; `__Secure-` only requires
HTTPS. The transaction cookie is issued host-only (no `Domain` attribute), but
its `__Secure-` name does not stop another host from setting a cookie of the
same name with a `Domain` that covers the auth host, and the browser sends that
one to the callback too. So the transaction cookie is the one place a
`form_post` flow is weaker than the session cookie, which is `__Host-` by
default — host-only, and checked as such at boot.

- **What an attacker needs:** control of any host that can set a cookie for the
  auth host — for `auth.example.com`, any host under its registrable domain
  `example.com`: `blog.example.com`, a forgotten staging host, a dangling DNS
  record, XSS on a lower-trust app next door, a shared-hosting neighbour.
  Nothing from this deployment: no session, no `state`, no account.
- **What it gets them:** from that host they set `__Secure-<name>.federation`
  with `Domain=example.com` in a victim's browser, start their own federation
  flow, plant *their* transaction id, and auto-submit
  *their* `state` and `code` to the callback. The victim's browser ends up
  logged into the **attacker's** federated account, and whatever the victim does
  next is recorded against it. It does not read the victim's session, expose
  credentials or reach the victim's own account — identity confusion, not
  account takeover.
- **Why signing the cookie would not help:** the attacker's transaction is
  genuinely theirs, so anything the server would accept as its own issuance is
  something they legitimately hold. It is inherent to a path-scoped cookie.
- **What to do:** treat every host under the auth host's registrable domain —
  every `*.example.com` for `auth.example.com` — as inside the deployment's trust
  boundary, and run no untrusted or lower-trust content on any of them.
  `session.domain = null` (the `__Host-` default) protects the session cookie,
  not the transaction cookie; it does nothing against this. That is the rule the
  signed CSRF token exists to survive on the login routes; here there is no
  session to bind to, so the rule is the whole mitigation.

#### When a transaction is spent

Both the record and the cookie are dropped on every callback exit that
**judged** the transaction — success, `invalid_state`, `exchange_failed`,
`unknown_user` alike — and are deliberately *not* dropped by a refusal that
judged nothing. The rule: **a refusal spends the transaction when the request
made a claim about it, and leaves it alone when it made none.** A `state` is
that claim. A callback carrying no `state` — checked once the record has resolved to this provider — claims nothing and costs nothing
(`400 invalid_request`, record untouched); a GET is refused with `405` before
the cookie is read. A *wrong* `state` is an attempt on this transaction, and it
still spends it, so a guess gets no second try; so does a transaction id that
resolves to no record or to another provider's (`400 invalid_session`), and a
store read that fails spends it best-effort (`503`; a spend that fails there, or
on a refusal, is one `federation_cleanup_failed` warn). The distinction matters because
the cookie is `SameSite=None` by necessity and accompanies any cross-site
request to the callback path: if every refusal consumed the record, a third
party could destroy a victim's in-flight login with one `<img>` tag.

That rule is `form_post`-only. A `query` federation keeps its envelope in the
session and retires it only on the path that *matched* `state`, so a wrong
`state` leaves the envelope in place — because the session cookie is
`SameSite=Lax` and **is** sent on a top-level cross-site GET, so spending the
envelope on a mismatch would give a third party the same availability attack.
The guess it would defend against is not a real one: `state` is 128 bits from
the CSPRNG. Only the "no `state`" rule is shared by both modes.

#### What "single use" guarantees

Retiring the record is a `get` followed by a `destroy`, two round trips. The
express-session `Store` API is `get` / `set` / `destroy`: there is no
compare-and-delete on it, and no atomic read-and-consume can be composed from
the three.

| | |
|---|---|
| **Guaranteed** | A callback arriving *after* an earlier one completed its delete finds no record and is refused. That covers the replay this is for: a `code` and `state` lifted from a proxy log, the back button, a retried request. |
| **Not guaranteed** | Callbacks that *overlap*. Two that both read the record before either deletes it both pass the `state` comparison and both reach `exchangeCode`. `MemoryStore` answers synchronously and happens to serialise them; a store with network latency does not. |
| **What bounds the overlap** | The IdP. An authorization code is single-use at the IdP, racing callbacks necessarily carry the same one, and at most one exchange succeeds however many get that far — the rest get `502 exchange_failed`. PKCE binds that exchange to the verifier held in the record. |

If the record cannot be deleted at all, the callback stops with `503
temporarily_unavailable` rather than exchanging the code. This is weaker than `DeviceCodeStore`, which *is* an
atomic read-and-consume: that store owns its adapter and can push the consume
into one Redis round trip, while a federation transaction shares the session
store rather than adding a component slot every deployment would have to
configure — for a property the IdP already provides.
[`Federation.transactionConcurrency.test.mts`](src/routes/__tests__/Federation.transactionConcurrency.test.mts)
pins both halves of the table.

A `query` federation is untouched by all of this: its callback is a same-site
top-level GET, its envelope stays in `req.session.federation`, and its
authorization URL is exactly what its adapter produced.

### Claim precedence: local wins, federated is namespaced

What `mapClaims` returns is an **assertion by an upstream IdP**, not a fact about
this deployment. The callback never merges it into the session's claims envelope
wholesale; it applies one rule
([`src/federations/claim-precedence.mts`](src/federations/claim-precedence.mts),
exported as `mergeFederatedClaims`):

- **The local record is authoritative.** Any claim read off the `User`
  (`email`, `emailVerified`, `name`, `picture`, `groups`) stands; a federated
  value never replaces it.
- **Three claims may fill a gap** — `email`, `name`, `picture`
  (`PROMOTABLE_FEDERATED_CLAIMS`) — only where the local record left the field
  absent, and only when the federated value is a string.
- **Everything else is namespaced** under `claims.federated[<providerName>]`,
  verbatim and complete — including values that were also promoted and values
  that lost to a local claim.

So an IdP cannot contribute `groups` (nor a `roles` / `scope` / `permissions` an
adapter invents): those reach `claims.federated[<providerName>]` and nothing
else. `filterClaimsByScope` never emits provider-specific claims, so nothing
under the namespace can appear in an id_token or `/userinfo` response by
accident.

**The `federated` claim is optional — read it with a presence check.** It is
written only when the provider mapped at least one claim, so it is absent on a
session whose provider implements no `SupportsClaimMapping`, and on one whose
`mapClaims` returned `{}` or a non-object. The provider key is likewise not
guaranteed: a session carries the one provider that authenticated it. Use
`claims.federated?.[name]?.groups`, never `claims.federated[name].groups`.

`emailVerified` is not promotable. It is Store-owned state that
`oauth.requireEmailVerified` can read as a gate on token issuance, and an
upstream IdP verifies an address *it* controls — the `provider:sub` linkage
never forces that to be the local account's address. A deployment that wants to
act on the assertion reads `claims.federated?.[<providerName>]?.emailVerified`
and publishes the result on the `User`.

```ts
// user: { id, username, email: "alice@corp.example", groups: ["staff"] }
// mapClaims → { email: "alice@gmail.example", picture: "https://…", groups: ["admin"] }
{
  email: "alice@corp.example",          // local wins
  groups: ["staff"],                    // federated groups cannot reach here
  picture: "https://…",                 // gap filled
  federated: {
    google: { email: "alice@gmail.example", picture: "https://…", groups: ["admin"] },
  },
}
```

#### `emailVerified` is a boolean, whatever the IdP sent

`MappedClaims.emailVerified` is `boolean | undefined`, and normalising to it is
the **adapter's** job — the merge does not coerce, and nothing downstream does
either. Sign in with Apple sends `email_verified` as the *string* `"true"` on
some responses; `Boolean("false")` is `true`, so an adapter that coerces reports
an unverified address as verified. Read `"true"` / `"false"` to their booleans
and treat every other shape as **absent** — absence is not `false`. A
non-boolean that does reach `mapClaims`'s output is not promoted, but it *is*
recorded verbatim under `claims.federated[<providerName>]`, where a deployment
reading it as a gate would be reading a string.

### Configuring federations

`federations.<name>` names a federation; `extractFederationSection`
([`src/federations/extract-federation-section.mts`](src/federations/extract-federation-section.mts))
normalises a section for the module that reads it. Three shapes are accepted:

```hocon
federations {
  # Shorthand: the key names the type (here "google").
  google {
    enabled = true
    clientId = ${FEDERATIONS_GOOGLE_CLIENT_ID}
    clientSecret = ${FEDERATIONS_GOOGLE_CLIENT_SECRET}
    callbackURL = "https://auth.example.com/session/oauth/federation/google/callback"
    clientUrl = "https://app.example.com/"
  }

  # Flat with an explicit type.
  okta {
    enabled = true
    type = "oidc"
    issuer = "https://dev-123.okta.com"
    # …
  }

  # Nested: the credentials under a sub-section named by the type.
  keycloak {
    enabled = true
    type = "oidc"
    oidc {
      issuer = "https://sso.example.com/realms/staff"
      # …
    }
  }
}
```

A nested section that also sets `clientId`, `clientSecret` or `callbackURL` at
its top level fails boot; any other top-level field is kept beside the
sub-section, and one the sub-section also sets is overridden by it. A section
without `enabled = true` is ignored. The Google, GitHub and Apple
modules are single-tenant — each registers its provider under a fixed name
(`google`, `github`, `apple`) — so a deployment has at most one of each;
`type = "oidc"` sections
([`@o3co/auth-provider-federation-oidc`](../federation-oidc/README.md)) are one
federation per section.

Boot rules:

- Every enabled section must have a `callbackURL`, or `sessionModule` fails boot.
  The federation router hands exactly that value to the adapter as `redirect_uri`.
- Every `federations.<name>` contribution must be paired with a
  `federationRedirectPolicies.<name>` one and vice versa, or boot fails with
  `federation-redirect-policy-unpaired`.
- `sessionModule` does not cross-check config against contributions. A
  federation enabled in config that no module contributes boots, and its routes
  answer `404`; a federation contributed without an enabled section has no
  callback URL, and its start answers `500 misconfiguration`. A composition that
  wants either to fail boot adds the check itself.

### Redirect allowlists

`GET /session/oauth/federation/:name?redirect_to=…` and `POST /session/login`'s
`redirect_to` name where the browser goes afterwards. Every value either may name
has to be listed: `federations.<name>.redirectAllowlist` for a federation (read
by its redirect policy), `session.redirectAllowlist` for the login.

```hocon
federations {
  google {
    enabled = true
    # …credentials…

    redirectAllowlist = [
      "https://app.example.com/welcome"
      "https://app.example.com/account/linked"
      "http://localhost:5173/welcome"      # local dev front-end
    ]

    sessionDomain    = ".example.com"
    authCallbackUrl  = "https://app.example.com/auth/callback"
    clientUrl        = "https://app.example.com/"
  }
}
```

The rule, shared by both lists
([`src/redirect-allowlist.mts`](src/redirect-allowlist.mts)):

- **Matching is exact.** Scheme, host, port, path, query and fragment all
  count. Only case, the default port, `..` segments and percent-encoding are
  normalized away. There is no wildcard, prefix or subdomain matching — an
  entry does not admit its own siblings, and a target that carries dynamic
  query parameters cannot be listed as a family. Make it a fixed path and carry
  the variable part in the session.
- **An absent or empty list refuses every `redirect_to`**, with
  `400 invalid_redirect`. That is the right setting for a deployment that does
  not use the parameter; it is not a way to allow everything.
- **`https` is required, except on loopback.** `localhost`, `127.0.0.0/8` and
  `[::1]` may use `http://`, which is what lets a local development front-end
  and a native client's loopback listener work without a certificate. The port
  is still matched, so list the port the client binds — RFC 8252 §7.3's
  port-agnostic loopback comparison is not implemented here.
- **A cookie domain, when set, constrains the list itself.** Every non-loopback
  entry must be inside `sessionDomain` (federation) or `session.domain` (login),
  checked when the policy is built, so an entry outside it fails boot rather
  than sitting in the config looking effective. Unset a federation's
  `sessionDomain` if a cross-domain redirect target is genuinely intended.

`authCallbackUrl` and `clientUrl` are read by `resolveCallbackRedirect`, not by
the allowlist: the former is the bridge page a `redirect_to` is handed to, the
latter the fallback for a callback whose start carried none. A callback that
needs one of them and finds it unset is answered `500 misconfiguration` — after
the session has been saved — and logged once at error level as
`redirect_policy_server_fault`, as every `5xx` a policy answers is. So every federation needs `clientUrl` unless every
start carries a `redirect_to`, and a start that carries one needs
`authCallbackUrl`.

`FederationRedirectPolicy` ([`src/federations/redirect-policy.mts`](src/federations/redirect-policy.mts))
is the replacement point: a module may contribute its own policy for a
federation, and must fail closed. `createFederationRedirectPolicy` is the
default; `checkRedirectShape`, `createRedirectAllowlistValidator`,
`describeRedirectRejection` and `isLoopbackHostname` are exported so a custom
policy reuses the same rules and rejection vocabulary. The policy's methods
answer with a [`FederationResult`](src/federations/types.mts): `ok` with a value,
or a status, an OAuth error code and a description to send. The route sends the
status as given and the code and description through core's `errorEnvelope`,
which holds them to RFC 6749's characters (printable ASCII without `"` and `\`):
a description character outside them goes out as `?`. A malformed code goes
out as `invalid_request` under a 4xx — the refusal is still the client's, and
`400 server_error` would contradict itself — logged as
`redirect_policy_error_malformed`, and as `server_error` under any other
status. `describeRedirectRejection`'s text is already inside them. A `5xx` is
not a verdict on the client but the policy saying the server cannot answer, so
it is also logged once at error level as `redirect_policy_server_fault`, with
the status and the policy's code and description sanitised and capped (and the
provider at the start leg); a `4xx` is not logged
([`src/internal/refusalEnvelope.mts`](src/internal/refusalEnvelope.mts)).

### Writing an adapter

For an IdP that publishes an OpenID Connect discovery document, write no code:
a `type = "oidc"` section of
[`@o3co/auth-provider-federation-oidc`](../federation-oidc/README.md) is the
adapter. Otherwise an adapter is a module that contributes both
`federations.<name>` (the `FederationProvider`) and
`federationRedirectPolicies.<name>`, with its config on a typed `ComponentMap`
slot that a small bridge module fills from `extractFederationSection`:

```ts
import { defineModule, type FederationProvider } from "@o3co/auth-provider-core";
import { createFederationRedirectPolicy } from "@o3co/auth-provider-session";

declare module "@o3co/auth-provider-core" {
  interface ComponentMap {
    readonly exampleFederationConfig?: ExampleConfig;
  }
}

export const exampleFederationModule = defineModule({
  name: "federation:example",
  requires: ["exampleFederationConfig"] as const,
  contributes: {
    federations: {
      example: (deps): FederationProvider => createExampleProvider(deps.exampleFederationConfig),
    },
    federationRedirectPolicies: {
      example: (deps) => createFederationRedirectPolicy(deps.exampleFederationConfig),
    },
  },
});
```

The contract's own rules are in [core's README](../core/src/federations/README.md)
and the doc comments of [`types.mts`](../core/src/federations/types.mts). What
core gives the provider half, exported from `@o3co/auth-provider-core`:

- `codeChallenge(codeVerifier)` — the S256 challenge for the verifier the router
  minted ([`pkce.mts`](../core/src/federations/pkce.mts)).
- `callbackUrlForExchange({ redirectUri, code, callbackParams })` — the URL to
  hand an OAuth library for the code exchange: `code`, the RFC 9207 `iss` when
  the callback carried one, and nothing else from the bag. Rebuilding the URL
  from `code` alone drops `iss`, so the mix-up check never runs and every login
  fails against an issuer that advertises
  `authorization_response_iss_parameter_supported`. Configure the library with
  the issuer the IdP actually publishes, or the comparison refuses every login
  ([`callback-url.mts`](../core/src/federations/callback-url.mts)).
- `FederationClientSecret` / `resolveClientSecret` — a `client_secret` that is a
  string or a resolver (`() => string | Promise<string>`). The adapter calls
  `resolveClientSecret` on every token request, and it caches nothing, so an
  adapter whose secret rotates (Apple's ES256 JWT) owns its caching. An empty or non-string result is refused
  locally rather than posted upstream
  ([`client-secret.mts`](../core/src/federations/client-secret.mts)).
- `federationTokenSnapshot(tokens, obtainedAt)` — the one reading of a token
  response for a profile or a refresh: `expiresIn` as the library read it and
  `expiresAt` from it, `null` on both when no lifetime was sent, `tokenType`,
  `scope` present exactly when sent
  ([`token-snapshot.mts`](../core/src/federations/token-snapshot.mts)).

The bundled adapters are the worked examples — for instance
[`google.mts`](../federation-google/src/google.mts) in `federation-google`.

## Tests that pin these rules

| Test file | Pins |
| --- | --- |
| [`src/__tests__/module.test.mts`](src/__tests__/module.test.mts) | the manifest's slots and absence policies, the two routers at `/session`, and the `callbackURL` boot rule |
| [`src/__tests__/sessionStoreModule.test.mts`](src/__tests__/sessionStoreModule.test.mts) | the middleware route at `/`, the cookie name, the `__Host-` rule, and the replica-safety declaration and refusal |
| [`src/store/__tests__/factory.test.mts`](src/store/__tests__/factory.test.mts) | the two built-in stores, the `session-store` readiness probe, and the Redis client's error listener |
| [`src/__tests__/cookieSessionStore.test.mts`](src/__tests__/cookieSessionStore.test.mts) | the cookie-session store failing under the real express-session and connect-redis: the middleware's `503` and its one line, and a route's outage answered once with the session not written again |
| [`src/__tests__/csrf.test.mts`](src/__tests__/csrf.test.mts) | the signed token, the origin check and the guard's acceptance rule |
| [`src/routes/__tests__/Session.test.mts`](src/routes/__tests__/Session.test.mts), [`loginRateLimit.test.mts`](src/routes/__tests__/loginRateLimit.test.mts) | login, what logout invalidates and that a store outage does not stop the `UserSession` delete, the outage answers and their one log line, and the login rate-limit guard |
| [`src/routes/__tests__/Federation.test.mts`](src/routes/__tests__/Federation.test.mts) | the start and callback legs, account linking, the store writes and their rollback, the outage answers and their log lines, `amr` |
| [`Federation.formPost.test.mts`](src/routes/__tests__/Federation.formPost.test.mts), [`Federation.applicationCookie.test.mts`](src/routes/__tests__/Federation.applicationCookie.test.mts), [`Federation.transactionFailures.test.mts`](src/routes/__tests__/Federation.transactionFailures.test.mts), [`Federation.transactionConcurrency.test.mts`](src/routes/__tests__/Federation.transactionConcurrency.test.mts) | response modes, the transaction cookie, the untouched session cookie, the transaction's failure paths and what single use guarantees |
| [`src/federations/__tests__/`](src/federations/__tests__/) | the toolkit and the router's federation parts; the request helpers are pinned in core ([`core/src/federations/__tests__/`](../core/src/federations/__tests__/)) |

## See also

- [`@o3co/auth-provider-core`](../core/README.md) — the ports this package drives,
  and the [federation adapter contract](../core/src/federations/README.md)
- [`@o3co/auth-provider-oauth`](../oauth/README.md) — token issuance, `/oauth/logout`,
  and the federation token and logout routes
- [`@o3co/auth-provider-redis`](../redis/README.md) — Redis adapters for the session
  stores (`UserSessionStore` and the rest), distinct from the browser session store
  above
