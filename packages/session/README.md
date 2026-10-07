# @o3co/auth-provider-session

Last updated: 2026-10-07

Browser login, logout and upstream-IdP federation routes for
[auth.provider](../../README.md), the redirect policy every federation adapter
package's type builds beside its provider, and the express-session store those
routes — and every other route that reads `req.session` — run over.

## Responsibility

**Role.** The browser-facing half of authentication. Core owns the ports this
package uses (`UserRepository`, `UserSessionStore`, `FederationTokenStore`,
`SessionLifecycle`, and the federation adapter contract) and implements no
route; this package is the driver of those ports for a browser. It has three
responsibilities:

1. **The `/session` routes** — `sessionModule`: password login, logout, the CSRF
   token route, and the federation start and callback routes. They turn a
   password check or an upstream IdP's answer into a `UserSession` record and an
   authenticated express session — both through one function,
   [`establishSession`](#establishing-the-session), which writes what core's
   [session admission](../core/src/session-admission/README.md) established and
   which a session requirement's completion (the MFA package's) calls too — and
   undo it at logout. A password login asks the registered session
   requirements before anything is written, and one may
   [interrupt it](#when-a-requirement-interrupts-the-login).
2. **The federation-adapter toolkit** — what an adapter package imports from
   the router it plugs into: `createFederationRedirectPolicy` and the allowlist
   rules it is built from. The helpers an adapter builds its upstream requests
   with — `codeChallenge`, `callbackUrlForExchange`, `FederationClientSecret` /
   `resolveClientSecret` — are core's.
3. **The browser session store** — `sessionStoreModule` and
   `createSessionStoreFactory` / `registerBuiltinSessionStores`:
   the express-session middleware, its cookie and its store (memory, or Redis
   through `connect-redis`).

**Owns:**

- the `/session` routes and their answers; the CSRF policy for them
  (`session.csrf.*`), which other packages run through the `csrfGuard` slot;
  the login's own attempt limit (`session.rateLimit.login`), counted through
  core's attempt guard on the `attemptCounter` slot, never a rate limiter's
  budgets; the redirect
  allowlists (`session.redirectAllowlist`, `core.federations.<name>.redirectAllowlist`);
- what the modules provide other packages through slots whose contracts
  are core's: `csrfGuard`, `loginEntry` and `loginCompletion`, and
  `sessionCookiePolicy` and `csrfTokenSigner`
  — [below](#what-the-modules-provide-other-packages);
- how a federation is driven: `state`, PKCE and `nonce`, the `form_post`
  transaction and its cookie, claim precedence, the `amr` a login records, and
  what a callback writes to the stores;
- the `federationRedirectPolicies` key it declares on core's `ContributesMap`,
  which types the redirect policy a federation type's `redirectPolicy` answers
  (boot refuses a module's contribution or override of it), and the
  `federationRedirectPolicyResolver` slot it declares on core
  ([`src/federations/contributes.mts`](src/federations/contributes.mts)), and
  [`FederationResult`](src/federations/types.mts);
- the express-session middleware, its cookie and its store
  (`session-store.*`);
- the two sections, `session` and `session-store`, and their defaults in
  [`config/reference.conf`](config/reference.conf) — [Configuration](#configuration).

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
- token issuance, RP-initiated logout (`POST /oauth/logout`), upstream logout
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

- The toolkit: the redirect policy is a contract this package declares — its
  type is what a federation type's `redirectPolicy` answers — and its router
  consumes. It is the router's, which is why every adapter
  package takes this package as a peer dependency. A federation's entry is not
  read here: core reads `core.federations` and hands the module what it reads
  of each entry through the `federationSettings` slot, the router's callback
  URLs included. The pure
  request helpers are not here: the router uses none of them, so they live in
  core beside the contract that tells adapters to use them.
- The store: it is what `req.session` is, and the routes here are what write it;
  the federation router also keeps `form_post` transactions in it. It is a
  module of its own, apart from `sessionModule`, because other packages read
  `req.session` without these routes — `oauth`'s `/authorize`, consent and
  logout, `device-grant`'s verification page, `federation-grants`' browser
  routes — so a deployment with a login of its own installs the store alone.

**Source layout.** [`src/routes/`](src/routes/) holds the two routers;
[`src/establish-session.mts`](src/establish-session.mts) the tail of a login
both routers share; [`src/federations/`](src/federations/) the toolkit and the
router's federation parts (claim precedence, consented scope, the transaction
store, the redirect policy); [`src/modules/`](src/modules/) and
[`src/store/`](src/store/) the browser session store;
[`src/internal/`](src/internal/) cookie reading, the cookie session's store
failing, the expiry of a destroyed session's cookie, the constant-time
comparison and the claims read off a `User`; [`src/csrf.mts`](src/csrf.mts) the CSRF rule;
[`src/redirect-allowlist.mts`](src/redirect-allowlist.mts) the allowlist rule
the login and federation routes share; and
[`src/login-entry.mts`](src/login-entry.mts),
[`src/login-completion.mts`](src/login-completion.mts),
[`src/session-cookie-policy.mts`](src/session-cookie-policy.mts) and
[`src/csrf-token-signer.mts`](src/csrf-token-signer.mts) what the
modules provide other packages beside the CSRF guard. What each file does is
in its header comment.

## Install

```sh
npm install @o3co/auth-provider-session @o3co/auth-provider-core express express-session
# and, for session-store.storage.type = "redis" (the default in this package's reference.conf):
npm install redis@^6.2.1 connect-redis@^10.0.0
```

Peer dependencies: `@o3co/auth-provider-core`, `express@^5.0.0` and
`express-session@^1.17.0`. Optional peer dependencies: `redis@^6.2.1` and
`connect-redis@^10.0.0`, the Redis session store's libraries. The package's
one dependency of its own is `zod`, which its sections' schemas are written in.

Core is a peer because this package augments it (the
`federationRedirectPolicies` key that types a federation's redirect policy, and
its slot), and an
augmentation reaches only the copy of core it resolves: as a peer, that is
your composition's one copy. A deployment on `session-store.storage.type = "memory"`
installs neither Redis library; nothing imports them until the Redis store is
built. On `"redis"` — the default — install both: with either missing, boot
fails naming it and the install command.

## Composition

```ts
import { createApp } from "@o3co/auth-provider-core";
import { sessionModule, sessionStoreModule } from "@o3co/auth-provider-session";
import { googleFederationTypeModule } from "@o3co/auth-provider-federation-google";

const handle = await createApp({
  modules: [
    sessionStoreModule,           // first, so every module after it can read req.session; provides csrfTokenSigner too
    sessionModule,                // a const Module, not a factory
    googleFederationTypeModule(), // handles every core.federations entry of type "google"
    // ... modules providing userRepository, userSessionStore, federationTokenStore
    //     and sessionLifecycleStore (for sessionLifecycleModule)
  ],
  bootstrapComponents: { config, pathResolver },
});
```

The standalone template's
[`buildModules.mts`](../../templates/standalone/src/buildModules.mts) is the
complete composition.

### What the modules provide other packages

A package imports only core, so what another
package needs of the browser session reaches it through a slot whose contract
is core's ([`core/src/browser-session/types.mts`](../core/src/browser-session/types.mts),
[`core/src/session-admission/login-completion.mts`](../core/src/session-admission/login-completion.mts)).
Each provider runs core's contract suite in this package's tests.

| Slot | Provided by | What it is | Read by |
| --- | --- | --- | --- |
| `csrfGuard` | `sessionModule` | The [CSRF policy](#csrf-on-the-state-changing-routes) `POST /session/login` runs: `middleware` for a request that changes state — the same `403 access_denied` and log line — and `check`, its verdict, which writes nothing; `checkNavigation` for a navigation that starts a flow (the [account-link start](#account-linking-across-federations-482)'s rule), and `issue`. The token's form field is `csrf_token`. | Device verification, once the grant is enabled; the federation-grants consent answer, once grants are enabled |
| `loginEntry` | `sessionModule` | The login page, `session.loginPage.url`, and `urlFor(returnTo)`, which adds `redirect_to` to the page's own query, before any fragment. A page whose query already carries `redirect_to` is refused when the entry is built, and at config validation as `session.loginPage.url`, which the section requires. | `/authorize`, which requires it; the federation-grants connect flow, once grants are enabled |
| `loginCompletion` | `loginCompletionModule` | [`establishSession`](#establishing-the-session), [`answerInterruption`](#when-a-requirement-interrupts-the-login) and [`renewSession`](#renewing-a-signed-in-sessions-id) over the session stores, the `csrfGuard` and the `sessionCookiePolicy` the module requires (the session's lifetime is the policy's). Its own module, loaded beside `sessionModule`: an interruption's token is the deployment's `csrfGuard`'s, whoever filled the slot, and `sessionModule` cannot require the slot it fills. | A requirement's completion, and the step-up's finish (the MFA package's) |
| `sessionCookiePolicy` | the session store's module | The session cookie's name, `secure`, `sameSite`, domain and lifetime: the value the store's route mounts its cookie from. A section that would break core's contract is refused at config validation ([below](#browser-session-store)). Authoritative: while the store's module is loaded an `overrideComponents` entry for the slot refuses boot (`authoritative-component-overridden`), since the store would go on mounting the cookie `session-store.*` describes; a composition without the module fills the slot itself. | `sessionModule` (the CSRF cookie, the session's lifetime, the federation transaction cookie's name) and `loginCompletionModule`, which require it; the subject revocation service, which requires it to size its horizon |
| `csrfTokenSigner` | the session store's module | The CSRF token's signature under a key derived from `session-store.secret` for this purpose alone: HKDF-SHA256, no salt, info `o3co.auth.provider/session-csrf/v1`, 32 bytes, then HMAC-SHA256, base64url. A fixed vector in the tests pins the derivation, so a token verifies for as long as the secret is kept. Neither the secret nor the key leaves it. | `sessionModule`: its `csrfGuard` and the `/session` routes |

The CSRF token's key is derived from `session-store.secret`, which the session
store's module owns. `sessionModule` requires `csrfTokenSigner` and reads no
`session-store.secret`: its `csrfGuard` and its routes sign and check through the one
signer, so a token the guard issues passes the routes' check, and one the routes
issue passes the guard's. The signer's derivation is pinned by literal vectors,
so while the secret is kept a token verifies across a deploy in either
direction: one issued before the deploy verifies after it, and one issued after
it verifies under the release it replaced. A composition that
provides `csrfGuard` without `sessionModule` builds it with
`createSessionCsrfGuard`, and one that loads `sessionModule` without the session
store's module provides `csrfTokenSigner` with `createSessionCsrfTokenSigner`
([Another store](#browser-session-store)).

## Configuration

Each module reads its own section, and nothing else of the configuration:
what `sessionModule` needs of `core.federations` comes from core's
`federationSettings` slot. The defaults and the environment variables
are in the package's [`config/reference.conf`](config/reference.conf), which a
composition root layers because the modules declare it.

| Key | Variable | Default | |
| --- | --- | --- | --- |
| `session-store.secret` | `SESSION_STORE_SECRET` | none | Signs the session cookie: at least 32 bytes (256 bits) of random material, measured decoded. Absent, the session store's module refuses to build, naming the variable |
| `session-store.name` | `SESSION_STORE_NAME` | `__Host-auth.session` | The session cookie's name ([what a browser keeps](#browser-session-store)) |
| `session-store.maxAge` | `SESSION_STORE_MAX_AGE` | `3600000` | The cookie's `Max-Age` and a session's lifetime, in milliseconds, 1 to a year |
| `session-store.secure` | `SESSION_STORE_SECURE` | `true` | |
| `session-store.sameSite` | `SESSION_STORE_SAME_SITE` | `lax` | `none` only with `secure = true` |
| `session-store.domain` | `SESSION_STORE_DOMAIN` | `null` | `null` or empty: a host-only cookie |
| `session-store.storage.type` | `SESSION_STORE_STORAGE_TYPE` | `redis` | Or `memory`, refused under `core.deployment.mode = "multi"` |
| `session-store.storage.redis.url`, `.password` | `SESSION_STORE_STORAGE_REDIS_URL`, `SESSION_STORE_STORAGE_REDIS_PASSWORD` | `redis://localhost:6379`, none | The Redis store's connection |
| `session.redirectAllowlist` | | `[]` | [Redirect allowlists](#redirect-allowlists) |
| `session.csrf.trustedOrigins`, `.ttlSeconds` | `SESSION_CSRF_TTL_SECONDS` (`ttlSeconds`) | `[]`, `7200` | [CSRF](#csrf-on-the-state-changing-routes) |
| `session.loginPage.url` | `SESSION_LOGIN_PAGE_URL` | `/login` | Required. The page the `loginEntry` slot names: a path or an absolute URL, with no `redirect_to` of its own |
| `session.rateLimit.login` | | `{ windowMs = 900000, limit = 20 }` | Required. `POST /session/login`'s own attempt limit: `windowMs` a whole number of milliseconds up to a day (86400000), read as whole seconds rounded up; `limit` a positive whole number |

Each section is strict at every level: a key it does not declare refuses boot,
naming it. `session-store.storage` holds `type` and the `redis` block alone, so
a block for any other storage type is refused too. The
paths these keys moved from — each key of the cookie and its store under
`session`, `endpoints.login.url` and `rateLimit.login` — refuse boot
(`config-path-relocated`), naming the new path and its variable. The variables
renamed with them — `SESSION_<KEY>` to `SESSION_STORE_<KEY>`, and
`ENDPOINTS_LOGIN_URL` to `SESSION_LOGIN_PAGE_URL` — refuse boot
(`environment-variable-renamed`) while the old name is set, alone or beside the
new one at any value: set the new name and unset the old one.

## Browser session store

`sessionStoreModule` contributes one route, `session-middleware`, mounted at `/`: express-session with its cookie
built from `session-store.*` (`HttpOnly`, `Path=/`, `session-store.secure`,
`session-store.sameSite`, `session-store.domain`, `Max-Age` = `session-store.maxAge`) and its store
built from `session-store.storage.*`. Every `req.session` in a deployment is this one.
Defaults and environment variables are in
[`config/reference.conf`](config/reference.conf); `session-store.storage.type` is
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
- **A cookie a browser would not keep is refused at config validation**
  (`config-validation-failed`, the issue naming the key): a `__Host-` name — the
  default, `__Host-auth.session` — unless `session-store.secure = true` and
  `session-store.domain = null`; a `__Secure-` name unless `session-store.secure = true`
  (either prefix in any case, as browsers match it); a `session-store.name` that is
  not an RFC 6265 token; a `session-store.domain` that is not a host name (one leading
  dot allowed; no scheme, port or path); `session-store.sameSite = "none"` unless
  `session-store.secure = true`; a `session-store.maxAge` outside 1 ms to a year. A
  plain-HTTP run sets `session-store.secure = false` with a name that carries no
  prefix (`auth.sid`).
- **The cookie a new session is given is the `sessionCookiePolicy`'s:** the
  route mounts express-session from the policy the slot holds. A stored session
  keeps the cookie attributes it was created with (express-session rebuilds the
  cookie from the record), so when these settings tighten, flush the session
  store to have every browser sign in again under the new cookie.
- **A session destroyed during a request has its cookie expired in the same
  answer**, whichever route destroyed it — `POST /session/logout`, `oauth`'s
  `POST /oauth/logout`, or a deployment's own: once `req.session.destroy`
  calls back without an error, the answer carries one `Set-Cookie` for
  `session-store.name` dated in the past, with the attributes the cookie is
  set with (`Path=/`, `HttpOnly`, and `session-store.domain`,
  `session-store.secure` and `session-store.sameSite`), so the browser drops
  it ([`src/internal/destroyedSessionCookie.mts`](src/internal/destroyedSessionCookie.mts)).
  A destroy the store fails leaves the cookie; a regenerated session keeps
  the new cookie it is given; a destroy that completes after the answer was
  sent changes nothing.
- **`memory` is refused under `core.deployment.mode = "multi"`.** express-session's
  `MemoryStore` forks per replica: a login served by one replica is unknown to
  the others, logout clears only the replica it lands on, and a restart loses
  every session. `sessionStoreModule` declares its replica safety from its own
  parsed section: replica-unsafe when `session-store.storage.type` is
  `memory`, nothing for any other type. So core's replica-safety guard refuses
  it at boot by name with the other offenders, warns when
  `core.deployment.mode` is unset, and says nothing under `"single"`. The guard
  decides before any route is built, by the section the route mounts, so the
  module reads no mode itself: it neither requires `deploymentMode` nor reads
  `deployment`.
- **The Redis store opens its own connection.** A `redis` (node-redis) client to
  `session-store.storage.redis.url` (with `password` when set), under `connect-redis`'s
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
`session-middleware`, or boot fails as above. It also fills the
`csrfTokenSigner` slot `sessionModule` requires, or boot fails
(`missing-required-component`): `createSessionCsrfTokenSigner(sessionSecret)`
signs as the module does, so tokens issued under that secret keep verifying.

## Routes

`sessionModule` contributes two routers, both mounted at `/session`:

| Method | Path | |
| --- | --- | --- |
| GET | `/session/csrf` | Issue a double-submit CSRF token |
| POST | `/session/login` | Password login |
| POST | `/session/logout` | End the browser session — see [what it invalidates](#what-post-sessionlogout-invalidates) |
| GET | `/session/oauth/federation/:name` | Start a federation (`?redirect_to=`, `?link=1`, and the freshness hints `?prompt=` — only `login` counts — and `?max_age=`, a non-negative integer no larger than 2^53−1; a repeated or malformed hint is `400 invalid_request`) |
| GET | `/session/oauth/federation/:name/callback` | Callback of a `query` federation; `405` (`Allow: POST`) for a `form_post` one |
| POST | `/session/oauth/federation/:name/callback` | Callback of a `form_post` federation; `405` (`Allow: GET`) for a `query` one |

`:name` is the federation's name; a name no enabled `core.federations` entry
registers is `404`.

The manifest ([`src/module.mts`](src/module.mts)):

- `requires`: `userRepository`, `userSessionStore`,
  `federationTokenStore`, `csrfTokenSigner` (what the
  CSRF token is signed and checked with; the session store's module provides
  it), core's `federationSettings` — its view of `core.federations`, which
  core fills in every composition: each enabled entry's callback URL, and
  whether an installed federation's upstream `amr` counts; the module reads
  nothing of the configuration but its own section — and the synthetic
  `federationProviders` and `federationRedirectPolicyResolver`, which core
  builds from the federations it dispatches by type — for each enabled
  `core.federations` entry, the provider and the redirect policy the module
  registering its `type` builds — and
  `sessionRequirementResolver` — the password login asks the registered
  requirements through core's
  [session admission](../core/src/session-admission/README.md) before anything
  is written, and the account-linking routes read their session through it,
  so a composition installing `sessionModule` declares
  `core.sessionRequirements.expected`. A router built by hand
  (`routes/Session.mts`, `routes/Federation.mts`) takes the resolver as the
  required `requirements` option and throws without it; a test builds one with
  core's `resolverForTests`. And `deploymentMode`, which core fills from
  `core.deployment.mode`: counting login attempts per process is refused under
  `multi`, so the mode is required rather than read as absent. The session
  router built by hand also takes the signer as the required `csrfTokenSigner`
  option, and throws without it, and the mode as the required `deploymentMode`
  option, where a value that is none of the three, absence included, is a
  TypeError at construction. The federation router built by hand takes
  core's view of the federations as the required `federationSettings` option,
  the transaction cookie's name as the required
  `federationTransactionCookieName` (the module names it after the
  `sessionCookiePolicy` slot's cookie), and where a link may start from as
  `linkTrustedOrigins` (the module passes `session.csrf.trustedOrigins`; absent,
  only this site's own pages), and throws without the first two.
- A link reads the session's federations from core's session lifecycle.
- `optional`: `logger`, `attemptCounter`, `auditSink`, `subjectSessionIndex`,
  `subjectRevocation` (the boundary the linking routes' admission reads),
  `sessionLifecycleStore` (core's session lifecycle port, which the linking
  routes' admission reads after a live record: a session closing or closed
  links nothing; it is required beside `userSessionStore`, and the federation
  routes' factory refuses a composition without it, naming both slots),
  `sessionLifecycle` (core's session lifecycle, which `sessionLifecycleModule`
  fills: each login opens its session's lifecycle record, a federation joins
  the session through it, and the logout closes the session through it;
  `loginCompletionModule` takes it too). It is optional to the manifest, but
  where `userSessionStore` is wired — always, for this module — it is
  required: the route factories, and `loginCompletionModule`'s provider,
  refuse the boot without it, naming both slots. A sessionless composition (no
  user-session store) needs none. `auditSink` unwired must be declared with
  `core.declaredAbsent = ["auditSink"]`, and `subjectSessionIndex` and
  `subjectRevocation` unwired with `oauth.revocation.subject = "unsupported"`,
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
  that fails is one `login_cleanup_failed` warn. The sequence is
  [Establishing the session](#establishing-the-session).
- Once the Store verified the user, and before anything is written, the route
  asks core's [session admission](../core/src/session-admission/README.md)
  (`admitPrimary`) about the primary core builds from the login
  (`passwordPrimary`: the subject, the `User`'s snapshot, the claims the record will hold,
  `authTime`, the allowlisted `redirect_to`, the client's address and user
  agent — `amr` and `authentication` are core's, never the route's). With no
  requirement registered every login is answered `establish`. A requirement's
  outage is `503 temporarily_unavailable` "session requirement unavailable"
  (core's `describeAdmissionOutage`) with nothing written, logged once by
  admission as `session_admission_unavailable` (`store` the requirement's
  name, `phase: "establishment"`). A requirement's interruption is
  [below](#when-a-requirement-interrupts-the-login). The route reads the
  `User` once, with core's `readUserSnapshot`, and takes the subject and the
  claims from that snapshot. A `User` the snapshot refuses (a declared field
  holding what is not plain data, such as a `Date` witness or a function) is
  refused before anything is written, as the route's error (`500`).
- On success — every requirement answered `establish` — it creates a
  `UserSession` (`amr: ["pwd"]`, `authentication` primary `pwd`, lifetime
  `session-store.maxAge`), records it in `subjectSessionIndex` when that is wired,
  regenerates the express session and saves it, and answers `200` with a fresh
  CSRF cookie. The save comes before the answer: a store that cannot save it is
  `503`, not a `200` for a session the next request would not find.
- `redirect_to`, when sent, must be on `session.redirectAllowlist` (see
  [Redirect allowlists](#redirect-allowlists)) and is stored as
  `req.session.redirectTo`; nothing in this package redirects to it.
- The login's attempt limit runs before the credentials are read: one attempt
  per request, keyed `login:ip:<client IP>`, counted against
  `session.rateLimit.login` by core's attempt guard (`createAttemptGuard`) on
  the `attemptCounter` slot's counter. No rate limiter takes part: a limiter's
  `limits`, `defaultLimit` and `failMode` neither loosen nor replace it, and
  the module claims the `login` prefix with core's
  `verifierLimitClaim({ setting: "session.rateLimit.login" })`: no budget, so
  no other module can set one, and the bundled limiter modules refuse a
  `limits.login` entry, naming this key. A refused attempt is
  `429 rate_limited` with `Retry-After` and `Cache-Control: no-store`, and no
  `RateLimit-*` headers, which would tell a guesser how many guesses are left.
  A counter that throws, does not answer within two seconds, or answers
  something core cannot read is `503 service_unavailable` whatever any
  limiter declares, logged as `attempt_counter_unavailable` and audited as
  `rate_limit.unavailable` (`tag: "login"`). With no `attemptCounter` wired
  the guard counts per process: boot is refused under
  `core.deployment.mode = "multi"`, an `attempt_counter_not_shared` warning is
  logged when the mode is unset, and nothing is said under `"single"`. The
  mode is core's `deploymentMode` slot, which the module requires; the router
  reads nothing of `deployment` itself. A refused attempt is not audited.

#### When a requirement interrupts the login

A registered requirement (MFA, when its package is installed) may answer the
login with an interruption: the login does not complete yet. The route then,
in two phases because the express session is regenerated between them:

1. regenerates the express session and leaves it unauthenticated — no
   `isAuthenticated`, `user`, `sid` or `redirectTo`;
2. opens the requirement's ceremony bound to the regenerated session's id; the
   requirement persists, in its own record, the continuation core built — the
   primary as the route built it, `redirect_to` included, and what earlier
   requirements added;
3. saves the session, and answers the requirement's `403` with its body — the
   closed shape core validated against what the requirement declared
   (`error`, and optionally `transaction`, `expires_in` and `hints`; never the
   `User`, a subject or an address) — and a fresh CSRF cookie.

No `UserSession` is written. The requirement's completion route establishes
the session later: it resumes the login through core's `resumePrimary`, which
asks, in order, every requirement not already done in this login — a
requirement that completed is not asked again — and calls
[`establishSession`](#establishing-the-session) with the establishment it
answers, or, when another requirement interrupts, answers that one exactly as
the login does. A regeneration, an `open` that throws or answers a body core
refuses, or a save that fails is `503 temporarily_unavailable` with the
request's cookie session dropped and nothing established, logged once as
`login_store_unavailable` (`store: "cookie_session"` with `step` `regenerate`
or `save`, or the requirement's name with `step: "open"`); after a failed
save the requirement's record is left to its own expiry, bound to a session
id no browser holds. That the `403` tells whoever holds the password it was
right is accepted (the MFA ADR's D23).

The sequence and its failure answers are one function the package exports,
`answerInterruption(admission, { req, res, csrf, reporter })`
([`src/answer-interruption.mts`](src/answer-interruption.mts)): the login
route calls it, and so does a requirement's completion route when
`resumePrimary` answers another interruption. It sends the response — the
`403` with a fresh token from the `CsrfProtection` it is handed, or the `503`
— tells the caller's reporter of a failure once (`store` and `step`, as
above), so each caller logs in its own vocabulary, and answers what it sent
(`answered`, or `unavailable` with the store and the step). Anything that is
not an interruption `admitPrimary` or `resumePrimary` answered — core's
`isInterruptAdmission`, so a copy of one or an object shaped like one too —
is a `RangeError` before the session is touched. A requirement's completion
reaches it through the `loginCompletion` slot, whose answer carries a token
from the deployment's `csrfGuard`; a caller of the function hands it
anything with `issue` — the login route's `CsrfProtection`, or a `csrfGuard`.
The token is signed, not stored, so every guard over one signer accepts the
others'.

### Establishing the session

The tail of a login — from the user verified to the session saved — is one
function, `establishSession`
([`src/establish-session.mts`](src/establish-session.mts)), which
`POST /session/login` and the federation callback both call, and which the
package exports — with the types a caller needs — so a requirement's
completion (the MFA package's, after core's `resumePrimary`) finishes a login
the same way. It takes the `Establishment` core's session admission built —
`admitPrimary`'s for the password login, `establishWithoutAsking`'s for the
federation callback, `resumePrimary`'s for a completion — and writes from its
primary alone: the subject, the `User`, the claims envelope, `authTime`, the
`amr` / `authentication` core composed, the `enrollmentFacts` core derived
from the `User` (the MFA enrollment witness and what its address is — none,
one the provider reads, or one it cannot — never the address), and the `redirectTo`; nothing a caller passes
beside it. Anything that is not an `Establishment` core built —
an object shaped like one, a copy of one — is a `RangeError` before anything
is written. On both paths the login route reads the `User` once, with core's
`readUserSnapshot`, into a plain snapshot — exactly the fields `User`
declares, each by name, once, however the object holds it, so a class
instance with getters or an ORM entity logs in — and hands that snapshot,
never the `User`, to the builders (`passwordPrimary`, `establishWithoutAsking`);
the subject, the claims and the route's log lines are read from it too.
`req.session.user` holds that snapshot: the declared fields alone, nothing
else the Store answered, and no Store's `toJSON` applied. A `User` whose `id`
is not a non-empty string, or whose declared field holds what is not plain
data, is refused by the snapshot; the login then answers `500` with nothing
written. It runs, in order: the
`UserSession` record's create (a fresh `sid`; expiry `session-store.maxAge` after
`authTime`), its lifecycle record opened first in core's session lifecycle,
required beside a `UserSessionStore` (one handed without it is a `TypeError`
before anything is written; an `open` that fails, throws or is refused is the
record's outage at `create` — reported with the lifecycle's own error when it
rejects, with an error naming the session lifecycle otherwise — and a
`create` that fails after the open closes the opened record again); the `subjectSessionIndex` entry when that is wired (best-effort:
a failure is reported and the login proceeds); the caller's steps before the
regeneration; the express session's regeneration (session fixation); the
caller's steps after it; `isAuthenticated`, `user`, `sid` and the primary's
`redirectTo` on the regenerated session; and its save. It answers
`established` with the `sid`, or `unavailable` naming the store and the step,
which the caller answers as `503 temporarily_unavailable`.

What holds:

- **What only one path writes is a step it supplies, not a flag.** The
  callback adds the `federationTokenStore` attach and then the federation's
  join through the session lifecycle after the regeneration, the attach with
  the undo it declares; the password login adds nothing. A step is undone only
  when its write completed.
- **Every failure after the record exists rolls back in reverse order**,
  best-effort: the caller's steps that completed, then the record — its
  lifecycle record closed (`session_logout`), then the `UserSession` deleted;
  a close that fails is reported as the record's `delete`, with the
  lifecycle's own error when it rejects, with an error naming the session
  lifecycle for any answer but `done` or `pending` — then its subject-index
  entry last. From the regeneration on, the request's cookie session is
  dropped too (`abandonCookieSession`), so express-session neither saves the fresh
  session against the store that failed nor sets a cookie naming it; before
  it, the cookie session is untouched. A rollback step that
  fails is reported and the rest still run.
- **Each route logs in its own vocabulary.** The function reports — a store
  that could not answer, a rollback step that failed, an index write that
  failed — through a reporter the route supplies, built once with the `sid`
  and the subject before the first write: `login_store_unavailable` and
  `login_cleanup_failed` for the password login,
  `federation_callback_store_unavailable` and `federation_cleanup_failed` for
  the callback, `subject_session_index_write_failed` for both.
- **Without a `UserSessionStore`** — which only `POST /session/login`'s router
  accepts — no record is created and no step runs: the express session alone
  is regenerated, flagged and saved.
- The CSRF token, the `200` and the redirect stay with the callers.

### Renewing a signed-in session's id

`renewSession` ([`src/establish-session.mts`](src/establish-session.mts),
beside the one function that writes the signed-in state) moves a signed-in
browser to a new express session id after its session is escalated — the MFA
step-up (the MFA ADR's D27). It reaches the MFA package through the
`loginCompletion` slot and is not exported. It reads `isAuthenticated`, `user`
and `sid`, regenerates the express session, writes back those of the three the
session held and a fresh renewal nonce (core's `newRenewalNonce`, as
`renewalNonce` beside `sid`), and saves. It answers `renewed` with the nonce,
or `unavailable` with `cookie_session` and the step, `regenerate` or `save`,
which the caller answers as an outage.

What holds:

- **Only the signed-in state moves, under a fresh nonce.** Every other field —
  a login's `redirectTo`, anything another flow left on the session, a nonce
  an earlier renewal wrote — is dropped. A session that is not signed in
  stays so. No `UserSession` record is written: the `sid` is the same.
- **The old id is destroyed, but that alone does not keep it out.**
  express-session regenerates by destroying the old id in its store, and its
  save overwrites whatever the store holds, unconditionally: a request in
  flight on the old id that writes its session and ends after the renewal
  puts the old id back, signed in on the same `sid`. What keeps the
  escalation off it is the nonce: the caller records the escalation with it
  (`recordSecondFactor`'s `renewalNonce`), and core's admission answers
  every cookie session that does not hold the record's nonce `not_live`
  (`renewed`) — the old id put back included.
- **A failure writes nothing and drops the request's cookie session**
  (`abandonCookieSession`), reported once through the caller's reporter; a
  request with no express session is the cookie session's outage at
  `regenerate`. At `save` the old id is already destroyed, so the browser is
  signed out. At `regenerate` the store could not destroy it, and the old id
  keeps what it held before. Either way the caller records nothing on
  `unavailable`, so no id holds the escalation.
- **What renewal orphans.** Records bound to the old express session id are
  lost: a consent `/authorize` parked, a federation-grant browser binding,
  and the session's other open MFA transactions. A flow in another tab starts
  again. A tab that still holds the old cookie is refused once the session is
  escalated, and signs in again; its `POST /session/logout` ends only its own
  cookie session, never the renewed one ([below](#what-post-sessionlogout-invalidates)).

### What `POST /session/logout` invalidates

Both logout endpoints, this one and `POST /oauth/logout`, end the session
through core's session lifecycle, so they invalidate the same things.

`POST /session/logout` — the browser's own logout, and the one a BFF /
`auth.proxy` injection topology calls — closes the session through core's
session lifecycle and destroys the express session. A router with a
`UserSessionStore` requires the lifecycle beside it; a sessionless router
(no store) has no record to close and destroys the express session alone.

The logout closes the session with `sessionLifecycle.close(sid, "session_logout")` (`sessionLifecycleModule` fills the slot). The close runs as `/oauth/logout`'s does, in order: it revokes the session's refresh-token families and removes its federation tokens, then tells its relying parties back-channel (through the notifier `oauthEndpointsModule` contributes), then removes the per-session indexes, then deletes the `UserSession`, and removes the subject-index entry last, so a close still pending keeps the sid where a subject-wide revocation finds it.
- A close that committed answers the same `200` and destroys the express session, whether its work is `done` or still `pending`: from the commit on, no liveness read answers the session live, and a later close or the lifecycle's sweep resumes what is left. A `pending` close is audited as `logout.close_pending` (`subject`, `sid`), as `/oauth/logout` audits it.
- A logout whose `UserSession` already lapsed has nothing to close: it answers `done` and destroys the express session, and the session's leftovers lapse with their TTL, as at `/oauth/logout`.
- A close that did not commit, or a lifecycle that threw — whatever the error, a `RangeError` included — answers `503 temporarily_unavailable` and keeps the express session for a retry. That includes a close whose commit found no live record (the session's end had passed on the store's clock) and whose work, run at once with no record to save it in, failed: a retry runs it again. It is logged once as `session_logout_store_unavailable` (error, `store: "session_lifecycle"`, `step: "close"`, `sid`), carrying the error's projection when the lifecycle rejected; any answer but `done` or `pending` is the same outage, with no error to project.
- A step of the close work that fails is core's `session_close_item_failed` (warn, with the `item`), and the close stays pending; alert on `item: "delete_user_session"`.

**A copy the record was renewed away from.** Before it invalidates anything,
the logout asks core's `cookieRenewedAway`: when the record the cookie names
carries a renewal nonce this cookie session does not hold — an old cookie, or
a copy of it, from before a step-up renewed the session — the record is the
renewed session's, so only this cookie session is destroyed and the answer is
the same `200`. The renewed session stays live, except in one window. The
logout reads the record and then closes the session, as two steps, and a
step-up keeps the `sid` and moves only the renewal nonce (the MFA ADR's D27).
When a step-up records its nonce after the logout read the record and before
the close commits, the logout acts on what it read and closes the session,
escalated by then, although the cookie it came from is now a copy the record
was renewed away from. The renewal nonce is written to the `UserSessionStore`
and the close commits in the `SessionLifecycleStore`, so no single store write
orders the two. This is accepted: the logout only ends the session, never
extends or grants one, and the same cookie could close that session before the
step-up. When the record cannot be read, that is logged as
`logout_user_session_read_failed` and the logout answers `503
temporarily_unavailable`: it closes nothing and keeps the express session for a
retry.

**The cookie session's destroy.** Once the express session is destroyed, the
answer also expires the session cookie: the session store expires the cookie
of any session destroyed during a request, `POST /oauth/logout`'s included,
with the attributes the cookie is set with
([Browser session store](#browser-session-store)), so the browser drops it;
the router sets no session cookie of its own. If destroying the express
session fails — the cookie store's outage — the user is not logged out, so the
response is `503 temporarily_unavailable`, logged once at error level as
`session_logout_store_unavailable` (`store: "cookie_session"`, `step:
"destroy"`, the `sid`), and the client retries, the cookie left as it is; by
then the session's close has committed, so `/authorize` refuses the surviving
cookie on its own account. A
session carrying no `sid` has nothing to close and only the express session is
destroyed.

### CSRF on the state-changing routes

`POST /session/login` and `POST /session/logout` accept a request that carries
**either** a same-origin (or explicitly trusted) `Origin` / `Referer`, **or** a
valid double-submit CSRF token. A request carrying neither is rejected with
`403 access_denied`.

- **Browsers** need nothing extra: the browser sets `Origin` on a same-origin
  `fetch` / form post, and that satisfies the check on its own.
- **Header-less clients** (curl, server-side agents, test harnesses) call
  `GET /session/csrf`, which sets a JS-readable `<session-store.name>.csrf` cookie
  and returns the same value as `csrf_token`. Send both back: the cookie plus
  either an `x-csrf-token` header or a `csrf_token` form field.
- A **foreign** `Origin` is rejected even when a token is present, since it is
  positive evidence of a cross-site request.
- A successful login returns a **fresh** CSRF cookie, so the follow-up logout
  needs no extra round trip.

The token is a signed, stateless HMAC over a random nonce and an expiry
(`session.csrf.ttlSeconds`), keyed by an HKDF expansion of `session-store.secret` — a
subdomain able to write the parent-domain cookie still cannot forge one. The
routes sign and check it through the `csrfTokenSigner` slot, which the session
store's module fills, and read no `session-store.secret`. A token is well signed only
when the signer's `verify` answers `true`, and one whose expiry lies more than
`session.csrf.ttlSeconds` and 60 seconds of clock skew ahead is refused, since
no token the routes issue expires later.
Cross-origin login UIs list their origin on `session.csrf.trustedOrigins`;
`http.cors.allowedOrigins` grants no CSRF trust. A listed origin can also answer
federation-grant consents and device verification, so a client's origin is
never listed (the federation-grants ADR's D7).

Another package runs this policy through the `csrfGuard` slot `sessionModule`
provides — device verification mounts its `middleware`, and the
federation-grants consent answer asks its `check` — rather than importing it. `checkRequestOrigin`, `createCsrfProtection`, `createCsrfProtectionFromConfig`,
`createCsrfGuard`, `createCsrfIssueHandler` and `createSessionCsrfGuard` are
exported ([`src/csrf.mts`](src/csrf.mts)) for compositions that mount their own
login page or protect their own routes. `createCsrfProtection` and
`createCsrfProtectionFromConfig` take the signer (`{ signer }`) — the
`csrfTokenSigner` slot's, or `createSessionCsrfTokenSigner(sessionSecret)`
([`src/csrf-token-signer.mts`](src/csrf-token-signer.mts)), which holds the
secret to core's entropy floor — and refuse to be built without one, or with
one that breaks core's contract: they sign two payloads and check the
signatures, a changed one and another payload's, before building. They read
`sign` and `verify` off the signer once, so a signer object changed afterwards
changes nothing they mint or accept.

### What a session records about the authentication

Every session carries `authTime`, `amr` — RFC 8176 values naming how the user
authenticated, as far as this provider vouches for it — and `authentication`,
how the session was established (the MFA ADR's D9: the primary, which
federation, what an untrusted upstream IdP asserted, when a second factor was
verified, and for a federated login when the upstream last authenticated the
user, `upstreamAuthTime`). So `/authorize` can honour `max_age`, `prompt=login` and
`acr_values`, and the id_token can say `auth_time`, `amr` and `acr` (the whole
picture is in the [oauth package README](../oauth/README.md)). Core composes
both for each login path (`passwordSessionAuthentication`,
`federatedSessionAuthentication`):

| login path | `amr` | `authentication` |
| --- | --- | --- |
| `POST /session/login` | `["pwd"]` (core's `PASSWORD_AMR`) | primary `pwd` |
| federation callback | `["fed"]` — `fed` is the deployment-defined marker for "through a federation", core's `FEDERATED_AMR`, which this package re-exports; RFC 8176 has no value for it, and OIDC Core leaves `amr` values to the deployment. For a federation with `trustUpstreamAmr = true`, the upstream IdP's `amr` beside it | primary `fed`, the federation's name, and — unless the federation trusts its IdP — the IdP's `amr` as `upstreamAmr`; `upstreamAuthTime`, the `auth_time` the adapter reports, or `null` when it reports none and the federation's `callbackMeetsFreshness` is `false` (the default), or nothing when that is `true` |
| account linking (`?link=1`) | unchanged — a link is not a login | unchanged |

**What an upstream IdP asserted counts only for a federation that trusts it**
(`core.federations.<name>.trustUpstreamAmr`, default `false`, the MFA ADR's D13).
The upstream `amr` is what a provider surfaces on the profile (`profile.amr`, a
string array; none of the bundled adapters does). By default it is kept in
`authentication.upstreamAmr`, for the record: no token carries it and no
`acr_values` entry is met by it — an IdP's word about its own login is not this
provider's. `trustUpstreamAmr = true`, beside `enabled` in the federation's
entry, records it beside `fed`, where it counts, as every federation's did
before the switch existed. The routes read each installed federation's switch
once, when they are built, from core's `federationSettings` slot, whose
`trustsUpstreamAmr` is core's `federationTrustsUpstreamAmr` — the reading
`@o3co/auth-provider-oauth`'s `acr` drop uses, so what a session records and
what `/authorize` advertises agree; a switch that is neither `true` nor
`false` refuses the boot, and the schema coerces the spellings an environment
variable delivers. Each federation's
switch is kept by the name it is installed under, and a login takes the switch
of the name its callback came in on, which is also the federation
`authentication.federation` names. The decision is written into the session
when it is created: changing the switch applies to sessions established
afterwards.

**Withdrawing trust.** Turning `trustUpstreamAmr` from `true` to `false`
does not reach a session already recorded under it: its `amr` keeps the IdP's
values — they were vouched for when it was written — so tokens minted from it
keep carrying them, and the refresh tokens minted from it carry them forward
until their family ends (`oauth.refreshToken.expiresIn` after the login, a day
by default). To withdraw at once, call core's `revokeAllForSubject` for the
subjects who signed in through that federation: it ends their sessions, the
refresh families and codes minted from them, and every access token this
provider itself verifies (introspection, `/oauth/userinfo`, the
federation-token route, token exchange, the refresh grant), and they log in
again under the new setting. An access token a resource server validates
offline lives until its `exp`. `revokeAllForSubject` needs
`subjectRevocation` and `subjectSessionIndex` wired, and reports itself
`incomplete` without them. The [operator runbook](../../docs/operator-runbook.md#trusting-an-upstream-idps-amr-and-withdrawing-that-trust)
has the procedure.

Re-authentication is a *new* session: `POST /session/login` and the federation
callback always create one with a fresh `authTime`. What `max_age` and
`prompt=login` measure is the session's freshness (core's `sessionFreshness`):
`authTime`, or for a federated login the earlier of that and the upstream's
recorded authentication. The federation start
(`GET /session/oauth/federation/:name`) takes optional `prompt` and `max_age`
hints — a space list in which only `login` counts, and a non-negative integer
no larger than 2^53−1; anything else is `400 invalid_request` — and passes them to the adapter as its
`ask`, which forwards only what its upstream documents. A start from a
browser that already holds an application session, and is not a link, is a
re-authentication and asks for a new login (`login: true`) whatever the hints
say, so an upstream that honours it (the OIDC adapter forwards `prompt=login`)
prompts the user again rather than answering from its own single sign-on —
the cost is that a signed-in user who starts a federated login again sees the
IdP's sign-in prompt. The callback records
the upstream's `auth_time` the adapter reports (`authentication.upstreamAuthTime`)
when it is an instant at or after the epoch no further ahead than
`DEFAULT_CLOCK_SKEW_MS`; any other value the adapter reports is a failed
exchange (`502 exchange_failed`, `federation_callback_exchange_failed`);
when it reports none, a federation with `core.federations.<name>.callbackMeetsFreshness`
`false` (the default) records `null`, never fresh, and one with `true` records
nothing, so the session is as fresh as its `authTime`. A login page that bounces an already-authenticated
browser straight back to `/authorize` is answered `login_required` there, not
looped.

### Account linking across federations (#482)

A federated identity is `<provider>:<sub>` — the federation's name and the IdP's opaque, stable subject — and that string is what the callback hands to `UserRepository.authenticateByToken`. **The Store decides who that is.** The session package never links by e-mail: the same person signing in with Google on the web and with Apple on iOS is two identities, and whether they are one account is the Store's record, not an inference from an address an IdP asserted.

An account gains a second identity through an explicit, authenticated action:

1. The browser already holds a session (`isAuthenticated`, a live `UserSession`).
2. It starts the federation with `?link=1`: `GET /session/oauth/federation/<name>?link=1`, **from a link or a form on the deployment's own pages**. The start is a GET and the session cookie is `SameSite=Lax`, so without a check any page could send a signed-in user there, and paired with a login CSRF at the IdP the attacker's identity would be linked to the victim's account. The start therefore needs positive evidence: `Sec-Fetch-Site: same-origin`, or `none` (a typed URL or bookmark). `cross-site` is refused. `same-site` is not enough on its own — it covers every host on the registrable domain, including a user-controlled `blog.example.com` — so it, and a request with no `Sec-Fetch-Site` (an older browser), must name this origin or one on `session.csrf.trustedOrigins` in its `Referer`; a missing `Referer` is refused, because the navigating page picks its own referrer policy. An account page on a sibling host is therefore listed in `session.csrf.trustedOrigins`, and must not send `Referrer-Policy: no-referrer`. A refusal is `403 link_requires_trusted_origin`. Next, when the Store's repository does not implement `linkFederatedIdentity`, the start is `400 link_unsupported` — a fault of the composition, answered before the session is read, so it is the same whatever the session store is doing. The start then reads the session through core's [session admission](../core/src/session-admission/README.md) as `session.link`, graded `credential_change` — a linked identity is a new way into the account, so a registered requirement decides its recent-authentication rule here, where a step-up has a page to return to: a cookie that is not authenticated, carries no `sid` or no `user.id`, or whose `UserSession` is gone, past its `expiresAt`, another subject's, or covered by the subject-revocation boundary (when `subjectRevocation` is wired), and a requirement's `reauthenticate` or `unmet`, are `401 login_required`; a requirement's step-up is `403 step_up_required` with `error_description`, `requirement` and `page`, the requirement's registered step-up page as one absolute URL string — see [When the start answers a step-up](#when-the-start-answers-a-step-up); an outage of the session store, the session lifecycle store, the boundary or a requirement is `503 temporarily_unavailable`, described by what failed (core's `describeAdmissionOutage`: "session store unavailable", "session lifecycle store unavailable", "revocation store unavailable" or "session requirement unavailable"), logged once by admission (`session_admission_unavailable`, `action: "session.link"`). All of these come before the browser is sent anywhere.
3. On the callback, after `state`, PKCE and `nonce` are checked exactly as for a login, the identity is resolved:
   - **nobody** → `userRepository.linkFederatedIdentity(currentUserId, { provider, sub, token, claims })`. `ok` links it; the Store's `refused` is `403 link_refused`, its `conflict` is `409 identity_conflict`, each with the Store's `description` when it gives one, sent within RFC 6749's characters (`?` for any other).
   - **another account** → `409 identity_conflict`; the Store is not asked. Linking never merges accounts.
   - **this account** → nothing to link; the callback proceeds.
4. The federation is attached to the **live** session — `federationTokenStore` under the current `sid`, and a join through core's session lifecycle — and the browser is redirected as after a login. Whether the session already carries the federation is read from the lifecycle (`sessionLifecycle.federations`): a re-link that fails leaves a federation it lists in place, and a read that rejects or answers anything but `listed` is `503` before anything is written. The tokens are attached first and the federation then joins the session through the lifecycle, which records it: a session closed since its admission is refused `401 login_required` and the lifecycle removes those tokens. So is a session established before the lifecycle was installed, which has no lifecycle record and cannot be joined by a federation alone: it must sign in again, and a re-link of a federation it already carries removes that federation's tokens; a join it cannot answer is `503`, rolled back as below. No new `UserSession` is minted and the express session is not regenerated: a link is not a login, and the session's claims envelope is unchanged (the next login through the new provider builds one the usual way).

The transaction records the session admission let link and its subject (`link: { sid, subject }` — the `sid` the cookie named, which is the key the record was read by, and the record's subject), and the callback links to *that* session's account: it reads the session through admission again, as `session.link_callback` (`use`) over the recorded `sid` and subject (core's `linkClaim`). A `form_post` federation's callback is a cross-site POST the application session cookie (`SameSite=Lax`) does not accompany, so the record is what binds it — Sign in with Apple links exactly as a `query` federation does — and a browser that presents a different authenticated session at the callback is refused `401 login_required`: the identity is never linked to whichever session the browser holds now. A session that is no longer live, whose record names another subject, that the revocation boundary covers, or that a requirement does not admit — a step-up included, since the callback comes from the IdP and has nowhere to return to — is `401 login_required` ("Linking a federated identity requires a live session"), and so is a transaction a start wrote before it recorded the subject: the user starts the link again. If attaching to the live session fails after the Store has linked, the half-attached federation is removed from the session best-effort (one the session already carried is left as it was, and nothing is removed when the session's federation list could not be read at all) and the callback answers `503`; the Store's link stands, and the next login through that federation lands on the account. Every store the link needs that cannot answer — the session read, the Store's `linkFederatedIdentity`, the session lifecycle's read of the session's federations, the token attach — is `503 temporarily_unavailable`, logged once at error level: the session read (the store, the boundary, a requirement — described as the link start's is) by admission as `session_admission_unavailable` with `store` and `action: "session.link_callback"`, never the `sid`; the others as `federation_link_store_unavailable` with `store`, `step`, the linking `sid` and the error's projection; a rollback step that fails is one `federation_cleanup_failed` warn.

Without `link=1`, an authenticated session that completes a federation whose identity the Store does not know is `401 unknown_user`. **There is no implicit linking** — a session cookie plus a stray identity is the login-CSRF shape, and `link=1` on an authenticated session is what makes the action the user's.

Two audit events: `federation.identity.linked` and `federation.identity.link_refused` (`details.reason`: `conflict` or `refused`), both with `subject` = the account.

**What a Store must check before it links.** The seam receives `claims` as the provider mapped them — the IdP's assertions, nothing more:

- **Never bind on an e-mail alone.** An address the IdP did not verify (`emailVerified !== true` — [absent is not `false`, and a string is absent](#emailverified-is-a-boolean-whatever-the-idp-sent)), a relay address (Apple's `@privaterelay.appleid.com`, surfaced as `isPrivateEmail`), or an IdP that lets a user change their address must never be matched against an existing account. The classic account takeover is exactly that match.
- The link request is already authenticated — that is what `link=1` on a live session guarantees — so a matching address is not what authorises the link; the session is. A Store may still refuse: one identity per provider per account, a maximum re-authentication age, a verified address required on the new identity.
- `sub` is opaque and stable per issuer. Store `<provider>:<sub>` verbatim; never derive an identity from `email`.

`@o3co/auth-provider-foundation`'s `HttpUserRepository` implements the seam when `linkFederatedIdentityUrl` is configured (`REPOSITORIES_USER_HTTP_LINK_FEDERATED_IDENTITY_URL`): see [its README](../foundation/README.md) for the wire contract. Core's in-memory repository links in memory only — development, not persistence.

#### When the start answers a step-up

The start is a navigation: the account page links to it, and the browser follows the redirect to the IdP. A `403 step_up_required` is JSON, not a page, so a browser that navigated there shows the body. A page that must handle the step-up probes the start first, from the deployment's own origin, and navigates itself:

```js
const res = await fetch(startUrl, { redirect: "manual", credentials: "include" });
if (res.type === "opaqueredirect") {
  location.assign(startUrl); // the start would send the browser to the IdP: go
} else if (res.status === 403 && (await res.json()).error === "step_up_required") {
  // send the user to `page` — the requirement's step-up — then start the link again
}
```

The probe runs a start of its own, whose transaction is abandoned and expires (`DEFAULT_FEDERATION_TRANSACTION_TTL_MS`). `page` is one absolute URL, as every consumer answers a step-up: the requirement's page as registered, resolved at registration on the **issuer's** origin (`oauth.jwt.issuer`) — not on the account page's own origin, which may be another host — with its params on the query and no return parameter, so the page navigates to it as it is, adding its own return parameter if it wants one. A navigation-shaped answer — the start itself redirecting to the step-up page and back — is for the MFA work to design; this release answers JSON.

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
   way and never reaches the Store, and so does an answer whose `expiresIn` or
   `expiresAt` throws when read, or whose `expiresAt` is neither absent,
   `null` nor a `Date` holding an instant. A profile without `sub` is
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
   is `fed` — with `profile.amr` beside it for a trusted federation, else
   `profile.amr` kept in `authentication.upstreamAmr`
   ([above](#what-a-session-records-about-the-authentication)).
5. **The session** is a new `UserSession` (lifetime `session-store.maxAge`)
   with its lifecycle record opened, a `subjectSessionIndex` entry when that
   is wired, and a regenerated express session —
   [Establishing the session](#establishing-the-session), with the tokens
   below and the federation's join as the callback's own steps. Its establishment is the
   one core's `establishWithoutAsking` builds from the federation's own facts:
   no session requirement is asked at a federated login in this release (an
   interruption there would have to be a navigation), so a requirement that
   interrupts a password login does not interrupt it; the requirements'
   use-time admission applies to the session at each use. Any store the callback cannot do
   without that fails — the Store's lookup, the `UserSession` write or the
   lifecycle's join, regenerating or saving the express session,
   attaching the tokens below, and before all of them retiring the ephemeral
   state (see [When a transaction is spent](#when-a-transaction-is-spent)) — is
   `503 temporarily_unavailable`, logged once at error level as
   `federation_callback_store_unavailable` with `store`, `step` and the error's
   projection. What was written is rolled back best-effort, in reverse order;
   a rollback step that fails is one `federation_cleanup_failed` warn. A
   `subjectSessionIndex` write that fails is logged
   (`subject_session_index_write_failed`) and the login proceeds.
   The federation joins the session through core's session lifecycle
   (`sessionLifecycle`), after the tokens below are attached: a session
   closed before the join commits is refused, the lifecycle removes the
   tokens handed to it, and the callback answers `401 login_required` with
   what it wrote rolled back, logging nothing (the session's close, not an
   outage); a join the lifecycle cannot answer is `503` (store
   `session_lifecycle`, step `join`). Every rollback
   closes the session's lifecycle record before it deletes the `UserSession`.
6. **Tokens** are attached to `federationTokenStore` under the new `sid` only
   when the profile carries an `accessToken`:
   - `accessToken`, `refreshToken` and `idToken` as the adapter returned them;
   - the lifetime, read once from `profile.expiresIn` and `profile.expiresAt`
     through core's `readUpstreamTokenLifetime`, at a floor of 0 and with no
     cap. When `expires_in` is stated and the reading is finite, `obtainedAt`
     is the instant just before `exchangeCode` was called and `expiresAt` is
     the reading's end, the earlier of the adapter's instant and
     `obtainedAt + expiresIn`. Otherwise (an end stated only as an instant,
     which is on the upstream's clock; none; a malformed, contradictory or
     spent one) `expiresAt` is the adapter's, `null` stored as `null` ("do not
     refresh"), and the record has no `obtainedAt`, so `oauth` keeps its
     refresh buffer for it. The router never invents an expiry. The link
     callback writes the same lifetime;
   - `scope` and `grantedScope`: `profile.scope` when the adapter returned one
     (an empty or unusable string names nothing), otherwise the provider's
     requested `scope` — RFC 6749 §3.3 reads an absent answer as "as requested"
     ([`src/federations/consented-scope.mts`](src/federations/consented-scope.mts));
   - `tokenType`: `profile.tokenType` verbatim, `""` when it is not a string,
     `undefined` when the adapter returned none (`oauth` reads that as `Bearer`).
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
| cookie name | `__Secure-<session-store.name, minus any prefix>.federation` — e.g. `__Host-auth.session` and `auth.session` both give `__Secure-auth.session.federation` |
| attributes | `HttpOnly; Secure; SameSite=None`, `Path` scoped to that provider's callback URL, `Max-Age` = the transaction lifetime (10 minutes) |
| contents | an opaque 256-bit id, and nothing else |
| record | `state`, `codeVerifier`, `nonce`, `redirectTo`, the link intent and the provider name, in the express-session store under a `fedtx:` key prefix |

The name is derived from `session-store.name` the way the CSRF cookie's is. The prefix
is the one deviation, and it is applied **unconditionally**: `__Secure-` rather
than `__Host-` because `__Host-` requires `Path=/` and this cookie is
path-scoped to the callback, so a `__Host-` name would be dropped by every
browser; and unconditionally because this cookie is `SameSite=None` and
therefore always `Secure` (browsers drop a `SameSite=None` cookie that is not).
A deployment with a `form_post` federation therefore serves the callback over
HTTPS — which Apple requires of its return URL anyway.

**The application session cookie keeps the attributes the deployment
configured**, on every session, whether or not it ever started a `form_post`
federation; `session-store.sameSite` is never touched.

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
  `session-store.domain = null` (the `__Host-` default) protects the session cookie,
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
  in its JSON form and complete — including values that were also promoted and
  values that lost to a local claim. Core stores `federated` as one custom claim:
  a mapped value JSON cannot hold (a bigint, a cycle) drops the whole
  `federated` claim, warned once on the callback's logger as
  `login_claim_dropped`, and the login continues.

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

Each `core.federations.<name>` entry is one federation, reached at
`/session/oauth/federation/<name>`. An entry is flat: the keys core owns and the
keys of its `type` sit side by side.

```hocon
core.federations {
  google {
    enabled = true
    type = "google"
    clientId = ${CORE_FEDERATIONS_GOOGLE_CLIENT_ID}
    clientSecret = ${CORE_FEDERATIONS_GOOGLE_CLIENT_SECRET}
    callbackURL = "https://auth.example.com/session/oauth/federation/google/callback"
    clientUrl = "https://app.example.com/"
  }

  okta {
    enabled = true
    type = "oidc"
    issuer = "https://dev-123.okta.com"
    callbackURL = "https://auth.example.com/session/oauth/federation/okta/callback"
    # …
  }

  keycloak {
    enabled = false
    type = "oidc"
    issuer = "https://sso.example.com/realms/staff"
    # …
  }
}
```

Core owns `enabled`, `type`, `trustUpstreamAmr` and `callbackURL`; every other
key belongs to the entry's type. Every entry names its `type`, enabled or not:
one without, or with an empty one, refuses boot (`config-validation-failed` at
`core.federations.<name>.type`). An enabled entry is handled by the module that
registers its type under `federationTypes`, which builds one provider and one
redirect policy for it, both named after the entry, so a type can have any
number of entries. The Google, GitHub, Apple and OIDC packages each export such
a module — `googleFederationTypeModule()`, `githubFederationTypeModule()`,
`appleFederationTypeModule()` and `oidcFederationTypeModule()`, for the types
`"google"`, `"github"`, `"apple"` and `"oidc"`
([`@o3co/auth-provider-federation-oidc`](../federation-oidc/README.md) for
any OpenID Connect IdP); each package's README lists its type's keys. A
disabled entry is not read past core's schema.

Boot rules:

- Core requires a non-empty `callbackURL` on every entry it dispatches to a
  type, or boot is refused (`config-validation-failed` at
  `core.federations.<name>.callbackURL`). The federation router hands exactly
  that value to the adapter as `redirect_uri`.
- `trustUpstreamAmr` is read only at an entry's top level, beside `enabled`; it
  is `false` when absent, and core's schema refuses anything but a boolean
  (after coercing the spellings an environment variable delivers). A
  `trustUpstreamAmr` nested under another key
  (`core.federations.okta.oidc.trustUpstreamAmr`) is not read. No environment
  variable is wired for it. What it decides is
  [above](#what-a-session-records-about-the-authentication).
- A federation's provider and redirect policy come together from the module
  registering its `type` under `federationTypes`: one of each per enabled entry,
  named after it. Modules cannot contribute or override `federations` or
  `federationRedirectPolicies`; either is refused at boot
  (`contribution-kind-guarded`).
- `sessionModule` does not cross-check config against the registered
  federations; core's boot does: an enabled entry whose `type` no installed
  module registers refuses boot (`federation-type-unhandled`). A disabled entry
  registers no federation, so its start answers `404`.

### Redirect allowlists

`GET /session/oauth/federation/:name?redirect_to=…` and `POST /session/login`'s
`redirect_to` name where the browser goes afterwards. Every value either may name
has to be listed: `core.federations.<name>.redirectAllowlist` for a federation (read
by its redirect policy), `session.redirectAllowlist` for the login.

```hocon
core.federations {
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
  entry must be inside `sessionDomain` (federation) or `session-store.domain` (login),
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
is the replacement point: a federation type's `redirectPolicy` builds the
policy for each of its entries, and a policy other than the default must fail
closed. A deployment that customises a federation's redirect policy overrides
its type (`overrides.federationTypes.<type>`). `createFederationRedirectPolicy`
is the default; `checkRedirectShape`, `createRedirectAllowlistValidator`,
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
a `type = "oidc"` entry of
[`@o3co/auth-provider-federation-oidc`](../federation-oidc/README.md) is the
adapter. Otherwise an adapter is a module that registers a type under
`federationTypes`: the schema of an entry's own keys, flat, and the two
factories core calls for each enabled entry of the type, with the entry's name,
its `callbackURL` and the keys the schema answered. Core removes the keys it
owns (`enabled`, `type`, `trustUpstreamAmr`, `callbackURL`) before the schema
reads the entry:

```ts
import { defineFederationType, defineModule } from "@o3co/auth-provider-core";
import { createFederationRedirectPolicy } from "@o3co/auth-provider-session";
import { z } from "zod";

const exampleEntrySchema = z.strictObject({
  clientId: z.string().min(1),
  clientSecret: z.string().min(1),
  clientUrl: z.string().optional(),
  redirectAllowlist: z.array(z.string()).optional(),
  authCallbackUrl: z.string().optional(),
  sessionDomain: z.string().optional(),
});

export const exampleFederationTypeModule = defineModule({
  name: "federation-example-type",
  contributes: {
    federationTypes: {
      example: defineFederationType()({
        entrySchema: exampleEntrySchema,
        factory: (_deps, { name, callbackURL, entry }) =>
          createExampleProvider(name, { ...entry, callbackURL }),
        redirectPolicy: (_deps, { entry }) => createFederationRedirectPolicy(entry),
      }),
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
| [`src/__tests__/sessionStoreModule.test.mts`](src/__tests__/sessionStoreModule.test.mts) | the middleware route at `/`, the cookie it sets and that it is the provider's policy, each cookie refused at validation through `createApp` and by the route itself before the store opens, the cookies that still mount, and the replica-safety declaration and refusal |
| [`src/store/__tests__/factory.test.mts`](src/store/__tests__/factory.test.mts) | the two built-in stores, the `session-store` readiness probe, and the Redis client's error listener |
| [`src/__tests__/cookieSessionStore.test.mts`](src/__tests__/cookieSessionStore.test.mts) | the cookie-session store failing under the real express-session and connect-redis: the middleware's `503` and its one line, and a route's outage answered once with the session not written again; the cookie of a session destroyed during the request expired once with the attributes express-session set it with, by a route or by `POST /session/logout`, and left as it is for a destroy the store fails, a regenerated session and a destroy after the answer |
| [`src/__tests__/csrf.test.mts`](src/__tests__/csrf.test.mts) | the signed token, its expiry bound, the signer refused when built and read as refusing unless `verify` answers `true`, the origin check and the guard's acceptance rule |
| [`src/__tests__/csrfTokenSigner.test.mts`](src/__tests__/csrfTokenSigner.test.mts) | the session store's `csrfTokenSigner`: core's contract, the fixed vectors, the entropy floor, a token signed under `session-store.secret` passing `/session/*` and the `csrfGuard` slot, and an override replacing it; `sessionModule` and a hand-built router refused without a signer, signing through the slot's, its tokens passing between the slot and `/session/*`, and reading no `session-store.secret` on any route |
| [`src/__tests__/csrfGuard.test.mts`](src/__tests__/csrfGuard.test.mts), [`loginEntry.test.mts`](src/__tests__/loginEntry.test.mts), [`loginCompletion.test.mts`](src/__tests__/loginCompletion.test.mts), [`sessionCookiePolicy.test.mts`](src/__tests__/sessionCookiePolicy.test.mts) | what the modules provide other packages: each keeps core's contract, the modules provide it, the guard answers and logs as `/session/login`'s does and accepts the tokens `GET /session/csrf` hands out, the login entry is built without a page and fails where it is read, the cookie policy refuses whatever would break the contract, over every combination of the cookie's attributes, and a name or domain it refuses is refused at validation with its message; an override of the policy beside the store's module refuses boot, and a composition without the module fills the slot |
| [`src/__tests__/establish-session.test.mts`](src/__tests__/establish-session.test.mts) | the login tail: what it writes (the establishment's primary alone, and a forged establishment refused), its sequence, what it hands each write, and the rollback at every point it can fail |
| [`src/__tests__/renewSession.test.mts`](src/__tests__/renewSession.test.mts) | the session renewal over express-session's `MemoryStore`: the signed-in state and a fresh nonce alone on the new id, the old id destroyed, a failed `regenerate` or `save` answered as the cookie session's outage with nothing written; and the race — a request in flight on the old id puts it back after the renewal, and core's admission refuses it once the escalation carries the nonce |
| [`src/routes/__tests__/Session.test.mts`](src/routes/__tests__/Session.test.mts), [`loginAttempts.test.mts`](src/routes/__tests__/loginAttempts.test.mts) | login, what logout invalidates, the logout answering `503` and keeping the cookie session when the `UserSession` record cannot be read, the outage answers and their one log line, and the login's attempt limit |
| [`src/routes/__tests__/Session.loginAdmission.test.mts`](src/routes/__tests__/Session.loginAdmission.test.mts) | the password login on session admission: what a requirement is asked, each outcome's answer, the interruption's two phases and the answer to each failure after the regeneration; `answerInterruption` on its own — its answer, its reporter and outcome at each failure, and what it refuses |
| [`src/routes/__tests__/Federation.test.mts`](src/routes/__tests__/Federation.test.mts) | the start and callback legs, account linking, the store writes and their rollback, the outage answers and their log lines, `amr` |
| [`src/routes/__tests__/Federation.linkAdmission.test.mts`](src/routes/__tests__/Federation.linkAdmission.test.mts) | the link start and callback on session admission: each outcome's answer, the subject recorded beside the `sid`, what a requirement is asked, the pre-upgrade transaction |
| [`src/routes/__tests__/Federation.loginEstablishment.test.mts`](src/routes/__tests__/Federation.loginEstablishment.test.mts) | the callback's login established without asking: a requirement that would interrupt a password login does not interrupt it, the record is what core composes, the `User` is read once, and a user the snapshot refuses is refused with nothing written |
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
