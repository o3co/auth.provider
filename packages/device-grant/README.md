# @o3co/auth-provider-device-grant

Last updated: 2026-09-24

OAuth 2.0 Device Authorization Grant ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)) for [`auth.provider`](https://github.com/o3co/auth.provider) — the device-code flow for input-constrained clients: TV apps, CLIs, IoT.

Optional, and off until `oauth.deviceAuthorization.enabled = true`: installed but disabled, it registers no grant — `/oauth/token` answers `unsupported_grant_type` for the device-code grant, and the discovery document names neither the grant nor the endpoint — and its two routes answer `404 not_found`.

## Responsibility

**Role.** An optional grant on top of the authorization server. It adds the two endpoints of the RFC 8628 ceremony — where a device starts and where a person answers — and the `urn:ietf:params:oauth:grant-type:device_code` grant, which `deviceGrantModule({ config })` contributes to core's grant registry when the grant is enabled, so that [`@o3co/auth-provider-oauth`](../oauth/README.md)'s `POST /oauth/token` dispatches it.

**Owns:**

- `POST /oauth/device_authorization`: client authentication, the per-IP throttle, and issuing the device and user codes;
- `POST /oauth/device/verification`: the JSON API a deployment's verification page calls, behind the session CSRF guard and the per-subject verification budget;
- the device-code grant: polling semantics, single use, and the binding to the client the code was issued to;
- `device_authorization_endpoint` in the discovery document, and the boot refusals for an enabled grant that is missing what it needs.

**Does not own:**

- the verification page — the deployment's ([below](#the-library-provides-the-api-the-deployment-provides-the-page));
- the `DeviceCodeStore` port, the code generators and the memory adapter — `@o3co/auth-provider-core`; the Redis adapter — `@o3co/auth-provider-redis` ([Storage](#storage));
- `/oauth/token` and client authentication — `@o3co/auth-provider-oauth`;
- the browser session, login and the CSRF policy — `@o3co/auth-provider-session`;
- the rate limiter and the seeding of its budget — core's and Redis's limiter modules.

**Why a separate package, and why it depends on two siblings.** Most deployments authorize no devices, so the grant and its routes are a package a deployment adds rather than a part of every token endpoint; the store port sits in core so that a store adapter depends on core and never on this package. The package itself sits on top of two sibling packages, and takes one piece from each so that there is one implementation rather than two that can drift:

- from `@o3co/auth-provider-oauth`, `createClientAuthMiddleware` — `/oauth/device_authorization` authenticates a client exactly as `/oauth/token` does, `private_key_jwt` and its `replaySeenSet` included;
- from `@o3co/auth-provider-session`, the CSRF guard (`createCsrfGuard`, `createCsrfProtectionFromConfig`) — the verification endpoint runs the policy `POST /session/login` runs ([below](#post-oauthdeviceverification)).

Neither sibling imports this package. Both are peer dependencies, installed whether or not the composition mounts their modules.

## The flow

```text
  device                     authorization server                 human
    │                                                               │
    ├── POST /oauth/device_authorization ──────►                    │
    │◄── device_code, user_code, verification_uri, interval ────    │
    │                                                               │
    │    "go to example.com/device and enter BCDF-GHJK" ────────────►
    │                                                               │
    │                    ◄── POST /oauth/device/verification ───────┤
    │                        { action: "lookup",  user_code }       │
    │                        { action: "approve", user_code }       │
    │                                                               │
    ├── POST /oauth/token ─────────────────────►                    │
    │    grant_type=…:device_code&device_code=…                     │
    │◄── authorization_pending / slow_down / access_denied …        │
    │◄── access_token (once approved)                               │
```

## Quick start

```hocon
oauth.deviceAuthorization {
  enabled = true
  verification-uri = "https://example.com/device"

  # The verification budget — RFC 8628 §5.1's "5 attempts". These are the
  # defaults; see "Rate limiting is half the security argument" below.
  rateLimit { limit = 5, windowSeconds = 300 }
}
```

```ts
import {
  createApp,
  jwksModule,
  memoryDeviceCodeStoreModule,
  memoryRateLimiterModule,
} from "@o3co/auth-provider-core";
import { deviceGrantModule } from "@o3co/auth-provider-device-grant";
import { oauthModule } from "@o3co/auth-provider-oauth";
import { sessionModule, sessionStoreModuleFor } from "@o3co/auth-provider-session";

const handle = await createApp({
  modules: [
    // First: mounts express-session, which is what creates `req.session`. It has
    // no ordering edge of its own, so it must be listed ahead of every module
    // that reads the session — without it the verification route answers every
    // request `401 login_required`.
    sessionStoreModuleFor(config),
    // Built from the config createApp boots with. Ahead of oauthModule so that
    // its 16 KiB limit also bounds a chunked body: see "Listing it beside oauthModule".
    deviceGrantModule({ config }),
    oauthModule({ config }), // POST /oauth/token, where the device polls
    // oauthModule serves the discovery document that advertises
    // `device_authorization_endpoint`, and that document requires `jwks_uri`.
    jwksModule,
    // Signs the user in: `POST /session/login` (or the federation callback) puts
    // the authenticated user on the session the verification route reads. A
    // deployment with its own login writes `isAuthenticated` and `user.id` itself.
    sessionModule,
    // Dev-only; a scaled deployment wires `redisDeviceCodeStoreModule` from
    // `@o3co/auth-provider-redis` instead — see "Storage".
    memoryDeviceCodeStoreModule,
    // Required once the grant is enabled; seeded with the verification budget above.
    memoryRateLimiterModule,
    // …the modules that provide what these require: clientRepository,
    // codeRepository, keyStore, the user repository, the session and
    // federation-token stores, and an access-token denylist (or its declared
    // absence) …
  ],
  bootstrapComponents: { config, pathResolver: import.meta.resolve },
});
```

The verification route's CSRF guard is built from the `session.*` config slice — see [JSON only, behind the session CSRF guard](#post-oauthdeviceverification). [`composition.test.mts`](./src/__tests__/composition.test.mts) boots this composition through `createApp`, with the repositories stubbed and the rest real. The standalone template's [`buildModules.mts`](../../templates/standalone/src/buildModules.mts) shows the full order of a real composition root; it does not mount this grant.

### Listing it beside `oauthModule`

`oauthModule` mounts its router at `/oauth`, and that router parses JSON and form bodies — with Express's default 100 KiB limit — for every request under `/oauth`, whichever route it is for. Routes mount in the order their modules are listed (this module declares no ordering edge), so with `oauthModule` listed first the device routes receive bodies that router has already parsed, and a body is not parsed twice. Neither rule this package keeps about a body depends on that:

- **What the verification route accepts.** The handler checks the media type itself and answers anything but `application/json` with `415 invalid_request` ([below](#post-oauthdeviceverification)).
- **The 16 KiB body limit.** Both routes check a declared `Content-Length` ahead of any parser and answer a larger body `413 invalid_request` (`body_too_large`); exactly 16 KiB is accepted, as the parsers accept it. This is the check federation grants use for the same bound.

One case is still decided by the order: a body sent without a `Content-Length` (chunked) has no size to check up front, so it is bounded by whichever parser reads it first — this package's 16 KiB when it is listed first, `oauthModule`'s 100 KiB when that router is. So list `deviceGrantModule({ config })` ahead of `oauthModule({ config })`. Nothing else in the device routes depends on the order: `/oauth/device_authorization` carries its own body parsers and client authentication, and the grant reaches `/oauth/token` through the grant registry, not through mount order.

## Public API

Exported from [`src/index.mts`](./src/index.mts); the linked file holds each definition:

- `deviceGrantModule`, `deviceGrantConfigSchema` — [`module.mts`](./src/module.mts). The module factory to install — `deviceGrantModule({ config })`, given the config the composition root boots with; a boot whose config disagrees with it about `oauth.deviceAuthorization.enabled` is refused — and the `oauth.deviceAuthorization` schema it composes.
- `createDeviceAuthorizationHandler`, `DeviceAuthorizationEndpointOptions` — [`deviceAuthorizationEndpoint.mts`](./src/deviceAuthorizationEndpoint.mts); `createDeviceVerificationHandler`, `DeviceVerificationHandlerOptions` — [`verificationEndpoint.mts`](./src/verificationEndpoint.mts); `createDeviceCodeGrant`, `DeviceCodeGrantOptions` — [`grant.mts`](./src/grant.mts). The two handlers and the grant, for a composition root that mounts them itself; it then owns what the module otherwise applies around them — client authentication, the throttle, the CSRF guard and the body parsers. The verification handler's `415` for a body that is not `application/json` is the handler's own and comes with it.
- `DEVICE_CODE_GRANT_TYPE`, `DEVICE_AUTHORIZATION_RATE_LIMIT_PREFIX`, `DEVICE_VERIFICATION_RATE_LIMIT_PREFIX`, `DeviceAuthorizationSettings`, `DeviceGrantDependencies` — [`types.mts`](./src/types.mts) (`DEVICE_VERIFICATION_RATE_LIMIT_PREFIX` is defined in core and re-exported there).

The `DeviceCodeStore` port and the code generators are not exported here; they are core's ([Storage](#storage)).

## The library provides the API, the deployment provides the page

There is no HTML in this package, and `verification-uri` is configuration rather than a route it mounts.

That is the boundary `/authorize` already draws — it redirects to a deployment-configured login URL rather than rendering a login form — and drawing it differently for this one ceremony would mean the library ships a page for one and not the other. What it does ship is the JSON API that page calls.

### `POST /oauth/device/verification`

Requires an authenticated end-user session. Body: `{ action, user_code }`.

| action | 200 response | notes |
| --- | --- | --- |
| `lookup` | `{ client_id, scope, expires_at }` | What to show the user before they commit |
| `approve` | `{ status: "approved", client_id }` | |
| `deny` | `{ status: "denied", client_id }` | |

Errors: `401 login_required`, `403 access_denied` (CSRF), `404 invalid_user_code`, `409 already_decided`, `410 expired_token`, `413 invalid_request` (`body_too_large`: a declared body over 16 KiB), `415 invalid_request` (a body that is not `application/json`), `429 slow_down`, `503 service_unavailable` (the limiter backend is down and `rateLimit.failMode = "closed"`).

**JSON only, behind the session CSRF guard.** The endpoint authorises on the end-user session cookie — the one credential a browser attaches to a request some other site made, which is all RFC 8628 §5.4's remote-phishing attack needs: obtain a `user_code` as any public client, auto-submit `action=approve&user_code=…` from the victim's browser, collect the victim's token. So the endpoint accepts `application/json` only (a form body is a "simple" request sent cross-site without a preflight; JSON is not): any other media type is `415 invalid_request`. The handler checks the media type itself rather than relying on no form parser having run, so the rule holds whichever module is listed first — `oauthModule`'s router parses form bodies for everything under `/oauth` ([Listing it beside `oauthModule`](#listing-it-beside-oauthmodule)). And the route runs the same `createCsrfGuard` as `POST /session/login`:

- a foreign `Origin` / `Referer` is refused with `403 access_denied` and logged as `csrf_origin_rejected`;
- the provider's own origin, or one listed in `session.csrf.trustedOrigins`, is accepted — a verification page served from another origin is declared there, on the same list the login form uses;
- a request with no origin signal at all (a non-browser client) must present the signed double-submit token from `GET /session/csrf`: the `<session.name>.csrf` cookie echoed in the `x-csrf-token` header.

The guard is built from the `session.*` config slice, so enabling the grant without one fails at boot. This is why the package depends on `@o3co/auth-provider-session`: one CSRF policy for the product, not a second origin check that can drift from it.

The route reads the end user from the express-session (`isAuthenticated`, `user.id`), so `sessionStoreModule` must be mounted ahead of it and something must sign the user in; with no authenticated session every action is `401 login_required`.

**One endpoint, three actions**, because all three take a `user_code` and **all three are the same brute-force oracle** — a `lookup` route that answered "which client is this?" without counting against the same budget would be a free oracle sitting beside a limited one. One route means one limiter call, and no way to add a fourth entry point that forgets it.

The code is accepted as displayed (`BCDF-GHJK`), lower-cased, or unseparated. A character *outside* the alphabet is rejected rather than stripped: a `0` typed for an `O` is a mistake, and silently removing it would turn an 8-character mistake into a 7-character lookup that fails invisibly — or matches a different code.

## Rate limiting is half the security argument, not a nicety

**Enabling this grant requires a `rateLimiter` component and the product's `rateLimit.failMode`.** Boot fails without either.

RFC 8628 §5.1 sizes the user code's entropy *against* a rate limit: an 8-character base-20 code has "roughly 34.5 bits of entropy", which the RFC calls sufficient only where "the rate-limiting interval and validity period would need to only allow 5 attempts". The entropy and the limit are two halves of one mitigation. A deployment without a limiter is not running a slower version of a limited one — it is running 34.5 bits against an unbounded attacker, which is why this is a refusal rather than a degraded mode.

Every attempt counts, malformed codes included: excluding them would hand an attacker an unmetered way to probe which shapes the endpoint accepts. The key is `device_verification:user:<subject>` — keyed on the **authenticated user**, not the code. Keying on the code would spend whichever code the attacker happened to hit, which is nobody's budget; keying on the subject means an attacker needs an account and burns their own.

The budget is `oauth.deviceAuthorization.rateLimit { limit, windowSeconds }`, default `5` / `300`. Both bundled limiter adapters seed their `limits.device_verification` from it — the same way `login` is seeded from `rateLimit.login` — so the number the boot refusal reasons from is the number the limiter applies. Without the seed, the prefix would fall through to the adapter's 60-per-minute default: twelve times the budget, silently. An operator-declared `memoryRateLimiter.limits.device_verification` (or the Redis equivalent) still wins; zero and fractional values are refused at the config boundary.

The seed is deliberately quiet: handed a config with no usable budget it leaves the adapter's default in place rather than invent one. So the module asks for the budget itself — **enabling the grant with no valid `oauth.deviceAuthorization.rateLimit` fails boot**, naming the key. A config that went through `createApp` always has one, because the schema defaults it; the refusal is for hand-built configs that never passed the schema, where the seed's silence would otherwise mean a limiter arguing from five attempts while applying sixty. Both the seed and the refusal read one definition of "usable", `isDeviceVerificationRateLimitSpec` in core, so they cannot disagree about a value.

`POST /oauth/device_authorization` is throttled as well, under `device_authorization:ip:<ip>` — the same `createRateLimitGuard` and key shape as `/oauth/token`, mounted **ahead of client authentication** so unauthenticated repeats are bounded before they reach a repository lookup. It uses the adapter's `defaultLimit` unless `memoryRateLimiter.limits.device_authorization` (or the Redis equivalent) declares one, and it honours the product's `rateLimit.failMode` outage policy.

### A limiter outage is the product's outage policy on both routes

`POST /oauth/device/verification` honours the same `rateLimit.failMode`. Its budget is keyed on the subject and its 429 is its own audit event, so it cannot sit behind the guard as a middleware; it runs the guard's check through core's `checkWithFailMode` instead, which is the guard minus the HTTP framing. When the limiter backend is down, `failMode = "closed"` answers `503 service_unavailable` "Rate limiter temporarily unavailable" — the body every guarded route answers — and `"open"` serves the lookup, approval or denial as if allowed. Either way the outage is logged as `rate_limiter_failed_closed` / `rate_limiter_failed_open` with `tag: "device_verification"` and emitted as a `rate_limit.unavailable` audit event, so the alert the operator runbook pages on fires for this endpoint too.

A limiter that *answers* "no" is not an outage. `429 slow_down` and the `device.rate_limited` audit event are the same under either mode — `"open"` waves through a request the limiter could not judge, never one it refused. A hand-mounted `createDeviceVerificationHandler` takes `failMode` alongside `rateLimiter`; the module reads both from the composition, and enabling the grant with no `rateLimit.failMode` fails boot for this route as it does for `device_authorization`.

## The decision is an audit event

`approve` emits `device.approved`, `deny` emits `device.denied`, and a subject who exhausts the verification budget emits `device.rate_limited` — the signal that an account is being used to guess codes. Each carries the subject, the client, the scope and the request's `ip` / `userAgent`; none carries the user code (the value being brute-forced) or the device code (a bearer credential). The names are part of core's `BUILT_IN_AUDIT_EVENT_TYPES` inventory.

`auditSink` is optional to wire, not optional to decide (#363): a composition that mounts this module with no sink must write `audit.sink.type = "none"`, or boot refuses. A device approval is a consent, and a consent that vanishes with no symptom is the shape that rule exists to refuse.

## The user code (§6.1)

`BCDFGHJKLMNPQRSTVWXZ` — the consonants. Two properties, neither arbitrary:

- **No vowels**, so no arrangement can spell a word. A code that reads as an obscenity gets screenshotted rather than typed.
- **No digits**, so `0`/`O`, `1`/`I`/`l`, `5`/`S`, `8`/`B` and `2`/`Z` cannot arise.

Codes are drawn with `randomInt`, not `randomBytes() % 20`: 256 is not a multiple of 20, so the modulo would bias toward the first 16 characters and quietly cost about a bit of the 34.5 the rate-limit budget is computed from.

`device_code` is the opposite problem — nobody types it — so it is 256 bits of base64url, per §5.2's "a very high entropy code SHOULD be used".

## `verification_uri_complete` is off by default

RFC 8628 §3.3.1 defines a URI with the code embedded, so a QR code can carry it. §5.4: with it "it is particularly important to confirm that the device is in the user's possession, as the user no longer has to type in the code".

The typing **is** the proof of proximity. Removing it without replacing that confirmation is what makes remote phishing work, so `verification-uri-complete` defaults to `false`. Turn it on only if the verification page displays the code and asks the user to confirm the device is showing the same one.

## Polling

The store enforces the interval, not the handler: the check and the state change have to be one operation, and a handler that read the record, compared timestamps and wrote back would let two concurrent polls both pass the gate.

`slow_down` widens the interval **the server measures against**, by 5 seconds each time. §3.5 addresses that increase to the client, but a server that says `slow_down` while continuing to measure against the original interval is asking for a change it does not itself observe — a compliant client would then be told to slow down forever.

The four error codes are kept distinct because a client library's whole control flow is built on telling them apart:

| code | client behaviour |
| --- | --- |
| `authorization_pending` | keep polling |
| `slow_down` | keep polling, more slowly |
| `access_denied` | stop — the user said no |
| `expired_token` | stop — the window closed |

Collapsing any pair into `invalid_grant` turns a client that would have shown "you denied this on your phone" into one that retries forever.

## Single use, and bound to one client

`DeviceCodeStore.poll` reads the status **and consumes an approved authorization in the same operation**. A `find`-then-`delete` implementation passes a naive unit test and issues two access tokens from one human approval under concurrency; the shared conformance suite in core has a test that races two polls for exactly this reason.

A device code is redeemable only by the client it was issued to, checked against the authenticated client identity rather than the request body. Without that, a leaked device code is redeemable by any other registered client — converting a leak into a full impersonation of the user's approval.

A client must also be **allowed the grant before it can start it**: `POST /oauth/device_authorization` answers `400 unauthorized_client` unless the client's `allowedGrantTypes` names `urn:ietf:params:oauth:grant-type:device_code` — deny by absence, as the token endpoint does for this grant (#326). Otherwise a client registered for nothing but `authorization_code` could still open a pending authorization and put a real-looking prompt in front of a user for a grant that can never complete.

## Storage

The `DeviceCodeStore` port lives in `@o3co/auth-provider-core`, not here, so an adapter author depends on core alone. Two adapters ship, and which one is wired decides whether the deployment can scale:

- **`memoryDeviceCodeStoreModule`** (`@o3co/auth-provider-core`) — in-process; development and single-replica only. It is registered in core's replica-unsafe module list, so a composition with `deployment.mode = "multi"` **refuses to boot** with it: pending authorizations fork per replica, and the human approves a code on the replica that served the verification page while the device polls one that has never heard of it. The store is bounded three ways: every read path drops an expired record it finds, `create` sweeps expired records every 1000 calls, and `maxEntries` (default 10 000) caps the resident set — at the cap, expired records are reclaimed first, and if every resident record is still live **`create` refuses** with `DeviceCodeStoreError { reason: "full" }` rather than evicting one. The endpoint answers that refusal with `503 temporarily_unavailable` — RFC 6749 §5.2's "temporary overloading" — without re-drawing a code, and logs `device_authorization_store_full`. Its `dispose` is registered with the boot planner's lifecycle registrar.
- **`redisDeviceCodeStoreModule`** (`@o3co/auth-provider-redis`) — what a scaled deployment runs. It requires the `deviceCodeStoreClient` slot, which `makeIoredisClients` provides off the shared connection, and is configured under `redisDeviceCodeStore.keyPrefix` (default `devauth:`). Every operation the port marks atomic is one Lua script, so the conformance suite's "two polls racing for one approval" case passes against a real Redis rather than only in sequence. With it wired, `deployment.mode = "multi"` boots.

Refusing at the cap is the fail-closed choice. Evicting the live record closest to expiry would not be: the flood that reaches the cap carries the newest expiries, so the records closest to expiry are exactly the pre-existing ones — a human's pending approval, an approval a device has not polled for yet — and all of them would go before any of the attacker's. The sibling caps in core evict because what they hold is reconstructible (a rate-limit bucket resets, a CRL cache entry refetches); a device authorization is not, so the store keeps what was issued and refuses what is new. The refused request is a `POST /oauth/device_authorization`, which sits behind the per-IP rate-limit guard, so the flooder is the one told to retry, and a legitimate device retries into a slot the next expiry frees. Evicting same-`clientId` records first was considered and rejected: device clients are public (RFC 8628 §5.6), so a flood arrives *as* the legitimate client and that policy would evict its real users first all the same.

Two things about the Redis adapter are worth knowing before choosing it:

- **Every device authorization shares one Redis Cluster slot.** The record is keyed by `device_code` and the `user_code → device_code` index by `user_code`; both are independent random values, and a script that follows the index to the record has to find both keys in the slot it was routed to. So both live under one constant hash tag — `devauth:{devauth}:code:<device_code>` and `devauth:{devauth}:user:<user_code>` — which concentrates the flow on a single slot. For a human-initiated ceremony that is an acceptable trade; this is not per-request traffic. The alternative, storing the record twice under each key, would make `approve`/`poll` non-atomic across the pair, which is what the port forbids.
- **The TTL is not the expiry.** Both keys carry the authorization's `expiresAtMs` as their TTL so Redis reclaims them without a sweep, but `poll` answers `expired` from the timestamp: a record still inside its TTL whose deadline has passed on the caller's clock expires, and is dropped.

The standalone template provides `deviceCodeStoreClient` from its shared ioredis connection but does not mount this grant; a deployment that adds `deviceGrantModule({ config })` to that manifest selects `redisDeviceCodeStoreModule` alongside it.

Mounting the module without any store fails boot naming `oauth.deviceAuthorization.store`, which accepts `"unsupported"` as an explicit statement that this deployment knowingly cannot authorize devices (#363) — for a deployment that leaves the grant off; with `enabled = true` the module refuses to boot without a store whatever the declaration says.

Every field of the `DeviceAuthorization` an adapter hands back is a required key: `requestedScope`, `subject` and `grantedScope` hold `undefined` where there is none, so a read-back that forgets one is a compile error rather than a dropped field; `create`'s `requestedScope` is a required key the same way ([Upgrading: store records name every field](../../docs/upgrading-required-record-keys.md)). The conformance suite compares the whole record with `toStrictEqual`, which also catches the two scope lists swapped.

## Tests

[`flow.test.mts`](./src/__tests__/flow.test.mts) runs the ceremony end to end, [`composition.test.mts`](./src/__tests__/composition.test.mts) boots the module beside `oauthModule` as the Quick start does — the discovery document, the disabled grant, and the JSON-only rule and the body limit in both mount orders — [`verificationCsrf.test.mts`](./src/__tests__/verificationCsrf.test.mts) pins the CSRF guard, [`configRateLimit.test.mts`](./src/__tests__/configRateLimit.test.mts) the verification budget, and [`module.test.mts`](./src/__tests__/module.test.mts) the boot refusals and the disabled routes. The store's atomicity is core's conformance suite, run against both adapters.

## License

Apache-2.0
