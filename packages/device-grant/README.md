# @o3co/auth-provider-device-grant

OAuth 2.0 Device Authorization Grant ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)) for [`auth.provider`](https://github.com/o3co/auth.provider) — the device-code flow for input-constrained clients: TV apps, CLIs, IoT.

Optional. Nothing here is active until `oauth.deviceAuthorization.enabled = true`.

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
import { deviceGrantModule } from "@o3co/auth-provider-device-grant";
import { memoryDeviceCodeStoreModule } from "@o3co/auth-provider-core";
import { oauthModule } from "@o3co/auth-provider-oauth";
import { sessionModule } from "@o3co/auth-provider-session";

const app = await createApp({
  // `sessionModule` is what puts the end user on `req.session`, and its
  // `session.*` config is what the verification route's CSRF guard is built
  // from — see "JSON only, behind the session CSRF guard" below.
  // `memoryDeviceCodeStoreModule` is dev-only; a scaled deployment wires
  // `redisDeviceCodeStoreModule` from `@o3co/auth-provider-redis` instead — see "Storage".
  modules: [oauthModule, sessionModule, deviceGrantModule, memoryDeviceCodeStoreModule],
  bootstrapComponents: { config, clientRepository, keyStore, rateLimiter },
});
```

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

Errors: `401 login_required`, `403 access_denied` (CSRF), `404 invalid_user_code`, `409 already_decided`, `410 expired_token`, `429 slow_down`.

**JSON only, behind the session CSRF guard.** The endpoint authorises on the end-user session cookie — the one credential a browser attaches to a request some other site made, which is all RFC 8628 §5.4's remote-phishing attack needs: obtain a `user_code` as any public client, auto-submit `action=approve&user_code=…` from the victim's browser, collect the victim's token. So the route accepts `application/json` only (a form body is a "simple" request sent cross-site without a preflight; JSON is not), and runs the same `createCsrfGuard` as `POST /session/login` (#272):

- a foreign `Origin` / `Referer` is refused with `403 access_denied` and logged as `csrf_origin_rejected`;
- the provider's own origin, or one listed in `session.csrf.trustedOrigins`, is accepted — a verification page served from another origin is declared there, on the same list the login form uses;
- a request with no origin signal at all (a non-browser client) must present the signed double-submit token from `GET /session/csrf`: the `<session.name>.csrf` cookie echoed in the `x-csrf-token` header.

The guard is built from the `session.*` config slice, so enabling the grant without one fails at boot. This is why the package depends on `@o3co/auth-provider-session`: one CSRF policy for the product, not a second origin check that can drift from it.

**One endpoint, three actions**, because all three take a `user_code` and **all three are the same brute-force oracle** — a `lookup` route that answered "which client is this?" without counting against the same budget would be a free oracle sitting beside a limited one. One route means one limiter call, and no way to add a fourth entry point that forgets it.

The code is accepted as displayed (`BCDF-GHJK`), lower-cased, or unseparated. A character *outside* the alphabet is rejected rather than stripped: a `0` typed for an `O` is a mistake, and silently removing it would turn an 8-character mistake into a 7-character lookup that fails invisibly — or matches a different code.

## Rate limiting is half the security argument, not a nicety

**Enabling this grant requires a `rateLimiter` component.** Boot fails without one.

RFC 8628 §5.1 sizes the user code's entropy *against* a rate limit: an 8-character base-20 code has "roughly 34.5 bits of entropy", which the RFC calls sufficient only where "the rate-limiting interval and validity period would need to only allow 5 attempts". The entropy and the limit are two halves of one mitigation. A deployment without a limiter is not running a slower version of a limited one — it is running 34.5 bits against an unbounded attacker, which is why this is a refusal rather than a degraded mode.

Every attempt counts, malformed codes included: excluding them would hand an attacker an unmetered way to probe which shapes the endpoint accepts. The key is `device_verification:user:<subject>` — keyed on the **authenticated user**, not the code. Keying on the code would spend whichever code the attacker happened to hit, which is nobody's budget; keying on the subject means an attacker needs an account and burns their own.

The budget is `oauth.deviceAuthorization.rateLimit { limit, windowSeconds }`, default `5` / `300`. Both bundled limiter adapters seed their `limits.device_verification` from it — the same way `login` is seeded from `rateLimit.login` — so the number the boot refusal reasons from is the number the limiter applies. Without the seed, the prefix fell through to the adapter's 60-per-minute default: twelve times the budget, silently. An operator-declared `memoryRateLimiter.limits.device_verification` (or the Redis equivalent) still wins; zero and fractional values are refused at the config boundary.

`POST /oauth/device_authorization` is throttled as well, under `device_authorization:ip:<ip>` — the same `createRateLimitGuard` and key shape as `/oauth/token`, mounted **ahead of client authentication** so unauthenticated repeats are bounded before they reach a repository lookup. It uses the adapter's `defaultLimit` unless `memoryRateLimiter.limits.device_authorization` (or the Redis equivalent) declares one, and it honours the product's `rateLimit.failMode` outage policy.

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

- **`memoryDeviceCodeStoreModule`** (`@o3co/auth-provider-core`) — in-process; development and single-replica only. It is registered in core's replica-unsafe module list, so a composition with `deployment.mode = "multi"` **refuses to boot** with it: pending authorizations fork per replica, and the human approves a code on the replica that served the verification page while the device polls one that has never heard of it. The store is bounded three ways: every read path drops an expired record it finds, `create` sweeps expired records every 1000 calls, and `maxEntries` (default 10 000) caps the resident set — at the cap, expired records are pruned first and then the live record closest to expiry is evicted. Its `dispose` is registered with the boot planner's lifecycle registrar.
- **`redisDeviceCodeStoreModule`** (`@o3co/auth-provider-redis`, #433) — what a scaled deployment runs. It requires the `deviceCodeStoreClient` slot, which `makeIoredisClients` provides off the shared connection, and is configured under `redisDeviceCodeStore.keyPrefix` (default `devauth:`). Every operation the port marks atomic is one Lua script, so the conformance suite's "two polls racing for one approval" case passes against a real Redis rather than only in sequence. With it wired, `deployment.mode = "multi"` boots.

Two things about the Redis adapter are worth knowing before choosing it:

- **Every device authorization shares one Redis Cluster slot.** The record is keyed by `device_code` and the `user_code → device_code` index by `user_code`; both are independent random values, and a script that follows the index to the record has to find both keys in the slot it was routed to. So both live under one constant hash tag — `devauth:{devauth}:code:<device_code>` and `devauth:{devauth}:user:<user_code>` — which concentrates the flow on a single slot. For a human-initiated ceremony that is an acceptable trade; this is not per-request traffic. The alternative, storing the record twice under each key, would make `approve`/`poll` non-atomic across the pair, which is what the port forbids.
- **The TTL is not the expiry.** Both keys carry the authorization's `expiresAtMs` as their TTL so Redis reclaims them without a sweep, but `poll` answers `expired` from the timestamp: a record still inside its TTL whose deadline has passed on the caller's clock expires, and is dropped.

The standalone template provides `deviceCodeStoreClient` from its shared ioredis connection but does not mount this grant; a deployment that adds `deviceGrantModule` to that manifest selects `redisDeviceCodeStoreModule` alongside it.

Mounting the module without any store fails boot naming `oauth.deviceAuthorization.store`, which accepts `"unsupported"` as an explicit statement that this deployment knowingly cannot authorize devices (#363).

## License

Apache-2.0
