# @o3co/auth-provider-device-grant

Last updated: 2026-10-05

OAuth 2.0 Device Authorization Grant ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)) for [`auth.provider`](https://github.com/o3co/auth.provider) — the device-code flow for input-constrained clients: TV apps, CLIs, IoT.

Optional, and off until `device-grant.enabled = true` (an absent section or key is off): installed but disabled, the module registers nothing — no grant, so `/oauth/token` answers `unsupported_grant_type` for the device-code grant and the discovery document names neither the grant nor the endpoint; no route, so the host answers both paths as for an uninstalled package; and no budget, requirement or absence policy, so it asks the composition for nothing.

## Responsibility

**Role.** An optional grant on top of the authorization server. It adds the two endpoints of the RFC 8628 ceremony — where a device starts and where a person answers — and the `urn:ietf:params:oauth:grant-type:device_code` grant, which `deviceAuthorizationGrantModule` contributes to core's grant registry when the grant is enabled, so that [`@o3co/auth-provider-oauth`](../oauth/README.md)'s `POST /oauth/token` dispatches it.

**Owns:**

- `POST /oauth/device_authorization`: client authentication, the per-IP throttle, and issuing the device and user codes;
- `POST /oauth/device/verification`: the JSON API a deployment's verification page calls, behind the session CSRF guard, session admission and the per-subject attempt limit;
- the device-code grant: polling semantics, single use, and the binding to the client the code was issued to;
- `device_authorization_endpoint` in the discovery document, and the boot refusals for an enabled grant that is missing what it needs.

**Does not own:**

- the verification page — the deployment's ([below](#the-library-provides-the-api-the-deployment-provides-the-page));
- the `DeviceCodeStore` port, the code generators and the memory adapter — `@o3co/auth-provider-core`; the Redis adapter — `@o3co/auth-provider-redis` ([Storage](#storage));
- `/oauth/token` and client authentication — `@o3co/auth-provider-oauth`; the token settings it reads — the issuer client authentication is held to, the access-token lifetime it mints, `requireEmailVerified` — are the oauth module's, read through the `oauthTokenSettings` slot alone, which an enabled grant requires; the module reads no configuration but its own section ([#728](https://github.com/o3co/auth.provider/issues/728));
- the browser session, login and the CSRF policy — `@o3co/auth-provider-session`, whose session module provides the policy as the `csrfGuard` slot; whether the session behind the cookie may act — core's session admission (`admitSession`), which reads the `UserSession` store (core's port, filled by a session-store module), the subject's sessions boundary and the registered session requirements;
- counting the verification's attempts — core's attempt guard (`createAttemptGuard`) on the `attemptCounter` slot, which `redisAttemptCounterModule` from `@o3co/auth-provider-redis` fills across replicas; this module hands it the limit;
- the rate limiter — the deployment's abuse control, which throttles `/oauth/device_authorization` when one is wired;
- what a log line may carry of an error — core's `loggableError`, which both routes log their failures through.

**Why a separate package, and what it takes from its siblings.** Most deployments authorize no devices, so the grant and its routes are a package a deployment adds rather than a part of every token endpoint; the store port sits in core so that a store adapter depends on core and never on this package. It takes two pieces from sibling packages, so that there is one implementation rather than two that can drift:

- from `@o3co/auth-provider-oauth`, `createClientAuthMiddleware` — `/oauth/device_authorization` authenticates a client exactly as `/oauth/token` does, `private_key_jwt` and its `replaySeenSet` included. An import that predates [#728](https://github.com/o3co/auth.provider/issues/728)'s rule that a package imports only core, tolerated until a slot replaces it; `@o3co/auth-provider-oauth` is a peer dependency;
- from `@o3co/auth-provider-session`, the CSRF guard — the verification endpoint runs the policy `POST /session/login` runs ([below](#post-oauthdeviceverification)) — through the `csrfGuard` slot its session module provides, whose contract is core's. This package does not import the session package.

Neither sibling imports this package.

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

## Install

```sh
npm install @o3co/auth-provider-device-grant @o3co/auth-provider-core @o3co/auth-provider-oauth @o3co/auth-provider-session express
```

Peer dependencies: `@o3co/auth-provider-core`, `@o3co/auth-provider-oauth`
and `express@^5.0.0`. The package depends on `zod`.
`@o3co/auth-provider-session` is what provides the `csrfGuard` slot an
enabled grant requires; a composition that provides it otherwise does not
need it.

Its defaults ship as HOCON in [`config/reference.conf`](config/reference.conf)
(exported as `@o3co/auth-provider-device-grant/reference.conf`). Layer it
between your `application.conf` and core's `reference.conf`; the module
declares it as its section's reference, so core's `moduleReferences(modules)`
names it among the files to layer. That file holds the section's only
defaults: the schema fills none, so a configuration built by hand without it
writes every key of the section, or boot refuses naming the missing key.
`device-grant` is the module's own section: a key it does not declare refuses
boot, and no environment variable binds one.
The section's old path, `oauth.deviceAuthorization`, refuses boot
(`config-path-relocated`) naming each key's new path
(`oauth.deviceAuthorization.verification-uri` → `device-grant.verificationUri`).

## Quick start

```hocon
device-grant {
  enabled = true
  verificationUri = "https://example.com/device"

  # The verification's attempt limit — RFC 8628 §5.1's "5 attempts". These
  # are the defaults; see "The attempt limit is half the security argument".
  rateLimit { limit = 5, windowSeconds = 300 }
}
```

```ts
import {
  createApp,
  jwksModule,
  memoryDeviceCodeStoreModule,
  memoryRateLimiterModule,
  memorySessionStoresModule,
} from "@o3co/auth-provider-core";
import { deviceAuthorizationGrantModule } from "@o3co/auth-provider-device-grant";
import { oauthEndpointsModule } from "@o3co/auth-provider-oauth";
import { sessionModule, sessionStoreModule } from "@o3co/auth-provider-session";

const handle = await createApp({
  modules: [
    // First: mounts express-session, which is what creates `req.session`. It has
    // no ordering edge of its own, so it must be listed ahead of every module
    // that reads the session — without it the verification route answers every
    // request `401 login_required`.
    sessionStoreModule,
    // One module, switched by its own section, device-grant.enabled. Its place
    // in the list is free: each module under /oauth parses its own body.
    deviceAuthorizationGrantModule,
    // POST /oauth/token, where the device polls; it also provides the
    // oauthTokenSettings slot an enabled grant requires.
    oauthEndpointsModule,
    // Core's createApp serves the discovery document that advertises
    // `device_authorization_endpoint`; oauthEndpointsModule's contribution switches it
    // on (it needs an issuer), and the document requires `jwks_uri`, which
    // jwksModule contributes.
    jwksModule,
    // Signs the user in: `POST /session/login` (or the federation callback) puts
    // the authenticated user on the session the verification route reads. A
    // deployment with its own login must do all of what they do: create a
    // `UserSession` in the userSessionStore, and write `isAuthenticated`,
    // `user.id` (the record's `sub`) and that record's `sid` on the session —
    // the route answers anything less `401 login_required`. It also provides
    // the csrfGuard slot the verification route requires once the grant is on.
    sessionModule,
    // Dev-only; a scaled deployment wires `redisDeviceCodeStoreModule` from
    // `@o3co/auth-provider-redis` instead — see "Storage".
    memoryDeviceCodeStoreModule,
    // The deployment's throttle on /oauth/device_authorization. Optional: without
    // one, core.declaredAbsent lists "rateLimiter". The verification's attempt
    // limit is not the limiter's: on more than one replica it needs
    // `redisAttemptCounterModule` from `@o3co/auth-provider-redis`.
    memoryRateLimiterModule,
    // Required once the grant is enabled: the userSessionStore the verification
    // route reads the live UserSession from. Dev-only; `redisSessionStoresModule`
    // from `@o3co/auth-provider-redis` on more than one replica.
    memorySessionStoresModule,
    // …the modules that provide what these require: clientRepository,
    // codeRepository, keyStore, the user repository, the federation-token
    // store, an access-token denylist (or its declared absence), and an audit
    // sink or `core.declaredAbsent = ["auditSink"]` — boot refuses without one …
  ],
  bootstrapComponents: { config, pathResolver: import.meta.resolve },
});
```

The verification route's CSRF guard is the `csrfGuard` slot `sessionModule` provides — see [JSON only, behind the session CSRF guard](#post-oauthdeviceverification). An enabled grant needs `oauthEndpointsModule` (or another token endpoint dispatching through core's grant registry) in the same composition: when the composition fills `oauthTokenSettings` itself the module boots without one, but the device codes it hands out could never be redeemed. **An enabled grant requires the `oauthTokenSettings` slot** — the issuer client authentication holds an assertion's audience to, the access-token lifetime it mints and `oauth.requireEmailVerified` — which `oauthEndpointsModule` provides; a composition without it puts core's `OAuthTokenSettings` in `bootstrapComponents`, or boot is refused for the missing component. [`composition.test.mts`](./src/__tests__/composition.test.mts) boots this composition through `createApp`, with the repositories stubbed and the rest real. The standalone template's [`buildModules.mts`](../../templates/standalone/src/buildModules.mts) shows the full order of a real composition root; it does not mount this grant.

### Beside `oauthEndpointsModule`

Both routes live under `/oauth`, where `oauthEndpointsModule` mounts its router. That router parses the bodies of its own routes only, so each module under `/oauth` parses its own body and the order the modules are listed in does not matter. What these routes accept is decided by their own middleware:

- **The 16 KiB body limit.** A body that declares a `Content-Length` over 16 KiB is `413 invalid_request` (`body_too_large`) before any of it is read — the check federation grants use. A chunked body gets the same `413` once the route's parser has read past the bound: JSON on either route, a form on `/oauth/device_authorization`. A chunked body the route does not parse — `text/plain`, or a form sent to the verification route — is never read, so it is answered by the checks that follow (`401`, `403` or `415`), not `413`. Exactly 16 KiB is accepted.
- **A body the parser refuses, or a failure.** What the routes' own parsers refuse as the caller's mistake — only their errors; an `expose`d 4xx thrown by a store is a failure like any other, and so is an error whose `expose`, `status` or `type` throws when read — is a 4xx with no error-level log: too many form parameters is `413 invalid_request` (`body_too_large`), a charset or `Content-Encoding` it cannot decode is `415 invalid_request` (`unsupported_encoding`), and malformed JSON or a compressed body that does not decompress is `400 invalid_request` (`malformed_body`). An unexpected failure is `500 server_error` (`unexpected_error`), logged as `device_route_unexpected_error` with core's [`loggableError`](../core/README.md#logger) projection of the error, never the error itself — so never a parser's `body`, a non-Error cause, or the command arguments an ioredis reply carries. What the line carries is that projection's rule, which core's README states: among it, the name, the message as `detail` (a `SyntaxError`'s dropped but for the `position` it names, Redis's `, with args beginning with: …` cut from any other), the stack's frames without the header line that repeats the message, and the Error causes projected the same way, three deep; a thrown value that is not an `Error` is logged as `{ name: "NonError", thrown: <its typeof> }`. What a kept message may still contain is the error's own wording — for a Redis reply, its text before the arguments (`ERR unknown command 'evalsha'`) — and, from an error no rule anticipates, up to 256 characters of whatever it says. `device_authorization_code_collision` logs its store error the same way, and so do the three `…_store_unavailable` lines of a store outage (see [Storage](#storage)). All are JSON, never the host's error page — RFC 8628 §3.2 gives `/oauth/device_authorization` RFC 6749 §5.2's error response — and every exit of both routes, refusals included, carries `Cache-Control: no-store`.
- **The media type.** The verification route parses JSON only, and its handler answers anything but `application/json` with `415 invalid_request` ([below](#post-oauthdeviceverification)).
- **Where a CSRF token may come from.** A header, or a JSON body; a form carrying the token in a body field has none, so the guard refuses it.

`POST /oauth/device_authorization` checks in this order: the per-IP throttle when a rate limiter is wired (`429` — an oversized request spends an attempt like any other), the declared size (`413`), the parsers (`413`, `415` or `400`, above), client authentication (`401 invalid_client`; `503 temporarily_unavailable` when the client repository cannot answer), then the request itself. Its `scope` is read as `/oauth/token` reads one (core's `readSpaceDelimitedParameter`): a value that is not RFC 6749 §3.3's space-delimited list of scope-tokens — a tab, a quote — is `400 invalid_scope`, a repeated one or any other value that is not a string `400 invalid_request`, and spaces alone — or a JSON `null`, RFC 6749 §3.2's parameter sent without a value — are an omitted scope that draws on `defaultScopes`. The verification route's order is [below](#post-oauthdeviceverification).

## Public API

Exported from [`src/index.mts`](./src/index.mts); the linked file holds each definition:

- `deviceAuthorizationGrantModule`, `deviceGrantConfigSchema` — [`module.mts`](./src/module.mts). The module to install, listed as it is: it reads its switch, `device-grant.enabled`, from its own section as boot parses it (`section.isEnabled`; an environment variable's `"true"` is on, an absent section or key off) — and the schema of that section, `device-grant`, which fills no default.
- `createDeviceAuthorizationHandler`, `DeviceAuthorizationEndpointOptions` — [`deviceAuthorizationEndpoint.mts`](./src/deviceAuthorizationEndpoint.mts); `createDeviceVerificationHandler`, `DeviceVerificationHandlerOptions` — [`verificationEndpoint.mts`](./src/verificationEndpoint.mts); `createDeviceCodeGrant`, `DeviceCodeGrantOptions` — [`grant.mts`](./src/grant.mts); its `accessTokenExpiresIn` must be a whole number of seconds from 1 to a year — core's `isLifetimeSeconds`, the rule `oauth.accessToken.*` is held to — or construction throws a `RangeError`. `createDeviceAuthorizationHandler` holds its `settings.codeLifetimeSeconds` and `settings.pollingIntervalSeconds` to the bounds the module's schema holds `device-grant.codeLifetimeSeconds` (30–3600) and `device-grant.pollingIntervalSeconds` (1–60) to, and throws a `RangeError` when it is built with anything else. The two handlers and the grant, for a composition root that mounts them itself; it then owns what the module otherwise applies around them — client authentication, the throttle, the CSRF guard and the body parsers. The verification handler's `415` for a body that is not `application/json` is the handler's own and comes with it.
- `DEVICE_GRANT_ADMISSION_ACTIONS`, `DeviceGrantAdmissionAction` — [`admissionActions.mts`](./src/admissionActions.mts). The actions the verification handler admits, which the module registers while the grant is on; a composition root that mounts the handler itself registers them under `contributes.admissionActions`: the handler refuses to be built on a resolver that does not register all three.
- `DEVICE_CODE_GRANT_TYPE`, `DEVICE_AUTHORIZATION_RATE_LIMIT_PREFIX`, `DEVICE_VERIFICATION_ATTEMPT_TAG`, `DeviceAuthorizationSettings`, `DeviceGrantDependencies` — [`types.mts`](./src/types.mts) (`DEVICE_VERIFICATION_ATTEMPT_TAG` is defined in [`verificationAttempts.mts`](./src/verificationAttempts.mts) and re-exported there).

The `DeviceCodeStore` port and the code generators are not exported here; they are core's ([Storage](#storage)).

## The library provides the API, the deployment provides the page

There is no HTML in this package, and `verificationUri` is configuration rather than a route it mounts.

That is the boundary `/authorize` already draws — it redirects to a deployment-configured login URL rather than rendering a login form — and drawing it differently for this one ceremony would mean the library ships a page for one and not the other. What it does ship is the JSON API that page calls.

### `POST /oauth/device/verification`

Requires an authenticated end-user session that session admission admits for the action ([below](#an-approval-needs-the-live-session)). Body: `{ action, user_code }`. Each body action is admitted as `device.<action>`, graded as the module registers it: `lookup` and `deny` grant nothing (`grants_nothing`), so a user refuses a phished request without a step-up; `approve` grants a device a token (`use`).

| action | 200 response | notes |
| --- | --- | --- |
| `lookup` | `{ client_id, scope, expires_at }` | What to show the user before they commit |
| `approve` | `{ status: "approved", client_id }` | |
| `deny` | `{ status: "denied", client_id }` | |

Errors: `400 invalid_request` (`malformed_body` for JSON the parser cannot read; otherwise a missing or unknown `action`), `401 login_required` (no authenticated session — "session identifier (sid) is required" for one with no `sid` — one whose `UserSession` has ended, expired or that the subject's sessions boundary covers, or one a session requirement asks to sign in again; for `approve`, a session whose `authTime` is further ahead of this replica's clock than `DEFAULT_CLOCK_SKEW_MS` or before the epoch, warned as `auth_time_ahead_of_clock`), `403 access_denied` (CSRF; or, under `oauth.requireEmailVerified`, an `approve` from a user without a verified email), `403 step_up_required` (a session requirement asks for a step-up; `requirement` names it and `page` is where the step-up starts), `404 invalid_user_code`, `409 already_decided`, `410 expired_token`, `413 invalid_request` (`body_too_large`: a JSON body over 16 KiB), `415 invalid_request` (a body that is not `application/json`; `unsupported_encoding` for a charset or `Content-Encoding` the parser cannot decode), `429 slow_down` (the subject's attempts are spent; with `Retry-After`), `500 server_error` (`unexpected_error`, logged as `device_route_unexpected_error`), `503 service_unavailable` (the attempt counter cannot count, whatever any rate limiter's `failMode`), `503 temporarily_unavailable` (the device-code store cannot be read or written, logged as `device_verification_store_unavailable`, see [Storage](#storage); or it answered a record core's `readDeviceAuthorization` refuses, logged at error as `device_verification_record_unreadable` with the `action`, `refused` and `field` — on an `approve` or `deny` the store reported applied, also audited as `device.decision_outcome_unknown` — the decision did land, and a retry answers `409 already_decided`; or an `approve` or `deny` answer around the record that cannot be read — not an object (`refused: "outcome_not_an_object"`), or a `status` or an `already_decided`'s `current` that is not one the type declares (`refused: "outcome_malformed"`, `field`) — logged the same way and audited as `device.decision_outcome_unknown`; or session admission could not answer — "session store unavailable" for the user-session store, "session lifecycle store unavailable" for the session lifecycle store, "revocation store unavailable" for the subject's sessions boundary, "session requirement unavailable" for a session requirement (core's `describeAdmissionOutage`) — logged by admission as `session_admission_unavailable`).

**JSON only, behind the session CSRF guard.** The endpoint authorises on the end-user session cookie — the one credential a browser attaches to a request some other site made, which is all RFC 8628 §5.4's remote-phishing attack needs: obtain a `user_code` as any public client, auto-submit `action=approve&user_code=…` from the victim's browser, collect the victim's token. So the endpoint accepts `application/json` only (a form body is a "simple" request sent cross-site without a preflight; JSON is not): any other media type is `415 invalid_request`. The handler checks the media type itself rather than relying on no form parser having run, so the rule is the endpoint's wherever it is mounted ([Beside `oauthEndpointsModule`](#beside-oauthendpointsmodule)). And the route runs the guard `POST /session/login` runs — the `csrfGuard` slot the session module provides ([#728](https://github.com/o3co/auth.provider/issues/728), #710 C4):

- a foreign `Origin` / `Referer` is refused with `403 access_denied` and logged as `csrf_origin_rejected`;
- the provider's own origin, or one listed in `session.csrf.trustedOrigins`, is accepted — a verification page served from another origin is declared there, on the same list the login form uses;
- a request with no origin signal at all (a non-browser client) must present the signed double-submit token from `GET /session/csrf`: the `<session-store.name>.csrf` cookie echoed in the `x-csrf-token` header.

**Enabling the grant requires a `csrfGuard` component**, so boot fails without one, naming it, and fails naming `csrfGuard.middleware` for a guard whose `middleware`, which the route mounts, cannot be read or is not a request handler (a function of at most three parameters; Express skips one of four or more as an error handler). The slot is optional in the manifest, so a deployment that leaves the grant off needs none. One CSRF policy for the product, read through its contract in core, not a second origin check that can drift from it — and not a guard rebuilt from the session's configuration: this package reads no `session.*` or `session-store.*` key.

**The checks run in this order:** the declared body size (`413`), the JSON parser (`413` for a chunked body over the bound, `415 unsupported_encoding` for one it cannot decode, `400 malformed_body` for one it cannot read), the CSRF guard (`403 access_denied`), then, in the handler, the media type (`415`), the action (`400`), session admission (`401 login_required`, `403 step_up_required`, or `503` when it cannot answer), for `approve` what the approval records (`401`, below), the email gate on `approve` (`403`), the attempt (`429`, or the counter outage's `503`), the code's shape (`404` for a malformed code), and then the store's answers (`404`, `409`, `410`), on a clock read after the attempt, so a code that expires while the counter answers is expired: an approval from a session dated ahead is `401` whatever its code, and spends no attempt. So RFC 8628 §5.4's cross-site form is refused by the guard with `403` before its media type is looked at. `415` is what a request the guard lets through gets for a body that is not JSON — a same-origin form, or a POST with no body at all — and it comes before `401`: a non-JSON request with no session is `415`. The action comes before the session too, since it names what admission is asked about: an unknown action is `400` whether or not the cookie is signed in, and whether or not the session store can answer.

The route reads the end user from the express-session (`isAuthenticated`, `user.id`, `sid`), so `sessionStoreModule` must be mounted ahead of it and something must sign the user in; with no authenticated session every action is `401 login_required`.

#### An approval needs the live session

The cookie's `isAuthenticated` is a claim; the `UserSession` its `sid` names is the fact. A logout, `revokeAllForSubject`, or a record deleted out of band ends the record and leaves the cookie as it was — and the device token an approval leads to carries no `sid` and no `family_id`, so no logout reaches it afterwards. (A subject watermark stamped after the token is minted does reach it — every token-accepting surface checks `iat` against it; one stamped before the approval is what the checks below enforce; and one stamped between the approval and the device's poll is refused at the poll — see [Polling](#polling).) So every action is first admitted by core's session admission (`admitSession`, [the session-admission ADR](../core/docs/adr/2026-09-28-session-admission.md)), the reading `/authorize`, `/oauth/consent`, the session grant and the federation-grants browser half share: on the cookie's claim (`cookieClaim`), as the action's own name — `device.lookup`, `device.approve` or `device.deny`, each graded `use`. Admission reads the record the cookie's `sid` names, which must be live, record the cookie's own subject and not be past its `expiresAt`; with `sessionLifecycleStore` wired, the session's lifecycle record; with `subjectRevocation` wired, the subject's sessions boundary; and then the registered session requirements.

- **No `sid` on the cookie session:** `401 login_required` "session identifier (sid) is required" — the session grant's words. `POST /session/login` and the federation callback always write one; a login of the deployment's own that sets `isAuthenticated` and `user.id` without it is told what it is missing (see the Quick start).
- **A `sid` the store no longer holds, a record past its `expiresAt`, or one recorded for another subject:** `401 login_required` "the session is no longer active; sign in again", and the page sends the user to sign in. A subject mismatch is also warned by admission, as `session_admission_subject_mismatch` (the action, no identifier), and audited as `session.admission.subject_mismatch` with the `sid` and both subjects: the cookie and the store disagree about who is signed in.
- **With `sessionLifecycleStore` wired, a session whose lifecycle record is closing or closed:** `401 login_required` "the session is no longer active; sign in again", from the closing commit on, though its `UserSession` is still there.
- **With `subjectRevocation` wired, a session the subject's sessions boundary covers:** the same `401`. `revokeAllForSubject` stamps the boundary before it deletes the subject's sessions, so a cascade that failed for one session — or a session the subject index never learnt of — leaves a record the boundary has ended; a session that authenticated at or before the boundary (core's `claimCoveredByRevocationBoundary`, in whole seconds with the one-second allowance `verifyJwt` gives it) is refused.
- **A session requirement that asks the user to sign in again, or that nothing can meet:** `401 login_required` "sign in again to continue" — a new login is the only remedy the page can offer a device.
- **A session requirement that asks for a step-up:** `403 step_up_required`, with the requirement's name in `requirement` and its step-up page in `page` — the page the requirement registered, as an absolute URL on the issuer with the requirement's params on its query and no return parameter (the verification page knows where it comes back to) — on any of the three actions. The MFA requirement asks it for `approve` alone — a user refuses a phished device request without a step-up — but another requirement may ask it for `lookup` or `deny`.
- **A store that cannot answer** — the session store, the session lifecycle store, the boundary, or a requirement that throws: `503 temporarily_unavailable`, described by what failed ("session store unavailable", "session lifecycle store unavailable", "revocation store unavailable" or "session requirement unavailable", core's `describeAdmissionOutage`), logged once at error by admission as `session_admission_unavailable` (`store` — `user_session`, `session_lifecycle`, `revocation_boundary` or the requirement's name — `action`, the error's projection, never the `sid`; on core's console logger when no logger is wired) — never an approval on the cookie's word.

None of these spends one of the subject's verification attempts or reads the code. With no session requirement registered, `step_up_required` is never answered.

**An approval records the session's authentication.** `approve` hands the store the `amr` the admitted session vouches for (core's `vouchedAmr`, read through `wellFormedAmr`: an untrusted federation's upstream values are never among them) and the session's `authTime`, the primary authentication's time. The poll stamps them on the device token ([Polling](#polling)). An `authTime` the store would refuse to record, one further ahead of the approval's clock than `DEFAULT_CLOCK_SKEW_MS` or before the epoch (core's `recordableDeviceApproval`), is refused before the email gate, the attempt and the code are looked at: `401 login_required` "sign in again to continue", warned as `auth_time_ahead_of_clock` (`sid`, `aheadMs`), and nothing is decided. The remedy is the clock of the replica that signed the user in, as for the session grant.

**Enabling the grant requires a `userSessionStore` component**, so boot fails without one (`memorySessionStoresModule` on one replica, `redisSessionStoresModule` from `@o3co/auth-provider-redis` otherwise). The slot is optional in the manifest, so a deployment that leaves the grant off needs none. A hand-mounted `createDeviceVerificationHandler` takes the store as `userSessionStore`, the session requirements as `requirements` — the `sessionRequirementResolver` the boot planner builds, or `resolverForTests` from `@o3co/auth-provider-core/testing` in a test; core's `checkResolver` refuses any other object — and refuses to be built without either; it takes no issuer: a step-up page arrives resolved on the issuer, as registration resolved it; it takes the boundary as the optional `subjectRevocation`. The module requires `sessionRequirementResolver` while the grant is on, so a composition that enables it declares `core.sessionRequirements.expected`. The module reads `subjectRevocation` from the composition, where `oauthEndpointsModule` makes its absence a declared decision (`oauth.revocation.subject = "unsupported"`).

Under `oauth.requireEmailVerified` (#297), `approve` from a user the Store has not published a verified email for is `403 access_denied` "email address is not verified" — the gate `/authorize` and the session grant hold at issuance, held here because an approval is what the device's token is issued from. It reads the session's user as `/authorize` does, applies to `approve` only (a lookup shows what is asked; a denial issues nothing), and comes before the attempt and the code, so it spends none. The module reads the setting from the `oauthTokenSettings` slot; a hand-mounted handler takes it as `requireEmailVerified`.

**One endpoint, three actions**, because all three take a `user_code` and **all three are the same brute-force oracle** — a `lookup` route that answered "which client is this?" without counting against the same limit would be a free oracle sitting beside a limited one. One route means one attempt counted, and no way to add a fourth entry point that forgets it.

The code is accepted as displayed (`BCDF-GHJK`), lower-cased, or unseparated. A character *outside* the alphabet is rejected rather than stripped: a `0` typed for an `O` is a mistake, and silently removing it would turn an 8-character mistake into a 7-character lookup that fails invisibly — or matches a different code.

## The attempt limit is half the security argument, not a nicety

RFC 8628 §5.1 sizes the user code's entropy *against* an attempt limit: an 8-character base-20 code has "roughly 34.5 bits of entropy", which the RFC calls sufficient only where "the rate-limiting interval and validity period would need to only allow 5 attempts". The entropy and the limit are two halves of one mitigation, so the limit is this module's own, and nothing the deployment wires around it loosens it.

The verification endpoint counts its attempts through core's attempt guard (`createAttemptGuard`), against `device-grant.rateLimit { limit, windowSeconds }` — `5` / `300` as the package's `reference.conf` ships it. No rate limiter takes part: a limiter's `limits`, `defaultLimit` and `failMode` never change it, and the bundled limiter modules refuse a `limits.device_verification` entry, naming this key. The module claims the `device_verification` prefix with core's `verifierLimitClaim({ setting: "device-grant.rateLimit" })`: no budget, so no other module can set one for it, and the declared setting is the key the refusal names.

Every attempt counts, malformed codes included: excluding them would hand an attacker an unmetered way to probe which shapes the endpoint accepts. The key is `device_verification:user:<subject>` — keyed on the **authenticated user**, not the code. Keying on the code would spend whichever code the attacker happened to hit, which is nobody's limit; keying on the subject means an attacker needs an account and burns their own.

**Where it is counted.** On the `attemptCounter` slot's counter — `redisAttemptCounterModule` from `@o3co/auth-provider-redis` — so the limit holds across replicas. Without one the guard counts per process: `core.deployment.mode = "multi"` refuses the boot, naming `device_verification` (the route's factory fails), an unset mode warns `attempt_counter_not_shared`, and `"single"` is silent.

**It fails closed.** A counter that throws, does not answer within 2 s, or answers outside its contract is an outage: every action is `503 service_unavailable` "Attempt counter temporarily unavailable", logged as `attempt_counter_unavailable` with `tag: "device_verification"` and audited as `rate_limit.unavailable`, whatever any rate limiter's `failMode` says. A counter that answers "no" is not an outage: `429 slow_down` "too many device code attempts", with `Retry-After` and `Cache-Control: no-store` and never `RateLimit-*` headers, which would tell whoever is guessing how many guesses are left; it is logged as `device_verification_rate_limited` and audited as `device.rate_limited`.

**The key is required, and bounded.** A section with no `device-grant.rateLimit` fails boot, naming the key: the schema fills no default, so a configuration that does not layer the package's `reference.conf` writes it; and the module refuses to mount the verification route without one, for a hand-built section that never passed the schema. The key is read as the schema reads it, so a string of decimal digits, as an environment substitution produces one, is its number. Zero, a fraction, a string that is not decimal digits, or a window longer than a day — the longest a counter takes — is refused, naming `device-grant.rateLimit`.

A hand-mounted `createDeviceVerificationHandler` takes the limit as `attemptLimit`, the counter as the optional `attemptCounter` and the replica count as `deploymentMode`, and counts through the same guard.

### `/oauth/device_authorization` and the rate limiter

Throttling `POST /oauth/device_authorization` is abuse control, the deployment's. With a `rateLimiter` wired it is throttled under `device_authorization:ip:<ip>` — the same `createRateLimitGuard` and key shape as `/oauth/token`, mounted **ahead of client authentication** so unauthenticated repeats are bounded before they reach a repository lookup — on the limiter's `defaultLimit` unless its `limits.device_authorization` declares one, and on the limiter's own outage policy, `failMode`. Without a limiter, requests pass through; core then requires `rateLimiter` in `core.declaredAbsent`, as it does wherever a module reads the slot. The module claims `device_authorization` with no budget, so no other module can set one for it. With the grant off the module registers nothing: it claims no prefix and reads neither slot.

## The decision is an audit event

`approve` emits `device.approved`, `deny` emits `device.denied`, and a subject who runs out of verification attempts emits `device.rate_limited` — the signal that an account is being used to guess codes. Each carries the subject, the client, the scope and the request's `ip` / `userAgent`; none carries the user code (the value being brute-forced) or the device code (a bearer credential). An `approve` or `deny` that meets a store outage emits `device.decision_outcome_unknown` with the subject, the `action` and the request's `ip` / `userAgent`: the decision may have been recorded before the reply was lost, and a device can then be handed tokens that no `device.approved` accounts for. It names no client, since the record could not be read. The names are part of core's `BUILT_IN_AUDIT_EVENT_TYPES` inventory.

`auditSink` is optional to wire, not optional to decide (#363): a composition that mounts this module with no sink must write `core.declaredAbsent = ["auditSink"]`, or boot refuses. A device approval is a consent, and a consent that vanishes with no symptom is the shape that rule exists to refuse.

## The user code (§6.1)

`BCDFGHJKLMNPQRSTVWXZ` — the consonants. Two properties, neither arbitrary:

- **No vowels**, so no arrangement can spell a word. A code that reads as an obscenity gets screenshotted rather than typed.
- **No digits**, so `0`/`O`, `1`/`I`/`l`, `5`/`S`, `8`/`B` and `2`/`Z` cannot arise.

Codes are drawn with `randomInt`, not `randomBytes() % 20`: 256 is not a multiple of 20, so the modulo would bias toward the first 16 characters and quietly cost about a bit of the 34.5 the attempt limit is computed from.

`device_code` is the opposite problem — nobody types it — so it is 256 bits of base64url, per §5.2's "a very high entropy code SHOULD be used".

## `verification_uri_complete` is off by default

RFC 8628 §3.3.1 defines a URI with the code embedded, so a QR code can carry it. §5.4: with it "it is particularly important to confirm that the device is in the user's possession, as the user no longer has to type in the code".

The typing **is** the proof of proximity. Removing it without replacing that confirmation is what makes remote phishing work, so `verificationUriComplete` ships as `false`. Turn it on only if the verification page displays the code and asks the user to confirm the device is showing the same one.

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

A store that cannot be read is none of the four: the poll answers `503 temporarily_unavailable`, as every grant at `/oauth/token` answers a store outage, and logs `device_code_grant_store_unavailable` at error (see [Storage](#storage)). So is an answer around the record that cannot be read — not an object (`refused: "outcome_not_an_object"`), a `status` the type does not declare, or a `slow_down` whose `intervalSeconds` is not a finite number of seconds, zero or more (`refused: "outcome_malformed"`, `field`) — logged at error as `device_code_grant_record_unreadable` (`clientId`, `refused`, `field`): whether it consumed an approval cannot be told.

**A record that cannot be read.** Every route reads a `DeviceAuthorization` the store answers through core's `readDeviceAuthorization` before it uses any of it. A record it refuses — one that is not an object, or a field whose read throws or that is not what `DeviceAuthorization` declares — is never a `500`. The poll answers `400 invalid_grant` "the approval cannot be read; start a new device authorization request": `poll` has consumed the approval, so the device starts again. It is logged at error as `device_code_grant_record_unreadable` (`clientId`, `refused`, and the `field`, never its value). It means a defect in a custom `DeviceCodeStore`. A scope entry must be an RFC 6749 §3.3 scope-token, and an optional field the record does not hold must be absent or `undefined`: `null` is refused. An `approvedAtMs` further ahead of the poll's clock than `DEFAULT_CLOCK_SKEW_MS` is `400 invalid_grant` "the approval's time is ahead of this server's clock; start a new device authorization request", warned as `device_approval_ahead_of_clock` (`clientId`, `aheadMs`): an approval from the future would postdate any sessions boundary.

**The deployment's grant policy.** With a `grantPolicy` wired, an approved poll consults it after the client check, and before it reads the revocation boundary and takes the instant it mints at (so neither is stale by the policy's latency), with `grantType` `urn:ietf:params:oauth:grant-type:device_code`, the authenticated client, the approving subject and the approved scope. It may only narrow: a deny is `400` with the policy's own `error` when it is a token-endpoint code (RFC 6749 §5.2's other than `invalid_client`, or `invalid_target`) or RFC 8628 §3.5's terminal `access_denied` or `expired_token`, and `invalid_grant` otherwise — never `authorization_pending` or `slow_down`, which would tell the device to keep polling an approval already spent — a policy that throws is `503 temporarily_unavailable`, and a `grantedScope` past the approved scope or a `grantedAudience` outside the client's `allowedAudiences` is `500 server_error`; a `grantedAudience` within them is the token's `aud`. `poll` has consumed the approval by then, so each refusal spends it and the device starts a new request. `createDeviceCodeGrant` takes the policy as a required `grantPolicy` key: a grant built by hand passes the policy, or `undefined` for none.

**A revocation between the approval and the poll.** With `subjectRevocation` wired, the poll holds the approval's own instant (`DeviceAuthorization.approvedAtMs`, which the store records when the approval is given) and the approving session's authentication time (`DeviceAuthorization.authTimeMs`) against the subject's sessions boundary. A `revokeAllForSubject` that lands after the approval and before the poll — anywhere within the code's lifetime — is older than the token the poll would mint, so nothing downstream would refuse that token; a holder of a stolen live session could otherwise approve codes ahead and redeem them after the victim's credential change. An approval either of whose times is at or before the boundary — in whole seconds with the one-second allowance, as `verifyJwt` compares `auth_time` (core's `claimCoveredByRevocationBoundary`) — is `400 invalid_grant` "the approval predates a revocation of the subject's sessions; start a new device authorization request". The store records the authentication time no later than the approval's instant, so an approval from a session that authenticated after the boundary passes both. An approval that records either as none is refused while a boundary is in force, as a token with no `iat` is, and honoured while none is. The poll fixes the instant it mints at, the token's `iat`, before it reads the boundary, and awaits nothing else before signing, so a boundary stamped while that read is answered covers the token. A boundary the poll cannot read is `503 temporarily_unavailable` "the revocation boundary is unavailable; start a new device authorization request", logged once at error as `device_code_grant_revocation_unavailable` (`store: "revocation_boundary"`, `step: "read"`).

*Upgrading.* A record approved before the store recorded the instant or the authentication time has none, and so does every approval a replica not yet upgraded writes: under `core.deployment.mode = "multi"` that is the whole rollout, not only the codes pending when it starts. An upgraded replica refuses such an approval at the poll only while the subject has a sessions boundary in force; the device is answered `invalid_grant` and starts a new device authorization request, which is refused again for as long as a replica not yet upgraded is the one that approves it, so for such a subject device sign-in may fail until the rollout completes. Nothing is lost but those codes, and nothing needs migrating. An approval path of the deployment's own that calls `DeviceCodeStore.approve` must hand it the session's `authTime`: every approval it records without one is refused while the subject has a sessions boundary in force. The poll has consumed the approval either way, so the device starts again. The module hands the grant the composition's `subjectRevocation`; a hand-built `createDeviceCodeGrant` takes it as the optional `subjectRevocation`.

**What the token says about the authentication.** The access token carries the approval's recorded `amr` and, as `auth_time`, when the approving session authenticated (its primary authentication, which a step-up never moves; the store records it no later than the approval's clock, so one up to `DEFAULT_CLOCK_SKEW_MS` ahead of that clock is recorded as that clock — it is not when the session approved), read against the minting clock with core's `authTimeAt`: an instant up to `DEFAULT_CLOCK_SKEW_MS` ahead is stamped as that clock, so `auth_time` is never after the token's `iat`. One further ahead is `400 invalid_grant` "the approving session's authentication time cannot be read; start a new device authorization request", nothing is minted, and it is warned as `auth_time_ahead_of_clock` (`clientId`, `aheadMs`). One before the epoch, not whole milliseconds, or whose read throws is a record that cannot be read (above). A recorded `amr` that cannot be read is stamped as none. An approval that records neither — one an older replica wrote during a rolling upgrade — mints a token with neither while the subject has no sessions boundary in force (with one, the poll refuses it, above): absent means "cannot tell", which a resource server gating on `amr` or `auth_time` refuses. The token carries no `acr`: device verification selects none.

**A sender-constrained poll.** With `@o3co/auth-provider-dpop` or `@o3co/auth-provider-mtls` installed, a poll that presents a DPoP proof or a client certificate gets an access token bound to it — the member the binding's mechanism owns (core's `ownedConfirmation`), as every grant stamps it — and the response's `token_type` is read off that `cnf`: `DPoP` for `cnf.jkt` (RFC 9449 §5), `Bearer` for an mTLS-bound or unbound token. The grant mints no refresh token, so there is no refresh-token binding to decide.

## Single use, and bound to one client

`DeviceCodeStore.poll` reads the status **and consumes an approved authorization in the same operation**. A `find`-then-`delete` implementation passes a naive unit test and issues two access tokens from one human approval under concurrency; the shared conformance suite in core has a test that races two polls for exactly this reason.

A device code is redeemable only by the client it was issued to, checked against the authenticated client identity rather than the request body. Without that, a leaked device code is redeemable by any other registered client — converting a leak into a full impersonation of the user's approval.

A client must also be **allowed the grant before it can start it**: `POST /oauth/device_authorization` answers `400 unauthorized_client` unless the client's `allowedGrantTypes` names `urn:ietf:params:oauth:grant-type:device_code` — deny by absence, as the token endpoint does for this grant (#326). Otherwise a client registered for nothing but `authorization_code` could still open a pending authorization and put a real-looking prompt in front of a user for a grant that can never complete.

## Storage

The `DeviceCodeStore` port lives in `@o3co/auth-provider-core`, not here, so an adapter author depends on core alone. Two adapters ship, and which one is wired decides whether the deployment can scale:

How each route answers what the store throws:

| Route and store call | Store throws | Answer | Logged |
| --- | --- | --- | --- |
| `POST /oauth/device_authorization` — `create` | `DeviceCodeStoreError { reason: "collision" }`: a live record already holds the drawn device code or user code | both codes are re-drawn, up to five times in all; then `500 server_error` ("could not allocate a device authorization code") | `device_authorization_code_collision` (warn) |
| `POST /oauth/device_authorization` — `create` | `DeviceCodeStoreError { reason: "full" }`: a bounded store is at its cap with every record live | `503 temporarily_unavailable`, no re-draw | `device_authorization_store_full` (warn) |
| `POST /oauth/device_authorization` — `create` | anything else: the store is down, timed out, or broke its own contract | `503 temporarily_unavailable` ("the device authorization store is unavailable; retry later"), at once, no re-draw | `device_authorization_store_unavailable` (error) |
| `POST /oauth/device/verification` — `findPendingByUserCode` (`lookup`), `approve`, `deny` | anything | `503 temporarily_unavailable`, the same description. For `approve` and `deny` the decision **may already be recorded**: the store's script can run before its reply is lost (a `commandTimeout`, a reset after the command was sent), so a retry may answer `409 already_decided`, and after an approval the device's poll may receive tokens | `device_verification_store_unavailable` (error, with the `action`); for `approve` and `deny`, the audit event `device.decision_outcome_unknown` (with the subject and the `action`) |
| `POST /oauth/token`, the device-code grant — `poll` | anything | `503 temporarily_unavailable`, the same description, written by the token endpoint as every grant's error is. An approval **may already be consumed**: `poll` takes it in the same script that reads it, so if that reply was lost, the device's retry answers `invalid_grant` and the device starts again | `device_code_grant_store_unavailable` (error, with the `clientId`) |

Each `…_store_unavailable` line carries core's `loggableError` projection of the error, never the error itself: a store error echoes the command it answered, and with it a user code, a device code or the approving subject. An adapter signals a collision with that reason and nothing else: a collision it reports any other way is answered as an outage.

- **`memoryDeviceCodeStoreModule`** (`@o3co/auth-provider-core`) — in-process; development and single-replica only. It is registered in core's replica-unsafe module list, so a composition with `core.deployment.mode = "multi"` **refuses to boot** with it: pending authorizations fork per replica, and the human approves a code on the replica that served the verification page while the device polls one that has never heard of it. The store is bounded three ways: every read path drops an expired record it finds, `create` sweeps expired records every 1000 calls, and `maxEntries` (default 10 000) caps the resident set — at the cap, expired records are reclaimed first, and if every resident record is still live **`create` refuses** with `DeviceCodeStoreError { reason: "full" }` rather than evicting one. The endpoint answers that refusal with `503 temporarily_unavailable` — RFC 6749 §5.2's "temporary overloading" — without re-drawing a code, and logs `device_authorization_store_full`. Its `dispose` is registered with the boot planner's lifecycle registrar.
- **`redisDeviceCodeStoreModule`** (`@o3co/auth-provider-redis`) — what a scaled deployment runs. It requires the `deviceCodeStoreClient` slot, which `makeIoredisClients` provides off the shared connection, and is configured under `redis-device-code-store.keyPrefix` (default `devauth:`). Every operation the port marks atomic is one Lua script, so the conformance suite's "two polls racing for one approval" case passes against a real Redis rather than only in sequence. With it wired, `core.deployment.mode = "multi"` boots.

Refusing at the cap is the fail-closed choice. Evicting the live record closest to expiry would not be: the flood that reaches the cap carries the newest expiries, so the records closest to expiry are exactly the pre-existing ones — a human's pending approval, an approval a device has not polled for yet — and all of them would go before any of the attacker's. The sibling caps in core evict because what they hold is reconstructible (a rate-limit bucket resets, a CRL cache entry refetches); a device authorization is not, so the store keeps what was issued and refuses what is new. The refused request is a `POST /oauth/device_authorization`, which sits behind the per-IP rate-limit guard, so the flooder is the one told to retry, and a legitimate device retries into a slot the next expiry frees. Evicting same-`clientId` records first was considered and rejected: device clients are public (RFC 8628 §5.6), so a flood arrives *as* the legitimate client and that policy would evict its real users first all the same.

Two things about the Redis adapter are worth knowing before choosing it:

- **Every device authorization shares one Redis Cluster slot.** The record is keyed by `device_code` and the `user_code → device_code` index by `user_code`; both are independent random values, and a script that follows the index to the record has to find both keys in the slot it was routed to. So both live under one constant hash tag — `devauth:{devauth}:code:<device_code>` and `devauth:{devauth}:user:<user_code>` — which concentrates the flow on a single slot. For a human-initiated ceremony that is an acceptable trade; this is not per-request traffic. The alternative, storing the record twice under each key, would make `approve`/`poll` non-atomic across the pair, which is what the port forbids.
- **The TTL is not the expiry.** Both keys carry the authorization's `expiresAtMs` as their TTL so Redis reclaims them without a sweep, but `poll` answers `expired` from the timestamp: a record still inside its TTL whose deadline has passed on the caller's clock expires, and is dropped.

The standalone template provides `deviceCodeStoreClient` from its shared ioredis connection but does not mount this grant; a deployment that adds `deviceAuthorizationGrantModule` to that manifest selects `redisDeviceCodeStoreModule` alongside it.

Enabling the grant without any store fails boot naming `device-grant.store`; the module refuses to boot without a store whatever that key says. A deployment that leaves the grant off needs no store and no declaration.

Every field of the `DeviceAuthorization` an adapter hands back is a required key: `requestedScope`, `subject`, `grantedScope`, `approvedAtMs`, `amr` and `authTimeMs` hold `undefined` where there is none, so a read-back that forgets one is a compile error rather than a dropped field; `create`'s `requestedScope` is a required key the same way ([Upgrading: store records name every field](../../docs/upgrading-required-record-keys.md)). The conformance suite compares the whole record with `toStrictEqual`, which also catches the two scope lists swapped.

## Tests

[`flow.test.mts`](./src/__tests__/flow.test.mts) runs the ceremony end to end, [`admission.test.mts`](./src/__tests__/admission.test.mts) pins the three admitted actions and what each admission is answered with, [`composition.test.mts`](./src/__tests__/composition.test.mts) boots the module beside `oauthEndpointsModule` as the Quick start does — the discovery document, the disabled grant, the JSON-only rule, the body limit and the JSON error answers in both list orders, and that a route of another module under `/oauth` still receives its body unread — [`verificationCsrf.test.mts`](./src/__tests__/verificationCsrf.test.mts) pins the CSRF guard, [`configRateLimit.test.mts`](./src/__tests__/configRateLimit.test.mts) and [`verificationAttempts.test.mts`](./src/__tests__/verificationAttempts.test.mts) the verification's attempt limit, and [`module.test.mts`](./src/__tests__/module.test.mts) the boot refusals, that a disabled module mounts nothing and what an error log line carries. The store's atomicity is core's conformance suite, run against both adapters.

## License

Apache-2.0
