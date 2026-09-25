# @o3co/auth-provider-federation-grants

Last updated: 2026-09-25

Federation grants for [`auth.provider`](https://github.com/o3co/auth.provider) — offline delegation of upstream access tokens (#593). A user consents once that a client may reach one upstream connection on their behalf; the client then obtains upstream access tokens over HTTP, later, with the user nowhere near a browser.

Optional. Nothing here is active until `federationGrants.enabled = true`.

The standalone template composes it from `FEDERATION_GRANTS_ENABLED=true` — see its README's "Federation Grants" — and [`docs/offline-access.md`](docs/offline-access.md) says what each IdP needs before it will issue a refresh token.

## Responsibility

**Role.** The HTTP half of federation grants: the five routes a client calls under `/oauth/federation-grants`, and the browser half — connect, consent, the upstream callback — under `/session/federation-grants`. It turns core's federation-grant domain into wire answers and runs the acquisition flow in the browser.

**Owns:**

- the client routes: the order of their guards (correlation id, throttle, body bound and parsing, client authentication), their answers and their error identifiers;
- the browser half: the connect handle, the consent page's contract, and the checks the callback runs before a grant is activated;
- the boot refusals of an enabled feature that is missing what it needs, and what a disabled deployment answers;
- the shutdown drain of work still in flight after a response (`federationGrantBackgroundModule`).

**Does not own:**

- the grant and intent records, the `FederationGrantStore` and `FederationGrantIntentStore` ports, and the rules for lodging, retrieval with a coordinated refresh, revocation and effective status — core, [`packages/core/src/federation-grants`](../core/src/federation-grants/README.md). A subject-wide revocation reaches grants through that port whether or not these routes are installed;
- the stores themselves — core's memory modules and `@o3co/auth-provider-redis`;
- the upstream authorization and refresh calls — the federation adapter's delegated-authorization capability, which only `@o3co/auth-provider-federation-oidc` implements ([`docs/offline-access.md`](docs/offline-access.md));
- the consent page — the deployment's;
- client authentication — `@o3co/auth-provider-oauth`'s `createClientAuthMiddleware`;
- the browser session and login — `@o3co/auth-provider-session` (the `session-middleware` route, `endpoints.login.url`).

**Why a separate package.** What these routes disclose is an *upstream* access token, held on a user's standing consent, for a backend the user is not present at. Behind `/oauth/token` it would inherit grant dispatch, `token.issued`, this provider's token minting and a sender-constraint policy that cannot bind a credential another issuer minted; inside the oauth package it would make an optional feature part of every deployment's routing surface, so enabling ordinary OAuth would acquire this lifecycle by accident. The domain and the store ports are core's so that a store adapter depends on core and never on these routes.

**Why it depends on `@o3co/auth-provider-oauth`.** For one thing, `createClientAuthMiddleware`: the five client routes authenticate a confidential client exactly as `/oauth/token` does, `private_key_jwt` included, and their client-authentication `401`s carry that middleware's wording ([below](#post-oauthfederation-grantsgrantidtoken)). It is a required peer, so the package is installed even by a deployment that mounts no `oauthModule` — which is an ordinary thing to do ([below](#beside-oauthmodule)). Nothing in oauth imports this package.

## Install

```sh
npm install @o3co/auth-provider-federation-grants @o3co/auth-provider-core @o3co/auth-provider-oauth express
```

Peer dependencies: `@o3co/auth-provider-core`, `@o3co/auth-provider-oauth` and
`express@^5.0.0`. The package depends on `zod`.

Delegation also needs
[`@o3co/auth-provider-federation-oidc`](../federation-oidc/README.md), the one
adapter that can delegate; the package does not import it.

## Install both modules

```ts
import { federationGrantsModules } from "@o3co/auth-provider-federation-grants";
import {
  memoryFederationGrantIntentStoreModule,
  memoryFederationGrantStoreModule,
} from "@o3co/auth-provider-core";

const app = await createApp({
  modules: [
    ...federationGrantsModules,
    memoryFederationGrantStoreModule,
    // Where a client's intent waits for the user's consent and the upstream's answer.
    memoryFederationGrantIntentStoreModule,
    // …and the session modules you already run: the browser half mounts after
    // `session-middleware` and re-reads the durable session behind the cookie.
  ],
  bootstrapComponents: { config, pathResolver: import.meta.resolve, clientRepository, keyStore },
});
```

`federationGrantsModules` is a pair: the routes, and the background registry a shutdown drains. They are separate manifests because their dependency edges point in different directions — see below — and mounting the routes without the registry is a boot refusal rather than a shutdown that quietly drops rotated credentials.

The grant store is a separate module again, because a store is what a deployment installs whether or not it mounts these routes: a subject-wide revocation reaches grants through the same port (an ordinary logout leaves them standing, D14 — a grant is consent to act while the user is away). `memoryFederationGrantStoreModule` is single-replica only; a scaled deployment wires `redisFederationGrantStoreModule` from `@o3co/auth-provider-redis`. The same holds for the intent store: `memoryFederationGrantIntentStoreModule` on one replica, `redisFederationGrantIntentStoreModule` on several — an intent lodged on one replica is otherwise unknown to the one the browser lands on.

Creating grants also needs, each refused at boot when missing rather than met by a user mid-flow: `federationGrants.consent.url` (the deployment's consent page — there is no default), a `callbackURL` on every connection, `endpoints.login.url`, a `userSessionStore`, and, once a connection is configured, either a `userRepository` whose `supportsFederatedIdentityLookup` answers `true` for every connection's registration (with `findSubjectByFederatedIdentity` beside it) or `federationGrants.identityLookup = "unsupported"`. The bundled `InMemoryUserRepository` covers no registration, so a deployment on it with a connection configured must choose the second. Each is described where the flow uses it, below.

Enabling the feature also requires a `subjectRevocation` component that carries the **grants boundary** — `revokeSessionsBefore` and `grantsRevokedBefore` beside the pair #296 shipped (D13). A grant outlives the session it was agreed through, so that boundary is what reaches one on a replica that never saw the withdrawal, and every disclosure is compared against it. Three compositions are refused at boot rather than per request:

| Composition | Why it is refused |
|---|---|
| no `subjectRevocation` | Nothing would end a grant the user withdrew. Declaring the capability absent (`oauth.revocation.subject = "unsupported"`) is **not** an escape: sessions end when their cookie does, and a grant ends when nothing does. |
| an adapter with only `revokeBefore` / `revokedBefore` | There is no second boundary to compare a grant against, and a subject-wide revocation could not be asked to keep one. |
| a non-`memory` grant store beside a `memory` `subjectRevocation` | The grants outlive the process and the boundary does not, so a restart — or the replica that never held it — discloses a credential for a grant that was revoked. A custom store of any other `kind` is treated as durable: `kind` is all the port exposes, and refusing a pairing that would lose the boundary is the conservative direction. |

### What is audited, and where it goes

Every operation on a grant emits its event — a status inspection excepted,
which audits only the backstop revocation it writes, and no denial — the
`federation.grant.*` types,
`.authorization_failed`, `.authorized`, `.reauthorization_required`,
`.reauthorized`, `.refresh_failed`, `.refresh_persist_failed`, `.refreshed`,
`.request.denied`, `.requested`, `.revoke.denied`, `.revoked`,
`.token.denied`, `.token.success` — with a correlation ID that is never empty: the request's
`x-request-id` on the routes, and on the library path (`revokeFederationGrant`,
`revokeAllForSubject`, the subject revocation service) the caller's own, or
one generated for the call when the caller gives none, so that a pass over a
subject's grants reads as one operation in the sink (#618). Recording and
delivery are the deployment's: the module refuses to boot with the feature
enabled and no `auditSink` unless `audit.sink.type = "none"` declares the
capability absent on purpose — the product-wide declaration, which opts the
whole provider out of audit and which the standalone does not offer. A Store
that drives a revocation through the library without passing `audit` records
nothing of it, by the same choice.

### What is logged

Through the deployment's `logger` component (the console when none is
wired), every line object-first with its event name as the message, and a
caught error on it as core's `loggableError` projection (`err`) — the name,
the message (capped at 256 characters: whatever the library or the store
wrote there is logged), a code, an upstream's `error`, the causes — never the
error itself, so nothing a library put beside the message (a response body, a
command's arguments, a token answer on a cause) reaches the line. Every string
field is sanitised and capped at 200 characters: a grant id or a connection
can be what the caller sent. The runbook's
[federation-grants tables](../../docs/operator-runbook.md#federation-grants--what-each-answer-means-593)
say what each one means and what to do.

- **An outage** — a `503`, or the callback's `temporarily_unavailable`
  redirect, because something could not answer — is exactly one line at
  error, naming what failed: `federation_grant_token_unavailable`,
  `federation_grant_status_unavailable`, `federation_grant_revoke_unavailable`,
  `federation_grant_lodge_unavailable`, `federation_grant_connect_unavailable`,
  `federation_grant_consent_unavailable`, `federation_grant_callback_unavailable`,
  with `reason` (what the caller was answered, or `upstream`) and, where a
  store failed, `store` (`federation_grant`, `federation_grant_intent`,
  `revocation_boundary`, `user_session`, `user_directory`) and `step`. A key
  missing from the ring is one of these with `reason: "key_unavailable"` and no
  `err`: nothing was thrown. A store or an upstream that did not answer in
  time is `err` "not answered in time; no longer waited for"; a credential
  write retried within the persist budget is one line, with `attempts`. A
  lodging's `connection_not_configured` names the `connection` — a renewal's
  is its grant's.
- **A client registry that cannot answer** is core's
  `client_repository_unavailable`: `site: "federation_grants"` from client
  authentication on the routes above, `federation_grant_connect` /
  `federation_grant_consent` from the browser half.
- **A failure that changed no answer** is one warn:
  `federation_grant_token_step_failed` (a failure core absorbed, a different
  kind of failure an earlier write attempt met, or work that failed after the
  answer — a lock release, a use record, an audit, a refresh still persisting,
  the upstream call the hard deadline abandoned), `federation_grant_status_step_failed`,
  `federation_grant_lodge_step_failed` (every store error core met that the
  answer does not stand for — a second write that threw and landed all the
  same, a question that could not be asked, an intent it could not close — on
  a `201` too), `federation_grant_consent_step_failed`,
  `federation_grant_callback_step_failed`, and
  `federation_grant_callback_exchange_refused` for an upstream that answered
  the code exchange with a refusal. A token request answered `503` because
  another replica holds the refresh (`lock_timeout`) or won the write
  (`concurrent_update`) is `federation_grant_token_contended`, a warn: nothing
  is down.
- **What escaped a handler** is `federation_grants_unexpected_error`, at error,
  with `site` and `err`: the handler that caught it (`token`, `status`,
  `revoke`, `create`, `reauthorize`, `connect`, `consent`, `callback`), or the
  router whose last error handler did (`federation_grants`,
  `federation_grants_browser`).
- **The throttles** log and audit a limiter outage through core with the
  deployment's own logger and sink — `rate_limiter_failed_closed` /
  `rate_limiter_failed_open` and `rate_limit.unavailable`, tagged
  `federation_grants` or `federation_grants_browser`.

## Public API

Exported from [`src/index.mts`](src/index.mts); the linked file holds each definition and its doc comment:

- `federationGrantsModules` — the pair to install — and its two halves `federationGrantsModule` and `federationGrantBackgroundModule`, with `federationGrantsConfigSchema` — [`module.mts`](src/module.mts).
- `createFederationGrantRouter`, `FederationGrantRouterOptions`, `createDisabledFederationGrantRouter`, `FEDERATION_GRANTS_RATE_LIMIT_PREFIX` — [`routes.mts`](src/routes.mts). The client routes with their middleware chain, in the order that is the security property (correlation, throttle, parsing, client authentication), for a root that mounts them itself; and what a disabled deployment mounts instead.
- `createFederationGrantTokenHandler`, `FederationGrantTokenHandlerOptions` — [`tokenRoute.mts`](src/tokenRoute.mts); `createFederationGrantStatusHandler`, `FederationGrantStatusHandlerOptions` — [`statusRoute.mts`](src/statusRoute.mts). Single handlers, without that chain.
- `createFederationGrantBackground`, `FederationGrantBackground` — [`background.mts`](src/background.mts). The shutdown registry ([below](#shutting-down-without-losing-a-rotated-credential)).
- `FEDERATION_GRANTS_MOUNT_PATH` — [`types.mts`](src/types.mts).

The browser half is mounted only by the module. The store ports, the grant domain types and retrieval are core's and are not re-exported.

## A disabled deployment names no feature and runs nothing

`federationGrants.enabled` defaults to `false`, and while it is false the package still mounts both of its paths, each answering every request with a `404` that says nothing about the feature.

Under `/oauth/federation-grants`, the client routes' JSON shape:

```http
HTTP/1.1 404 Not Found
Cache-Control: no-store
Pragma: no-cache
x-request-id: 4f1e…

{"error":"not_found"}
```

Under `/session/federation-grants`, the browser half's shape — a navigation, so plain text and no redirect, and no `x-request-id`:

```http
HTTP/1.1 404 Not Found
Cache-Control: no-store
Pragma: no-cache
Referrer-Policy: no-referrer
Content-Type: text/plain; charset=utf-8

Not found.
```

No description, deliberately. A body naming the feature would tell an unauthenticated caller that this deployment could do offline delegation if someone flipped one key. Nothing on either path parses a body, authenticates a client or reads a store either, so there is no timing to measure it by — and a deployment that leaves the feature off needs none of the components it would need to turn it on.

What it is **not** is byte-identical to a deployment that never installed the package: there, nothing matches the path at all and the host's own fallback answers — Express's HTML 404 in a bare composition. The difference is the headers and the content type, not what the body reveals. So the property this has is the one worth having: the refusal names no feature, and nothing behind it runs. A deployment that wants the two indistinguishable gives its host a 404 of its own. [`disabledRoutes.test.mts`](src/__tests__/disabledRoutes.test.mts) pins both shapes.

## The routes a client calls

All five are `POST` and all are authenticated as a confidential client
(`client_secret_basic`, `client_secret_post` or `private_key_jwt`). The three
that address a grant take its id as an opaque path segment; the two that lodge
an intent answer where to send the user's browser.

### `POST /oauth/federation-grants` — lodging a first-time intent

```json
{
  "connection": "calendar",
  "sub": "local-subject",
  "redirect_uri": "https://client.example/connected",
  "state": "opaque-client-state",
  "scope": "openid offline_access calendar.read",
  "expires_in": 2592000,
  "upstream_sub": "00u-expected"
}
```

`scope`, `expires_in` and `upstream_sub` are optional. The answer is where to
send the user, and nothing has been granted yet:

```json
{
  "grant_id": "…",
  "status": "pending",
  "connect_uri": "https://provider.example/session/federation-grants/connect?request=…",
  "connect_expires_in": 600,
  "expires_in": 2592000
}
```

- `connect_uri` is built on the issuer, never on a request header. The handle
  in it is single-use and the whole flow — connect, consent, the upstream,
  the callback — has to finish within `connect_expires_in` seconds: ten
  minutes, measured from this answer. A user who spends nine of them on the
  consent page has one left for the upstream; start again if it runs out.
- `expires_in` is the grant lifetime that applied — a request above
  `federationGrants.maxExpiresIn` is clamped, not refused. There is no
  `expires_at` yet: a grant is dated from the user's consent.
- `sub` is what the client asserts. The connect flow is where a browser
  session proves it, and a session for anyone else is refused.

`redirect_uri` must be one of the client's `federationGrantRedirectUris`,
exactly — no prefix, no fallback to its ordinary redirect URIs — and may not
already carry `grant_id`, `state` or `error`, which the end of the flow
appends. `scope` must be within the connection's scopes, keep `openid`, and
keep `offline_access` where the connection lists it.

| Exit | HTTP | `error` | `error_description` |
|---|---:|---|---|
| Lodged | 201 | — | — |
| Body is not an object | 400 | `invalid_request` | `invalid_body` |
| A required field missing or empty | 400 | `invalid_request` | `sub_required` / `connection_required` / `redirect_uri_required` / `state_required` |
| A field repeated, or not a string | 400 | `invalid_request` | `duplicate_<field>` / `invalid_<field>` |
| `scope` present and empty, or not a space-delimited list of scope-tokens (RFC 6749 §3.3: a tab, a quote) | 400 | `invalid_request` | `invalid_scope` |
| `expires_in` not a whole positive number of seconds | 400 | `invalid_request` | `invalid_expires_in` |
| Any other body parameter (`resource`, `expires_at`, …) | 400 | `invalid_request` | `unexpected_parameter` |
| `redirect_uri` not registered, registered but not a valid redirect URI, or carrying a result parameter | 400 | `invalid_request` | `redirect_uri_not_registered` / `redirect_uri_invalid` / `redirect_uri_reserved_parameter` |
| `scope` outside the connection / without `openid` / without `offline_access` / a subset where subsets are off | 400 | `invalid_scope` | `scope_exceeded` / `openid_required` / `offline_access_required` / `scope_subsets_not_allowed` |
| The client may not use this connection — whether or not it exists | 403 | `access_denied` | `connection_not_permitted` |
| Sixteen live first-time intents for this client and this user | 429 | `rate_limited` | `intent_limit` |
| The connection is not configured | 503 | `temporarily_unavailable` | `connection_not_configured` |
| A store could not be read or written | 503 | `temporarily_unavailable` | `storage` |
| Admitted as the process began shutting down | 503 | `service_unavailable` | `shutting_down` |
| Unexpected fault | 500 | `server_error` | `unexpected_error` |

A lodged intent emits `federation.grant.requested` (`outcome: "initial"`) with
the connection and the resolved scopes; a refused one emits
`federation.grant.request.denied` with the fixed outcome. Neither carries the
handle.

### `POST /oauth/federation-grants/:grantId/reauthorize` — renewing a grant

The same body without `connection` (sent anyway, it is checked against the
grant's and never moves it: `400 invalid_request/connection_mismatch`). The
answer has the same shape; `status` is the grant's own — `active`,
`reauthorization_required`, or `upstream_token_ineligible` for a grant starved
of scope (below) — because a renewal changes nothing a client can see until
the user finishes it.

Ownership first, with the same `404 grant_not_found` for an unknown id,
another client's grant and another subject's. Then the subject's grants
boundary: a grant a subject-wide revocation covers is revoked here, durably,
before anything else is asked of it, and answers `410 grant_revoked/backstop`.
Then what a renewal cannot mend — each with the status `/token` gives it,
but for a connection the deployment no longer configures, which is
`503 temporarily_unavailable/connection_not_configured` here, an outage the
deployment may put right without the client, where `/token` folds it into
`403 access_denied/connection_not_permitted`: `400 authorization_pending`, `410 grant_revoked/<by>`,
`410 grant_expired/<reason>`, `410 connection_identity_changed`,
`502 upstream_token_ineligible/<reason>` for every reason but one — a consent
mends no token lifetime, type or shape, but it does mend a consent an
accumulating IdP widened under a narrower grant, so `scope_exceeded` is
admitted and the 201 reports it (#616; the guide's Entra section says how) —
and a key missing from the ring as `503 temporarily_unavailable/key_unavailable`,
an outage rather than a reason to send the user through consent again. Then the client's current permission
and the request itself, as above. A renewal takes no place against the bound.

A renewal emits `federation.grant.requested` with `outcome: "reauthorization"`;
a backstop it wrote emits `federation.grant.revoked` with `outcome: "backstop"`.

### `POST /oauth/federation-grants/:grantId/token`

```json
{ "sub": "local-subject", "min_ttl": 60, "connection": "graph", "scope": "openid Files.Read" }
```

`sub` is required and compared exactly. The rest are *assertions*: things the
caller claims about the grant, which are checked and never widen anything —
asking for a scope the grant does not carry is a refusal, not a request.
`scope` is read strictly by RFC 6749 §3.3's grammar (core's
`readSpaceDelimitedParameter`): spaces delimit, and a value holding anything
that is not a scope-token — a tab, a quote — is `invalid_scope` before core is
asked, as is one that names nothing.
`min_ttl` asks for a refresh; it does not turn a short token into an error.

A success is an ordinary OAuth token response carrying the **upstream's**
access token, its own spelling of `token_type`, and the scopes that token
holds. There is never a refresh token, an id token or an upstream response
object in it.

`expires_in` is the smaller of the token's remaining life and the grant's
effective expiry: a cache hint for a cooperating worker, never enforcement.
The token is valid at the upstream for as long as the upstream says, and
lowering `maxAccessTokenLifetime` shortens nothing already disclosed — only
what is disclosed next. `min_ttl` is a request, not a guarantee: a fresh token
still shorter than it is returned with its true `expires_in`, and the caller
decides.

Every retrieval re-evaluates the record and the deployment — never the
upstream. A consent withdrawn at the IdP, or an account disabled there, is seen
when a refresh is refused; until one is due, a stored token that serves is
disclosed, so the upstream's change reaches the grant at most one access-token
lifetime on. The provider receives no upstream events. A deployment that has
them ends the grant itself, through `/revoke` or `revokeAllForSubject`.

Everything else is `{"error": "<code>"}` with an `"error_description"`
alongside it wherever the failure has a reason to give — `grant_not_found`,
`invalid_scope`, `invalid_target` and `authorization_pending` have none, and
carry the code alone. Both fields are **identifiers, not prose**, for every
answer **this package** owns: a client may switch on them, and the wording may
be improved without breaking one. What these routes inherit — client
authentication's `401`s, its `503 temporarily_unavailable` with "client
repository unavailable" when the client repository cannot answer (not a
`401`: the client did nothing wrong), and the shared rate limiter's `503` —
still carries that middleware's own wording, and it is the same wording every other
throttled, client-authenticated route in this provider gives; rewriting it
here would make one failure read two ways depending on which route met it.

The body identifiers are `invalid_body`, `sub_required`, `invalid_sub`,
`duplicate_sub`, `unexpected_parameter`, and — on `/token`, which is the only
route that takes them — `invalid_connection`, `invalid_resource`,
`invalid_scope`, `invalid_min_ttl` and `duplicate_min_ttl`. A parameter this
route does not take is never named back to the caller: it is their string, and
`error_description` goes into logs.

The status
says what kind of problem it is: `400` the caller's, `403` the client's
registration, `404` no such grant of theirs, `410` the user must be asked
again, `429` slow down, `502` the upstream, `503` come back. `Retry-After` is
present whenever the answer knew when — including on `502` and `503`, not only
on `429`.

A refresh against an upstream that could not be reached, did not answer in
time, or answered with a 5xx is `503 temporarily_unavailable/upstream` — core's
`isFederationUpstreamOutage` (the callback's own test, below) beside the
refresh-error classifier's `network` — and one the upstream answered with a
refusal is `502 upstream_rejected`, with its code when this provider knows it
and `unknown` otherwise. The outage is decided first: a 5xx is never a verdict
on the credential, whatever OAuth code its body names — a 503 saying
`invalid_grant` does not end the credential, and one naming an interaction code
is not the user's absence. A 429 is no outage.

An unknown grant id, a grant belonging to another client and one belonging to
another subject all answer the same `404` body, byte for byte.

A refresh the upstream refused for the user's absence — `interaction_required`,
`login_required`, `consent_required` or `account_selection_required`, read off
the error's own code and never off a message, beside any status but a 5xx
(which is the outage above) — answers
`410 reauthorization_required` with the code as the description
(`upstream_consent_required`), with no `Retry-After` and no cached token:
nothing said the refresh token is bad, so it is kept; nothing is mended by
waiting, so nothing is told to wait (#616). The record remembers it, and
`/status` says the same, until a reauthorization activates. Pause the grant's
work, lodge one renewal, send the user through its `connect_uri`, and resume
on the callback; polling `/token` against it changes nothing.

### `POST /oauth/federation-grants/:grantId/status`

```json
{ "sub": "local-subject" }
```

`sub` and nothing else; the token route's assertions are refused here rather
than ignored. A successful inspection answers `200` for **every** effective
status, expired and revoked included — a grant that is over is not a failed
call — with the grant's lifecycle, its upstream account, the scopes consented
to and its dates in UTC.

`expires_at` is **effective** expiry, computed from `maxExpiresIn` as it is
configured now. Lowering the maximum therefore moves it earlier for grants that
already exist, possibly into the past; raising it moves it back, never beyond
the stored expiry, which never changes. `last_used_at` is the last *recorded*
disclosure, a cached one included: it is written best-effort after the answer,
so it may lag a disclosure the store did not get to write down. It is not the
last time the upstream was asked, and no measure of an upstream's idle window.

Status opens no credential, refreshes nothing, takes no refresh lock and
never `touch`es. The one thing it writes is the backstop: a grant the
subject's grants boundary covers is revoked here, durably, and
`federation.grant.revoked` with `outcome: "backstop"` is emitted before the
`revoked` status is answered. It is also **not** a health check for `/token` — `active`
does not promise a token, and an ineligible status can sit beside a perfectly
usable cached one. A refresh the upstream refused for the user's absence reads
`reauthorization_required` with `upstream_<code>` as the reason, for as long
as the record carries it; a grant starved of scope by an accumulating IdP reads
`upstream_token_ineligible/scope_exceeded`, the one ineligibility
`/reauthorize` admits (#616).

### `POST /oauth/federation-grants/:grantId/revoke`

```json
{ "sub": "local-subject" }
```

The owning client ends its own grant: the user disconnected the integration on
its side, the workspace was deleted, the agent is being decommissioned. A
success is **`204` with no body** — a withdrawal has no result to report — and
a second call answers `204` as well, because the record is retained as a
tombstone for `/status` and a client retrying after a timeout must not be told
its second attempt failed.

**Ownership is the whole check.** The grant is this client's and this
subject's, or it answers the same `404` as an unknown id. After that nothing
else is consulted: not the connection allowlist, not the current connection
configuration, not the revision, not eligibility, not expiry, not the subject's
boundary. Every one of those decides whether a credential may be *disclosed*,
and none of them is a reason to refuse a withdrawal — a grant whose connection
was removed, whose encryption key is out of the ring, or which expired last
week and is still retained, is exactly the grant an operator most needs to be
able to end.

It does not stamp either subject boundary, touch the subject's other grants,
cascade sessions, or call the upstream. Ending a grant here is a local fact
about one record; revoking the upstream's own refresh token is that upstream's
API and a different failure domain, and waiting on it would mean a user cannot
disconnect while somebody else's service is down.

| Exit | HTTP | `error` | `error_description` |
|---|---:|---|---|
| Ended, or already over | 204 | — | — |
| Body is not an object | 400 | `invalid_request` | `invalid_body` |
| `sub` missing or empty | 400 | `invalid_request` | `sub_required` |
| `sub` repeated / not a string | 400 | `invalid_request` | `duplicate_sub` / `invalid_sub` |
| Any other body parameter | 400 | `invalid_request` | `unexpected_parameter` |
| Unknown id, another client's, another subject's | 404 | `grant_not_found` | — |
| The record could not be read or written | 503 | `temporarily_unavailable` | `storage` |
| Admitted as the process began shutting down | 503 | `service_unavailable` | `shutting_down` |
| Unexpected fault, or no authenticated client on the request | 500 | `server_error` | `unexpected_error` |

Client authentication, the throttle and the body-size and content-type guards
are the same ones `/token` inherits, and answer the same way here.

A withdrawal that changed something emits one `federation.grant.revoked` with
`outcome: "client"`, built from the record the write returned. A refused one
emits `federation.grant.revoke.denied` — its own type, not a
`.token.denied`: a credential that was not handed out and a credential that is
still live are opposite facts, and a dashboard counting one must not count the
other.

## The browser half: connect and consent

Mounted at `/session/federation-grants`, **after** the session middleware — the
module declares `after: ["session-middleware"]`, so a composition without it is
a boot error rather than a flow that reads every signed-in user as signed out.

### `GET /session/federation-grants/connect?request=<handle>`

Where `connect_uri` sends the browser. A navigation: it answers with redirects
and plain text, never a JSON body.

1. A prefetch parks nothing (`204`).
2. An unknown, spent or expired handle: `400`, plain.
3. Not signed in: `303` to `endpoints.login.url?redirect_to=<this link>` —
   the handle and nothing else from the original query. It is `/oauth/authorize`'s
   login round trip: the login page signs the user in and then returns the
   browser to `redirect_to` **verbatim** itself. It is not a value to post as
   `redirect_to` to `POST /session/login`, whose exact-match allowlist names
   fixed landing pages and would refuse this link — as it would refuse an
   authorize URL — for carrying a per-flow handle. Core's schema leaves
   `endpoints.login.url` optional and only `oauthModule` requires it, so an
   enabled deployment without it is refused at boot rather than answering
   this step with a 500.
4. Signed in as someone other than the intent's subject: `403`, plain, and no
   redirect anywhere.
5. The durable session is gone or expired, or authenticated at or before the
   subject's sessions boundary: `403` "sign in again". `authTime` never
   changes, so signing in again is the remedy.
6. The grant no longer names this intent, the client may no longer use the
   connection, or the connection changed since the intent was lodged: `400` /
   `403`, plain.
7. Otherwise one consent challenge is parked for this browser — a reload gets
   the same one — and the browser is sent to `federationGrants.consent.url`
   with `?challenge=`.

It does not apply the login flow's `Sec-Fetch-Site` refusal: a client's site
sending the browser here is what connect is for. That is sound only because
holding the handle authorizes nothing — see "What the exemption depends on"
below.

### `GET` and `POST /session/federation-grants/consent`

The deployment page's contract, and deliberately the same one `/oauth/consent`
has, so one page can serve both kinds of consent.

`GET ?challenge=` answers what to show:

```json
{
  "challenge": "…",
  "client_id": "worker",
  "client_name": "Calendar Agent",
  "connection": "calendar",
  "scopes": ["openid", "offline_access", "calendar.read"],
  "resource": "https://calendar.example/",
  "grant_expires_in": 2592000,
  "continues_after_logout": true,
  "expires_in": 540
}
```

`grant_expires_in` is the duration **after approval** — the grant is dated
from the answer, so an absolute date computed when the page renders would be
an estimate the grant does not keep. `continues_after_logout` is what D8
obliges the page to tell the user. `expires_in` is what is left of the flow.

The page's URL carries the challenge, so the page sends
`Referrer-Policy: no-referrer` on its own responses: the provider's
`no-referrer` covers only the provider's answers, and an outbound link the
page renders would otherwise hand the challenge to its target.

`POST` with `challenge` and `decision` (`accept` or `deny`). Both success paths
are `303`: an approval to the upstream's authorization endpoint, a refusal
back to the client's `redirect_uri` with `error=access_denied`, the client's
own `state` and the `grant_id`. A refused renewal ends that renewal and
nothing else; the grant keeps working.

| Exit | HTTP | `error` | `error_description` |
|---|---:|---|---|
| Page data | 200 | — | — |
| Answered | 303 | — | — |
| No authenticated session | 401 | `login_required` | `no authenticated session` |
| No challenge | 400 | `invalid_request` | `challenge is required` |
| Unknown, answered, expired, another browser's, stale | 400 | `invalid_request` | one sentence for all of them |
| `decision` neither `accept` nor `deny` | 400 | `invalid_request` | (nothing is spent) |
| The session was revoked, or predates the sessions boundary | 403 | `reauthentication_required` | `sign in again to continue` |
| The client may no longer use the connection | 403 | `access_denied` | `connection_not_permitted` |
| A cross-site `Sec-Fetch-Site` on the answer | 403 | `invalid_request` | `cross-site answer refused` |
| This deployment's own throttle (`federation_grants_browser`) | 429 | `rate_limited` | `provider` |
| A store, the session store or the boundary could not answer | 503 | `temporarily_unavailable` | `storage` |
| The client registry could not answer — judging the question or describing the client | 503 | `temporarily_unavailable` | `client registry unavailable` |
| The limiter backend is down, under `rateLimit.failMode = "closed"` | 503 | `temporarily_unavailable` | `rate_limiter` |
| The upstream URL could not be built, or the federation lost the capability (nothing is spent) | 503 | `temporarily_unavailable` | `upstream_unavailable` |

A challenge is not a bearer token: it is answerable only from the browser it
was issued to, by the same durable session and subject, and every answer
re-reads that session and the sessions boundary.

### `GET /session/federation-grants/callback/:connection`

Where the upstream returns the browser: each connection's `callbackURL`
points here. Query mode only — a `form_post` federation is refused at boot,
because that callback arrives without the session cookie.

A `:connection` segment Express cannot percent-decode (`/callback/%zz`) never
reaches the checks below: it is answered by the router's last error handler
as JSON `400 invalid_request` (`malformed_path`), not as one of the callback's
plain pages.

It checks, in this order:

1. **The transaction** — the `state` is one this provider issued, for THIS
   connection, and it is spent before any code is exchanged. Otherwise a plain
   `400` and no redirect: there is nowhere trustworthy to send the browser.
2. **The intent** is still the grant's current one, within the flow's deadline,
   and the connection is still what it was lodged against; for a renewal, the
   grant it would renew is checked against the subject's grants boundary and
   **revoked there, durably,** if a subject-wide revocation should have ended
   it — the one failure meant to change a record.
3. **The browser** is the one the flow started in — the same express session
   and durable session — still live, the intent's subject's, and signed in
   after the subject's sessions boundary.
4. **The upstream's answer**, validated by the adapter's
   `exchangeDelegatedCode`: PKCE, the id_token's signature, issuer, audience,
   expiry and nonce, `iss` forwarded (RFC 9207), the resource sent at the token
   endpoint, aborted at `upstreamHardTimeoutMs`. A response carrying any
   parameter twice is refused as malformed (`upstream_error`) before the code
   is exchanged, rather than having the copies dropped — a dropped `iss` would
   leave RFC 9207's check to the issuer's metadata. An exchange that got no
   answer, or got a 5xx, is `temporarily_unavailable` — core's
   `isFederationUpstreamOutage`, read off what the error is, never what its
   text says: an `AbortError` or `TimeoutError` (openid-client's
   `OAUTH_TIMEOUT` carries one), a connection code (`ECONNREFUSED`,
   `ECONNRESET`, `ENOTFOUND`, `ETIMEDOUT`, `UND_ERR_SOCKET`, …) on the error
   or its causes, `fetch`'s `TypeError` over a transport's code — a connection
   code, the TLS layer's (`CERT_…`, `ERR_TLS_…`, `ERR_SSL_…`, the certificate-
   verification names), or `ERR_INVALID_URL`; any other code there, such as an
   adapter's validation error wrapped in a `TypeError`, is not an outage — or a
   5xx `status` on the error or on the `Response` it was raised over (an IdP
   answering 503; a deployment's own `fetch` — npm undici's `Response` —
   included) — each read only on what the library raised, never on the IdP's
   parsed body. The token route's refresh reads the same shapes as an
   outage (`503 upstream`). One the upstream answered with a refusal is
   `upstream_error`.
5. **The upstream account**: the connection's issuer; for a renewal, the
   account already on the grant; the client's `upstream_sub` if it sent one;
   and — unless `identityLookup = "unsupported"` — the Store's answer to who
   holds it. Held by this user, or by nobody, passes; held by another user is
   `identity_conflict`; an answer that establishes neither is
   `identity_unverifiable`.

   **What the Store is asked, and what it must answer (#611).** The callback
   calls `findSubjectByFederatedIdentity({ provider, issuer, clientId, sub, claims })`:
   the registration the identity was issued under — the connection's
   federation name, its configured issuer (already compared with the verified
   id_token's) and client — the verified `sub`, and `claims`: the id_token
   claims the connection names in `identityClaims` (`{}` when it names none),
   exactly those, as the adapter verified them. If any named claim is missing
   or not a non-empty string, the Store is not asked and the flow is
   `identity_unverifiable`. The Store must not log, keep or echo them. It
   answers one of:

   - `{ kind: "linked", subject }` — it looked everywhere a link to this
     person could be, and found exactly one local user;
   - `{ kind: "unlinked" }` — it looked everywhere, and nobody holds them;
   - `{ kind: "indeterminate", reason }` — it cannot say either:
     `registration_not_covered` (no strategy for this registration) or
     `identity_not_resolvable` (a strategy, and this identity is not in it).

   "Everywhere" is the point. A login links an identity under the federation
   the user signed in through, and an IdP whose `sub` is pairwise per
   registration (Entra's is) gives the same person a different `sub` under
   every registration — so a connection on a registration of its own, as D19
   recommends for an IdP that accumulates consent, finds nothing under its own
   name even for an account another user holds. A Store that searched only
   the name and `sub` it was given has not established `unlinked`, and must
   not answer it. A backend that cannot answer throws, and so does data that
   names more than one owner; either, and any answer that is not one of the
   three, is `temporarily_unavailable`.

   **At boot**, under `"required"`, the Store is asked
   `supportsFederatedIdentityLookup({ provider, issuer, clientId }, identityClaims)`
   for every configured connection — two on one registration are asked about
   separately, each with its own claims — and anything but a literal `true` —
   `false`, a truthy value, a throw — refuses to start, naming the connection
   and the registration. A deployment finds out there, not from the first user
   who connects. With no connection configured nothing is required — not even
   the two methods — because no callback can reach check 5; removing the last
   connection stays operable on any repository. A connection re-pointed onto
   another `federations.<name>` entry mid-flow ends that flow
   (`grant_not_authorizable`), because boot probed the Store under the new
   name.

   The bundled `InMemoryUserRepository` keys links by name and `sub` and knows
   nothing of registrations, so it covers none and answers `indeterminate` for
   every identity: a deployment on it that configures a connection sets
   `identityLookup = "unsupported"` — the recorded decision not to make this
   check — or installs a Store that covers the registration. The foundation
   package's `HttpUserRepository` (#613) asks a deployment's own Store over
   HTTP and answers the boot probe from an operator's declaration of what that
   Store covers, per registration and claims; its README carries the wire
   contract a Store implements.

   **For an IdP with a registration of its own for grants** (D19 — Entra, for
   one): **a Store that learns identities only from logins cannot satisfy
   `"required"` there.** A login tells it `<provider>:<sub>`, and the grants
   registration's pairwise `sub` is one no login ever saw. What can is a Store
   with its own directory keyed by what does not change across registrations
   — for Entra, the tenant and object id, provisioned from Entra onto each
   local user — with the connection naming them:

   ```hocon
   federationGrants.connections.files {
     federation = "entra-files"          # its own app registration
     scopes = ["openid", "profile", "offline_access", "Files.Read"]
     allowScopeSubsets = false
     identityClaims = ["oid", "tid"]
   }
   ```

   Name **immutable identifiers only**. `email`, `preferred_username` and
   `upn` pass the name check but are attributes the account's holder or an
   administrator can change — Microsoft says so of all three, and that a guest's
   `email` need not be correct — so a Store matching on them can be walked
   past: change the attribute, get `unlinked`. Two things boot cannot see and
   the first connect will: an upstream that does not issue a named claim (Entra
   without `profile` omits `oid`), and a custom adapter that returns no
   `claims`. Either refuses every flow, after consent, as
   `identity_unverifiable/identity_claims_unavailable` — fail closed, but try
   one connect before telling users. Under `identityLookup = "unsupported"`
   `identityClaims` is ignored: nothing is asked for and nothing is required.

   `profile` is there because Entra issues `oid` only with it. The Store
   resolves `(tid, oid)`, answers `unlinked` only where its directory is
   complete for the tenant, and `identity_not_resolvable` for a person it was
   never given; its `supportsFederatedIdentityLookup` answers `false` for a
   connection that does not name both claims. Not verified on a real tenant:
   that both claims are issued for your registration and account types, and
   the scope set Entra reports with `profile` added. Otherwise, choose
   `identityLookup = "unsupported"` and accept the loss of this one check.
6. **Eligibility**: a refresh token, and an access token with a finite lifetime
   within `maxAccessTokenLifetime`, of a type a route without a proof key can
   present.
7. **Scope containment**: nothing beyond what the user was shown. The
   upstream's `scope` is read tolerantly by RFC 6749 §3.3's grammar (core's
   `parseScopeTokens`, as every upstream answer is): whitespace separates, and
   only scope-tokens count. An omitted `scope` means as requested; one that
   names no scope-token is not an answer; an upstream that granted more is
   refused, because a token cannot be narrowed after the fact.
8. **Activation**, immediately after re-reading the session, the sessions
   boundary, the current-intent pointer and the grants boundary. It replaces
   the authorization and the credentials together, and clears with them the
   ineligibility marker and the stamp of a refresh the upstream refused for
   the user's absence (#616); a renewal refused at any check above leaves all
   of it exactly as it was.

Every failure after check 1 goes back to the intent's `redirect_uri` with the
client's own `state`, the `grant_id`, and one of: `access_denied`,
`reauthentication_required`, `account_mismatch`, `identity_conflict`,
`identity_unverifiable`, `refresh_token_absent`, `upstream_token_ineligible`,
`scope_exceeded`, `upstream_error`, `temporarily_unavailable`,
`grant_not_authorizable`. Nothing
an upstream described, and no thrown message, reaches it. Success goes back
with `grant_id` and `state` — never a token. The `grant_id` proves nothing on
its own: every grant-addressed route needs `sub`, and `/status` says which
upstream account the grant got.

**What the re-read before activation does, and does not, do.** The upstream
leg can take seconds, and a caller can hold the redirect and finish it much
later. A subject-wide revocation that keeps established grants (`"keep"`)
stamps the sessions boundary and nothing else, so without a second look a
flow that passed check 3 before the stamp could activate after it. The re-read
narrows that from a window the caller controls to the gap between the read and
the write. It does not close it: that needs write fencing, which is deferred.

A grant created emits `federation.grant.authorized`, a renewal
`federation.grant.reauthorized`, each described from the record the write
returned. Its outcome is what check 5 let it through on: `required/linked`
(the Store placed the upstream account with this user), `required/unlinked`
(with nobody), or `unsupported` (the deployment does not ask). A failed flow
emits `federation.grant.authorization_failed` with the code as its outcome —
for `identity_unverifiable`, with the Store's reason after a slash
(`identity_unverifiable/identity_not_resolvable`). Neither ever names the other
owner of a conflicting account.

### What the exemption depends on

Connect skips the request-origin check because consent is its CSRF defence.
That holds only while connect never approves anything, every grant and renewal
goes through consent (first-party clients included), the answer needs the
challenge and the exact session binding, the consent data is never readable
cross-origin with credentials (hence the same-origin page), and the challenge
never leaks through a referrer (`Referrer-Policy: no-referrer` on every
response, the deployment's page included). Making consent skippable later is
a redesign of this, not a UI
option.

A flow that ended without a grant — declined, the wrong account, a session to
refresh, a stale link — emits `federation.grant.authorization_failed` with a
fixed outcome and only the facts established by then.

## Beside `oauthModule`

These routes live under `/oauth`, where `oauthModule` mounts its own router.
That router parses the bodies of its own routes only (the paths in its
[Endpoints](../oauth/README.md#endpoints) table), so a request to
`/oauth/federation-grants/...` reaches this package's router with its body
unread, whatever order the modules are listed in. Every body rule here is
this package's own:

- **The body limit.** The 16 KiB bound is checked from `Content-Length` ahead
  of the parsers, so it holds whatever else is mounted; a body with no
  `Content-Length` is bounded by this package's own parsers.
- **A body the parser refuses.** What body-parser marks as the caller's
  mistake is answered by this package as a 4xx, with its `x-request-id` and
  `Cache-Control: no-store`, after its throttle: too many form parameters is
  `413 invalid_request` (`body_too_large`), a charset or `Content-Encoding`
  it cannot decode is `415 invalid_request` (`unsupported_encoding`), and JSON
  it cannot read or a compressed body that does not decompress is
  `400 invalid_request` (`malformed_body`). A grant id in the path that
  Express cannot percent-decode (`/oauth/federation-grants/%zz/token`) is
  `400 invalid_request` (`malformed_path`). Only the parsers' errors, and
  that one, are read as the caller's mistake: anything else that escapes
  every handler is `500 server_error` (`unexpected_error`), logged as
  `federation_grants_unexpected_error` with `site: "federation_grants"`, the
  request's `correlationId` and the error's projection (`err`).

So the list order of `federationGrantsModules` and `oauthModule` does not
matter. This package declares no ordering edge against the OAuth router — it
needs none, and one would refuse to boot for every deployment that runs
federation grants *without* `/oauth/token`, which is a perfectly ordinary
thing to want.

## `x-request-id`

Every response this package produces carries one: the caller's when it matches `[A-Za-z0-9._:+/=#-]{1,128}` and arrived exactly once, a fresh UUID otherwise. An unusable value is *replaced*, never trimmed into a usable one.

It is caller-controlled correlation metadata and nothing else — not authentication, not an idempotency key, not a lock key, not a trusted identifier of a person. Its job is that a credential rotation persisted *after* the response was sent can still be tied to the request that started it.

## Shutting down without losing a rotated credential

A refresh against an upstream is not finished when the HTTP response is. The provider may still be letting go of a refresh lock, writing down a refresh token the upstream has already rotated to, or telling the audit sink what happened — and if the caller was answered at the soft deadline, the refresh itself is still running, holding its lock until its result is persisted.

`federationGrantBackgroundModule` provides the per-application registry that holds all of it, and its cleanup drains: it refuses new operations, then waits for every admitted request and registered promise, rechecking as finishing work registers more.

It is a **component** rather than a `lifecycleRegistrar` callback because `AppHandle.dispose()` runs component cleanups first and registrar callbacks afterwards — a drain registered there would run after the store's own cleanup, and an adapter that closes its client there would pull the connection out from under the write being waited for. The registry's `optional` edges on `federationGrantStore`, `subjectRevocation` and `auditSink` order it after all three at boot, and therefore before all three at shutdown.

What it is not: durable job execution, guaranteed audit delivery, or protection against `SIGKILL`. It bounds nothing by itself — core bounds its own waits, and an adapter whose read can hang needs its own I/O timeout.

And there is one thing it cannot wait for, by core's design rather than by omission: the wait for a refresh lock the call gave up on is kept outside the registry, because it may never end. If that lock arrives after the drain has finished, its release is registered into a registry nobody is waiting for. No answer and no credential is lost; what is left is a lock nobody released, which stands for its `refreshLockTtlMs` while other replicas answer `503 temporarily_unavailable/lock_timeout` for that one grant. A larger cleanup allowance does not help — the drain has already returned. A store whose lock acquisition is bounded does.

### Give the host enough cleanup allowance

A deployment mounting this package wants **at least 45 seconds** of cleanup allowance: the ten-second drain a host would otherwise give cleanup is shorter than the upstream hard timeout and persist budget this feature ships with, so a shutdown under it would abandon exactly the write the drain exists to wait for. The standalone template gives cleanup the longest refresh tail its budgets allow plus a margin — 45 seconds under the shipped budgets, more when `upstreamHardTimeoutMs`, `persistRetryBudgetMs` or `lockWaitMs` is raised — and its compose files give the process 60; Kubernetes' default `terminationGracePeriodSeconds` of 30 is below drain plus cleanup and has to be raised to 60 or more. HTTP draining and the orchestrator's termination grace are sized separately, and both have to be longer again.

## License

Apache-2.0
