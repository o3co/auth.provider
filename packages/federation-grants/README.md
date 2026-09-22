# @o3co/auth-provider-federation-grants

Federation grants for [`auth.provider`](https://github.com/o3co/auth.provider) — offline delegation of upstream access tokens (#593). A user consents once that a client may reach one upstream connection on their behalf; the client then obtains upstream access tokens over HTTP, later, with the user nowhere near a browser.

Optional. Nothing here is active until `federationGrants.enabled = true`.

> **Work in progress (#593).** Every route is here. The standalone template, the documentation roll-up and the CHANGELOG are slice 7, and #611 — check 5's identity lookup across registrations — is to be settled before the release.

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
  bootstrapComponents: { config, clientRepository, keyStore },
});
```

`federationGrantsModules` is a pair: the routes, and the background registry a shutdown drains. They are separate manifests because their dependency edges point in different directions — see below — and mounting the routes without the registry is a boot refusal rather than a shutdown that quietly drops rotated credentials.

The grant store is a separate module again, because a store is what a deployment installs whether or not it mounts these routes: a logout and a subject-wide revocation reach grants through the same port. `memoryFederationGrantStoreModule` is single-replica only; a scaled deployment wires `redisFederationGrantStoreModule` from `@o3co/auth-provider-redis`. The same holds for the intent store (slice 6): `memoryFederationGrantIntentStoreModule` on one replica, `redisFederationGrantIntentStoreModule` on several — an intent lodged on one replica is otherwise unknown to the one the browser lands on.

Creating grants also needs, each refused at boot when missing rather than met by a user mid-flow: `federationGrants.consent.url` (the deployment's consent page — there is no default), a `callbackURL` on every connection, `endpoints.login.url`, a `userSessionStore`, and either a `userRepository` whose `supportsFederatedIdentityLookup` answers `true` for every connection's registration (with `findSubjectByFederatedIdentity` beside it) or `federationGrants.identityLookup = "unsupported"`. The bundled `InMemoryUserRepository` covers no registration, so a deployment on it with a connection configured must choose the second. Each is described where the flow uses it, below.

Enabling the feature also requires a `subjectRevocation` component that carries the **grants boundary** — `revokeSessionsBefore` and `grantsRevokedBefore` beside the pair #296 shipped (D13). A grant outlives the session it was agreed through, so that boundary is what reaches one on a replica that never saw the withdrawal, and every disclosure is compared against it. Three compositions are refused at boot rather than per request:

| Composition | Why it is refused |
|---|---|
| no `subjectRevocation` | Nothing would end a grant the user withdrew. Declaring the capability absent (`oauth.revocation.subject = "unsupported"`) is **not** an escape: sessions end when their cookie does, and a grant ends when nothing does. |
| an adapter with only `revokeBefore` / `revokedBefore` | There is no second boundary to compare a grant against, and a subject-wide revocation could not be asked to keep one. |
| a non-`memory` grant store beside a `memory` `subjectRevocation` | The grants outlive the process and the boundary does not, so a restart — or the replica that never held it — discloses a credential for a grant that was revoked. A custom store of any other `kind` is treated as durable: `kind` is all the port exposes, and refusing a pairing that would lose the boundary is the conservative direction. |

## A disabled deployment is indistinguishable from an uninstalled one

`federationGrants.enabled` defaults to `false`, and while it is false both paths answer:

```http
HTTP/1.1 404 Not Found
Cache-Control: no-store
Pragma: no-cache
x-request-id: 4f1e…

{"error":"not_found"}
```

No description, deliberately. A body naming the feature would tell an unauthenticated caller that this deployment could do offline delegation if someone flipped one key. Nothing on that path parses a body, authenticates a client or reads a store either, so there is no timing to measure it by — and a deployment that leaves the feature off needs none of the components it would need to turn it on.

What it is **not** is byte-identical to a deployment that never installed the package: there, nothing matches the path at all and the host's own fallback answers — Express's HTML 404 in a bare composition. Review measured the difference and it is the headers and the content type, not the body. So the property this actually has is the one worth having: the refusal names no feature, and nothing behind it runs. A deployment that wants the two indistinguishable gives its host a JSON 404 of its own.

## The routes a client calls

All five are `POST` and all are authenticated as a confidential client
(`client_secret_basic`, `client_secret_post` or `private_key_jwt`). The three
that address a grant take its id as an opaque path segment; the two that lodge
an intent (slice 6) answer where to send the user's browser.

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
| `scope` present and empty | 400 | `invalid_request` | `invalid_scope` |
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
answer has the same shape; `status` is the grant's own — `active` or
`reauthorization_required` — because a renewal changes nothing a client can
see until the user finishes it.

Ownership first, with the same `404 grant_not_found` for an unknown id,
another client's grant and another subject's. Then the subject's grants
boundary: a grant a subject-wide revocation covers is revoked here, durably,
before anything else is asked of it, and answers `410 grant_revoked/backstop`.
Then what a renewal cannot mend — each with the status `/token` gives it:
`400 authorization_pending`, `410 grant_revoked/<by>`,
`410 grant_expired/<reason>`, `410 connection_identity_changed`,
`502 upstream_token_ineligible/<reason>`, and a key missing from the ring as
`503 temporarily_unavailable/key_unavailable`, an outage rather than a reason
to send the user through consent again. Then the client's current permission
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
`min_ttl` asks for a refresh; it does not turn a short token into an error.

A success is an ordinary OAuth token response carrying the **upstream's**
access token, its own spelling of `token_type`, and the scopes that token
holds. There is never a refresh token, an id token or an upstream response
object in it.

Everything else is `{"error": "<code>"}` with an `"error_description"`
alongside it wherever the failure has a reason to give — `grant_not_found`,
`invalid_scope`, `invalid_target` and `authorization_pending` have none, and
carry the code alone. Both fields are **identifiers, not prose**, for every
answer **this package** owns: a client may switch on them, and the wording may
be improved without breaking one. What these routes inherit — client
authentication's `401`s and the shared rate limiter's `503` — still carries
that middleware's own wording, and it is the same wording every other
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

An unknown grant id, a grant belonging to another client and one belonging to
another subject all answer the same `404` body, byte for byte.

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
the stored expiry, which never changes.

Status calls `inspect` and nothing else: never a refresh, never the refresh
lock, never `touch`. It is also **not** a health check for `/token` — `active`
does not promise a token, and an ineligible status can sit beside a perfectly
usable cached one.

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
| The session was revoked, or predates the sessions boundary | 403 | `reauthentication_required` | — |
| The client may no longer use the connection | 403 | `access_denied` | `connection_not_permitted` |
| A cross-site `Sec-Fetch-Site` on the answer | 403 | `invalid_request` | `cross-site answer refused` |
| A store, the session store or the boundary could not answer | 503 | `temporarily_unavailable` | `storage` |
| The upstream URL could not be built (nothing is spent) | 503 | `temporarily_unavailable` | `upstream_unavailable` |

A challenge is not a bearer token: it is answerable only from the browser it
was issued to, by the same durable session and subject, and every answer
re-reads that session and the sessions boundary.

### `GET /session/federation-grants/callback/:connection`

Where the upstream returns the browser: each connection's `callbackURL`
points here. Query mode only — a `form_post` federation is refused at boot,
because that callback arrives without the session cookie.

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
   leave RFC 9207's check to the issuer's metadata.
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
   who connects. With no connection configured nothing is asked.

   The bundled `InMemoryUserRepository` keys links by name and `sub` and knows
   nothing of registrations, so it covers none and answers `indeterminate` for
   every identity: a deployment on it that configures a connection sets
   `identityLookup = "unsupported"` — the recorded decision not to make this
   check — or installs a Store that covers the registration.

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
7. **Scope containment**: nothing beyond what the user was shown. An omitted
   `scope` means as requested; an upstream that granted more is refused,
   because a token cannot be narrowed after the fact.
8. **Activation**, immediately after re-reading the session, the sessions
   boundary, the current-intent pointer and the grants boundary.

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
response). Making consent skippable later is a redesign of this, not a UI
option.

A flow that ended without a grant — declined, the wrong account, a session to
refresh, a stale link — emits `federation.grant.authorization_failed` with a
fixed outcome and only the facts established by then.

## Install these modules before `oauthModule`

These routes live under `/oauth`, and `oauthModule` mounts its own router there
whose first two middlewares are `express.json()` and `express.urlencoded()`
with the library's defaults. Express runs route contributions in mount order,
so when that router is mounted first it sees `/oauth/federation-grants/...`
requests before this one does — and `body-parser` does not parse a body twice.

What that costs, and what it does not:

- **It does not cost the body limit.** The 16 KiB bound is checked from
  `Content-Length` ahead of the parsers, so it holds whatever else is mounted.
- **It does cost one exit.** A body that is not valid JSON is rejected by
  whichever parser reaches it first. Mounted second, that is the OAuth
  router's, and its refusal carries neither this package's `x-request-id` nor
  its `Cache-Control: no-store`, and does not pass this package's throttle.

So list `federationGrantsModules` ahead of `oauthModule` at the composition
root. This package deliberately does not declare a `before` edge against the
OAuth router's id: that would refuse to boot for every deployment that runs
federation grants *without* `/oauth/token`, which is a perfectly ordinary thing
to want.

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

A deployment mounting this package wants **at least 45 seconds** of cleanup allowance. The standalone template's default is ten, which is shorter than the upstream hard timeout and persist budget this feature ships with, so a shutdown would abandon exactly the write the drain exists to wait for. HTTP draining and the orchestrator's termination grace are sized separately, and both have to be longer again.

## License

Apache-2.0
