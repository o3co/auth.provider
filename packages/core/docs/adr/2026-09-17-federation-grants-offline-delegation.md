# Federation grants: session-independent delegated access to upstream APIs

- Status: proposed
- Date: 2026-09-17
- Tracks: #593 (the direction, the survey of prior art and two review
  conditions are recorded in that issue's comments; this ADR turns them into
  names, contracts and a build order)

## Context

A background operation — increasingly an AI agent — may pause for days or
weeks and then need to call an upstream API with a user's delegated
permissions. Its lifetime is independent of the interactive session that
started it.

What exists today is session-bound by design, and works as designed:

- Upstream tokens are attached only in the federation login/link callback
  (`packages/session/src/routes/Federation.mts`), keyed by
  `(sid, federationName)` in `FederationTokenStore`.
- Logout deletes them (`cascadeLogout`, and `/session/logout`'s own hygiene),
  and the Redis record defaults to a 24 h TTL.
- `POST /oauth/federation/:name/token` requires a bearer with `family_id`,
  `sid` and `azp`, a live `UserSession`, and a federation linked to that
  session.

Loosening those checks would break the guarantee #276 established: after
logout the provider holds nothing that can act as the user. So this is a new,
explicit lifecycle next to the session-bound path, not a change to it. It is
additive and targets the next minor release.

No standard covers this yet. The IETF has no adopted document for delegation
to agents that outlives a session; the OpenID Foundation calls revocation in
these architectures "largely unsolved"; vendors differ on whether offline
delegation is supported at all. Competing drafts and shipping products do
converge on one shape: an explicit actor, bounded scope, an absolute lifetime
that refresh cannot extend, re-evaluation on every issuance, and revocation
by an identifier that does not require holding a token. The decisions below
follow that shape. What they take from existing RFCs is modest and named where
it is used: RFC 6749's field names, RFC 8707's `resource`, RFC 9126's
intent-first pattern, and the POST-only endpoint style of RFC 7009 and
RFC 7662. RFC 8693 and RFC 9396 are left room for, not used (D9).

## Vocabulary

- **Federation grant** (a *grant* below): a record of one user's consent that
  one client may obtain upstream access tokens through one connection, within
  stated scopes, until a stated time. It owns the upstream refresh credential.
  "Grant" here never means an OAuth grant type; the directory is
  `federation-grants/`, next to `federation-tokens/`.
- **Connection**: a named configuration entry that points at a
  `federations.<name>` section and adds what delegation needs (D4).
- **Intent**: the backend's single-use request to authorize, or reauthorize,
  one grant (D6).
- **Owning client**: the one confidential client a grant names.
- **Residual access**: what an upstream access token that was already handed
  out still allows after the provider has stopped issuing new ones.

## Decisions

### D1 — A grant is a first-class record with its own lifecycle

```ts
type FederationGrantRevokedBy = "client" | "subject" | "operator" | "logout_policy" | "backstop";

interface FederationGrantBase {
	readonly id: string; // opaque, 256 bits, base64url; a reference, not a credential
	readonly subject: string; // the local owner
	readonly clientId: string; // the owning client
	readonly connection: string;
	readonly createdAt: Date;
	readonly version: number; // bumped by every status or credential change (D2)
}

// What an activation writes, and only an activation replaces. These decide who
// may obtain what, until when, and every one of them is inside the sealed
// credential's authenticated envelope (D16).
interface FederationGrantAuthorization {
	readonly identityRevision: string; // D4
	readonly authorizationRevision: string; // D4
	readonly upstream: { readonly issuer: string; readonly subject: string };
	readonly resource?: string;
	readonly scopes: readonly string[]; // granted by the upstream, within consent.scopes
	readonly consent: { readonly at: Date; readonly sid: string; readonly scopes: readonly string[] };
	readonly authorizedAt: Date;
	readonly expiresAt: Date; // set at consent; never moved by a refresh
}

// What changes while a grant is in use, outside any activation and outside the
// envelope: neither decides what the grant allows.
interface FederationGrantUsage {
	readonly lastUsedAt?: Date;
	readonly ineligible?: { reason; at: Date; judgedAgainst: number }; // D5
}

interface FederationGrantRevocation {
	readonly status: "revoked";
	readonly revocation: { readonly by: FederationGrantRevokedBy; readonly at: Date };
}

type FederationGrant =
	| (FederationGrantBase & NeverAuthorized & { readonly status: "pending" })
	| (FederationGrantBase & FederationGrantAuthorization & FederationGrantUsage & {
			readonly status: "active" | "reauthorization_required";
	  })
	// revoked after authorization: keeps every authorization field
	| (FederationGrantBase & FederationGrantAuthorization & FederationGrantUsage &
			FederationGrantRevocation)
	// revoked while `pending`: never had any, and the type forbids them
	| (FederationGrantBase & NeverAuthorized & FederationGrantRevocation);
```

Every exported name says `FederationGrant`: the core barrel already exports
`GrantContext`, `GrantResult` and `GrantPolicy*` for OAuth grant types, which
these are not. `NeverAuthorized` types every authorization and usage field as
`never`, so that a record with `consent` and no `expiresAt` does not compile,
and the narrowing to "has an authorization" cannot promise fields that are not
there.

A grant names exactly one client in the first cut. The issue allows
"client(s)"; one is enough for every case we have, and it keeps isolation
trivially true.

The stored `status` has four values. What a caller is told is an *effective*
status, computed on every read: an `active` grant past its expiry reads as
expired; one whose connection the operator removed reads as
`connection_not_configured`, which removing an entry establishes and a changed
identity it does not; one whose connection's identity changed reads as
`connection_identity_changed`; one whose connection otherwise changed, or
whose credential cannot be opened, reads as `reauthorization_required`; and
one whose upstream stopped issuing eligible tokens reads as
`upstream_token_ineligible` (D5). Computed conditions are never persisted,
so undoing the configuration change, or restoring the key, restores the grant.
Only an upstream `invalid_grant` is persisted as `reauthorization_required`,
because it is a fact about the credential, not about this deployment.

### D2 — Every transition is a guarded write inside the store

A revoked or expired grant must never become usable again. Declaring that is
not enough: the store enforces it at the write.

| event | precondition, evaluated in the store | effect |
| --- | --- | --- |
| lodge first intent | no record is there under the ID, whether or not this caller's clock can see it; the intent has not already lapsed | create `pending`, naming this intent as current; key lives as long as the intent |
| lodge reauthorization intent | the record exists; status is `active` or `reauthorization_required`; `now < expiresAt`; the intent has not already lapsed | name this intent as current, superseding any other; `version` is *not* bumped |
| activate (callback succeeds) | status is `pending`, `active` or `reauthorization_required`; `now` is before the *stored* `expiresAt` unless `pending`; the intent is the grant's current intent and has not lapsed; the *new* `expiresAt` is after `now`, and `expiresAt − consent.at` is within the lifetime ceiling (D3); `consent.at` and `authorizedAt` are not after `now` (D13); unless `pending`, the upstream account and the identity revision are the stored ones (D4, D7) | `active`; replace the authorized fields as a whole; write credentials; clear the ineligibility marker (D5) and the stamp of a failed refresh (D12); retire the intent; `version++` |
| replace credentials (refresh) | status is `active`; `version` equals the one read; `now < expiresAt` | replace credentials as a whole; set or clear the ineligibility marker (D5); clear the stamp of a failed refresh (D12); `version++`; the current intent is left alone |
| note refresh failure | status is `active`; `version` equals the one read; `now < expiresAt` | set the stamp of a failed refresh (D12), its `count` one more than the stamp it replaces when that one is no older than the row window, and `1` otherwise; `version` is *not* bumped; nothing else changes |
| require reauthorization | status is `active`; `version` equals the one read | `reauthorization_required`; delete credentials; clear the stamp; `version++` |
| revoke | the record exists; status is not `revoked` | `revoked`; record `revocation`; delete credentials; clear the stamp; retire the intent; `version++` — one atomic operation that always wins |
| retire intent | status is `active` or `reauthorization_required`; there is a current intent, and it is the named one when one is named | retire the intent; `version` is *not* bumped |
| touch | the record exists; status is `active` | set `lastUsedAt` only, and never back |
| first intent lapses unused | — | the `pending` grant is deleted with it |

Every row is one script that checks the record exists. A bare field write on a
key that has expired or been tombstoned would re-create a partial record with
no TTL.

`revoked`, and expiry by the stored `expiresAt`, are terminal: new consent
means a new grant. One expiry is not terminal, and D11 says so: a grant that
reads as expired only because the operator lowered `maxExpiresIn` (D3) is
usable again if the maximum is raised, always within the bound the user
consented to. The grant ID stays the same across reauthorization from `active`
(a renewal) and from `reauthorization_required`, as the Australian CDR does
with `cdr_arrangement_id`.

A writer whose precondition fails does not use what it fetched. It
re-evaluates D10 from the top: if the winner was another refresh it returns
the stored token, and if the winner was a revocation it answers
`grant_revoked`. It never returns a token it obtained for a grant it could not
write.

`touch` is best-effort: it does not bump `version` and cannot fail a call.

The details of the table are there for a reason each.

- Naming a reauthorization intent does not bump `version`. A refresh in flight
  holds the version it read, and a reauthorization the user may never finish
  must not make it drop the rotated refresh token it is about to store.
- An activation retires the intent, so the same handle cannot activate twice,
  and it refuses an intent that lapsed while the code was being exchanged. The
  connect callback also asks whether the intent is current *before* the
  exchange (D7), which the activation at the end cannot stand in for; the port
  has an operation for that, and the handle is never part of the record a
  client is shown.
- The renewal guard reads the stored `expiresAt` and the ceiling reads the new
  one. With one expiry for both, a new consent could resurrect a grant whose
  consented lifetime had ended. The guard holds for every grant that is not
  `pending` — one that needs the user has a consented lifetime too — and the
  port's "is this intent current?" applies it as well, so that the callback
  does not exchange a code for a grant it can no longer activate, and leave a
  refresh token at the upstream that nothing will use.
- The mirror image of the first point holds too: a refresh, an upstream
  `invalid_grant` and a `touch` leave the current intent alone. A refresh in
  the background must not cost the user the reauthorization they are in the
  middle of.
- An intent can be retired without ending the grant. D13's `"keep"` ends every
  renewal in flight while preserving established grants, and by the time a
  callback has passed its checks the pointer on the grant is the only thing
  left to end. A reauthorization consent that the user declines retires the
  intent it was asked about, and no newer one. A *first* consent that is
  declined retires nothing and revokes nothing: declining spends the intent
  record before any callback can exist, so nothing can reach the activation,
  and the `pending` grant is left to lapse — a tombstone per decline would
  report as revoked a grant that never was.
- A renewal never re-points a grant. The callback checks that the upstream
  account is the grant's (D7), and an identity change is terminal (D4); the
  activation refuses both again, so that one slip in the callback cannot hand
  a grant ID, and the client that holds it, to another upstream account.
- A refused activation leaves an existing grant exactly as it was (D7):
  everything it carries is checked before anything is written. Beside a
  `pending` grant a half-written credential would be invisible; beside an
  active one it would have replaced the user's working refresh token.

Three races are part of the contract suite both adapters run: a callback that
passed its checks and activates after a revocation (it must fail); a refresh in
flight while the grant is revoked (it must not re-create the credential record,
and must not return the token); and a refresh that starts before `expiresAt`
and finishes after it (the write must fail, and no token is returned). "Must
not return the token" is the retrieval's to keep (D10), and is tested there.

Run one after the other, those races prove that the guards exist. They do not
prove that a guard and its write are one step: an adapter that checks and
writes in two round trips passes them. So the suite also runs the conflicting
writes at once: a revocation against an activation, a renewal, a refresh, an
upstream `invalid_grant` and the naming of an intent; two refreshes on one
version, two callbacks on one intent, two lodgings of one ID, two revocations;
and the writes to the intent pointer against each other and against the
activation they would end or supersede. Those last ones matter because naming
and retiring an intent do not bump `version`: an activation that checks the
handle and then writes behind a compare-and-set on `version` passes everything
else, and loses to both. Each pair is started in both orders, because whichever is started first gets
its check in first, and the interleaving that matters — the write checks, the
revocation lands, the write applies — exists only when the write is. The
suite asserts what may be left behind: a revoked grant, exactly one winner,
and never a credential beside a revoked grant.

That last assertion cannot be made through the port. There a grant that is not
`active` reads as having no credential whether the secret was deleted or is
only hidden behind a status check, and a revocation that forgot the delete
would pass with a live refresh token at rest. So the suite requires each
adapter to supply a probe from outside the port — for Redis, whether the
credential key exists — and asks it after the transitions away from `active`,
a revocation past the expiry included, and after refused writes.

### D3 — Expiry is absolute, required, and bounded by the operator

`federationGrants.defaultExpiresIn` and `federationGrants.maxExpiresIn` follow
the rules `oauth.accessToken` got in 0.14.0. Above them sits a one-year
ceiling, `FEDERATION_GRANT_LIFETIME_CEILING_MS`, which is a core constant and
not only a schema rule: a hand-built config bypasses a schema, as #448 showed.
The module refuses at boot a maximum above it, and a requested `expires_in` is
clamped to `min(maxExpiresIn, ceiling)` when the intent is lodged — not
rejected, and not left for `activate` to refuse after the user has already
consented upstream. The response reports the value that applied. `expiresAt` is `consent.at` plus
that value, fixed at consent. A refresh never moves it; only a new consent
does.

At retrieval, lowering the maximum also shortens existing grants:

```
effectiveExpiry = min(grant.expiresAt, grant.consent.at + maxExpiresIn)
```

That is what an operator lowering it means. Nothing that is persisted — key
TTLs, the revocation watermark (D13) — is computed from the configured
maximum, because a value that can be raised again cannot be the basis of a
guarantee. Persisted horizons use the stored `expiresAt` or the core ceiling.

A mandatory expiry is not universal practice: the FAPI Grant Management WG
decided against one, and the UK relaxed its 90-day re-authentication because
of the cost. Hence a required field with an operator-set maximum, and no
fixed cap below the one-year ceiling.

### D4 — Connections are configured by name, with two revisions

```hocon
federationGrants.connections.<name> {
  federation = "<key under federations>"
  scopes = ["openid", "offline_access", "..."] # the ceiling an intent may ask within
  resource = "https://api.example"              # optional, RFC 8707
  authorizationParams { prompt = "consent" }    # allowlisted keys only
  callbackURL = "https://.../session/federation-grants/callback/<name>"
  maxAccessTokenLifetime = 3600                 # seconds, see D5
  allowScopeSubsets = true                      # false: every intent gets the full set (D19)
  boundary = "prod-eu"                          # required; names the environment
}
```

A grant records two fingerprints of the connection it was authorized under:

- **Identity revision**: the upstream issuer and the upstream client ID. When
  it differs, the recorded upstream subject cannot be compared any more — many
  IdPs issue a `sub` per client — so reauthorization could never succeed. The
  grant reads as `connection_identity_changed`, which is terminal: the
  application asks for a new grant.
- **Authorization revision**: `resource`, the sorted `scopes`, `boundary`, and
  the sorted `authorizationParams` (audience and tenant hints live there).
  When it differs the grant reads as `reauthorization_required` /
  `connection_changed`, and is reauthorized in place.

Both are computed at read (D1), so reverting a mistaken edit restores the
grants. Narrowing the scopes changes the revision too; reusing consent across
a narrowing would be sound, but proving "narrower" for every field is not
worth a first cut, and asking again is always safe.

`boundary` is required because the issue asks that separate environments stay
isolated, and an optional field makes isolation opt-in.

A client is pinned to connections by a new `Client` field,
`allowedFederationGrantConnections?: readonly string[]`, absent meaning none.
A list, not a boolean, because "may use delegation" without "through which
connection" is the implicit sharing the issue forbids. A second new field,
`federationGrantRedirectUris?: readonly string[]`, lists where a connect flow
may return. It is separate from `allowedRedirectUris` so that a connect result
never lands on an OAuth callback that does not expect it.

A connection on a `form_post` federation is refused at boot (D7, check 3).

### D5 — Only connections with renewable, bounded tokens are eligible

At authorization, the upstream token response must carry

1. a refresh token, and
2. a finite `expires_in` that does not exceed the connection's
   `maxAccessTokenLifetime`.

"Finite" alone would admit a 30-day access token; the maximum is what turns
residual access (D15) into a number the operator chose. The maximum is
therefore a positive, finite number of seconds itself. Under anything else —
absent from a hand-built config, NaN, zero, or Infinity, which every finite
lifetime is within — no token is eligible, a marker already left stands, and
the grant reads as `upstream_token_ineligible` / `lifetime_over_maximum`
without the upstream being asked. A token with
`expiresAt: null` fails by definition. At authorization a failure stores
nothing but the `pending` grant, which then lapses. GitHub OAuth Apps' classic
tokens fail twice: no expiry and no refresh token. The session-bound endpoint
keeps its `expiresAt: null` behaviour unchanged.

On a refresh the rule is deliberately softer, so that a configuration slip
cannot cost every user a reconnect:

- A refresh response may omit `refresh_token` (RFC 6749 §6); the stored one is
  kept, as the session-bound route already does.
- A rotated refresh token is **always** persisted, even when the access token
  that came with it is ineligible. Discarding the response would discard the
  only valid credential.
- An access token is ineligible when it fails condition 2, or when the scopes
  the refresh response reports are not within `consent.scopes`. The second
  case is real: an IdP that accumulates consent returns, on refresh, every
  scope the user has since granted to the same upstream client, and the
  generic OIDC adapter sends no `scope` on refresh to narrow it.
- An ineligible access token is withheld **and never written**. The call
  answers `upstream_token_ineligible` — unless the token the grant had still
  serves the request, as below — the grant is untouched, and an operator who
  set `maxAccessTokenLifetime` too low fixes it without any user acting.
- The stored access token is kept beside the rotated refresh token when it is
  one that could still be disclosed: eligible under the current maximum,
  alive, and dated believably (D10). What is kept is what the look under the
  lock found, never what the look before the wait found: that one may have
  been replaced meanwhile. A refresh that brought nothing usable must not cost the grant the
  token that worked — a refresh asked for on behalf of one unusual request
  would otherwise starve every ordinary one until the upstream recovers.
  Nothing is lowered by that: the kept token is judged again at every
  disclosure, as any cached token is.

The same predicate guards every disclosure, not only a fresh one (D10). It
judges the lifetime a token was *issued* with, not what remains of it, so a
cached token does not become disclosable merely by ageing below a lowered
maximum. Lowering `maxAccessTokenLifetime` therefore takes effect on the next
call. The sealed credential records, beside the refresh token, the access
token (which may be absent), when it was obtained, its issued lifetime, and
its own `scope` and `token_type`. A refresh response that omits `scope` — or
sends an empty one, which is not a scope — means the grant's `scopes`
(RFC 6749 §6).

A refresh whose answer is not one an adapter should report — no usable access
token, or a field of the wrong type — is ineligible too, as
`malformed_token_response`. The refresh token it came with is kept all the
same, since the rule above does not depend on the rest of the answer being
sound, and the marker below keeps a broken adapter from rotating on every
request.

An ineligible refresh also leaves a non-secret marker on the record:
`{ reason, at, judgedAgainst }`. Without it a starved grant would take the
lock, call the upstream and rotate the refresh token on every `/token` call —
each rotation another chance to lose the credential (D12), and a drain on the
upstream client's rate limit that other grants share. With it:

- `/token` does not ask the upstream until
  `federationGrants.ineligibleRetryAfter` (default 300 s) has passed. Until
  then it answers the stored token while that is good — the marker limits how
  often the upstream is asked, and is no reason to withhold a token that
  works — and `upstream_token_ineligible` from the marker, with
  `retryAfterSeconds`, once it is not;
- the status route reports it, so a grant that cannot yield a token never
  reads as `active`. The converse does not hold, and is not meant to: while a
  kept token lasts, `/token` answers 200 under a status of
  `upstream_token_ineligible`. The status says whether the grant can be
  *refreshed*, which is what an operator has to act on; a client does not
  gate `/token` on it;
- it is cleared by an eligible refresh, by reauthorization, and when the
  connection's `maxAccessTokenLifetime` no longer equals `judgedAgainst`.

The delegated refresh sends the grant's `scopes` (D17). RFC 6749 §6 lets a
refresh ask for a narrower scope, and an IdP that honours it never starves a
narrow grant. The predicate stays as the backstop for the ones that do not.

Not in the first cut: an adapter capability for upstream revocation (RFC 7009
or provider-specific) could admit connections with unbounded token lifetimes
as an explicit opt-in.

### D6 — Acquisition starts with an intent the backend lodges

```
POST /oauth/federation-grants          (client-authenticated)
  connection, sub, redirect_uri, state, [scope], [expires_in], [upstream_sub]
→ 201 { grant_id, status: "pending", connect_uri, connect_expires_in }
```

- `redirect_uri` must be one of the client's `federationGrantRedirectUris`.
- `state` is required; the client binds it to its own user session.
- `scope`, when sent, must be a subset of the connection's `scopes` that keeps
  `openid` (the adapter requires an `id_token`) and keeps `offline_access`
  where the connection lists it. The validated subset is bound to the intent
  and is what consent shows and what is requested upstream. Absent, it is the
  connection's full set. A connection with `allowScopeSubsets = false` refuses
  a subset.
- `upstream_sub`, when the client already knows which upstream account it
  expects, is checked at the callback.
- `connect_uri` is `/session/federation-grants/connect?request=<handle>`. The
  handle is single-use, 256 bits, and lives for 10 minutes.

This is the pattern of RFC 9126 (PAR) and of UK Open Banking's consent
resource, and it is what lets the callback be bound to "the intended subject,
connection, and pending request" as the issue requires. A browser-initiated
start could name any `client_id`; this one cannot.

Reauthorization is the same call on an existing grant:
`POST /oauth/federation-grants/:grantId/reauthorize`. It judges the
*effective* status (D1): it is accepted from `active` and
`reauthorization_required`, and refused for a grant that is `pending`,
expired, reads as `connection_identity_changed`, or whose connection is no
longer configured. It evaluates the
revocation backstop first (D13): a grant that a subject-wide revocation should
have ended is revoked there, not renewed.

A grant has at most one live intent. Lodging another supersedes the older one,
whose callback is then refused as stale. Live first-time intents are bounded
per `(client, subject)` by a constant on the intent port (D16), as
`PENDING_CONSENT_PER_SESSION_LIMIT` bounds parked consents.

A login never creates a grant, and a connect never creates a login link.

### D7 — The connect flow binds its callback, and refuses on any mismatch

**Start.** `GET <connect_uri>` is a cross-site navigation by construction: the
client's site sends the browser to the provider. It therefore does *not* apply
the link start's request-origin check, which refuses `Sec-Fetch-Site:
cross-site` outright, and whose allowlist (`session.csrf.trustedOrigins`) must
not be widened to third-party client origins. The link start needs that check
because it has no consent step. Connect has one (D8), bound to the session,
and that is its CSRF defence, as it is for `/authorize`.

- With no authenticated session, the start redirects to
  `endpoints.login.url?redirect_to=<this request>`, as `/authorize` does.
- With a session whose `sub` is not the intent's `sub`, it answers 403 and
  redirects nowhere.
- With a session that authenticated at or before the subject's sessions
  boundary (D13), it answers 403 `reauthentication_required`, and so does the
  consent answer. A session that a subject-wide revocation has not yet
  reached, or failed to reach, cannot mint a consent dated after the
  watermark. `authTime` never changes, so signing in again is the remedy, and
  the distinct error lets the page say so. The comparison is D13's. A
  watermark that cannot be read fails closed.
- None of these, nor an unknown handle, nor a prefetch, spends the handle.
  The handle is consumed, atomically, when the consent is answered. An
  approval creates the upstream transaction and redirects upstream with
  `state`, `nonce`, PKCE, the intent's scopes, the connection's `resource` and
  its `authorizationParams`. A refusal ends the intent.

The transaction is a single-use record in the intent store (D16), consumed
atomically, with a 10-minute TTL. It is not the one-slot
`req.session.federation` envelope, which a second start overwrites, and not
`fedtx:`, which lives in the express-session store and is read and then
deleted.

**Callback.** `/session/federation-grants/callback/:connection` checks in
order:

1. the transaction exists, names this connection, and its `state` matches; it
   is consumed before the code is exchanged;
2. the intent is still the grant's current intent and has not expired; on a
   reauthorization, the existing grant still passes the revocation backstop
   (D13);
3. the `UserSession` the flow started under is re-read from the store and is
   still live, the browser still presents it, its `sub` is the intent's `sub`,
   and it authenticated after the subject's sessions boundary;
4. the adapter's own validation passes (PKCE, `id_token` signature, `iss`,
   `aud`, `exp`, `nonce`);
5. account binding. On reauthorization the upstream `(issuer, subject)` must
   equal the one on the grant. With `upstream_sub` in the intent it must equal
   that. If the upstream identity is linked to a *different* local subject the
   flow is refused; one linked to nobody is accepted and recorded. That last
   test needs a read-only lookup the Store port lacks: `authenticateByToken`
   carries login semantics, and a Store may stamp a last login or provision a
   user on first sight. So `UserRepository` gains an optional, side-effect-free
   `findSubjectByFederatedIdentity?`. `federationGrants.identityLookup` is
   `"required"` or `"unsupported"`: with the first the module refuses to boot
   when the repository lacks the method, and with the second this one test is
   skipped, by a recorded decision, and the other two still hold;
6. eligibility (D5);
7. scope containment. The scopes the upstream reports must be within
   `consent.scopes`. A response that omits `scope` means "as requested"
   (RFC 6749 §5.1). An upstream that grants more than the user was shown is
   refused, because an upstream token cannot be narrowed after the fact. The
   comparison is exact, on the names the connection configures. An adapter
   whose IdP answers in another vocabulary — Google's `userinfo.*` URLs for
   `email` and `profile`, Entra's resource-qualified names — normalizes them
   before it reports, or its connections fail closed. The generic OIDC adapter
   normalizes nothing, so there the operator configures the scope names
   exactly as the IdP reports them, including any it adds by itself;
8. the guarded activation in D2.

`form_post` federations are not eligible: the session cookie is absent on
their callback, so check 3 cannot run.

**Outcomes.** A failure of check 1 has no trustworthy redirect target and
answers a plain 400 from the provider. Every later failure leaves an existing
grant exactly as it was and redirects to the intent's `redirect_uri` with
`grant_id`, `state` and one of: `access_denied` (the user or the upstream
declined), `reauthentication_required`, `account_mismatch`,
`identity_conflict`, `refresh_token_absent`, `upstream_token_ineligible`,
`scope_exceeded`, `upstream_error`, `temporarily_unavailable`,
`grant_not_authorizable`. Success redirects with `grant_id` and `state`.

The grant ID in the redirect is not proof of anything. Every grant-addressed
route requires `sub` (D9), so a grant that belongs to another user cannot be
adopted by mistake, and the status response carries `upstream` so the client
can see which upstream account it got.

### D8 — Consent is the provider's own, recorded, and never skipped

The upstream's consent screen names auth.provider's upstream client. It says
nothing about which backend client will act, until when, or that this outlives
logout. So the connect start parks a consent challenge: 32 random bytes, bound
to the session that parked it, read and answered by the deployment's page, as
`packages/oauth/src/routes/consent.mts` does for `/authorize`.

It reuses that mechanism and nothing else:

- its own endpoints, `GET` and `POST /session/federation-grants/consent`,
  contributed by the new package, and its own page URL,
  `federationGrants.consent.url`. A deployment may serve both kinds of consent
  from one page;
- its own record, held with the intent in the intent store (D16). Not
  `PendingConsentRecord`, which is shaped for `/authorize`. Not `ConsentStore`:
  a record there would later suppress `/authorize` consent for local scopes,
  confusing two different things the user agreed to.

The page is told the client, the connection, the scopes, the expiry, and that
access continues after logout. What was shown is recorded in `grant.consent`.
Consent is never skipped: not for `firstParty` clients, and not from any
remembered record.

That makes a consent page a prerequisite of this feature. The provider is
headless: it ships no UI, and the login and consent pages are the
deployment's. A deployment whose clients are all first-party may have no
consent page today, and enabling federation grants obliges it to provide one.
The obligation is small — one `GET` to learn what to show, one `POST` to
answer. `federationGrants.consent.url` has no default, unlike
`endpoints.consent.url`, which falls back to `/consent`, and the feature
refuses to boot without it. That is stricter than consent is today, on
purpose. It cannot prove that a page exists; it makes enabling the feature a
recorded statement that one does.
The upstream's own consent screen cannot stand in: it does not name the
client, the expiry, or the fact that this outlives logout.

### D9 — POST-only, client-authenticated routes in a new package

```
POST /oauth/federation-grants                        lodge an intent (D6)
POST /oauth/federation-grants/:grantId/reauthorize   lodge a reauthorization
POST /oauth/federation-grants/:grantId/token         upstream access token (D10)
POST /oauth/federation-grants/:grantId/status        non-secret status
POST /oauth/federation-grants/:grantId/revoke        revoke; 204; idempotent
```

All are `POST`. `createClientAuthMiddleware` reads `client_secret_post`
credentials and `private_key_jwt` assertions from the request body only, and
every route that uses it today is a `POST`. A `GET` or `DELETE` would be open
to `client_secret_basic` clients alone, and #593 tells workers that should not
hold a shared secret to register `private_key_jwt`. RFC 7009 and RFC 7662 made
the same choice for the same reason.

All leave `allowPublicClients` at its default, sit behind a rate-limit guard,
and set `Cache-Control: no-store` on every exit.

Every grant-addressed route requires `sub` and answers the same 404
`grant_not_found` for an unknown ID, another client's grant and a subject
mismatch, so a known grant ID tells a stranger nothing, on any of the four.

The status response carries `grant_id`, the effective `status` with its
reason, `sub`, `client_id`, `connection`, `upstream`, `scope`, `resource`,
`created_at`, `authorized_at`, `expires_at` and `last_used_at`. It evaluates
everything a retrieval does short of contacting the upstream — the revocation
backstop (D13), the revisions, and whether the credential authenticates under
the current key ring, without the tokens leaving the store — and the marker
of D5, so it never reports `active` for a grant that cannot be used. A key
that is not in the ring answers 503 here as it does on `/token`.

The routes ship in a new package, `@o3co/auth-provider-federation-grants`,
which contributes them the way `device-grant` does and answers 404 when
disabled. The port and the in-memory adapter live in core, so that
`revokeAllForSubject` and `/session/logout` can reach them; the Redis adapter
lives in `@o3co/auth-provider-redis`.

An extension grant on `/oauth/token` was considered, because RFC 8693 is the
natural wire shape. It fits this codebase badly: a successful grant must be a
`TokenResponse` and is always audited as `token.issued`, which mislabels an
upstream token; `GrantDependencies` carries no audit sink; error exits get
neither `no-store` nor `WWW-Authenticate`; and a client with
`senderConstrained.required` would have to present DPoP or mTLS proof for a
token that cannot carry `cnf`. The route keeps RFC 6749 field names, so a
token-exchange profile can be added later as a thin facade if a standard
settles. RFC 9396 `authorization_details` is likewise left for later.

### D10 — Every retrieval re-evaluates the grant

`POST …/:grantId/token` takes `sub` (required), and optionally `min_ttl`,
`connection`, `scope` and `resource` as assertions the provider checks. It
evaluates, in order:

1. the grant exists, its `clientId` is the authenticated client, and `sub`
   equals its subject;
2. status is `active`, and `now < effectiveExpiry`;
3. the subject's grants boundary does not cover `consent.at` (D13). A boundary
   that cannot be read answers 503, as `verifyJwt` fails closed;
4. the connection is in the client's `allowedFederationGrantConnections`; an
   asserted `connection` names it; both revisions match (D4);
5. asserted `resource` equals the grant's, and asserted `scope` is within
   `consent.scopes` — checked here so that a request that can never succeed
   does not cost an upstream call.

When more than one of steps 2 to 4 would refuse, what is *reported* goes from
what cannot be undone to what can, so that a client is never sent to a remedy
that cannot work: a stored revocation, then the backstop (before expiry, so
that a revocation which never reached the record is not reported as a mere
expiry), then expiry, then a changed upstream identity, then what a
reauthorization mends, then an upstream that stopped issuing eligible tokens.
The ineligibility marker (D5) only limits how often this route calls the
upstream — so for this route, and not for the status route, it is not where
the evaluation ends. It goes on to step 5, and to the stored token: one that
is good is answered under the marker, and the marker is what is reported
where a refresh would have been needed and its retry interval has not passed.
Once it has, the evaluation goes on to a refresh, or no starved grant would
ever recover. One marker does end it: under a `maxAccessTokenLifetime` that
no token can satisfy nothing is disclosed, and nothing of step 5 can be
judged, since `min_ttl` is held against that maximum.

Two kinds of refusal are neither terminal facts nor remedies the client has,
and their place in that order is fixed too:

- *Configuration* — a connection the client may not use, or one the operator
  removed — comes after a revocation, the backstop and an expiry, and before
  everything else, a changed identity included: a client that may not use the
  connection cannot act on "ask for a new grant" either. A client must not be sent to its operator about a grant
  that is over, so a revoked grant on a removed connection answers 410, and
  never 403.
- *Outages* come where they cannot mask anything. "Not yours", a stored
  revocation and a pending grant are answered from the record alone, before
  the subject's boundary is consulted, so that a boundary that cannot be read
  turns none of them into a 503. A key that is missing from the ring is not a
  status (D1, D16), and it is answered 503 exactly where the evaluation would
  otherwise say `credential_unreadable` — the first point at which the
  credential matters. Everything reported ahead of that is decided without a
  credential, so a missing key masks neither the backstop nor an expiry, and
  the backstop is still made durable under it. The boundary is read
  first and the record last, so that the record — the thing a revocation
  changes — is the freshest thing evaluated, and `now` is sampled after both.

Then it takes the stored upstream access token, or refreshes it (D12) as set
out below. Before any
token is disclosed, cached or fresh, these are checked again: steps 2 and 3,
because a refresh may have straddled the expiry, or a subject-wide revocation
may have stamped its watermark meanwhile without reaching this grant; the
eligibility predicate of D5 against the *current* `maxAccessTokenLifetime`;
and an asserted `scope` against the scopes that token carries, not against
what the grant once got.

"Checked again" means the record is read again. A successful guarded write
proves that the grant was `active` at that instant, and a per-grant
revocation can land while the boundary is being read after it; a token that
has not been disclosed yet is not D15's residual access. So after its own
write the call takes one more look — the boundary, then the record, then the
clock — and discloses what is *stored*, never the token it holds in a
variable. That look never refreshes: a call refreshes at most once. The same
look ends every call that went for a refresh, whatever the attempt came to —
it wrote, it lost, the upstream failed or refused, the caller stopped waiting
at the soft deadline, the lock was not to be had, the lease was spent — and
it answers a stored token that is good and carries what was asked with the
life it has. A refresh is an attempt to improve on the stored token, never a
condition for answering one that is good: an outage improves nothing, and it
must take nothing away. Only where nothing stored serves the request is what
the attempt came to answered — `temporarily_unavailable`, `rate_limited`,
`upstream_rejected`, `lock_timeout` — and the look's own verdicts come before
that: an expiry or a revocation that landed during the upstream call is what
is reported, even when the upstream answered `invalid_grant` and the record
was marked meanwhile. After its own write the token it wrote is answered as
`refreshed` while that is still what is stored; a reauthorization does not
take the refresh lock, and what it stored meanwhile is answered as somebody
else's. A fresh token that is good and lacks an asserted scope answers
`invalid_scope`, after its rotated refresh token was kept: missing what was
asked for is not exceeding the consent.

consent.

**When a stored token is refreshed.** A token is refreshed once it is half
spent and either has run down to `federationGrants.refreshBuffer`, or the
caller wants more than it has: more life (`min_ttl`), or a scope it does not
carry. Before it is half spent it is answered as it is — below `min_ttl` with
its true lifetime, short of an asserted scope as `invalid_scope`. Until then a
refresh has little more life to give, and an upstream that has just left a
scope out is not going to change its mind, while every refresh rotates the
refresh token at an IdP that rotates. Without the bound a client asking an
hour of tokens that are issued for an hour, or a scope the upstream never
puts in a token, or anything at all of tokens issued with less life than the
buffer, would get a rotation on every request: the harm D5's marker exists to
prevent, on a path the marker does not cover, because such a token is
eligible. A naive `min_ttl` is enough to get there; no malice is needed. It
is one rule and no setting: a refresh buffer of zero is a setting an operator
may choose, and must not be a way round it.

What the rule bounds is what a *client* can cause while the upstream answers:
two rotations in a token's lifetime — or, under a standing marker beside a
kept token, one per `ineligibleRetryAfter`. What an upstream that *fails*
costs is bounded by the stamp of D12: one prompt retry, then one attempt per
backoff. And `min_ttl` is a request, never a guarantee:
one above half the lifetime the upstream issues cannot be met for most of a
token's life, and `expires_in` is what tells the caller what it got.

A token that is already dead is never answered, however it was come by. One
that is dated far ahead of `now` is not believed: read as it stands it would
be unspent, and alive, for as long as its date is ahead. "Far" is further
than the refresh buffer absorbs — or than `revocationSkew`, where the buffer
is set to less. Believing a date that is a little ahead costs that the token
is refreshed so much later; not believing it costs a second rotation on the
heels of the first, whenever the replica that refreshed is the one whose
clock is ahead. What believing it can cost is a token answered after the
upstream has let it die, by as much as its date was ahead: where a token
lives less than twice that, and under a marker, where a token is answered
with however little it has. That is a 401 for the worker and nothing
disclosed, and clocks that far apart are the fault to fix. No token is given more life than
it was issued with, whatever its date says. Where the marker of D5 forbids
asking the upstream, a stored token that is good is answered with the life it
has, however little.

This evaluation and the refresh of D12 are one function in core,
`retrieveFederationGrantToken`, written against a structural refresh
interface as the session-bound route's is. The package only maps its typed
result to HTTP. The rule "a writer that loses never returns the token" is
about orchestration, and that is where slice 1 can test it.

`min_ttl` may not exceed the connection's `maxAccessTokenLifetime`; a larger
value is `invalid_request`. A call refreshes at most once. If the fresh token
is still shorter than `min_ttl` it is returned with its true `expires_in`, and
the caller decides.

`expires_in` in the response is `min(token remaining, effectiveExpiry − now)`.
That clamp is a cache hint for a cooperating worker. It is documented as such
and never as enforcement (D15).

### D11 — One typed result, one HTTP mapping

```ts
type FederationGrantTokenResult =
	| { ok: true; accessToken: string; tokenType: string; expiresIn: number;
	    scopes: readonly string[]; // what this token carries
	    refreshed: boolean }
	| ({ ok: false } & FederationGrantDenial);
```

`FederationGrantDenial` is a union of objects, one per row below, so that a
reason cannot be attached to a code that has none.

| `code` | reasons | HTTP | what the application does |
| --- | --- | --- | --- |
| `grant_not_found` | — | 404 | treat as no delegation; never fall back |
| `authorization_pending` | — | 400 | the user has not finished connecting |
| `grant_expired` | `consented_lifetime`, `operator_maximum` | 410 | ask for a new grant; only `operator_maximum` can lift by itself |
| `grant_revoked` | `client`, `subject`, `operator`, `logout_policy`, `backstop` | 410 | terminal. Stop the work and tell the user; offer a fresh authorization, which is a new grant. Never retry, never `/reauthorize` |
| `connection_identity_changed` | — | 410 | terminal while it lasts; ask for a new grant |
| `reauthorization_required` | `upstream_invalid_grant`, `connection_changed`, `credential_unreadable` | 410 | call `/reauthorize`, send the user, retry later |
| `access_denied` | `connection_not_permitted` | 403 | configuration: the client may not use the connection, the operator removed it, or its federation cannot refresh for a grant. Do not retry. Reported after a revocation, the backstop and an expiry, and before a changed identity (D10) |
| `invalid_request` | `connection_mismatch`, `min_ttl_out_of_range` | 400 | the request is malformed; the reason is for an `error_description` |
| `invalid_scope`, `invalid_target` | — | 400 | the request exceeds the grant — or, for `invalid_scope`, the stored token does not carry what was asked for and it is too early to ask the upstream again (D10): a refresh may bring the scope once the token is half spent |
| `upstream_token_ineligible` | `no_finite_lifetime`, `lifetime_over_maximum` | 502 | operator; the grant is untouched; honour `retryAfterSeconds` |
| `upstream_token_ineligible` | `malformed_token_response` | 502 | operator: the federation adapter reported an answer without a usable access token, or with a field of the wrong type. The grant is untouched; honour `retryAfterSeconds` |
| `upstream_token_ineligible` | `scope_exceeded` | 502 | no operator action un-accumulates consent: `/reauthorize` for the wider set, or a new grant on a connection of its own (D19) |
| `upstream_rejected` | the upstream's error code, or `unknown` | 502 | operator, e.g. an expired upstream client secret; the grant is untouched. Answered from the stamp of a failed refresh (D12) it carries `retryAfterSeconds`, and is answered only where nothing stored serves the request (D10). The code is repeated only when it is one of the RFC 6749, RFC 6750, RFC 8707 and OpenID Connect codes this provider knows, and is `unknown` otherwise — an allow-list, because any pattern that fits `invalid_client` fits an opaque token as well, and an upstream that echoes what it was sent must not get a refresh token repeated through this field |
| `rate_limited` | `provider`, `upstream` | 429 | retry after `Retry-After`. `upstream` is answered only where nothing stored serves the request (D10) |
| `temporarily_unavailable` | `upstream`, `storage`, `lock_timeout`, `concurrent_update`, `key_unavailable` | 503 | retry; the grant is untouched. Each of these is answered only where nothing stored serves the request (D10). `concurrent_update`: this call's refresh was overtaken — its guarded write lost, or what it wrote was replaced before the last look — and what is stored now is nothing to answer with |

410 follows the session-bound endpoint's `re_authentication_required`. Only an
upstream `invalid_grant` and a revocation change a grant. No other outcome
changes its status or deletes anything, and no code path substitutes another
subject's grant or an application-wide credential.

### D12 — Refresh is coordinated per grant, and fails safe

The session-bound lock cannot be reused as it is: it is typed to
`(sid, federationName)`, its TTL is a 5 s default the route never overrides,
with no renewal, and the write after it is an unconditional `SET`. With a rotating upstream, a lock that
expires mid-refresh lets two replicas present the same refresh token, which a
reuse-detecting IdP answers by revoking the family.

- The lock is keyed by grant ID and added beside `internal/lock.mts`, not
  refactored into it. Its TTL is configurable
  (`federationGrants.refreshLockTtlMs`, default 30 s).
- A slow upstream must not cost users their grants. No federation adapter
  sets a timeout and `refreshToken()` takes no signal, while `openid-client`
  applies its own 30 s default underneath. Giving up at 10 s and dropping the
  late response would, against a rotating IdP, turn every refresh during a
  latency incident into `invalid_grant` on the retry. So:
  - `federationGrants.upstreamTimeoutMs` (default 10 s) is a *soft*
    deadline. It bounds only how long the worker's call waits before it is
    answered `temporarily_unavailable` / `upstream`. The upstream request is
    not aborted: aborting a token request does not undo a rotation at the IdP,
    it only guarantees the new credential is never received;
  - the request goes on, holding the lock, and its result is offered to the
    guarded write of D2 whenever it arrives. D2's preconditions keep a late
    write from landing after a revocation or the expiry;
  - `federationGrants.upstreamHardTimeoutMs` (default 25 s) is where the
    delegated refresh's `signal` (D17) does abort. Past it the outcome is
    unknown. It is audited like the persist failure below, and the caller —
    answered at the soft deadline already — is told `upstream`, which is
    where the failure was;
  - the lock has no renewal, so "until the call settles" is only true if
    settling always comes first. `assertFederationGrantRetrievalLimits`, which
    the package calls at boot (slice 4), requires
    `upstreamHardTimeoutMs + persistRetryBudgetMs + 1 s <= refreshLockTtlMs`
    (defaults 25 s + 3 s + 1 s <= 30 s). The second is a margin: the lease is
    counted from a lower bound on when the store started the TTL, and timers
    fire late, so a configuration that fits by a millisecond does not fit. All
    three are this provider's
    configuration; nothing depends on an adapter's internals. It validates
    every other limit of the retrieval too — NaN compares as fine everywhere,
    and a NaN retry interval switches the marker's limit off.
- After acquiring the lock the record is re-read; another replica may have
  refreshed already.
- The lease has one clock, started when the store TOOK the lock: when the
  lock was asked for, plus how long the store says it waited before it took
  it (`waitedMs` in the lock's reply — a duration, so that it means the same
  on the caller's clock as on the store's; a `now` read in whole seconds is
  allowed the lock's margin over the round trip). Not when the acquisition was
  acknowledged: an acknowledgement that took a second would overstate what
  is left of the lock by that second, and a slow enough one lets a second
  holder in while the first still refreshes — two refreshes presenting one
  refresh token, which is what the lock exists to prevent. Every deadline
  counts from there and not from the upstream call: what a call spends under
  the lock before it asks the upstream — the re-read above — is spent of the
  same lease, and an inequality between configured durations bounds nothing
  if each of them starts when it likes. A store whose reply does not say how
  long it waited, or says it waited longer than the whole round trip, is not
  one to run a refresh on: the lock is let go of and the caller is told
  `storage`.
- The upstream is not asked at all once that re-read has used up the soft
  deadline — or more: the whole lease, when a read hung through a store
  failover. A rotation started then is one nobody waits for, run toward a
  deadline it no longer has the time to meet, perhaps under a lock that has
  already run out while another replica presents the same refresh token. The
  call answers `temporarily_unavailable` / `storage` — the upstream was never
  asked, and what was slow is the look under the lock — tells the logger so,
  and lets go of the lock.
- A call waits `federationGrants.lockWaitMs` (default 5 s) for another
  replica's refresh, then looks once more and answers. The store is told how
  long to wait and is not trusted to keep to it: three seconds past that the
  call answers `storage`, and a lock that arrives afterwards, for nobody, is
  let go of. Nothing relates `lockWaitMs` to the lock's TTL: after an outcome
  that is unknown (below) the lock is left to run out, and until it has, every
  call that needs a refresh answers `lock_timeout` after waiting this long.
- One worker owns the upstream call and the guarded write. Its tail — letting
  go of the lock, and then telling the audit sink, in that order — and, when
  the caller stopped waiting at the soft deadline, the worker itself, are
  handed to a `background` seam that whoever composes the retrieval must
  supply, so that a shutdown can drain them and a test can await them. One
  thing is detached any other way: the wait for a lock that was given up on,
  which may never arrive, while what is handed over has to settle. Letting go
  of that lock, once it has arrived, is handed over like any other release:
  bounded, and reported when it fails. Nothing is audited while the lock is held, and no
  answer waits for the sink, for the release, or for the record of a use: a
  sink that hangs must hold no lock, and a lock that is slow to let go of must
  not turn a refresh that was persisted into an outage. What is handed over
  waits for a sink, a `touch` or a release for three seconds and no longer,
  so that nothing handed over can fail to settle: a registry would hold it for
  ever, and a shutdown would never finish draining.
- At the hard deadline the worker aborts and stops accepting a result,
  whether or not the abort ever settles. A write that hangs is not waited for
  past the persist budget; if it lands later it is still guarded by the
  version.
- While something of a call's is still *in flight* the lock is left to run
  out instead of being let go of: an upstream request that was aborted, a
  write still going at the end of its budget, and a worker that failed in a
  way nobody foresaw once the upstream may have been asked. Whoever acquired
  the lock next would present the stored refresh token, the old one, beside
  an operation that is about to replace it, and an IdP that detects reuse
  answers that by revoking the family, the new token included. The price is
  that other callers wait out what is left of the lock, while the store or
  the upstream is failing anyway.
- An upstream failure that *arrived* is not that, whatever it was — a refusal,
  a 5xx, a connection that failed, an answer that could not be parsed, an
  error nobody can read — and the lock is let go of. Nothing of the call's is
  in flight any more. If the IdP rotated before its answer was lost, the old
  refresh token is presented again whenever the next refresh comes, and
  waiting out the lock changes nothing about that; an IdP that keeps a grace
  window for exactly this takes a prompt retry and not a late one; and one
  transient 503 would otherwise cost every caller of the grant the lock's
  whole TTL. How *often* a failing upstream is asked is a matter of rate, and
  of slice 1d.
- Wherever a cause is turned into a typed answer it is handed to a `report`
  seam, for a logger that redacts: a 503 says that something failed, and an
  operator needs to know what. Nothing handed there reaches a response.
- A write that throws may have landed with only its acknowledgement lost. The
  retry is then refused on the version that write bumped. It is not forced
  through. One look, still under the lock and spent of the same persist
  budget — the lock is sized for one — tells whose write it was: the call's
  own when what is stored is what it tried to store, the marker beside the
  credentials included — two replicas can come to store the very same
  credentials, and the marker is dated. Then it is a refresh like
  any other — audited as `.refreshed`, answered as `refreshed` — and otherwise
  it is a write that lost.
- The write is the guarded "replace credentials" of D2, in one Lua script.
- `classifyFederationRefreshError`, today a private function of the
  session-bound route, moves to core and both routes import it. For a grant,
  only a *structured* `invalid_grant` or `invalid_token` requires
  reauthorization and deletes credentials. The classifier's substring fallback
  never does; it maps to `upstream_rejected`. 429 and 5xx/network failures
  change nothing in the record.
- If the upstream refresh succeeds but the replacement cannot be persisted
  after bounded retries inside the lock, the call answers
  `temporarily_unavailable` / `storage`, the new credentials are dropped, and
  `federation.grant.refresh_persist_failed` is audited. The stored refresh
  credential is *not* assumed to be still good: the next refresh decides, and
  an `invalid_grant` there becomes `reauthorization_required`.
- **A failed refresh is remembered.** Every failure that arrived, other than
  the structured `invalid_grant` that marks the grant, leaves a non-secret
  stamp on the record — `{ at, kind, count, retryAfterSeconds?, upstreamCode? }`,
  written under the lock by one guarded script that bumps no version and
  touches nothing else, and cleared by whatever replaces or ends the
  credentials (D2). A refresh whose answer could not be persisted leaves one
  too, best effort, with what is left of the persist budget and not a
  millisecond past it: the store is what failed, and a stamp written past
  the lease could land under the next holder. While the stamp stands the
  upstream is not asked: a stored token that serves the request is answered
  as it is (D10), and otherwise the failure is, with what is left of the
  wait as `retryAfterSeconds` — `temporarily_unavailable` / `upstream`,
  `rate_limited` / `upstream`, or `upstream_rejected` with the code the
  upstream gave. The marker of D5 comes first where both stand. Without the
  stamp every request that needs a refresh asks a failing upstream again, and
  N polls during an incident are N upstream calls: the lock serializes them,
  it does not deduplicate them. With it, a waiter that acquires the lock after
  the holder failed finds the stamp, and asks nothing unless the stamp is the
  first of a row and the prompt retry below is its to make.
  - What the stamp waits depends on what failed. An *outage* — a 5xx, a
    connection that failed, an answer nobody could read — is retried promptly
    ONCE: the request may have been processed and its answer lost, and an IdP
    that keeps a grace window for exactly that takes the old refresh token
    back on the next attempt, not a late one; from the second failure in a
    row, `federationGrants.refreshFailureBackoff` (default 30 s). A *rate
    limit* is remembered at once, for the upstream's advice, never less than
    the backoff and never more than `ineligibleRetryAfter`: a 429 was not
    processed, and there is nothing to recover promptly; the failing caller
    is told the same capped wait as the next. A *refusal* with a code this
    provider knows is remembered for `ineligibleRetryAfter`: a configuration
    fault is the marker's class of problem, and gets the marker's interval —
    except `server_error` and `temporarily_unavailable`, which RFC 6749
    §4.1.2.1 names for an outage, and which are one whatever status they came
    with. The count is what tells the first outage from the second; a refresh
    that wrote forgets it, and so does time: failures further apart than
    `ineligibleRetryAfter` are not a row, so a day-old stamp does not cost
    today's outage its prompt retry. The failing caller is told the wait the
    stamp will tell the next one, computed the same way, whether or not the
    stamp lands. `refreshFailureBackoff` may not exceed `ineligibleRetryAfter`,
    and the ceiling bounds what the stamp does, not only what is told.
  - The stamp is outside the authenticated envelope, as the marker is: one
    dated further ahead than the refresh buffer absorbs is not believed — as
    a marker is not — and never re-read "from now", which would let it stand
    until its date caught up.

This does not claim exactly-once behaviour across an external IdP. It claims
that isolation holds and that every ambiguous outcome resolves toward asking
the user again.

### D13 — Revocation is persisted on the grant; the watermark is the backstop

There are three entry points, and ordinary logout is not one of them.

- **Per grant.** `POST …/:grantId/revoke` for the owning client, and a library
  function `revokeFederationGrant(deps, grantId, by)` for the operator's Store.
  There is no admin route: the provider mounts none today ("a library call a
  Store makes rather than a route this server mounts"), and this follows that.
  A second library function, `listFederationGrantsForSubject(deps, subject)`,
  is what lets a Store offer users a "connected applications" page; without it
  the user has no direct way to withdraw a grant.
- **Per subject.** A subject-wide revocation ends the subject's grants. A
  Store may keep them across a routine credential change, through the service
  described below and nowhere else. The free function `revokeAllForSubject`
  gains an optional `federationGrantStore`. A throw from it is a `failures`
  entry with `capability: "federationGrantStore"`, the grant stays enumerable
  for a retry, and `complete` accounts for it.
- **At logout, by policy.** See D14.

Revocation is the atomic, always-winning write of D2. Deleting the refresh
credential is what makes it irreversible; nothing about it depends on a TTL.
An outage is surfaced as 503 or as a `failures` entry, never swallowed the way
`routes/revoke.mts` swallows a `revokeFamily` throw.

**Two boundaries, one default.** A password change and "revoke everything" are
different events, and the industry treats them so. In Microsoft Entra's own
table, after "Password changed by user" a confidential client's token "Stays
alive", and only "User revokes their refresh tokens" revokes every class.
Google revokes on a password change for some scopes only. Ending every
delegation on every password change also puts the price in the wrong place:
each agent and each paused job then needs a new login, a new grant, a new
consent and a new upstream authorization. So the subject watermark becomes
two:

- the **sessions boundary**, which is today's watermark: sessions, and the
  provider's own tokens, issued before it are dead;
- the **grants boundary**: federation grants consented before it are dead.

`SubjectRevocation.revokeBefore`, the existing method, advances **both**. Every
existing caller, a Store that upgrades without touching its call site, and
anything that stamps the watermark directly therefore end the subject's
grants, exactly as one watermark would. Keeping grants is the narrower, new
operation, and it takes a deliberate call:

```ts
interface SupportsSessionsOnlyRevocation {
	revokeSessionsBefore(subject: string, before: Date, expiresAt: Date): Promise<void>;
	grantsRevokedBefore(subject: string): Promise<Date | null>;
}
```

The two boundaries are two fields of **one record**, advanced by one atomic,
monotonic write. Two separate writes would open a window between them: with
the grants boundary written and the sessions boundary still to come, a session
that should already be dead could consent, and that consent would be dated
after the grants boundary and escape the backstop for good. The Redis script
is atomic for one key only, so it stays one key, `ss:rev:<subject>`, now
holding both fields; a value written before this change, a lone number, reads
as both boundaries.

It is a capability, detected by method presence like the others, and both
built-in adapters implement it. With federation grants enabled it is
**required**: boot refuses a `SubjectRevocation` adapter without it. Method
absence could only change which watermark is read. It could not enforce
retention, and a custom adapter that accepts whatever expiry its caller picks
would let a short direct stamp lapse under a long-lived grant. So the
capability's contract includes the retention floor below, applied inside
`revokeBefore` by the adapter and checked by the adapter contract suite, which
makes a direct stamp as safe as the helper's. A deployment that does not use
grants is unaffected, whatever its adapter.

The free function `revokeAllForSubject` always revokes: it stamps both
boundaries first, then cascades the sessions, then lists the subject's grants,
`pending` ones included, and revokes each. It has no way to keep anything.

Keeping is offered only by a **subject revocation service**, a component that
a module factory builds from the validated configuration and the wired
dependencies: the stores, the session cascade, the grant store, the retention
rules. A boolean that the Store itself hands to a helper would be a convention
among trusted callers, not a control, so the operator's allowance
(`federationGrants.allowKeepOnSubjectRevocation`, default `false`) is read
where the Store cannot supply it. The service also always has the grant store,
so the Store that forgets to pass it no longer exists. Its call takes
`federationGrants?: "revoke" | "keep"`, default `"revoke"`:

- **`"revoke"`** is the free function's behaviour.
- **`"keep"`**, when the operator allows it, advances the sessions boundary
  only and preserves the subject's *established* grants. It does not preserve
  anything in flight: every `pending` grant is revoked, and every outstanding
  intent and connect transaction of the subject is invalidated, so that a
  callback which passed its session check before the stamp cannot finish a
  grant or a renewal after it. When the operator does not allow it the service
  revokes, and says so in its result. It never keeps silently, and it never
  falls back silently.
  One window stays open, as wide as two replicas' clocks disagree. A `pending`
  grant within that much of its intent's lapse is already gone for a pass
  whose clock is ahead — it is not listed, and revoking it changes nothing —
  while a callback on a correct clock may still activate it. Under `"revoke"`
  the backstop closes this, since the consent predates the boundary. Under
  `"keep"` nothing does. It needs a callback that passed its session check
  before the stamp, an intent in its last second, and a skewed clock, and it
  is recorded here and not engineered around.
- With `"keep"`, an optional `revokeGrantsConsentedSince: Date` still revokes
  the grants consented at or after that instant — the window in which a
  session thief would have been creating them. It is a heuristic. The grants
  boundary can say "before", not "since", so this runs on the primary path
  only; a failure is reported like any other and leaves nothing worse off than
  not asking.

`"keep"` is a decision per call and not a deployment-wide setting, because the
provider cannot tell a routine change from a recovery: `revokeAllForSubject`
is called for both. The Store owns both flows and can tell.

The reason the default is `"revoke"` is also the reason to be careful with
`"keep"`. A grant is consented through a session, and session-bound consent
proves possession of the session, not the intent of its owner. Whoever held a
stolen session could, with a cooperating or controlled client, have created or
renewed a grant, and `"keep"` lets an established one survive the password
change. Proving the current credential justifies calling the change routine.
It does not prove that the grants already there are benign, and clients being
first-party is no proof either. So the documentation says when `"keep"` is
sound — a change the signed-in user made after proving the current credential
— and when it is not: a reset, a forced change, a suspected compromise, a
disablement. It tells the Store to show the user which applications keep
their access, which `listFederationGrantsForSubject` is there for, and to use
`revokeGrantsConsentedSince` when it has any reason to doubt the recent past. And it tells applications what
to do on `grant_revoked` with reason `subject` or `backstop`: stop the work,
tell the user why, and offer a fresh authorization. Not a retry and not
`/reauthorize`: revocation is terminal (D2), so that is a new grant with a new
ID.

Global Token Revocation, OpenID Provider Commands' Invalidate and Entra's
explicit revocation are comprehensive, offline access included, and that is
what `"revoke"` remains. RFC 9700 §4.14.2 only *permits* revocation on a
password change. A suspend-and-reconfirm design was also considered and
dropped: the provider is headless, so the confirming click would need one more
page from every deployment, and agents would stay stopped until the user came
back to press it.

**The backstop.** `"revoke"` stamps the boundaries first, as the helper does
now. D10 step 3 and the status route compare the grants boundary with the
grant's `consent.at`. Not with a token's `iat`: a token minted from a
surviving grant is always fresh. And not with `authorizedAt`: consent precedes
the callback by up to ten minutes, and a callback landing just after the
boundary must not hide a consent given before it. The comparison is inclusive
and adds `subjectRevocationSkewMs` — the 1 s allowance `verify.mts` applies to
the watermark, which becomes an exported constant — and not the 5-minute
`clockSkewMs`, which would refuse the re-login a revocation sends the user to.
A hit revokes that grant durably, with `by: "backstop"`. When that write
cannot be made the call answers 503 and not 410: the watermark would make the
denial sound, and a revocation outage is one of the things this section says
must surface. A write that changes nothing — somebody else revoked the grant
meanwhile — leaves the answer as it is.

Reauthorization must not launder a revocation that was stamped but never
reached the grant. A new consent replaces `consent.at`, and with it the only
evidence the backstop has. So the backstop is evaluated on the existing grant
when a reauthorization intent is lodged, and again in the callback before the
authorized fields are replaced (D6, D7). A hit revokes the grant and ends the
flow.

D7's session test uses the *sessions* boundary with the same comparison, so it
holds after a `"keep"` as well, and a login within that second cannot connect
for that session's life.

The boundary's retention cannot be computed from the configured maximum: a
grant consented under a long maximum survives the maximum being lowered,
revoked with a part-way failure, and raised again. So retention depends
neither on configuration nor on what the caller passes:

```
expiresAt = at + max(watermarkTtlMs, SUBJECT_REVOCATION_MIN_RETENTION_MS)
```

`SUBJECT_REVOCATION_MIN_RETENTION_MS` is the one-year ceiling plus a fixed
one-minute margin, and `revokeBefore` gets it unconditionally. Any grant the
boundary covers was consented no later than `at` plus the skew and the
rounding to seconds, both far inside the margin, and its `expiresAt` is at
most `consent.at` plus one year. So it cannot outlive the boundary, whatever
the operator does to the configuration, and whether or not the Store passed
the grant store. Both adapters already refuse to shorten an in-force
watermark, so a later sessions-only stamp cannot undo it, and a `"keep"` never
moves the grants boundary back: a grant that an earlier revocation should have
ended stays ended. The cost is one small key per revoked subject for a year.

A sessions-only stamp needs no one-year floor, but it is not free of one. D7
relies on the sessions boundary to refuse a session that a cascade missed, so
the boundary has to outlast that session, and today's rule sizes it to refresh
tokens alone. `resolveSubjectRevocationHorizonMs(config)` is the longer of the
refresh-token lifetime and the user-session lifetime, plus the comparison's
allowances, and the service applies it as the floor of a sessions-only stamp.

Two things make that true by construction and not by convention:

- **The ceiling is a core constant, enforced at the write.** The config schema
  caps `federationGrants.maxExpiresIn` at one year, but a hand-built config
  bypasses a schema, as #448 showed. So `FEDERATION_GRANT_LIFETIME_CEILING_MS`
  lives in core (D3), `activate` refuses a lifetime beyond it (D2),
  `SUBJECT_REVOCATION_MIN_RETENTION_MS` is defined from it, and a test pins
  the relation.
- **The boundary must exist, and must last as long as the grants do.**
  `subjectRevocation` is an optional slot, and a deployment may declare it
  unsupported. With federation grants enabled that is refused at boot, as
  `device-grant` refuses to start without a rate limiter. So is a durable
  grant store beside the in-memory `subjectRevocation`, whose watermark is a
  process-local map: a restart would drop the boundary and keep the grants.

What remains is the stamp itself. It is a store write, and it can fail. The
helper then records a `failures` entry, reports `complete: false`, and still
runs the per-subject pass. A Store has to check `complete` and retry, as it
already must for sessions and tokens. The guarantee holds from the moment a
stamp succeeds.

So the per-subject pass is what makes revocation prompt and deletes the
credentials at once, and the backstop is what holds when that pass does not
run or does not finish. A Store that upgrades without touching its
`revokeAllForSubject` call site is covered by the backstop, not silently
exempt. One window remains and D7 closes it: a consent given through a session
that the revocation has not reached would be dated after the boundary, so such
a session cannot consent at all. The primary path alone fails when a store
write fails part-way. The boundary alone would make revocation depend on a
TTL, which today is sized to refresh tokens. Hence both.

`RevokeAllForSubjectCapability` and the failure `operation` union gain
members, so a caller that switches exhaustively on them needs a new case. That
is accepted here, because an unreported grant failure is worse. D14 declines
the same trade for `cascadeLogout`.

### D14 — Grants survive logout; a logout policy is designed, and deferred

By default session expiry, local logout and upstream logout leave a grant
alone. That is what offline access means, and OIDC Back-Channel Logout 1.0
§2.7 says the same of refresh tokens issued with `offline_access`. Logout
still deletes every session-bound `(sid, federation)` record, so #276 holds.

A policy that also ends the subject's grants at logout is **not in the first
release**. It is additive and off by default, so shipping it later breaks
nothing. It waits because it edits both logout paths that #276 hardened, and
the first release already has its safety valve in the per-grant and
per-subject revocations. Until then, a Store that wants logout to end
delegations calls `listFederationGrantsForSubject` and `revokeFederationGrant`
from its own logout flow. The design is recorded here so that the later slice
starts from it.

`federationGrants.revokeOnLogout` (default `false`) would make logout revoke
the subject's grants as well. The two logout endpoints can honour it
differently, and the documentation will say so:

- `/oauth/logout` runs it before `userSessionStore.delete`, using
  `session.sub`. A failure answers 503 without ending the browser session, so
  a retry still has its cookie. It is a step in the route, not inside
  `cascadeLogout`, which has no `sub`, would repeat it per `sid` under
  `revokeAllForSubject`, and whose `step` union callers switch on
  exhaustively.
- `/session/logout` cleans up its records best-effort: a failure there is
  logged and never propagated, by contract. Its only 5xx is a failed session
  destroy, which comes after the records are gone. So it has no way to report
  a failed grant revocation as something to retry. A deployment that needs the
  guarantee sends logout through `/oauth/logout`.

Subject disablement and consent withdrawal are the Store's events: it calls
`revokeAllForSubject` or `revokeFederationGrant`. The provider cannot receive
upstream logout or security events today, so an upstream account being
disabled is seen only as `invalid_grant` on the next refresh. A Shared Signals
receiver could map such events to per-subject revocation later.

### D15 — "Retrieval stops" and "residual access" are separate boundaries

| event | retrieval | residual access |
| --- | --- | --- |
| grant expires or is revoked | stops immediately; the provider enforces it | tokens already disclosed work until their upstream expiry, at most `maxAccessTokenLifetime` |
| upstream revokes the refresh token | stops at the next refresh | the same |

The provider cannot shorten residual access. A shorter `expires_in` does not
make a token expire sooner at the upstream API. D5 is what bounds it. The
documentation states both boundaries for each event and does not describe the
clamp in D10 as a security control.

### D16 — Storage: bound, sealed, and never self-deleting

The port follows `ConsentStore` (#589), not `FederationTokenStore`: a shared
contract suite that both adapters run, and a key TTL that is only a safety
net. Unlike `ConsentStore` it takes the time from its caller. Slice 1 settled
the grant half; the key layout below illustrates the contract, and slice 3
settles its names.

```ts
interface FederationGrantStore {
	readonly kind: string;
	createPending(input: { id; subject; clientId; connection; intent: { handle; expiresAt }; now }): Promise<FederationGrantWrite>;
	nameIntent(input: { grantId; intent: { handle; expiresAt }; now }): Promise<FederationGrantWrite>; // a reauthorization's; supersedes
	isCurrentIntent(grantId: string, handle: string, now: Date): Promise<boolean>; // D7, before the code exchange; spends nothing
	retireIntent(input: { grantId; handle?; now }): Promise<FederationGrantWrite>; // ends a renewal in flight, not the grant
	find(grantId: string, now: Date): Promise<FederationGrant | null>;
	listBySubject(subject: string, now: Date): Promise<readonly FederationGrant[]>;
	inspect(grantId: string, now: Date): Promise<{ grant; credentials: "ok" | "absent" | "unreadable" | "key_unavailable" } | null>; // for the status route; returns no token
	open(grantId: string, now: Date): Promise<{ grant; credentials: { state: "ok"; value } | { state: "absent" | "unreadable" | "key_unavailable" } } | null>;
	activate(input: { grantId; intentHandle; authorization: FederationGrantAuthorization; credentials; now }): Promise<FederationGrantWrite>;
	replaceCredentials(input: { grantId; expectedVersion; credentials; ineligible: Marker | null; now }): Promise<FederationGrantWrite>;
	requireReauthorization(input: { grantId; expectedVersion; now }): Promise<FederationGrantWrite>;
	revoke(grantId: string, by: FederationGrantRevokedBy, at: Date): Promise<FederationGrantWrite>; // `ok`: whether it changed anything
	touch(grantId: string, at: Date): Promise<void>;
	acquireRefreshLock(grantId: string, options: { ttlMs: number; waitForMs: number }): Promise<FederationGrantLockResult>;
}

type FederationGrantWrite = { ok: true; grant: FederationGrant } | { ok: false };
```

- **The intents are a second port.** The intent records — redirect URI, scopes,
  consent challenge — the connect transactions and the bound on live intents
  arrive with acquisition (slice 6), as `FederationGrantIntentStore`. The
  layout below already keeps them under another hash tag and needs no
  atomicity between the two, so a single `lodge` could never be one step in
  Redis; it would be two writes whose order each adapter chose for itself.
  Core orders them once. What a grant record knows of an intent is a pointer:
  its handle, and when it lapses.
- **A credential is read with its record, as one snapshot.** `open` and
  `inspect` take the grant ID and return the record they read beside the
  credential's state, and the caller evaluates *that* record. Handing the
  adapter a record read earlier would let a concurrent activation make a good
  credential read as unreadable, since the binding below is recomputed from
  the record; opening by ID and returning the credential alone would hand
  back credentials for an authorization the caller never evaluated.
- **A failed write carries no reason.** The record may change again before the
  caller looks, so D2 has it re-read and re-evaluate whatever the reason was;
  and a reason on the port would oblige two adapters to agree on which one
  wins when several preconditions fail at once.
- **Every operation on a record takes the time from its caller**, sampled at
  the write and not at the start of the request; the race across `expiresAt`
  depends on that. So do the reads: a `pending` grant whose intent has lapsed
  reads as absent, and a credential is never returned from the stored
  `expiresAt` on, whatever TTL its key still has. A time that is not a date is
  refused and not compared — every comparison with NaN is false, and the
  record would read as lapsed.
- **Two clocks, kept apart.** What a caller is told is judged on the time it
  passes. What an adapter reclaims is judged on the adapter's own clock, as a
  key TTL is. A `now` that is wrong for one call is then told the wrong thing
  once, and costs nothing: no operation, read or write, deletes anything
  because of the time its caller passed — "the key has lapsed, so delete it
  while we are here" is what this forbids. An ID is taken for as long as a
  record is there under it, not for as long as the caller can see it. The
  in-memory adapter follows the same rule, so that the two agree on it.
- **An activation's dates are bounded against the write.** `consent.at` and
  `authorizedAt` may not be after `now`, with no allowance. The backstop of
  D13 compares the consent with a boundary, and a boundary stamped from the
  activation on must always cover it. That comparison has its own allowance
  for two replicas' clocks (`subjectRevocationSkewMs`); any added here would
  come on top of it, and a consent dated thirty seconds ahead would slip past
  a revocation stamped ten seconds after the activation — for good, since
  neither instant ever changes. A consent precedes its callback by two
  redirects and a code exchange, so replicas that disagree by more than that
  refuse the activation, and the user connects again.
- **The handle is opaque to the store**, which compares it and does nothing
  else with it. Core may hand over a digest in place of the value the browser
  carries; slice 6 decides.
- **The lock is part of the port**, so the in-memory adapter and the contract
  suite cover it too.
- **Records are handed out and taken in as copies.**

Redis layout, default prefix `fg:`. Keys that one script touches share a
Cluster hash tag, as the consent store's do:

- `fg:{<id>}:grant` — a HASH of non-secret fields, `status`, `version`, and the
  current intent's handle with its expiry.
- `fg:{<id>}:cred` — one AES-256-GCM ciphertext of the upstream tokens,
  reusing `internal/crypto.mts`.
- `fg:{<id>}:lock`.
- `fg:sub:<subject>` — a ZSET index scored by the instant the record stops
  answering, which is what the record's own key TTL is set to: the intent's
  expiry while the grant is `pending`, the stored `expiresAt` plus the
  tombstone retention once it is authorized, the revocation plus the retention
  for one revoked while `pending`. Scored by `expiresAt` alone, a listing
  would drop the tombstones that `find` still answers for, and the contract
  suite holds the two to the same set. Written before the record; a dangling
  entry is tolerated and pruned.
- `fg:{intents}:<handle>`, `fg:{intents}:tx:<state>` and the per
  `(client, subject)` counter, each with its own TTL. They share one constant
  tag, as the consent store's parked requests do, so the bound is enforced
  atomically among intents. Nothing needs atomicity across the two tags:
  supersession is enforced at activation, by the grant's current-intent
  pointer (D2).

Key TTLs come from the stored `expiresAt`, never from `effectiveExpiry`, which
depends on configuration (D3). The grant HASH keeps a tombstone retention
beyond that (`federationGrants.tombstoneRetention`, default 30 days), so a
revoked or expired grant still answers the status route. A revocation moves
no horizon: an authorized grant is retained from its expiry whenever it was
revoked. The credential key gets no such retention. A `pending` grant lives as
long as its intent, with no retention; one revoked while `pending` has no
expiry, and is retained from its revocation. The
refresh buffer is 30 s, as on the session-bound route, and the persist-retry
budget is 3 s.

**The authorization binding is inside the authenticated envelope.** The
session-bound store binds a ciphertext to its key name, because there the key
name *is* the binding (#293). Here the binding is a set of fields in a
plaintext HASH, and someone able to write to Redis — or a mismatched restore —
could re-point `clientId`, extend `expiresAt`, or move `consent.at` past the
watermark without touching the ciphertext. Rewriting `authorizationRevision`
to the current value would hide a scope or `boundary` change and skip the
renewed consent; swapping `upstream` would weaken the account check at the
next reauthorization. So the additional authenticated data is a canonical
encoding of the key name together with `id`, `subject`, `clientId`,
`connection` and every field of `FederationGrantAuthorization` (D1),
recomputed from the HASH when the credential is opened. The usage fields —
`lastUsedAt`, the ineligibility marker and the stamp of a failed refresh — are
outside it: they change while the grant is in use, and none of them decides
what the grant allows. The
authorization fields change only at activation, which seals a new credential
under the new fields and writes both in one script; a refresh re-seals under unchanged fields, which the `version`
guard guarantees. A tampered field fails authentication and reads as
`credential_unreadable`. `status`, `version`
and `revocation` are left out on purpose: every transition away from `active`
deletes the credential, so rewriting them gains nothing.

Two behaviours differ from the session-bound store on purpose, because a
mistake here revokes every user's delegation at once:

- **A key ring.** `federationGrants.encryptionKeys` is a list of `{ id, key }`;
  the first seals, and the envelope names the key that sealed it. That is a
  new `v2` envelope in `internal/crypto.mts`, beside the `v1` the
  session-bound store keeps; `v1` carries no key ID and its reader rejects any
  other shape. An unknown
  key ID is a configuration problem: 503 `key_unavailable`, record kept.
  Paused grants are not re-sealed, so the runbook says an old key stays in the
  ring for the one-year ceiling.
- **No self-heal delete.** A record that cannot be read is never deleted on
  read. `credential_unreadable` is computed, not persisted (D1): wrong key
  material under a known key ID must not durably flip every grant.

The `allow-plaintext` production guard applies unchanged. The in-memory
adapter declares `replicaSafety: unsafe`.

### D17 — The federation adapter surface gains one capability, in two methods

Every adapter fixes its authorization parameters today, so `offline_access`
with `prompt=consent` — what OIDC Core §11 requires — cannot be sent at all.
House capabilities are detected by method presence (`supportsRefresh`,
`supportsLogout`), and an optional parameter on an existing method cannot be
detected. So this is a new optional method with its guard:

```ts
interface SupportsDelegatedAuthorization {
	buildDelegatedAuthorizationUrl(params: {
		readonly redirectUri: string;
		readonly state: string;
		readonly codeVerifier: string;
		readonly nonce: string;
		readonly scopes: readonly string[];
		readonly resource?: string; // sent as the RFC 8707 `resource` parameter
		readonly authorizationParams?: Readonly<Record<string, string>>;
	}): URL;
	refreshDelegatedToken(params: {
		readonly refreshToken: string;
		readonly scopes?: readonly string[]; // the grant's; RFC 6749 §6 allows asking for no more
		readonly resource?: string; // an upstream that needs it at authorization needs it here too
		readonly signal?: AbortSignal; // D12
	}): Promise<RefreshedTokens>;
}
```

The existing `refreshToken(refreshToken)` takes nothing else. An upstream that
requires a resource indicator would authorize and then fail its first refresh,
or answer with a default-audience token that D10 would still file under the
configured resource. `openid-client`'s `refreshTokenGrant` has no per-call
signal, so the generic adapter passes this one through `customFetch`.

`FederationProfile` and `RefreshedTokens` also gain the token response's
`scope` and `token_type`. The generic OIDC adapter's `snapshot` drops both
today, so the scope actually granted is unobservable, and both D7 check 7 and
the refresh rule in D5 need it.

They gain the raw `expires_in` too, as `expiresIn`, beside the `expiresAt`
they have. D5 judges the lifetime a token was *issued* with, and that cannot
be recovered from an absolute expiry: one step of the clock between the
adapter and the judgement turns 3600 into 3601, and starves every grant on a
connection whose maximum is 3600. The two together also say when the token
was obtained on the adapter's reading of the clock (`expiresAt − expiresIn`),
which is what the stored record keeps; pairing `expiresIn` with a later
reading taken in core would lengthen the token's life. Core holds that
instant inside the window of its call, so that a wild `expiresAt` cannot date
a token in the future. A response with one of the two and not the other has
no finite lifetime as far as D5 is concerned.
All of these additions are optional, so existing adapters and the login flow
are unaffected; the retrieval reads an answer field by field and trusts none
of it (D5). Core's structural type for that answer is all-optional for the
same reason. `RefreshedTokens` as it stands today is still not assignable to
it — `Omit` over a type with an index signature erases the named fields — and
becomes so once slice 2 declares the additions on it. A connection whose federation lacks the capability is refused at
boot. The first cut implements it for the generic OIDC adapter.

### D18 — Audit, with a correlation ID

New event types, each added to `BUILT_IN_AUDIT_EVENT_TYPES`:
`federation.grant.requested`, `.authorized`, `.reauthorized`,
`.authorization_failed`, `.token.success`, `.token.denied`, `.refreshed`,
`.reauthorization_required`, `.refresh_failed`, `.refresh_persist_failed`,
`.revoked`. `.refreshed` is emitted whenever credentials are replaced,
including by a result that arrived after its caller was answered (D12), which
no `.token.success` would record. `.refresh_failed` is emitted whenever the
upstream was asked and nothing came of it — a refusal, a guarded write or a
mark that lost (`write_lost`, `mark_lost`), a mark that could not be written
(`mark_not_written`), a worker that failed unforeseen (`internal_error`) —
since the upstream may have rotated the refresh token all the same, and that
must leave a trail. `.refresh_persist_failed` names which of the three it was:
`storage`, `write_in_flight`, or `hard_timeout`.

Every event carries the grant ID, the caller in `clientId`, the owner and the
upstream subject, the connection, the resource, the scopes, the outcome and a
correlation ID. The provider has no request ID today; these routes accept
`x-request-id` when it is 1–128 characters of `A-Z a-z 0-9 - _ . : + / = #`
(the shape auth.policy-verifier 0.11.0 settled on), generate one otherwise,
and echo it. No event or response carries a refresh token or any other
long-lived secret, and no log line this provider writes does. One seam is
outside that: the retrieval's `report` hands a cause to the composer's logger
as it was thrown, and an upstream's error may carry what the upstream echoed.
The package logs its name and its classification, never the error whole
(slice 4).

### D19 — Entra: on-behalf-of is not implemented, and consent accumulates

An OBO assertion must be an access token issued for the middle-tier API that
makes the request. A token auth.provider issued, or a login through another
IdP, is not one. The documentation says OBO is unsupported, and describes the
supported path: an authorization-code connect flow against Entra as an OIDC
federation with `offline_access`. OBO can follow if there is demand.

Entra returns every scope the user has ever consented to for a resource and
upstream client, not only the ones just asked for, and it does so on refresh
as well. Two grants with different scope subsets on one connection therefore
broaden each other: the narrower one's next refresh comes back carrying the
wider one's scopes. D5 withholds that token, so the design fails closed, but
the narrower grant is then unusable until it is reauthorized for the wider
set. The documentation gives the rule for any IdP that accumulates consent:
one connection per scope set, with `allowScopeSubsets = false`, each pointing
at a `federations.<name>` entry with its own app registration — and not the
registration used for login, whose `profile` and `email` consent accumulates
just the same. A dedicated registration alone is not enough. What Entra adds
to a reported scope by itself is to be verified on a real tenant for that
guide.

## Acceptance criteria

| # | criterion in #593 | decided in | proving test |
| --- | --- | --- | --- |
| 1 | survives restart and session expiry | D1, D14, D16 | Redis adapter: new client instance, session deleted, token returned |
| 2 | not renewable without refresh credentials | D5 | callback with no `refresh_token`: no credential is stored, the grant never leaves `pending`, the redirect says `refresh_token_absent` |
| 3 | wrong client / subject / connection / environment / resource / scopes denied, grant ID known | D4, D9, D10 | one case per dimension, on all four grant-addressed routes; "not yours" responses are byte-identical; `boundary` change reads as `connection_changed` |
| 4 | expired or revoked upstream credentials → reauthorization, no fallback | D11, D12 | structured upstream `invalid_grant`; assert no other grant or credential is read |
| 5 | transient failures distinguishable and non-destructive | D5, D11, D12 | injected 5xx, 429, storage throw, `invalid_client`, over-long token lifetime, unreadable watermark; record unchanged in each. A rotating upstream that answers between the soft and the hard deadline: the late credential is persisted, `.refreshed` is audited, the next call succeeds. One that answers after the hard deadline: an acknowledged loss, handled as a persist failure. A starved grant calls the upstream once per retry interval, not once per request |
| 6 | concurrent refresh, lock expiry, restart, persistence failure | D2, D12 | two replicas on one testcontainer; lock TTL forced to expire; guarded-write loser; injected persist failure; refresh response without `refresh_token`; refresh straddling `expiresAt` |
| 7 | duplicate, stale, wrong-account callbacks cannot replace or broaden | D5, D6, D7 | replayed callback; superseded intent; expired intent; different upstream `sub`; upstream grants more scopes than consented. Broadening through refresh: G1 consented for one scope, G2 later for two on the same connection, G1's refresh returns both — G1's client gets `upstream_token_ineligible`, never the token |
| 8 | session-expiry / logout / subject-revocation behaviour; session-bound endpoint preserved | D13, D14 | slice 5: both logout endpoints leave grants alone, subject revocation ends them, existing `federationToken` suite untouched and green. The policy-on cases are deferred with D14 |
| 9 | no refresh token or long-lived secret in responses, audit or logs | D18 | a sentinel secret is grepped for in every response body, audit event and captured log line |
| — | the storage guarantees D1 and D16 claim | D1, D3, D4, D16 | a rewritten `clientId`, `expiresAt` or `authorizationRevision` reads as `credential_unreadable`; an unknown key ID answers 503, keeps the record, and restoring the key restores the grant; an identity change reads as `connection_identity_changed` and reverting it restores the grant; activation beyond the ceiling is refused |
| 10 | provider-specific `offline_access` documentation | D19 | documentation review |

The two review conditions add:

- a revoked grant whose lifetime exceeds the refresh-token watermark retention
  stays unusable after that retention has elapsed — on the durable path; on an
  injected part-way failure; when the Store passes no grant store at all; and
  when the maximum is lowered, the failure injected, and the maximum raised
  again (D13);
- a grant that expires before its issued access token: retrieval stops, and
  the documented residual window is that token's remaining life; an upstream
  token with no finite expiry: refused at authorization, nothing but the
  lapsing `pending` grant stored, nothing disclosed; `maxAccessTokenLifetime`
  lowered while a longer-lived token is cached: that token is not disclosed
  (D5, D10, D15);
- a subject revoked while a refresh is in flight, with the grant pass omitted:
  the refreshed token is not returned (D10).

The two boundaries of D13 add:

- `"keep"`: the subject's sessions and tokens are dead, and its grants still
  yield tokens;
- a `"keep"` followed by a `"revoke"`: the grants are dead;
- a `"revoke"` whose grant write fails part-way, followed by a `"keep"`: the
  grant the first call should have ended stays unusable;
- `"keep"` without the operator's allowance: the grants are revoked, and the
  result says why. The free function offers no `"keep"` at all;
- a `"revoke"` that stamps but misses a grant's write, then a fresh login and
  `/reauthorize` on that grant, with no `/token` or `/status` call in between:
  the grant is revoked, not renewed;
- a callback that passed its session check before a `"keep"`: it cannot
  activate after it, and `pending` grants are gone;
- once a revocation of either kind is stamped, a session that predates it
  cannot consent, and that still holds when the refresh-token lifetime has
  passed but the session's has not;
- federation grants refuse to boot on a `SubjectRevocation` adapter without
  the capability, and the adapter contract suite refuses a `revokeBefore`
  that accepts an expiry below the floor;
- `"keep"` with `revokeGrantsConsentedSince`: grants consented since then are
  revoked, older ones are kept;
- a caller that stamps `revokeBefore` directly ends the grants.

And D2 adds its three races, and the conflicting writes run at once, in the
contract suite both adapters run.

Time is controlled (`now` is injected everywhere it is read) and failures are
injected deterministically.

## Build order

Each slice is its own PR and follows RED → GREEN → REFACTOR: the contract or
route test is written first and watched failing.

1. **core: port and domain.** `federation-grants/` types, the lifetime
   ceiling, the transition rules, the two revisions, eligibility,
   `retrieveFederationGrantToken` with its typed result, the in-memory adapter
   and the contract suite, races and lock included.
   - **1d: a failed refresh is remembered, the lease is dated by the store,
     and every refresh outcome ends in the last look.** Before it, a failure
     changed nothing in the record, so every request that needs a refresh
     asked the upstream again — N polls during an IdP incident were N
     upstream calls — and a call whose refresh failed answered the failure
     even where the stored token would still have served it. The stamp of
     D12, `noteRefreshFailure` on the port, `waitedMs` in the lock's reply,
     and the last look after every outcome (D10). A port change, so its own
     slice, before slice 3 implements the port for Redis and before slice 4
     can reach the retrieval.
2. **federation adapter capability** (D17), generic OIDC first.
3. **redis adapter** (D16), with the duplicated contract suite on a
   testcontainer, the guarded-write scripts and the grant-keyed lock.
4. **package: token and status routes** (D9–D12), exercised on grants seeded
   straight into the store; the `Client` fields, audit events, configuration.
5. **revocation** (D13): the revoke route, the two library functions, the
   `revokeAllForSubject` extension, the retention floor and lifetime ceiling,
   the boot refusals (no `subjectRevocation`, or an in-memory one beside a
   durable grant store), the condition tests, and the tests that default
   logout leaves grants alone.
6. **acquisition** (D6–D8): the intent routes, consent, the connect flow, the
   optional `UserRepository` lookup, and the second port of D16 —
   `FederationGrantIntentStore`, both adapters, and the core function that
   orders an intent's two writes.
7. **standalone template, documentation, CHANGELOG.** Includes the key-ring
   retention rule and the provider-specific `offline_access` guide. The
   operator runbook rows and the `adapter-surface.md` rows are not left for
   this slice: the drift tests require them of whichever slice adds a module
   or a slot.

Slices 1–3 change no behaviour. Nothing can create a grant until slice 6, and
revocation exists from slice 5, so no release cut between slices ships an
offline credential without an off switch. Slice 5 also carries the second
boundary of D13: the capability on `SubjectRevocation` and its contract suite,
both adapters, and the subject revocation service with its `"keep"` option.

Later, outside the first release: the **logout policy** (D14).

## Consequences

**Good.** The session-bound guarantees are untouched. Application workers
never hold a refresh credential. Every grant has an owner, a client, a scope
and an end. A terminal grant cannot come back, by construction of the write. A
revoked subject's grants stay dead whatever the Store or the operator does
afterwards. Each ambiguous failure resolves toward asking the user again, and
no configuration slip costs every user a reconnect.

**Bad.** It is a large surface: a package, a port, two adapters, five client
routes, the connect flow and a consent page contract, and two new `Client`
fields. It asks two things of integrators: `subjectRevocation` becomes
mandatory once grants are enabled (D13), and the account check is at full
strength only with a new optional `UserRepository` lookup (D7). A rotating
upstream combined with a storage outage during a refresh, or one slower than
the hard deadline, costs the user a reconnect (D12). Connections on federations that issue non-expiring tokens are
unsupported (D5). An IdP that accumulates consent needs one connection and one
app registration per scope set (D19). Every revoked subject leaves a watermark
key for a year. By default every password change that calls
`revokeAllForSubject` ends that user's delegations; a Store may keep them for
a routine change through the revocation service, and the soundness of that
rests on the Store telling a routine change from a recovery (D13). A custom
`SubjectRevocation` adapter has to implement the two-boundary capability
before its deployment can enable federation grants (D13). A deployment that enables federation
grants has to provide a consent page, even if it has none today (D8).

**Neutral.** Upstream refresh tokens also die from disuse — Google after six
months unused, Entra on a 90-day rolling window — and the provider runs no
scheduler. The status route reports `last_used_at` so that the application,
which owns scheduling, can refresh a paused job's grant before the window
closes. A connection may carry a documented idle lifetime later; the provider
does not hard-code one and does not promise indefinite unattended execution.

## Deferred

Nothing is left open. These are designed or considered, and not in the first
release:

- the logout policy (D14);
- an adapter capability for upstream revocation, which could admit connections
  with unbounded token lifetimes as an explicit opt-in (D5);
- a token-exchange (RFC 8693) facade and RFC 9396 `authorization_details`, if
  a standard settles (D9);
- a Shared Signals receiver that maps upstream security events to per-subject
  revocation (D14);
- Entra on-behalf-of (D19);
- revoking everything one client holds. A leaked client secret is answered by
  rotating it, which leaves the legitimate client its grants, and a disabled
  client cannot authenticate to use them. The store lists by subject and not
  by client, so adding this later means an index with a backfill; and a
  store-level ceiling on how long a first intent may live, which today is a
  constant of core's (D6) with no configuration to bypass.

## References

- #593 and its comments: direction, survey, and the two review conditions
- #276 (logout invalidation), #293 (ciphertext bound to its key), #524
  (generic OIDC federation), #589 (consent stores and their contract suites)
- RFC 6749 §5.1 and §6, RFC 7009, RFC 7662, RFC 8693, RFC 8707, RFC 9126,
  RFC 9396, RFC 9700 §4.14.2
- OpenID Connect Core 1.0 §11; OpenID Connect Back-Channel Logout 1.0 §2.7
- draft-zhu-oauth-async-delegation-05; draft-ietf-oauth-refresh-token-expiration-03;
  draft-parecki-oauth-global-token-revocation-06; OpenID Provider Commands 1.0 §6.14
- Consumer Data Standards (Australia): `cdr_arrangement_id`, `sharing_duration`
- `packages/core/docs/adr/2026-07-31-rfc8707-resource-audience-binding.md`
