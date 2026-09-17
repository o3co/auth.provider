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
type RevokedBy = "client" | "subject" | "operator" | "logout_policy" | "backstop";

interface FederationGrantBase {
	readonly id: string; // opaque, 256 bits, base64url; a reference, not a credential
	readonly subject: string; // the local owner
	readonly clientId: string; // the owning client
	readonly connection: string;
	readonly createdAt: Date;
	readonly version: number; // bumped by every status or credential change (D2)
}

type FederationGrant =
	| (FederationGrantBase & { readonly status: "pending" })
	| (FederationGrantBase & AuthorizedFields & {
			readonly status: "active" | "reauthorization_required";
	  })
	| (FederationGrantBase & AuthorizedFields & Revoked) // revoked after authorization
	| (FederationGrantBase & Revoked); // revoked while `pending`: no authorized fields

interface Revoked {
	readonly status: "revoked";
	readonly revocation: { readonly by: RevokedBy; readonly at: Date };
}

interface AuthorizedFields {
	readonly identityRevision: string; // D4
	readonly authorizationRevision: string; // D4
	readonly upstream: { readonly issuer: string; readonly subject: string };
	readonly resource?: string;
	readonly scopes: readonly string[]; // granted by the upstream, within consent.scopes
	readonly consent: { readonly at: Date; readonly sid: string; readonly scopes: readonly string[] };
	readonly authorizedAt: Date;
	readonly expiresAt: Date; // set at consent; never moved by a refresh
	readonly lastUsedAt?: Date;
}
```

A grant names exactly one client in the first cut. The issue allows
"client(s)"; one is enough for every case we have, and it keeps isolation
trivially true.

The stored `status` has four values. What a caller is told is an *effective*
status, computed on every read: an `active` grant past its expiry reads as
expired; one whose connection's identity changed reads as
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
| lodge first intent | — | create `pending`, naming this intent as current; key lives as long as the intent |
| lodge reauthorization intent | the record exists; status is `active` or `reauthorization_required`; `now < expiresAt` | name this intent as current, superseding any other |
| activate (callback succeeds) | status is `pending`, `active` or `reauthorization_required`; `now < expiresAt` unless `pending`; the intent is the grant's current intent; `expiresAt − consent.at` is within the lifetime ceiling (D3) | `active`; set the authorized fields; write credentials; `version++` |
| replace credentials (refresh) | status is `active`; `version` equals the one read; `now < expiresAt` | write credentials; `version++` |
| require reauthorization | status is `active`; `version` equals the one read | `reauthorization_required`; delete credentials; `version++` |
| revoke | the record exists; status is not `revoked` | `revoked`; record `revocation`; delete credentials; `version++` — one atomic operation that always wins |
| touch | the record exists; status is `active` | set `lastUsedAt` only |
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

Three races are part of the contract suite both adapters run: a callback that
passed its checks and activates after a revocation (it must fail); a refresh in
flight while the grant is revoked (it must not re-create the credential record,
and must not return the token); and a refresh that starts before `expiresAt`
and finishes after it (the write must fail, and no token is returned).

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
residual access (D15) into a number the operator chose. A token with
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
- An ineligible access token is withheld **and never written**: the credential
  record keeps the refresh credential only. The call answers
  `upstream_token_ineligible`, the grant is untouched, and an operator who set
  `maxAccessTokenLifetime` too low fixes it without any user acting.

The same predicate guards every disclosure, not only a fresh one (D10). It
judges the lifetime a token was *issued* with, not what remains of it, so a
cached token does not become disclosable merely by ageing below a lowered
maximum. Lowering `maxAccessTokenLifetime` therefore takes effect on the next
call. The sealed credential records, beside the refresh token, the access
token (which may be absent), when it was obtained, its issued lifetime, and
its own `scope` and `token_type`. A refresh response that omits `scope` means
the grant's `scopes` (RFC 6749 §6).

An ineligible refresh also leaves a non-secret marker on the record:
`{ reason, at, judgedAgainst }`. Without it a starved grant would take the
lock, call the upstream and rotate the refresh token on every `/token` call —
each rotation another chance to lose the credential (D12), and a drain on the
upstream client's rate limit that other grants share. With it:

- `/token` answers `upstream_token_ineligible` from the marker, with
  `retryAfterSeconds`, until `federationGrants.ineligibleRetryAfter` (default
  300 s) has passed;
- the status route reports it, so a grant that cannot yield a token never
  reads as `active`;
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
expired, or reads as `connection_identity_changed`.

A grant has at most one live intent. Lodging another supersedes the older one,
whose callback is then refused as stale. Live first-time intents are bounded
per `(client, subject)` by a constant on the port, as
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
- With a session that authenticated at or before the subject's revocation
  watermark, it answers 403 `reauthentication_required`, and so does the
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

The transaction is a single-use record in the grant store, consumed
atomically, with a 10-minute TTL. It is not the one-slot
`req.session.federation` envelope, which a second start overwrites, and not
`fedtx:`, which lives in the express-session store and is read and then
deleted.

**Callback.** `/session/federation-grants/callback/:connection` checks in
order:

1. the transaction exists, names this connection, and its `state` matches; it
   is consumed before the code is exchanged;
2. the intent is still the grant's current intent and has not expired;
3. the `UserSession` the flow started under is re-read from the store and is
   still live, the browser still presents it, its `sub` is the intent's `sub`,
   and it authenticated after the subject's revocation watermark;
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
- its own record, held with the intent in the grant store. Not
  `PendingConsentRecord`, which is shaped for `/authorize`. Not `ConsentStore`:
  a record there would later suppress `/authorize` consent for local scopes,
  confusing two different things the user agreed to.

The page is told the client, the connection, the scopes, the expiry, and that
access continues after logout. What was shown is recorded in `grant.consent`.
Consent is never skipped: not for `firstParty` clients, and not from any
remembered record.

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
3. the subject's revocation watermark does not cover `consent.at` (D13). A
   watermark that cannot be read answers 503, as `verifyJwt` fails closed;
4. the connection is in the client's `allowedFederationGrantConnections`; an
   asserted `connection` names it; both revisions match (D4);
5. asserted `resource` equals the grant's, and asserted `scope` is within
   `consent.scopes` — checked here so that a request that can never succeed
   does not cost an upstream call.

Then it takes the stored upstream access token if its remaining life exceeds
`max(min_ttl, refreshBuffer)`, and refreshes otherwise (D12). Before any
token is disclosed, cached or fresh, these are checked again: steps 2 and 3,
because a refresh may have straddled the expiry, or a subject-wide revocation
may have stamped its watermark meanwhile without reaching this grant; the
eligibility predicate of D5 against the *current* `maxAccessTokenLifetime`;
and an asserted `scope` against the scopes that token carries, not against
what the grant once got.

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
	| { ok: false; code: FederationGrantDenial; reason?: string; retryAfterSeconds?: number };
```

| `code` | reasons | HTTP | what the application does |
| --- | --- | --- | --- |
| `grant_not_found` | — | 404 | treat as no delegation; never fall back |
| `authorization_pending` | — | 400 | the user has not finished connecting |
| `grant_expired` | `consented_lifetime`, `operator_maximum` | 410 | ask for a new grant; only `operator_maximum` can lift by itself |
| `grant_revoked` | `client`, `subject`, `operator`, `logout_policy`, `backstop` | 410 | terminal; ask for a new grant, if at all |
| `connection_identity_changed` | — | 410 | terminal while it lasts; ask for a new grant |
| `reauthorization_required` | `upstream_invalid_grant`, `connection_changed`, `credential_unreadable` | 410 | call `/reauthorize`, send the user, retry later |
| `access_denied` | `connection_not_permitted` | 403 | configuration; do not retry |
| `invalid_request`, `invalid_scope`, `invalid_target` | — | 400 | the request is malformed or exceeds the grant |
| `upstream_token_ineligible` | `no_finite_lifetime`, `lifetime_over_maximum` | 502 | operator; the grant is untouched; honour `retryAfterSeconds` |
| `upstream_token_ineligible` | `scope_exceeded` | 502 | no operator action un-accumulates consent: `/reauthorize` for the wider set, or a new grant on a connection of its own (D19) |
| `upstream_rejected` | the upstream's error code | 502 | operator, e.g. an expired upstream client secret; the grant is untouched |
| `rate_limited` | `provider`, `upstream` | 429 | retry after `Retry-After` |
| `temporarily_unavailable` | `upstream`, `storage`, `lock_timeout`, `key_unavailable` | 503 | retry; the grant is untouched |

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
    unknown and is treated like the persist failure below;
  - the lock has no renewal, so "until the call settles" is only true if
    settling always comes first. Boot requires
    `upstreamHardTimeoutMs + persistRetryBudgetMs < refreshLockTtlMs`
    (defaults 25 s + 3 s < 30 s). All three are this provider's
    configuration; nothing depends on an adapter's internals.
- After acquiring the lock the record is re-read; another replica may have
  refreshed already.
- The write is the guarded "replace credentials" of D2, in one Lua script.
- `classifyFederationRefreshError`, today a private function of the
  session-bound route, moves to core and both routes import it. For a grant,
  only a *structured* `invalid_grant` or `invalid_token` requires
  reauthorization and deletes credentials. The classifier's substring fallback
  never does; it maps to `upstream_rejected`. 429 and 5xx/network failures
  change nothing.
- If the upstream refresh succeeds but the replacement cannot be persisted
  after bounded retries inside the lock, the call answers
  `temporarily_unavailable` / `storage`, the new credentials are dropped, and
  `federation.grant.refresh_persist_failed` is audited. The stored refresh
  credential is *not* assumed to be still good: the next refresh decides, and
  an `invalid_grant` there becomes `reauthorization_required`.

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
- **Per subject.** `revokeAllForSubject` gains an optional
  `federationGrantStore`. After the session cascade it lists the subject's
  grants, `pending` ones included, and revokes each. A throw is a `failures`
  entry with `capability: "federationGrantStore"`, the grant stays enumerable
  for a retry, and `complete` accounts for it.
- **At logout, by policy.** See D14.

Revocation is the atomic, always-winning write of D2. Deleting the refresh
credential is what makes it irreversible; nothing about it depends on a TTL.
An outage is surfaced as 503 or as a `failures` entry, never swallowed the way
`routes/revoke.mts` swallows a `revokeFamily` throw.

**The backstop.** `revokeAllForSubject` stamps the subject watermark first, as
now. D10 step 3 and the status route compare it with the grant's `consent.at`.
Not with a token's `iat`: a token minted from a surviving grant is always
fresh. And not with `authorizedAt`: consent precedes the callback by up to ten
minutes, and a callback landing just after the watermark must not hide a
consent given before it. The comparison is inclusive and adds
`subjectRevocationSkewMs` — the 1 s allowance `verify.mts` applies to the
watermark, which becomes an exported constant — and not the 5-minute
`clockSkewMs`, which would refuse the re-login a revocation sends the user to.
D7's session test uses the same comparison, so a login within that second
cannot connect for that session's life. A hit revokes that grant durably, with
`by: "backstop"`.

The watermark's retention cannot be computed from the configured maximum: a
grant consented under a long maximum survives the maximum being lowered,
revoked with a part-way failure, and raised again. So retention depends
neither on configuration nor on what the caller passes:

```
expiresAt = at + max(watermarkTtlMs, SUBJECT_REVOCATION_MIN_RETENTION_MS)
```

`SUBJECT_REVOCATION_MIN_RETENTION_MS` is the one-year ceiling plus a fixed
one-minute margin, and `revokeAllForSubject` applies it unconditionally. Any
grant this watermark covers was consented no later than `at` plus the skew and
the rounding to seconds, both far inside the margin, and its `expiresAt` is at
most `consent.at` plus one year, so it cannot outlive the watermark — whatever the operator does to the
configuration, and whether or not the Store passed the grant store. Both
adapters already refuse to shorten an in-force watermark. The cost is one
small key per revoked subject for a year, in every deployment.

Two things make that true by construction and not by convention:

- **The ceiling is a core constant, enforced at the write.** The config schema
  caps `federationGrants.maxExpiresIn` at one year, but a hand-built config
  bypasses a schema, as #448 showed. So `FEDERATION_GRANT_LIFETIME_CEILING_MS`
  lives in core (D3), `activate` refuses a lifetime beyond it (D2),
  `SUBJECT_REVOCATION_MIN_RETENTION_MS` is defined from it, and a test pins
  the relation.
- **The watermark must exist.** `subjectRevocation` is an optional slot, and a
  deployment may declare it unsupported. With federation grants enabled that
  is refused at boot, as `device-grant` refuses to start without a rate
  limiter.

So the per-subject pass is what makes revocation prompt and deletes the
credentials at once, and the backstop is what holds when that pass does not
run or does not finish. A Store that upgrades without touching its
`revokeAllForSubject` call site is safe, not silently exempt. One window
remains and D7 closes it: a consent given through a session that the
revocation has not reached would be dated after the watermark, so such a
session cannot consent at all. The primary path alone fails when a store write fails
part-way. The watermark alone would make revocation depend on a TTL, which
today is sized to refresh tokens. Hence both.

`RevokeAllForSubjectCapability` and the failure `operation` union gain
members, so a caller that switches exhaustively on them needs a new case. That
is accepted here, because an unreported grant failure is worse. D14 declines
the same trade for `cascadeLogout`.

### D14 — Grants survive logout unless the deployment says otherwise

By default session expiry, local logout and upstream logout leave a grant
alone. That is what offline access means, and OIDC Back-Channel Logout 1.0
§2.7 says the same of refresh tokens issued with `offline_access`. Logout
still deletes every session-bound `(sid, federation)` record, so #276 holds.

`federationGrants.revokeOnLogout` (default `false`) makes logout revoke the
subject's grants as well. The two logout endpoints can honour it differently,
and the documentation says so:

- `/oauth/logout` runs it before `userSessionStore.delete`, using
  `session.sub`. A failure answers 503 without ending the browser session, so
  a retry still has its cookie. It is a step in the route, not inside
  `cascadeLogout`, which has no `sub`, would repeat it per `sid` under
  `revokeAllForSubject`, and whose `step` union callers switch on
  exhaustively.
- `/session/logout` is best-effort and logged by contract; it never answers
  5xx. A deployment that needs the guarantee sends logout through
  `/oauth/logout`.

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
contract suite that both adapters run, the caller's clock for expiry, and a
key TTL that is only a safety net. The listing and the key layout below
illustrate the contract; slices 1 and 3 settle the signatures and the names.

```ts
interface FederationGrantStore {
	readonly kind: string;
	lodge(intent: FederationGrantIntent): Promise<LodgeResult>; // creates or supersedes; enforces the bound
	readIntent(handle: string): Promise<FederationGrantIntent | null>;
	readIntentByChallenge(challenge: string): Promise<FederationGrantIntent | null>; // the consent page's lookup (D8)
	consumeIntent(handle: string): Promise<FederationGrantIntent | null>; // atomic, single-use
	putTransaction(tx: ConnectTransaction): Promise<void>;
	consumeTransaction(state: string): Promise<ConnectTransaction | null>; // atomic, single-use
	find(grantId: string): Promise<FederationGrant | null>;
	listBySubject(subject: string): Promise<readonly FederationGrant[]>;
	openCredentials(grant: FederationGrant): Promise<OpenResult>; // "unreadable" and "key_unavailable" are results, not throws
	verifyCredentials(grant: FederationGrant): Promise<"ok" | "unreadable" | "key_unavailable">; // for the status route; returns no token
	activate(grantId: string, intentHandle: string, fields: AuthorizedFields, credentials: UpstreamCredentials): Promise<TransitionResult>;
	replaceCredentials(grantId: string, expectedVersion: number, credentials: UpstreamCredentials): Promise<TransitionResult>;
	requireReauthorization(grantId: string, expectedVersion: number): Promise<TransitionResult>;
	revoke(grantId: string, by: RevokedBy, at: Date): Promise<boolean>; // whether it changed anything
	touch(grantId: string, at: Date): Promise<void>;
	acquireRefreshLock(grantId: string, opts: { ttlMs: number; waitForMs: number }): Promise<LockResult>;
}
```

Every guarded write takes `now` from its caller, sampled at the write and not
at the start of the request; the race across `expiresAt` depends on that. The
lock is part of the port, so the in-memory adapter and the contract suite
cover it too.

Redis layout, default prefix `fg:`. Keys that one script touches share a
Cluster hash tag, as the consent store's do:

- `fg:{<id>}:grant` — a HASH of non-secret fields, `status`, `version` and the
  current intent's handle.
- `fg:{<id>}:cred` — one AES-256-GCM ciphertext of the upstream tokens,
  reusing `internal/crypto.mts`.
- `fg:{<id>}:lock`.
- `fg:sub:<subject>` — a ZSET index scored by `expiresAt`, or by the intent's
  expiry while the grant is `pending`, written before the record; a dangling
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
revoked or expired grant still answers the status route. The credential key
gets no such retention. A `pending` grant lives as long as its intent. The
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
`connection` and every authorized field except `lastUsedAt`, recomputed from
the HASH when the credential is opened. Those fields change only at
activation, which seals a new credential under the new fields and writes both
in one script; a refresh re-seals under unchanged fields, which the `version`
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
Both additions are optional, so existing adapters and the login flow are
unaffected. A connection whose federation lacks the capability is refused at
boot. The first cut implements it for the generic OIDC adapter.

### D18 — Audit, with a correlation ID

New event types, each added to `BUILT_IN_AUDIT_EVENT_TYPES`:
`federation.grant.requested`, `.authorized`, `.reauthorized`,
`.authorization_failed`, `.token.success`, `.token.denied`, `.refreshed`,
`.reauthorization_required`, `.refresh_failed`, `.refresh_persist_failed`,
`.revoked`. `.refreshed` is emitted whenever credentials are replaced,
including by a result that arrived after its caller was answered (D12), which
no `.token.success` would record.

Every event carries the grant ID, the caller in `clientId`, the owner and the
upstream subject, the connection, the resource, the scopes, the outcome and a
correlation ID. The provider has no request ID today; these routes accept
`x-request-id` when it is 1–128 characters of `A-Z a-z 0-9 - _ . : + / = #`
(the shape auth.policy-verifier 0.11.0 settled on), generate one otherwise,
and echo it. No event, response or log line carries a refresh token or any
other long-lived secret.

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
| 8 | session-expiry / logout / subject-revocation behaviour; session-bound endpoint preserved | D13, D14 | slice 5: both logout endpoints leave grants alone, subject revocation ends them, existing `federationToken` suite untouched and green. Slice 8: the same with the policy on |
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

And D2 adds its three races, in the contract suite both adapters run.

Time is controlled (`now` is injected everywhere it is read) and failures are
injected deterministically.

## Build order

Each slice is its own PR and follows RED → GREEN → REFACTOR: the contract or
route test is written first and watched failing.

1. **core: port and domain.** `federation-grants/` types, the lifetime
   ceiling, the transition rules, the two revisions, eligibility,
   `retrieveFederationGrantToken` with its typed result, the in-memory adapter
   and the contract suite, races and lock included.
2. **federation adapter capability** (D17), generic OIDC first.
3. **redis adapter** (D16), with the duplicated contract suite on a
   testcontainer, the guarded-write scripts and the grant-keyed lock.
4. **package: token and status routes** (D9–D12), exercised on grants seeded
   straight into the store; the `Client` fields, audit events, configuration.
5. **revocation** (D13): the revoke route, the two library functions, the
   `revokeAllForSubject` extension, the retention floor and lifetime ceiling,
   the boot refusal without `subjectRevocation`, the condition tests, and the
   tests that default logout leaves grants alone.
6. **acquisition** (D6–D8): the intent routes, consent, the connect flow, and
   the optional `UserRepository` lookup.
7. **standalone template, documentation, CHANGELOG.** Includes the operator
   runbook rows the replica-safety drift test requires, `adapter-surface.md`,
   the key-ring retention rule, and the provider-specific `offline_access`
   guide.
8. **logout policy** (D14).

Slices 1–3 change no behaviour. Nothing can create a grant until slice 6, and
revocation exists from slice 5, so no release cut between slices ships an
offline credential without an off switch.

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
key for a year (D13).

**Neutral.** Upstream refresh tokens also die from disuse — Google after six
months unused, Entra on a 90-day rolling window — and the provider runs no
scheduler. The status route reports `last_used_at` so that the application,
which owns scheduling, can refresh a paused job's grant before the window
closes. A connection may carry a documented idle lifetime later; the provider
does not hard-code one and does not promise indefinite unattended execution.

## Open for review

1. Whether D14's logout policy ships in the first release or the next.
   Recommended: the next. It is off by default, it is the last slice, and its
   guarantee differs between the two logout endpoints.
2. Whether a subject-wide revocation should always take grants with it (D13).
   Recommended: yes, as Global Token Revocation and OpenID Provider Commands
   both specify. The cost is real: a deployment that calls
   `revokeAllForSubject` on every password change ends its users' delegations
   on every password change. Keeping grants would need a second watermark.

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
