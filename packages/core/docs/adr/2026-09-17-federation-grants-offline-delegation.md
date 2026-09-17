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
			readonly status: "active" | "reauthorization_required" | "revoked";
			readonly revocation?: { readonly by: RevokedBy; readonly at: Date };
	  });

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
expired, and one whose connection changed or whose credential cannot be opened
reads as `reauthorization_required`. Computed conditions are never persisted,
so undoing the configuration change, or restoring the key, restores the grant.
Only an upstream `invalid_grant` is persisted as `reauthorization_required`,
because it is a fact about the credential, not about this deployment.

### D2 — Every transition is a guarded write inside the store

A revoked or expired grant must never become usable again. Declaring that is
not enough: the store enforces it at the write.

| event | precondition, evaluated in the store | effect |
| --- | --- | --- |
| lodge first intent | — | create `pending`; key lives as long as the intent |
| activate (callback succeeds) | status is `pending`, `active` or `reauthorization_required`; not expired; the intent is the grant's current intent | `active`; set the authorized fields; write credentials; `version++` |
| replace credentials (refresh) | status is `active`; `version` equals the one read | write credentials; `version++` |
| require reauthorization | status is `active`; `version` equals the one read | `reauthorization_required`; delete credentials; `version++` |
| revoke | status is not `revoked` | `revoked`; record `revocation`; delete credentials; `version++` — one atomic operation that always wins |
| first intent lapses unused | — | the `pending` grant is deleted with it |

`revoked` and expired are terminal: new consent means a new grant. The grant
ID stays the same across reauthorization from `active` (a renewal) and from
`reauthorization_required`, as the Australian CDR does with
`cdr_arrangement_id`.

A writer whose precondition fails does not use what it fetched. It
re-evaluates D10 from the top: if the winner was another refresh it returns
the stored token, and if the winner was a revocation it answers
`grant_revoked`. It never returns a token it obtained for a grant it could not
write.

`lastUsedAt` is a best-effort field write that does not bump `version` and
cannot fail a call.

Two races are part of the contract suite both adapters run: a callback that
passed its checks and activates after a revocation (it must fail), and a
refresh in flight while the grant is revoked (it must not re-create the
credential record, and must not return the token).

### D3 — Expiry is absolute, required, and bounded by the operator

`federationGrants.defaultExpiresIn` and `federationGrants.maxExpiresIn` follow
the rules `oauth.accessToken` got in 0.14.0, including the schema's one-year
ceiling on the maximum. A requested `expires_in` is clamped, not rejected, and
the response reports the value that applied. `expiresAt` is `consent.at` plus
that value, fixed at consent. A refresh never moves it; only a new consent
does.

At retrieval, lowering the maximum also shortens existing grants:

```
effectiveExpiry = min(grant.expiresAt, grant.consent.at + maxExpiresIn)
```

That is what an operator lowering it means. Nothing that is persisted — key
TTLs, the revocation watermark (D13) — is computed from the configured
maximum, because a value that can be raised again cannot be the basis of a
guarantee. Persisted horizons use the stored `expiresAt` or the schema ceiling.

A mandatory expiry is not universal practice: the FAPI Grant Management WG
decided against one, and the UK relaxed its 90-day re-authentication because
of the cost. Hence a required field with an operator-set ceiling and no fixed
cap below the schema's.

### D4 — Connections are configured by name, with two revisions

```hocon
federationGrants.connections.<name> {
  federation = "<key under federations>"
  scopes = ["openid", "offline_access", "..."] # the ceiling an intent may ask within
  resource = "https://api.example"              # optional, RFC 8707
  authorizationParams { prompt = "consent" }    # allowlisted keys only
  callbackURL = "https://.../session/federation-grants/callback/<name>"
  maxAccessTokenLifetime = 3600                 # seconds, see D5
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
  that came with it fails condition 2. Discarding the response would discard
  the only valid credential.
- When condition 2 fails, only the access token is withheld. The call answers
  `upstream_token_ineligible`, the grant is untouched, and an operator who set
  `maxAccessTokenLifetime` too low fixes it without any user acting.

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
- `scope`, when sent, must be a subset of the connection's `scopes`. The
  validated subset is bound to the intent and is what consent shows and what
  is requested upstream. Absent, it is the connection's full set.
- `upstream_sub`, when the client already knows which upstream account it
  expects, is checked at the callback.
- `connect_uri` is `/session/federation-grants/connect?request=<handle>`. The
  handle is single-use, 256 bits, and lives for 10 minutes.

This is the pattern of RFC 9126 (PAR) and of UK Open Banking's consent
resource, and it is what lets the callback be bound to "the intended subject,
connection, and pending request" as the issue requires. A browser-initiated
start could name any `client_id`; this one cannot.

Reauthorization is the same call on an existing grant:
`POST /oauth/federation-grants/:grantId/reauthorize`. It is accepted from
`active` and `reauthorization_required`, not from `pending`.

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
- Neither of those, nor an unknown handle, nor a prefetch, spends the handle.
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
   still live, the browser still presents it, and its `sub` is the intent's
   `sub`;
4. the adapter's own validation passes (PKCE, `id_token` signature, `iss`,
   `aud`, `exp`, `nonce`);
5. account binding. On reauthorization the upstream `(issuer, subject)` must
   equal the one on the grant. With `upstream_sub` in the intent it must equal
   that. If the upstream identity is linked to a *different* local subject the
   flow is refused; one linked to nobody is accepted and recorded;
6. eligibility (D5);
7. scope containment. The scopes the upstream reports must be within
   `consent.scopes`. A response that omits `scope` means "as requested"
   (RFC 6749 §5.1). An upstream that grants more than the user was shown is
   refused, because an upstream token cannot be narrowed after the fact;
8. the guarded activation in D2.

`form_post` federations are not eligible: the session cookie is absent on
their callback, so check 3 cannot run.

**Outcomes.** A failure of check 1 has no trustworthy redirect target and
answers a plain 400 from the provider. Every later failure leaves an existing
grant exactly as it was and redirects to the intent's `redirect_uri` with
`grant_id`, `state` and one of: `access_denied` (the user or the upstream
declined), `account_mismatch`, `identity_conflict`, `refresh_token_absent`,
`upstream_token_ineligible`, `scope_exceeded`, `upstream_error`,
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
the revocation backstop (D13) like a retrieval does, so it never reports
`active` for a grant that cannot be used.

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
3. the subject's revocation watermark does not cover `consent.at` (D13);
4. the connection is in the client's `allowedFederationGrantConnections`; an
   asserted `connection` names it; both revisions match (D4);
5. asserted `scope` is within the grant's scopes; asserted `resource` equals
   the grant's.

Then it returns the stored upstream access token if its remaining life
exceeds `max(min_ttl, refreshBuffer)`, and refreshes otherwise (D12).

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
	    scopes: readonly string[]; refreshed: boolean }
	| { ok: false; code: FederationGrantDenial; reason?: string; retryAfterSeconds?: number };
```

| `code` | reasons | HTTP | what the application does |
| --- | --- | --- | --- |
| `grant_not_found` | — | 404 | treat as no delegation; never fall back |
| `authorization_pending` | — | 400 | the user has not finished connecting |
| `grant_expired` | — | 410 | terminal; ask for a new grant |
| `grant_revoked` | `client`, `subject`, `operator`, `logout_policy`, `backstop` | 410 | terminal; ask for a new grant, if at all |
| `connection_identity_changed` | — | 410 | terminal while it lasts; ask for a new grant |
| `reauthorization_required` | `upstream_invalid_grant`, `connection_changed`, `credential_unreadable` | 410 | call `/reauthorize`, send the user, retry later |
| `access_denied` | `connection_not_permitted` | 403 | configuration; do not retry |
| `invalid_request`, `invalid_scope`, `invalid_target` | — | 400 | the request is malformed or exceeds the grant |
| `upstream_token_ineligible` | `no_finite_lifetime`, `lifetime_over_maximum` | 502 | operator; the grant is untouched |
| `upstream_rejected` | the upstream's error code | 502 | operator, e.g. an expired upstream client secret; the grant is untouched |
| `rate_limited` | `provider`, `upstream` | 429 | retry after `Retry-After` |
| `temporarily_unavailable` | `upstream`, `storage`, `lock_timeout`, `key_unavailable` | 503 | retry; the grant is untouched |

410 follows the session-bound endpoint's `re_authentication_required`. Only an
upstream `invalid_grant` and a revocation change a grant. No other outcome
changes its status or deletes anything, and no code path substitutes another
subject's grant or an application-wide credential.

### D12 — Refresh is coordinated per grant, and fails safe

The session-bound lock cannot be reused as it is: it is typed to
`(sid, federationName)`, its TTL is a fixed 5 s with no renewal, and the write
after it is an unconditional `SET`. With a rotating upstream, a lock that
expires mid-refresh lets two replicas present the same refresh token, which a
reuse-detecting IdP answers by revoking the family.

- The lock is keyed by grant ID and added beside `internal/lock.mts`, not
  refactored into it. Its TTL is configurable
  (`federationGrants.refreshLockTtlMs`, default 30 s).
- No federation adapter sets a timeout, and `refreshToken()` takes no signal.
  So the caller bounds the wait (`federationGrants.upstreamTimeoutMs`, default
  10 s), and boot refuses a lock TTL that does not exceed it. A timed-out call
  has an unknown outcome: it answers `temporarily_unavailable` / `upstream`,
  and the stored refresh credential is not assumed to be still good.
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
consent given before it. A hit revokes that grant durably, with
`by: "backstop"`.

The watermark's retention cannot be computed from the configured maximum: a
grant consented under a long maximum survives the maximum being lowered,
revoked with a part-way failure, and raised again. So retention depends
neither on configuration nor on what the caller passes:

```
expiresAt = at + max(watermarkTtlMs, SUBJECT_REVOCATION_MIN_RETENTION_MS)
```

`SUBJECT_REVOCATION_MIN_RETENTION_MS` is a constant equal to the schema's
ceiling on `federationGrants.maxExpiresIn`, one year. `revokeAllForSubject`
applies it unconditionally. Any grant this watermark should stop was consented
at or before `at`, and its `expiresAt` was clamped at consent to at most
`consent.at` plus that ceiling, so it cannot outlive the watermark — whatever
the operator does to the configuration, and whether or not the Store passed
the grant store. Both adapters already refuse to shorten an in-force
watermark. The cost is one small key per revoked subject for a year, in every
deployment.

So the per-subject pass is what makes revocation prompt and deletes the
credentials at once, and the backstop is what makes it certain. A Store that
upgrades without touching its `revokeAllForSubject` call site is safe, not
silently exempt. The primary path alone fails when a store write fails
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
key TTL that is only a safety net. Its shape, not its final signatures:

```ts
interface FederationGrantStore {
	readonly kind: string;
	lodge(intent: FederationGrantIntent): Promise<LodgeResult>; // creates or supersedes; enforces the bound
	readIntent(handle: string): Promise<FederationGrantIntent | null>;
	consumeIntent(handle: string): Promise<FederationGrantIntent | null>; // atomic, single-use
	putTransaction(tx: ConnectTransaction): Promise<void>;
	consumeTransaction(state: string): Promise<ConnectTransaction | null>; // atomic, single-use
	find(grantId: string): Promise<FederationGrant | null>;
	listBySubject(subject: string): Promise<readonly FederationGrant[]>;
	openCredentials(grant: FederationGrant): Promise<OpenResult>; // "unreadable" and "key_unavailable" are results, not throws
	activate(grantId: string, intentHandle: string, fields: AuthorizedFields, credentials: UpstreamCredentials): Promise<TransitionResult>;
	replaceCredentials(grantId: string, expectedVersion: number, credentials: UpstreamCredentials): Promise<TransitionResult>;
	requireReauthorization(grantId: string, expectedVersion: number): Promise<TransitionResult>;
	revoke(grantId: string, by: RevokedBy, at: Date): Promise<boolean>; // whether it changed anything
	touch(grantId: string, at: Date): Promise<void>;
}
```

Redis layout, default prefix `fg:`. Keys that one script touches share a
Cluster hash tag, as the consent store's do:

- `fg:{<id>}:grant` — a HASH of non-secret fields, `status` and `version`. The
  status route reads this without decrypting anything.
- `fg:{<id>}:cred` — one AES-256-GCM ciphertext of the upstream tokens,
  reusing `internal/crypto.mts`.
- `fg:{<id>}:lock`.
- `fg:sub:<subject>` — a ZSET index scored by `expiresAt`, written before the
  record; a dangling entry is tolerated and pruned.
- `fg:intent:<handle>` and `fg:tx:<state>`, each with its own TTL.

Key TTLs come from the stored `expiresAt`, never from `effectiveExpiry`, which
depends on configuration (D3). The grant HASH keeps a tombstone retention
beyond that, so a revoked or expired grant still answers the status route for
a while. The credential key gets no such retention. A `pending` grant lives as
long as its intent.

**The authorization binding is inside the authenticated envelope.** The
session-bound store binds a ciphertext to its key name, because there the key
name *is* the binding (#293). Here the binding is a set of fields in a
plaintext HASH, and someone able to write to Redis — or a mismatched restore —
could re-point `clientId`, extend `expiresAt`, or move `consent.at` past the
watermark without touching the ciphertext. So the additional authenticated
data is a canonical encoding of the key name together with `id`, `subject`,
`clientId`, `connection`, `identityRevision`, `consent.at` and `expiresAt`,
recomputed from the HASH when the credential is opened. A tampered field fails
authentication and reads as `credential_unreadable`.

Two behaviours differ from the session-bound store on purpose, because a
mistake here revokes every user's delegation at once:

- **A key ring.** `federationGrants.encryptionKeys` is a list of `{ id, key }`;
  the first seals, and the envelope names the key that sealed it. An unknown
  key ID is a configuration problem: 503 `key_unavailable`, record kept.
  Paused grants are not re-sealed, so the runbook says an old key stays in the
  ring for the one-year ceiling.
- **No self-heal delete.** A record that cannot be read is never deleted on
  read. `credential_unreadable` is computed, not persisted (D1): wrong key
  material under a known key ID must not durably flip every grant.

The `allow-plaintext` production guard applies unchanged. The in-memory
adapter declares `replicaSafety: unsafe`.

### D17 — The federation adapter surface gains one capability

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
}
```

`FederationProfile` and `RefreshedTokens` also gain the token response's
`scope` and `token_type`. The generic OIDC adapter's `snapshot` drops both
today, so the scope actually granted is unobservable, and D7 check 7 needs it.
Both additions are optional, so existing adapters and the login flow are
unaffected. A connection whose federation lacks the capability is refused at
boot. The first cut implements it for the generic OIDC adapter.

### D18 — Audit, with a correlation ID

New event types, each added to `BUILT_IN_AUDIT_EVENT_TYPES`:
`federation.grant.requested`, `.authorized`, `.reauthorized`,
`.authorization_failed`, `.token.success`, `.token.denied`,
`.reauthorization_required`, `.refresh_failed`, `.refresh_persist_failed`,
`.revoked`.

Every event carries the grant ID, the caller in `clientId`, the owner and the
upstream subject, the connection, the resource, the scopes, the outcome and a
correlation ID. The provider has no request ID today; these routes accept
`x-request-id` when it is 1–128 characters of `A-Z a-z 0-9 - _ . : + / = #`
(the shape auth.policy-verifier 0.11.0 settled on), generate one otherwise,
and echo it. No event, response or log line carries a refresh token or any
other long-lived secret.

### D19 — Entra: on-behalf-of is not implemented, and scopes need their own registration

An OBO assertion must be an access token issued for the middle-tier API that
makes the request. A token auth.provider issued, or a login through another
IdP, is not one. The documentation says OBO is unsupported, and describes the
supported path: an authorization-code connect flow against Entra as an OIDC
federation with `offline_access`. OBO can follow if there is demand.

Entra returns every scope the user has ever consented to for a resource and
client, not only the ones just asked for. Under D7 check 7 a narrower intent
is then refused. The documentation says so and gives the remedy, which is also
the isolation the issue asks for: a dedicated app registration per connection.

## Acceptance criteria

| # | criterion in #593 | decided in | proving test |
| --- | --- | --- | --- |
| 1 | survives restart and session expiry | D1, D14, D16 | Redis adapter: new client instance, session deleted, token returned |
| 2 | not renewable without refresh credentials | D5 | callback with no `refresh_token`: no credential is stored, the grant never leaves `pending`, the redirect says `refresh_token_absent` |
| 3 | wrong client / subject / connection / environment / resource / scopes denied, grant ID known | D4, D9, D10 | one case per dimension, on all four grant-addressed routes; "not yours" responses are byte-identical; `boundary` change reads as `connection_changed` |
| 4 | expired or revoked upstream credentials → reauthorization, no fallback | D11, D12 | structured upstream `invalid_grant`; assert no other grant or credential is read |
| 5 | transient failures distinguishable and non-destructive | D5, D11, D12 | injected 5xx, 429, timeout, storage throw, `invalid_client`, over-long token lifetime; record unchanged in each |
| 6 | concurrent refresh, lock expiry, restart, persistence failure | D2, D12 | two replicas on one testcontainer; lock TTL forced to expire; guarded-write loser; injected persist failure; refresh response without `refresh_token` |
| 7 | duplicate, stale, wrong-account callbacks cannot replace or broaden | D6, D7 | replayed callback; superseded intent; expired intent; different upstream `sub`; upstream grants more scopes than consented |
| 8 | session-expiry / logout / subject-revocation behaviour; session-bound endpoint preserved | D13, D14 | both logout endpoints, policy off and on; existing `federationToken` suite untouched and green |
| 9 | no refresh token or long-lived secret in responses, audit or logs | D18 | a sentinel secret is grepped for in every response body, audit event and captured log line |
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
  lapsing `pending` grant stored, nothing disclosed (D5, D15).

And D2 adds the two races, in the contract suite both adapters run.

Time is controlled (`now` is injected everywhere it is read) and failures are
injected deterministically.

## Build order

Each slice is its own PR and follows RED → GREEN → REFACTOR: the contract or
route test is written first and watched failing.

1. **core: port and domain.** `federation-grants/` types, the typed result,
   the transition rules, the two revisions, eligibility, the in-memory adapter
   and the contract suite, races included.
2. **federation adapter capability** (D17), generic OIDC first.
3. **redis adapter** (D16), with the duplicated contract suite on a
   testcontainer, the guarded-write scripts and the grant-keyed lock.
4. **package: token and status routes** (D9–D12), exercised on grants seeded
   straight into the store; the `Client` fields, audit events, configuration.
5. **revocation** (D13): the revoke route, the two library functions, the
   `revokeAllForSubject` extension, the retention floor, and the condition
   tests.
6. **acquisition** (D6–D8): the intent routes, consent, the connect flow.
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
fields. A rotating upstream combined with a storage outage or a timeout during
a refresh costs the user a reconnect (D12). Connections on federations that
issue non-expiring tokens are unsupported (D5). Entra needs an app
registration per connection (D19). Every revoked subject leaves a watermark
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
