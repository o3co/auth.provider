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
follow that shape and build on the parts that are already RFCs (6749, 7009,
8707, 9126, 9396), so that what is specific to this project stays thin.

## Vocabulary

- **Federation grant** (a *grant* below): a record of one user's consent that
  one client may obtain upstream access tokens through one connection, within
  stated scopes, until a stated time. It owns the upstream refresh credential.
  "Grant" here never means an OAuth grant type; the directory is
  `federation-grants/`, next to `federation-tokens/`.
- **Connection**: a named configuration entry that points at a
  `federations.<name>` section and adds what delegation needs: the scopes to
  request, the resource, extra authorization parameters, its own callback URL,
  and the limits in D4. Two connections on the same federation share nothing.
- **Connection revision**: a fingerprint of a connection's security-relevant
  fields. A grant records the revision it was authorized under.
- **Owning client**: the one confidential client a grant names.
- **Residual access**: what an upstream access token that was already handed
  out still allows after the provider has stopped issuing new ones.

## Decisions

### D1 — A grant is a first-class record with its own lifecycle

```ts
interface FederationGrant {
	readonly id: string; // opaque, 256 bits, base64url; a reference, not a credential
	readonly status: "pending" | "active" | "reauthorization_required" | "revoked";
	readonly subject: string; // the local owner
	readonly clientId: string; // the owning client
	readonly connection: string;
	readonly connectionRevision: string;
	readonly upstream: { readonly issuer: string; readonly subject: string } | null;
	readonly resource?: string;
	readonly scopes: readonly string[]; // as granted by the upstream, not as asked
	readonly consent: { readonly at: Date; readonly sid: string } | null;
	readonly createdAt: Date;
	readonly authorizedAt: Date | null;
	readonly expiresAt: Date;
	readonly lastUsedAt?: Date;
	readonly reauthorization?: { readonly reason: ReauthorizationReason; readonly at: Date };
	readonly revocation?: { readonly by: RevokedBy; readonly at: Date };
	readonly version: number; // for compare-and-set, see D11
}
```

`expired` is not stored; it is `now >= effectiveExpiry(grant)` (D2). A grant
names exactly one client in the first cut. The issue allows "client(s)"; one
is enough for every case we have, and it keeps isolation trivially true.

The grant ID stays the same across reauthorization from `active` (a renewal)
and from `reauthorization_required`, as the Australian CDR does with
`cdr_arrangement_id`. `revoked` and expired are terminal: new consent means a
new grant.

### D2 — Expiry is absolute, required, and bounded by the operator

`federationGrants.defaultExpiresIn` and `federationGrants.maxExpiresIn` follow
the rules `oauth.accessToken` got in 0.14.0. A requested `expires_in` is
clamped to the maximum, not rejected, and the response reports the value that
applied. A refresh never moves `expiresAt`; only a new consent does.

```
effectiveExpiry = min(grant.expiresAt, grant.authorizedAt + maxExpiresIn)
```

The second term uses the *current* maximum, so lowering it shortens existing
grants. That is what an operator lowering it means, and D12's revocation
horizon depends on it.

A mandatory expiry is not universal practice: the FAPI Grant Management WG
decided against one, and the UK relaxed its 90-day re-authentication because
of the cost. Hence a required field with an operator-set ceiling and no fixed
cap.

### D3 — Connections are configured by name and fingerprinted

```hocon
federationGrants.connections.<name> {
  federation = "<key under federations>"
  scopes = ["openid", "offline_access", "..."]
  resource = "https://api.example"          # optional, RFC 8707
  authorizationParams { prompt = "consent" } # allowlisted keys only
  callbackURL = "https://.../session/federation-grants/callback/<name>"
  maxAccessTokenLifetime = 3600              # seconds, see D4
  boundary = "prod-eu"                       # optional, operator-chosen
}
```

The revision is a SHA-256 over the upstream issuer, the upstream client ID,
`resource`, the sorted `scopes` and `boundary`. If a grant's recorded revision
differs from the current one, retrieval answers `reauthorization_required`
with reason `connection_changed`. Narrowing the scopes changes the revision
too. Reusing consent across a narrowing would be sound, but proving "narrower"
for every field is not worth a first cut; asking again is always safe.

A client is pinned to connections by a new `Client` field,
`allowedFederationGrantConnections?: readonly string[]`, absent meaning none.
A list, not a boolean, because "may use delegation" without "through which
connection" is the implicit sharing the issue forbids.

### D4 — Only connections with renewable, bounded tokens are eligible

A connection can back a grant only if the upstream token response carries

1. a refresh token, and
2. a finite `expires_in` that does not exceed the connection's
   `maxAccessTokenLifetime`.

The same check runs on every refresh. "Finite" alone would admit a 30-day
access token; the maximum is what turns residual access (D14) into a number
the operator chose. A token with `expiresAt: null` fails by definition, with
the typed outcome `unbounded_token_lifetime`, and nothing is stored or
disclosed. GitHub OAuth Apps' classic tokens fail twice: no expiry and no
refresh token. The session-bound endpoint keeps its `expiresAt: null`
behaviour unchanged.

Not in the first cut: an adapter capability for upstream revocation (RFC 7009
or provider-specific) could admit such connections as an explicit opt-in.

### D5 — Acquisition starts with an intent the backend lodges

The backend creates the grant before the user sees anything:

```
POST /oauth/federation-grants          (client-authenticated)
  connection, sub, redirect_uri, [scope], [expires_in], [state]
→ 201 { grant_id, status: "pending", connect_uri, connect_expires_in }
```

`redirect_uri` must be one of the client's `allowedRedirectUris`. `connect_uri`
carries a single-use 256-bit request handle that lives for 10 minutes. This is
the pattern of RFC 9126 (PAR) and of UK Open Banking's consent resource, and
it is what lets the callback be bound to "the intended subject, connection,
and pending request" as the issue requires. A browser-initiated start could
name any `client_id`; this one cannot.

Reauthorization is the same call on an existing grant:
`POST /oauth/federation-grants/:grantId/reauthorize`.

A login never creates a grant, and a connect never creates a login link.

### D6 — The connect flow binds its callback, and refuses on any mismatch

`GET <connect_uri>` (a session route) requires an authenticated provider
session whose `sub` equals the intent's `sub`, and a trusted request origin,
as the link start does today. It obtains consent (D7), then redirects upstream
with `state`, `nonce`, PKCE, the connection's scopes and its
`authorizationParams`.

The transaction is a single-use server-side record with a 10-minute TTL, in
the style of `fedtx:`. It is not the one-slot `req.session.federation`
envelope, which a second start overwrites.

The callback, `/session/federation-grants/callback/:connection`, checks in
order:

1. the transaction exists and names this connection; `state` matches;
2. the transaction is retired before the code is exchanged;
3. the session is still the one that started the flow, and its `sub` is still
   the intent's `sub`;
4. the adapter's own validation passes (PKCE, `id_token` signature, `iss`,
   `aud`, `exp`, `nonce`);
5. account binding. On reauthorization, the upstream `(issuer, subject)` must
   equal the one on the grant. On first authorization, if that upstream
   identity is linked to a *different* local subject the flow is refused; an
   identity linked to nobody is accepted and recorded on the grant;
6. eligibility (D4);
7. the intent is still pending and unexpired, and the grant is still in a
   state that accepts authorization.

Any failure leaves an existing grant exactly as it was — nothing is replaced
or broadened — and redirects to the client's `redirect_uri` with `error`,
`grant_id` and `state`. Success stores the credentials, sets `active`, and
redirects with `grant_id` and `state`.

`form_post` federations (Apple) are not eligible in the first cut: the session
cookie is absent on their callback, so check 3 cannot run.

The grant ID in the redirect is not proof of anything. The client confirms
with `GET /oauth/federation-grants/:grantId` that the grant's `sub` is the
user it is serving before it stores the reference.

### D7 — Consent is the provider's own, and it is recorded

The upstream's consent screen names auth.provider's upstream client. It says
nothing about which backend client will act, until when, or that this outlives
logout. So the connect flow parks a consent challenge exactly as `/authorize`
does (`packages/oauth/src/routes/consent.mts`: an unguessable challenge bound
to the session, read and answered by the deployment's consent page). The page
is told the client, the connection, the scopes, the expiry, and that access
continues after logout. The answer is recorded in `grant.consent`.
`firstParty` clients are not exempt.

### D8 — Client-authenticated routes in a new package, not an extension grant

```
POST   /oauth/federation-grants                        lodge an intent (D5)
POST   /oauth/federation-grants/:grantId/reauthorize   lodge a reauthorization
POST   /oauth/federation-grants/:grantId/token         upstream access token
GET    /oauth/federation-grants/:grantId               status, non-secret
DELETE /oauth/federation-grants/:grantId               revoke; 204; idempotent
```

All five use `createClientAuthMiddleware` with `allowPublicClients` left at
its default, behind a rate-limit guard, and set `Cache-Control: no-store` on
every exit. They ship in a new package, `@o3co/auth-provider-federation-grants`,
which contributes its routes the way `device-grant` does and answers 404 when
disabled. The port and the in-memory adapter live in core, so that
`revokeAllForSubject` and `/session/logout` can reach them; the Redis adapter
lives in `@o3co/auth-provider-redis`.

An extension grant on `/oauth/token` was considered, because RFC 8693 is the
natural wire shape. It fits this codebase badly: a successful grant must be a
`TokenResponse` and is always audited as `token.issued`, which mislabels an
upstream token; `GrantDependencies` carries no audit sink; error exits get
neither `no-store` nor `WWW-Authenticate`; and a client with
`senderConstrained.required` would have to present DPoP or mTLS proof for a
token that cannot carry `cnf`. The route keeps RFC 6749 field names
(`access_token`, `token_type`, `expires_in`, `scope`), so a token-exchange
profile can be added later as a thin facade if a standard settles.

### D9 — Every retrieval re-evaluates the grant

`POST …/:grantId/token` accepts `min_ttl` (seconds), and optionally `sub`,
`scope` and `resource` as assertions the provider checks. It evaluates, in
order:

1. the grant exists and its `clientId` is the authenticated client; an
   asserted `sub` equals the grant's subject;
2. status is `active`, and `now < effectiveExpiry`;
3. the subject's revocation watermark does not cover `authorizedAt` (D12);
4. the connection is in the client's `allowedFederationGrantConnections`, and
   its revision matches;
5. asserted `scope` is within the grant's scopes; asserted `resource` equals
   the grant's.

Then it returns the stored upstream access token if its remaining life
exceeds `max(min_ttl, refreshBuffer)`, and refreshes otherwise (D11).
`expires_in` in the response is
`min(token remaining, effectiveExpiry − now)`. That clamp is a cache hint for
a cooperating worker. It is documented as such and never as enforcement (D14).

Step 1 answers 404 `grant_not_found` for an unknown ID, another client's
grant and a subject mismatch alike, so a known grant ID tells a stranger
nothing.

### D10 — One typed result, one HTTP mapping

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
| `grant_expired` | — | 410 | ask for a new grant |
| `grant_revoked` | `client`, `subject`, `operator`, `logout_policy` | 410 | ask for a new grant, if at all |
| `reauthorization_required` | `upstream_invalid_grant`, `connection_changed`, `credential_unreadable` | 410 | call `/reauthorize`, send the user, retry later |
| `access_denied` | `connection_not_permitted` | 403 | configuration; do not retry |
| `invalid_scope` / `invalid_target` | — | 400 | the request exceeds the grant |
| `unbounded_token_lifetime` | — | 502 | the upstream stopped meeting D4; operator |
| `rate_limited` | — | 429 | retry after `Retry-After` |
| `temporarily_unavailable` | `upstream`, `storage`, `lock_timeout` | 503 | retry; the grant is untouched |

410 for the three terminal-until-interaction codes matches the session-bound
endpoint's `re_authentication_required`. A transient failure never changes the
grant's status and never deletes anything. No code path substitutes another
subject's grant or an application-wide credential.

### D11 — Refresh is coordinated per grant, and fails safe

The session-bound lock cannot be reused as it is: it is typed to
`(sid, federationName)`, its TTL is a fixed 5 s with no renewal, and the write
after it is an unconditional `SET`. With a rotating upstream, a lock that
expires mid-refresh lets two replicas present the same refresh token, which a
reuse-detecting IdP answers by revoking the family.

- The lock is keyed by grant ID. Its TTL is configurable
  (`federationGrants.refreshLockTtlMs`, default 30 s) and must exceed the
  upstream call's timeout (default 10 s); boot refuses a configuration where
  it does not.
- After acquiring the lock the record is re-read; another replica may have
  refreshed already.
- The write is a compare-and-set on `version`, in one Lua script. A writer
  that loses re-reads and returns the winner's token. It never overwrites a
  newer record.
- Upstream `invalid_grant` sets `reauthorization_required`, deletes the
  credentials and stops returning the cached token. 429 and 5xx/network
  failures change nothing.
- If the upstream refresh succeeds but the replacement cannot be persisted
  after bounded retries inside the lock, the call answers
  `temporarily_unavailable` / `storage`, the new credentials are dropped, and
  `federation.grant.refresh_persist_failed` is audited. The stored refresh
  credential is *not* assumed to be still good: the next refresh decides, and
  an `invalid_grant` there becomes `reauthorization_required`.

This does not claim exactly-once behaviour across an external IdP. It claims
that isolation holds and that every ambiguous outcome resolves toward asking
the user again.

### D12 — Revocation is persisted on the grant; the watermark is the backstop

There are three entry points, and ordinary logout is not one of them.

- **Per grant.** `DELETE /oauth/federation-grants/:grantId` for the owning
  client, and a library function `revokeFederationGrant(deps, grantId, by)`
  for the operator's Store. There is no admin route: the provider mounts none
  today ("a library call a Store makes rather than a route this server
  mounts"), and this follows that.
- **Per subject.** `revokeAllForSubject` gains an optional
  `federationGrantStore`. After the session cascade it lists the subject's
  grants and revokes each; a throw is a `failures` entry with
  `capability: "federationGrantStore"`, the grant stays enumerable for a
  retry, and `complete` accounts for it. Not passing the store means the
  deployment has no grants, not a gap.
- **At logout, by policy.** See D13.

Revoking sets `status: "revoked"`, records `revocation`, and deletes the
credential record. Deleting the refresh credential is what makes it
irreversible; nothing about it depends on a TTL. An outage is surfaced as 503
or as a `failures` entry, never swallowed the way `routes/revoke.mts` swallows
a `revokeFamily` throw.

**The backstop.** `revokeAllForSubject` stamps the subject watermark first, as
now. D9 step 3 compares it with the grant's `authorizedAt` — not with any
token's `iat`, since a token minted from a surviving grant is always fresh —
and a hit revokes that grant durably, with `by: "backstop"`. The watermark's
horizon is sized by a new helper, `resolveSubjectRevocationHorizonMs(config)`:
the longer of `oauth.refreshToken.expiresIn` and `federationGrants.maxExpiresIn`.
Because `effectiveExpiry` honours the current maximum (D2), no usable grant
can outlive that horizon. Both adapters already refuse to shorten an in-force
watermark, so a later, shorter write cannot undo it.

The primary path alone fails when a store write fails part-way. The watermark
alone would let a grant come back when the watermark expires — today's
retention is sized to refresh tokens — and would make the status API report
`active` for a grant that cannot be used. Hence both.

### D13 — Grants survive logout unless the deployment says otherwise

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

### D14 — "Retrieval stops" and "residual access" are separate boundaries

| event | retrieval | residual access |
| --- | --- | --- |
| grant expires or is revoked | stops immediately; the provider enforces it | tokens already disclosed work until their upstream expiry, at most `maxAccessTokenLifetime` |
| upstream revokes the refresh token | stops at the next refresh | the same |

The provider cannot shorten residual access. A shorter `expires_in` does not
make a token expire sooner at the upstream API. D4 is what bounds it. The
documentation states both boundaries for each event and does not describe the
clamp in D9 as a security control.

### D15 — Storage: status in the clear, credentials sealed, nothing self-deletes

The port follows `ConsentStore` (#589), not `FederationTokenStore`: a shared
contract suite that both adapters run, the caller's clock for expiry, and a
key TTL that is only a safety net.

Redis layout, default prefix `fg:`:

- `fg:grant:<id>` — a HASH of non-secret fields, `status` and `version`. The
  status API reads this without decrypting anything.
- `fg:cred:<id>` — one AES-256-GCM ciphertext of the upstream tokens, with the
  key name as additional authenticated data, reusing `internal/crypto.mts`.
- `fg:sub:<subject>` — a ZSET index, written before the record.
- `fg:req:<handle>` — intents and transactions, with their own TTL.
- `fg:lock:<id>`.

Key TTLs are `effectiveExpiry − now` plus a tombstone retention, so a revoked
or expired grant still answers the status API for a while, and revocation
state always outlives usability.

Two behaviours differ from the session-bound store on purpose, because a
mistake here revokes every user's delegation at once:

- **A key ring.** `federationGrants.encryptionKeys` is a list of `{ id, key }`;
  the first seals, and the envelope names the key that sealed it. An unknown
  key ID is a configuration problem: 503, record kept. A failed authentication
  tag under a known key is `reauthorization_required` /
  `credential_unreadable`, record kept.
- **No self-heal delete.** A record that cannot be read is never deleted on
  read.

The `allow-plaintext` production guard applies unchanged. The in-memory
adapter declares `replicaSafety: unsafe`.

### D16 — The federation adapter surface gains two optional things

- `buildAuthorizationUrl` accepts optional `scopes` and `authorizationParams`.
  The parameter set is fixed inside every adapter today, so `offline_access`
  with `prompt=consent` — what OIDC Core §11 requires — cannot be sent at all.
- `FederationProfile` and `RefreshedTokens` carry the token response's `scope`
  and `token_type`. The generic OIDC adapter's `snapshot` drops both today, so
  the scope actually granted is unobservable, and D1 needs it.

Both are optional, so existing adapters and the login flow are unaffected. A
connection whose federation's adapter does not implement them is refused at
boot. The first cut implements them for the generic OIDC adapter.

### D17 — Audit, with a correlation ID

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
and echo it. No event and no response carries a refresh token or any other
long-lived secret.

### D18 — Entra on-behalf-of is not implemented

An OBO assertion must be an access token issued for the middle-tier API that
makes the request. A token auth.provider issued, or a login through another
IdP, is not one. The documentation says OBO is unsupported, and describes the
supported path: an authorization-code connect flow against Entra as an OIDC
federation with `offline_access`. OBO can follow if there is demand.

## Acceptance criteria

| # | criterion in #593 | decided in | proving test |
| --- | --- | --- | --- |
| 1 | survives restart and session expiry | D1, D13, D15 | Redis adapter: new client instance, session deleted, token returned |
| 2 | not renewable without refresh credentials | D4 | callback with no `refresh_token` stores nothing |
| 3 | wrong client / subject / connection / environment / resource / scopes denied, grant ID known | D3, D9 | one case per dimension; responses for "not yours" are byte-identical |
| 4 | expired or revoked upstream credentials → reauthorization, no fallback | D10, D11 | upstream `invalid_grant`; assert no other grant or credential is read |
| 5 | transient failures distinguishable and non-destructive | D10, D11 | injected 5xx, 429, storage throw; record unchanged |
| 6 | concurrent refresh, lock expiry, restart, persistence failure | D11 | two replicas on one testcontainer; lock TTL forced to expire; CAS loser; injected persist failure |
| 7 | duplicate, stale, wrong-account callbacks cannot replace or broaden | D6 | replayed callback; expired intent; different upstream `sub` |
| 8 | session-expiry / logout / subject-revocation behaviour; session-bound endpoint preserved | D12, D13 | both logout endpoints, policy off and on; existing `federationToken` suite untouched and green |
| 9 | no refresh token or long-lived secret in responses or audit | D17 | a sentinel secret is grepped for in every response body and audit event |
| 10 | provider-specific `offline_access` documentation | D18 | documentation review |

The two review conditions add:

- a revoked grant whose lifetime exceeds the refresh-token watermark retention
  stays unusable after that retention has elapsed, on the durable path and on
  an injected part-way failure (D12);
- a grant that expires before its issued access token: retrieval stops, and
  the documented residual window is that token's remaining life; an upstream
  token with no finite expiry: refused, nothing stored, nothing disclosed
  (D4, D14).

Time is controlled (`now` is injected everywhere it is read) and failures are
injected deterministically.

## Build order

Each slice is its own PR and follows RED → GREEN → REFACTOR: the contract or
route test is written first and watched failing.

1. **core: port and domain.** `federation-grants/` types, the typed result,
   `effectiveExpiry`, the connection revision, eligibility, the in-memory
   adapter and the contract suite.
2. **federation adapter surface** (D16), generic OIDC first.
3. **redis adapter** (D15), with the duplicated contract suite on a
   testcontainer, the CAS script and the grant-keyed lock.
4. **federation-grants package: client routes** (D8–D10), the `Client` field,
   audit events, configuration.
5. **connect flow** (D5–D7).
6. **revocation** (D12): `revokeFederationGrant`, the `revokeAllForSubject`
   extension, the horizon helper and the two condition tests.
7. **logout policy** (D13).
8. **standalone template, documentation, CHANGELOG.** Includes the operator
   runbook rows the replica-safety drift test requires, `adapter-surface.md`,
   and the provider-specific `offline_access` guide.

Slices 1–3 change no behaviour. Nothing is reachable until 4.

## Consequences

**Good.** The session-bound guarantees are untouched. Application workers
never hold a refresh credential. Every grant has an owner, a client, a scope
and an end. Revocation cannot silently lapse. Each ambiguous failure resolves
toward asking the user again.

**Bad.** It is a large surface: a package, a port, two adapters, five client
routes, the connect flow and a consent page contract. A rotating upstream combined with a storage
outage during a refresh costs the user a reconnect (D11). Connections on
federations that issue non-expiring tokens are unsupported (D4). The safety
valve depends on the Store calling `revokeAllForSubject` with the grant store
wired; the watermark backstop covers a Store that forgets only if it sizes the
horizon with the new helper.

**Neutral.** Upstream refresh tokens also die from disuse — Google after six
months unused, Entra on a 90-day rolling window — and the provider runs no
scheduler. The status API reports `lastUsedAt` so that the application, which
owns scheduling, can refresh a paused job's grant before the window closes. A
connection may carry a documented idle lifetime later; the provider does not
hard-code one and does not promise indefinite unattended execution.

## Open for review

1. Whether D13's logout policy ships in the first release or the next. It is
   the last slice either way.
2. Whether a subject-wide revocation should always take grants with it (D12).
   It does here, as Global Token Revocation and OpenID Provider Commands both
   specify. A deployment that calls `revokeAllForSubject` on every password
   change will end its users' delegations on every password change. Keeping
   grants would need a second watermark.
3. The consent page contract in D7 reuses the mechanism, not the endpoints, of
   `/oauth/consent`. Whether one page should serve both is a UI question this
   ADR leaves to the first implementation.

## References

- #593 and its comments: direction, survey, and the two review conditions
- #276 (logout invalidation), #524 (generic OIDC federation), #589 (consent
  stores and their contract suites)
- RFC 6749, RFC 7009, RFC 8693, RFC 8707, RFC 9126, RFC 9396, RFC 9700 §4.14.2
- OpenID Connect Core 1.0 §11; OpenID Connect Back-Channel Logout 1.0 §2.7
- draft-zhu-oauth-async-delegation-05; draft-ietf-oauth-refresh-token-expiration-03;
  draft-parecki-oauth-global-token-revocation-06; OpenID Provider Commands 1.0 §6.14
- Consumer Data Standards (Australia): `cdr_arrangement_id`, `sharing_duration`
- `packages/core/docs/adr/2026-07-31-rfc8707-resource-audience-binding.md`
