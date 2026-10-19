# federation-tokens

## Responsibilities
- Keeps the upstream tokens of a federation login, sealed, per session and IdP, and seals again what a `previous` key sealed: when a read opens it (a write that cannot be made leaves the read whole), and for `seal`'s resealers (as `federation-tokens`, walking every record and counting an entry no key opens).
- Hands a receiving client the session's upstream access token.
- Refreshes that token when its end is near.
- Logs a session out of one upstream: forgets that IdP's tokens, then sends the browser to the upstream's end of session.
- Forgets a session's upstream tokens when the session closes.
- Builds the end of session of a session's first upstream, for a logout that starts elsewhere.
- Its internal modules: `caller` accepts the access token a request presents; `renewal` keeps the records and renews them; `vault` seals them and reads their shape.

## Not here
- The upstream login and the IdP types (`upstreams`). What a refresh request holds (the IdP type). Checking and binding access tokens (`tokens`, `sender-binding`). The link of a token to its session (`session-tokens`). Offline delegation (federation-grants).

## Offers
- Receiver `federation-tokens` for `upstreams`' upstream login receivers; its receipt is the kept entry's version, so `withdrawn` given it removes that entry only while it holds that version, and without one removes nothing.
- Participant `federation-tokens` for closing sessions.
- `upstreamEndSessions.of` (session handle, return and state → the end of session of the first IdP the session holds tokens of, with its id_token as the hint / none).
  - It forgets nothing, so it is asked before the session closes.
  - An end of session the upstream cannot build is none, warned as `federation-tokens.end_session_failed` with the IdP and the failure's kind only.
- Route `POST /oauth/federation/<idp>/token` (no body is read): `200 {access_token, token_type: "Bearer", expires_in?, scope?}`; taken from other sites, as a client's own call, authenticated as that client, which reads no cookie.
  - `expires_in` only for a finite end; `scope` only when there is one.
  - Errors: `401 invalid_token` (or `sender-binding`'s answer), `403 forbidden` or `upstream_interaction_required`, `404 federation_not_linked`, `410 refresh_token_absent`, `re_authentication_required` or `refresh_not_supported` (no refresh at the upstream, or an IdP no longer set), `429 rate_limited` (the upstream's `retry-after` when 1 to 86400), `500 refresh_failed`, `502 upstream_token_ineligible` (`retry-after: 300`), `503 lock_timeout` or `temporarily_unavailable`.
- Route `POST /oauth/federation/<idp>/logout` (form: `post_logout_redirect_uri?`, `state?`): `303` to the upstream's end of session, or `200 {"disconnected": true}` where it has none or fails; taken from other sites as the token route is.
  - Errors as the token route's, without `403`.
- Both routes answer `no-store` and are limited per source by `rate-limit`'s requests policy.
- Client metadata section `federation-tokens`: `receives` (default false), `post-logout-redirect-uris` (default none).
- Operator section: `refresh-before` (default `30s`), `max-lifetime` (default `1d`), `lock-lifetime` (default `5s`), `requests` in `window`; times written with their unit, a bare number refused.
- Store interfaces, which the assembly wires; the store never reads a record.
  - Upstream tokens: one record per session handle, saved once, read, changed from what it holds with a new lifetime or its own, removed, and the sessions whose records live walked by pages. Needs: no eviction, never rolled back by failover.
  - Refresh locks: held under their holder's mark unless held, for a lifetime, and changed only from the mark they hold. Needs: no eviction.
- Audit events with the subject, `idp`, `client` and the source when determined: `federation.token.succeeded` (`refreshed`), `federation.token.failed` (`reason`), `federation.logout.succeeded` (`redirected`).
- Test configuration builders and the contract test of both store interfaces (`./testing`).

## Invariants
- A token goes out only to a client the operator made a receiver (`receives`).
- A token goes out only for a presented access token `caller` accepts: its audience names its client, its family has not ended, and its session enters at `use` for the same subject (one short of a requirement does not).
- The session is checked again before answering.
- Only a bearer token goes out (any case). Any other type answers `502`, and the record stays.
- A session's record lives no longer than the session (the end of its entry at `session`).
- Nothing is kept for a session that lets nobody in at `use` (one short of a requirement included), even one that closes while a login's tokens are written.
- An entry holds the access, refresh and id tokens, the end, the scope the login granted and the scope now. Nothing else of the upstream's is kept.
- A write lands only over the version it read, so a removed or relinked entry is neither brought back nor written over.
- Only a structured `invalid_grant`, or `interaction_required` (the upstream asks the user to act there first), removes an entry.
- A rotated refresh token is kept when the answer matches the IdP type's token answer schema, even where the rest of it is refused here.
- An upstream logout removes the IdP's entry before it builds the upstream URL.
- The return goes to the upstream only on an exact match of the client's list.
- The id_token goes to the upstream only as the hint.
- Tokens and upstream text reach neither answers, logs nor audit.

## Data
- A failed refresh answers the same for 30 seconds without asking the upstream: kept in each process, by session, IdP and a hash of the access token.

## Depends on
- `kernel`, `http`, `request-source`, `clients`, `upstreams`, `rate-limit`, `audit`, `session`, and through its internal modules `tokens`, `sender-binding`, `refresh`, `session-tokens`, `seal`

## Vocabulary
- receiver: a client the operator lets receive upstream tokens.
- entry: one IdP's sealed tokens in a session's record, with its version.
