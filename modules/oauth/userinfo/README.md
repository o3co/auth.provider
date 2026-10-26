# userinfo

## Responsibilities
- Serves OIDC's userinfo: admits the access token a request presents, checks the session it was issued in, and answers `sub` and the claims `oidc` releases for its scope and the selection `claims-selection` kept for the token.

## Not here
- The claim table and mapping attributes to claims (`oidc`). A token's validity (`tokens`) and its holder's proof (`sender-binding`). Whether a session is open (`session`). Which session a token was issued in (`session-tokens`). What a token's request asked beyond its scope (`claims-selection`). How cross-origin requests are answered (`http`).

## Offers
- Routes `GET` and `POST /oauth/userinfo`, the GET declared not to change state and the POST to take requests from other sites without a per-source limit, taking cross-origin requests from the operator's origins: a page may send `authorization`, `dpop` and `content-type`, and read `www-authenticate`, `dpop-nonce` and `retry-after`.
- The issuer's metadata `userinfo_endpoint`.

## Invariants
- The token comes from the `Authorization` header only, admitted by `sender-binding`; a body or query `access_token` is never read. A refusal is passed on with its status and challenge; one for a request with no token carries no `error`.
- A token whose scope lacks `openid` is refused `403 insufficient_scope`, challenged in the token's scheme, before its session is read.
- The token's audience is not read: userinfo is the issuer's own resource, answering any token it issued whose session enters.
- A token issued in no session (client credentials, say) is answered `sub` only.
- A token issued in a session is answered its claims only while that session enters at `use` for the token's subject; else (closed, ended, revoked, short of a requirement, or another subject's) `401 invalid_token`, challenged in the token's scheme.
- The claims are what `oidc` releases for the token's scope and its kept selection: the names it asks beyond the scope, and the constraints on all it releases. The selection is read only for a token whose session enters.
- `sub` is always the token's subject, and `sid` is never answered.
- Every answer is `no-store`. A check or the claims that cannot tell answer `503 temporarily_unavailable`, never a refusal or a claim, logged as `userinfo.unavailable` (warn) with what failed.

## Data
- None.

## Depends on
- `kernel`, `http`, `issuer` (metadata), `sender-binding`, `tokens`, `session`, `session-tokens`, `claims-selection` (a token's selection), `oidc` (released claims)
