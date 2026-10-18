# token-control

## Responsibilities
- Answers the introspection endpoint (RFC 7662) and the revocation endpoint (RFC 7009).
- Revokes access tokens itself, and other token kinds through the modules that contribute them.

## Not here
- The token format and its revocation: `tokens`.
- What a contributed token kind does when revoked: the contributing module.

## Offers
- Routes: `POST /oauth/introspect` and `POST /oauth/revoke`. Revocation answers `http`'s listed origins (a page may send `authorization` and `content-type`, and read `www-authenticate` and `retry-after`); introspection answers none.
- Extension point: revocable token kinds, one per hint; a kind takes a token and a client and answers written, done, unknown or unsupported.
- `issuer` metadata: `introspection_endpoint`, and `revocation_endpoint` where any token can be revoked; both absolute on `http`'s public origin, and left out without one. With each, its `*_auth_methods_supported` (`clients`' methods; at introspection, not `none`) and `*_auth_signing_alg_values_supported` where a method signs.
- Audit events, never holding a token: declared in `./audit-events`, listed in the audit event reference.
- Both events carry `source` when `request-source` determines it.
- Operator section: `requests` (per source, window and route; 1–100000, default 60) and `window` (written with its unit, `1s` to `1d` in whole seconds, default `1m`).

## Invariants
- Each route counts requests per source on its own, before any client is authenticated, and answers `429` past the limit.
- Both routes refuse a repeated parameter with `invalid_request`.
- Introspection refuses public clients.
- Introspection answers active only for a valid token whose audience the caller may see (`token-endpoint`'s allowance); every other token is `active:false`.
- A bound token is introspected with its own token type and `cnf`.
- Only the client a token was issued to can revoke it; another client gets `200` and the token stays.
- An access token's revocation is written on every request, past any earlier one, and answered only once confirmed.
- The hint only orders the kinds tried; a token no kind knows gets `200`.
- A kind that cannot revoke its token gets `unsupported_token_type`, as do access tokens where `tokens` cannot revoke them.
- A contribution for the hint `access_token` refuses boot.
- An unavailable dependency answers `503`, never `active:false` or `200`; both routes then warn `token-control.unavailable` with what and the route, and introspection records `introspection.unavailable`.

## Depends on
- `kernel`, `http`, `request-source`, `clients`, `issuer`, `tokens`, `token-endpoint`, `rate-limit`, `audit`

## Vocabulary
- written: this request wrote the token's revocation.
- done: nothing is left to do, as for a token already revoked or issued to another client.
