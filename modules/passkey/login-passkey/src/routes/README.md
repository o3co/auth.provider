# routes

Internal module of `login-passkey`: the options route and the login route, up to the assertion.

## Responsibilities
- Answers options under a new requester, kept in a cookie, and redeems the assertion sent back with it, handing what it proved to `opening`.

## Not here
- What follows the assertion (`opening`). Assertions and challenges (`passkeys`). Where a login may return (`login-gates`).

## Offers
- `routesIn` → the options route and the login route; `loginRoutes` (passkeys, cookies, where a login may return, the opening, what it records, random bytes, the challenge's lifetime, the window per source).

## Invariants
- A requester is 32 random bytes in base64url, kept in the cookie `passkey-login` (`__Host-` where cookies are secure) as long as the challenge lives.
- The login route refuses before the assertion is asked: a repeated parameter, a destination `login-gates` does not allow, a `response` that is no object.
- With no requester cookie, or an assertion `passkeys` refuses, it records `passkey.session.refused` with the refusal and answers `401`.
- A store unavailable is `503` `temporarily_unavailable`.
- Every login answer, whatever it is, ends the requester's cookie, in one place: the challenge is redeemed once.

## Depends on
- `http`, `csrf`, `rate-limit`, `cookies`, `passkeys`, `webauthn` (the challenge's lifetime), `login-gates`; the internal modules `opening` and `audited`
