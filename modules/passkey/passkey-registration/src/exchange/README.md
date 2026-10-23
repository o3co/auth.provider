# exchange

Internal module of `passkey-registration`: how its routes meet a request, before a passkey is touched.

## Responsibilities
- Enters the session at `credentials` and hands its subject to a route's work; answers no session, a session short of the requirement, and a store that cannot tell.
- Builds a POST route: JSON or no body, under `csrf`'s policy and `rate-limit`'s requests policy.

## Not here
- What each route does with a passkey (`registering`, `managing`). The routes' declaration and the section (the package's module).

## Offers
- `exchangeOver` (`session`'s sessions, the requests window) → `entered` (a route's work → a handler) and `post` (path, a route's work → the route).
- `sourced` (request → the `source` an audit event records, when determined); `invalid` (description → `400 invalid_request`).

## Invariants
- The subject comes from the session, never from the body.
- No session is `401 unauthorized`; short of `credentials`, `403` with the requirement's answer; a store that cannot tell, `503 temporarily_unavailable`.

## Depends on
- `http`, `session`, `kernel` (`isUnavailable`), `csrf`, `rate-limit`, `request-source`.
