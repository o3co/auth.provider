# options

Internal module of `webauthn-login`: the route answering request options for a passkey login.

## Responsibilities
- Answers `POST /oauth/webauthn/authentication/options` with `passkeys`' options, made for the client that asks.

## Not here
- The grant (`grant`). Making and keeping the challenge (`passkeys`).

## Offers
- `optionsRouteIn` (the build context) → the route, over the assembly's passkeys, limited per source as the package's `requests` and `window` say.
- `optionsRoute` (passkeys, the window) → the same route.

## Invariants
- What it reads and answers is the package's (its card).

## Depends on
- `http`, `kernel` (the build context), `rate-limit`, `passkeys`; the package's section
