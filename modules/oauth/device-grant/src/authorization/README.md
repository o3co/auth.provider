# authorization

Internal module of `device-grant`: device authorization (RFC 8628 §3.1–3.2), where a device asks for its codes.

## Responsibilities
- Authenticates the client, its refusal recorded through `token-endpoint`'s `authenticateClient`, decides the scope and audience, and keeps a pending device record with its user code.

## Not here
- The route's declaration and its rate limit (the package's). Approving a code (`verification`). Polling (`grant`).

## Offers
- `authorizationOver` (the build context) → `authorizationWith` (`clients`, the audit, the store interfaces, the issuer's URL, the runtime, the settings) → the route's handler and its answer to Unavailable, `503` `temporarily_unavailable`.

## Depends on
- `clients` (authentication); `token-endpoint` (the allowance, client authentication and its audit, OAuth error responses); `audit`; `issuer` (its URL); `http` (the request and response); `kernel` (the build context, randomness, unavailable); the package's codes, record and store interfaces
