# introspection

Internal module of `token-control`: the handler of `POST /oauth/introspect` (RFC 7662).

## Responsibilities
- Authenticates the calling client, verifies the token and answers what the caller may see of it.

## Not here
- The route's declaration and its limit (the package's module). Revocation (`revocation`).

## Offers
- `introspectionIn` (the build context) → the handler and its answer to Unavailable, taking `clients`, `tokens`, the issuer and `audit` from the assembly.
- `introspection` (those parts, given directly) → the same.

## Invariants
- What it answers and records is the package's (its card).

## Depends on
- `audit`, `client-allowance`, `clients`, `http`, `issuer`, `kernel` (the build context), `request-source`, `token-endpoint` (client authentication, error answers), `tokens`; the package's audit events and `tokenOf` (the token asked about)
