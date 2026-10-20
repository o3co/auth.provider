# revocation

Internal module of `token-control`: the handler of `POST /oauth/revoke` (RFC 7009), for access tokens and the kinds contributed.

## Responsibilities
- Authenticates the calling client and revokes the token it names, if it is that client's, by the kind that owns it.

## Not here
- The route's declaration, its limit and the refusal of a contributed `access_token` kind (the package's module). Introspection (`introspection`).

## Offers
- `revocationIn` (the build context, the kinds contributed) → the handler, with access tokens as `tokens` revokes them first.
- `accessKind` (tokens) → access tokens as a revocable kind; `revocation` (clients, kinds, audit) → the handler, given directly.

## Invariants
- What it answers and records is the package's (its card).

## Depends on
- `audit`, `clients`, `http`, `kernel` (the build context), `request-source`, `token-endpoint` (client authentication, error answers), `tokens`; the package's contract and audit events
