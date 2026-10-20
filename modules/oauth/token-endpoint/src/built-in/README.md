# built-in

Internal module of `token-endpoint`: what the package contributes of its own, the `client_credentials` grant and the composed rule for a request's audience.

## Responsibilities
- The `client_credentials` grant, for a confidential client, within its allowance.
- The one rule for the audience a request asks for, from what `targetRules` holds.

## Not here
- Handling the request and what a grant issues through (`route`).

## Offers
- `clientCredentials` (issuer) → the `client_credentials` grant.
- `composedRule` (the build context) → the one rule contributed to `targetRules`, or `unread` (the default audience, the request unread) when none is; two refuse boot.

## Depends on
- `client-allowance`, `grants`, `kernel`; the package's contract.
