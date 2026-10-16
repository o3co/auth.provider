# verified-email

Internal module of `conformance-code`: the scenes of refusing a token to a user whose email is not verified.

## Responsibilities
- Checks the authorization endpoint: a code for a user stated verified, and `access_denied` with the state and the issuer for one stated not or not at all, before any consent is asked; with the policy off, a code for either.
- Checks the session grant: a token for a user stated verified, `invalid_grant` saying why for the others, and the refusal's audit event.
- Checks users from a ledger over HTTP, told apart by what the ledger said at login.

## Depends on
- The package's scene builder and browser; `conformance` (the target, the fake ledger); `conformance-identity` (users, the ledger need); `conformance-oauth` (clients)
