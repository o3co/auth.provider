# revocation

Internal module of `conformance-code`: the scenes of a subject the ledger revokes over HTTP.

## Responsibilities
- Checks what a revocation ends: the subject's session, which no longer lets it in, its refresh tokens, its access tokens from a code and from a session grant, and the session grant itself; another user's session and tokens go on.

## Depends on
- The package's scene builder and browser; `conformance` (the target); `conformance-identity` (the need for the ledger's route); `conformance-oauth` (clients)
