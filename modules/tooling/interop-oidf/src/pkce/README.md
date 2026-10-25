# pkce

Internal module of `interop-oidf`: the PKCE the suite's OIDC tests do not send, given as a client gives it.

## Offers
- `pkceShim`: an S256 challenge for an authorization request with none (query or form), its verifier for the token requests of the code that request got, and a record of each addition.

## Invariants
- A request carrying `code_challenge` or `code_challenge_method`, right or wrong, and a token request carrying `code_verifier`, pass as they are; so does a token request for a code the shim did not see, or of another grant.
- A code is tied to the latest request with its state at its redirect URI; another URI or an error answer ties none.
- Every token request for a tied code gets the same verifier: a code used twice is refused by the provider as ever.
