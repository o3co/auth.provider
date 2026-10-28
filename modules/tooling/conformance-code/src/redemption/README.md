# redemption

Internal module of `conformance-code`: the scenes of redeeming a code or a refresh token issued for OpenID Connect at the token endpoint.

## Responsibilities
- Checks that the token endpoint authenticates the client that redeems a code or refreshes by the method it registered, refuses a refresh token it did not issue or one already spent, and answers tokens uncached.

## Depends on
- The package's scene builder and test tools; `conformance` (the target)
