# refresh-certificate

Internal module of `conformance-code`: the scenes of a public client's refresh family bound to the certificate its code was redeemed with.

## Responsibilities
- Checks that a public client's refresh tokens are bound to the certificate its first tokens were, and are redeemed only with that certificate again.

## Depends on
- The package's scene builder and test tools; `conformance` (the target); `conformance-mtls` (certificates)
