# id-token

Internal module of `conformance-code`: the scenes of what an OpenID Connect request's ID token and authorization response carry, and of the authorization endpoint across origins.

## Responsibilities
- Checks that the ID token carries `auth_time` where it was asked, keeps the nonce to itself, and names as `iss`, as the authorization response does, the issuer the metadata document publishes; and that the authorization endpoint answers no CORS request.

## Depends on
- The package's scene builder and test tools; `conformance` (the target)
