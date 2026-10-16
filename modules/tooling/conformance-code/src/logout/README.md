# logout

Internal module of `conformance-code`: the scenes of a logout a client starts.

## Responsibilities
- Checks a logout a client starts by an ID token hint (OpenID Connect RP-Initiated Logout 1.0): the session it ends, where the browser goes back, the hints it refuses, the front-channel page and the back-channel logout token, and the metadata document's logout items.
- Checks that the provider refuses to boot with a client whose return or front channel it may not register, and tells no back channel the operator did not allow.

## Depends on
- The package's scene builder and browser; `conformance` (the target and a fake HTTP server); `conformance-oauth` (the client's logout fields)
