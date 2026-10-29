# logout

Internal module of `conformance-code`: the scenes of a logout a client starts.

## Responsibilities
- Checks a logout a client starts by an ID token hint (OpenID Connect RP-Initiated Logout 1.0): the session it ends, where the browser goes back, the hints it refuses, the front-channel page and what its policy lets it load, the back-channel logout token, and the metadata document's logout items.
- Checks a logout a client starts without a hint, or with one naming a session the browser does not hold: the provider asks the person on a page of its own, closes once they agree only the session the browser holds, never sends the browser to a return a request without a hint names, refuses the form without its CSRF token or from another site, and asks again where the browser holds another session than the page was shown for, closing nothing.
- Checks that the provider refuses to boot with a client whose return or front channel it may not register, and tells no back channel the operator did not allow.

## Depends on
- The package's scene builder and browser; `conformance` (the target and a fake HTTP server); `conformance-oauth` (the client's logout fields)
