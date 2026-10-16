# redirect-uris

Internal module of `authorize`: which redirect URIs a client may register, which given one matches, and the answer sent back to it.

## Responsibilities
- Judges the shape of a redirect URI to register, matches a given redirect URI against a registered one, and builds the answer's URL.

## Not here
- Which URIs a client registered (the client's `authorize` metadata section, the package's). When an answer goes back to the redirect URI (`route`).

## Offers
- Registrable (URI → yes / no), matches (registered, given → yes / no), the answer's URL (redirect URI, parameters → URL; a parameter without a value is left out).

## Invariants
- A registrable URI is https, http to localhost or a loopback IP literal, or a private-use reverse-domain scheme not starting with `javascript.` (RFC 8252). Fragments, userinfo, control characters, and query parameters named like a response parameter are rejected.
- Matching compares the strings with no normalization; a loopback IP literal is 127.x or [::1], and only its port is dropped before comparing.
- The answer's parameters are added to the redirect URI's own query.

## Depends on
- Nothing
