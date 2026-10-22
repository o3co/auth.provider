# redirect-uris

## Responsibilities
- Owns the rules of a client's redirect URIs: which may be registered, which given one matches a registered one, and the URL an answer is sent back to.
- Owns the client metadata section holding them, named `authorize` for the authorization request that reads it.

## Not here
- When an answer goes back to the redirect URI, and what it carries (`authorize`). Registering clients (`clients` and its sources).

## Offers
- Client metadata section `redirects` (`authorize`): `redirect-uris` (default empty), each registrable. From a client's metadata document it copies `redirect_uris` as given, under its own key, for the schema to check (`reads`: `redirect_uris`); nothing without it. An empty list is taken too: that a document's client needs a redirect URI is `clients-cimd`'s rule.
- `redirectsCopy`: the same copy, for `client-documents`' `documentCopies`.
- `registrable` (URI → whether a client may register it to be sent back to).
- `matches` (registered, given → whether the given redirect URI is the registered one).
- `answerTo` (redirect URI, parameters → the answer's URL; a parameter without a value is left out).
- `redirectsAt` (client, origin → whether the origin is the scheme, host and port of one of its redirect URIs), for a URL another module frames for the client.
- `./testing`: `redirectsFor` (URIs → a client's sections registering them).

## Invariants
- A registrable URI is https, http to localhost or a loopback IP literal, or a private-use reverse-domain scheme not starting with `javascript.` (RFC 8252).
- Fragments, userinfo, control characters, and query parameters named like a response parameter are refused.
- Matching compares the strings with no normalization; for a loopback IP literal (127.x or [::1]) alone, the port is dropped before comparing. localhost is not one.
- The answer's parameters are added to the redirect URI's own query.
- `redirectsAt` takes no origin from a private-use scheme (its origin is `null`), and finds no URI for a client read where the section is not composed.

## Depends on
- `clients` (the section and the client), `client-documents` (the copy), `zod`.

## Vocabulary
- redirect URI: where a client asks an authorization answer to be sent back to.
