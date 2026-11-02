# redirect-uris

## Responsibilities
- Owns the rules of a client's redirect URIs: which may be registered, which given one matches a registered one, the URL an answer is sent back to, and how each is shown to a user.
- Owns the client metadata section holding them, named `authorize` for the authorization request that reads it.

## Not here
- When an answer goes back to the redirect URI, and what it carries (`authorize`). Registering clients (`clients` and its sources).

## Offers
- Client metadata section `redirects` (`authorize`): `redirect-uris` (default empty), each registrable.
- `redirectsCopy`, the section's copy for `client-documents`' `documentCopies`: from a client's metadata document, `redirect_uris` as given, under the section's own key, for the schema to check (`reads`: `redirect_uris`); nothing without it. An empty list is taken too: that a document's client needs a redirect URI is `clients-cimd`'s rule.
- `registrable` (URI → whether a client may register it to be sent back to).
- `matches` (registered, given → whether the given redirect URI is the registered one).
- `answerTo` (redirect URI, parameters → the answer's URL; a parameter without a value is left out).
- `redirectsAt` (client, origin → whether the origin is the scheme, host and port of one of its redirect URIs), for a URL another module frames for the client.
- `redirectsShown` (client → each destination of its redirect URIs, once, as `RedirectShown`: `host` and `kind`), for a page that shows the user where a client may send them.
- `./testing`: `redirectsFor` (URIs → a client's sections registering them).

## Invariants
- A registrable URI is https followed by `//`, so that it says its host the one way every reader of an answer sent as written takes it; http to localhost or a loopback IP literal, or a private-use reverse-domain scheme not starting with `javascript.` (RFC 8252).
- Fragments, userinfo, control characters, and query parameters named like a response parameter are refused.
- Matching compares the strings with no normalization; for a loopback IP literal (127.x or [::1]) alone, the port is dropped before comparing. localhost is not one.
- The answer's parameters are added to the redirect URI's own query.
- `redirectsShown` reads what the URL parser takes of a URI, never how it is written: `host` in lower case with an A-label for a name beyond ASCII, and a port other than the scheme's default, but none for a loopback IP literal whose port matching drops, so two URIs that match show alike. `kind` is `loopback` where `url-setting`'s `isLoopbackName` takes the host, over https too, else `web`. A private-use scheme shows the scheme alone, without its `:`, as `app`, whatever authority it writes.
- `redirectsAt` takes no origin from a private-use scheme (its origin is `null`), and finds no URI for a client read where the section is not composed.

## Depends on
- `clients` (the section and the client), `client-documents` (the copy), `url-setting` (`isLoopbackName`), `zod`.

## Vocabulary
- redirect URI: where a client asks an authorization answer to be sent back to.
