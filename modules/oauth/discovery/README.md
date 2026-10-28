# discovery

## Responsibilities
- Builds the discovery document from `issuer`'s URL and metadata items, and publishes it.

## Not here
- The metadata extension point and its rules: `issuer`.
- What each item means and holds: the contributing side's.

## Offers
- Routes `GET` at OpenID Connect Discovery's place (the issuer's path, then `/.well-known/openid-configuration`), each also with a trailing `/`.
- Routes `GET` at RFC 8414's place (`/.well-known/oauth-authorization-server`, then the issuer's path), each also with a trailing `/`.
- Every route answers `http`'s listed origins.

## Invariants
- Only what is upheld is published: an item of a feature not composed is absent, and an item without a value, or whose value is a list with no elements, is left out.
- `issuer` is `issuer`'s URL, and comes first.
- The document is fixed at boot; no request header shapes it.
- For an issuer without a path both places are at the root; for one with a path, nothing answers at the root, as a document there would name another issuer.

## Data
- The document, built once at boot.

## Depends on
- `kernel`, `http`, `issuer`

## Vocabulary
- discovery document: `issuer`'s metadata items as one JSON object, `issuer` first.
