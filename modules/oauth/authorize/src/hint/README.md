# hint

Internal module of `authorize`: reading the `id_token_hint` request parameter (OpenID Connect Core §3.1.2.1).

## Responsibilities
- Asks the one hint reader contributed to `hintReaders` which End-User a hint names, and turns its answer into the sub `flow` asks or the refusal to give.

## Not here
- Which hint is an ID token this provider issued, and whose, an expired one included: the reader's, `oidc` where it is composed. Comparing the End-User named with the session's subject (`flow`).

## Offers
- `hintCheckOver` (the build context → a hint → the End-User it names / none / `invalid_request`), `hintCheckTakes`

## Invariants
- A hint the reader does not take is `invalid_request`, described `id_token_hint is not valid`.
- An empty hint, or none, names no End-User. With no reader composed, every hint is left unread, as a parameter not understood (RFC 6749 §3.1): no ID token is issued that it could be.
- At most one reader: a second is refused at boot by the kernel, the point being keyed by one key.

## Depends on
- `kernel` (the build context); `authorize`'s `hintReaders` point
