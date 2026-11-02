# clientless

Internal module of `jwt-bearer`: a grant naming no client (RFC 7523 §3.1), where an entry's `client` is the client its verified assertion identifies, and the binding of entries and their clients.

## Responsibilities
- Tells the client a verified assertion identifies for a request naming none, with what it found for the grant's `handle`.
- Tells whether an assertion is for another client than the one asking, whichever way the request names it.

## Not here
- Reading an entry's `client` and refusing one at boot (`issuers`). Verifying an assertion (`assertion`). Whether a request names no client, and the client's own checks (`token-endpoint`). When each is asked, and the answers' words but `unidentified` (the package).

## Offers
- `identifiedBy` (the assertion as `check` answered it, the entry of an issuer, the subject a verified signer stands for) → the entry's `client` with what was identified, or `unidentified`. `identifiedOf` (what the grant was handed back) → what was identified, as this module made it, or none.
- `unidentified`: `invalid_grant` with `untrusted signer`.
- `bindingOf` (the entries) → `forAnother` (an entry, none for a delegated issuer's assertion; a client's id) → whether the assertion is for another client.

## Invariants
- A request naming no client gets one answer, `unidentified`, for whatever fails before its subject is taken: an assertion `check` refuses, one of an entry with no `client`, one whose claims do not meet its entry's conditions, one whose signer stands for no subject. So it tells nothing of which issuers take such a request, their conditions or their links. A subject that cannot be told throws, as its lookup does.
- An entry's conditions are asked once its assertion is verified, before its subject is looked up, by `conditions`' `meets`, as on every request.
- `identifiedOf` reads back only what `identifiedBy` made, frozen: a look-alike is none.
- Bound both ways: an entry with a `client` issues to that client alone, and an entry's client takes its own entry's assertions alone, another entry's and a delegated issuer's none.

## Depends on
- The package's `assertion` (`check`'s answer), `conditions` (`meets`) and `issuers` (an entry's form)
