# users-http

## Responsibilities
- Contributes a user ledger to `users`: asks the operator's HTTP ledger to verify an identifier and password, and to look a user up by subject or by upstream identity, through `outbound`.
- Reads each answer once, at this boundary, into a `users` answer (internal module `calls`).
- Without `subject-url`, answers every lookup by subject unanswerable, asking nothing.

## Not here
- Written links and verified contacts (`users`). Whether the ledger may be reached, redirects, and the caps on size and time (`outbound`). The names of attributes and the shape of a subject (`users`). Hashing passwords (the ledger's).

## Offers
- Composition definition only (a contribution to `users`' `ledgers`).
- Operator section, each URL whole (https or a plain-http pair outbound names, no fragment; optional, at least one):
  - `verify-url`: the password call; without it, no password matches and nothing is asked.
  - `subject-url`: the lookup by subject, posting `{"subject"}`; `404` and `410` are none, `401` and `403` unavailable.
  - `upstream-url`: the lookup by upstream identity, posting `{"idp", "subject"}` apart, read as the lookup by subject. With it the ledger offers `byUpstream`, and its answer is the last word: users reads no link of its own. Without it, none is offered.
- `credential` (optional: a bare RFC 6750 token with at least 32 bytes of key material, counted as the fewest of its bytes, hex or base64 decoding), sent on every call.
- `timeout` and `max-response-size`: each narrows outbound's cap on every call; written with its unit, a bare number refused.
- The calls and how each answer is read: [`calls`](src/calls/README.md). The password call is 0.17's `authenticateUrl`.

## Invariants
- The ledger is reached only through `outbound`, at each URL's host alone; a redirect is not followed. Each URL is an internal destination: a private address is reached only when its host is in `outbound.internal-hosts`.
- Boot is refused with no URL, on a URL outbound's destination policy refuses (at that URL's key), and with a `credential` beside URLs at more than one origin: the credential goes to one party alone.
- The password goes in the request body alone, never in a URL, a log line or an error.
- A destination refused when sending, or no answer in time or size, is unavailable. A wrong `verify-url` makes verification unavailable, never "no such user", unless what answers there is a `401` or `403` without a Bearer challenge, which reads as none.
- Boot reports never show the credential.
- The operator's ledger must do the same work for an unknown identifier as for a known one; this module sends the same one request either way.
- Holds no state, so it is safe on multiple instances.

## Depends on
- `kernel`, `users`, `outbound`, `url-setting`
