# users-http

## Responsibilities
- Contributes a user ledger to `users`: asks the operator's HTTP ledger to verify an identifier and password, and to look a user up by subject or by upstream identity, through `outbound`.
- Reads each answer once, at this boundary, into a `users` answer (internal module `calls` makes the calls).
- Without `subject-url`, answers every lookup by subject unanswerable, asking nothing.

## Not here
- Written links and verified contacts (`users`). Whether the ledger may be reached, redirects, and the caps on size and time (`outbound`). The names of attributes and the shape of a subject (`users`). Hashing passwords (the ledger's).

## Offers
- Composition definition only (a contribution to `users`' `ledgers`).
- Operator section, each URL whole (https or a plain-http pair outbound names, no fragment; optional, at least one):
  - `verify-url`: the password call; without it, no password matches and nothing is asked.
  - `subject-url`: the lookup by subject, posting `{"subject"}`; `404` and `410` are none, `401` and `403` unavailable.
  - `upstream-url`: the lookup by upstream identity, posting `{"idp", "subject"}` apart, read as the lookup by subject. With it the ledger offers `byUpstream`, and its answer is the last word: users reads no link of its own. Without it, none is offered.
- `credential` (optional: `keys`' `bearerToken` of at least 32 bytes of key material, never a `REPLACE-` sample), sent on every call.
- `timeout` and `max-response-size`: each narrows outbound's cap on every call; written with its unit, a bare number refused.
- Every call: `POST {url}` with the URL as written, nothing added; `Content-Type` and `Accept: application/json`; `Authorization: Bearer {credential}` when one is set, none otherwise.
- The password call, with the body `{"email": identifier, "password"}`:

  | Answer | Read as |
  |---|---|
  | `200`, a JSON object with an `id` of a subject's shape (`users`) and a non-empty string `username` | the user |
  | `401` with a Bearer challenge, when a credential was sent | unavailable (the credential is refused) |
  | `401` otherwise | none; to be read as a lookup's is in a later release |
  | anything else, `403` (a proxy before the ledger may send it while it fails), a `200` of another shape, `404` and other `2xx` included | unavailable |

- A lookup, with the body `{"subject"}` by subject or `{"idp", "subject"}` by upstream identity:

  | Answer | Read as |
  |---|---|
  | `200`, a JSON object with an `id` of a subject's shape | the user; no `username` is asked for |
  | `404` (not known) or `410` (known, and refused) | none |
  | anything else, `401` and `403` included, challenged or not | unavailable |

- A user: `id` is the subject; `email`, `name`, `picture`, `groups` and a boolean `emailVerified` (only beside `email`) are the attributes `users` names for them; other fields are dropped.

- `./testing`: `usersLedger` (users, each with any upstream identity linked to it), a fake ledger speaking these calls for the users given, behind a credential of its own: its answer to a call (none for a call not its own) and the section pointing users-http at it, for a scene or an operator's trial.
## Invariants
- The ledger is reached only through `outbound`, at each URL's host alone; a redirect is not followed. Each URL is an internal destination, named to `outbound` as itself: a private address is reached only when its host is in `outbound.internal-hosts` or, over plain http, when `outbound.plain-internal` names its `host:port`, and only at that URL's origin (scheme, host and port).
- Boot is refused with no URL, on a URL outbound's destination policy refuses (at that URL's key, with which of `outbound`'s keys to set), and with a `credential` where `outbound.credentials` refuses its URLs (more than one origin, or one neither https nor a `plain-loopback` or `plain-internal` pair, in `credentialRefusalText`'s words; at `credential`): the credential goes to one party alone, sent by `outbound` as its `credential`.
- The password goes in the request body alone, never in a URL, a log line or an error.
- A destination refused when sending, or no answer in time or size, is unavailable. A wrong `verify-url` makes verification unavailable, never "no such user", unless what answers there is a `401` without a Bearer challenge, which reads as none.
- Boot reports never show the credential.
- A lookup's `404` is none whatever answered it, logged nowhere: the operator's ledger refuses a caller it does not accept with `401` or `403`, never `404`, and a gateway before it that answers an unknown route `404` reads as no such user.
- The operator's ledger must do the same work for an unknown identifier as for a known one; this module sends the same one request either way.
- Holds no state, so it is safe on multiple instances.

## Depends on
- `kernel`, `users`, `outbound`, `outbound-policy`, `url-setting`, `keys` (the credential's rule)
