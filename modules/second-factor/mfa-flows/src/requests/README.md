# requests

Internal module of `mfa-flows`: what every route reads of a request, and answers alike.

## Responsibilities
- Reads what a POST names (a value, the proof, the transaction), and holds the answers and the checks every route shares.

## Not here
- What a route does with them, and its other answers (`proof`, `release`, and `mfa-enrollment` through `flowParts`). The routes and their policies (the package's module). Tying a transaction to its browser (`transactions`). Where the revocation boundary lies (`subject-revocation`).

## Offers
- `Handler`: what an internal module gives the package for one route.
- `unknownTransaction` (`400`), `loginRequired` (`401 login_required`), `unavailable` (`503 temporarily_unavailable`).
- `field` (request, name), `proofOf` (request), `postedTransaction` (request: none where none is named, `false` where body and header differ).
- `revokedSince` (`subject-revocation`'s check, a transaction); `managing` (`session`, request) → the session entered to change credentials, or the answer refusing it.

## Invariants
- A POST's values are read by name from its form or JSON body, a JSON member that is not a string being absent; the query is never read, so nothing secret goes in a URL.
- A `proof` sent as a JSON object (a WebAuthn response, say) is its JSON text; an array, a number or another non-string is none.
- The transaction is named by the body's `transaction_id` or the `MFA-Transaction` header, never a URL; a body and header that differ name none.
- One answer, `unknownTransaction`, for every transaction that cannot be used, so it tells nothing of why.
- A transaction's subject is revoked since it started where `subject-revocation` answers so for its start.

## Depends on
- `http` (the request and response types, `jsonAnswer`); `session` (entry); `subject-revocation` (the check's type); the package's `transactions` (the transaction type)
