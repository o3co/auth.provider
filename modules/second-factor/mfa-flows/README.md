# mfa-flows

## Responsibilities
- Owns transactions (short records waiting for a second factor) and drives the login gate, step-up, and enrollment.
- Owns the numbers of the lockout policy (the mechanism is `rate-limit`).
- Owns a user's own release of their lockout.

## Not here
- Factor records and decisions about them (`mfa`). Verifying each factor (the side contributing the kind). Session records and raise (`session`). The login flow (`login-gates`). Managing a session's own factors (`mfa-management`). An operator's reset of a subject's factors (`mfa-reset`, which takes the lockout through `flowParts`).

## Offers
- Contributions: the `login-gates` gate `mfa`, and the step `mfa-flows` that proves a factor to `mfa`.
- Routes under `/session/mfa/`, whose URLs outside users rely on: `GET transaction`, `POST challenge`, `POST verify`, `POST step-up`, `POST enrollment`, `POST enrollment/complete`, `POST lock/release`.
- Audit events carry the subject, the transaction's `purpose` and the `source` where determined; never a proof, a challenge or a transaction id.
- `mfa.challenge.sent` (`kind`): a factor's or a binding proof's challenge sent; a login held or a step-up begun records nothing.
- With the judged `factor` (a binding proof's name as `kind`): `mfa.verified` once the transaction is taken, `mfa.verify.failure` (`reason`), `mfa.locked` (`hold`), and `mfa.locked.first` (`hold`) with the wrong guess that starts a hold.
- `mfa.email_address_mismatch` (`kind`) when a kind refuses a factor whose contact changed. `mfa.lock.recovered` when a release clears something (fields in `release`'s card).
- Operator section: `transaction-lifetime` (1m–30m, default `10m`), `attempts-per-transaction` (2–10, default 5), `requests` (POSTs per source in each window, over every route, 1–100000, default 60), `window` (1s–1d, default `5m`).
- `lockout` in the section holds the lockout numbers (`budget` 10 by default, `budget-window` `7d`); `rate-limit` judges their shape, refusing boot when it does not fit.
- Store interface for transactions by their unguessable identifier, never kept in clear: save for a lifetime, read, change from what it holds (the lifetime stays). Contents are not shown to it. Its needs: never evicted, survives a crash, never back after a failover.
- Store interface for each holder's live transactions (a session's handle, or a held login's subject), each by a digest of its identifier for its lifetime: add (answering those pushed out past 5, a constant), members, remove. Its needs: never evicted, survives a crash and a failover, confirmed reads.
- Extension point `enrollmentFlow` (at most one): the handlers of `POST enrollment` and `POST enrollment/complete`, and the answer to a challenge in an enrollment's transaction; the routes stay declared here, and where none is contributed the package's own `enrollment` answers.
- Contract `flowParts`, for the module binding factors: the transactions, the resume of a held login, recording through this package's declaration, the common answers, the request helpers, and the lockout's name and policy (`seams`' card).
- `./testing`: test configuration builders, and the store interfaces' contract tests for every implementation (see `transactions`' card).

## Invariants
- Internal modules, and what each is given: `wiring`'s card. The package's module declares the routes.
- Every POST declares `csrf`'s policy, then `rate-limit`'s requests per source, and takes a form or JSON body read by name, a JSON member that is not a string being absent.
- A `proof` sent as a JSON object (a WebAuthn response, say) reaches the kind as its JSON text; an array, number or other non-string is absent.
- The gate asks `mfa` what login requires: nothing lets the login through; a proof or a first enrollment starts a transaction and holds it.
- The transaction identifier comes from the body's `transaction_id` or the `MFA-Transaction` header, never a URL; it is tied to the browser by its own cookie. Unknown, other browser, used, expired, and a body and header that differ all get the same `400`, and nothing is used up.
- A challenge sent is held sealed by `mfa`, and the next attempt takes it once; asking again voids it.
- An attempt is used before the proof is judged, and success takes the transaction exactly once. A proof that cannot be judged (unavailable) is `503` and gives its attempt back. When `rate-limit` cannot settle a success once it is taken, the transaction stays spent and the answer is `503` (fail closed). Lockout counts only kinds where guessing works; while locked out, even a correct proof gets `429`.
- If the subject was revoked after the transaction started, every route naming it answers `401 login_required`, and a POST ends it; a login opening meanwhile is closed. If the store cannot answer, `503`, never a negative verdict.
- A transaction counts only while its holder's listing still holds it, read once each time it is used (`503` when the listing cannot tell). A holder keeps 5 at most, a constant: one more pushes out the one ending first, so a sixth device's held login can push out the first's. A taken one, or one out of attempts, leaves the listing; a removal that fails is logged and passed.
- A step-up raises only the session that started it, under a new cookie.

## Data
- Transactions: one per identifier (256 random bits), kept for `transaction-lifetime`. Its needs say what the place must keep it through (a taken one coming back could finish a login twice); the wiring side meets them.

## Depends on
- `kernel`, `http`, `cookies`, `request-source`, `csrf`, `session`, `login-gates`, `subject-revocation`, `rate-limit`, `audit`, `mfa` (the factor decision interface, the label's shape), `mfa-binding-proof` (the binding proof)

## Vocabulary
- Transaction: a short-lived record waiting for second-factor confirmation. Its purpose is login, login with a first enrollment, step-up, or enrollment.
