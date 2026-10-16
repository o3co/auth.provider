# mfa-flows

## Responsibilities
- Owns transactions (short records waiting for a second factor) and drives the login gate, step-up, and enrollment.
- Owns the routes for managing factors from within a session (list, name, remove, reissue recovery codes).
- Owns the numbers of the lockout policy (the mechanism is `rate-limit`).
- Owns an operator's reset of a subject's second factors, and a user's own release of their lockout.

## Not here
- Factor records and decisions about them (`mfa`). Verifying each factor (the side contributing the kind). Session records and raise (`session`). The login flow (`login-gates`).

## Offers
- Contributions: the `login-gates` gate `mfa`, and the step `mfa-flows` that proves a factor to `mfa`.
- `mfaReset.reset(subject, { requestedBy? })`, for an embedder that has verified who asks: ends the subject's sessions, removes every factor, releases the lockout, and answers how many factors went.
- `mfaReset` is there whenever mfa-flows is composed, so the one template can use it as is; checking who asks stays the embedder's.
- A reset that cannot do a step rejects as unavailable; running it again finishes it. It records `mfa.reset` and logs a line (see `reset`'s card).
- Routes under `/session/mfa/`, whose URLs outside users rely on: `GET transaction`, `POST challenge`, `POST verify`, `POST step-up`, `POST enrollment`, `POST enrollment/complete`, `GET factors`, `POST factors/rename`, `POST factors/remove`, `POST recovery-codes`, `POST lock/release`.
- Audit events carry the subject, the transaction's `purpose` and the `source` where determined; never a proof, a challenge or a transaction id.
- `mfa.challenge.sent` (`kind`): a factor's or a binding proof's challenge sent; a login held or a step-up begun records nothing.
- With the judged `factor` (a binding proof's name as `kind`): `mfa.verified` once the transaction is taken, `mfa.verify.failure` (`reason`), `mfa.locked` (`hold`), and `mfa.locked.first` (`hold`) with the wrong guess that starts a hold.
- `mfa.email_address_mismatch` (`kind`) when a kind refuses a factor whose contact changed. `mfa.lock.recovered` when a release clears something (fields in `release`'s card).
- Operator section: `transaction-seconds` (60–1800, default 600), `attempts-per-transaction` (2–10, default 5), `requests` (POSTs per source in each window, over every route, 1–100000, default 60), `window-seconds` (1–86400, default 300).
- `lockout` in the section holds the lockout numbers (`budget` 10 by default, `budget-window-seconds` 7 days); `rate-limit` judges their shape, refusing boot when it does not fit.
- Store interface for transactions by their unguessable identifier, never kept in clear: save for a lifetime, read, change from what it holds (the lifetime stays). Contents are not shown to it. Its needs: never evicted, survives a crash, never back after a failover.
- `./testing`: test configuration builders, and the store interface's contract test for every implementation (see `transactions`' card).

## Invariants
- Internal modules: `transactions` keeps transactions; `proof` holds a login (the gate) or a session (step-up) until a factor is proved; `enrollment` binds a new factor; `management` serves a session's own factors; `reset` is the operator's reset; `release` the user's, by `permits`; `recording` records a request's audit events. `transactions` takes its own contracts; the package's module gives the others only what they use, and declares the routes.
- Every POST declares `csrf`'s policy, then `rate-limit`'s requests per source, and takes a form or JSON body read by name, a JSON member that is not a string being absent.
- A `proof` sent as a JSON object (a WebAuthn response, say) reaches the kind as its JSON text; an array, number or other non-string is absent.
- The gate asks `mfa` what login requires: nothing lets the login through; a proof or a first enrollment starts a transaction and holds it.
- The transaction identifier comes from the body's `transaction_id` or the `MFA-Transaction` header, never a URL; it is tied to the browser by its own cookie. Unknown, other browser, used, expired, and a body and header that differ all get the same `400`, and nothing is used up.
- A challenge sent is held sealed by `mfa`, and the next attempt takes it once; asking again voids it.
- An attempt is used before the proof is judged, and success takes the transaction exactly once. A proof that cannot be judged (unavailable) is `503` and gives its attempt back. When `rate-limit` cannot settle a success once it is taken, the transaction stays spent and the answer is `503` (fail closed). Lockout counts only kinds where guessing works; while locked out, even a correct proof gets `429`.
- If the subject was revoked after the transaction started, every route naming it answers `401 login_required`, and a POST ends it; a login opening meanwhile is closed. If the store cannot answer, `503`, never a negative verdict.
- A step-up raises only the session that started it, under a new cookie.
- A first factor bound after a binding proof passed counts at once: its login goes on, or its session is raised. Bound without one, it counts from the next sign-in.
- The management routes and enrollment from a session enter the session at the credential-changing level (`mfa` contributes the requirement).

## Data
- Transactions: one per identifier (256 random bits), kept for `transaction-seconds`. Its needs say what the place must keep it through (a taken one coming back could finish a login twice); the wiring side meets them.

## Depends on
- `kernel`, `http`, `cookies`, `request-source`, `csrf`, `session`, `login-gates`, `subject-revocation`, `rate-limit`, `audit`, `mfa` (the factor decision interface, the label's shape), `mfa-binding-proof` (the binding proof)

## Vocabulary
- Transaction: a short-lived record waiting for second-factor confirmation. Its purpose is login, login with a first enrollment, step-up, or enrollment.
