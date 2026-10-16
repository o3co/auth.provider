# proof

Internal module of `mfa-flows`: holding a login or a session until a factor is proved, and proving it.

## Responsibilities
- The login gate, step-up, a factor's challenge and proof, and the view of a transaction.

## Not here
- Keeping transactions (`transactions`). Judging a proof (`mfa`). Raising a session (`session`). Going on with a login (`login-gates`).

## Offers
- `gateOver` (`mfa`'s factor decisions, `transactions`) → the gate's hold.
- `resumeOver` (`session`'s close, `login-gates`, `subject-revocation`, `transactions`, `kernel`'s log) → going on with a login held at the gate, adding what was proved to its amr, and what it carries to `done` once it opens.
- `proofOver` (`mfa`'s factor decisions, `session`, `login-gates`, `rate-limit`'s lockouts and the package's policy, `subject-revocation`, `transactions`, `audit`, `kernel`'s log, enrollment's answer to a challenge) → the handlers of challenge, verify, the transaction's view, and step-up.

## Invariants
- The gate starts a login transaction when the subject must prove a factor, and a first-enrollment one when it must bind one; it holds the login's facts, `done` and `from` unread.
- Verify takes only login and step-up transactions, a step-up one only from the session that started it. Challenge takes these and an enrollment's, which enrollment answers.
- A challenge is asked with the transaction's deadline as its latest end, for whom `transactions` names (`askedFrom`), and asking voids the challenge before, unavailable included. A sent one is kept sealed; the next attempt takes it, and passes it to the proof only for the factor it was sent for.
- A challenge sent is answered `200` with what to show, recorded as `mfa.challenge.sent` with `kind` and `purpose`. A factor whose kind sends none is answered `200` with nothing; limited is `429 rate_limited`; refused is `403 mfa_factor_refused`, recorded as `mfa.email_address_mismatch` with `kind` and `purpose` only when the kind says the factor's contact changed.
- Only kinds where guessing works count toward lockout.
  - They reserve one unit with `rate-limit` before the decision.
  - Only a proof judged wrong is kept as a failure.
  - Success (after taking the transaction), attempts that were not judged, and correct proofs that lost to reuse or a conflict return the reservation.
  - The wrong guess whose reservation starts a hold records `mfa.locked.first`.
  - While locked out, even a correct proof gets `429`.
- Kinds where guessing does not work (such as recovery) are never locked out.
  - Their success ends the run of failures too, with nothing to hand back.
  - The budget stays.
- An attempt is spent before the proof is judged, and the attempt that uses up the limit ends the transaction. A proof `mfa` cannot judge (unavailable) gives its attempt back. Success takes the transaction before anything else happens.
- A local proof of a factor guessing cannot beat grants the session a release permit (`permits`), once its login opens or its raise is written; a permit that cannot be written is logged `mfa-flows.release_permit_unrecorded` (warn) and the login goes on.
- A login transaction's success goes on with the login after the gate `mfa`, with its held facts plus the proof's amr, `done` and `from`, and answers `done`. A step-up's success raises the session under a new cookie.
- A login transaction held without an authentication time goes on with it `"unknown"`, never the opening time.
- A resume that opens nothing and holds nothing (one past its caller's deadline) is answered `403 login_required` and logged `mfa-flows.login_expired`.
- A login that opens after a revocation since its transaction started (one landing between the proof and the opening) has its session closed and answers `401 login_required`; its cookie never goes out.

## Depends on
- `audit`; `http` (the request and response types); `kernel` (the log); `login-gates` (the gate type, going on with a login); `mfa` (factor decisions); `rate-limit` (lockouts); `session` (entering, raising); `subject-revocation`; `transactions`; the package's routing helpers; `recording`
