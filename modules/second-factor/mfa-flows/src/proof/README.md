# proof

Internal module of `mfa-flows`: holding a login or a session until a factor is proved, and proving it.

## Responsibilities
- The login gate, step-up, a factor's challenge and proof, and the view of a transaction.

## Not here
- Keeping transactions (`transactions`). Judging a proof (`mfa`). Raising a session (`session`). Going on with a login (`login-gates`).

## Offers
- `gateOver` (`mfa-reading`'s factor reading, `transactions`) → the gate's hold.
- `resumeOver` (`session`'s close, `login-gates`, `subject-revocation`, `transactions`, `kernel`'s log) → going on with a login held at the gate, adding what was proved to its amr, and what it carries to `done` once it opens.
- `proofOver` (`mfa-reading`'s factor reading, `session`, `login-gates`, `rate-limit`'s lockouts and the package's policy, `subject-revocation`, `transactions`, `audit`, `kernel`'s log, the enrollment flow's answer to a challenge) → the handlers of challenge, verify, the transaction's view, and step-up.

## Invariants
- A login whose amr holds `secondFactorAmr` (`mfa`) passes the gate, nothing asked of its subject's factors and no transaction started: the amr is the login's own word, so a first factor's module, or an operator mapping an upstream's amr to `mfa`, decides it.
- The gate starts a login transaction when the subject must prove a factor, and a first-enrollment one when it must bind one; it holds the login's facts, `done` and `from` unread.
- A transaction that cannot be used (unknown, another browser's, used, expired, or named differently by body and header) is answered the same `400`, using nothing up.
- If the subject was revoked after the transaction started, every route naming it answers `401 login_required`, and a POST ends it. If the revocation store cannot answer, `503`, never a negative verdict.
- Verify takes only login and step-up transactions, a step-up one only from the session that started it. Challenge takes these and an enrollment's, which the enrollment flow answers.
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
- A resume hands `login-gates` the held facts as the first factor gave them, their `provenSince` included. One a gate refused is answered `403 login_required` with the transaction's cookie cleared, logging nothing; one `session` answered revoked, `401 login_required`, as a revocation since the transaction started is. One that opens, holds and refuses nothing (one past its caller's deadline) is answered the same, cookie and all, and logged `mfa-flows.login_expired`.
- A login that opens after a revocation since its transaction started (one landing between the proof and the opening) has its session closed and answers `401 login_required`; its cookie never goes out.
- What a resume carries is made only once the login opened past that check. A response it makes instead closes the session and is answered, the session's cookie never going out; a throw closes it as best it can and goes on, with no cookie either. A part unavailable there, the close included, is answered `503`, clearing the transaction's cookie.

## Depends on
- `audit`; `http` (the request and response types); `kernel` (the log); `login-gates` (the gate type, going on with a login); `mfa-reading` (factor reading and proving); `mfa-extensions` (`secondFactorAmr`); `rate-limit` (lockouts); `session` (entering, raising); `subject-revocation`; `transactions`; `permits` (types); `requests`; `recording`; the package's section (the lockout's name)
