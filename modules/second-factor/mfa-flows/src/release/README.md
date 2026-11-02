# release

Internal module of `mfa-flows`: a user's own release of their second-factor lockout.

## Responsibilities
- Judges and answers `POST /session/mfa/lock/release` for a session holding a permit: a factor guessing cannot beat, proved locally and recently in it.

## Not here
- Keeping permits (`permits`). Applying a release, its generation and its once-only id (`rate-limit`). When factors were bound (`mfa`). The boundary (`subject-revocation`).

## Offers
- `releaseOver` (`session`, the permits, `rate-limit`'s lockouts and the policy, `subject-revocation`'s check, `mfa-reading`'s factor reading, `audit`) → the release's handler.

## Invariants
- The session enters at the credential-changing level: absent `401 login_required`; short `403` with the requirement's answer. With no permit, `403 mfa_exempt_proof_required` with 0.17's description; an upstream's word (a mapped amr) never makes one.
- A boundary more than 5 minutes ahead of the clock (written by a host whose clock runs ahead) judges nothing: `503 temporarily_unavailable`, logged `mfa-flows.lock_release_boundary_ahead` (error), nothing spent or recorded, as 0.17.
- The budget and run are forgiven when the subject was revoked after the first counted failure plus 5 minutes and a second (the boundary counts whole seconds), or when nothing is counted. A fixed hold is lifted when every guessable factor was bound after its start plus 5 minutes. Both are read first and applied by `rate-limit` only while still so when written.
- A boundary is the deadline of the write that recorded it (`subject-revocation`), up to 10 seconds after the revocation, so both thresholds above, ahead of the clock and after the first failure, sit up to that much nearer to the revocation itself.
- A permit counts for `session`'s recent window from its proof, and an hour at most from the session's first. A release is named by the permit's id (kept for `session`'s longest recent window): releases racing on one permit apply once, the others answering alike. An applied release marks the permit used with its answer, and a used permit answers that again, asking nothing; a refusal spends nothing.
- Answers in 0.17's words: `200 {"lock":"released"}`; a fixed hold left, `200 {"lock":"held","hold":"hard",…}`; nothing applicable, `409 mfa_lock_release_refused` (`reason` `not_revoked_since`). Where a fixed hold stands, `rebind_after` is its start plus 5 minutes.
- `mfa.lock.recovered` is recorded only when a release is applied: `operation` `recover`, `generation`, and `week` (the budget, by 0.17's name), `run` and `hard` as `true` or `false`. Each answer past entry logs `mfa-flows.lock_release` (`outcome`: `released`, `held`, `repeated` or `refused`); `rebind_after` goes to neither.
- A part that cannot answer fails the release as unavailable.

## Depends on
- `audit`; `mfa-reading` (factor reading); `rate-limit` (lockouts); `session` (entry, the longest recent window); `subject-revocation` (check); `requests`; the package's section (the lockout's name); `recording`
