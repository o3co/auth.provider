# completion

Internal module of `mfa-enrollment`: beginning a binding, and completing it with its first proof.

## Responsibilities
- Begins a binding, after the binding proof where one is asked, and completes it: the first proof judged, the factor bound, the login going on or the session raised, and the recovery codes shown.

## Not here
- The binding proof (`binding-proof`). Where the enrollment goes on (the package). Factor records and the first proof's judgement (`mfa`).

## Offers
- `completionOver` (the package's parts, where the enrollment goes on, the binding proof) → the handlers of enrollment and of its completion.

## Invariants
- It asks `mfa-binding-proof` whether a binding proof is asked, which sends nothing, and begins the binding without a pass first: `mfa` answers an unknown kind `400` before any proof is sent.
- A first factor bound on a binding proof goes on at once: the login resumes, or the session is raised. Its recovery codes are written only after, by `mfa`'s `reissue` under the fence the binding began under, the binding asking `later`; where either fails, none are written, the factor stays, and codes can be reissued.
- Completion judges the label before an attempt is spent: one that is not a string or not of `mfa`'s shape is `400` `invalid label`, and a missing one binds no label.
- Completion spends an attempt before the proof is judged, and takes the transaction before binding.
- A first proof `mfa` cannot judge (unavailable) gives its attempt back.
- A first factor bound in a transaction where a binding proof passed counts at once, by the amr `mfa` answers for its first proof: a login goes on through the resume, answering `done` with the factor and recovery codes made once it opens; a session is raised, its codes made once the raise is written (a raise not written answers the factor alone), a failure to make them answered `503` with the raised session's cookie.
- A first factor bound without one counts from the next sign-in: binding it answers the factor and recovery codes and ends the transaction, never the login.
- Completing an enrollment checks for a revocation again after the proof, just before `mfa` writes, and a reset since it began, or a revocation once complete (`mfa-revocation` moves the fence), is stopped in that write (`fenced`); both answer `401 login_required` and bind nothing.
- Recovery codes are written only where no revocation came since the transaction started, checked just before `reissue` writes them and again after, the last wait before they go out; else the answer is `401 login_required`. Codes stand unseen only where a revocation lands after that last check, or the check fails. A fence moved or the factor gone writes none (`401`); another factor taking their place answers `409 mfa_factor_limit`, the factor standing.

## Depends on
- `http`, `kernel` (unavailable), `mfa` (factor decisions, the label's shape), `mfa-flows` (the handler type); the package's parts, place, what a binding keeps, and `binding-proof`.
