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
- A first factor bound on a binding proof goes on at once: the login resumes, or the session is raised. Where that fails after the factor brought recovery codes, the codes are removed before the failure is answered, as no one would ever see them; the factor stays, and codes can be reissued.
- Completion judges the label before an attempt is spent: one that is not a string or not of `mfa`'s shape is `400` `invalid label`, and a missing one binds no label.
- Completion spends an attempt before the proof is judged, and takes the transaction before binding.
- A first proof `mfa` cannot judge (unavailable) gives its attempt back.
- A first factor bound in a transaction where a binding proof passed counts at once, by the amr `mfa` answers for its first proof: a login goes on through the resume, answering `done` with the factor and recovery codes once it opens; a session is raised, and the factor and codes answered whatever the raise came to.
- A first factor bound without one counts from the next sign-in: binding it answers the factor and recovery codes and ends the transaction, never the login.
- Completing an enrollment checks for a revocation again after the proof, just before `mfa` writes, and a reset since it began, or a revocation once complete (`mfa-revocation` moves the fence), is stopped in that write (`fenced`); both answer `401 login_required` and bind nothing.
- Recovery codes a first factor brought are shown only where no revocation came since the transaction started, checked after the factor is written, and again after the session is raised or the login goes on where either runs, the last check always being the last wait before they go out; else the answer is `401 login_required`, and taking the codes back is best effort: a failure, or a fence moved meanwhile, leaves them unseen.

## Depends on
- `http`, `mfa` (factor decisions, the label's shape), `mfa-flows` (the handler type); the package's parts, place, what a binding keeps, and `binding-proof`.
