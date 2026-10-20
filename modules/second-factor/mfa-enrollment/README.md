# mfa-enrollment

## Responsibilities
- Binds a new second factor: begins a binding, asks the binding proof where one is asked, and completes the binding with its first proof.
- A bridge to `mfa-flows`: it comes wherever `mfa-flows` is composed, and is the one contributor of its `enrollmentFlow`.

## Not here
- The routes, their policies and the transactions (`mfa-flows`, through its `flowParts`). Factor records, sealing, the first proof's judgement, and the label's shape (`mfa`). Sending and judging a binding proof (`mfa-binding-proof`).

## Offers
- Contribution to `mfa-flows`' `enrollmentFlow`: the handlers of `POST /session/mfa/enrollment` and `POST /session/mfa/enrollment/complete`, and the answer to a challenge in an enrollment's transaction.

## Invariants
- Internal modules: `binding-proof` asks, judges and sends again the binding proof; `completion` begins and completes a binding. Where an enrollment goes on, and what a binding keeps in its transaction, are the package's.
- A first factor bound after a binding proof passed counts at once: its login goes on, or its session is raised. Bound without one, it counts from the next sign-in.
- A first binding another factor beat while it was under way binds nothing (`mfa` decides): a login gets `401 login_required`, a session `409 mfa_enrollment_conflict`.
- A login's transaction binds only the subject's first factor (`mfa` decides, told the login it came from): begun or completed once a factor counts, it gets `401 login_required` and binds nothing.
- Enrollment from a session enters the session at the credential-changing level (`mfa` contributes the requirement).
- With a transaction (a login's first enrollment, or one a session's enrollment started), enrollment goes on in it. Without one, it enters the session at the credential-changing level, and starts its own only once a binding proof is sent or a binding begins: a refused request writes nothing.
- A session's enrollment goes on (enrollment, its challenge, completion) only from that session, entered the same way; without it or from another, it is refused as a missing session is. A login's first enrollment needs no session.
- Each call to `mfa` names whom it is for: the session by its handle, or the transaction's (`askedFrom`).
- `mfa` refusing a binding, as it begins or binds, is answered: full `409 mfa_factor_limit`, duplicate `409 mfa_factor_duplicate`, limited `429 rate_limited`, refused `403 mfa_factor_refused`, binding proof required `403 mfa_binding_proof_required`; an unknown kind `400`.
- A factor bound whose recovery codes find no place left (another factor took it) is answered `409 mfa_factor_limit`: the factor stands, codes can be reissued, and a login's opened session is closed, so the user signs in again.
- The secret in mid-enrollment is held in the transaction, still sealed by `mfa`; its contents are not read.
- What a binding keeps (the binding begun, the binding proof's challenge and pass, whether a proof passed) is what the transaction holds, each change made by `transactions`' `keep` from what it holds.

## Depends on
- `kernel`, `http`, `mfa` (factor decisions, the label's shape), `mfa-binding-proof` (the binding proof), `mfa-extensions` (whom `mfa` is asked for), `session` (entry, raising), `subject-revocation`, `mfa-flows` (`flowParts`, `enrollmentFlow`).
