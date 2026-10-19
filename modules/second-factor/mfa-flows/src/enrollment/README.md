# enrollment

Internal module of `mfa-flows`: binding a new factor, from a session or within a login.

## Responsibilities
- Begins a binding and completes it with its first proof.

## Not here
- Keeping transactions (`transactions`). Factor records, sealing, the first proof's judgement, and the label's shape (`mfa`).

## Offers
- `enrollmentOver` (`mfa`'s factor decisions, `mfa-binding-proof`'s proof, `session`, `subject-revocation`, `transactions`, `audit`, `proof`'s resume of a login) → the handlers of enrollment and its completion, and the answer to a challenge in an enrollment's transaction.

## Invariants
- With a transaction (a login's first enrollment, or one a session's enrollment started), enrollment goes on in it. Without one, it enters the session at the credential-changing level, and starts its own only once a binding proof is sent or a binding begins: a refused request writes nothing.
- A session's enrollment goes on (enrollment, its challenge, completion) only from that session, entered the same way; without it or from another, it is refused as a missing session is. A login's first enrollment needs no session.
- It asks `mfa-binding-proof` whether a binding proof is asked, which sends nothing, and begins the binding without a pass first: `mfa` answers an unknown kind `400` before any proof is sent.
- Each call to `mfa` names whom it is for: the session by its handle, or the transaction's (`askedFrom`).
- Only when the binding proof is asked and `mfa` waits for it, it asks `mfa-binding-proof` to send it, good until the transaction's deadline. None lets the binding begin.
- A binding proof sent is held sealed in the transaction and answered `403 mfa_binding_proof_required` with what to show; limited is `429 rate_limited`, refused `403 mfa_binding_proof_unavailable`.
- A first factor bound on a binding proof goes on at once: the login resumes, or the session is raised. Where that fails after the factor brought recovery codes, the codes are removed before the failure is answered, as no one would ever see them; the factor stays, and codes can be reissued.
- A challenge in an enrollment's transaction sends the binding proof again, answered `200` with what to show, or with nothing while a pass is kept or none is asked.
- A `proof` sent while a binding proof's challenge is held spends a transaction's attempt, never the subject's lockout. One that passes keeps `mfa-binding-proof`'s pass, sealed to this transaction and the kind asked; a wrong one is `401 mfa_invalid`.
- Only a binding of that kind begun in that transaction hands the pass to `mfa`, and the write holding the binding ends it, so it begins one binding. A pass kept for another kind is left unused, and the proof is asked again. The last attempt ends the transaction, even one that passes (`400`): no attempt would be left to complete a binding.
- `mfa` refusing a binding, as it begins or binds, is answered: full `409 mfa_factor_limit`, duplicate `409 mfa_factor_duplicate`, limited `429 rate_limited`, refused `403 mfa_factor_refused`, binding proof required `403 mfa_binding_proof_required`; an unknown kind `400`.
- A binding proof's challenge held is recorded `mfa.challenge.sent`, and a proof judged `mfa.verified` or `mfa.verify.failure` (`reason` `invalid`), each with the proof's name as `kind`, `purpose` and the source; never a code.
- The secret in mid-enrollment is held in the transaction, still sealed by `mfa`; its contents are not read.
- Completion judges the label before an attempt is spent: one that is not a string or not of `mfa`'s shape is `400` `invalid label`, and a missing one binds no label.
- Completion spends an attempt before the proof is judged, and takes the transaction before binding.
- A binding proof or a first proof `mfa` cannot judge (unavailable) gives its attempt back.
- A first factor bound in a transaction where a binding proof passed counts at once, by the amr `mfa` answers for its first proof: a login goes on through the resume, answering `done` with the factor and recovery codes once it opens; a session is raised, and the factor and codes answered whatever the raise came to.
- A first factor bound without one counts from the next sign-in: binding it answers the factor and recovery codes and ends the transaction, never the login.

## Depends on
- `audit`; `http` (the request type); `mfa` (factor decisions, the label's shape); `mfa-binding-proof` (the binding proof); `session` (entry, raising); `subject-revocation`; `transactions`; `proof`'s resume, given by the package; the package's routing helpers; `recording`
