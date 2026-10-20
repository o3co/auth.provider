# binding-proof

Internal module of `mfa-enrollment`: the binding proof a binding may need before it begins.

## Responsibilities
- Asks the binding proof where `mfa` waits for it, judges a proof sent for it, and sends it again in an enrollment's transaction.

## Not here
- Sending and judging the proof itself (`mfa-binding-proof`). Beginning the binding (`completion`). Where the enrollment goes on (the package).

## Offers
- `bindingProofOver` (the package's parts, where the enrollment goes on) → the pass for a binding (kept or passed now, none when none is asked, or the answer), and the answer to a challenge in an enrollment's transaction.

## Invariants
- Only when the binding proof is asked and `mfa` waits for it, it asks `mfa-binding-proof` to send it, good until the transaction's deadline. None lets the binding begin.
- A binding proof sent is held sealed in the transaction and answered `403 mfa_binding_proof_required` with what to show; limited is `429 rate_limited`, refused `403 mfa_binding_proof_unavailable`.
- A challenge in an enrollment's transaction sends the binding proof again, answered `200` with what to show, or with nothing while a pass is kept or none is asked.
- A `proof` sent while a binding proof's challenge is held spends a transaction's attempt, never the subject's lockout. One that passes keeps `mfa-binding-proof`'s pass, sealed to this transaction and the kind asked; a wrong one is `401 mfa_invalid`.
- Only a binding of that kind begun in that transaction hands the pass to `mfa`, and the write holding the binding ends it, so it begins one binding. A pass kept for another kind is left unused, and the proof is asked again. The last attempt ends the transaction, even one that passes (`400`): no attempt would be left to complete a binding.
- A binding proof's challenge held is recorded `mfa.challenge.sent`, and a proof judged `mfa.verified` or `mfa.verify.failure` (`reason` `invalid`), each with the proof's name as `kind`, `purpose` and the source; never a code.
- A binding proof `mfa-binding-proof` cannot judge (unavailable) gives its attempt back.

## Depends on
- `http`, `mfa-extensions` (whom it is asked for), `mfa-flows` (the transaction type); the package's parts, place and what a binding keeps.
