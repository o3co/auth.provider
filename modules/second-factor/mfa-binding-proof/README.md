# mfa-binding-proof

## Responsibilities
- Asks a subject with no counting second factor for another proof, such as owning a contact, before a first counting factor is bound, and gives the pass `mfa`'s `begin` takes.

## Not here
- What a proof checks, and sending it (each binding proof). Factors, and whether one is held (`mfa`). Transactions and routes (`mfa-flows`). Sealing (`seal`).

## Offers
- Extension point `bindingProofs`, keyed by name: `available` (subject, where it was asked from), `send` (subject, latest end, where from → as a kind's challenge), `check` (subject, what was kept, proof).
- `bindingProof`: `asks` (proof / nothing, sending nothing); `challenge` (sent with the proof's name, what to show and the challenge sealed / none / limited / refused with the name); `prove` (proof, sealed challenge, the transaction and kind it is for → a pass sealed to the subject / none).
- Contribution to `mfa`'s `firstBindingGates`: a first counting factor begins only with the subject's pass, when a proof is asked.
- Operator section `mfa-binding-proof`: `mode` (`never`, `when-available` by default, or `always`); its keys are in the configuration reference.

## Invariants
- A proof is asked only of a subject holding no counting factor: the first available, or under `always` the first contributed; `always` with none composed refuses to boot. Under `never`, none is asked.
- A challenge is sealed to the subject, and keeps the proof's name, what it kept and its end; a pass is sealed to the subject, with its end, the transaction and the kind.
- A pass begins only the binding of the transaction and kind it names, before the challenge's end.
- Sealed values come back only from `mfa-flows`' transactions: one that will not open is unavailable.
- Where it was asked from goes to the proofs unread.

## Depends on
- `kernel`, `mfa`, `seal`

## Vocabulary
- binding proof: a proof asked before a subject's first counting factor; pass: what a proved challenge gives, for `mfa`'s `begin`.
