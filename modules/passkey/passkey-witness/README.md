# passkey-witness

## Responsibilities
- Owns the contract of a passkey witness: who remembers, apart from `passkeys`' store, that a subject holds a passkey, so losing that store never reads as holding none.

## Not here
- What is decided with the witness, and when it is marked or withdrawn: `passkeys` and the module that matches the witness's mark with the passkeys.
- Where the mark is kept: the implementation, such as an outside user ledger's adapter (`passkey-witness-http`).

## Offers
- `passkeyWitnesses` (`passkeys.witnesses`): at most one; the module that asks it refuses to start with two.
- `PasskeyWitness`: `read` (whether the subject carries the mark); `enroll` (subject, token: sets the mark to the token unless one is set, at once, and answers whether the mark is that token's; the same token answers alike however often); `withdraw` (subject, token: removes the mark only where it is that token's, leaving any other or none); `markedWith` (subject: the token the mark is set to, none where it carries no mark, read as `read` is).
- `./testing`: `passkeyWitnessStandIn` (in memory, with failures, lost answers and races around the next call), and the contract test `passkeyWitnessContract` with `passkeyWitnessProblems`, which names each promise a witness breaks.

## Invariants
- Per subject, the calls are linearizable; `enroll`'s set-if-absent and `withdraw`'s compare-and-delete are atomic, on the one mark.
- A write answered lasts: a crash or a failover keeps it. An answer is never older than the last answered write: no lagging replica or cache answers.
- Where an implementation cannot keep that, or cannot tell, it throws Unavailable, never a default. An adapter cannot check its store's promises; they are the deployment's to keep.
- A witness offers no way to remove another's mark: a mark goes only by its own token.

## Depends on
- `kernel`
