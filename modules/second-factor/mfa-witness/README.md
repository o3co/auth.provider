# mfa-witness

## Responsibilities
- Owns the contract of an enrollment witness: who remembers, apart from `mfa`'s store, that a subject holds a counting factor, so losing that store never reads as never enrolled.

## Not here
- What `mfa` decides with the witness, and when it marks or clears it: `mfa`.
- Where the mark is kept: the implementation, such as an outside user ledger's adapter.

## Offers
- `enrollmentWitnesses`: at most one; the module that asks it refuses to start with two.
- `EnrollmentWitness`: `read` (whether the subject carries the mark); `enroll` (subject, token: sets the mark to the token unless one is set, at once, and answers whether the mark is that token's; the same token answers alike however often); `clear` (removes the mark).
- `./testing`: `witnessStandIn` (in memory, with failures, lost answers and races to set), and the contract test `enrollmentWitnessContract` with `witnessProblems`.

## Invariants
- Per subject, the three calls are linearizable, and `enroll`'s set-if-absent is atomic.
- A write answered lasts: a crash or a failover keeps it. An answer is never older than the last answered write: no lagging replica or cache answers.
- Where an implementation cannot keep that, or cannot tell, it throws Unavailable, never a default `false`. An adapter cannot check its store's promises; they are the deployment's to keep.

## Depends on
- `kernel`
