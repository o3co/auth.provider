# mfa-witness

## Responsibilities
- Owns the contract of an enrollment witness: who remembers, apart from `mfa`'s store, that a subject holds a counting factor, so losing that store does not read as never enrolled, but for a factor lost between its write and its mark.

## Not here
- What is decided with the witness, and when it is marked or cleared: `mfa` and `mfa-witnessing`.
- Where the mark is kept: the implementation, such as an outside user ledger's adapter.

## Offers
- `enrollmentWitnesses`: at most one; the module that asks it refuses to start with two.
- `EnrollmentWitness`: `read` (whether the subject carries the mark); `enroll` (subject, token: sets the mark to the token unless one is set, at once, and answers whether the mark is that token's; the same token answers alike however often); `clear` (removes the mark).
  - `withdraw` (subject, token), where an implementation offers it: removes the mark only where it is that token's, leaving any other or none; the same token answers alike. An implementation without it leaves the method out.
- `./testing`: `witnessStandIn` (in memory, with failures, lost answers and races to set; `withdraw: false` leaves `withdraw` out), and the contract test `enrollmentWitnessContract` with `witnessProblems`, which checks `withdraw` where it is offered.

## Invariants
- Per subject, the calls are linearizable; `enroll`'s set-if-absent and `withdraw`'s compare-and-delete are atomic, on the one mark.
- A write answered lasts: a crash or a failover keeps it. An answer is never older than the last answered write: no lagging replica or cache answers.
- Where an implementation cannot keep that, or cannot tell, it throws Unavailable, never a default `false`; a `withdraw` answers only once its check and any removal are settled. An adapter cannot check its store's promises; they are the deployment's to keep.

## Depends on
- `kernel`
