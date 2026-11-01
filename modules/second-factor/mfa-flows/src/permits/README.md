# permits

Internal module of `mfa-flows`: a session's permit to release its subject's lockout.

## Responsibilities
- Keeps one permit per session, granted when a factor guessing cannot beat is proved locally in it (at the login gate or a step-up), and marks it used, with what its release answered.

## Not here
- Which factors guessing cannot beat, and how long a proof stays recent (`session`). The release itself (`release`). When to grant (`proof`).

## Offers
- `permitsOver` (the transaction store, the clock, `session`'s recent window and its longest one) → grant, the session's permit (none / ready with its id / used with its answer), and use.

## Invariants
- A permit is named by a hash of the session's handle in the transaction store; the handle is never kept in clear.
- A later proof's permit replaces the session's, used or not, under a new id; a use names its proof, so it leaves a later one alone. A permit is named by its proof's time: two proofs of one session in the same millisecond share one, and a use of either uses it (a release refused, never one more granted).
- A permit counts while its proof is recent (`session`), and lasts at most an hour from the session's first: the record is kept that long and not renewed, which fails closed.
- Used is a mark in the record, not a time: a used permit answers what it answered, however clocks drift.

## Data
- In the transaction store, beside transactions: `{proofAt, used?}` per session, kept an hour from its first grant.

## Depends on
- `kernel`; the package's transaction store and its record helpers
