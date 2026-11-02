# boundaries

Internal module of `subject-revocation`: a subject's boundaries, how they are written through the store interface, and how they are compared.

## Responsibilities
- Moves a subject's boundaries for a revocation, and compares a time with one.
- Writes them through `subject-revocation`'s store interface, and reads the record it keeps.

## Not here
- Calling the followers, and what `record` answers (`subject-revocation`).
- The store interface and its needs (`subject-revocation`'s contract).

## Offers
- `recorded`: the boundaries after a revocation at a time, the deadline of the write that records them; `compared`: valid or revoked, in seconds, with the boundary widened by an allowance.
- `writtenTo`: the store → the write `record` makes before its followers, at each attempt's deadline; a write handed no deadline, or one of no number, is unavailable.
- `opened`: the boundaries a stored record holds, or none when it holds no time.
- `subjectRevocationOf`: the single-boundary interface over `revocations`.

## Invariants
- An update through the store interface writes the larger value. A subject's first boundary is saved, and updated when another request saved one first.

## Depends on
- `kernel`; `subject-revocation`'s contract, store interface and write type.
