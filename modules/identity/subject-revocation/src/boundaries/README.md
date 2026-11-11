# boundaries

Internal module of `subject-revocation`: a subject's boundaries, how they are written through the store interface, and how they are compared.

## Responsibilities
- Moves a subject's boundaries for a revocation, and compares a time with one.
- Writes them through `subject-revocation`'s store interface, and reads the record it keeps.

## Not here
- Calling the followers, and what `record` answers (`subject-revocation`).
- The store interface and its needs (`subject-revocation`'s contract).

## Offers
- `recorded`: the boundaries after a revocation at a time, the deadline of the write that records them, the erasure's mark kept; `comparedTo`: `compared` against a subject's boundaries, revoked where it is erased; `compared`: valid or revoked, in seconds, with the boundary widened by an allowance.
- `writtenTo`: the store → the write `record` makes before its followers, at each attempt's deadline; a write handed no deadline, or one of no number, is unavailable.
- `opened`: the boundaries a stored record holds, or none when it holds no time, or a mark that is no time; `markIn`: the mark a record carries as stored, readable or not; `stored`, `timeOf`.
- An unreadable mark of erasure is never rewritten: the write is unavailable, as the read is. A record that holds no time and no mark reads unavailable, and is written over by the next revocation, which moves both kinds, as in 0.19. A record with a mark of erasure that is a time is revoked, and fenced as erased, whatever else it holds.
- `subjectRevocationOf`: the single-boundary interface over `revocations`.
- `erasedIn`: the store → `erasedSubjects`' `erased`: whether the subject's record carries a mark of a time, read through `markIn` on every call, with no cache and never through the enabled reading. For choosing what a module writes about a subject; not an authorization check: `compare` is the only read that decides access, and the fence the only write.

## Invariants
- Each `record` writes the boundary, even one already far enough, so a write not yet confirmed is confirmed by the next: a retry after `complete: false` or unavailable moves the boundary to its write's deadline, and only refuses more. An update through the store interface writes the larger value. A subject's first boundary is saved, and updated when another request saved one first.
- A recorded boundary is reported only after its confirmed write; an instance still on the old primary after a failover reads it as it stands there until it reconnects, the deployment's fence (security model, revocation delays).
- `erased` answers true for a mark of a time, whatever else the record holds; false with no record or no mark; a mark of no time, or a read the store cannot answer, is unavailable, never false. It reads as `compare` reads, as of the read: a module calling or following `record` reads `erased` there instead, as of its write.

## Depends on
- `kernel`; `subject-revocation`'s contract, store interface and write type.
