# erasure

Internal module of `subject-revocation`: marking a subject erased.

## Responsibilities
- Writes a subject's mark of erasure through `subject-revocation`'s store interface.

## Not here
- Reading the mark, and refusing an erased subject: internal module `boundaries`. When a subject is erased: account erasure.

## Offers
- `markedIn` (the store) → `markErased`: the mark, at the deadline of the write that makes it.

## Invariants
- The mark is the deadline of a confirmed write, on the store's clock; the boundaries stay as they are, and a subject marked already keeps its first mark, which is answered.
- A subject with no boundary, or one of no time, gets a `sessions` boundary at the mark's time with it: a record holds `sessions`.
- A write the store answers with no mark is unavailable.

## Depends on
- `kernel`; internal module `boundaries`; `subject-revocation`'s store interface.
