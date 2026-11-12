# erasure

Internal module of `mfa-flows`: fencing a subject's transactions and permits and erasing its listings, and migrating their spaces, through the stores' ports.

## Responsibilities
- Is mfa-flows' eraser, `mfa-flows`, as its spaces' `erasedBy` names it, and states whether it can erase.

## Not here
- What a store's erasure removes or fences, and the tombstone (`subject-records`, behind the stores' ports). When an eraser runs, and the run's report (`account-erasure`). Forgetting the subject's lockout (`rate-limit`'s eraser, by `subjectLockouts`).

## Offers
- `flowsEraser` (the transaction store, the listings, `session` read late) → an `Eraser`: `online` fences the subject's transactions and permits, then erases its listings; `window` each subject in turn; `migrate` the transactions (bounded: nothing to index), then the listings by `listingSubjectOf`.
- `portsRefused` (the transaction store, the listings): why a part of the four ports refuses the boot, which `transactions` asks at its build; `portsOf`: the four, where both stores offer both.
- `listingSubjectOf` (`session`'s `subjectOf`) → a listing's subject from its key: `login:<subject>` that subject; `session:<handle>` its session's, through `subjectOf`; anything else, or a session with no record naming one, unreadable, so the space stops and a run after the listing's end finishes it: its last transaction's end (`transactionLifetimeMaxMs` at most), then the store's clearing of the set.

## Invariants
- `erasable` only where both stores offer both ports; otherwise empty reports. `logoutGaps` is 0: it removes no session.
- Where `session` offers no `subjectOf`, the listings' migration answers `owner-stopped`, and the transactions' still runs.
- No `after`: whichever of it and `rate-limit`'s eraser runs first, a dropped lockout key holds (`rate-limit`'s card).
- 0.19's raw transactions and permits stay raw: the space is bounded (0/0), and its bound, an hour, covers the longest a 0.19 instance writes.

## Depends on
- `erasure-extensions` (the eraser, its reports, `ownerStopped`); `session` (`subjectOf`); the package's store interfaces.
