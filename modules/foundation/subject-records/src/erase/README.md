# erase

Internal module of `subject-records`: erasing a subject from one space, and sweeping a space's index.

## Responsibilities
- Writes a subject's tombstone and removes what it holds in a space, answering the space's report; drops from the index the keys whose records are gone.

## Not here
- Which spaces an owner erases, and when: its eraser, which passes the reports on. The journal, the order and the answers of erasure: `account-erasure`. Naming the index: internal module `index`.

## Offers
- `eraseSubject` (a place, a subject, the owner's `keys` for `online-keyed`, a signal) → a `SpaceReport`: `erased` with the records and sets removed, `fenced` until a store-clock time, or `stopped` (`not-indexed`, `aborted`, `unavailable`).
- `sweepIndex` (a place, a cursor) → the keys a page of the index space dropped, and where to go on.

## Invariants
- The tombstone is written first, endless, holding its attempt's deadline, and kept where one stands; erasing again answers the same, `removed` 0 once all is gone.
- Each write settles at most 32 keys: their records and sets and the bucket listing them, as one, each held as read. A key leaves its bucket in the write removing its record and set.
- A record or set is removed only where it reads absent or its envelope names the subject; another subject's, moved or created there, stays, the key leaving this subject's bucket. A race makes the write read again.
- `sweepIndex` drops a key only where its record and set both read absent, removing both, so no expired one stays held.
- Reports are made here alone, by one cast.

## Depends on
- `erasure-extensions` (the report), `kernel` (Unavailable), `records` (`changeRecords`), `store`
