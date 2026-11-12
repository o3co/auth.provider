# erase

Internal module of `subject-records`: erasing a subject from one space, and sweeping a space's index.

## Responsibilities
- Writes a subject's tombstone and removes what it holds in a space, answering the space's report; drops from the index the entries whose records or sets are gone.

## Not here
- Which spaces an owner erases, and when: its eraser, which passes the reports on. The journal, the order and the answers of erasure: `account-erasure`. Naming the index: internal module `index`.

## Offers
- `eraseSubject` (a place, a subject, a signal) → a `SpaceReport`: `erased` with the records and sets removed, `fenced` until a store-clock time, or `stopped` (`not-indexed`, `aborted`, `unavailable`, `index-unreadable`: a bucket in no shape this version reads, nothing skipped).
- `sweepIndex` (a place, a cursor) → the entries a page of the index space dropped, and where to go on.
- `clockAllowanceMs`, the 5 minutes a bounded fence allows for the store's clock.

## Invariants
- The tombstone is written first, endless, holding its attempt's deadline, and kept where one stands; erasing again answers the same, `removed` 0 once all is gone.
- A place is checked as the builders check it (TypeError): the store's batch across once indexed, the space's own index, a category erased here.
- In an `online-keyed` space, the record and the set under the subject itself are removed with their witnesses in one write, what they witness gone by its end or not: the key is the subject, so nothing is missed.
- A write that finds nothing to change (a tombstone standing, nothing under the subject) leaves records' settle mark in its place, `true` for 1 ms, beside the first key it read (its partition), so under the subject itself in an `online-keyed` space. It holds no data and goes by the store's expiry (physical remains).
- Each write settles at most 32 entries: what they list and the bucket listing them, as one, each held as read. An entry leaves its bucket in the write removing what it lists.
- A record or set is removed only where it reads absent or its envelope names the subject; another subject's, moved or created there, stays, the entry leaving this subject's bucket. A race makes the write read again.
- A bounded space is `fenced` until the tombstone's deadline, `boundedMs` and 5 minutes, fixed: hosts keep synchronized clocks (docs/security-model.md, what the deployment does), so a store clock stepping back further is the operator's fault.
- `sweepIndex` drops an entry only where what it lists reads absent, removing it, so no expired one stays held.
- Erasing's reports are made here, by one cast; this package makes reports nowhere else but internal module `migrate`.

## Depends on
- `erasure-extensions` (the report), `kernel` (Unavailable), `records` (`changeRecords`), `store`
