# erasure-journal

## Responsibilities
- Owns the contract of the one record of account erasures a deployment keeps: appending that an erasure began or finished, listing them, and the header that ties the record to the store's copy of it.

## Not here
- Where and how it is kept: its adapter (`erasure-journal-file`). When it is written and read, what a restored record means, and what the operator declares of it: `account-erasure`.

## Offers
- The `erasureJournal` contract: `create` (once, with a new random id), `header` (the id and the last record's number), `begun` (a subject, who asked), `finished` (a subject), `list` (each subject begun, once, in the order begun: who asked, when, whether it finished since, its last number).
- `Unusable`: the content cannot be relied on, `missing` (no header), `torn` (the last record does not match its length or checksum) or `corrupt`.
- `./testing`: the contract test, `journalContract`, run on a harness that opens, reopens, tears the last record, and fails the next write.

## Invariants
- Appended to only. Records are numbered from 1, each one more than the last.
- An answer to `begun` or `finished` means the record is durable; a later process reads what was answered.
- Every call answers `Unusable` where the content cannot be relied on, so erasure can stop with `journal-unusable`. A failure of the medium (an I/O error, a full disk, the journal held elsewhere) is no such state: it throws Unavailable, appends nothing, and the call can be made again.

## Depends on
- `kernel` (contracts, unavailable)

## Vocabulary
- header: the journal's first part, its random id, which the store's control record copies with the last number.
