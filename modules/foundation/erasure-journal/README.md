# erasure-journal

## Responsibilities
- Owns the contract of the one record of account erasures a deployment keeps: appending that an erasure began or finished, listing them, and the header that ties the record to the store's copy of it.

## Not here
- Where and how it is kept: its adapter (`erasure-journal-file`). When it is written and read, what a restored record means, and what the operator declares of it: `account-erasure`.

## Offers
- The `erasureJournal` contract: `create` (once, with a new random id), `header` (the id and the last record's number), `begun` (a subject, who asked), `finished` (a subject), `list` (each subject begun, once, in the order begun: who asked, when, whether it finished since, its last number, the number of its last `begun` record), `hold` (the journal for one process until released, or `busy` naming its holder).
- `Unusable`: the content cannot be relied on, `missing` (no header), `torn` (the last record does not match its length or checksum) or `corrupt`.
- `./testing`: the contract test, `journalContract`, run on a harness that opens, reopens, tears the last record, and fails the next write, and its hold.

## Invariants
- Appended to only. Records are numbered from 1, each one more than the last.
- An answer to `begun` or `finished` means the record is durable; a later process reads what was answered.
- Every call but `hold` answers `Unusable` where the content cannot be relied on, so erasure can stop with `journal-unusable`. A failure of the medium (an I/O error, a full disk) is no such state: it throws Unavailable, appends nothing, and the call can be made again. So does an append made outside a hold while another holds the journal; account-erasure never appends outside its hold, so no automation retries against a dead one.
- A hold is the journal's for one process until released, whatever the journal holds (it is taken before `create`); its appends are made under it. A held journal answers `busy`, an answer and never Unavailable, naming the holder as the medium records it: text for the operator, never parsed, never judged live.
- An adapter never breaks a hold on a guess (a pid, a time): one whose holder died stays until the medium or the operator releases it. No OS lock: Node has none that ends with its process without a native dependency, and breaking a lock by pid or time can break a live one, letting two commands interleave.

## Depends on
- `kernel` (contracts, unavailable)

## Vocabulary
- header: the journal's first part, its random id, which the store's control record copies with the last number.
