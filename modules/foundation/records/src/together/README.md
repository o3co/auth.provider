# together

Internal module of `records`: records of several partitions and spaces changed as one.

## Responsibilities
- Reads the records named and those the decision watches, and writes what it decides in one batch across, held by conditions on everything read.
- Pairs a place's records, or the records of two places, refusing through the builder's `refuse` where their store cannot.

## Not here
- How one write is sent, resent and tried again: the internal module `writing`. What is decided: the caller's.

## Offers
- `changeRecords` with `keyOf`, `changeTogether`, `changesTogether`, `pairedRecordsIn`, `pairedRecordsAcross`, and `Target`, `Next`, `ChangedRecord`: as the package offers them.

## Invariants
- As the package states them: a record named twice is read once, held once and written from one naming at most; another writer of anything read first makes it read all again and decide again; what writes nothing is confirmed by a write of its own under the same conditions.
- A store without a batch across, two stores, a target named twice, or two places whose spaces declare other guarantees is refused.

## Depends on
- `kernel`, `store`; the internal module `writing`
