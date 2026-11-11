# together

Internal module of `records`: records of several partitions and spaces changed as one.

## Responsibilities
- Reads the records named and those the decision watches, and writes what it decides in one batch, within one partition, or across partitions, held by conditions on everything read.
- Pairs a place's records, or the records of two places, refusing through the builder's `refuse` where their store cannot.

## Not here
- How one write is sent, resent and tried again: the internal module `writing`. What is decided: the caller's.

## Offers
- `changeRecords` with `keyOf`, `changeTogether`, `changesTogether`, `pairedRecordsIn`, `pairedRecordsAcross`, and `Target`, `Next`, `ChangedRecord`: as the package offers them.

## Invariants
- As the package states them: a record named twice is read once, held once and written from one naming at most; another writer of anything read first makes it read all again and decide again; what writes nothing is confirmed by a write of its own under the same conditions.
- Each attempt sends one write, chosen by the keys it sends (the settled mark among them) by space name and partition: the store's `batch` for one, its batch across for more, which a store without one refuses at that attempt; a resend takes the write it took.
- Two stores, a target named twice, or two places whose spaces declare other guarantees is refused; a pairing builder refuses a store without a batch across at build.

## Depends on
- `kernel`, `store`; the internal module `writing`
