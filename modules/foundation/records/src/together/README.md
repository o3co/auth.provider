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
- Records changed together are read, the watched ones with them, and held by one write's conditions (the ones kept unchanged too); another writer of any of them first makes it read all again, the watch too, and decide again. A record named twice is read once, held once, and written from one naming at most. Nothing written is confirmed the same way.
- Each attempt sends one write, chosen by its keys (conditions and writes, the settled mark among them) by space and partition: the store's batch where they are one, its batch across where more, which a store without one refuses at that attempt. One call may take each on two attempts; a resend takes the one it took.
- Two stores, a target named twice, or two places whose spaces declare other guarantees is refused; a pairing builder refuses a store without a batch across at build.

## Depends on
- `kernel`, `store`; the internal module `writing`
