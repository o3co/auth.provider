# together

Internal module of `records`: records of several partitions and spaces changed as one.

## Responsibilities
- Reads the records named and those the decision watches, and writes what it decides in one batch, within one partition, or across partitions, held by conditions on everything read.
- Pairs a place's records, or the records of two places, refusing through the builder's `refuse` where their store cannot.

## Not here
- How one write is sent, resent and tried again: the internal module `writing`. What is decided: the caller's.

## Offers
- Records changed together, as the package offers them:
  - `changeRecords`: records of spaces of the same guarantees on one store, each by key, by the secret it is kept under or as a keyed set (a space named plainly or by secret in a call), and the records the decision watches from them, any of them written, as one, handing the decision its attempt's deadline, and sending the subject writer with the write where the caller gives it (store's `SubjectWriter`, which subject-records passes);
  - `changeRecords.keyOf`, a target's store key; `changeTogether`, two of them, only the two written; `changesTogether`: whether a store can across partitions.
- `pairedRecordsIn`, `pairedRecordsAcross`, and `Target`, `Next`, `ChangedRecord`: as the package offers them.

## Invariants
- Records changed together are read, the watched ones with them, and held by one write's conditions (the ones kept unchanged too); another writer of any of them first makes it read all again, the watch too, and decide again. A record named twice is read once, held once, and written from one naming at most. Nothing written is confirmed the same way.
- Each attempt sends one write, chosen by its keys (conditions and writes, the settled mark among them) by space and partition: the store's batch where they are one, its batch across where more, which a store without one refuses at that attempt. One call may take each on two attempts; a resend takes the one it took.
- A record under a secret is the same record by its secret or by `secretName`, the name it is kept by: both name its space by secret, so an owner that keeps names, not secrets, reaches the record it wrote by secret.
- Two stores, a target named twice, or two places whose spaces declare other guarantees is refused; a pairing builder refuses a store without a batch across at build.

## Depends on
- `kernel`, `store`; the internal module `writing`
