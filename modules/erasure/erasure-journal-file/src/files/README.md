# files

Internal module of `erasure-journal-file`: the journal's and its lock's files on the node's file system.

## Responsibilities
- Reads, creates and appends to the journal's file, each durable before it answers, and takes and releases its lock: a take publishes a file holding its holder, and a release removes the lock only while it still records that holder.

## Not here
- What the records are, what an append numbers, and how a hold queues its appends: the package's journal. Where the file is: the operator's setting.

## Offers
- `JournalFiles` (read, create, append, lock) and `nodeFiles`, the node's own; `nodeFilesWith` over `MediumSteps`, the two steps a test can fail.

## Depends on
- Node's file system
