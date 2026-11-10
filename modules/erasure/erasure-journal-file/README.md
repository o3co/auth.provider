# erasure-journal-file

## Responsibilities
- Implements the `erasureJournal` contract with one file on the one node that runs erasure.

## Not here
- When the journal is written and read, and what a restored file means: `account-erasure`. Backing the file up apart from the store, and keeping erasure to one node: the operator's.

## Offers
- Composition definition only: the `erasureJournal` contract.
- Operator section: `path`, the journal's file, an absolute path; its lock is the same path with `.lock` added.

## Invariants
- A record is its body's length in bytes, the body (JSON), its SHA-256 in hex and a line feed. The first is the header (format 1, the random id), the rest are numbered from 1.
- Creating writes the file only where none is, then syncs the file and its directory.
- Each append is made under the lock, a file created only where none is, holding its holder (pid, host, time), and removed after; a lock held elsewhere is unavailable, naming the lock's path and its holder. The file is read and checked first, the record appended, then synced before the answer.
- Each append reads and checksums the whole file first, so a record costs the file's length: fine for the few records erasure writes.
- An append the medium fails is cut back to the file's length before it, so nothing half written stays, and is unavailable.
- A last record that does not match its length or checksum reads as torn; an earlier one, or records out of their numbering, as corrupt; no file, as missing.
- A lock a crash left behind holds every later append unavailable, naming it and its holder, until the operator removes it, having made sure the holder's process is gone (`docs/runbook.md` gives the step with erasure's).

## Deployment
- A durable directory on the one node that runs erasure, backed up apart from the store.

## Depends on
- `kernel`, `erasure-journal`; Node's file system
