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
- The lock is a file holding its holder (pid, host, time, a token of the take), written whole and synced in a file of its own first, then linked as the lock only where none is: a lock never stands without its holder, and a failed take leaves no file.
- A take killed before it removes its own file leaves `<path>.lock.<16 hex>.tmp`, which nothing reads; the operator may remove it.
- A lock whose holder cannot be read is named `unread`; one found empty, as an earlier version could leave one, `unnamed`. With no holder to check, the operator removes it only once no erasure command runs on the node.
- `hold` takes it for the whole command, and the holder's appends take none, one after another; a lock held elsewhere answers `busy`, naming the holder as recorded. An append outside a hold takes it for itself and removes it after; held elsewhere, it is unavailable, naming the lock's path and its holder. The file is read and checked first, the record appended, then synced before the answer.
- A release removes the lock only while it still records this holder: a read, then a removal, not one atomic step. The window between them opens only after an operator removed a live holder's lock.
- A holder whose lock the operator removed keeps appending under its hold, beside the next holder: two commands append, and the journal can then read corrupt. That is why the lock is removed only once its holder's process is gone.
- Each append reads and checksums the whole file first, so a record costs the file's length: fine for the few records erasure writes.
- An append the medium fails is cut back to the file's length before it, so nothing half written stays, and is unavailable.
- A last record that does not match its length or checksum reads as torn; an earlier one, or records out of their numbering, as corrupt; no file, as missing.
- A normal end, or a stop through the tool's stop path, releases the hold. A crash (SIGKILL, OOM) leaves the lock: every later hold answers `busy` and every append is unavailable, naming it and its holder, until the operator removes it, having made sure the holder's process is gone (`docs/runbook.md` gives the step with erasure's). Nothing removes it on a guess.

## Deployment
- A durable directory on the one node that runs erasure, on a file system that takes hard links, backed up apart from the store. Back up the journal's file, not its `.lock`: a restored lock answers `busy` for a holder that never ran there.

## Depends on
- `kernel`, `erasure-journal`; Node's file system
