# notice-body

Internal module of `rp-logout`: what a notice tells, kept apart once under its subject, and the entry that names it.

## Responsibilities
- Holds a body's one fixed form and its id, an entry's form, and the steps that keep a body, move a 0.19 notice and drop one past its time.

## Not here
- Trying a notice and settling it (`notices`). Where bodies and entries are kept (the store interfaces).

## Offers
- `bodyOf` (a notice) → its body; `idOf` (a body) → its id; `bodyRead` (an id, a body) → the notice, `newer` (its id's, in a format this host does not know), or none.
- `entryOf` (an id, a time) → an entry; `entryRead` (an entry) → its id and time, or none; `pendingOf` (a 0.19 notice) → its fields and wait, or none.
- `keep` (the bodies, the queue, a notice, now, a time) → its entry, or `erased`; `move` (also the pending notices; a 0.19 notice; a new wait) → `moved`, `dropped` (past its time or unreadable, done and logged) or `withheld` (its subject erased, done, logged as `rp-logout.notice_unkept`, `told` false).

## Invariants
- A notice names the client, the session's handle and subject, the time it is given up (`notify-within` on `kernel`'s clock), its logout token's `jti` and, once a try failed, the time before which it is not tried again (on its entry); a 0.19 notice past that time is dropped and logged, and an entry whose body ended is done. Fields it does not know are left unread; one that does not read is dropped and logged.
- A body is format 1, its fields in one order, UTF-8 JSON, with no wait: kept as that exact string, its id the string's SHA-256, so a notice and its 0.19 retry meet at one body. A body read back is taken only where it hashes to its id and reads as format 1; one of another format is left to a newer host.
- An entry holds a body's id and its wait, and no subject. One is added only after the body's create answered `created` or `exists`, so an entry never names a body not kept; a subject erased keeps nothing. That `exists` is confirmed: subject-records' create answers it only once `changeRecords`' settled mark, conditioned on the version read, confirms what it read (auth-5f).
- A 0.19 notice moved keeps its wait on its entry, then is done; one whose subject is erased is done, nothing kept, logged naming no subject.
- A retried close draws a new `jti`, so it keeps a second body, as 0.19 sent a second notice: no idempotency is claimed beyond a move.

## Depends on
- `kernel` (`Log`); the package's store interfaces.
