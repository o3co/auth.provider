# erasure

Internal module of `session-lifecycle`: erasing a subject's sessions and listing, and migrating their spaces, through the stores' ports.

## Responsibilities
- Is session-lifecycle's eraser, `session-lifecycle`, as its spaces' `erasedBy` names it, and states whether it can erase.

## Not here
- What a store's erasure removes, and the tombstone that fences it (`subject-records`, behind the stores' ports). When an eraser runs, and the run's report (`account-erasure`).
- Closing a session and telling its participants (`lifecycle`): an erased session is removed, never closed.

## Offers
- `sessionEraser` (the session store, the listing, the clock and lifetime in force) → an `Eraser`: `online` erases the subject's sessions, then its listing; `window` each subject in turn; `migrate` the sessions by `sessionSubjectOf`, then the listing, which has nothing to migrate.
- `sessionSubjectOf`: a record's subject; a closed mark alone, holding no subject (0.19's raw shape), an orphan; anything else unreadable.
- `portsRefused` (the session store, the listing): why a part of the four ports refuses the boot; `portsOf`: the four, where both stores offer both.

## Invariants
- The session store's `erase` and `migrate` and the listing's come together or none, so sessions are never erased under a listing that still names the subject; a part refuses the boot. With none, the eraser is not erasable and answers empty reports.
- `logoutGaps` counts each session record the erase removed closing, open within the lifetime in force, or unreadable (counted high), as one whose participants were never told; a closed one is none, and so is an open one past its lifetime, owed no logout as none is called on its end alone. It counts sessions, not (session, RP) notices, so it is low for a session several RPs hold. A crash between a removal and its count loses it: counts after an interrupted run are lower bounds.

## Depends on
- `erasure-extensions` (the eraser and its reports); `lifecycle`'s record codec; `session-lifecycle`'s store interfaces.
