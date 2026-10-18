# listing

Internal module of `lifecycle`: a subject's listing once a session closes, and the sessions a login's listing pushed out.

## Responsibilities
- Takes a closed session off its subject's listing.
- Closes the sessions a login's listing pushed out over the cap, or puts the listing back when it cannot.

## Not here
- Listing a session at login, and the cap (`lifecycle`, over `session-lifecycle`'s listing store).
- Closing a session, the record and what it has left (`lifecycle`).

## Offers
- `listingOver`: the listing and closings stores, the log, and the lifecycle's close, time left and ending of an open record → `unlist` and `closePushedOut`.

## Data
- A session is taken off its listing once closed; a failed removal is logged and passed.
- Sessions pushed out over the cap are closed by the login that pushed them out, and logged by count only.
- Each pushed-out session is kept as a closing before any is closed, so the sweep finishes a close that fails.
- If the closings refuse them, the login is unavailable and the listing is put back: the opened session off, and the pushed-out ones on for what each has left of the lifetime in force, from its opening.
- Each pushed-out session is put back on its own, even if the opened one cannot be taken off; one that cannot be put back is ended in its record, calling no participants, so none stays open and unlisted.
- One the listing pushes out to take a session back is ended in its record the same way, never put back in turn.
- Sessions ended in their record are logged by count, and those neither put back nor ended by count, apart.

## Depends on
- `kernel` (the log); `session-lifecycle`'s store interfaces.
