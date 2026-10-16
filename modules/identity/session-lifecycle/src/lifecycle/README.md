# lifecycle

Internal module of `session-lifecycle`: a session's record, its cookie, and its way from open to closed.

## Responsibilities
- Opens, enters and closes sessions over `session-lifecycle`'s store interfaces.
- Makes the entry decision that `session`'s contract describes.
- Mints, indexes and retires cookie secrets.

## Not here
- What `session` offers callers (`session`).
- How `session-lifecycle` maps that onto these steps.
- Raising a session (`raise`).
- The store interfaces and their needs (`session-lifecycle`'s root).

## Offers
- `lifecycleOver`: the stores, subject revocation, participants, requirements, cookies, clock, randomness, log, lifetime, sweep interval and credentials window → the steps below.
- The handle a well-formed session cookie opens, and the cookie's secret.
- The record of a live session: open, within the lifetime in force, and after the subject's revocation boundary.
- Entry at a level.
- A read or a close that finds an open record ended by the lifetime in force closes it there, calling no participants.
- `open` (as `complete`), `close` (as `close`) and `closeIn` (as `closeRequest`).
- One sweep of pending closings, which goes on past a failing one.
- A sweep ends at the stop signal, and the host waits for it.
- A new secret indexed to a handle as a cookie for a given time, unavailable unless the index answers created.
- Retiring a secret, and the session a record shows.
- The record codec, to and from what the store keeps.
- A close calls the participants by `session`'s rules, and logs each that failed by name and kind.
- `authenticatedAtOf`: the authentication time a login reports, or that it is unknown.
- A reported time later than the opening is capped to the opening, and only the cap is logged.

## Invariants
- The lifecycle only moves forward: the next state is decided from the state at the time of writing.
- Every state change is written, and a step answers that the state moved only after the confirmed write returns.
- Without a record, a close writes a closed mark before it answers closed.
- A handle to close is added to the closings first, and taken off once closed.
- A closing whose participants keep failing is retried after half its age (at least the sweep interval, at most 1 hour), and that time is logged.
- A closing whose record a host cannot read is put off the same way, by that host alone.
- The cookie secret is 256 random bits, checked for its shape before any lookup.
- The index's place keeps the secret only as a name it cannot be had from.
- The handle is a separate random value, not derivable from the secret, and each login gets a new one.

## Data
- Session record, per handle: format 2, state, the opening time, authentication context (attributes as `session-lifecycle` keeps them), when closing began and when to retry.
- A format 1 record is read as opened at its authentication time, which is read as unknown.
- Every read checks the record: one of another format or shape lets nobody in, and closing it is unavailable.
- A record lives for the lifetime from login, without end while closing, and for the lifetime again once closed.
- Cookie index, by the cookie's secret: the handle, for the session's lifetime.
- Each subject's listing: the handle, for the session's lifetime from login.
- A session is listed after its record and before its cookie; a login that cannot list it is unavailable.
- A session is taken off its listing once closed; a failed removal is logged and passed.
- Sessions pushed out over the cap are closed by the login that pushed them out, and logged by count only.
- Each pushed-out session is kept as a closing before any is closed, so the sweep finishes a close that fails.
- If the closings refuse them, the login is unavailable and the listing is put back: the opened session off, and the pushed-out ones on for what each has left of the lifetime in force, from its opening.
- The listing never pushes out the session being opened.
- The index needs confirmed reads: an entry after a raise or a close decides on what another request wrote.

## Depends on
- `kernel`, `http` (the request type), `cookies`, `subject-revocation`, `login-attributes` (the form kept attributes are read back in); `session`'s contract and rules; `session-lifecycle`'s store interfaces.
