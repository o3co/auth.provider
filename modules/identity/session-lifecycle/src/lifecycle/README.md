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
- Taking a session off its listing, and what a login's listing pushed out (`listing`).
- The store interfaces and their needs (`session-lifecycle`'s root).

## Offers
- `lifecycleOver`: the stores, subject revocation, `session`'s seams to the participants and to the entry requirements, cookies, clock, randomness, log, lifetime, sweep interval and the recent-authentication window → the steps below.
- The handle a well-formed session cookie opens, and the cookie's secret.
- The record of a live session: open, within the lifetime in force, and after the subject's revocation boundary.
- An entry asks again whether the session is live once its requirements have answered, last before it answers, so a close or a revocation that came meanwhile holds.
- Entry at a level.
- Entry by a request's cookie (`entryIn`, behind `enter` and `enterFor`) reads which session the cookie opens again once the entry is decided, and is absent unless it still opens it. A raise retires the old cookie before it writes the session, so a cookie a raise retired meanwhile never enters the raised session.
- A read that finds an open record ended by the lifetime in force closes it there, calling no participants; a close that finds one calls them, as any close does.
- `open` (as `complete`), `close` (as `close`) and `closeIn` (as `closeRequest`).
- One sweep of pending closings, which goes on past a failing one.
- A sweep ends at the stop signal, and the host waits for it.
- A new secret indexed to a handle as a cookie for a given time, unavailable unless the index answers created.
- Retiring a secret, and the session a record shows.
- The record codec, to and from what the store keeps.
- A close calls the participants through `session`'s `closingParticipants`, and logs each that failed by name and kind.
- `authenticatedAtOf`: the authentication time a login reports, or that it is unknown. `checkAuthenticatedAt`: a `TypeError`, naming no value, for one neither epoch milliseconds (0 to 8.64e15) nor unknown, thrown before a login closes or opens anything.
- A reported time later than the opening is capped to the opening, and only the cap is logged.

## Invariants
- The lifecycle only moves forward: the next state is decided from the state at the time of writing.
- Every state change is written, and a step answers that the state moved only after the confirmed write returns.
- Without a record, a close writes a closed mark before it answers closed.
- A handle to close is added to the closings first, and taken off once closed.
- A closing whose participants keep failing is retried after half its age (at least the sweep interval, at most 1 hour), and the closing's age is logged (`session-lifecycle.closing_pending`).
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
- The listing never pushes out the session being opened.
- The index needs its wiring to answer reads only from writes a failover keeps: an entry after a raise or a close decides on what another request wrote.

## Depends on
- `kernel`, `http` (the request type), `cookies`, `subject-revocation`, `login-attributes` (the form kept attributes are read back in); `session`'s contract and rules; `session-lifecycle`'s store interfaces; `listing`.
