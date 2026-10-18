# session

## Responsibilities
- Owns the contract of user sessions: their cookie, their listing under their subject, and their lifecycle (open → closing → closed), as every implementation keeps them; a session is opened only once listed, so a revocation finds every live one.
- Owns the entry decision, and nothing outside an implementation of it decides: a record exists, is open, within the lifetime in force, and after the subject's revocation boundary.
- A login opens a new session under a new handle, closing the one the request carried (fixation prevention); the cookie holds an unguessable secret and lives as long as the session.
- A closing session stays closing until every participant has finished; a session's authentication can be raised (step-up).

## Not here
- Authentication methods, what is issued after a session, the table of authentication levels, and what each amr value means (its giver's vocabulary).
- Keeping sessions: their records, store interfaces, operator section and sweep (`session-lifecycle`, the default implementation).

## Offers
- `enter`: request → session or none, throwing when unavailable; `stillOpen`, `openContext` and `endsAt` answer the same check by handle, with the context or the end.
- `complete`: login fact → session and cookie at `kernel`'s time; the carried session is closed first, and the login is unavailable when that close cannot be added to the closings, or the new session cannot be listed under its subject.
- `enterFor`: request and level (use / none / credentials) → entered (with its end: the opening plus the lifetime in force), absent, or short with the requirement's name and its answer, passed on unread.
- Extension point `entryRequirements`: context and level → admit or short, with the levels it `judges`; asked in name order, and with "use" by `enter` and the checks by handle. Where none judges `credentials`, it needs a sign-in at a known time within 300 s by default, else short `session` `{"error":"step_up_required"}`.
- `refusedEntry`: an entry that did not enter → its answer, absent `401` `{"error":"login_required"}`, short `403` with the requirement's answer, both kept out of caches.
- `raise`: request and amr → the raised session and a new cookie, or none; it adds the amr and keeps the raise time (`kernel`'s clock).
- `recent`: a time (`kernel`'s clock) → whether it is within the one recent-authentication window, at most `longestRecentMs` (1 hour); the checker passes the time of what it judges.
- `closeRequest` closes, in any state, the session the request's cookie opens, and destroys any session cookie it carries, even one opening nothing; `close`: handle → closed or pending, destroying the cookie only when the request's cookie opens that session. Both name the moved session (handle and subject) while its record is kept.
- A revoked subject's listed sessions are each closed through `close`; the revocation answers incomplete while one fails or is left pending (it stays listed). A session pushed out of a full listing (one ending first, never the one being opened) is closed through `close`.
- Extension point `participants`: called with the handle and the context, never the cookie secret, one at a time in collect order; a failing one does not stop the rest; none is called for a session the lifetime in force has ended (by expiry), and each must be safe to call any number of times, from several hosts at once. `sessionRules` holds these orders (participants, requirements, a subject's listed sessions) for an implementation and the stand-in alike.
- `./testing`: a stub, a stand-in in memory behind cookies by `cookies`' rule (each subject's listing as the contract has it; a pending close goes on only when asked again), and contract tests of the sessions.

## Invariants
- A session's state only moves forward. A host that cannot read a record (one a newer host wrote, during a rolling upgrade) lets nobody in on it and answers a login or close over its cookie Unavailable; the cookie stays.
- A login's authentication time is kept (a raise included), the opening time when it gives a later one; one it reports unknown is answered as `authenticatedAtUnknown` and never counts as fresh. The lifetime, the cookie and the subject's revocation boundary count from the opening instead.
- A login's attributes are kept as `login-attributes` keeps them, a frozen copy taken at login, kept unchanged (a raise included) until the session closes.

## Depends on
- `kernel`, `http`, `cookies` (the stand-in), `login-attributes` (the attributes a login gives), `subject-revocation` (the stand-in).

## Vocabulary
- attributes: `login-attributes`' word, under the source that stated them; the source is never read here.
- authentication context: subject, amr, authentication time, the last raise's time and amr, and attributes. login fact: the subject, amr, attributes and authentication time a login hands over. handle: a random value that names one session and can be handed out. participant: a contribution that cleans up when a session closes.

## Rules for callers
- On a route with an unsafe method, pass the CSRF check as well as `enter`: the session cookie rides on cross-site requests.
- To end every session for sure, use revocation, not the lifetime: a shorter lifetime closes a session only once a read finds it ended, and a longer one restored later lets the others in again.
