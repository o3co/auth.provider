# session

## Responsibilities
- Owns the contract of user sessions: their cookie, their listing under their subject, and their lifecycle (open → closing → closed), as every implementation keeps them; a session is opened only once listed, so a revocation finds every live one.
- Owns the entry decision, and nothing outside an implementation of it decides: a record exists, is open, within the lifetime in force, and after the subject's revocation boundary.
- A login opens a new session under a new handle, closing first the one the request carried (fixation prevention); the cookie holds an unguessable secret and lives as long as the session.

## Not here
- Authentication methods, what is issued after a session, the table of authentication levels, and what each amr value means (its giver's vocabulary).
- Keeping sessions: their records, store interfaces, operator section and sweep (`session-lifecycle`, the default implementation).

## Offers
- `enter`: request → session or none, throwing when unavailable; `entryOf` answers by handle the entry its cookie would get, at `use` unless another level is asked.
- `open`: login fact → `opened` with the session and cookie at `kernel`'s time, or `revoked`; an authentication time neither epoch milliseconds (0 to 8.64e15), `opening` nor `unknown`, or a `provenSince` missing or not epoch milliseconds, is a `TypeError`, before anything is closed; the login is unavailable when the carried session's close cannot be added to the closings, or the new session cannot be listed under its subject.
  - `provenSince`, when the proof began, is compared with the subject's boundary once the session is saved, before any cookie; revoked, it is closed. A login's authentication time, and what counts from the opening instead, follow `rules`' card.
- `enterFor`: request and level (use / none / credentials) → entered (with its end: the opening plus the lifetime in force), absent, or short with the requirement's name and its answer, passed on unread; a session closed or revoked while the requirements are asked is absent.
- Extension point `entryJudge`: context and level → the first requirement that falls short, or admitted with whether one judged the level; asked with "use" by `enter` and the checks by handle. Where nothing judges `credentials`, `sessionRules` holds the floor (`rules`' card), for an implementation and the stand-in alike.
- `refusedEntry`: an entry that did not enter → its answer, absent `401` `{"error":"login_required"}`, short `403` with the requirement's answer, both kept out of caches.
- `raise`: request and amr → the raised session and a new cookie, the session unraised with `raised: false` where its record could not be written, or none; it adds the amr and keeps the raise time (`kernel`'s clock).
- `recent`: a time (`kernel`'s clock) → whether it is within the one recent-authentication window, at most `longestRecentMs` (1 hour); the checker passes the time of what it judges.
- `handleOf`: the handle of the session the request's cookie opens, read from the cookie's index alone; no session record is read or changed, so it tells nothing of whether the session lives or is authenticated. None for no cookie, one sent twice, a forged one or one retired.
- `closeRequest` closes, in any state, the session the request's cookie opens, and destroys any session cookie it carries, even one opening nothing; `close`: handle → closed, or pending (the session stays closing) until every participant has finished, destroying the cookie only when the request's cookie opens that session. Both name the moved session (handle and subject) while its record is kept, and the state they found it in (`from`: open, even past its lifetime, closing or closed).
- A revoked subject's listed sessions are each closed through `close`; the revocation answers incomplete while one fails or is left pending (it stays listed). A session pushed out of a full listing (one ending first, never the one being opened) is closed through `close`.
- Extension point `closingParticipants`: the session (its handle and context, never the cookie secret) → each participant that failed, by name and the error's kind.
  - None is called for a session that ends by expiry alone, while a close calls them for a session whose record it finds, even one the lifetime in force has ended.
- Each seam takes at most one contribution, from the module keeping the requirements (`session-requirements`) or the participants (`session-participants`); its factory takes `sessions` only late.
- An implementation refuses to boot where a seam has no contribution; the stand-in takes none as no requirement and no participant, the `credentials` floor still kept.
- `./testing`: a stub, a stand-in in memory behind cookies by `cookies`' rule (each subject's listing as the contract has it; a pending close goes on only when asked again), `openedOf` (`open`'s session and cookie, or its throw), and contract tests of the sessions.

## Invariants
- A session's state only moves forward. A host that cannot read a record (one a newer host wrote, during a rolling upgrade) lets nobody in on it and answers a login or close over its cookie Unavailable; the cookie stays.
- A session's subject is the one its login gave while its record lives (a raise included), so a caller that kept a handle with its subject never finds them disagree.
- A login's attributes are kept as `login-attributes` keeps them, a frozen copy taken at login, kept unchanged (a raise included) until the session closes.

## Depends on
- `kernel`, `http`, `cookies` (the stand-in), `login-attributes` (the attributes a login gives), `subject-revocation` (the stand-in).

## Vocabulary
- attributes: `login-attributes`' word, under the source that stated them; the source is never read here.
- authentication context: subject, amr, authentication time, the last raise's time and amr, and attributes. login fact: the subject, amr, attributes, authentication time and proof's start a login hands over. handle: a random value that names one session and can be handed out. participant: a contribution that cleans up when a session closes.

## Rules for callers
- On a route with an unsafe method, pass the CSRF check as well as `enter`: the session cookie rides on cross-site requests.
- To end every session for sure, use revocation, not the lifetime: a shorter lifetime closes a session only once a read finds it ended, and a longer one restored later lets the others in again.
