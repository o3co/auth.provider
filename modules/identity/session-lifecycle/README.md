# session-lifecycle

## Responsibilities
- Keeps sessions for `session`'s contract: their records, cookies and listing under their subject, and their lifecycle (open → closing → closed), over its own store interfaces as the assembly wires them.
- Makes the entry decision, opens a new session under a new handle on each login, keeps a closing session closing until every participant has finished, and raises a session's authentication, as `session` describes each.

## Not here
- What callers see of sessions, the rules every implementation keeps, the extension points and the stand-in (`session`).
- Where records are kept (the wiring of its store interfaces).

## Offers
- Provides `session`'s `sessions`, as the adapter that replaces `session` (its default), keeping `sessionRules`.
- Follower of `subject-revocation`, named `session-lifecycle`: closes each listed session of a revoked subject through `close`, by `sessionRules`, and fails when one fails or is left pending (it stays listed), so the revocation answers incomplete.
- The operator section (its keys in the settings list): `lifetime`, `sweep-interval` and `recent-authentication`, times written with their unit (`8h`, `1m`, `10m`); a bare number is refused.
- Each host goes on with pending closes every `sweep-interval`, past a failing one; on stop, the host waits for the sweep under way.
- Logs as `session-lifecycle.*`, never a value: the names a login's attributes dropped (names outside the set as a count), a capped authentication time, a failed participant by name and kind, a closing put off with its age, a sweep's failures and the listing's (a failed removal by kind, sessions pushed out by count, sessions ended in their record by count, and pushed-out sessions neither put back nor ended, by count).
- Store interfaces of its own, named `session-lifecycle.*`, which a wiring must provide for it: records by handle (create, read, change from the current contents, with a lifetime or none), the cookie index by secret (create, read, remove), the closings (add, done, each) and each subject's listed sessions (add for a lifetime, members, remove). The stores never see record contents and need no eviction, crash survival and no rollback on failover.
- The records, the cookie index and the listing read only what a failover keeps, since an entry or a revocation decides on what other requests wrote; the cookie index names its entries from the secret and never keeps it in clear.
- `./testing`: the configuration builder, and contract tests of its store interfaces.

## Invariants
- A login whose authentication time is neither epoch milliseconds (0 to 8.64e15) nor unknown is a `TypeError`, naming no value, before an earlier session is closed or a new one opened.
- A login's attributes are kept as `login-attributes` keeps them, a frozen copy taken at login, kept unchanged (a raise included) until the session closes.
- It asks the entry requirements through `session`'s `entryJudge` and calls the participants through its `closingParticipants`; boot is refused, naming each, where either has no contribution, never taken as no rule.
- Where nothing judges `credentials`, `sessionRules` holds entry there to a sign-in within `recent-authentication`.
- `recent(at)` answers whether a time on `kernel`'s clock is within `recent-authentication`, the one window every recent-authentication check counts in.
- A host that cannot read a record (one a newer host wrote, during a rolling upgrade) lets nobody in on it and answers a login or close over its cookie Unavailable; the cookie stays.

## Depends on
- `kernel`, `session` (the contract and its rules), `http`, `cookies`, `subject-revocation`, `login-attributes` (the attributes a login gives).
