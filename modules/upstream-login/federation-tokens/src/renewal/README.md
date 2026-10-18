# renewal

Internal module of `federation-tokens`: keeping each session's upstream tokens and renewing them.

## Responsibilities
- Keeps a login's tokens, hands the current ones, and refreshes them under a lock when their end is near.
- Removes one IdP's entry (logout, withdrawal) or the whole record (a session closing). A withdrawal removes it whatever the session's state, any number of times.

## Not here
- Accepting the caller and what the routes answer (the package). Sealing and the record's shape (`vault`). The refresh request itself (the IdP type, through `federation`).

## Offers
- `renewalWith` (store, locks, `upstreams`, `session`'s ends, vault, `kernel`'s runtime, settings): `current` (session, IdP → handed / an outcome the routes answer), `receive`, `disconnect` (→ the id_token, or not linked), `withdraw`, `close`

## Invariants
- When a token ends is judged here only, on `kernel`'s clock, capped at the longest lifetime. At login, an end not a positive number is due now, and none stays none unless a refresh token can renew it. At a refresh, none is the cap and one not a positive number refuses the answer.
- A token is due within `refresh-before` of its end, once half its life is spent; at once with less than a second left, or no time it was obtained.
- A token with less than a second left is unavailable, never handed.
- The lock is taken per session and IdP for `lock-lifetime`, under a mark of 128 random bits; a request waits for it at most that long, then reads the entry again. It is let go (ending a millisecond later) only while it holds that mark.
- Writes land only over the version read; a new version is 128 random bits.
- What the upstream says is read once: a part that cannot be read refuses the answer, never counts as absent.
- An entry that does not open is removed.
- A refresh asks for the granted scope.
- A refresh answer narrower than the grant is kept; one with no scope means the grant; a wider or unreadable one changes nothing.
- A record is written for what is left of its session, and not at all once the session lets nobody in.
- A login's tokens are checked against their session once written; when it closed meanwhile, they are withdrawn.

## Depends on
- `federation`, `kernel`, `session`; the package's store interface and `vault`
