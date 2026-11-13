# renewal

Internal module of `federation-tokens`: keeping each session's upstream tokens and renewing them.

## Responsibilities
- Keeps a login's tokens, hands the current ones, and refreshes them under a lock when their end is near.
- Removes one IdP's entry (logout, withdrawal) or the whole record (a session closing). A withdrawal removes it whatever the session's state, any number of times.

## Not here
- Accepting the caller and what the routes answer (the package). Sealing and the record's shape (`vault`). The refresh request itself (the IdP type, through `federation`).

## Offers
- `renewalIn` (the build context) builds it, taking the stores, `upstreams`, the vault and `session`'s entries (late) itself.
- `tokensEraser` (the store, `session`, read late) → the eraser `federation-tokens`, contributed to `erasure-extensions`' `erasers`: a subject's records erased through the store's `erase`, a window doing so for each subject; `erasable` only where the store offers the pair, else empty reports.
- `portsRefused` (the store) → why its ports cannot be used, or none: `erase` and `migrate` come together or neither, one alone refused at build in `renewalIn`; `portsOf` → the pair, whole, or none.
- `tokensSubjectOf` (`session`'s `subjectOf`) → the migration's reading: a record's key is its session's handle and its value holds only the upstream's tokens, so its subject is its session record's, in any state, from one read that writes nothing. A session with no record, or one naming no subject, proves nothing: unreadable, stopping the space; the record ends by its own lifetime, and a rerun after that end finishes. A `session` that cannot tell stops it too.
- With a `Sessions` without `subjectOf`, the migration answers `owner-stopped`, reading no record: the migration is not finished until `session` offers it (0.22 requires it).
- `renewalWith` (store, locks, `upstreams`, `session`'s entries by handle, vault, `kernel`'s runtime, settings): `current` (session, IdP → handed / an outcome the routes answer), `receive`, `disconnect` (→ the id_token, or not linked), `withdraw`, `close`

## Invariants
- When a token ends is judged here only, on `kernel`'s clock, capped at the longest lifetime. At login, an end not a positive number is due now, and none stays none unless a refresh token can renew it. At a refresh, none is the cap and one not a positive number refuses the answer.
- A refresh's end is `upstreams`' `refreshedExpiry`: the same access token keeps the earlier of the two ends. Its life is counted from the refresh, so it is not due again at once: a back-off, as the next refresh waits half of what is left, so an upstream that keeps answering the same token is asked about five times before its end. Counted from its first obtaining, it would be asked on every request within `refresh-before` until the rotation budget ran out.
- A token is due within `refresh-before` of its end, once half its life is spent; at once with less than a second left, or no time it was obtained.
- A token with less than a second left is unavailable, never handed: a fixed margin, as it would end on its way.
- A failed refresh answers the same for 30 seconds without asking the upstream (fixed: shorter asks a failing upstream more often, longer only delays recovery): kept in each process, by session, IdP and a hash of the access token.
- The lock is taken per session and IdP for `lock-lifetime`, under a mark of 128 random bits; a request waits for it up to that long between its asks (every 100 ms, a fixed pace), the time each ask takes to answer coming on top, then reads the entry again.
- While the refresh runs, the lock is kept for its lifetime again every half of it, only under that mark; once lost, nothing the refresh answered is written, and a store that cannot answer stops the keeping. It is kept no longer, then let go (ending a millisecond later, `records`' conditional removal) only while it holds that mark.
- Writes land only over the version read, tried three times under a changing version (a fixed contention margin); a new version is 128 random bits.
- What the upstream says is read once: a part that cannot be read refuses the answer, never counts as absent.
- An entry that does not open is removed.
- A refresh asks for the granted scope.
- A refresh answer narrower than the grant is kept; one with no scope means the grant; a wider or unreadable one is refused, its access token neither kept nor handed.
- The store's `erase` and `migrate` are optional in 0.20 and required in 0.22.
- A record is written for what is left of its session, and not at all once the session lets nobody in at `use`: closed, ended, revoked, or short of a requirement. A first record is saved for the session's subject; a save answered `erased`, its subject's erasure fencing it, keeps nothing, and the login's tokens are not kept.
- A login's tokens are checked against their session once written; when it closed or fell short of a requirement meanwhile, they are withdrawn.

## Depends on
- `upstreams` (the refresh, the tokens), `kernel`, `session`, `erasure-extensions` (the eraser, its reports and reading); the package's store interface and `vault`
