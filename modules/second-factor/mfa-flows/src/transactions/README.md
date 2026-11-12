# transactions

Internal module of `mfa-flows`: transactions over the package's store interface, each tied to one browser.

## Responsibilities
- Starts, finds, spends, takes and changes transactions, on `kernel`'s clock.

## Not here
- What a request may do with a transaction, and every answer (`proof`, and `mfa-enrollment` through `flowParts`). What a binding keeps in one (`mfa-enrollment`). The store's implementation (the wiring side).

## Offers
- `transactionsIn` (the build context) → the operations below. It takes the package's store interface and `cookies`' contract from the assembly, and randomness, the clock and the package's `transaction-lifetime` and `attempts-per-transaction` from the context.
- `transactionsOver` (those parts, given directly) → the same operations. `transactionsTakes`: what `transactionsIn` takes, for the takes of each module calling it.
- `start`: a new transaction with every attempt, holding what it is given for its work → its identifier, deadline and cookie. `nextDeadline`: the deadline of one started now.
- `find` (request, identifier) → the transaction and the time left, or none.
- `carried` (request) → the identifier the browser's cookie names, or none.
- `spend` → the attempts left and the challenge it took, or none. `take` → whether this call took it.
- `judged` (identifier, a judgement on the attempt spent) → its answer; an unavailable one gives the attempt back, the last one included, so the transaction is found again.
- `challenged` (a factor's challenge sealed by `mfa`, or none to clear it) → whether it was kept.
- `keep` (a change of what the transaction holds for its work, from what it holds) → what it holds now, or none when it is no longer in use or the change gives nothing.
- `askedFrom` (a transaction's purpose) → whom `mfa`'s kinds are asked for: a held login by the email its login gave, `vouched` when `subject-attributes`' `vouches` says `users` stands behind it, else the session by its handle.
- `cleared` → the cookie that ends the transaction's binding to its browser.
- The listings' contract test holds a place to the cap it gives; a place that gives none is held to 5, as every place was before one could give it.

- Store interface for transactions by their unguessable identifier, never kept in clear: save for a lifetime and a subject, read, change from what it holds (the lifetime stays). Contents are not shown to it. Its needs: never evicted, survives a crash, never back after a failover. It holds transactions (at most `transactionLifetimeMaxMs`, 30 min) and release permits (at most an hour); `heldLifetimeMaxMs`, the longer of the two, is the bound a Store fencing it declares.
- Store interface for each holder's live transactions (a session's handle, or a held login's subject), each by a digest of its identifier for its lifetime: add for the holder's subject (answering those pushed out past its cap, the wiring's), members, remove. Its needs: never evicted, survives a crash and a failover, confirmed reads.
- Where the Store fences saves past a subject's erasure, a save or an add for an erased subject answers `erased` (an add may answer `another-subject` too), a change nothing; a start takes either as refused, unavailable. Both stores' optional `erase` and `migrate` come together or none: a part refuses the boot.

## Invariants
- The store interface's contract test (`./testing`) checks every implementation: kept whole and once, changed only from what it holds, ended at exactly its lifetime; restarts, memory pressure, lost answers and failovers where the place has them.
- A transaction's identifier and its browser's secret are 256 random bits each; the record keeps only a hash of the secret, and `find` answers only the browser holding it.
- The cookie holds the identifier and the secret (`<identifier>.<secret>`) for the transaction's lifetime (30 minutes at most), so it alone names the transaction, and `find` answers it for no other. One of the earlier form, the secret alone, names none, and is read for its secret until it ends; one with an empty part or another dot is no cookie.
- The cookie has one name, so a browser holds one transaction at a time: starting another leaves the earlier one out of its reach.
- A transaction's start and deadline are on `kernel`'s clock, read once outside the store's change; past its deadline it is gone, whatever the store still keeps.
- Every change starts from what the store holds and leaves a taken or past one as it is. Spend and take say whether this call made the change, so of two racing calls only one wins.
- A transaction's record carries its deadline and, once taken, its mark. What it holds for its work is JSON never read here.
- Records are written in format 2. One of format 1, with a binding's fields at the top, reads them as what it holds.
- Taking marks the transaction; a marked one is kept until its lifetime and read as gone.
- A start whose identifier is already held is unavailable.
- A start keeps the transaction for its subject, then lists it under its holder (the session it is tied to, or the held login's subject) by a digest of its identifier; a listing that cannot answer, or a save or listing its subject's erasure refused, makes the start unavailable, never tried again. A lifetime past `transactionLifetimeMaxMs` is a TypeError.
- A transaction counts only while its holder's listing still holds it, read once each time it is used (`503` when the listing cannot tell). A holder keeps up to its listing's cap, the store wiring's: one more pushes out the one ending first, so one device's held login can push out another's. A taken one, or one out of attempts, leaves the listing; a removal that fails is logged and passed.
- `find` answers a transaction only while its holder's listing holds it and an attempt is left; taking it takes it off the listing, logging `mfa-flows.listing_failed` when that fails. Every caller takes it once its last attempt is judged.

## Depends on
- `kernel` (the build context, the clock, unavailable); `http` (the request type); `cookies`; `session` (the login facts type); `login-gates` (`LoginFrom`); `mfa-extensions` (`AskedFrom`, whom it asks for); `subject-attributes` (`vouches`); the package's store interface
