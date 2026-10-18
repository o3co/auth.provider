# transactions

Internal module of `mfa-flows`: transactions over the package's store interface, each tied to one browser.

## Responsibilities
- Starts, finds, spends, takes and changes transactions, on `kernel`'s clock.

## Not here
- What a request may do with a transaction, and every answer (`proof`, `enrollment`). The store's implementation (the wiring side).

## Offers
- `transactionsIn` (the build context) → the operations below. It takes the package's store interface and `cookies`' contract from the assembly, and randomness, the clock and the package's `transaction-lifetime` and `attempts-per-transaction` from the context.
- `transactionsOver` (those parts, given directly) → the same operations.
- `start`: a new transaction with every attempt, holding a pending binding or a binding proof's challenge when given → its identifier, deadline and cookie. `nextDeadline`: the deadline of one started now.
- `find` (request, identifier) → the transaction and the time left, or none.
- `spend` → the attempts left and the challenge it took, or none. `take` → whether this call took it.
- `judged` (identifier, a judgement on the attempt spent) → its answer; an unavailable one gives the attempt back.
- `hold` (a pending binding, ending any pass kept in the same write), `challenged` (a factor's challenge sealed by `mfa`, or none to clear it), `bindingSent` (a binding proof's name and challenge) → whether it was kept.
- `askedFrom` (a transaction's purpose) → whom `mfa`'s kinds are asked for: a held login by the email its login gave, `vouched` when `subject-attributes`' `vouches` says `users` stands behind it, else the session by its handle.
- `bindingPassed` (the challenge the proof answered, `mfa-binding-proof`'s pass and the kind it is for) → whether that challenge was still the one held; it marks the transaction proved for good. `cleared` → the cookie that ends the binding.

## Invariants
- The store interface's contract test (`./testing`) checks every implementation: kept whole and once, changed only from what it holds, ended at exactly its lifetime; restarts, memory pressure, lost answers and failovers where the place has them.
- A transaction's identifier and its browser's cookie are 256 random bits each; the record keeps only a hash of the cookie, and `find` answers only the browser holding it.
- The cookie has one name, so a browser holds one transaction at a time: starting another leaves the earlier one out of its reach.
- A transaction's start and deadline are on `kernel`'s clock, read once outside the store's change; past its deadline it is gone, whatever the store still keeps.
- Every change starts from what the store holds and leaves a taken or past one as it is. Spend and take say whether this call made the change, so of two racing calls only one wins.
- A transaction's record carries its deadline and, once taken, its mark.
- Taking marks the transaction; a marked one is kept until its lifetime and read as gone.
- A start whose identifier is already held is unavailable.
- A start lists the transaction under its holder (the session it is tied to, or the held login's subject) by a digest of its identifier, after keeping it; a listing that cannot answer makes the start unavailable.
- `find` answers a transaction only while its holder's listing holds it; taking it, or spending its last attempt, takes it off, logging `mfa-flows.listing_failed` when that fails.

## Depends on
- `kernel` (the build context, the clock, unavailable); `http` (the request type); `cookies`; `session` (the login facts type); `mfa` (the type of whom it asks for); `subject-attributes` (`vouches`); the package's store interface
