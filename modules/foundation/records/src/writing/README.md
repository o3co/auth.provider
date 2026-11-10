# writing

Internal module of `records`: how a record is written, the same for every kind of place.

## Responsibilities
- Sends a write until the store answers, tries again after a lost race, and confirms what it read where it writes nothing.

## Not here
- What is written, and to which keys: the package's builders and internal modules.

## Offers
- `Place`, `Attempt`, `Changed`, `writeDeadline`: as the package offers them.
- `untilAnswered`, `retried` with `again`, `markedAt`, `confirmedAsRead`: one write sent and settled, a decision tried again.
- `rewrite` and `rewriteOpened`: a key read, decided and written on its version, `rewriteOpened` deciding out of the record's envelope and writing back into it.
- `expiryOf` (a lifetime) → the store's expiry; `claim` (a place, a kind) → the place held to one kind of records.

## Invariants
- As the package states them: a resend under the same unguessable mark for up to 10 seconds of pauses, 8 tries after lost races, a send past its deadline refused, any error but unavailable thrown at once.
- A space holds one kind of records; a place opened for the other kind on the same store refuses the boot.

## Depends on
- `kernel`, `store`; the internal module `envelope`
