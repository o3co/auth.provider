# writing

Internal module of `records`: how a record is written, the same for every kind of place.

## Responsibilities
- Sends a write until the store answers, tries again after a lost race, and confirms what it read where it writes nothing.

## Not here
- What is written, and to which keys: the package's builders and internal modules.

## Offers
- `Place`, `Attempt`, `Changed`, `writeDeadline`: as the package offers them.
- `untilAnswered`, `retried` with `again`, `markedAt`, `confirmedAsRead`: one write sent and settled, a decision tried again.
- `rewrite`: a key read, decided and written on its version.
- `expiryOf` (a lifetime) → the store's expiry; `claim` (a place, a kind) → the place held to one kind of records. `nameOf` (a space, a secret) → the name a record under that secret is kept by.

## Invariants
- A change runs again on what is there after a lost race, so it must be pure; after 8 lost races it is unavailable, a fixed margin against contention.
- A write whose answer was lost is resent under the same unguessable mark, so it takes effect once, for up to 10 seconds of pauses (from 50 ms, doubling to 1 second), fixed to stay within the store's idempotency window, where a resend still gets its first answer; a send past its deadline is refused, and any error but unavailable is thrown at once.
- A secret's name is `1.` and the base64url SHA-256 of the space's name, a line feed and the secret; the store never receives the secret.
- A space holds one kind of records; a place opened for the other kind on the same store refuses the boot.

## Depends on
- `kernel`, `store`
