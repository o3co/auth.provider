# holders

Internal module of `passkeys`: whether subjects hold passkeys, and the settle that keeps the witness's mark in line with them.

## Responsibilities
- Settles a subject: marks one holding a passkey with no mark, under a new token, and has a mark beside none go where the call may end it.

## Not here
- How passkeys are written and listed (the package's records). The witness's promises and its wire (the witness composed). Who asks a settle, and when (the package's registrations, and the modules taking `passkeyHolders`).

## Offers
- `holdersOver` (records, witness, audit, log, a fresh token) → `holders` (the package's `PasskeyHolders`) and `settle` (subject, where asked, whether this call emptied the list), for the package's registrations.

## Invariants
- A settle reads the passkeys and the mark again after each write, its own withdraw and clear included, and marks twice at most: the limit is judged before a mark, so the last mark is checked too, then it is unavailable while they still differ. It answers whether the subject holds a passkey as the read the mark agreed with saw it, and `held` answers that, never a read of the passkeys alone after.
- Its own mark, by the latest `enroll`'s token, goes by `withdraw`, which leaves another's. A mark not its own goes by `clear` only where its call emptied the list (a removal's last one, or `cleared`); elsewhere it reads once more, as a last removal may lie between emptying the list and its clear, then records the mark as inconsistent and is unavailable.
- What is left open: a registration and a last removal at once can leave a passkey with no mark until the next settle (losing the store meanwhile reads as holding none); a last removal stopped between emptying the list and its clear leaves a mark beside none, which only `cleared` mends.

## Depends on
- `audit`, `kernel`; the package's contract, records and audit events
