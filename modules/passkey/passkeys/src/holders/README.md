# holders

Internal module of `passkeys`: whether subjects hold passkeys, and the settle that keeps the witness's mark in line with them.

## Responsibilities
- Settles a subject: marks one holding a passkey with no mark, under a new token, and has a mark beside none go where the call may end it.

## Not here
- How passkeys are written and listed (the package's records). The witness's promises and its wire (the witness composed). Who asks a settle, and when (the package's registrations, and the modules taking `passkeyHolders`).

## Offers
- `holdersOver` (records, witness, audit, log, a fresh token, a fresh handle) → `holders` (the package's `PasskeyHolders`) and `settle` (subject, where asked, the holder its call's write left where it emptied the list), for the package's registrations.

## Invariants
- A settle reads the passkeys and the mark again after each write, its own withdraw included, and marks twice at most: the limit is judged before a mark, so the last mark is checked too, then it is unavailable while they still differ. It answers whether the subject holds a passkey as the read the mark agreed with saw it, and `held` answers that, never a read of the passkeys alone after.
- Its own mark, by the latest `enroll`'s token, goes by `withdraw`, which leaves another's; it never asks `clear`.
- Where its call emptied the list (a last removal, an end, `cleared`), it reads the mark's token, then what the holder that write left holds (`afterRemoval`), and withdraws that token only where that answers none.
- None holds only where all three hold: the holder's handle is the one that write left (no holder lost or made anew since); its fence is that write's or later (no write of it lost, no copy from before it put back); and every record its list names reads, none being the subject's pending or live passkey (a missing record is lost, never none). Anything else not held is unsure; a holder that changes between its two reads is read again from the start, once.
- Held (the subject's pending or live passkey listed) leaves the mark; unsure records it as inconsistent and is unavailable, the mark kept.
- The withdraw is asked again with the same token, reading nothing again; after it, it reads the holder again and marks where a passkey came meanwhile, a pending one marking once admitted.
- Elsewhere a mark beside none is read once more, as a last removal may lie between emptying the list and its withdraw, then recorded as inconsistent and unavailable.
- What is left open: a call that stops after its withdraw can leave a passkey with no mark until the next settle (losing the store meanwhile reads as holding none); a call stopped between emptying the list and its withdraw leaves a mark beside none, which only `cleared` mends.

## Depends on
- `audit`, `kernel`; the package's contract, records and audit events
