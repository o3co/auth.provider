# holders

Internal module of `passkeys`: whether subjects hold passkeys, and the settle that asks the witnessing where `passkeys` settles.

## Responsibilities
- Answers whether a subject holds a passkey, and ends them all; asks the witnessing contributed, if any, to bring the mark in line after each write.

## Not here
- Matching the witness's mark with the passkeys (the witnessing, `passkey-witnessing`). How passkeys are written and listed (the package's records). Who asks a settle, and when (the package's registrations, and the modules taking `passkeyClearing` or `passkeyHolders`).

## Offers
- `holdersOver` (records, the witnessing contributed, a fresh handle) → `holders` (the package's `PasskeyHolders`) and `settle` (subject, where asked, the holder its call's write left where it emptied the list), for the package's registrations.
- `PasskeyHolding`'s members, the package's `passkeyHolding`: `held` (settled first) and `witnessed` (whether a witness is composed).
- `PasskeyClearing`'s, the package's `passkeyClearing`: `cleared` (ends every passkey of the subject, making its holder where it has none, and has its mark go → how many list entries it took off) and `settle`.
- `PasskeyHolders`, the package's `passkeyHolders`, has both; the package gives all three from the one `holders`.

## Invariants
- Where a witnessing is contributed, a settle asks it: `settle` (held, a registration, a removal that leaves a passkey, `settle`) or `emptied` (a removal or an end that empties the list, a reset). It hands `holds`, whether the subject's list names a passkey, and after an emptying write `after`, what the holder that write left holds (the records' `afterRemoval`). Both read anew each time and write nothing.
- `held` answers what the witnessing answered, as the read the mark agreed with saw it, never a read of the passkeys alone after it. Without a witnessing the store alone tells.
- A reset empties the list whatever it held, making a holder where the subject has none, then asks `emptied`: a mark beside none is what it mends.

## Depends on
- None (the package's contract and records)
