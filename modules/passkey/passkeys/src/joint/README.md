# joint

Internal module of `passkeys`: the writes that change a holder's list, each with the records it names in one change, and what a write that emptied a list leaves.

## Responsibilities
- Registers, ends, removes and clears passkeys as one change of the list and its records, and tells what a holder holds after a write that emptied its list.

## Not here
- The record shapes, and the writes that keep a list as it is (`records`). Settling the witness's mark after these writes (`holders`). Who may write (the package's registration and holdings).

## Offers
- `jointOver` (the passkey store, `records`' read of a holder, `kernel`'s clock) → `joined`, `ended`, `removed`, `cleared` and `afterRemoval`; the type `Emptied` (the holder an emptying write left: its handle and fence).

## Invariants
- In what 0.19 writes, a list names an id exactly while its record names the subject, pending or a passkey: a registration writes the record and the list in one change, as an end, a removal and a clear change them. An orphan record or an old entry 0.18 left stays the accepted exception.
- A credential that would not read back is refused before a write. A registration's change checks again that the holder's handle is the credential's: a holder made anew since is `malformed`, nothing written.
- An id its holder lists is a conflict, and a list at its limit that lacks it is full, both judged in the one change. A record no holder lists (removed, or left by 0.18) is taken over in the same write, an old entry for it kept until its holder lets it go.
- A removal strips the subject's record to its subject: no key, count or name. A record only another subject holds is never stripped; an old entry for it only frees its slot.
- An end takes off only what its write's token names.
- Each write that empties a list moves its fence on by one in the same change, and no other write moves it. A clear always does, making a holder at fence 1 under the handle given where the subject has none. The write answers the holder it left (`emptied`).
- `afterRemoval` reads without writing. A listed passkey or pending one of the subject is held; none needs the holder that write left (its handle, at its fence or later) and every listed record readable, none the subject's; anything else is unsure. A holder that changes between its two reads is read again from the start, once.

## Depends on
- `webauthn` (the credential's form); the internal module `records`; the package's store interface
