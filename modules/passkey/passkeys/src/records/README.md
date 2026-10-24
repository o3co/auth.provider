# records

Internal module of `passkeys`: the passkey records, read in the shape written, and the writes that leave every list as it is.

## Responsibilities
- Reads holders and passkeys in the shape written, and makes the writes that keep a holder's list as it is: a first holder, an activation, a count, a name.

## Not here
- The writes that change a list, and the fence they move (the package's records, which compose this module). Challenges (`challenges`). Where records are kept (the package's store interface).

## Offers
- `recordsOver` (the passkey store) → `holder`, `handleFor`, `passkey`, `activated`, `count`, `listed`, `renamed`.
- For the package's writes that change a list: the shapes read (`holderOf`, `keptOf`), the keys (`subjectKey`, `credentialKey`), a pending record by its write's token (`pendingOf`), the removed form (`removedOf`), `heldBy`, `stored` and `broken`.

## Invariants
- Handles and credential ids are written and compared only in `webauthn`'s canonical form. A record read in another shape is unavailable: a broken record decides nothing.
- A holder is version 1, with its handle, its list and an optional fence, read as 0 where 0.18 kept none. A passkey is version 1. A pending one is version 2 with its write's token, so a host reading only version 1 finds it broken, never a passkey. A removed one keeps only its subject.
- `handleFor` makes a holder only where the subject has none, and answers the one kept.
- An activation turns only the pending record its write's token names into a passkey, keeping its subject and every list; any other (written over, taken by another subject, or removed) is `taken`.
- A count moves on only over the count judged, as the record before the change tells; a removed or pending record has none.
- A name is set only on a passkey the subject's holder lists and that names the subject.
- `listed` follows the holder's list in its order, leaving out each id whose record is not the subject's passkey.

## Data
- Passkeys under `c-` and subjects under `s-`, each followed by the SHA-256 of the id or the subject in base64url, in the passkey store's two spaces.

## Depends on
- `webauthn` (the canonical form, the credential); the package's contract and store interface
