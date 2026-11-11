# stores

Internal module of `users`: how users writes through its store interfaces (declared in `store.ts`, the contract), and which of their optional ports may be offered together. This module is the mechanics; `store.ts` is the interface.

## Responsibilities
- Writes a subject's link or contact record, saved with its subject, changed from what it holds.
- Judges, at build, whether a link store and a contact store offer their erasure ports as whole sets.

## Not here
- What the interfaces are, and what each port answers: `store.ts`. What a link or a contact holds: `links` and the package.

## Offers
- `keptFor` (a store, a key, the first record, a change, the subject) → the record before and after: changed where it is there; saved for the subject where it is not.
- `portsRefused` (the link store, the contact store) → why their ports cannot be used together, or none.

## Invariants
- A create that meets a record a read then finds gone is tried again, at most 8 times, then unavailable: a record can now be removed, so `exists` then absent is no proof of another subject's record.
- A save the store answers `erased` (its subject's erasure fences it) is unavailable, never another's answer, and nothing is created; a retry never succeeds, as the fence is for good. users does not check that a subject exists before `link` or `verifiedContact`, so a caller holding an erased subject's id meets this on every call; in users' own flows the subject's sessions are revoked, so a request meets it where it was under way as the erasure landed.
- The link store's `names` and `unowned` come together or neither: optional in 0.20; in 0.22 `names` is required and `unowned`, deprecated from birth, goes.
- The link store's `remove`, `erase` and `migrate` come as one set, with `names` (and so `unowned`): a part of the set refuses the boot, as `erase` or `migrate` without `remove` would let a link released inside one subject's envelope be taken by another and misread, and without `names` the names would stay in the link space. The contact store's `erase` and `migrate` come together.

## Depends on
- `kernel` (Unavailable); users' store interfaces (`store.ts`)
