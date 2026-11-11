# stores

Internal module of `users`: how users writes through its store interfaces (declared in `store.ts`, the contract), which of their optional ports may be offered together, and users' eraser over them. This module is the mechanics; `store.ts` is the interface.

## Responsibilities
- Writes a subject's link or contact record, saved with its subject, changed from what it holds.
- Judges, at build, whether a link store and a contact store offer their erasure ports as whole sets.
- Erases a subject's links and contacts, and migrates both spaces, through those ports: the eraser `users`.

## Not here
- What the interfaces are, and what each port answers: `store.ts`. What a link or a contact holds: `links` and the package.

## Offers
- `keptFor` (a store, a key, the first record, a change, the subject) → the record before and after: changed where it is there; saved for the subject where it is not.
- `portsRefused` (the link store, the contact store) → why their ports cannot be used together, or none.
- `portsRefused` is the one statement of the sets; `everyPortOffered` (the link store, the contact store) → whether every set is offered whole.
- `usersEraser` (the link store, the contact store, the readings) → the eraser `users`, contributed to `erasure-extensions`' `erasers`: a subject's links and contacts erased through the stores' `erase`; the one migration through their `migrate`, with each space's reading and names' step (`ErasureReadings`), which the package composes from the modules owning the records.

## Invariants
- A create that meets a record a read then finds gone is tried again, at most 8 times, then unavailable: a record can now be removed, so `exists` then absent is no proof of another subject's record.
- A save the store answers `erased` (its subject's erasure fences it) is unavailable, never another's answer, and nothing is created; a retry never succeeds, as the fence is for good. users does not check that a subject exists before `link` or `verifiedContact`, so a caller holding an erased subject's id meets this on every call; in users' own flows the subject's sessions are revoked, so a request meets it where it was under way as the erasure landed.
- The link store's `issuers` and `unowned` come together or neither, alone too: names are copied apart with no erasure ports. Optional in 0.20; in 0.22 `issuers` is required and `unowned`, deprecated from birth, goes.
- The link store's `remove`, `erase` and `migrate` come together or none, and only with `issuers` (and so `unowned`): a part refuses the boot, as `erase` or `migrate` without `remove` would let a link released inside one subject's envelope be taken by another and misread, and without `issuers` the names would stay in the link space. The contact store's `erase` and `migrate` come together.
- The eraser is `erasable` only where `everyPortOffered`; otherwise it answers empty reports. Its `window` erases each subject as `online` does: links are indexed by their subject and contacts keyed by it, so no walk reaches more.

## Depends on
- `kernel` (Unavailable), `erasure-extensions` (the eraser, its reports and readings); users' store interfaces (`store.ts`). No other internal module: the readings come from the package.
