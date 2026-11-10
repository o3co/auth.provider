# sets

Internal module of `subject-records`: keyed sets in a space holding subjects' data.

## Responsibilities
- Keeps a subject's keyed sets where and as `records`' keyed sets keep them, so the one migration and processes that only read see the same sets, and indexes or fences them by subject.

## Not here
- What a set holds, its cap and pushed-out members: `records`' `keyedSetsIn.codec`. Naming the index: internal module `index`. The envelope: internal module `envelope`.

## Offers
- `subjectKeyedSetsIn` (a place with its cap and clock) → `add` (a key, its subject, a member, a lifetime: those pushed out, or `erased`), `members`, `remove`, `awaiting`, `settled`, in a space declaring `online-indexed` or `online-keyed`.

## Invariants
- Every write goes through `changeRecords`, to the target `{ place, key, set: true }`; a read goes to the store.
- Once indexed, a set is kept in an envelope with its subject; an add holds the subject's tombstone absent and, in an `online-indexed` space, writes the set's key in its subject's bucket as one.
- A member's end is fixed at its add, so an add that lands late never shortens it.
- A removal and a settling rewrite the set in the envelope it was read in; no tombstone stops them.
- A member pushed out over the cap is logged (`records.pushed_out`), as `records` logs it.

## Depends on
- `kernel` (the clock), `records` (`changeRecords`, `keyedSetsIn.codec`), `store`
