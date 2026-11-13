# keyed-sets

Internal module of `records`: sets of members by key, at most a cap to a key, ending on `kernel`'s clock.

## Responsibilities
- Holds the keyed set's format at rest, its only definition, and writes sets with it.

## Not here
- What a member stands for, and the cap: the feature's and the wiring's. Sets keyed by a subject: subject-records, which composes the codec inside `changeRecords`.

## Offers
- `keyedSetsIn` (a place, a cap, a clock) → `add`, `members`, `remove`, `awaiting`, `settled`, as the package offers them.
- `keyedSetsIn.codec` (a cap, a clock) → the same changes and reads as pure functions over a set's stored value, each change answering its value and the lifetime it is kept for.
- `keyedSetsIn.strict` (a stored value, no cap or clock) → `set` where every part is well formed, each member with its end, ended ones included, or `unreadable` with why (`StrictSet`): nothing dropped, for a migration that must not lose a member. The codec's reads stay lenient.
- `Member`, `KeyedSetWrite`; `overCap` and `checkedCap`, deprecated, as the package offers them.

## Invariants
- A keyed set is one record per key, rewritten whole, so its cap stays small; anything in it that is not a member is no member.
- A member ends at its add's time plus its lifetime on `kernel`'s clock, however late the write lands; the set is kept ten minutes past its last end, a fixed storage margin. What an add pushes out awaits in that same write, until its caller settles it or its end passes, so a caller stopped between the add and its own work finds it again. A set kept as a bare list, as before, reads as members alone.
- Over the cap, the other members ending first are pushed out (ties by code point order), never the one being added, and that is logged with the space. A cap is a whole number from 1.

## Depends on
- `kernel` (the clock), `store`; the internal module `writing`
