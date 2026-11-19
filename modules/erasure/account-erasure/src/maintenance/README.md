# maintenance

Internal module of `account-erasure`: erasure's maintenance interface, in erasure's words.

## Responsibilities
- Declares `erasureMaintenance`, what erasure needs of the store's data as a whole, with its answers.

## Not here
- How a store answers it: the wiring (`account-erasure-store`), mapping store's contracts and subject-records' phase onto it. When a member is called: the commands, through the step.

## Offers
- `erasureMaintenance` (`takenBy: ["account-erasure"]`) and its types.

## Invariants
- No type is shared with store. Where a word means what store's does, it is the same word.
- A process whose epoch is not the record's changes nothing through it: each change is unavailable (kernel's `Unavailable`).
- A process that took its epoch under the key changes only while the key is held: after `leave()`, each change, `enter()` and `leave()` among them, is unavailable.

## Depends on
- `kernel` (contracts)

## Vocabulary
- `record()`: the control record, confirmed: its epoch, whether the maintenance key is held, the spaces required, and each owner's mark with the epoch it was written in.
- `enter()`: sets the maintenance key and a new epoch in one write; this process takes the epoch. `leave()`: lifts the key; the epoch stays.
- `mark(name, value)`: writes an owner's mark in the present epoch, confirmed.
- `require(names)`: replaces the spaces required, never with none; outside the key, `not-in-maintenance`.
- `kept()`: the ledger, every space ever declared to the data until retired, with whether any declaration may have held a subject's data.
- `retire(name, generation)`: takes a space off the ledger as of the generation a walk read: `retired`, or `declared` (this process declares it), `redeclared` (declared since), `missing`, `not-in-maintenance`.
- `sweepKept(name, cursor?)`, where the store offers it: a page of the walk of a kept space this process doesn't declare: about how many live keys, how many endless, the latest end and, on the first page, its generation; or `declared`, `missing`, `not-in-maintenance`. Where it isn't offered, nothing is retired.
- `honours(guarantees)`: whether the store gives these guarantees now, checked anew: verified, declared (the settings named) or unmet (with why), with a witness of the server and its history with either of the first two.
- `sweep(space, cursor?)`: a page of the walk of a space, by its declared name, removing for good each expired key it meets: the page's live keys, opaque here and only handed on to an eraser, the next cursor, and the server it ran on.
- `phase()`: the phase records are in, `reader` or `indexed`. `writePhase()`: turns records `indexed`, under the key alone (`not-in-maintenance`), where the store writes records of two partitions as one (`not-paired`).
- `alone()`: whether another process is attached to the store's data now: `alone`, `accompanied {count}` or `unchecked {reasons}`; unavailable where the read is disturbed.
- `declared()`: the spaces this process declares, in declaration order: each one's name and erasure fields (`subjectData`, `erasedBy`, `boundedMs`, `requiredOnceErasing`).
- declared: said by someone, not found by the store, as in store: by the operator in `honours`' `declared` (settings, taken as stated); by this process in `retire`'s `declared` and `declared()` (its spaces).
