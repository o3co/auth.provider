# upkeep

Internal module of `store`: keeping a store's data whole, apart from reading and writing its keys.

## Responsibilities
- Declares the `storeControl` and `storeUpkeep` contracts, which every implementation offering them keeps alike, and their contract test.

## Not here
- What an owner's mark means, which spaces erasure needs, and when maintenance runs: the owners' and their tools'. Checking the input: the package's `checkedUpkeep`.

## Offers
- `storeControl`: `control()`, the control record (epoch, maintenance key, the spaces required, the marks), confirmed.
- `storeUpkeep`: `mark`, `require`, `enterMaintenance` and `leaveMaintenance`; the ledger's `kept` and `retire`; `honours`; `sweep`.
- `upkeepContract` (through `./testing`): the contract test, run on an implementation's harness.

## Invariants
- One control record and one ledger per store's data, kept apart from every space, so no key of a space reaches them.
- A process takes the control record's epoch as it starts. Once the record's epoch is another, each change the process makes, through `store` or here, is unavailable and writes nothing: it neither replays a kept answer nor removes what expired. Reads still answer.
- Entering maintenance sets the key and a new epoch, never one the data had, in one write, and the process entering takes the epoch; leaving lifts the key and keeps the epoch.
- A mark is kept with the epoch it was written in, through later epochs; its reader judges what that epoch means for it.
- `require` replaces the set of spaces, under the maintenance key alone, and never with none.
- Before its first change, a starting process adds each space it declares to the ledger, or its start is refused. A space's `subjectDataEver` turns true once a declaration names a category other than `none`, or none at all, and never turns back. Only `retire` takes a space off, under the maintenance key alone, never one the process declares.
- `honours` checks anew on each call, and answers verified, declared (naming the settings the operator declared) or unmet (with why).
- `sweep` removes for good each expired key it meets, its answer confirmed as a write, and names the server each page ran on.

## Depends on
- `kernel` (contracts)

## Vocabulary
- epoch: the control record's mark, new on each entry to maintenance; a process's changes count only under the epoch it took. maintenance key: the record's flag that upkeep holds the data under. ledger: the spaces ever declared to the data.
