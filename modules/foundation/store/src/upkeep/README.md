# upkeep

Internal module of `store`: keeping a store's data whole, apart from reading and writing its keys.

## Responsibilities
- Declares the `storeControl` and `storeUpkeep` contracts, which every implementation offering them keeps alike, and their contract test.

## Not here
- What an owner's mark means, which spaces erasure needs, and when maintenance runs: the owners' and their tools'. Checking the input: `checkedUpkeep` (internal module `checks`).

## Offers
- `storeControl`: `control()`, the control record (epoch, maintenance key, the spaces required, the marks), confirmed. It may go unprovided until 0.22 (`optional`): a store adapter of 0.19 offers none, and a taker reads a mark it cannot read as unknown, failing closed.
- `storeUpkeep`: `mark`, `require`, `enterMaintenance` and `leaveMaintenance`; the ledger's `kept` and `retire`; `honours`; `sweep`; `alone()`.
  - `declared()`: the spaces this process declares: the declarations themselves, as checked, in declaration order, in a frozen array.
- `upkeepContract` (through `./testing`): the contract test, run on an implementation's harness.

## Invariants
- One control record and one ledger per store's data, kept apart from every space, so no key of a space reaches them.
- A process takes the control record's epoch as it starts. Once the record's epoch is another, each change the process makes, through `store` or here, is unavailable and writes nothing: it neither replays a kept answer nor removes what expired. Reads still answer. A read never removes anything, for any process: what expired is removed by a change or by `sweep`, each under both fences, or by the server itself where it expires keys on its own.
- A process is refused at start (kernel's `BuildRefused`), judged on the same read of the record it takes the epoch from:
  - under the maintenance key, unless it may build under it, this refusal first where both apply: `where` `store`, "only a tool may start while the store is under the maintenance key";
  - without a space `requires` names, unless it may build under the key and is under it: `where` `store`, "the data requires a space this process does not declare", naming no space; the operator reads `requires` from the control record (`storeControl`);
  - refused, it writes nothing to the control record, the ledger or any declared space: it takes no epoch and adds nothing to the ledger. An implementation's own checks of its server at boot may write keys of their own, outside every space, holding no value of any process's data and no subject's data.
- A process that took its epoch under the maintenance key, by starting under it or entering it, changes only while the key is held. Once the record shows no key, each change it makes, through `store` or upkeep, `enterMaintenance` and `leaveMaintenance` among them, is unavailable and writes nothing.
- Entering maintenance sets the key and a new epoch, never one the data had, in one write, and the process entering takes the epoch; leaving lifts the key and keeps the epoch.
- A mark is kept with the epoch it was written in, through later epochs; its reader judges what that epoch means for it.
- `require` replaces the set of spaces, under the maintenance key alone, and never with none.
- Before its first change, a process adds each space it declares to the ledger; until it has, it changes nothing (each change unavailable) and its readiness says so, retrying. A space's `subjectDataEver` turns true once a declaration names a category other than `none`, and never turns back. Only `retire` takes a space off, under the maintenance key alone, never one the process declares.
- `honours` checks anew on each call, and answers verified, declared (naming the settings the operator declared) or unmet (with why).
- `honours` answers a witness of the server and its history; equal witnesses, the same server and history, nothing evicted between. Its reader compares them, never the store.
- `alone()` reads anew on each call whether another process is attached: `alone` only where every process the storing side would now let run any part of a store operation on the data was seen and none is attached; `accompanied` with the implementation's count of those attached, for the operator, never compared; `unchecked` where it could not look, with its reasons; unavailable where a read is disturbed, never `alone` in doubt.
  - Where the implementation offers no way to look, `checkedUpkeep` answers `unchecked` with store's own code; the fallback goes once every implementation must offer one.
- `unchecked`'s reasons are codes: a server named only as `primary` or `replica N`, in the configured order; never an endpoint, address, host or user name, run id or witness. A setting may say how to look, never what the answer is.
  - Store's own code: `no-look-offered`, the implementation offers no way to look.
- `sweep` walks a space by the name this process declares it by; any other name is a caller's error (`TypeError`). It removes for good each expired key it meets, its answer confirmed as a write, and names the server each page ran on.

## Depends on
- `kernel` (contracts); the internal module `planting`, for its contract test to plant values in a space of subjects' data

## Vocabulary
- attached: another process, neither this one nor the store's own replication, that the storing side would now let run any part of a store operation on the data.
- UpkeepImplementation: the upkeep an implementation answers; `checkedUpkeep` adds the rest (`declared`), answers `alone()` where the implementation offers none, and hands the implementation's `sweep` the declared space the caller named.
- the key's fence: a process that took its epoch under the maintenance key changes only while the key is held; once it lifts, the process is done, and a new window is a new process.
- may build under the maintenance key: a process's grant to start under the key, and under it without a space `requires` names; its composition grants it from kernel's `neverStarted` alone, a tool's assembly that is never started.
- epoch: the control record's mark, new on each entry to maintenance; a process's changes count only under the epoch it took. maintenance key: the record's flag that upkeep holds the data under. ledger: the spaces ever declared to the data.
