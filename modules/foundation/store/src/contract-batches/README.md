# contract-batches

Internal module of `store`: the contract test's batches across partitions and spaces, counting, and reads of several keys and a batch's time.

## Responsibilities
- Holds every implementation to the store contract on batches across partitions and spaces, on counting in a window, and on reads of several keys and a batch's time.

## Not here
- Single keys, marks, walking and input, faults: the other parts.

## Offers
- `batchesContract(harness, kit)`, run by `storeContract`.

## Depends on
- `contract-harness`; `store`'s contract.
