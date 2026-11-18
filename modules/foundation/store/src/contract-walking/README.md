# contract-walking

Internal module of `store`: the contract test's scanning of a space, and the checks on every input.

## Responsibilities
- Holds every implementation to the store contract on scanning a space, and on the checks every input meets before anything is written.

## Not here
- Single keys, marks, batches, faults: the other parts.

## Offers
- `walkingContract(harness, kit)`, run by `storeContract`.

## Depends on
- `contract-harness`, `writer` (the subject writer, for the batch options' case); `store`'s contract.
