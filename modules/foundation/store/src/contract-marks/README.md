# contract-marks

Internal module of `store`: the contract test's deadlines and idempotency marks, and concurrent connections.

## Responsibilities
- Holds every implementation to the store contract on deadlines and idempotency marks, and on what two connections to the same data see.

## Not here
- Single keys, batches, walking and input, faults: the other parts.

## Offers
- `marksContract(harness, kit)`, run by `storeContract`.

## Depends on
- `contract-harness`; `store`'s contract.
