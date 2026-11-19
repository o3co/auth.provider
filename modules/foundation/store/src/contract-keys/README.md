# contract-keys

Internal module of `store`: the contract test's single keys: reads and writes, versions and expiry.

## Responsibilities
- Holds every implementation to the store contract on single keys: reads and writes, their versions, and their expiry.

## Not here
- Marks and concurrency, batches, walking and input, faults: the other parts.

## Offers
- `keysContract(harness, kit)`, run by `storeContract`.

## Depends on
- `contract-harness`; `store`'s contract.
