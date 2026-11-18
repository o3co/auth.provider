# contract-faults

Internal module of `store`: the contract test's replication faults: replicas that do not acknowledge, lost replies, restarts and failover.

## Responsibilities
- Holds every implementation that replicates, persists or talks over a network to the store contract under faults: replicas that do not acknowledge, a reply lost, a restart, and a failover to a replica lacking the latest writes. A case whose fault the harness does not offer is skipped.

## Not here
- Single keys, marks, batches, walking and input: the other parts.

## Offers
- `faultsContract(harness, kit)`, run by `storeContract`.

## Depends on
- `contract-harness`; `store`'s contract.
