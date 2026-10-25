# orphans

Internal module of `interop-oidf`: the suites a run killed before its stops leaves, found and taken down.

## Offers
- `ownerLabel`: the label each container of a suite carries, the process that started it.
- `reclaimOrphans`: takes down the suites whose owner no longer runs: each container's log kept where a directory is given, then the containers, their volumes and their networks removed; answers the projects taken down.

## Invariants
- A suite whose owner runs is never touched.
- Every step is held to its own time; every one is tried, and any that failed is told after.
