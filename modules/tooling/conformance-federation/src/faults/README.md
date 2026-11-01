# faults

Internal module of `conformance-federation`: what the area's fault scenes share in its words, its scene and the store writes a fault is about; the deployment, the waits and the repointing around a fault are `conformance`'s (`fault-scene`).

## Responsibilities
- Gives federation grants' scene on the Redis store at an upstream the users log in through, the ledger revoking subjects, with what a scene sets of the grants; runs a scene on a deployment of its own, the upstream started before it and stopped however it ends.
- Gives what a scene does at an instance: lodging, connecting and calling grants (`grants`'s, at that instance).
- Names, in `test/wire.ts` alone, a subject's revocation boundary's writes and the one that creates it, a follower's first write (session-lifecycle adding to its closings, before federation-grants' follower runs), and a write to a grant's record; and the boundaries a write of a subject's boundary puts (`sessions` and, once a revocation moved it, `delegations`).

## Offers
- `faultScene`, `on`, `grantsOn`.
- From `test/wire.ts`: `boundaryOf`, `boundaryCreated`, `closingAdded`, `grantWritten`, `boundariesPut` and the deployment's `prefix`.

## Invariants
- The store's own names (spaces, partitions, operations) are written in `test/wire.ts` alone, never in a scene's file.

## Depends on
- `grants` (the scene and what a scene does at a base URL); `conformance` (the fault scene's deployment, the relay and store-wire)
