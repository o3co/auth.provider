# faults

Internal module of `conformance-code`: what the area's fault scenes share in the code flow's words, its scene and the store writes a fault is about; the deployment, the waits and the repointing around a fault are `conformance`'s (`fault-scene`).

## Responsibilities
- Gives the code flow's scene on the Redis store, and runs a scene on a deployment of its own on that scene unless it names another.
- Runs the code flow against one instance: a code for a browser logged in there (one given or a new one), and a request to its token endpoint, a refresh among them.
- Names a code's writes as the relay matches them, by the code's challenge: its use (the record turned consumed), and the token noted on it after; and a refresh token's rotation, by its family and secret.
- Names, in `test/wire.ts`, what the revocation boundary's scenes take from the store's inside: a store operation as the Redis adapter sends it, a subject's boundary writes and the one that creates it, and a follower's first write, session-lifecycle adding to its closings.

## Offers
- `faultScene`, `on` (`conformance`'s, on `faultScene` by default), `browserOn`, `codeAt`, `tokenAt`, `redeemAt`, `refreshAt`, `said`, `codeUse`, `codeNoted`, `rotationFrom`, and the scene's `issuer`, `callback`, `prefix` and client `app`.
- From `test/wire.ts`: `isStoreOperation`, `boundaryOf`, `boundaryCreated`, `closingAdded`.

## Invariants
- Each code has a challenge of its own, so a match on it never takes another code's write.
- A code's use is the write that turns its record consumed before any token is noted on it; a code that comes again voids its record and a noted token records the token, neither of which is its use.
- A refresh token's rotation is the write that moves its family's current secret off the token's, the family still live; a revocation keeps no current secret and is none.

## Depends on
- The package's scene builder and browser; `conformance` (the fault scene's deployment, the relay and store-wire); `conformance-oauth` (clients)
