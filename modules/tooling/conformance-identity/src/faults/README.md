# faults

Internal module of `conformance-identity`: what the area's fault scenes share in its words, its scene and the store writes a fault is about; the deployment, the waits and the repointing around a fault are `conformance`'s (`fault-scene`).

## Responsibilities
- Gives password login's scene on the Redis store, one user, with what a scene adds, and runs a scene on a deployment of its own on that scene unless it names another.
- Sends a password login to an instance, as its proxy forwards it from a source, and reads its answer: status, error, the session cookie it set and the wait it asks.
- Names, in `test/wire.ts` alone, what the scenes take from the store's inside, so the case files name none of it: the deployment's prefix and a store operation as the Redis adapter sends it.
- There too: a login attempt's count under the route's name and its source in `rate-limit.attempts`; any request about an identifier's lockout in `rate-limit.lockouts`, and the writes to one identifier's; a session's record in `session-store.sessions` and its cookie's index in `session-store.cookies`.

## Offers
- `faultScene`, `on` (`conformance`'s, on `faultScene` by default), `nextSource`, `loginAt`, `said`, and the scene's `issuer` and user `alice`.
- From `test/wire.ts`: `prefix`, `isStoreOperation`, `storeOperations`, `attemptFrom`, `identifierLockout`, `lockoutOf`, `sessionRecord`, `cookieIndexed`.

## Invariants
- The store's inside (spaces, partitions, operations, the adapter's commands) is named only in `test/wire.ts`; when the adapter and the wirings describe it themselves, that file alone changes.
- Each source is one of its own, so a match on its count never takes another scene's.

## Depends on
- The package's scene builder; `conformance` (the fault scene's deployment, the relay and store-wire); `conformance-keys` (the signing key)
