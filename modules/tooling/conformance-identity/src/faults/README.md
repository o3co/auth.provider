# faults

Internal module of `conformance-identity`: what the area's fault scenes share in its words, its scene and the store writes a fault is about; the deployment, the waits and the repointing around a fault are `conformance`'s (`fault-scene`).

## Responsibilities
- Gives password login's scene on the Redis store, one user, with what a scene adds, and runs a scene on a deployment of its own on that scene unless it names another.
- Sends a password login to an instance, as its proxy forwards it from a source, and reads its answer: status, error and the session cookie it set.
- Names the writes a login makes as the relay matches them: its attempt's count under the route's name and its source in `rate-limit.attempts`, and any request about an identifier's lockout in `rate-limit.lockouts`, its read or a write.

## Offers
- `faultScene`, `on` (`conformance`'s, on `faultScene` by default), `nextSource`, `loginAt`, `said`, `attemptFrom`, `identifierLockout`, and the scene's `issuer`, `prefix` and user `alice`.

## Invariants
- Each source is one of its own, so a match on its count never takes another scene's.

## Depends on
- The package's scene builder; `conformance` (the fault scene's deployment, the relay and store-wire); `conformance-keys` (the signing key)
