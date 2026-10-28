# faults

Internal module of `conformance-device`: what the area's fault scenes share in its words, its scene and the store writes a fault is about; the deployment, the waits and the repointing around a fault are `conformance`'s (`fault-scene`).

## Responsibilities
- Gives the device grant's scene on the Redis store, one client allowed the grant and one user, and runs a scene on a deployment of its own on that scene.
- Authorizes a device at an instance, logs the user in there, sends the user's lookup or decision to its verification interface, and polls its token endpoint; gives a device approved and not yet polled, whose first poll takes the approval at once.
- Names, in `test/wire.ts` alone, the writes to a device's record in `device-grant-store.devices`, under the name made from its device code, as the relay matches them: the poll's take of the approval, a decision (approved or denied), and the confirmation a rewrite sends where what it read leaves nothing to write (which tells no kept record from a lost one); and which commands are store calls.

## Offers
- `faultScene`, `on` (`conformance`'s, on `faultScene`), `deviceAt`, `loginAt`, `decideAt`, `pollAt`, `approvedAt`, `said`, and the scene's `issuer`, `deviceGrant` and client `tv`.
- From `test/wire.ts`: `takeOf`, `decisionOf`, `confirmedOf`, `isStoreCall` and the deployment's `prefix`.

## Invariants
- The store's own names (spaces, record names and fields, operations, the commands it sends) are written in `test/wire.ts` alone, never in a scene's file.
- Each device has a record of its own, so a match on its writes never takes another device's.
- The scene's attempt limit is its own value, not the default, so the decisions of one scene stay within one window.

## Depends on
- The package's scene builder; `conformance` (the fault scene's deployment, the relay and store-wire)
