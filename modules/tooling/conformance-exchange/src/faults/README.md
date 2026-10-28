# faults

Internal module of `conformance-exchange`: what the area's fault scenes share in its words, its scene and the store writes a fault is about; the deployment, the waits and the repointing around a fault are `conformance`'s (`fault-scene`).

## Responsibilities
- Gives the code flow with token exchange on the Redis store, one client that redeems a code and exchanges the access token it was given, and two users, with what a scene adds; runs a scene on a deployment of its own on that scene unless it names another.
- Gives a user's access token from a code of her login at an instance, and exchanges a token there as the subject token.
- Names, in `test/wire.ts` alone, a subject's revocation boundary's writes in `subject-revocation-store.boundaries` and the one that creates it, and a follower's first write, session-lifecycle adding to its closings in `session-store.closings`.

## Offers
- `faultScene`, `on` (`conformance`'s, on `faultScene` unless it names another), `accessAt`, `exchangeAt`, `said`, and the scene's `issuer`, `exchangeGrant`, client `app` and `users`.
- From `test/wire.ts`: `boundaryOf`, `boundaryCreated`, `closingAdded` and the deployment's `prefix`.

## Invariants
- The store's own names (spaces, partitions, operations) are written in `test/wire.ts` alone, never in a scene's file.

## Depends on
- The package's area; `conformance-code` (the code flow's scene and browser); `conformance` (the fault scene's deployment, the relay and store-wire)
