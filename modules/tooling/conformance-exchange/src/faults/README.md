# faults

Internal module of `conformance-exchange`: what the area's fault scenes share in its words, its scene and the store writes a fault is about; the deployment, the waits and the repointing around a fault are `conformance`'s (`fault-scene`).

## Responsibilities
- Gives the code flow with token exchange on the Redis store, one client that redeems a code and exchanges the access token it was given, and two users, with what a scene adds; runs a scene on a deployment of its own on that scene unless it names another.
- Gives a user's access token from a code of her login at an instance, and exchanges a token there as the subject token.
- Gives Apple's host as the app reaches it (`test/apple.ts`): a front answering Apple's key set under a certificate of its own, and a tunnel to it alone, for the app's outbound and its trusted certificates; the scene with the client taking Apple's id_tokens by both grants and alice linked at Apple; id_tokens Apple signs for her, exchanged or sent as JWT bearer assertions.
- Names, in `test/wire.ts` alone, a subject's revocation boundary's writes in `subject-revocation-store.boundaries`, the one that creates it and the boundaries each puts, a follower's first write, session-lifecycle adding to its closings in `session-store.closings`, and an id_token's take in `exchange-id-tokens-store.used`.

## Offers
- `faultScene` (with the exchange part a scene gives), `on` (`conformance`'s, on `faultScene` unless it names another), `postAt`, `accessAt`, `exchangeAt`, `said`, and the scene's `issuer`, `exchangeGrant`, client `app` and `users`.
- From `test/apple.ts`: `startApple`, `appleScene`, `idToken`, `exchangedAt`, `assertedAt`.
- From `test/wire.ts`: `boundaryOf`, `boundaryCreated`, `boundariesPut`, `closingAdded`, `takenOf` and the deployment's `prefix`.

## Invariants
- The store's own names (spaces, partitions, operations) are written in `test/wire.ts` alone, never in a scene's file.
- Apple's issuer and key set are never changed for a scene: the app reaches Apple's own host, through the tunnel to the front.

## Depends on
- The package's area; `conformance-code` (the code flow's scene and browser); `conformance` (the fault scene's deployment, the relay and store-wire); `conformance-front` and `conformance-tunnel` (Apple's host)
