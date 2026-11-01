# faults

Internal module of `conformance-passkey`: what the area's fault scenes share in its words, its scene and the store writes a fault is about; the deployment, the waits and the repointing around a fault are `conformance`'s (`fault-scene`).

## Responsibilities
- Gives passkey login at the token endpoint on the Redis store, for one confidential client allowed no refresh and one user, and runs a scene on a deployment of its own on that scene.
- Registers the user's passkey at an instance with an authenticator that keeps no count, so only the challenge refuses an assertion that comes again; asks request options at an instance and signs an assertion for them, noting when its challenge was asked for; sends an assertion to an instance's token endpoint.
- Names, in `test/wire.ts` alone, the write that takes a challenge, as the relay matches it: its record in `webauthn-store.challenges`, under the name made from the challenge, turned taken; and which commands are store calls.

## Offers
- `faultScene`, `on` (`conformance`'s, on `faultScene`), `registeredAt`, `assertionAt`, `loginAt`, `said`, the challenge's lifetime `challengeLifetimeMs`, the client `app` and `grantType`, and the types `Authenticator`, `Assertion` and `Answer`.
- From `test/wire.ts`: `takeOf`, `isStoreCall` and the deployment's `prefix`.

## Invariants
- The store's own names (spaces, record names and fields, operations, the commands it sends) are written in `test/wire.ts` alone, never in a scene's file.
- The challenge's lifetime is the scene's own value, the longest webauthn allows, not the default, so no scene's challenge ends by its age between its uses.
- A challenge's take is written, and succeeds, on every assertion of a challenge still kept, taken or not; so its successes do not count the challenge's uses.

## Depends on
- The package's area; `conformance-code`, `conformance-identity`, `conformance-keys`, `conformance-oauth` (their parts), `conformance-second-factor`'s browser, `webauthn`'s software authenticator; `conformance` (the fault scene's deployment, the relay and store-wire)
