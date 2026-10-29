# conformance-keys

## Responsibilities
- Owns the conformance scenes of the keys area: publishing the public key set, with no private part of a key and no shared secret in its answers, and boot refusals for key configuration.
- Sets up the keys area's parts (signing key, previous key) on each of the legacy and new targets. On the new target, where `oidc` is composed, a signing key neither RS256 nor HS256 is also written as `oidc.id-token-alg`, as an operator would.

## Not here
- Scene composition and drivers (`conformance`). Starting the legacy system (`conformance-legacy`).

## Offers
- Area `keys` and the shape of its parts (signing key, previous key, unknown configuration)

## Invariants
- The legacy set-up lives only in `src/legacy.ts`.
- Touches only the HTTP interface and boot refusals.
- On the new target the `keys` section holds the scene's keys alone (`whole`), on a pattern's app too; beside it the set-up writes only `oidc.id-token-alg`.

## Depends on
- `conformance`, `conformance-legacy`
