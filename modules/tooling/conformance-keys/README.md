# conformance-keys

## Responsibilities
- Owns the conformance scenes of the keys area: publishing the public key set, with no private part of a key and no shared secret in its answers, and boot refusals for key configuration.
- Sets up the keys area's parts (signing key, previous key) on each of the legacy and new targets.

## Not here
- Scene composition and drivers (`conformance`). Starting the legacy system (`conformance-legacy`).

## Offers
- Area `keys` and the shape of its parts (signing key, previous key, unknown configuration)

## Invariants
- The legacy set-up lives only in `src/legacy.ts`.
- Touches only the HTTP interface and boot refusals.
- On the new target the `keys` section holds the scene's keys alone (`whole`), on a pattern's app too.

## Depends on
- `conformance`, `conformance-legacy`
