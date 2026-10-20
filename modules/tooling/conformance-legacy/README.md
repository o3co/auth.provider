# conformance-legacy

## Responsibilities
- Starts the legacy build for conformance scenes (location, how to start it, configuration file, preparation script).
- Collects the legacy fragments each area returns (environment variables, configuration lines, files, extra packages) and starts with them.
- Where a part asks for packages the standalone build does not load, starts its own composed entry instead: the standalone build's start-up, with those packages appended.
- The composed entry is a combination the legacy system does not ship.
- Where a part names a fake upstream for a type that fixes its hosts in code (GitHub, Google, Apple), the composed entry sends that type's requests to the fake.
- The composed entry puts Google's type, which the standalone build loads, in place of the build's own.

## Not here
- Scene vocabulary, and the legacy configuration per feature (each area's legacy set-up). The scene and driver contracts (`conformance`).

## Offers
- Registration of legacy set-ups (area → fragments, needs that cannot be provided, declared differences)
- Registration of driver `legacy` (registered on import)
- Driver `legacy` runs the build in the legacy directory
- Preparation script (`prepare-legacy`): clones the baseline (`LEGACY_BRANCH`, by default the tag `v0.17.0`, the version the legacy directory is named for) into the legacy directory and builds the standalone build and the packages the composed entry adds
- The preparation script and the composed entry read those packages from one list
- The legacy directory: `LEGACY_DIR` where set, else `auth-provider/legacy-0.17.0` under `$XDG_CACHE_HOME` (`~/.cache` when that is unset or relative), never the OS temp dir

## Invariants
- Legacy knowledge lives only here and in each area's legacy set-up.
- The legacy knowledge here is the defaults for starting the legacy build with no features in any scene (port, configuration name, in-memory store, values that turn features off, empty registrations).
- Area set-ups override the defaults that live here.
- Makes no changes to the legacy build.
- Runs the legacy build only through configuration files and environment variables, and, for extra packages, through the composed entry.
- Keeps the composed entry outside the build.
- The composed entry imports the build's own files and packages as they are.
- Cannot meet the need of reading audit events (`conformance`'s), whatever the scene: the build sends none over HTTP.
- Starts a throwaway Redis for every scene, since the build wires stores on Redis whatever the scene.
- If the scene asks for a store failure, stops the scene's throwaway Redis.

## Depends on
- `conformance`

## Vocabulary
- Fragment: the configuration the legacy system needs for one area part.
