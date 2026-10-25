# release

## Responsibilities
- Packs the release, the index sealed in between, into the tarballs it publishes.
- Stops the release before anything is published where a package already published at its version is not this run's tarball.

## Not here
- Forming, checking and building the bundles: the package's.
- Publishing: the release workflow's.
- Checking the release as an operator meets it: `release-check`.

## Offers
- `pnpm release:pack <dir>` (after `pnpm bundles`): packs every bundle but the one holding the index, seals the index with their integrity and zod's, then packs the index's bundle and the entrances, into `dir`. Prints each problem and exits 1.
- `pnpm release:published <dir>`: before anything is published, asks the registry for each tarball's name at its version; exits 1, naming each, where one is there with another integrity or its answer cannot be read.

## Invariants
- The index is sealed over every packed bundle but its own: `integrity` names each bundle's npm integrity (the SHA-512 of its tarball's bytes, at the index's `version`), and `zod` the one zod the workspace's lockfile holds, with its integrity.
- A bundle without exactly one tarball, a tarball of another version or of no such bundle, a lockfile without exactly one zod or its sha512 integrity, not exactly one bundle declaring the index, a shipped bundle or entrance not built, or one built that is not declared to ship refuses the pack: what is packed and sealed comes from the declarations, never from what was built.
- A package already published at the release's version, the index's bundle and the entrances among them, must be this run's tarball: any other integrity, an npm error other than E404, an answer that is no JSON or holds no sha512 integrity stops the release before anything is published; E404 alone is not published.

## Depends on
- The package's bundle manifests; `yaml` and `tar`, to seal; `npm view`, to ask the registry; pnpm, to pack.
