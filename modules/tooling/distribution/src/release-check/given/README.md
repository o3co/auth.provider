# given

Internal module of `release-check`: which tarballs the release check holds to.

## Responsibilities
- Names the tarballs the check tests: those in the directory it is given, as the release publishes them, or, given none, those it packs.

## Not here
- Building the bundles and packing them: the package's and `release`. Checking the tarballs: `release-check`.

## Offers
- `tarballsToCheck` (the directory given or none, the pack, the scratch directory) → the directory and its tarballs, or why there are none.
- `packBuilt` (the build, the pack) → the pack `tarballsToCheck` takes: the bundles built, then packed; a build with problems stops it, nothing packed.

## Invariants
- A directory given is read for every `.tgz` in it, sorted; one with none is refused, never read as a release of nothing.
- The bundles are built only where the release is packed: never for tarballs given.

## Depends on
- Nothing beyond Node's own modules.
