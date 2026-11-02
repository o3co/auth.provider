# packing

Internal module of `release`: the release packed, the index sealed over every bundle before its own.

## Responsibilities
- Packs every package the release publishes in the release's order, sealing the index with the integrity of the bundles before it, those taken from the registry as they are and those packed alike.

## Not here
- The order: `order`. Taking from the registry what npm holds: `fetched`. Sealing the index's content: `release`'s seal.

## Offers
- `packRelease` (the workspace's root, a directory, the tarballs given by directory) → the tarballs and how many the index is sealed over, or each problem, with pnpm's pack.
- `packWith` (what `dist/bundles` holds, the order, the lockfile, the directory, the tarballs given, a pack) → the same, the pack given.

## Invariants
- A package given is copied in as it is, not packed, and sealed over as it is.
- Where the index's own bundle is given (published already), nothing is sealed again, and each bundle its index seals over must be given too.
- Each pack runs with stdin closed, so no lifecycle script reads it.

## Depends on
- `order`, `release`'s seal, `packed`; pnpm, run.
