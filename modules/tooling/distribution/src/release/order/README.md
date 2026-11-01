# order

Internal module of `release`: in what order the release packs and publishes what `pnpm bundles` built.

## Responsibilities
- Orders the packages the release publishes so the index is sealed over every other bundle before its own bundle is packed, and published after every bundle it seals over.

## Not here
- Packing and sealing: `release`. Taking from the registry what npm holds: `fetched`.

## Offers
- `packOrder` (the directories built, what each bundle manifest declares) → the bundles first (every shipped bundle but the index's), the index's bundle and file, and those last (the index's bundle, then the entrances); or why not.
- `releaseOrder` (the workspace's root) → that order as `dist/bundles` holds it, with each package's name and version.

## Invariants
- The order comes from the declarations, never from what was built: no shipped bundle or more than one declaring the index, one shipped not built, or one built not declared to ship is refused.
- The release publishes in this order, so where the index's bundle is on npm, every bundle it seals over is too.

## Depends on
- The package's bundle manifests, and `dist/bundles`.
