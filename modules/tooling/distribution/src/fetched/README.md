# fetched

Internal module of `distribution`: the packages of this version npm already holds, taken from the registry for a release run again.

## Responsibilities
- Asks the registry for each package the release publishes at its version, and takes those it holds as they are, each held to the integrity it gave, so a run after a partial publish publishes what is there and packs only the rest.

## Not here
- Packing the rest and sealing the index over them: `release`. The order the release publishes in: `release`'s pack order.

## Offers
- `fetchPlan` (the pack order's packages, the registry's answers) → those to take, with their integrity, or why not.
- `lookedUp` (packages) → the registry's answers; `takenFromRegistry` (those to take, a directory) → each one's tarball by its directory, or each problem.

## Invariants
- The release publishes the index's bundle after every bundle its index seals over. Where that bundle is on npm and one it seals over is not, it was published out of order and the index cannot be sealed again: it stops, for a person to look.
- An answer the registry gave that cannot be read stops it, never read as not there.
- A tarball taken whose bytes are not of the integrity the registry gave is refused. No script runs as it is taken.

## Depends on
- `release`'s registry answers (`lookupOf`), `packed`; npm, run.
