# change-record

Internal module of `guard`: a change record's machine rows, what two commits of the workspace differ in.

## Responsibilities
- Reads each commit in a worktree of its own, installed with no script run, then removed: each unit's files, each package's export signatures, the dependency edges, every budget measure.
- Writes what differs, as Markdown: the commits and their trees, the units added, removed, moved and changed, the contract's changes, the edges added and removed, and each measure that moved.

## Not here
- What the rows are for, and the rows written by hand (the owner's confirmation, the reruns of the checks, the design review): the private ledger's record, which the output names.
- A signature's text: `guard-imports`' surface. The measures: the internal module `budget`.

## Offers
- `readingOf` (packages, budget, commit and tree → `Reading`), `changesOf` (two readings → what differs), `changeRecordOf` (two readings → the Markdown).
- The script `change-record <base> <head>`, any revisions git resolves to commits.

## Invariants
- A contract change is an export's: added, removed, changed (its signature differs, a member's type or a member put in another's place with the count kept), renamed (gone, and another name with its signature comes in its package) or moved (gone, and its name with its signature comes in another package).
- A unit is moved where it is the one gone and another the one come with the same last part of its place, else added and removed; changed where its files or their content differ.
- An edge is a manifest's: `dependencies` and `peerDependencies` at run time, `devDependencies` for tests, to workspace packages.
- A commit is measured on its own budget numbers, or on the current ones where it has none.
- Nothing is kept: a worktree is removed however its reading ends.

## Depends on
- `guard-imports` (the workspace as read, the surfaces), and git and pnpm, run.
