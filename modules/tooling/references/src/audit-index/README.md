# audit-index

Internal module of `references`: the generated parts of the audit index, the cards and what each package depends on.

## Responsibilities
- Generates `docs/audit/cards.md`: each workspace package by the directory under `modules` it lies in, with its kind and the line its card opens with, and its internal modules (a `README.md` in a directory under `src`, tests' left out) beneath it.
- Generates `docs/audit/dependencies.md`: which directories depend on which, drawn, and each package's kind and the workspace packages its manifest names to run with (`dependencies`, `peerDependencies`).

## Not here
- Reading the workspace, its manifests and cards: `guard-imports`' `readWorkspace`. Holding shipped imports to the manifest and the direction to the kinds' order: the guard's rules.
- The hand-written index that links these, and the scope of an audit: `docs/audit`.

## Offers
- `auditIndexIn` (root) → the packages as the index reads them; `cardsOf`, `dependenciesOf` → each file; `cardsFile`, `dependenciesFile`.
- `cardLine`: the line a card opens with, its first paragraph (an internal module's without its `Internal module of` prefix, its owner nested or not) or else its first responsibility.

## Invariants
- A list here is what manifests and cards say, never a reading of the source; a card naming no line is listed so.
- The workspace root is no package of the index.

## Depends on
- `guard-imports`, to read the workspace.
