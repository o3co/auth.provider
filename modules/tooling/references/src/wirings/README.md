# wirings

Internal module of `references`: the wiring reference, which wiring to compose for the module a boot refusal names.

## Responsibilities
- Generates `docs/wirings.md`: for each package a wiring's `wires` names, by the name its module is refused by, every wiring that wires it, so an operator reading `refused <module>: no module provides <contract>` finds what to compose.

## Not here
- Reading the workspace, its manifests and cards: `guard-imports`' `readWorkspace`. That every feature declaring `storeWiring` has a wiring, and that only a wiring wires: the guard's G22.
- The refusal itself: `kernel`, unchanged.

## Offers
- `wiringsIn` (the packages) → a row per package wired, its wirings together; `wiringsOf` → the file; `wiringsFile`.

## Invariants
- A row is what the wirings' manifests say (`kind` `wiring`, `wires`), never a reading of the source; a row is keyed by the wired package's name without its scope.
- Held by a test: the committed file is what the manifests give; each row names a workspace package, whose module's definition gives the very name the row is keyed by, the name a refusal prints.

## Depends on
- `guard-imports`, to read the workspace.
