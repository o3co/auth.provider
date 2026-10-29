# guard

## Responsibilities
- Checks the workspace's invariants, each reported by its id, place and what went over:
  - The import and dependency rules (G1–G4, G8, G10, G14, G16, G22, G24, G25, G28–G32, G34): `guard-imports`', run beside these.
  - G5: a package exports `.`, `./testing`, `./module` and `./audit-events` (its events, as `audit` declares them) only.
  - G6: the bottom level (common, protocol) holds no name another package's contract owns, in its contract or its imports.
  - G7: the budget, measured by the internal module `budget`.
  - G9: types in public signatures are exported.
  - G11: no line numbers in comments and documents.
  - G12: no document points at a file in another directory.
  - G13, G23: the clock and randomness come from `kernel`, in the kinds the configuration lists.
  - G15: wiring neither branches nor loops; `&&`, `||`, `??` and calls that walk a collection with a function, such as `map` or `filter`, count too.
  - G17: a card holds only the current contract; plans, moves and removals in progress, by their phrases as written, go to the plan list outside the repo.
  - G21: no document copies a list of the configuration.
  - G26: product code reaches the network through `outbound`, or as the words its manifest declares let it (the `network` internal module).
  - G27: a package whose declared `network` word reaches a server the deployment provides (`redis`, `smtp`) states what that server must be in a `## Deployment` section of its card (the `network` internal module).
  - G33: a protocol package holds a wire's contract alone: it imports `zod` and its own files alone, reaches only the globals that hold no behaviour of the host, and keeps no state nor runs code as it loads (the `protocol` internal module).
- Measures each package's public surface: its exported values, and the members of its exported interfaces and type aliases.

## Not here
- Lists of names, fixed places, snapshots, lists of exceptions.
- Findings, approvals and past change records: the private ledger's. A change record is written from the two commits each time, and kept by no one here.
- Whether a card's dependency item agrees with the package's dependencies, whether a verification base holds legacy-system names, and whether a card holds only the current contract beyond the phrase match: review judges.
- The map, which review reads as the README of the deepest folder that holds every package: an owner cell made only of lowercase names and separators (`,`, `/`, `and`) lists packages; any other cell is a general phrase.
- A dependency item, which review reads as naming modules with the lowercase names it opens with, before any note in brackets or sentence after a full stop.
- What a module means: the rules read how code is laid out, so a misdesign of sound shape passes. `test/misdesigns.test.ts` here and in `guard-imports` try misdesigns: the rule that stops each, or that the guard does not detect it, beside the evidence another gate gives. Neither the guard nor the kernel decides whether a contract assigns responsibility well (`CONCEPT.md`, "Refuse mistakes mechanically").

## Offers
- The check command.
- `measures` (packages, budget, and the surfaces where the caller read them already → every unit's budget measures, each with its limit, whether past it or not), for a record that compares two states.
- `pnpm --filter @mod/guard run change-record <base> <head>`: a change record's machine rows between two commits, as Markdown on standard output (internal module `change-record`).

## Invariants
- Checks are derived from the repository's current state. Nothing is enumerated, and there is no place to write exceptions.
- A package's sources are its `.ts` files, `.config.ts` ones aside, and its `.mjs` files.
- A document copies a configuration list when one line lays out more consecutive values of a list (nested lists flattened) than the configuration allows, in order, with no word between them but `and`, `or` or `then`.
- Documents are all Markdown in the repository. A target is a link target, or an inline path that is explicitly relative or whose first part is beside the document (any other, `/`-rooted ones too, names a place outside it); it resolves from the document's directory, and is refused if it leaves it or names a missing file with an extension.
- G12 reads no fenced code block: a block's samples show another project's files, not references to this one. G11 and G21 read blocks as any text.

## Data
- The configuration: the budget numbers.
- The kinds' roles (common, protocol, wiring, capability, verification, product, adapter, feature, the wider surface, taking the runtime from `kernel`), in the kind words `kinds` gives; their order and the kinds never depending on a capability are `kinds`'s.
- Nothing is written; the workspace is read on each run.

## Depends on
- `guard-imports` (the workspace as read, the scope, and the import and dependency rules), `typescript`, `kinds` (the kind words, their order, and the capability-blind kinds).

## Vocabulary
- unit: a package, or an internal module apart from it.
- reading scope: a unit's contents plus the cards of what it depends on.
