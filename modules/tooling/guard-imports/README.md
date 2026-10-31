# guard-imports

## Responsibilities
- Reads the workspace: its packages and their manifests, what each source file imports, and each package's public surface.
- Checks how packages depend on one another and what they import, each reported by its id, place and what went over:
  - G1, G2: no cycles, and the bottom level of the kinds' order depends on nothing in the workspace.
  - G3: a package exporting `./module` imports no workspace package's `./module` in shipped code (tests may).
  - G4: contract tests (`./testing`) are used only from tests.
  - G8: shipped code imports at run time only what the manifest declares.
  - G34: each file a source names, tests' too, by an import, a re-export, a dynamic import, an import type, `import … = require(…)` or `require`, is a file of its own package, as `facts` resolve it (links followed) and as the scope's owner of the path tells; one reaching another package is a dependency no manifest states. A relative specifier named at run time (a template with a substitution) is refused, being unknowable; a resolve names a file and takes no dependency.
  - G10: kind direction: a lower kind never depends on a higher one, by each manifest's kind; a test dependency may point up to the wiring kind only. No kind, or one `kinds` does not know, is refused.
  - G14: a verification base depends on no product module.
  - G16: a feature depends on no capability, nor on a package declaring `forWiring` (a feature's storage is its wiring's to build on it); its tests may use their `./testing` stand-in. `forWiring` is `true` only.
  - G22: only a wiring-kind package wires (`wires` in its manifest), and a feature that declares `storeWiring` has one.
  - G24: a wiring keys its guarantees by the needs its feature declares: shipped code takes `keyof typeof` a name imported from the feature.
  - G25: an adapter declares exactly one of `replaces` and `adapts`, naming a workspace package; an axis has at most one `default`, and one when it has several adapters; `default` and `optIn` are `true` only, on an adapter and a feature; a wording adapter never `joins` its owner.
  - G28: a dependency a manifest names in `helpers` lends functions and types alone: shipped code takes from it no value the kernel's `contract` or `extensionPoint` makes.
  - G29: a test file composing every module a feature bridge `joins` and a module contributing to the bridge's points composes the bridge too, so no contribution that decides an answer is silently lost.
  - G30: outside the package each `./audit-events` declares through (`audit`), shipped code records an event only through the declared wrapper (`declaredAudit`), never on the contract's own `record`, so every event reaches the audit event reference.
  - G31: a contract a manifest declares `takenBy` (contract name → the packages that may take it) is imported, in shipped code, by those packages alone, by name, alias, namespace or re-export; the declaration names the modules of the kernel `takenBy` the contract declares, no more and no fewer.
  - G32: the property an owner holds to declaration (the narrower's `internal`, which reaches private addresses) is written in shipped code only by the packages declaring it in their manifest and card.

## Not here
- Hostile code: the rules hold our own code to its design, written the ordinary way; a form written to slip past them, a dependency's behaviour, prototype or reflection tricks, custom loaders and file-system races are review's.
- The budget, the documents, the vocabulary and the source's contents (the clock, randomness, branches, the network): `guard`, which runs these rules beside its own.
- The kinds' order and roles: given by the caller, in the kind words it holds.

## Offers
- `readWorkspace` (root → its packages, as pnpm lists them, minus the root), `scopeOf` (packages, rules, where findings go → the scope every rule reads: what a manifest declares apart from what a source is seen to say, each file's `facts` by one lexical program over every package's sources and the files the caller adds (a fork's helper), and the package whose directory holds a path), `surfacesOf` (packages → each one's public surface).
- `importRules` (scope, surfaces): every rule above, reported through the scope; `importViolations` (packages, rules → the findings).
- The readers the other checks build on: `parse`, `packageOf`, `importsOf`, `importedNames`; `budgetsAsTest`, whether a file counts as a test (a published contract test suite does).
- `lexicalAnalysis` and the facts' types (`FileFacts`, `Edge`, …): the `facts` card's; `Kinds`, `Rules`, `Scope`: `scopeOf`'s; `propertyDeclarations`: `owned-property`'s.

## Invariants
- Checks are derived from the repository's current state. Nothing is enumerated, and there is no place to write exceptions.
- The rules read each file's `facts`:
  - G3, G4, G8 and G16 every edge to a package but a resolve. G8 asks a declared run-time dependency of every edge that loads its module, `import { type T }` included (the hint: `import type` loads nothing).
  - G24, G28 and G31 a file's top-level imports and re-exports (G24 the names imported by name, a default so taken too), never one inside a declared module.
  - G29 a test's edges that load its module, a resolve or an import type composing nothing.
  - G34 every edge but a resolve, tests' too.
- A package depends on what its manifest names in `dependencies` and `peerDependencies`, and in `devDependencies` where a rule counts tests (G1, G2, G10, G14, G16 do).
- G29 reads a test file's imports: a `./module` (its own package's by path) is composed, a `./testing` value named `…StandIn` composes its package, and an adapter composes its owner; a stand-in named otherwise, or a composition built elsewhere or at run time, is missed, not reported. A package contributes to a bridge when its shipped code takes one of the bridge's `extensionPoint` values.
- G29 counts feature bridges only: a foundation bridge's points collect operational counts that decide no answer a test reads.
- Internal modules `recorded` (G30), `taken` (G31), `owned-property` (G32), `facts` and `surface`.

## Depends on
- `typescript`, `pnpm` (asks it for the workspace's packages).

## Vocabulary
- scope: the packages, the rules they are read under, and where findings go.
- surface: a package's exported values and types, and the contracts and extension points among them.
