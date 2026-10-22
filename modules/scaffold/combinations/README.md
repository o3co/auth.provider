# combinations

## Responsibilities
- Completes a list of modules with what comes with them by default: each feature's wirings, and the bridges whose modules are all composed.
- Composes a selection, and the full template, from what the packages need to run and the axes their adapters declare.
- Reads all of it from the package.json of each package the workspace definition lists or, built into a bundle, from the index at the bundle's root (those manifests as written); adding a wiring, a bridge or an adapter needs no change here.
- Composes, beside those, packages declared outside the workspace, each a module, once what each declares and the graph of all of them are checked.

## Not here
- Whether a composition boots: the kernel's refusals.
- The kinds' words and which way a dependency between them may point: `kinds`. The checks on what each kind depends on: `guard`.
- Generating an app, and reading an outside package into what it declares: `create-app`.
- Running scenes: the conformance areas.
- Checking that each feature declaring `storeWiring` has a wiring: `guard`.

## Offers
- `completed`: the modules given, each owner whose declared default replaces it swapped for that default and each adapter's owner counted for bridges, then the wirings and bridges they come with, including those of what is brought in, each once, in the order first named.
- `composed` (features in named groups, an adapter or the owner by axis owner, modules added): the selection, what it needs to run (a foundation or feature among its dependencies, in turn), each composed axis's chosen adapter or default, then `completed`.
- `composed` refuses, naming each: a name the workspace lacks, a group value that is not a feature, an addition that is not a feature or adapter with a module, an axis key that owns no axis, an axis value that is neither its adapter nor its owner, and an owner chosen for its own axis that has no module.
- `needed` (modules): the modules given, what they need to run, then `completed`, as `composed` reaches them but with no axis default other than one declared to replace its owner; owners a reached adapter replaces are left out. It refuses, naming each, a name the workspace lacks, as `composed` does.
- `full` (modules added): every foundation and feature with a module that does not opt in, composed alike. `optIns`: the features that opt in.
- `addable`: the names a selection or the full template may add (a feature or an adapter, with a module), in code point order; `composed` and `full` refuse any other.
- `published` (modules): built into a bundle, each name given as published, in the order given: `{ name, package, entry }`, the bundle to depend on and the path its entries import under (a module at `<entry>/module`), read from the index's entries. It refuses, naming each, a name no bundle publishes; in the workspace, where nothing is published, it refuses every name.
- `combinationsWith` (declarations: name, kind, needs, and as its kind takes them optIn, replaces or adapts, default, wires, joins): the offers above, over the workspace and those beside it.
- `combinationsWith` refuses, naming each declaration: a name declared already, a kind no package beside the workspace may be (a feature, an adapter or a wiring may), a field its kind does not take, a need not declared or against `mayNeed` or on what declares forWiring, an adapter without one of replaces and adapts, a wiring of no outside feature.
- `combinationsWith` refuses too, over all packages: a name replaced, adapted, joined or wired that is not declared, an axis with several defaults or several adapters and no default, a cycle of needs and joins; a need on what is not declared (an npm package) is no edge.

## Invariants
- A wiring names the feature it `wires`; it comes with the feature, whether given or brought in.
- A bridge names the modules it `joins`, a non-empty list of names; it comes once every one of them is composed, whether given or brought in. An axis owner reached counts, with a module or not.
- A `joins` that is not a non-empty list of names, or a `wires` that is not a name, is refused, naming each such package.
- A dependency a manifest names in `helpers` (functions and types alone) or `optional` (contracts used only where something contributes, which brings it) is not needed to run; either, when not a non-empty list of its dependencies, is refused, naming each package.
- Wirings of one feature, and bridges, come in code point order of name.
- An axis is its owner's: an adapter `replaces` the owner (composed instead of its module) or `adapts` it (beside it). Its default is the one adapter declaring `default`, or its only one.
- An axis's default comes only where its owner is composed (reached among what runs, with a module or not, as the kernel), and not where another adapter of that axis is already composed. A default declared to replace its owner comes wherever that owner would, whether the owner has a module or not, so the owner's module is never composed beside it.
- A feature that opts in comes in `full` only where something composed needs it to run.
- An axis's only adapter in the workspace stays its default beside an adapter declared outside; an outside adapter declares no default of an axis the workspace owns.
- Every name it gives is a module of the workspace, as it reads them there; `published` alone turns one into what an app outside the workspace depends on and imports.

## Data
- The workspace's declarations, and in a bundle the index's published names, each read once per process; nothing is written.

## Depends on
- `pnpm` (asks it for the packages the workspace definition lists); `kinds` (the kinds' words, and `mayNeed` for a declaration's needs).

## Vocabulary
- axis: an owner's adapters to outside systems; default: the adapter composed unless another is chosen.
- wiring: the module that ties a feature's store interfaces to an implementation.
- bridge: a module that comes once every module it joins is composed: one module it adds to (`metrics` to `http`), or several it ties together (`session-tokens`).
