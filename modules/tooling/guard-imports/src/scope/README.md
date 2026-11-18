# scope

Internal module of `guard-imports`: the scope every rule reads, and whether a file counts as a test.

## Responsibilities
- Builds the scope (`scopeOf`): the packages and the rules they are read under, where findings go, what a manifest declares apart from what a source is seen to say (the entries a package keeps for named takers, `keptEntries`; the owner an adapter serves, `ownerServed`), each file's `facts` by one lexical program over every package's sources and the files the caller adds (a fork's helper), and the package whose directory holds a path.
- Says whether a file counts as a test (`budgetsAsTest`): a published contract test suite does.

## Not here
- What each rule holds: the rules, the internal modules `recorded`, `taken` and `owned-property`.
- What a source is seen to say: `facts`.

## Offers
- `scopeOf`, `Scope`, `Kinds`, `Rules`, `budgetsAsTest`.

## Invariants
- A reader of the scope reports nothing: the rule reading it does.

## Depends on
- `facts`, and the workspace's packages as read.
