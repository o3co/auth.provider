# scope

Internal module of `guard-imports`: the scope every rule reads, and whether a file counts as a test.

## Responsibilities
- Builds the scope (`scopeOf`): the packages and the rules they are read under, where findings go, what a manifest declares apart from what a source is seen to say (the entries a package's `takenBy` names, `takenEntries`; the owner an adapter serves, `ownerServed`; the feature a wiring wires, `wiredFeature`), each file's `facts` by one lexical program over every package's sources and the files the caller adds (a fork's helper), and the package whose directory holds a path.
- Says whether a file counts as a test (`budgetsAsTest`): a file named as a test, and beyond that from the import graph alone, no directory or path deciding it:
  - a file its package's `./testing` reaches and nothing else in the package does: no other export, and no file not named as a test that `./testing` does not reach. A published contract test suite and its internal modules are so read;
  - `./testing` is walked by the imports that load or take types (a value, a type, a dynamic import, a re-export), never by a resolve, which only names a file; the shipped roots by every edge, a resolve too. Either walk fails toward shipped;
  - every other file is shipped, a file `./testing` shares with another export among them;
  - every file of a package is shipped, failing closed, where its shipped files hold an import the graph cannot resolve (for the reasons `facts`' resolve gives) or reach a script of the package that is no source (a `.config.ts`, a `.js`, a shipped root among them), or where its `./testing` is a conditional export; each string target of a conditional export is a shipped root;
  - a file outside the graph (a template, a bundle) is read by its name alone, and never throws;
  - the budgets and the rules on the clock, randomness, network, audit recording and owned properties read `budgetsAsTest`, and so does the rule on importing another package's `./testing` (G4); the other rules on imports between packages (G3, G8, G31) read a file named as a test alone (`isTest`).
- Reads the entries a package's `takenBy` names (`takenEntries`), from the manifest alone: kept where one plain segment (`./name`), none of the standard entries the caller gives (`Rules.standardEntries`, G5's), naming its takers as a non-empty list of names, and exported as one file; each other key with why not.

## Not here
- What each rule holds: the rules, the internal modules `recorded`, `taken` and `owned-property`.
- What a source is seen to say: `facts`.

## Offers
- `scopeOf`, `Scope`, `Kinds`, `Rules`, `TakenEntries`, `budgetsAsTest`.

## Invariants
- A reader of the scope reports nothing: the rule reading it does.

## Depends on
- `facts`, and the workspace's packages as read.
