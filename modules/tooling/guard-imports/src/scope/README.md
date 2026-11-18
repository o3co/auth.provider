# scope

Internal module of `guard-imports`: the scope every rule reads, and whether a file counts as a test.

## Responsibilities
- Builds the scope (`scopeOf`): the packages and the rules they are read under, where findings go, what a manifest declares apart from what a source is seen to say (the entries a package keeps for named takers, `keptEntries`; the owner an adapter serves, `ownerServed`), each file's `facts` by one lexical program over every package's sources and the files the caller adds (a fork's helper), and the package whose directory holds a path.
- Says whether a file counts as a test (`budgetsAsTest`), from the import graph alone, never from a path or a name:
  - a file named as a test, or one its package's `./testing` reaches by any import (a value, a type, a dynamic import, a re-export) and nothing else in the package does: no other export, and no file not named as a test that `./testing` does not reach. A published contract test suite and its internal modules are so read;
  - every other file is shipped, a file `./testing` shares with another export among them;
  - every file of a package is shipped, failing closed, where its shipped files hold an import the graph cannot resolve (for the reasons `facts`' resolve gives), or where its `./testing` is a conditional export; each string target of a conditional export is a shipped root;
  - a file outside the graph (a template, a bundle) is read by its name alone, and never throws.

## Not here
- What each rule holds: the rules, the internal modules `recorded`, `taken` and `owned-property`.
- What a source is seen to say: `facts`.

## Offers
- `scopeOf`, `Scope`, `Kinds`, `Rules`, `budgetsAsTest`.

## Invariants
- A reader of the scope reports nothing: the rule reading it does.

## Depends on
- `facts`, and the workspace's packages as read.
