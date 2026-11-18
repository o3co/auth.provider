# taken

Internal module of `guard-imports`: G31, that a contract or an entry its owner declares `takenBy` is imported by the packages it names alone.

## Responsibilities
- Reads each manifest's `takenBy` (a contract's name, or an entry's `./name`, → the packages that may take it), and holds it to every other package's shipped imports, and a contract's also to the kernel `takenBy` the contract declares.

## Not here
- Which modules a contract binds at boot: the kernel, by the `takenBy` the contract declares. What an entry's value grants at run time: its owner's own check.

## Offers
- `takenByRules` (G31).

## Invariants
- A package's module is the name its shipped code gives `defineModule`; a contract's kernel `takenBy` is the list of names written in its exported `contract` call, read from the syntax tree, never run.
- A contract's declaration names the modules of the kernel `takenBy` the contract declares, no more and no fewer.
- An import is a value import of the contract by its exported name, an alias, a namespace import, `export { … } from` or `export * from`; a type-only import, a test and the owner itself are not counted.
- An entry is the owner's export of that `./name`; each package named is a workspace package, none asked for a module or a kernel `takenBy`. Every edge that loads the entry counts (an import, a re-export, `import()`, `require`); a type alone does not. A package named does not re-export it.

## Depends on
- `typescript`.
