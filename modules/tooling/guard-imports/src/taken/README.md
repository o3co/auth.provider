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
- An import is a value import of the contract by its exported name, an alias, a namespace import, `export { … } from` or `export * from`; a type-only import, a test, the owner itself, and an adapter of the owner importing to provide it are not counted; taking it is refused at assembly (kernel `takenBy`). An adapter handing it on is counted.
- The entries a package keeps are the scope's reading (`takenEntries`), from the manifest alone. G31 reports every other key naming an entry with the scope's reason, and refuses a kept entry whose file exports a type (a type, an interface, a type re-export, `export *` or `export * as`): its types go on `.`.
- An entry is the owner's export of that `./name`; each package named is a workspace package, none asked for a module or a kernel `takenBy`. Every edge that loads the entry counts (an import, a re-export, `import()`, `require`); a type alone does not. A package named does not hand it on.
- G31 sees a kept value handed on only where a shipped file exports a binding as it was imported (directly, renamed or re-bound); a value made from it (a default, a pattern, a field, a return, an expression) is not seen.
- The kernel refuses any module that takes a kept contract; the writer is held by `subject-records`' own test and review.
- The hand-on check is in-repo defence in depth. The guarantees are the kernel's `takenBy` for contracts, and the import binding with `subject-records`' own test for the writer. Shapes beyond the principle above are accepted limits.

## Depends on
- `typescript`.
