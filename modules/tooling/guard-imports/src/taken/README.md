# taken

Internal module of `guard-imports`: G31, that a contract its owner declares `takenBy` is imported by the packages it names alone.

## Responsibilities
- Reads each manifest's `takenBy` (contract name → the packages that may take it), and holds it to the kernel `takenBy` its contract declares and to every other package's shipped imports.

## Not here
- Which modules a contract binds at boot: the kernel, by the `takenBy` the contract declares.

## Offers
- `takenByRules` (G31).

## Invariants
- A package's module is the name its shipped code gives `defineModule`; a contract's kernel `takenBy` is the list of names written in its exported `contract` call, read from the syntax tree, never run.
- An import is a value import of the contract by its exported name, an alias, a namespace import, `export { … } from` or `export * from`; a type-only import, a test and the owner itself are not counted.

## Depends on
- `typescript`.
