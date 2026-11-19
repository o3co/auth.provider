# writer

Internal module of `store`: the subject writer, the one value a change to subjects' data carries.

## Responsibilities
- Holds the subject writer: one frozen value, matched by identity.

## Not here
- The entry that offers it, and who takes it: store's card. Checking it on a batch and taking it off: `checkedStore` (internal module `checks`). Writing a value with it, for tests: the internal module `planting`.
- Passing it: `records`' changes, where the caller gives it.

## Offers
- `subjectWriter`: to other packages on the entry `./subject-writer` alone; within store, to `checks` and `planting`.

## Invariants
- It is no boundary against a deployment's own code, which does not import it.
