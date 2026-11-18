# writer

Internal module of `store`: the subject writer, the one value a change to subjects' data carries.

## Responsibilities
- Holds the subject writer: one frozen value, matched by identity.

## Not here
- The entry that offers it, and who takes it: store's card. Checking it on a batch and taking it off: `checkedStore`.
- Passing it: `records`' changes, where the caller gives it.

## Offers
- `subjectWriter`, on the entry `./subject-writer` alone.

## Invariants
- It is no boundary against a deployment's own code, which does not import it.
