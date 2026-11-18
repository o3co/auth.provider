# writer

Internal module of `store`: the subject writer, the one value a change to subjects' data carries.

## Responsibilities
- Holds the subject writer's one value, which the entry `./subject-writer` offers and nothing else: the manifest's `takenBy` keeps that entry for `subject-records`. Its type, `SubjectWriter`, is on `.`, which never offers the value.
- `checkedStore` takes it on a batch and a batch across as `writer`, checks it by identity (another value, a copy among them, is a `TypeError`), and hands the store below none of it.

## Not here
- Which spaces need it, and refusing a change without it: `checkedStore`, once store enforces it.
- Passing it: `records`' changes, given it by `subject-records`.

## Offers
- `subjectWriter`, on the entry `./subject-writer` alone.

## Invariants
- It stops a wiring, or a records plain port, of this workspace from writing subjects' data, and stops an accident; it is no boundary against a deployment's own code.
- The entry is published, as `subject-records` loads it at run time; it is no part of store's semver surface for anyone else, changes with `subject-records` in the same release, and a deployment's own code does not import it.
