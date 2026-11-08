# reading

Internal module of `app-output`'s `lockfile`: a pnpm lockfile read as data, and the words of its keys and references.

## Responsibilities
- Reads a lockfile's text as data, refusing what is not pnpm's lockfile as written, and pnpm's workspace settings the same way.
- Says what a lockfile key names, what a reference resolves to, and what a declared range or alias is.
- Lists every reference the lockfile holds, as a check of it reads them.

## Not here
- Holding a lockfile to a record, and what is refused for it: `lockfile`'s.

## Offers
- `lockOf` (lockfile text): the lockfile, or throws why it is not read.
- `workspaceOf` (`pnpm-workspace.yaml`'s text): the settings, or throws why they are not read.
- `own` (a value): its own entries as a map where it is a plain object, none otherwise.
- `bare`, `nameOf`, `targetOf`, `specOf`: a resolution without its peers, the name a key holds, what a reference resolves to (a version, an alias's package, or something local), and a declared range or alias.
- `referencesIn` (the lockfile): each importer's three kinds of dependency, and each snapshot's two, with where each is.

## Invariants
- A lockfile is read as data: pnpm's version 9.0 alone, at most 16 MiB, no anchor's alias resolved, no merge key (`<<`), no unknown tag and no duplicate key; only own keys are read, never inherited ones.
- Workspace settings are read as data the same way, but for the version and the bound.
- It imports nothing of the workspace: `yaml`, `semver` and node only, so `lockfile`'s bundle holds it.

## Depends on
- `yaml`, `semver`.
