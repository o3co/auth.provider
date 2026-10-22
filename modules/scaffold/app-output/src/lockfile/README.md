# lockfile

## Responsibilities
- Holds a pnpm lockfile to what was recorded of the packages outside the release when an app was generated: the version its root depends on, the content, the dependencies declared, and one copy of each package the app's overrides hold.
- Reads that record from a project pnpm installed a package into.
- Is, in one file, the module app-output reads; its bundle, holding what it uses, is the script an app runs to check its own lockfile.

## Not here
- Fetching, authenticating, integrity on install and the age of a version: pnpm's.
- Reading a manifest into a record, and writing the record, the script and the overrides into an app: their callers.

## Offers
- `outsideLock.recordOf` (lockfile text, name, registries): the version and integrity the root importer resolves the name to.
  - It refuses a name the importer lacks, a resolution to no version (a link, a file, an alias), and one from no registry.
- `outsideLock.refusals` (lockfile text, records, overrides, registries: the default origin and each scope's, and where recorded the integrity of each package held): why the lockfile is not as recorded; none where it is.
- `outsideLock.script`: the file an app runs beside its `pnpm-lock.yaml`, `outside-modules.json` (`{ modules: records, registries }`) and `pnpm-workspace.yaml` (its `overrides`); it prints each refusal, or why a file cannot be read, and exits 1 on any. It is `check-outside.mjs` bundled with `yaml` and `semver` inside (`pnpm check-outside` makes it, in development), so it loads nothing of the install it checks.

## Invariants
- A lockfile is read as data: pnpm's version 9.0 alone, at most 16 MiB, no anchor's alias resolved, no unknown tag and no duplicate key; only own keys are read, never inherited ones.
- From a registry means an integrity, and at most the address of a tarball at the origin of the package's registry (its scope's, else the default), under any path; another origin, a directory, a repository or a local file is not.
- The app's lockfile was resolved with the app's overrides (pnpm writes them into it).
- A record's version is the one the root importer depends on exactly and resolves, from a registry, with the recorded integrity; no other version of it is in the lockfile.
- A peer range is compared after the app's overrides: pnpm writes an override in a range's place. The range recorded must still hold the override.
- Every resolution of a recorded package (not the root's alone) resolves each required dependency and peer as required, and each optional one as optional; an optional declaration takes the place of a required one of its name. Each resolves to a version in its range, the overrides applied, or, declared as an alias, to a version of the package the alias names; nothing undeclared is resolved.
- A package the overrides hold resolves, wherever it is referenced (by an importer's dependencies of any kind or by a resolution), to the held version from its registry under its own name, and to a resolution the lockfile holds, with the package's entry; the lockfile holds no other version, and one resolution, of it.
- Where the integrity the release recorded of each package the overrides hold is given (`held` in `outside-modules.json`), each one's entry at its held version (the package, not a resolution with peers) holds that integrity, and each held package has one recorded.
- Where it is not given, a held package is bound to its registry's origin alone: its integrity, what the package is, is not held, so a lockfile changed to another package's tarball on the same registry is not refused. A later change records and checks it.
- The file imports nothing of the workspace: `yaml`, `semver` and node only. Its bundle requires node's builtins alone, and a test holds it to what the file bundles to.

## Depends on
- `yaml`, `semver`; `rolldown`, to bundle them into the script; nothing in the workspace.

## Vocabulary
- record: a package's name, version, integrity and declared dependencies, as checked at generation.
- held: a package the app's overrides fix to one version (the release's bundles, `zod`).
