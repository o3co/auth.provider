# lockfile

## Responsibilities
- Holds a pnpm lockfile to what was recorded of the packages outside the release when an app was generated: the version its root depends on, the content, the dependencies declared, and one copy of each package the app's overrides hold.
- Reads that record from a project pnpm installed a package into.
- Is, in one file, the module app-output reads and the script an app runs to check its own lockfile.

## Not here
- Fetching, authenticating, integrity on install and the age of a version: pnpm's.
- Reading a manifest into a record, and writing the record, the script and the overrides into an app: their callers.

## Offers
- `outsideLock.recordOf` (lockfile text, name): the version and integrity the root importer resolves the name to.
  - It refuses a name the importer lacks, a resolution to no version (a link, a file, an alias), and one from no registry.
- `outsideLock.refusals` (lockfile text, records, overrides): why the lockfile is not as recorded; none where it is.
- `outsideLock.script`: the file an app runs beside its `pnpm-lock.yaml`, `outside-modules.json` (`{ modules: records }`) and `pnpm-workspace.yaml` (its `overrides`); it prints each refusal and exits 1 on any.

## Invariants
- Only a lockfile of version 9.0 is read; any other is refused.
- A record's version is the one the root importer resolves, from a registry (its resolution holds an integrity alone), with the recorded integrity.
- A peer range is compared after the app's overrides: pnpm writes an override in a range's place. The range recorded must still hold the override.
- Each dependency the package's snapshot resolves is declared by the record, resolves to a version, and satisfies its range (overrides applied); each declared dependency (not optional) is resolved.
- Each package the overrides name has one version and one resolution in the whole lockfile, and is reached under no other name.
- The file imports nothing of the workspace: `yaml`, `semver` and node only.

## Depends on
- `yaml`, `semver`; nothing in the workspace.

## Vocabulary
- record: a package's name, version, integrity and declared dependencies, as checked at generation.
- held: a package the app's overrides fix to one version (the release's bundles, `zod`).
