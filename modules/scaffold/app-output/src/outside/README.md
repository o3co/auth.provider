# outside

## Responsibilities
- Gives an app composing packages outside the release what holds them to what was recorded: the record, the script checking the lockfile against it, the pnpm settings that keep one copy of the release and zod, and the check in the image.
- Writes the guide's section and the agents' index's line on those packages.

## Not here
- Reading the packages and recording them: the caller's (create-app's `outside`).
- Checking a lockfile against the record: `lockfile`.
- Writing the files: `app-output`'s `writeDeployment`.

## Offers
- `besideRelease` (the packages outside, as `OutsideModules`, and the app's dependencies, release version and zod): the files, dependencies, scripts, image lines, guide section and index line to add; nothing where there is no package outside.
- `OutsideModules`: the records, the registries they and the release come from, and the names let through though fresh.

## Invariants
- `outside-modules.json` holds the records and the registries; `scripts/check-outside.mjs` is `lockfile`'s file as it ships, run by the app's `check:outside`; it holds what it uses, so the app depends on nothing for it.
- Where the release records the integrity of its bundles and of zod, `outside-modules.json` also holds (`held`) that of every package the overrides hold; one it records none of refuses the output.
- `pnpm-workspace.yaml` overrides every release package the app depends on, or an outside package takes as a peer, to the version the app has (the release's for a peer alone), and zod to the app's.
- It sets `minimumReleaseAge` to a day, excluding the release's packages by name, and each name let through as fresh at its recorded version alone; a name let through but not recorded is refused.
- The image's install stage copies the record and the script and runs `check:outside` after installing.

## Depends on
- `lockfile` (the script and the record's shape), `yaml` (to write the settings); nothing in the workspace.
