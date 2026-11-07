# outside-scene

## Responsibilities
- Composes a package outside the release as an operator does, beside the packed release, and checks that the app is held to what the release sealed.

## Not here
- Packing the release and sealing its index: `release`.
- Generating the app, recording the packages and checking the lockfile: `create-app` and `app-output`, run as published.

## Offers
- `outsideScene` (the release's tarballs, a scratch directory, the release's version, the workspace's zod and a pattern): what passed, or throws why not.

## Invariants
- The release's tarballs and a package outside it are served by `registry`, its projects asking it for the `@o3co` and `@x` scopes, over the upstream registry the scratch directory's pnpm names. A registry that does not start fails the scene; it is stopped and waited for however the scene ends. Each command runs at most 10 minutes.
- The package outside needs a module of the release and takes its bundle and zod as peers, at the release's version and the workspace's zod.
- `create-auth-provider` is installed from the registry, the package outside into a project of its own, and the app is generated from that project by `--outside-from`, then installed by version, never from a file, through the `.npmrc` it was given, in the order its guide says: the lockfile, the check, the install with `--ignore-scripts`.
- The app's `scripts/check-outside.mjs`, run with node, passes. With the lockfile's zod pointed at another package's tarball on zod's registry, with that package's good integrity, it exits 1 for the integrity the release recorded, and for that alone: any other answer fails the scene.

## Depends on
- `registry`, to serve the packages; pnpm, to pack, install and run; `yaml`, to change the lockfile; the network, for the upstream registry.
