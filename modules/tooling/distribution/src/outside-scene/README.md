# outside-scene

## Responsibilities
- Composes a package outside the release as an operator does, beside the packed release, and checks that the app is held to what the release sealed.

## Not here
- Packing the release and sealing its index: `release`.
- Generating the app, recording the packages and checking the lockfile: `create-app` and `app-output`, run as published.

## Offers
- `outsideScene` (the release's tarballs, a scratch directory, the release's version, the workspace's zod and a pattern): what passed, or throws why not.

## Invariants
- The release's tarballs and a package outside it are served by a registry of the check's own, at the `@o3co` and `@x` scopes; each document's integrity is the SHA-512 of the tarball's bytes, and each version was published two days before. Any other name is answered by the upstream registry the scratch directory's pnpm names. An upstream request that fails or takes over 30 seconds (less where its starter says so, as its test does) is answered 502, and the registry stays up for pnpm to retry.
- The registry listens within 30 seconds, or the scene fails; it is stopped and waited for however the scene ends. Each command runs at most 10 minutes.
- The package outside needs a module of the release and takes its bundle and zod as peers, at the release's version and the workspace's zod.
- `create-auth-provider` is installed from the registry, the package outside into a project of its own, and the app is generated from that project by `--outside-from`, then installed by version, never from a file.
- The app's `check:outside` passes. With the lockfile's zod pointed at another package's tarball on zod's registry, with that package's good integrity, it exits 1 for the integrity the release recorded, and for that alone: any other answer fails the scene.

## Depends on
- pnpm, to pack, install and run; `yaml`, to change the lockfile; node's `http`, for the registry; the network, for the upstream registry.
