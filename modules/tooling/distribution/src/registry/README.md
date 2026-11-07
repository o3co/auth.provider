# registry

Internal module of `distribution`: the packed release served as a registry.

## Responsibilities
- Serves the packed release, and packages outside it, from a registry of a check's own, as an operator first meets the release; any other name from the upstream registry.

## Not here
- Which scopes an install asks it for: the caller's `.npmrc` routes them, and it holds no list of scopes.
- Packing the release: `release`. Composing a package outside it: `outside-scene`.

## Offers
- `packedRegistry` (the directory of the release's tarballs, the directories of packages outside it, the upstream registry, and optionally how long the upstream may take) → its origin and a stop, or throws why it did not start.

## Invariants
- Each package's document holds every version its tarballs hold: the manifest as packed, the tarball's address on the registry, and npm's integrity of the tarball's bytes (their SHA-512).
- The release's versions were published as the registry started, as they are when a release is first installed, so an app's `minimumReleaseAge` applies to them; those outside it, two days before.
- Any other name is answered as the upstream answers it, under the upstream's path, its address written with or without a trailing slash. An upstream request that fails or takes over 30 seconds (less where its starter says so, as its test does) is answered 502, and the registry stays up for pnpm to retry.
- It runs as a process of its own on loopback, listening within 30 seconds, or its start fails; so does one that exits or cannot be spawned, stopped first. Its stop ends when the process has exited.

## Depends on
- node's `http`, for the registry; `tar`, run, to read a tarball's manifest.
