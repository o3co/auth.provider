# local-registry

## Responsibilities
- A registry of a check's own: serves the tarballs in the directories it is given, each at the publish time the caller gives, and forwards every other name to the upstream (under its path) within a limit.

## Not here
- Which scopes an install asks it for: the caller's `.npmrc` routes them, and it holds no list of scopes.
- What its packages are, and when each should seem published: the caller's.
- Anything a product reads: it is assembly, unpublished.

## Offers
- `localRegistry` (`published`: each directory of tarballs and when its versions were published; the upstream registry; and optionally how long the upstream may take) → its origin and a stop, or throws why it did not start.

## Invariants
- Each package's document holds every version its tarballs hold: the manifest as packed, the tarball's address on the registry, npm's integrity of the tarball's bytes (their SHA-512), and the time its directory was given. The document was created at the earliest of its versions' times and modified at the latest, so pnpm's `minimumReleaseAge` reads each version as the caller set it.
- Any other name is answered as the upstream answers it, under the upstream's path, its address written with or without a trailing slash. An upstream request that fails or takes over 30 seconds (less where its starter says so, as its test does) is answered 502, and the registry stays up for pnpm to retry.
- It runs as a process of its own on loopback, listening within 30 seconds, or its start fails; so does one that exits or cannot be spawned, stopped first. Its stop ends when the process has exited.

## Depends on
- node's `http`, for the registry; `tar`, run, to read a tarball's manifest; the network, for the upstream registry.
