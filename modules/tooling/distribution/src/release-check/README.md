# release-check

## Responsibilities
- Checks the release as an operator meets it: apps made by the packed `create-auth-provider`, installed from the tarballs, type-checked, and booted in their image; an app assembled by hand from them; and a package outside the release composed beside them (`outside-scene`).

## Not here
- Building the bundles: the package's.
- Packing and sealing them: `release`, whose packing it uses, so it checks the tarballs the release would publish.

## Offers
- `pnpm release:check [<tarballs>]`: checks the tarballs in the directory named, the very ones the release publishes; named none, builds and packs the release as `release-pack` does, the index sealed, and checks those. It tells each problem and exits 1 on any.
  - Each pattern: an app made with the packed `create-auth-provider`, installed from the tarballs alone, type-checked, and booted to `/readyz` or to its refusals, each told.
  - By hand, as one keeping its own composition root does: `combinations`' full names, made published, installed from the tarballs, each module imported, and assembled to the kernel's refusals.
  - Outside: a package outside the release composed beside it, from a registry of the check's own (`outside-scene`).
  - Helpers: on the `simple-web` image, the resolver's two helper processes run with the root file system read-only, under a process limit and Docker's default seccomp profile, and the image's outbound, run once more in the container, resolves a name through its helpers and reaches the app by it; boot is refused at `outbound.resolution` under the limit the app takes resolving in its own process, measured first; and killing the app's process ends the container, nothing left.

## Invariants
- The release check refuses a tarball without its `LICENSE`.
- The release check boots each app in the image its Dockerfile builds; only the `deps` stage is replaced, by the same `--prod` install from the tarballs in the `base` stage, as the registry has none of them yet. That install runs as the runner's own user, in directories the check made, so what it writes is the runner's to remove.
- Without Docker, the release check exits 1 at once: no boot is skipped.
- The processes a container takes are read from its cgroup (`cgroup`): v2's count, or v1's under its pids controller, only where v2's file is not there; any other failure, Docker's included, is thrown.
- Every docker command, and each container, goes through `containers`: a command within a minute (a build fifteen); the install's container and each boot's run under one deadline (fifteen minutes; three for a boot, a minute of it to be ready or end, failing where it does neither, each look five seconds) and are removed at the end, however the work ends.
- Each launch of the check is a run of its own, named by a random id, so no name or label of an earlier one is ever its own; it sweeps its run's containers by label at its end, a container still there a problem told. What a killed check left is removed by hand while no check runs (`containers`' card).

## Depends on
- The package's build; `create-app` (its patterns), `trial` (the layer each image boots on); pnpm, to pack and install; Docker, to build and run images.
