# release-check

## Responsibilities
- Checks the release as an operator meets it: apps made by the packed `create-auth-provider`, installed from the tarballs, type-checked, and booted in their image; an app assembled by hand from them; and a package outside the release composed beside them (`outside-scene`).

## Not here
- Building the bundles: the package's.
- Packing and sealing them: `release`, whose packing it uses, so it checks the tarballs the release would publish.

## Offers
- `pnpm release:check`: builds and packs the release as `release-pack` does, the index sealed, then checks it; it tells each problem and exits 1 on any.
  - Each pattern: an app made with the packed `create-auth-provider`, installed from the tarballs alone, type-checked, and booted to `/readyz` or to its refusals, each told.
  - By hand, as one keeping its own composition root does: `combinations`' full names, made published, installed from the tarballs, each module imported, and assembled to the kernel's refusals.
  - Outside: a package outside the release composed beside it, from a registry of the check's own (`outside-scene`).
  - Helpers: on the `simple-web` image, the resolver's two helper processes run with the root file system read-only, under a process limit and Docker's default seccomp profile, and the image's outbound, run once more in the container, resolves a name through its helpers and reaches the app by it; boot is refused at `outbound.resolution` under the limit the app takes resolving in its own process, measured first; and killing the app's process ends the container, nothing left.

## Invariants
- The release check refuses a tarball without its `LICENSE`.
- The release check boots each app in the image its Dockerfile builds; only the `deps` stage is replaced, by the same `--prod` install from the tarballs in the `base` stage, as the registry has none of them yet.
- Without Docker, the release check exits 1 at once: no boot is skipped.
- The processes a container takes are read from its cgroup: v2's count, or v1's, under its pids controller.
- Every docker command goes through `docker.ts`, within a deadline (a minute; a build, or an install in a container, fifteen), its client killed past it, so the check fails rather than waits; a booted app's `docker run` is waited on within the boot's own (a minute to be ready, each look five seconds, 30 seconds to end).
- A container is gone only where Docker answers that it is not there: stopping or removing one gone is no failure, and inspecting tells it gone by that answer alone; any other failure of Docker's fails the check. One that does not end within 30 seconds is removed and fails the check, so no boot waits on it for ever.

## Depends on
- The package's build; `create-app` (its patterns), `trial` (the layer each image boots on); pnpm, to pack and install; Docker, to build and run images.
