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

## Invariants
- The release check refuses a tarball without its `LICENSE`.
- The release check boots each app in the image its Dockerfile builds; only the `deps` stage is replaced, by the same `--prod` install from the tarballs in the `base` stage, as the registry has none of them yet.
- Without Docker, the release check exits 1 at once: no boot is skipped.

## Depends on
- The package's build; `create-app` (its patterns), `trial` (the layer each image boots on); pnpm, to pack and install; Docker, to build and run images.
