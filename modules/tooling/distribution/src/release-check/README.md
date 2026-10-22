# release-check

## Responsibilities
- Checks the release as an operator meets it: apps made by the packed `create-auth-provider`, installed from the tarballs, type-checked, and booted in their image; and an app assembled by hand from them.

## Not here
- Building the bundles: the package's.
- Packing and sealing them: `release`.

## Offers
- `pnpm release:check`: packs every bundle and entrance, makes an app of each pattern with the packed `create-auth-provider`, installs it from the tarballs alone, type-checks it, and boots it to `/readyz` or to its refusals, each told. It also assembles an app by hand, as one keeping its own composition root does: `combinations`' full names, made published, installed from the tarballs, each module imported, and assembled to the kernel's refusals. Exits 1 on any problem.

## Invariants
- The release check refuses a tarball without its `LICENSE`.
- The release check boots each app in the image its Dockerfile builds; only the `deps` stage is replaced, by the same `--prod` install from the tarballs in the `base` stage, as the registry has none of them yet.
- Without Docker, the release check exits 1 at once: no boot is skipped.

## Depends on
- The package's build; `create-app` (its patterns), `trial` (the layer each image boots on); pnpm, to pack and install; Docker, to build and run images.
