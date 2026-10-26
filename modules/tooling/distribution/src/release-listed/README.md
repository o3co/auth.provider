# release-listed

Internal module of `distribution`: where the release publishes, the tarballs held to those its lists of what it ships were made of.

## Responsibilities
- Before anything is published, in the job that publishes, refuses a tarball that is not one the lists (`release-sbom`'s) were made of, so what is published is what they cover.

## Not here
- Making the lists, and their `tarballs.json`: `release-sbom`. Reading a tarball: `packed`.

## Offers
- `pnpm release:listed <tarballs> <tarballs.json>`: prints each problem and exits 1.
- `listedProblems` (the tarballs, the listed) and `orderProblems` (the order the release publishes in, the tarballs' files) → each problem.

## Invariants
- Each name and version is one tarball, in the file npm packs it as (where the publish step finds the entrance), in the file the lists name, of the bytes they were made of; none unlisted, none listed missing.
- The order beside the tarballs (`publish-order.json`) names each of them once, and nothing else.
- It loads Node's own modules and the package's files alone, as it runs where the release publishes.

## Depends on
- `packed`.
