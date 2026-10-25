# release-sbom

Internal module of `distribution`: the release's lists of what it ships (SBOMs), made from the tarballs it publishes.

## Responsibilities
- Makes, before anything is published, CycloneDX lists of the operator's app, of the entrance, of the packages bundles hold inside, of the tools that build the release, and of the reference image; checks that they hold every tarball the release packed.

## Not here
- Listing a dependency tree or an image: the tools pinned in `sbom.json` (`pnpm sbom`, by the pnpm the workspace names; syft, its image by digest).
- What a bundle holds inside: each package's manifest declares it (`bundledInside`), its own test holding the declaration to the bundle.
- Packing the tarballs and attaching the lists to the release: `release` and the release workflow.

## Offers
- `pnpm release:sbom <tarballs> <dir>` (Docker running): writes into `dir` `app.cdx.json` and `entrance.cdx.json` with their locks, `inside.cdx.json`, `build-tools.cdx.json`, `image.cdx.json` with `image.json` (its id and syft's), `tarballs.json` and a `README.md` saying what each is. Prints each problem and exits 1.
- `npmNamed`, `coverageProblems` and `insideBom`: the naming and the checks, apart from the tools.

## Invariants
- The app is the full template with every feature that opts in, made by the packed entrance and installed from the tarballs alone, no script run; the entrance is installed alone, as an operator runs it.
- A component of a package this release packed is named as npm publishes it (purl, reference, distribution URL), its hash kept; one not named by the path of a tarball the release packed stops the release, nothing renamed. Every other component is as the tool wrote it.
- Every tarball packed is in the app's list or the entrance's, by its name, version and SHA-512, with a dependency entry.
- A bundled file no manifest declares, one declared in no tarball, and a package held inside that its declaration does not name, stop the release.
- Every development dependency a workspace manifest names is in the build tools' list.
- The image is built from the app's Dockerfile as the release check builds it, and removed, its base stage's too, however its build or listing ends.
- The release workflow is held, by a test reading it, to make the lists after the tarballs are checked against npm and before the draft release, and to attach them to it.

## Depends on
- The package's `release` (the tarballs read) and `release-check` (the install and the image); `combinations` (the features that opt in); pnpm, Docker and tar, run.
