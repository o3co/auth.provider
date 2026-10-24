# api-docs

## Responsibilities
- Builds a release's API site from the shipped bundles, as an app installs them: one module per member's contract, named and imported by its public name.
- Keeps every minor's API in one dir of the site, and the site's root and list of releases.

## Not here
- Forming and naming the bundles, and what each ships (`distribution`). Publishing the site to the repository's pages (the release workflow).

## Offers
- `pnpm api-docs link <bundles> <project>`: the bundles built here (`pnpm bundles`) at their public names in a project, and each outside package their manifests name, from a workspace member that holds it; for a check before a release.
- `pnpm api-docs build <project> <site> <version>`: the API of the bundles a project holds, into the version's minor's dir of the site, then the site's root and `versions.html`.

## Invariants
- An entry is a shipped bundle's member's `.` export (`<bundle>/<member>`); its `testing`, `module` and `audit-events`, an unshipped bundle, and a package exporting none are not read.
- It reads only the published form of the bundles, so no workspace name (`@mod/*`) is an entry or an import.
- A minor's dir is `v<major>.<minor>`, which each of its patches writes over; a version that is not a release (a prerelease among them) is refused.
- The root points at the newest minor by number, and `versions.html` lists every minor newest first; other dirs of the site are left as they are.
- A conversion or a write the documentation tool reports an error in fails the build.

## Depends on
- `typedoc` (the documentation tool), `typescript` (the version the workspace compiles with); no workspace package.
