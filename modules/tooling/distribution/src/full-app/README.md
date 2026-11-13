# full-app

Internal module of `distribution`: the app of the release with the most packages, made as an operator makes it.

## Responsibilities
- Installs the packed `create-auth-provider` from the tarballs alone, and makes with it the full template with every feature that opts in.

## Not here
- What the full template composes, and which features opt in: `combinations`. Writing the app: the entrance, `create-app`.
- What is done with the app: its lists (`release-sbom`) and its image's scan (`image-scan`).

## Offers
- `fullApp(byName, scratch)` → the entrance's project and the app, in `scratch`; `installFromTarballs(dir, byName)`, the install a project of the release takes; `entrance`, the entrance's name.

## Invariants
- Nothing is installed but from the tarballs named, and no install script runs.
- Tarballs holding no entrance are refused before anything is installed.

## Depends on
- `release-check` (`overridesFile`); `combinations` (the features that opt in); pnpm, run.
