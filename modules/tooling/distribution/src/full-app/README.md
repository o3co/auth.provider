# full-app

Internal module of `distribution`: the app of the release with the most packages, made as an operator makes it.

## Responsibilities
- Installs the packed `create-auth-provider` from the tarballs alone, and makes with it the full template with every feature that release opts in.

## Not here
- What the full template composes, and which features opt in: `combinations`, the release's own in the tarballs. Writing the app: the entrance, `create-app`.
- What is done with the app: its lists (`release-sbom`) and its image's scan (`image-scan`).

## Offers
- `fullApp(byName, scratch)` → the entrance's project and the app, in `scratch`; `installFromTarballs(dir, byName)`, the install a project of the release takes; `releaseOptIns(project)` → the features that opt in, as the release installed in `project` tells; `entrance`, the entrance's name.

## Invariants
- Nothing is installed but from the tarballs named, and no install script runs.
- The features added are those the tarballs' release opts in, read from the `combinations` of the bundle its entrance depends on, never this workspace's; an entrance depending on other than that bundle alone, or opt-ins that are not a list of names, is refused.
- Tarballs holding no entrance are refused before anything is installed.

## Depends on
- `release-check` (`overridesFile`); an entrance depending on its bundle alone (`distribution`'s card); the release's `combinations` (the features that opt in), run from the tarballs, where it is in the entrance's bundle (both in `scaffold`; moved, the read fails); pnpm and Node, run.
