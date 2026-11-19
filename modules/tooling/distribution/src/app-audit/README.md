# app-audit

Internal module of `distribution`: the known vulnerabilities, of any severity, in what an app of the release installs, as an operator installs it on the day, any of them failing the audit.

## Responsibilities
- Makes `full-app`'s app from the tarballs, installs it from them as a project of the release is installed, and runs `pnpm audit` in it from its lowest level (`--audit-level=low`), over the lockfile that install wrote.

## Not here
- Making the app, and its install: `full-app`. Packing the tarballs: `release`, through `pack-published.sh`.
- Knowing what is vulnerable: npm's advisory database, through `pnpm audit`.
- When it runs: ci.yml's `audit` job, daily on the default branch, on every push to develop, main or a release branch, and on a manual run.
- The other checks of what the release ships, which share nothing with it: `release-scan` reports on the release's lists and stops nothing; `image-scan` fails the app's image on a critical or high finding that has a fix, or a Node behind a security release; this audit fails on a finding of any severity in the app's install.
- The workspace's own tools and test runners, which no app installs: Dependabot alone keeps them current. Neither this audit nor `image-scan`'s Trivy sees them.

## Offers
- `pnpm app:audit <tarballs>`: prints `pnpm audit`'s report. Exits 0 only where the audit ran and found nothing.

## Invariants
- A finding of any level fails it, with a fix or without: nothing is excluded, so a finding with no fix holds the audit until someone decides on it.
- An app that could not be made or installed, or an audit that did not run, fails; never as clean.
- The app is made in a directory of its own, removed however the audit ends.

## Depends on
- `full-app` (`fullApp`, `installFromTarballs`), `release` (`packedOf`); pnpm, run; npm's registry and its audit endpoint, fetched.
