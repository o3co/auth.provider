# Audit index

What an audit of a release reads, from its tag. Each entry names a file by its path in the repository, or a release asset by its name, and says what it is for; none of them is copied here.

[The scope](scope.md) says what an audit covers, what lies outside it, where trust is handed over and what flows between the parts. [Findings and fixes](findings.md) says how a finding is kept until it is fixed, and what each fix records.

## Design

- `CONCEPT.md`: what the provider is for, and why it is built as modules composed into an app the operator runs.
- `docs/design.md`: how a package is divided, the kinds of package and the one direction they depend in, and the design decisions.
- `docs/security-model.md`: the guarantees, each with what keeps it and the conformance scenes that test it; the trust assumptions the deployment must meet; how long each revocation takes to reach what it revokes; what each part leaves to the deployment.
- `SECURITY.md`: how to report, what a report covers, what is not a vulnerability, and how a fix is made and published.

## Modules

- [The cards](cards.md) (generated): every package and internal module, by its directory, with the line its card opens with. A card is the `README.md` of the directory named: its responsibilities, what is not its, what it offers, its invariants, its data and what it depends on.
- [The dependencies](dependencies.md) (generated): what each package depends on to run, and which directories depend on which.
- The guard holds the code to the cards' shape and the kinds' direction: `modules/tooling/guard/README.md` names each rule.

## Dependencies from outside

- The release asset `auth-provider-<version>-sbom.tar.gz`: the release's lists of what it ships (CycloneDX), made from the tarballs it published: the operator's app, the entrance, what bundles hold inside, the tools that build the release, and the reference image. Its `README.md` says what each file is.
- `pnpm-lock.yaml`: the workspace's resolved dependencies, the lock of each list's install beside it in the asset.
- The dependency audit: `audit.json` in the release asset `auth-provider-<version>-evidence.tar.gz`.

## Configuration and what reaches the provider

- `docs/configuration.md` (generated): every setting, its type, its bounds and its default.
- `docs/routes.md` (generated): every route the full template with every opt-in serves, with its policies and what keeps other sites' requests out.
- `docs/attack-surface.md` (generated): what reaches the provider and what it reaches out to, the secrets among the settings, and the settings that weaken a guarantee. What no module declares is held in `modules/tooling/references/src/attack-surface/coverage.ts`, each entry with why.
- `docs/audit-events.md` (generated): every audit event a module records.

## Operation

- `docs/runbook.md`: what the deployment must provide before it runs, and how it is run.
- `docs/migration.md`: moving from the earlier system.
- `docs/releasing.md`: how a release is cut, what it checks before it publishes anything, and how a security fix is released.

## What was verified

- The release asset `auth-provider-<version>-evidence.tar.gz`: the CI run that tested the tag's tree, its manifest naming the run and the commit it tested; each test's result, passed or skipped, by the job that ran it; the compliance table of the specifications' checklists, read again for the release; the release run's own checks, and the commands and environment they ran in.
- `docs/compliance` (generated): each specification's checklist, its items' roles and statuses, and each item's tests.

## Security regressions anyone can run

- Each promise in `docs/security-model.md`, under "Promises across modules", names the conformance scenes that test it, by area and scene, and says where no scene tests a part yet.
- An area's scenes run with `pnpm --filter @mod/conformance-<area> run conformance`, one scene with `-t "<scene>"` added; every pattern's app on the areas it composes with `pnpm conformance:patterns`, one pattern with `pnpm conformance:patterns <pattern> <area>`.

## Running the checks

- `CONTRIBUTING.md`: the local checks (`pnpm check`), the tests that need Docker, the conformance scenes and the release check, and where CI runs each.
