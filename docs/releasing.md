# Releasing

How a maintainer cuts a release. The release workflow (`release.yml`) does the building and publishing once a tag is pushed; this guide covers what comes before the tag and after it.

## Contents

- [What a version promises](#what-a-version-promises)
- [What a release publishes](#what-a-release-publishes)
- [Before the tag](#before-the-tag)
- [Tagging](#tagging)
- [What the workflow does](#what-the-workflow-does)
- [A package name never published before](#a-package-name-never-published-before)
- [When a publish stops partway](#when-a-publish-stops-partway)
- [When the release finds no evidence](#when-the-release-finds-no-evidence)
- [A security release](#a-security-release)
- [The API site](#the-api-site)
- [After the release](#after-the-release)

## What a version promises

This section is the compatibility policy: what semver covers, how a change to it is announced, and what an operator must act on. The repository's security policy (`SECURITY.md`) says which versions get security fixes.

### The surfaces semver covers

A change that breaks one of these is a major version after 1.0, and a minor version before 1.0 (where a release candidate may break one too):

1. **HTTP**: the routes, their methods and parameters, and their answers (status, error code, body members), as [the route reference](routes.md) lists them.
2. **Configuration**: each setting's key, type, bounds and default, as [the configuration reference](configuration.md) lists them. A value refused at boot that was accepted before is a break.
3. **Module contracts**: what each package exports at `.` and `./module`, the names of the modules an app composes, and the contract tests a package offers (`*Contract`) for implementations of its contracts. The rest of `./testing` (fakes, configuration builders) is offered as is.
4. **Audit events**: each kind and its attributes, as [the audit event reference](audit-events.md) lists them.
5. **Metrics**: each metric's name, type and labels.
6. **Data at rest**: a version reads what the version before it wrote to the store, so an upgrade needs no migration of stored records. How a record's format changes is decided in 0.20; until then, a minor version that changes a record's format says so with an upgrade notice.
7. **Log events**: each event's name (such as `kernel.stop_failed`), as operators alert on it; not its fields or the wording of a message.

Not covered: internal modules and anything a package does not export, the wording of error descriptions and log messages, `./testing` but for its contract tests, behaviour no card or reference states, the conformance and tooling packages, and a feature marked preview on its card.

### Deprecation

A covered surface is removed or changed incompatibly only after it was deprecated:

- The release that deprecates it says so in the changelog's **Deprecated** section, on the owning module's card, and in the migration guide, with what to use instead.
- It stays as it was for at least two minor versions or three months after that release, whichever is longer, and is removed no earlier than in the release that ends that notice.
- A security fix may shorten the notice where keeping the surface would keep the hole; the changelog says why.

This notice holds for what is deprecated from 0.19 on; what 0.19 itself removes or changes without a deprecation is announced by its [upgrade notices](#upgrade-notices).

### Preview features

A feature that follows an Internet-Draft is preview until the draft is published as an RFC:

- Adopting one is the maintainers' decision, recorded in the changelog line that brings it.
- Its card says it is preview and names the one draft revision it follows (`draft-ietf-oauth-…-04`); a feature follows one revision at a time.
- A later revision may change it in a minor version. A change an operator must act on still carries an upgrade notice, and so does a change to a value other implementations rely on, such as a media type or a metadata name.
- Once the RFC is published and the feature is checked against it, the feature leaves preview in a minor version whose changelog says so; from then on, semver covers it.

### Attack surface

What an outside party can reach, and what the provider reaches out to, grows only on purpose:

- A new route, setting, outbound call or place a secret is kept opens only where the operator asks for it: by composing the module that brings it, or by writing the setting. A new default that opens one in a module already composed counts as opening it, and so needs the maintainers' agreement, as one that is on with no setting does.
- What opens is declared: a route's marks and its reasons, which `http` checks at boot ([the route reference](routes.md)); a setting that weakens a guarantee is named `accept-*` and warns at each boot, or is named among the declared exceptions in [the security model](security-model.md).
- What nothing uses any more is removed through [Deprecation](#deprecation).

### Upgrade notices

Each change an operator must act on to upgrade carries a numbered notice, `U-<minor>-<n>` numbered within the minor version that brings the change (`U-0.19-3`), at its line in the changelog and at its entry in [the migration guide](migration.md). A notice states what to change, and how to tell whether a deployment is affected. An operator checks off the notices between the version they run and the one they move to; a release with none says so.

In the migration guide, a notice is an item that starts with its anchor and bold id (`<a id="u-0.19-3"></a>**U-0.19-3. …**`), says what to change, and ends with an **Affected:** line; the minor's section opens with a table of its notices (notice, what to do, affected). The changelog line links to it (`docs/migration.md#u-0.19-3`). Once a release, a release candidate included, carries a notice, its number stays: a later notice takes the next number.

## What a release publishes

One package per concern, `@o3co/auth-provider-<concern>`, and the entrance `@o3co/create-auth-provider`, all at the version the root `package.json` states. A version with a prerelease part (`0.18.0-rc.2`) is published under the npm `next` tag and marked a prerelease on GitHub; any other under `latest`.

## Before the tag

1. **The changelog.** The version's section in `CHANGELOG.md` is complete, and its `Unreleased` becomes the date.
2. **The migration guide.** Every change an operator must act on has its line in [the migration guide](migration.md), with its numbered upgrade notice ([What a version promises](#upgrade-notices)); a deprecation also has its line in the changelog's **Deprecated** section.
3. **Preview features.** For each feature a card marks preview, look for a newer revision of the draft it follows. Where one changes the rules the feature applies, open an issue for the next minor version ([Preview features](#preview-features)).
4. **The release notes.** The release's notes are the version's section of `CHANGELOG.md`, as committed (`pnpm release:notes`), and a version with no dated section, or an empty one, stops the release. Read the section as the notes: a security fix's line names the kind of hole it closes and the module, never how to reach it.
5. **The attack surface.** Read the diff of [the attack surface reference](attack-surface.md) since the last tag: each route, outbound reach, secret or weakening setting it adds was meant to open, and is declared as [What a version promises](#what-a-version-promises) asks.
6. **The version.** One commit changes the root `package.json` version, by itself; on the release branch it is the last commit (step 7).
7. **To `main`.** Stop merging into `develop`. Cut a branch `release/<version>` from `main`, named for the version as the tag will write it (`release/0.19.1` for `v0.19.1`). On it, commit `develop`'s tree one package at a time, in the order of their dependencies, each commit holding one package's whole change since the last release, its subject that change in the form the contributing guide (`CONTRIBUTING.md`, its Commits) gives and its body the numbers of the pull requests into `develop` that made it; then the repository's root files and the generated documents; the version's commit last, by itself. The branch's tree is then `develop`'s, and a commit before the last need not build alone. CI on its push runs the conformance scenes, `pnpm release:check` and the compliance job in its release mode, restoring no cache; wait for them all. Then a pull request from it to `main`, merged with a merge commit, with nothing pushed to the branch since its CI ran. Tag within 30 days of that run: the release keeps that run's evidence, and its artifacts are kept 30 days.

## Tagging

Tag the merge commit on `main` as `v<version>` and push the tag. Only those the repository's tag rules allow may create, move or delete a `v*` tag, and tagging is what makes a commit a release: check that the merge commit's tree, `.github/workflows/ci.yml` included, is the one that was reviewed. Before it builds anything, the workflow refuses a tag that does not name the root `package.json` version, one that is not a merge of the release branch into `main` with the branch's tree, and one whose release branch head no successful CI run of its push tested.

## What the workflow does

It runs in four jobs before the API site's. `evidence` reads the CI runs, and nothing else. `pack` runs the checks and packs, and `sbom` makes the lists; both run what the release packed, and read alone. `publish` alone holds what publishing takes (its OIDC token and writing the release), and runs nothing the release packed. The API site's own two jobs build it where nothing can write, then push it in a job that runs none of the build's code.

1. Fetches CI's runs of the push of the release branch's head the tag's commit merged, with the run's token and before anything is installed (`pnpm release:evidence-fetch`); then, holding no credential, judges them and keeps the evidence of the run that tested the tag's tree: each test's result and the compliance table (`pnpm release:evidence-judge`). It stops the release where none will do; see [When the release finds no evidence](#when-the-release-finds-no-evidence).
2. Runs `pnpm check`.
3. Packs every package (`pnpm release:pack --from-registry`): every bundle but the scaffold, then the scaffold's index sealed with their integrity and zod's, then the scaffold and the entrance; a package an earlier attempt published is taken from the registry instead, of the integrity npm gave it. Writes beside them the order the release publishes them in. Refuses any tarball without the root `LICENSE` word for word, Runs `pnpm release:check` on those very tarballs, the ones it will publish: every pattern generated from them alone, type-checked and booted, and a package outside the release composed beside them, its app held to the integrity the release sealed. Then saves them to the run, with that order, and hands each artifact to the jobs after it by its id.
4. Makes the release's lists of what it ships (`pnpm release:sbom`), CycloneDX 1.6, from those very tarballs: the operator's app (the full template with every feature that opts in) and the entrance, each installed from them with its lock; the packages bundles hold inside, as the manifests declare them; the tools that build the release; and the reference image built from the app's Dockerfile, listed by syft. Each list names the release's own packages as npm publishes them, with their tarballs' SHA-512; a tarball no list holds, or a bundled file undeclared, stops the release.
5. Checks that npm can publish through trusted publishing (11.5.1 or later).
6. Holds the tarballs it is about to publish to those the lists were made of, by name, version, integrity and file, and the order beside them to the tarballs (`pnpm release:listed`).
7. Refuses to go on where a package of this version is on npm already as another tarball, or npm's answer cannot be read (`pnpm release:published`).
8. Creates a draft GitHub release with the version's section of the changelog as its notes, and attaches the lists as `auth-provider-<version>-sbom.tar.gz` (its `README.md` says what each file is) and the evidence as `auth-provider-<version>-evidence.tar.gz`: the CI run's artifacts with a manifest naming the run and the commit it tested (of the tag's tree), this run's own `pnpm check` results, `pnpm audit --json`, and the commands and environment they ran in.
9. Publishes each tarball with provenance, in the order the pack wrote: the bundles the index seals over, then the scaffold, then the entrance, which depends on the others. Each is authenticated by the run's own token, through the package's trusted publisher; no npm token is stored.
10. Publishes the draft release.
11. For a final release (never a prerelease), builds its API from the bundles it published, installed from npm, into the minor's dir of the API site on GitHub Pages (`v<major>.<minor>/`, each patch writing over it), and points the site's root at the newest minor. The **API site** workflow (`api-docs.yml`) builds a released tag again by hand.

## A package name never published before

Trusted publishing is set in a package's settings on npm, so the name must exist first. Before the first release that adds a concern:

1. From a maintainer's account, publish a placeholder `0.0.0` of the new name under the dist-tag `bootstrap`. npm also points `latest` at a name's first version, so the placeholder is `latest` until the name's first final release.
2. In the package's settings on npm, add this repository's release workflow as its trusted publisher.

A release whose new name is missing either stops at that package; see the next section.

## When a publish stops partway

Fix the cause and re-run the failed jobs of the same run (not a new run, and not a new tag). Each attempt asks npm for each package of this version: every one an earlier attempt published is taken from the registry, of the integrity npm gave it, and the rest are packed, the index sealed again over the bundles before it. The run's evidence names those taken in `fetched.json`.

- A failure before anything was published: the rerun packs, checks and publishes everything anew.
- A failure partway through publishing: the rerun takes what is on npm and packs the rest. The release publishes the index's bundle after every bundle it seals over, so the index is sealed again over what is packed, or, once it is on npm, taken as it is. Each package already on npm is passed over, so the rerun publishes only what is missing, and the release is published once every package is.
- The index's bundle on npm while a bundle it seals over is not (published out of order, as by hand): the pack stops, as the index cannot be sealed again, and no rerun changes that. Publish the next version instead.

The check stops for one of two reasons, and its output names which for each package:

- npm's answer could not be read ("the registry's answer is unread": a network or authentication error, an answer that is no JSON or holds no sha512 integrity). Nothing is known to differ: re-run the job once the registry answers.
- A package of this version is on npm with another integrity than this run's tarball ("published with another integrity"). What is on npm is not what the index of this version names, and no rerun changes that: publish the next version instead.

## When the release finds no evidence

The first job holds the tag to a release's: it names its version, and its commit is a merge of two parents, the first on `main` and the second the head of `release/<version>`, with that head's tree. It then looks for CI's successful runs of a push of that head to `release/<version>`, as GitHub states them, and examines them in turn, the newest first, taking the first that will do: its reports name the commit GitHub ran it on, its `conformance`, `release-check` and `compliance` jobs passed, and the evidence it kept, each job's from its newest attempt, still makes the release's compliance when read again. It runs before anything is built, so where it stops nothing is published; its output names what it found and each run it examined, with the reason:

- **The tag is not a release's**: it names no version, its commit is not a merge of two parents, its first parent is not on `main`, or its tree is not the tree of the release branch's head it merged (`main` held changes the branch did not, so what CI tested is not what the tag publishes). Have the tag deleted by one the tag rules allow, merge `main` into the release branch, push it, wait for its CI, merge it into `main`, and tag the new merge commit.
- **The tag's CI workflow would restore a cache** in a push to its release branch (each step is named). Make `ci.yml` restore none in that run, and release the next version.
- **No successful CI run of the release branch's push.** Push the branch under its name if it was not, or re-run its CI (on its run, **Re-run all jobs**); wait for it to pass, then re-run the failed jobs of the release's run.
- **A release job did not pass, an artifact is missing or expired, or the evidence kept no longer makes the release's compliance** (the runs that did not report are named). Re-run all jobs of the run it names: the new attempt keeps its artifacts anew, and each job's newest attempt is the one taken, so an older attempt's expired one stops nothing. Then re-run the failed jobs of the release's run. GitHub re-runs a run within 30 days of it; past that, push a new commit to the release branch and do as for a tag that is not a release's, above.
- **A run's reports name another commit than the one GitHub ran it on.** Its evidence is not that run's own: re-run all its jobs, and where it stays so, find what wrote those reports before releasing.
- **A run could not be examined** (an archive or a file that failed). The next older run was examined in its place; where none would do, re-run the failed jobs of the release's run.
- **GitHub could not be asked** (fetching stops on an answer it cannot have, never taking it for no runs). Re-run the failed jobs of the release's run once GitHub answers.

## A security release

A fix for a reported hole is made and tested in the security repository (`o3co/auth.provider-security`, private), which mirrors this one, and is made public with the version that carries it (`SECURITY.md`, [findings and fixes](audit/findings.md)). Where the tag declares a security release, the release takes that repository's run as its evidence, by the same rules, in a job of its own; no tag that does not declare one takes it, whatever ran here.

What the owner sets up once: the GitHub App that reads the security repository's runs, installed there alone; the `security-evidence` environment, its reviewer and its `v*` tag rule; and that repository's branch rules. The App's private key exists only from step 6 to step 11.

1. Draft the advisory and request its CVE. Add the finding to the ledger.
2. Bring the security repository's mirror of `main` up to date, after checking that `git remote get-url security` names it: `git fetch origin`, so the mirror gets this repository's current `main` and not a stale checkout's, then `git push security origin/main:refs/heads/mirror/main`. The refspec is fast-forward only; never force-push. The fix is made from `main` alone: `develop` is not mirrored, as it is reset at each release.
3. Make the fix on `security/<finding>` from `mirror/main`: the fix, the version's commit, the changelog (the kind of hole and the module, never how to reach it) and the migration guide. Run the checks locally.
4. Have it reviewed.
5. Push its head to the security repository as `release/<version>`: CI there runs every job a release needs. Wait for that run to finish and pass before going on: the release takes only a successful run as its evidence, and from step 7 the fix is public. Where it fails, fix it on `security/<finding>`, have it reviewed and push again. Run `pnpm release:sbom` locally over the release check's tarballs, the one job of the release CI does not run.
6. Fetch both branches from the security repository, `git fetch security mirror/main release/<version>`, and check that `security/release/<version>` is the head reviewed in step 4 and tested in step 5. On top of `security/mirror/main` (`git switch --detach security/mirror/main`), make the merge commit, `git merge --no-ff security/release/<version> -m "Merge release/<version>"`, and check that its tree is the branch head's. Read that whole tree before you tag it, not only `release.yml`: the tag rules and the environment's approval stop a writer only where the owner has read every file the release will run. Then tag it, declaring the security release in the tag's message: `git tag -a v<version> -m "v<version>" -m "Release-Evidence: security"`. Add the App's ID and private key to the environment's secrets.
7. Push the tag alone: `git push origin refs/tags/v<version>`. From here the fix is public.
8. The release workflow reads the tag's declaration and hands over to the security repository's run: approve the `security-evidence` deployment once you have checked that it runs the tag you made.
9. Once npm has the version, publish the advisory. Where it does not within two hours of step 7, publish the advisory then, with the versions affected and any workaround, and update it every day until the version is out; the steps of [When a publish stops partway](#when-a-publish-stops-partway) still hold.
10. Fast-forward `main` to the merge commit, an owner's push past the required checks it has none of here, and push its second parent as `release/<version>`: CI runs every job on it in public. Bring `main` into `develop` through a pull request.
11. Remove the secrets and delete the App's key.
12. Add the public run to the change record, have it reviewed and publish it. Delete `security/<finding>` and `release/<version>` from the security repository, and mark the finding fixed.

Where `main` here moved after step 2, start again from step 2 before step 6. Where it moved after step 7, `main` cannot be fast-forwarded: bring the merge commit into it through a pull request.

## The API site

The site on GitHub Pages is built from the `gh-pages` branch: one dir per minor, the root and `versions.html` (`modules/tooling/api-docs`). Only the release workflow and the API site workflow write it.

Once, before the 0.19.0 tag: the branch still holds the 0.17 site (v0.3.0 to v0.17.0, and files a deploy left in by mistake). Remove every file but `.nojekyll` in one commit to `gh-pages`, with a placeholder `index.html` saying the 0.19 API comes with 0.19.0 and that the old system's API is in the source at tag v0.17.0. Never force-push: the old pages stay in the branch's history.

## After the release

- Install the entrance from npm (`npx @o3co/create-auth-provider@<version>`), generate a pattern and boot it.
- For a final release, check that `latest` names the version for every package, the placeholders' included.
- The cross-component tests in the umbrella repository run by hand (`umbrella-e2e.yml`); its header says against which revisions.
- Reset `develop` to the merge commit on `main`, then open `develop` to merges again (step 7 stopped them). The reset is a force push: the owner allows force pushes to `develop` for this step alone, and disallows them once it is done. After it, `develop`'s history is `main`'s, and a commit only `develop` held is reachable from its pull request alone.
- Move each open branch made from the old `develop` onto the new one: `git rebase --onto develop <the old develop's head> <branch>`, then push it, as its rebase rewrote it. A branch made from the old head finds the same tree; one made from an older commit may conflict, as any rebase may. Reset every local `develop` to `origin/develop`.
- What names a commit after the release, an umbrella revision pinned or a change record, names one on `main`, or a pull request by number: the commits only `develop` held are not kept.
- At the first final 0.18 release: deprecate the 0.17 packages with `npm deprecate`, each by version range (`<0.18.0`), so a name 0.18 reuses keeps its new versions undeprecated.
- Open the API site and check the release's minor shows its version in each page's title. The [migration guide](migration.md#packages) says which 0.17 package went where.
