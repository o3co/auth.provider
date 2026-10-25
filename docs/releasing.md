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
4. **Pull request titles.** The release notes are generated from the titles of the pull requests merged since the last tag. Read them: a security fix's title names the kind of hole it closes and the module, never how to reach it. Retitle one on GitHub before tagging; the notes read the titles when the release is made.
5. **The attack surface.** Read the diff of [the attack surface reference](attack-surface.md) since the last tag: each route, outbound reach, secret or weakening setting it adds was meant to open, and is declared as [What a version promises](#what-a-version-promises) asks.
6. **The version.** One commit changes the root `package.json` version, by itself, and reaches `main` with the rest.
7. **To `main`.** A pull request from `develop` to `main`, merged with a merge commit. CI on the pull request to `main` runs the conformance scenes and `pnpm release:check`; wait for both.

## Tagging

Tag the merge commit on `main` as `v<version>` and push the tag. The workflow refuses a tag that does not name the root `package.json` version, before it builds anything.

## What the workflow does

1. Checks that npm can publish through trusted publishing (11.5.1 or later).
2. Runs `pnpm check` and `pnpm release:check`: every pattern generated from the packed tarballs alone, type-checked and booted, and a package outside the release composed beside them, its app held to the integrity the release sealed.
3. Restores the tarballs an earlier attempt of the run saved, or, where none was saved, packs every package (`pnpm release:pack`): every bundle but the scaffold, then the scaffold's index sealed with their integrity and zod's, then the scaffold and the entrance. Refuses any tarball without the root `LICENSE` word for word, and saves the tarballs it packed to the run.
4. Refuses to go on where a package of this version is on npm already as another tarball, or npm's answer cannot be read (`pnpm release:published`).
5. Creates a draft GitHub release with generated notes.
6. Publishes each tarball with provenance, the entrance last since it depends on the others. Each is authenticated by the run's own token, through the package's trusted publisher; no npm token is stored.
7. Publishes the draft release.
8. For a final release (never a prerelease), builds its API from the bundles it published, installed from npm, into the minor's dir of the API site on GitHub Pages (`v<major>.<minor>/`, each patch writing over it), and points the site's root at the newest minor. The **API site** workflow (`api-docs.yml`) builds a released tag again by hand.

## A package name never published before

Trusted publishing is set in a package's settings on npm, so the name must exist first. Before the first release that adds a concern:

1. From a maintainer's account, publish a placeholder `0.0.0` of the new name under the dist-tag `bootstrap`. npm also points `latest` at a name's first version, so the placeholder is `latest` until the name's first final release.
2. In the package's settings on npm, add this repository's release workflow as its trusted publisher.

A release whose new name is missing either stops at that package; see the next section.

## When a publish stops partway

Fix the cause and re-run the failed job of the same run (not a new run, and not a new tag). Each attempt first restores the tarballs an earlier attempt saved, and packs only where none was saved:

- A failure before the tarballs were saved (installing, the checks, packing, saving them) published nothing: the rerun packs, checks and saves them anew.
- A failure after they were saved, publishing included: the rerun restores them, never packing again, and checks that every package of this version already on npm is that very tarball before publishing anything; one that is passed over, so the rerun publishes only what is missing, and the release is published once every package is.

The tarballs are kept 90 days. A rerun after that, or one whose restore fails, packs anew; the same check then lets it go on only where what is on npm is the same bytes.

The check stops for one of two reasons, and its output names which for each package:

- npm's answer could not be read ("the registry's answer is unread": a network or authentication error, an answer that is no JSON or holds no sha512 integrity). Nothing is known to differ: re-run the job once the registry answers.
- A package of this version is on npm with another integrity than this run's tarball ("published with another integrity"). What is on npm is not what the index of this version names, and no rerun changes that: publish the next version instead.

## The API site

The site on GitHub Pages is built from the `gh-pages` branch: one dir per minor, the root and `versions.html` (`modules/tooling/api-docs`). Only the release workflow and the API site workflow write it.

Once, before the 0.19.0 tag: the branch still holds the 0.17 site (v0.3.0 to v0.17.0, and files a deploy left in by mistake). Remove every file but `.nojekyll` in one commit to `gh-pages`, with a placeholder `index.html` saying the 0.19 API comes with 0.19.0 and that the old system's API is in the source at tag v0.17.0. Never force-push: the old pages stay in the branch's history.

## After the release

- Install the entrance from npm (`npx @o3co/create-auth-provider@<version>`), generate a pattern and boot it.
- For a final release, check that `latest` names the version for every package, the placeholders' included.
- The cross-component tests in the umbrella repository run by hand (`umbrella-e2e.yml`); its header says against which revisions.
- At the first final 0.18 release: deprecate the 0.17 packages with `npm deprecate`, each by version range (`<0.18.0`), so a name 0.18 reuses keeps its new versions undeprecated.
- Open the API site and check the release's minor shows its version in each page's title. The [migration guide](migration.md#packages) says which 0.17 package went where.
