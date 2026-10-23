# Releasing

How a maintainer cuts a release. The release workflow (`release.yml`) does the building and publishing once a tag is pushed; this guide covers what comes before the tag and after it.

## Contents

- [What a release publishes](#what-a-release-publishes)
- [Before the tag](#before-the-tag)
- [Tagging](#tagging)
- [What the workflow does](#what-the-workflow-does)
- [A package name never published before](#a-package-name-never-published-before)
- [When a publish stops partway](#when-a-publish-stops-partway)
- [After the release](#after-the-release)

## What a release publishes

One package per concern, `@o3co/auth-provider-<concern>`, and the entrance `@o3co/create-auth-provider`, all at the version the root `package.json` states. A version with a prerelease part (`0.18.0-rc.2`) is published under the npm `next` tag and marked a prerelease on GitHub; any other under `latest`.

## Before the tag

1. **The changelog.** The version's section in `CHANGELOG.md` is complete, and its `Unreleased` becomes the date.
2. **The migration guide.** Every change an operator must act on has its line in [the migration guide](migration.md).
3. **Pull request titles.** The release notes are generated from the titles of the pull requests merged since the last tag. Read them: a security fix's title names the kind of hole it closes and the module, never how to reach it. Retitle one on GitHub before tagging; the notes read the titles when the release is made.
4. **The version.** One commit changes the root `package.json` version, by itself, and reaches `main` with the rest.
5. **To `main`.** A pull request from `develop` to `main`, merged with a merge commit. CI on `main` runs the conformance scenes and `pnpm release:check`; wait for both.

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

## After the release

- Install the entrance from npm (`npx @o3co/create-auth-provider@<version>`), generate a pattern and boot it.
- For a final release, check that `latest` names the version for every package, the placeholders' included.
- The cross-component tests in the umbrella repository run by hand (`umbrella-e2e.yml`); its header says against which revisions.
- At the first final 0.18 release: deprecate the 0.17 packages with `npm deprecate`, each by version range (`<0.18.0`), so a name 0.18 reuses keeps its new versions undeprecated, and mark the 0.17 API site on GitHub Pages as 0.17's. The [migration guide](migration.md#packages) says which 0.17 package went where.
