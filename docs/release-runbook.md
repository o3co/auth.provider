# Release Runbook

Operational mechanics for cutting an `auth.provider` release. Companion to [release-policy.md](release-policy.md) (which covers version labeling discipline / R1–R6).

This runbook captures patterns established through `v0.7.0` (manual bootstrap recovery) and `v0.8.0` (clean pre-bootstrap + multi-agent audit) so future releases hit the same shape.

---

## TL;DR

1. **Run cumulative final audit** (multi-agent + FCoT) on the cut diff BEFORE pushing the tag — not after.
2. **For each new monorepo package, pre-flight `npm view`**. If 404, pre-bootstrap with a 0.0.1 dummy publish from local BEFORE pushing the tag.
3. **Run R6 label audit** per [release-policy.md §R6](release-policy.md#r6-release-cut-audit-pass-mandatory-checklist-before-tagging).
4. **Tag + push** → `release.yml` does the rest (`pnpm -r exec pnpm version` from the tag).
5. **Verify** all packages on npm + GitHub Release page.

---

## Pre-release checklist

### Step 1. Cumulative final audit (mandatory)

Run multi-agent review + FCoT on the **full release diff** before tagging:

```bash
# From the develop branch at the commit that will be tagged
LAST_TAG=$(git describe --tags --abbrev=0)
git diff "$LAST_TAG"..HEAD --stat
# Then run /multi-agent-review on the diff range
```

Before the roll-up commit, the mechanical part of R6 step 5 — placeholders in
operator-facing strings that the cut is supposed to stamp. This is how
`removedIn: "this release (#330)"` shipped in v0.10.0 *and* v0.11.0 (#458): the
grep below has to be read rather than merely run — it matches the doc comments
that describe the convention as well as any real placeholder, and the block
says how to tell them apart. Backing it up,
`packages/core/src/config/__tests__/removedIn.drift.test.mts` fails the cut that
moves a still-placeholdered PR out of `## [Unreleased]`, so a miss there is a
red CI run rather than a released error message naming no release.

```bash
# Every operator-facing string still saying "this release" — stamp each with
# the tag being cut (docs/release-policy.md R5, R6 step 5).
#
# Read the hits, do not expect none. The pattern also matches doc comments that
# describe the convention (`removedIn.drift.test.mts`, `application.schema.mts`
# say what the placeholder is), and those are correct as they stand. A finding
# is a hit where the string is a VALUE an operator can see — `removedIn: "this
# release (#NNN)"`, a Zod message, a log field. Cross-check the hits against
# `git grep -n 'removedIn:' -- ':(glob)packages/*/src/**'`: every value there
# must already name a released tag.
#
# The pathspec must be `:(glob)` with `/**`: git's default pathspec treats
# `packages/*/src` as a literal path, which matches no file, so the plain form
# reported "no output" whatever the tree contained. That is how the placeholder
# this check exists to catch shipped twice (#458).
git grep -n '"this release' -- ':(glob)packages/*/src/**' ':(glob)templates/*/src/**'
```

The audit must cover:

- **Security**: per-mechanism + cross-cutting (header injection, key handling, cnf claim shape)
- **Extensibility & immutability**: the exported surface of every published package is unchanged or additive only. Diff each package's entry point against the last tag (`git diff <lastTag>..HEAD -- packages/<p>/src/index.mts`, and follow the re-exports it names), and classify every change as additive / breaking / behavioural-only. Two shapes that read as additive but are not: **a new required field on an exported options or config type** breaks a caller that constructs it, and **a new required member on an exported interface** breaks a third-party implementer. Every break must appear in the release's CHANGELOG section saying what a consumer has to do.
- **Interface design**: ADR-level decisions still hold across the cut
- **FCoT** on load-bearing decisions: pre-declare dismissal conditions for each counter-argument

**Why mandatory**: `v0.8.0` skipped this and ran a retroactive audit afterwards. The audit surfaced 3 Important findings (`issue #199`) that should have been resolved or knowingly accepted before the tag, not after. Per-sub-PR reviews caught the load-bearing security issues, but cross-cutting / documentation items only surface in a final pass.

If the audit finds **Critical**: stop, fix, re-audit. Do not tag.
If **Important** only: decide explicitly — fold into this release, or file follow-up issue for next release and proceed knowingly.

### Step 2. R6 label audit

Follow [release-policy.md §R6](release-policy.md#r6-release-cut-audit-pass-mandatory-checklist-before-tagging) verbatim. The CHANGELOG roll-up commit (`## [Unreleased]` → `## [X.Y.Z] - YYYY-MM-DD`) is part of this step.

### Step 3. npm new-package bootstrap pre-flight

For every monorepo package that will publish at the new version:

```bash
for pkg in packages/*/package.json; do
  name=$(jq -r '.name' "$pkg")
  [[ "$(jq -r '.private // false' "$pkg")" == "true" ]] && continue
  echo "$name: $(npm view "$name" version 2>&1 | head -1)"
done
```

For each scoped package that returns **404 / E404**: it has never been published. The release CI npm token can update existing packages but **cannot create new scoped packages** (the npm registry's PUT to a non-existent scoped package 404s with the CI token). Pick a path:

- **Pre-bootstrap (recommended)** — see [Pattern A](#pattern-a-pre-bootstrap-recommended) below
- **Tag-first manual recovery** — see [Pattern B](#pattern-b-tag-first-manual-recovery)

### Step 4. Tag + push

```bash
git tag -a "vX.Y.Z" -m "Release vX.Y.Z" "$RELEASE_COMMIT"
git push origin "vX.Y.Z"
```

`release.yml` triggers on `v*` tags and:

1. Checks out the tagged commit
2. Sets the version across all workspace packages via `pnpm -r exec pnpm version "${GITHUB_REF#refs/tags/v}" --no-git-tag-version`
3. Builds + typechecks
4. Publishes each non-private package with provenance attestation — under npm dist-tag `latest` for a final release, `next` when the tag carries a prerelease identifier (`v1.0.0-rc1`), so an RC never becomes what `npm install` resolves to; the GitHub Release is marked *prerelease* in the same case
5. Creates the GitHub Release with auto-generated notes

Watch the workflow:

```bash
gh run watch $(gh run list --workflow=release.yml --limit=1 --json databaseId --jq '.[0].databaseId')
```

### Step 5. Post-release verification

```bash
# All published at the new version?
for pkg in packages/*/package.json; do
  name=$(jq -r '.name' "$pkg")
  [[ "$(jq -r '.private // false' "$pkg")" == "true" ]] && continue
  echo "$name: $(npm view "$name" version)"
done

# GitHub Release published (not draft)?
gh release view "vX.Y.Z" --json isDraft,publishedAt
```

---

## Pattern A. Pre-bootstrap (recommended)

Use when `npm view @scope/<new-pkg>` returns 404 in step 3. Establishes the scoped name on the registry from local BEFORE the release tag, so CI sees an existing package on first PUT.

```bash
# 1. npm login (interactive — OTP)
npm login

# 2. For each new pkg:
cd packages/<new-pkg>
npm version 0.0.1 --no-git-tag-version
pnpm publish --access public --no-git-checks

# 3. Revert the local version bump (keep develop clean for the tag)
cd ../..
git checkout packages/<new-pkg>/package.json

# 4. Repeat for each new pkg, then proceed to step 4 (tag + push)
```

**Cost**: `<new-pkg>@0.0.1` remains visible in the npm version history as a registration-only release (no usable code).

**Benefit**: zero provenance gap. Every shipped `X.Y.Z` was published from `release.yml` with provenance attestation. This is the path used by `v0.8.0` (`dpop`, `mtls`).

## Pattern B. Tag-first manual recovery

Use only when pre-bootstrap was not done and the tag has already been pushed.

After CI fails on the new package's publish step (404 PUT):

```bash
# 1. From local, with npm logged in:
cd packages/<new-pkg>
pnpm publish --access public --no-git-checks
# (the version is already set on disk by the failed CI run? — actually no, CI ran pnpm version which only modified its own checkout)
# So bump locally to match the tag version first:
npm version X.Y.Z --no-git-tag-version
pnpm publish --access public --no-git-checks
cd ../..
git checkout packages/<new-pkg>/package.json

# 2. Re-run the failed CI publish step:
gh run rerun --failed $(gh run list --workflow=release.yml --limit=1 --json databaseId --jq '.[0].databaseId')
```

**Cost**: the bootstrap-published version has **no provenance attestation** (published from a local machine, not GHA). Subsequent versions have provenance once CI succeeds. This is the path used by `v0.7.0` (`webauthn`).

---

## Common pitfalls

### zsh `$status` is read-only

Watcher loops like `until status=$(gh run view ... --jq '.status'); [ "$status" = "completed" ]; do sleep 30; done` will fail in zsh with `read-only variable: status`. Use a different variable name (`s`, `state`, `phase`).

```bash
# Bad (zsh)
until status=$(gh run view "$RUN" --json status --jq '.status'); [ "$status" = "completed" ]; do sleep 30; done

# Good
until s=$(gh run view "$RUN" --json status --jq '.status'); [ "$s" = "completed" ]; do sleep 30; done
```

### `gh run watch` vs polling

`gh run watch <run-id>` streams the workflow live and exits when the run completes. Prefer this over polling — it handles cancellation and shows live step progress.

### Rebase artifacts in `## [Unreleased]`

A rebase onto `develop` can leave the Unreleased section with a second `### Fixed` (or `### Added`, `### Security`) heading and entries repeated verbatim — the v0.11 pre-cut review found three entries duplicated up to four times. R6 step 2 renames the section as-is, so check before stamping:

```bash
# one heading per type under Unreleased, and no repeated entry openers
awk '/^## \[Unreleased\]/{f=1} /^## \[[0-9]/{f=0} f && /^### /' CHANGELOG.md | sort | uniq -d
awk '/^## \[Unreleased\]/{f=1} /^## \[[0-9]/{f=0} f && /^- \*\*/' CHANGELOG.md | sort | uniq -d
```

Both commands print nothing when the section is clean. Order is Added / Changed / Removed / Fixed / Security (as in `v0.9.0`).

### Dependency bumps merged just before tag

Dependabot PRs landing between the audit and the tag invalidate the audit's diff range. Re-run the cumulative audit if any non-trivial dependency change lands after the audit started.

### `pnpm version` rewrites only `version`

Step 2 of `release.yml` sets every package's `version` from the tag and nothing else. A sibling range written as a literal (`"@o3co/auth-provider-core": "^0.0.0"`) is published verbatim — and `^0.0.0` means `<0.0.1`, which no released sibling satisfies: pnpm warns on install, npm 7+ fails `ERESOLVE`. `v0.10.0` shipped that way — `npm view @o3co/auth-provider-dpop@0.10.0 peerDependencies` still answers `^0.0.0`.

Sibling peers are therefore declared as `workspace:^`, which `pnpm pack` / `pnpm publish` rewrite to `^<sibling version>` at pack time, so the range tracks the tag with no second rewrite step. The matching `devDependencies` stay `workspace:*` — that is what satisfies the peer inside the workspace and in the runtime image. The `publish-readiness` CI job asserts both the source spec and the packed manifest, so a package that copies a literal range fails on the PR rather than on the registry. To see what a tag would publish, run the version step locally and inspect a tarball, then restore:

```bash
pnpm -r exec pnpm version 0.0.0-check --no-git-tag-version --no-commit-hooks
(cd packages/dpop && pnpm pack --pack-destination /tmp/tarballs)
tar -xzOf /tmp/tarballs/o3co-auth-provider-dpop-0.0.0-check.tgz package/package.json | jq .peerDependencies
git checkout -- ':(glob)**/package.json'
```
