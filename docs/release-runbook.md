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

The audit must cover:

- **Security**: per-mechanism + cross-cutting (header injection, key handling, cnf claim shape)
- **Extensibility & immutability**: per [`extensibility-immutability-check`](../.claude/skills/extensibility-immutability-check/SKILL.md) — exported surface unchanged or additive only
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
4. Publishes each non-private package with provenance attestation
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

### Dependency bumps merged just before tag

Dependabot PRs landing between the audit and the tag invalidate the audit's diff range. Re-run the cumulative audit if any non-trivial dependency change lands after the audit started.
