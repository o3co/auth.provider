# Release Labeling Policy

**Scope (4 OSS repos)**: `auth.utils` / `auth.provider` / `auth.policy-verifier` / `auth.proxy`. These four share the auth-scope release cadence and migration story; this policy applies uniformly to all four.

**Out of scope**:

- `protobuf.interceptors` — Go-based, separate release cadence and ecosystem (Go semver convention differs)
- `ts.hocon` / `go.hocon` / `rs.hocon` — HOCON library implementations; their release cadence is independent
- Private composition roots and archived repositories are not subject to this policy

---

## Why this policy exists

Pre-2026-05-12, this project anchored multi-release planning on future version labels ("v0.6.0", "1.0 GA") written into specs, CHANGELOG forward-promises, JSDoc `@deprecated removed-in` annotations, PR titles, and validation error message strings. As actual release cuts diverged from plan, those labels drifted: features were rebucketed mechanically, internal memos became self-contradictory, and at least two operator-facing artifacts (v0.5.2/v0.5.3 CHANGELOGs and `removedIn` Zod validation error metadata) shipped forward-references that no longer match the actual release where the change lands.

The "1.0 GA" planning anchor used pre-2026-05-12 has been **retired**. Removals previously labeled "1.0 GA" in v0.5.x CHANGELOGs and JSDoc land in **v0.6.0**.

This policy codifies how to handle release labels going forward so the same drift cannot recur silently.

## Core rule

**Past version numbers are facts. Future version numbers are predictions. Treat them differently.**

| Where | Past version OK? | Future version OK? |
| --- | --- | --- |
| Tagged release notes / CHANGELOG section heading | ✅ (the version itself) | ❌ |
| CHANGELOG entry body, current release | ✅ (cross-reference past releases) | ❌ |
| CHANGELOG `## [Unreleased]` body | ✅ (cross-reference past releases) | ❌ (do NOT write "removed in vX.Y" predictions) |
| JSDoc `@deprecated since` | ✅ | — |
| JSDoc `@deprecated removed-in` | ❌ (do not predict) | ❌ |
| Code comments (line or block) | ✅ (cross-reference past) | ❌ |
| HOCON / YAML config comments | ✅ | ❌ |
| README forward statements | ✅ (history) | ⚠️ (only with "subject to change", and never specific version numbers) |
| Migration guide forward statements | ✅ | ⚠️ (use "next major" / "future release", not specific version) |
| Error message strings | ✅ | ❌ (this is the worst — operator sees the lie at error time) |
| PR title | ✅ (post-merge facts) | ❌ (do not pre-label PR with "for vX.Y") |
| GitHub issue body | ✅ | ⚠️ (acceptable for tracking, but use milestones for the "when" — labels rot less than text) |
| Internal planning memos (`.claude/`) | ✅ | ⚠️ (acceptable for short-lived plans, but add "labels may shift" disclaimer if doc lives >1 release cycle) |

## The six concrete rules (R1-R6)

### R1. Past-only rule (code + public docs)

code / JSDoc / public docs (README, migration guide) / config comments / error message strings reference **only** released version tags.

**Bad**: `@deprecated since v0.5.1, removed in 1.0` / `error: field X was removed in 1.0 GA`
**Good**: `@deprecated since v0.5.1; see CHANGELOG for removal version` / `error: field X was removed in v0.6.0`

### R2. CHANGELOG uses `## [Unreleased]` until cut

Follow Keep a Changelog convention. The Unreleased section accumulates entries describing what changed on HEAD. **Do not pre-stamp** "## [0.6.0]" or "## [1.0.0]" before the tag is cut. At cut time, rename `## [Unreleased]` → `## [X.Y.Z] - YYYY-MM-DD` in a single commit that also creates the git tag.

When tagging a release, also grep for forward-version references in the Unreleased body and either rewrite to the actual version or generalize. **Specifically**: any "removed in NEXT" / "deprecated will be removed in X" / "before X" forward-promise must be resolved to the actual release where it lands.

### R3. JSDoc `@deprecated` says "since" only

```typescript
/** @deprecated since v0.5.1 */          // ✅
/** @deprecated since v0.5.1, removed in v1.0 */   // ❌
/** @deprecated since v0.5.1 — see MIGRATION.md */ // ✅ alternative
```

Removal timing belongs in CHANGELOG and MIGRATION.md, not in JSDoc. JSDoc annotations are read by IDEs to flag deprecated usage; they should warn users *that* something is deprecated, not bind us to a specific removal date.

### R4. PR titles describe what was done, not what release

```text
feat(oauth): rename CodeRepository.getByCode → findByCode    // ✅
feat(oauth)!: rename CodeRepository.getByCode → findByCode   // ✅ (semver-major signal)
M5 (1.0 GA): rename CodeRepository.getByCode → findByCode    // ❌ (label drift)
```

The PR's eventual release is determined by which tag includes the merge commit. The PR title should not predict.

Milestones can be used for "when" tracking — milestones are mutable and don't end up in git history.

### R5. Validation error message strings: factual, not predictive

Operator-facing strings (Zod issues, error messages, structured log fields) must use **released** version names only.

```typescript
// ❌
removedIn: "1.0 GA (Phase G / M4)"
// Error: "oauth.refreshToken.legacyTokenCompat was removed in 1.0 GA (Phase G / M4). ..."

// ✅
removedIn: "v0.6.0 (Phase G / M4)"
// Error: "oauth.refreshToken.legacyTokenCompat was removed in v0.6.0 (Phase G / M4). ..."
```

If a removal is announced in advance (deprecated now, will be removed later), the error path during the deprecated window emits a *deprecation warning* (not yet an error), and the removed-in version is filled in **at the release that actually removes it**. Do not pre-stamp the removed-in string before that release is cut.

### R6. Release-cut audit pass (mandatory checklist before tagging)

Before tagging a release `vX.Y.Z`:

1. `git grep -i -E "(removed|deprecated|planned).*(1\.0 GA|next major|in v[0-9]+\.[0-9]+)"` — review every match and resolve
2. Replace `## [Unreleased]` → `## [X.Y.Z] - YYYY-MM-DD` in CHANGELOG
3. In CHANGELOG Unreleased body: replace any forward-version reference (e.g., "removed in 1.0 GA") with the actual release name (`vX.Y.Z`)
4. JSDoc / code comments / config comments: replace forward-version references with `vX.Y.Z` or genericize
5. Schema metadata strings (Zod `removedIn`, etc.): replace forward-version references with `vX.Y.Z`
6. PR title for the release-cut PR uses "release: vX.Y.Z" (no Phase / GA labels)
7. Release notes (gh release create body) include a brief retirement note if any pre-existing label was retired in this cut

## "1.0 GA" label retirement (2026-05-12)

Prior to 2026-05-12, the auth scope's planning artifacts anchored multi-release commitments on the label "1.0 GA". That label was retired because bookkeeping drift made it internally contradictory and silently dropped originally-committed features.

Removals, renames, and default flips previously labeled "1.0 GA" in v0.5.x CHANGELOGs, JSDoc, configuration comments, schema-validation error metadata, and PR titles land in the **v0.6.0** release of the affected package(s). The specific list of changes that were re-labeled (with corresponding PR references) is recorded in each affected repo's `CHANGELOG.md` under the v0.6.0 entry. Consumers who installed v0.5.2 or v0.5.3 from npm and read CHANGELOG entries promising "will be removed at 1.0 GA" should expect those removals in v0.6.0; there is no separate "1.0 GA" release.

The next major version (whether labeled `0.7.0`, `1.0.0`, or otherwise) will be decided through a feature inventory process after v0.6.0 cut, not anchored on the retired "1.0 GA" framing.

Merged PR titles in git history that contain "(1.0 GA)" labels are retained as historical artifacts; they cannot be rewritten without rewriting shared git history.
