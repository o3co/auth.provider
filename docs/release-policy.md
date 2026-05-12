# Release Labeling Policy

**Scope (4 OSS repos)**: `auth.utils` / `auth.provider` / `auth.policy-verifier` / `auth.proxy`. These four share the auth-scope release cadence and migration story; this policy applies uniformly to all four.

**Out of scope**:

- `protobuf.interceptors` — Go-based, separate release cadence and ecosystem (Go semver convention differs)
- `ts.hocon` / `go.hocon` / `rs.hocon` — HOCON library implementations; their release cadence is independent
- Private composition roots and archived repositories are not subject to this policy

---

## Why this policy exists

Pre-2026-05-12, the auth scope anchored multi-release planning on future version labels (specifically "1.0 GA") written into specs, CHANGELOG forward-promises, JSDoc `@deprecated removed-in` annotations, PR titles, and validation error message strings. As actual release cuts in `auth.provider` diverged from plan, those labels drifted: features were rebucketed mechanically, internal memos became self-contradictory, and operator-facing artifacts shipped forward-references to a release that was never cut.

The "1.0 GA" planning anchor has been **retired**. The release that the affected changes actually land in is recorded in the relevant repo's `CHANGELOG.md` under the corresponding release section (filled in at the moment of release cut, not pre-stamped).

This policy codifies how to handle release labels going forward so the same drift cannot recur silently. It applies uniformly to all 4 in-scope OSS repos regardless of each repo's individual release history.

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
| Internal planning artifacts (specs, design docs, agent memos) | ✅ | ⚠️ (acceptable for short-lived plans, but add "labels may shift" disclaimer if doc lives >1 release cycle) |

## The six concrete rules (R1-R6)

### R1. Past-only rule (code + public docs)

code / JSDoc / public docs (README, migration guide) / config comments / error message strings reference **only** released version tags.

**Bad**: `@deprecated since vX.Y, removed in 1.0` / `error: field foo was removed in NEXT_RELEASE`
**Good**: `@deprecated since vX.Y; see CHANGELOG for removal version` / `error: field foo was removed in vX.Y.Z` (where `vX.Y.Z` is the released tag that performed the removal — filled in at release-cut time)

### R2. CHANGELOG uses `## [Unreleased]` until cut

Follow Keep a Changelog convention. The Unreleased section accumulates entries describing what changed on HEAD. **Do not pre-stamp** specific version numbers (e.g., `## [0.6.0]`, `## [1.0.0]`, `## [0.0.4] — Unreleased`) before the tag is cut. At cut time, rename `## [Unreleased]` → `## [X.Y.Z] - YYYY-MM-DD` in a single commit; then create the git tag pointing at that commit (the tag and the rename commit are separate git operations, but happen as one atomic release-cut step).

When tagging a release, also grep for forward-version references in the Unreleased body and either rewrite to the actual version or generalize. **Specifically**: any "removed in NEXT" / "deprecated will be removed in X" / "before X" forward-promise must be resolved to the actual release where it lands.

### R3. JSDoc `@deprecated` says "since" only

```typescript
/** @deprecated since vX.Y */                    // ✅
/** @deprecated since vX.Y, removed in v1.0 */   // ❌ (don't pre-stamp removal version)
/** @deprecated since vX.Y — see CHANGELOG */    // ✅ alternative
```

Removal timing belongs in CHANGELOG (and migration guides, when the repo provides one), not in JSDoc. JSDoc annotations are read by IDEs to flag deprecated usage; they should warn users *that* something is deprecated, not bind us to a specific removal date.

### R4. PR titles describe what was done, not what release

```text
feat(oauth): rename CodeRepository.getByCode → findByCode    // ✅
feat(oauth)!: rename CodeRepository.getByCode → findByCode   // ✅ (semver-major signal)
M5 (1.0 GA): rename CodeRepository.getByCode → findByCode    // ❌ (label drift)
```

The PR's eventual release is determined by which tag includes the merge commit. The PR title should not predict.

Milestones can be used for "when" tracking — milestones are mutable and don't end up in git history.

### R5. Validation error message strings: factual, not predictive

Operator-facing strings (Zod issues, error messages, structured log fields) must use **released** version names only — or omit the version entirely.

```typescript
// ❌ — refers to a label that was never released
removedIn: "1.0 GA (Phase G / M4)"

// ❌ — pre-stamps a version that hasn't been cut yet
removedIn: "vX.Y.Z (Phase G / M4)"   // when vX.Y.Z is still pending

// ✅ — neutral wording, no forward reference
removedIn: "this release (Phase G / M4)"
// or omit the version entirely:
removedIn: "(Phase G / M4)"

// ✅ — released tag, post-cut (R6 audit at cut time fills this in)
removedIn: "vA.B.C (Phase G / M4)"   // where vA.B.C is the tag that landed this removal
```

If a removal is announced in advance (deprecated now, will be removed later), the error path during the deprecated window emits a *deprecation warning* (not yet an error). The removed-in version is filled in **at the release-cut PR that actually performs the removal** (per R6, step 5), not at the sweep/refactor PR before it. Operators running the release that contains the removal naturally know their own version; the "in version X" context inside the error message is optional and can be omitted to avoid pre-stamping pressure.

### R6. Release-cut audit pass (mandatory checklist before tagging)

Before tagging a release `vX.Y.Z`:

1. `git grep -i -E "(removed|deprecated|planned).*(1\.0 GA|next major|next release|in v[0-9]+\.[0-9]+)"` — review every match and resolve
2. Replace `## [Unreleased]` → `## [X.Y.Z] - YYYY-MM-DD` in CHANGELOG (where `X.Y.Z` is the tag being cut)
3. In CHANGELOG body (now the named release section): replace any forward-version reference (e.g., "removed in 1.0 GA", "this release", "next release") with the actual release name `X.Y.Z`
4. JSDoc / code comments / config comments: replace forward-version references with `X.Y.Z` or remove the version mention entirely
5. Schema metadata strings (Zod `removedIn`, etc.): replace neutral / forward-version values with `X.Y.Z` so operator error messages name the release that actually removed the field
6. PR title for the release-cut PR uses "release: vX.Y.Z" (no Phase / GA / "next-release" labels)
7. Release notes (`gh release create` body) include a brief retirement note if any pre-existing label was retired in this cut

## "1.0 GA" label retirement (2026-05-12)

Prior to 2026-05-12, the auth scope's planning artifacts anchored multi-release commitments on the label "1.0 GA". That label was retired because bookkeeping drift made it internally contradictory and silently dropped originally-committed features.

Impact varies by repo:

- `auth.provider` had substantive drift — CHANGELOG entries in tagged v0.5.x releases promising "will be removed at 1.0 GA", operator-facing schema error metadata referencing the same label, and JSDoc/code comments scattered throughout the source tree. The cleanup and the actual landing release are recorded in `auth.provider`'s own `CHANGELOG.md`, with the version filled in at release-cut time per R6.
- `auth.utils`, `auth.proxy`, `auth.policy-verifier` had no forward-version drift in source code. They adopt this policy going forward; the historical narrative above describes the scope-wide reason it exists.

Consumers who installed `auth.provider` v0.5.2 or v0.5.3 from npm and read CHANGELOG entries promising "will be removed at 1.0 GA" should consult the current `CHANGELOG.md` on `develop` (or the latest released tag) for the actual release that performed those removals — there is no separate "1.0 GA" release.

The next major version (whether labeled `0.7.0`, `1.0.0`, or otherwise, for any of the in-scope repos) will be decided through a feature inventory process, not anchored on the retired "1.0 GA" framing.

Merged PR titles in git history that contain "(1.0 GA)" labels are retained as historical artifacts; they cannot be rewritten without rewriting shared git history.
