# Project Guidelines

## Language

- All source code, comments, variable names, function names, test descriptions, and commit messages must be written in **English only**.
- Responses to the user may be in any language.

## README Files

Each kind of documentation has one job, so that every fact has one home and nothing is kept in two places that can drift apart:

| Where | Its job | Written for |
| --- | --- | --- |
| The repository's root `README.md` | What the product does, where it sits in the auth stack, how to run and configure it | Users and operators |
| A package's root `README.md` | How to use the package and a guide to its public API (linking the definitions) | People installing the package |
| A `README.md` inside a source directory | That directory's responsibility, role and invariants: its boundary, the direction of its dependencies, the contracts it keeps | People changing the code |
| The header comment of a source file | What that file does | People changing the code |

Rules for every README:

- **A last-updated date is required**, on the line directly under the H1 title: `Last updated: YYYY-MM-DD` (`最終更新: YYYY-MM-DD` in a `README.ja.md`). Update it whenever you change the README.
- **Responsibility and role are required**, in a `## Responsibility` section (`## 責務と役割` in Japanese) near the top: what the module is for and where it sits, what it owns and what it does not, and why it is a separate module.
- **Refer to code by file name, never by line number.** Line numbers drift with every edit, and a README does not need that precision.
- **Link definitions instead of copying them.** A copied type or signature drifts from the code.

Rules for a source directory's README — it describes the directory, not its files:

- **No per-file descriptions.** What a file does belongs in that file's header comment, which is the source of truth. Do not add a table of files, a line per file, or per-file dependency lists. Name a file only to point at where a contract or entry point lives.
- **No lists of test names.** Test names change like line numbers do. When an invariant is pinned by tests, name the test file.
- **State invariants as rules**, not as history: what holds now. The history belongs in commits, issues and the CHANGELOG.
- A small directory may be described by its parent's README instead of having its own.

When you change what a directory does, what it depends on or an invariant it keeps, update its README in the same PR. When you change what a file does, update its header comment.

In `packages/core/src`, `boot/`, `federation-grants/`, `federations/`, `grants/`, `modules/manifest/`, `repositories/`, `session-admission/` and `user-sessions/` have a README of their own; every other directory directly under `src/` is described by `packages/core/src/README.md`, and every other nested directory by the README that describes its parent. `README.md` is the source of truth; a `README.ja.md` carries the same facts.

## Extension surface: four axes

A package changes what the provider does in one of four ways, and each has its own mechanism ([#710](https://github.com/o3co/auth.provider/issues/710)). Most of the defects #710 found in the extension surface are code on the wrong axis: a policy wired by hand into every consumer, or a single slot where two owners need to add to one decision.

| Axis | What it does | Mechanism | Examples |
| --- | --- | --- | --- |
| **Plugin** | Adds behaviour | A `routes`, `grants` or `federations` contribution | `device-grant`, the `federation-*` packages, `webauthn` |
| **Adapter** | Implements a port core declares | `provides` of a `ComponentMap` slot | The memory and Redis stores, `foundation`'s `HttpUserRepository` |
| **Capability** | Lets an adapter opt into more than its port | An optional method, detected by a `supportsX` guard beside the port | `supportsSecondFactorUpdate`, `supportsSessionsOnlyRevocation`, `supportsLogout`, `supportsRefresh`, `supportsClaimMapping`, `supportsDelegatedAuthorization`, `supportsLock`, `supportsMfaEnrollmentWitness` |
| **Extension** | Changes what an existing core decision means | A contribution kind core composes (a package that owns a decision declares the kind for it, as `session` does for `federationRedirectPolicies`) | `tokenBindingMechanisms` (dpop, mtls), `tokenExchangeValidators`, `federationRedirectPolicies`, `sessionRequirements` (the MFA package's `mfa` requirement) |

**An extension is known by what it declares, never by its name.** Core keys no decision on an extension's name: what an extension may do beyond its kind is a role it declares in its contract, and core enforces the invariants on whichever registered extension declares it. A session requirement declares that it is the second-factor authority (`SessionRequirement.secondFactorAuthority`), which the MFA package's `mfa` requirement does; core lets that one alone reach and add a second factor, binds it to its MFA ports, and refuses a second declaration. The name `mfa` is the MFA package's own (the session-admission ADR's D3 and D7).

`grantPolicy` is an extension still shaped as a single slot: a scope policy and an audience policy from different owners cannot both be installed ([#710](https://github.com/o3co/auth.provider/issues/710), C5).

**Choosing the axis for a policy.** A pull request that adds a policy answers one question on purpose: does more than one owner — packages, the deployment, or both — add to the same decision?

- Yes: a contribution kind core composes (an extension).
- No, one implementation per composition: a port's slot (an adapter).
- An adapter's optional extra beyond its port: a capability.
- A pure predicate with one home: a shared helper (below).

The adapter axis is "one implementation per composition", not only a port's: a key one module owns and others read is a slot too — a settings slot (`oauthTokenSettings`, `httpSettings`, `sessionCookiePolicy`, `deploymentMode`), filled once by its owner and read through its contract in core ([#728](https://github.com/o3co/auth.provider/issues/728)). A module that provides one — `oauthTokenSettings`, `httpSettings`, `sessionCookiePolicy` — names it `authoritative`, so no composition substitutes it while the module is loaded; `deploymentMode` is core's: boot fills it from `core.deployment.mode` and reserves its key as a synthetic one, so no module provides it or names it `authoritative`.

Two more things can look like an axis and are not one:

- **A shared helper** is a pure predicate, or the one reading of a value, with one home in [docs/design-vocabulary.md](docs/design-vocabulary.md): `isLoopbackHostname` and `coveredByRevocationBoundary`, for example. It is replaced by editing its home, never by a deployment. A second definition is a defect, not a second implementation, and the vocabulary's drift guard catches it for every row marked guarded.
- **A closed vocabulary core owns**, such as `ADMISSION_ACTIONS`: a closed union of the bundled plugins' action names, each with its grade, so that a requirement's tests can prove its table exhaustive over it (the session-admission ADR's D4). It names plugins, but it is vocabulary, not an extension point. A deployment's own route builds its own `{ name, grade }` and never adds to the union, and a new bundled consumer's action is added in core. `BUILT_IN_AUDIT_EVENT_TYPES` is the same kind of list, for audit events.

**Packages depend on core alone** ([#728](https://github.com/o3co/auth.provider/issues/728), its decided B4 and B13). In code, a package imports only `@o3co/auth-provider-core`; at run time, one package depends on another only through a slot whose contract lives in core. Three edges predate the rule and are tolerated on a list that may only shrink, never grow: `device-grant` → `oauth`, `federation-grants` → `oauth`, and the federation adapters (`federation-google`, `federation-github`, `federation-apple`, `federation-oidc`) → `session`. Device verification reaches the session package's CSRF policy through the `csrfGuard` slot, and the federation-grants connect flow its login page through `loginEntry`. [`packages/core/src/__tests__/packageImports.drift.test.mts`](packages/core/src/__tests__/packageImports.drift.test.mts) holds that list, with the names each edge imports: an import between packages that is not on it fails, value or type-only, and so does an entry whose import is gone. Each package's runtime dependencies on other packages in its `package.json` must match that list, and every import of a package goes through its published entry. A package's tests may import another package that the package declares, since tests compose what they test and never ship; the standalone template and `tools/composition` compose every package and are not held to the rule.

`packages/session` exports `establishSession` and `answerInterruption` today for a peer: the MFA package, which is to finish a login with them. The session-admission ADR planned that as an import (its D5 and §7), which the rule above would count as a new edge. #728 decided that the MFA package reaches them through a slot instead: core declares the contract, `loginCompletion` (`packages/core/src/session-admission/login-completion.mts`), the session package's login-completion module provides it over the deployment's `csrfGuard`, and the MFA package is to require it. Until the MFA package does, the two stay exported.

## Development Process

- All feature work and bug fixes **must** follow TDD (Test-Driven Development).
- Write the failing test first. Watch it fail. Then write the minimal code to make it pass.
- Never write production code without a failing test that demands it.
- If code was written before its test, delete it and start over from the test.
- When generating implementation plans, every task must include explicit RED → GREEN → REFACTOR steps.

## Workspace Scripts

- Every workspace under `packages/**`, `templates/**`, `tools/**`, and `create-app` **must** define a `test` script.
- The root `test` and `test:coverage` scripts are the local entry points. `test` carries no `--if-present`; do not add one (#88). pnpm's recursive `run` skips a workspace that lacks the script without failing, so the root script alone does not enforce the rule above — CI does.
- Coverage is a per-package concern. Only `packages/**` define `test:coverage`; a package without coverage wiring is still tested, without a report.
- CI runs each workspace's suite once, in parallel shards (`.github/scripts/test-shards.sh`), through `.github/scripts/run-workspace-suite.sh`: `test:coverage` when the workspace defines it, `test` otherwise; a workspace without `test` fails the run, even when it defines `test:coverage`. A workspace the named shards do not list runs in the `rest` shard, so a new workspace is tested without editing the shard list. The required check is `build-and-test`, which reports the `checks` job and every shard. Do not move CI back to the root `test` script: it would stop failing on a workspace without `test`.

## Umbrella E2E

[`umbrella-e2e.yml`](.github/workflows/umbrella-e2e.yml) runs the cross-component E2E suite of the umbrella repository, [o3co/auth](https://github.com/o3co/auth) (`make test-e2e`), on every pull request to `develop`: the suite at the umbrella's `develop`, the pull request's code as `PROVIDER_REV`, and auth.proxy and auth.policy-verifier at the revisions the umbrella's `Makefile` pins. The umbrella otherwise tests a pinned provider and moves the pin at release time, so a change that narrows what the provider accepts — a required config key, a stricter claim, a new status — used to break it only then.

- **Red means the pull request breaks the umbrella's contract — or the umbrella's `develop` is itself red: check its latest `e2e` run first.** For a broken contract, fix the umbrella's `tests/` first — the suite is kept forward-compatible, so change it to pass against both the pinned provider and this change, merge that to o3co/auth's `develop`, and re-run this check. Or change the pull request. The job summary names the revisions tested; the `Dump container logs on failure` step has the services' output.
- **A pull request that changes only Markdown skips it** (`paths-ignore`: `**/*.md`, `docs/**`). No Markdown reaches the image the suite builds, so such a run would only re-test `develop`, which the umbrella's nightly `e2e-develop` run does. A release cut touches only Markdown; the umbrella's pull request that moves its pin to the cut runs the suite at that commit.
- **It is not a required check** — `build-and-test` is. A required check whose workflow `paths-ignore` filtered out never reports, and blocks the pull request. So to require it, first replace `paths-ignore` with a first job that always runs and lists the changed files, and make the E2E job conditional on it (a job skipped by `if:` counts as passing); then add `umbrella-e2e` to the required status checks of `develop`'s branch protection.
- Run it on a branch from the Actions tab (`workflow_dispatch`). To reproduce it locally, clone o3co/auth, put a clone of this repository at the commit to test at `repos/auth.provider` inside it, and run `make test-e2e PROVIDER_REV=<that commit>` there.

## Local Cleanup

- The old DID grant package was deleted from git tracking and moved out of this repository. Developers with pre-deletion workspaces may still have untracked `packages/did/` build artifacts on disk; remove that directory locally before broad `git add` operations.

## Module Resolution

Each package uses Node.js [subpath imports](https://nodejs.org/api/packages.html#subpath-imports) with a conditional `development` / `default` mapping:

```json
"imports": {
  "#/*": {
    "development": "./src/*",
    "default": "./dist/*"
  }
}
```

- **Source files** use relative imports (`./`, `../`) — not `#/` aliases. This ensures published builds resolve correctly without relying on the `development` condition.
- **Test files** use `#/` imports. During `vitest run`, Vite 8+ includes `"development|production"` in its default resolve conditions, which expands to `"development"` (since `isProduction=false`), resolving `#/*` to `./src/*`. This is an implicit dependency on Vite's resolver — Node.js does not enable the `development` condition natively.
- **Cross-package references** (e.g., `oauth` importing from `core`) go through `exports`, which always point to `./dist/`. Run `pnpm -r run build` before running tests in downstream packages.
