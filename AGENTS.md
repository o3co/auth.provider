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

In `packages/core/src`, `boot/`, `federation-grants/`, `federations/`, `grants/`, `modules/manifest/`, `repositories/` and `user-sessions/` have a README of their own; every other directory directly under `src/` is described by `packages/core/src/README.md`, and every other nested directory by the README that describes its parent. `README.md` is the source of truth; a `README.ja.md` carries the same facts.

## Development Process

- All feature work and bug fixes **must** follow TDD (Test-Driven Development).
- Write the failing test first. Watch it fail. Then write the minimal code to make it pass.
- Never write production code without a failing test that demands it.
- If code was written before its test, delete it and start over from the test.
- When generating implementation plans, every task must include explicit RED → GREEN → REFACTOR steps.

## Workspace Scripts

- Every workspace under `packages/**`, `templates/**`, and `create-app` **must** define a `test` script.
- The root `test` script runs `pnpm -r run test` **without** `--if-present` on purpose: if any workspace lacks `test`, CI fails loudly rather than silently skipping it. Do not add `--if-present` here — see issue #88 for the regression this prevents.
- Coverage is a per-package concern. Only `packages/**` define `test:coverage`. The root `test:coverage` is filtered to `./packages/**` and keeps `--if-present` so that a future package without coverage wiring does not break CI.

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
