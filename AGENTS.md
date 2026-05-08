# Project Guidelines

## Language

- All source code, comments, variable names, function names, test descriptions, and commit messages must be written in **English only**.
- Responses to the user may be in any language.

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
