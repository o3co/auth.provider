# @o3co/create-auth-provider

Last updated: 2026-09-24

CLI scaffolder for auth.provider. Generates a new standalone server project from the built-in template.

## Responsibility

**Role.** The `npx` entry point that turns the in-repo template
[`templates/standalone`](../templates/standalone) into a new, independent
project. It runs once, on the operator's machine; nothing in the generated
project imports it, and it imports none of the `packages/*` libraries.

**Owns.** Project-name and directory validation, copying the template,
rewriting the generated `package.json` (name, `workspace:*` → published
versions), writing the project's `pnpm-workspace.yaml`, and the one-time
`pnpm-lock.yaml` resolution.

**Does not own.** The content of the generated project — source, config,
Dockerfile, tests — which is the template's (edit `templates/standalone`, not
this package). Runtime behaviour belongs to `@o3co/auth-provider-core` and the
libraries the template depends on.

**Why a separate package.** It is published on its own with a `bin`, so it can
be run with `npx` without installing the provider. The monorepo is not in the
published tarball, so the package carries its own copy of the template and of
the library versions it pins ([How the template is bundled](#how-the-template-is-bundled)).

## Usage

```bash
npx @o3co/create-auth-provider <project-name> [--dir <dir-name>] [--no-lockfile]
```

`<project-name>` may be either a scoped npm name (`@scope/pkg`) or an unscoped name (`pkg`).

Unscoped example:

```bash
npx @o3co/create-auth-provider my-auth-server
cd my-auth-server
pnpm install
```

Scoped example (directory defaults to the package portion `auth.provider`):

```bash
npx @o3co/create-auth-provider @my-org/auth.provider
cd auth.provider
pnpm install
```

Override the directory name with `--dir`:

```bash
npx @o3co/create-auth-provider @my-org/auth.provider --dir provider
cd provider
```

`--no-lockfile` skips the lockfile step (step 7 below).

The generated project is a pnpm project: its `Dockerfile` installs with
`pnpm install --frozen-lockfile`, and its build allowlist lives in
`pnpm-workspace.yaml`.

The CLI's closing message suggests `pnpm run debug` next. On the scaffold's
defaults alone that does not boot: it reads no `.env` file (only the compose
files do), and needs from the shell's environment an issuer
(`OAUTH_JWT_ISSUER`), a signing key pair, a session secret, the two URLs of
your user service (`CLIENT_USER_AUTHENTICATE_URL`,
`CLIENT_USER_AUTHENTICATE_BY_TOKEN_URL`) and a Redis on `localhost:6379`. The
template's README, which the project carries, gives the commands under
[Usage](../templates/standalone/README.md#usage).

## What It Does

1. Validates `<project-name>` (see [Validation Rules](#validation-rules)).
2. Derives the target directory name: `--dir <value>` if given, else the unscoped part of a scoped name, else the name itself.
3. Resolves the target directory as `<cwd>/<dir-name>`, and errors if it already exists.
4. Copies the bundled template to the target directory, excluding `node_modules/` and `dist/`, and restores its `.gitignore` (the tarball carries it as `gitignore`, because npm drops a file named `.gitignore` from a published package).
5. Rewrites `package.json` in the generated directory:
   - Sets `name` to `<project-name>` verbatim (scope-preserving).
   - Keeps `"private": true` on purpose: a scaffolded identity provider should not be publishable by accident. Remove the field yourself if you really intend to publish.
   - Replaces each `workspace:*` version in `dependencies`, `devDependencies` and `peerDependencies` with `^<version>` from the bundled `versions.json`.
6. Writes `pnpm-workspace.yaml` with the `onlyBuiltDependencies` allowlist for `bcrypt` — pnpm 10.29 and later read that allowlist only from this file, in a single-package project too.
7. Resolves the dependency set into `pnpm-lock.yaml` (`pnpm install --lockfile-only --ignore-workspace`, through `corepack pnpm` when `pnpm` is not on `PATH`), unless `--no-lockfile` was passed. This needs a reachable registry; a failure prints a warning and the scaffold still completes.
8. Prints next-step instructions.

### The generated `pnpm-lock.yaml`

The template's `Dockerfile` installs with `pnpm install --frozen-lockfile`, so
the generated project needs a lockfile to build at all. It cannot ship with the
template: until step 5 has replaced every `workspace:*` with a published
version, the dependency set the lockfile would have to pin does not exist. So
it is resolved once, here, against the rewritten `package.json`. **Commit it** —
it is what makes `docker build` reproducible. If step 7 failed or was skipped,
run `pnpm install` in the project once and commit the result.

## How the template is bundled

The package's `prebuild` and `prepack` scripts run
[`scripts/copy-templates.mjs`](scripts/copy-templates.mjs), which copies
`templates/standalone` into `create-app/templates/standalone` (git-ignored;
`node_modules/` and `dist/` excluded) and writes `create-app/templates/versions.json`,
the current version of every published `@o3co/auth-provider-*` package. The
tarball ships both (`files: ["dist", "templates"]`), and `scaffold()` reads
them from there. A scaffold is therefore the template as it was when this
package was built, pinned to the library versions of that same build.

CI runs [`scripts/check-versions-json.mjs`](scripts/check-versions-json.mjs),
which fails when a published package under `packages/` is missing from
`copy-templates.mjs`'s version list, or the list names one that no longer
exists — a scaffold would otherwise fail to resolve that package's
`workspace:*` version.

## Validation Rules

`<project-name>` must match one of:

- Unscoped: `^[a-z0-9][a-z0-9-._~]*$`
- Scoped: `^@[a-z0-9][a-z0-9-._~]*/[a-z0-9][a-z0-9-._~]*$`

Both forms must be non-empty, not `.` or `..`, and ≤ 214 characters.

`--dir <value>` must match the unscoped pattern above (same constraints).

## Known Limitations

- The bundled template's `README.md` / `README.ja.md` carry the upstream title `@o3co/auth-provider-standalone`. When generating a scoped project, that title will not match your `package.json` name; edit it manually if it matters for your use case.
- The template's README links into this repository with relative paths (`../../docs/…`, `../../packages/…`). Those resolve in the monorepo and not in a scaffolded project, where there is no `docs/` or `packages/` beside it; read them on GitHub instead.

## Generated Structure

The generated project is a complete copy of
[`templates/standalone`](../templates/standalone) (without `node_modules/` and
`dist/`) plus `pnpm-workspace.yaml` (step 6) and, unless `--no-lockfile` was
given or the lockfile step failed, `pnpm-lock.yaml` (step 7). The template's README describes its layout — which file is
the composition, which is the host process, and what the scaffold owns.

## Programmatic API

The module exports the functions the CLI is built from; their signatures are
in [`src/index.mts`](src/index.mts).

- `scaffold(targetDir, projectName)` — steps 4–6. Throws if the bundled template is missing or a `workspace:*` dependency has no entry in `versions.json`.
- `generateLockfile(targetDir)` — step 7. Returns `{ ok: true, command }` or `{ ok: false, reason }` rather than throwing.
- `main()` — the CLI: reads `process.argv`, and exits non-zero on an invalid argument or an existing directory.
- `isValidProjectName(name)` / `isValidDirName(name)` — the [Validation Rules](#validation-rules).

## See Also

- [`@o3co/auth-provider-standalone`](../templates/standalone) — The template this tool generates from
- [`@o3co/auth-provider-core`](../packages/core) — Core application factory
