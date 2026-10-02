# @o3co/create-auth-provider

Last updated: 2026-10-03

CLI scaffolder for auth.provider. Generates a new server project from one of the built-in templates.

## Responsibility

**Role.** The `npx` entry point that turns one of the in-repo templates under
[`templates/`](../templates) — each a deployable composition root — into a new,
independent project. It runs once, on the operator's machine; nothing in the generated
project imports it, and it imports none of the `packages/*` libraries.

**Owns.** Project-name, directory and template validation, copying the
chosen template, making the copy the one with MFA or without it by what the
template marks ([With or without MFA](#with-or-without-mfa)), rewriting the
generated `package.json` (name, `workspace:*` → published versions, the MFA
package dropped without MFA), writing the project's `pnpm-workspace.yaml`,
and the one-time `pnpm-lock.yaml` resolution.

**Does not own.** The content of the generated project — source, config,
Dockerfile, tests — which is the template's (edit `templates/<name>`, not
this package), what of it is MFA's included; and which templates there are, and what each is for — the
[composition templates ADR](../packages/core/docs/adr/2026-09-29-composition-templates.md).
Runtime behaviour belongs to `@o3co/auth-provider-core` and the libraries the
template depends on.

**Why a separate package.** It is published on its own with a `bin`, so it can
be run with `npx` without installing the provider. The monorepo is not in the
published tarball, so the package carries its own copy of every template and
of the library versions they pin ([How the templates are bundled](#how-the-templates-are-bundled)).

## Usage

```bash
npx @o3co/create-auth-provider <project-name> [--template <name>] [--dir <dir-name>] [--no-lockfile] [--no-mfa]
```

`--template` names the template to copy, `standalone` by default. The
templates are the directories under [`templates/`](../templates) that hold a
`package.json` (not a symbolic link, not dot-named), and the CLI refuses any
other name, listing the ones it has.
What each template is for is in its own README; how the set is drawn — a
template per composition shape, not per feature — is in the
[composition templates ADR](../packages/core/docs/adr/2026-09-29-composition-templates.md).

```bash
npx @o3co/create-auth-provider my-auth-server --template standalone
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

`--no-mfa` scaffolds a project without MFA: `@o3co/auth-provider-mfa` is not a
dependency, nothing in the project imports it, and the MFA configuration, the
development MFA key, the Mailpit overlay and the tests that need MFA are left
out ([With or without MFA](#with-or-without-mfa)). Its MFA switch is fixed
off: `MFA_MODE` or a file's `mfaMode` other than `off`, and an `mfa.mode` the
configuration writes other than `off`, are refused before boot, so the
project never runs while its configuration asks for a second factor. To add
MFA later, compare with a scaffold made without the flag.

```bash
npx @o3co/create-auth-provider my-auth-server --no-mfa
```

The generated project is a pnpm project: its `Dockerfile` installs with
`pnpm install --frozen-lockfile`, and its build allowlist lives in
`pnpm-workspace.yaml`.

The CLI's closing message suggests `pnpm run debug` next. On the scaffold's
defaults alone that does not boot: it reads no `.env` file (only the compose
files do), and needs from the shell's environment an issuer
(`OAUTH_JWT_ISSUER`), a signing key pair, a session secret, the two URLs of
your user service (`REPOSITORIES_USER_HTTP_AUTHENTICATE_URL`,
`REPOSITORIES_USER_HTTP_AUTHENTICATE_BY_TOKEN_URL`) and a Redis on `localhost:6379`. The
template's README, which the project carries, gives the commands under
[Usage](../templates/standalone/README.md#usage).

## What It Does

1. Validates `<project-name>` (see [Validation Rules](#validation-rules)).
2. Derives the target directory name: `--dir <value>` if given, else the unscoped part of a scoped name, else the name itself.
3. Checks that `--template` (default `standalone`) names a bundled template, and resolves the target directory as `<cwd>/<dir-name>`, erroring if it already exists.
4. Copies the named template to the target directory, excluding `node_modules/` and `dist/`, restores its `.gitignore` (the tarball carries it as `gitignore`, because npm drops a file named `.gitignore` from a published package), and makes the copy the one with MFA, or without it under `--no-mfa` ([With or without MFA](#with-or-without-mfa)).
5. Rewrites `package.json` in the generated directory:
   - Sets `name` to `<project-name>` verbatim (scope-preserving).
   - Keeps `"private": true` on purpose: a scaffolded identity provider should not be publishable by accident. Remove the field yourself if you really intend to publish.
   - Without MFA, removes `@o3co/auth-provider-mfa` from `dependencies`, `devDependencies` and `peerDependencies`.
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

## How the templates are bundled

The package's `prebuild` and `prepack` scripts run
[`scripts/copy-templates.mjs`](scripts/copy-templates.mjs), which copies
every template into `create-app/templates/<name>` (git-ignored; `node_modules/`
and `dist/` excluded; the destination is rebuilt whole, so a template removed
from the repository does not linger) and writes `create-app/templates/versions.json`, the current version
of every published `@o3co/auth-provider-*` package. The tarball ships both
(`files: ["dist", "templates"]`), and `scaffold()` reads them from there. A
scaffold is therefore the template as it was when this package was built,
pinned to the library versions of that same build.
What a template is — a directory under `templates/`, not a symbolic link and
not dot-named, holding a `package.json`, named in lowercase kebab-case — is
defined once, in [`scripts/templates.mjs`](scripts/templates.mjs), which the
copy and CI's build of every template both use; the scaffolder's
`availableTemplates()` reads the copy by the same rule.
[`published-package.test.mts`](src/__tests__/published-package.test.mts)
packs the package and holds the tarball to the repository: it must ship every
template, and each must scaffold from it.

CI runs [`scripts/check-versions-json.mjs`](scripts/check-versions-json.mjs),
which fails when a published package under `packages/` is missing from
`copy-templates.mjs`'s version list, or the list names one that no longer
exists — a scaffold would otherwise fail to resolve that package's
`workspace:*` version.

## With or without MFA

A template is written with MFA, and says what of it is MFA's; the scaffolder
applies what it says ([`src/internal/mfa-variant.mts`](src/internal/mfa-variant.mts)):

- `<name>.no-mfa.<ext>` is the twin of `<name>.<ext>` beside it: without MFA
  it takes that file's place; with MFA it is dropped. The standalone
  template's twin of its MFA switch, `src/mfaSwitch.no-mfa.mts`, is the one
  file that differs; `src/__tests__/mfa-switch.test.no-mfa.mts` is that
  switch's tests.
- A line holding `no-mfa:omit-file`, in any comment syntax, leaves its file
  out without MFA.
- The lines from one holding `no-mfa:omit-begin` to one holding
  `no-mfa:omit-end` are left out without MFA. Blocks do not nest.

The marker lines are dropped either way, so a scaffold with MFA is the
template as written. A twin with no target, an unbalanced block, or a
`no-mfa:omit-*` token it does not know refuses the scaffold, naming the file,
before any file changes.

[`scaffold-runs.test.mts`](src/__tests__/scaffold-runs.test.mts) scaffolds
the default template with MFA and without it, links each to the workspace's
packages (the MFA package left out without MFA), and typechecks it and runs
its own suite, which boots its composition; `index.test.mts` holds the
scaffold without MFA to naming the MFA package nowhere and no file it leaves
out. An MFA test or reference added to the template without a marker fails
there.

## Validation Rules

`<project-name>` must match one of:

- Unscoped: `^[a-z0-9][a-z0-9-._~]*$`
- Scoped: `^@[a-z0-9][a-z0-9-._~]*/[a-z0-9][a-z0-9-._~]*$`

Both forms must be non-empty, not `.` or `..`, and ≤ 214 characters.

`--dir <value>` must match the unscoped pattern above (same constraints).

`--template <name>` must be the name of a bundled template, exactly; a path is
never one. A template's name is lowercase kebab-case,
`^[a-z0-9]+(?:-[a-z0-9]+)*$` (lowercase letters and digits, in parts joined by
single hyphens); the build refuses a template named otherwise.

## Known Limitations

- Each bundled template's `README.md` / `README.ja.md` carry its upstream title, such as `@o3co/auth-provider-standalone`. When generating a scoped project, that title will not match your `package.json` name; edit it manually if it matters for your use case.
- The template's README links into this repository with relative paths (`../../docs/…`, `../../packages/…`). Those resolve in the monorepo and not in a scaffolded project, where there is no `docs/` or `packages/` beside it; read them on GitHub instead.

## Generated Structure

The generated project is a complete copy of the chosen template, such as
[`templates/standalone`](../templates/standalone) (without `node_modules/` and
`dist/`) plus `pnpm-workspace.yaml` (step 6) and, unless `--no-lockfile` was
given or the lockfile step failed, `pnpm-lock.yaml` (step 7). The template's README describes its layout — which file is
the composition, which is the host process, and what the scaffold owns.

## Programmatic API

The module exports the functions the CLI is built from; their signatures are
in [`src/index.mts`](src/index.mts).

- `scaffold(targetDir, projectName, template?, options?)` — steps 4–6, from `template` (default `DEFAULT_TEMPLATE`, `"standalone"`); `options.mfa: false` scaffolds without MFA (default `true`). Throws, before writing anything, with `templateRefusal`'s message; and throws if a `workspace:*` dependency has no entry in `versions.json`.
- `availableTemplates(templatesRoot?)` — the bundled templates' names, sorted.
- `templateRefusal(template, templates)` — why `template` cannot be scaffolded (none bundled, or not one of them), or `undefined`.
- `generateLockfile(targetDir)` — step 7. Returns `{ ok: true, command }` or `{ ok: false, reason }` rather than throwing.
- `main()` — the CLI: reads `process.argv`, and exits non-zero on an invalid argument, an unknown template or an existing directory.
- `isValidProjectName(name)` / `isValidDirName(name)` — the [Validation Rules](#validation-rules).

## See Also

- [`templates/`](../templates) — The templates this tool generates from; [`@o3co/auth-provider-standalone`](../templates/standalone) is the default
- [Composition templates ADR](../packages/core/docs/adr/2026-09-29-composition-templates.md) — Why the templates are split as they are
- [`@o3co/auth-provider-core`](../packages/core) — Core application factory
