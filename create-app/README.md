# @o3co/create-auth-provider

CLI scaffolder for auth.provider. Generates a new project from the standalone template.

## Usage

```bash
npx @o3co/create-auth-provider <project-name> [--dir <dir-name>]
```

`<project-name>` may be either a scoped npm name (`@scope/pkg`) or an unscoped name (`pkg`).

Unscoped example:

```bash
npx @o3co/create-auth-provider my-auth-server
cd my-auth-server
npm install
npm run debug
```

Scoped example (directory defaults to the package portion `auth.provider`):

```bash
npx @o3co/create-auth-provider @my-org/auth.provider
cd auth.provider
npm install
npm run debug
```

Override the directory name with `--dir`:

```bash
npx @o3co/create-auth-provider @my-org/auth.provider --dir provider
cd provider
```

## What It Does

1. Validates `<project-name>` (see Validation Rules).
2. Derives the target directory name: `--dir <value>` if given, else the unscoped part of a scoped name, else the name itself.
3. Resolves the target directory as `<cwd>/<dir-name>`.
4. Errors if the directory already exists.
5. Copies `templates/standalone/` to the target directory, excluding `node_modules/` and `dist/`.
6. Rewrites `package.json` in the generated directory:
   - Sets `name` to `<project-name>` verbatim (scope-preserving).
   - Removes the `private` field.
   - Replaces all `workspace:*` version references with published semver versions from `versions.json`.
7. Prints next-step instructions.

## Validation Rules

`<project-name>` must match one of:

- Unscoped: `^[a-z0-9][a-z0-9-._~]*$`
- Scoped: `^@[a-z0-9][a-z0-9-._~]*/[a-z0-9][a-z0-9-._~]*$`

Both forms must be non-empty, not `.` or `..`, and ≤ 214 characters.

`--dir <value>` must match the unscoped pattern above (same constraints).

## Known Limitations

The bundled template's `README.md` / `README.ja.md` still carry the upstream title `@o3co/auth-provider-standalone`. When generating a scoped project, that title will not match your `package.json` name; edit it manually if it matters for your use case.

## Generated Structure

```
<project-name>/
├── config/
│   ├── application.conf   # HOCON config (overridable via env vars)
│   ├── clients.yaml       # OAuth client registry
│   └── clients.yaml.example
├── src/
│   └── app.mts            # Composition root
├── tests/
├── .dockerignore
├── .env.example
├── Dockerfile
├── docker-compose.yml
├── docker-compose.test.yml
├── Makefile
├── package.json
├── tsconfig.json
└── vitest.config.mts
```

After generation, fill in the required environment variables in `.env` (copy from `.env.example`).

## Programmatic API

```typescript
import { scaffold, main } from "@o3co/create-auth-provider";

// Generate a project at an absolute path
scaffold(targetDir: string, projectName: string): void;

// CLI entry point — reads process.argv and exits on error
main(): void;
```

`scaffold` throws if the template directory is missing or if a `workspace:*` dependency cannot be resolved in `versions.json`.

## See Also

- [`@o3co/auth-provider-standalone`](../templates/standalone) — The template this tool generates from
- [`@o3co/auth-provider-core`](../packages/core) — Core application factory
