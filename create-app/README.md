# create-o3co-auth-provider

CLI scaffolder for auth.provider. Generates a new project from the standalone template.

## Usage

```bash
npx create-o3co-auth-provider <project-name>
```

Example:

```bash
npx create-o3co-auth-provider my-auth-server
cd my-auth-server
npm install
npm run debug
```

## What It Does

1. Validates the project name.
2. Resolves the target directory as `<cwd>/<project-name>`.
3. Errors if the directory already exists.
4. Copies `templates/standalone/` to the target directory, excluding `node_modules/` and `dist/`.
5. Rewrites `package.json` in the generated directory:
   - Sets `name` to the given project name.
   - Removes the `private` field.
   - Replaces all `workspace:*` version references with published semver versions from `versions.json`.
6. Prints next-step instructions.

## Validation Rules

The project name must satisfy all of the following:

- Must not be `.` or `..`
- Must not contain path separators (`/` or `\`)

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
import { scaffold, main } from "create-o3co-auth-provider";

// Generate a project at an absolute path
scaffold(targetDir: string, projectName: string): void;

// CLI entry point — reads process.argv and exits on error
main(): void;
```

`scaffold` throws if the template directory is missing or if a `workspace:*` dependency cannot be resolved in `versions.json`.

## See Also

- [`@o3co/auth-provider-standalone`](../templates/standalone) — The template this tool generates from
- [`@o3co/auth-provider-core`](../packages/core) — Core application factory
