# Federation Provider Package Split Design

**Date:** 2026-04-23
**Release target:** v0.5.0
**Status:** Draft for implementation planning

## Goal

Split the built-in Google and GitHub federation providers out of
`@o3co/auth-provider-session` into one package per provider:

- `@o3co/auth-provider-federation-google`
- `@o3co/auth-provider-federation-github`

`@o3co/auth-provider-session` must own only the federation route layer and the
shared `FederationProvider` contract. It must not know concrete provider
implementations.

This is a breaking v0.5.0 change. v0.4.0 already carried TODO-F and passport
exit breakage; provider package extraction intentionally lands in the next
minor to keep migration boundaries legible.

## Decisions

### Package placement

Use the hybrid path:

- During 0.x, keep provider packages inside the `auth.provider` monorepo under
  `packages/federation-google` and `packages/federation-github`.
- Revisit repo split after the provider surface has stabilized or external
  provider maintainers need independent ownership.

Rationale:

- Shared CI and release automation already exist for `packages/*`.
- Provider packages need tight version alignment with the session contract until
  1.0.
- Tests can move with minimal tooling churn.
- Future CLI work can still map provider names to npm package names without
  requiring separate repositories.

### Ownership boundaries

Stay in `@o3co/auth-provider-session`:

- `FederationProvider`
- `FederationProfile`
- `FederationResult`
- capability interfaces and guards:
  - `SupportsRefresh`
  - `SupportsLogout`
  - `SupportsClaimMapping`
- `FederationProviderFactory`
- `createFederationProviderFactory`
- route-layer PKCE state generation and callback handling
- public federation helper utilities needed by provider packages:
  - `validateRedirect`
  - `resolveCallbackRedirect`
  - `codeChallenge`

Move out:

- `createGoogleProvider`
- `GoogleProviderConfig`
- `createGithubProvider`
- `GithubProviderConfig`
- Google/GitHub provider tests
- `openid-client` dependency used only by concrete providers

Delete:

- `registerBuiltinFederations`
- session's runtime imports from `./federations/google.mjs` and
  `./federations/github.mjs`

Do not introduce `@o3co/auth-provider-federation-common` in v0.5.0. Exporting
the small helper surface from session keeps the dependency graph simpler. A
common package can be introduced later only if multiple non-session packages
need non-contract shared code that no longer belongs in session.

### Registration model

Consumers are responsible for provider registration. `sessionModule` must accept
an explicitly configured factory:

```ts
import { createFederationProviderFactory, sessionModule } from "@o3co/auth-provider-session";
import { registerGoogleFederation } from "@o3co/auth-provider-federation-google";
import { registerGithubFederation } from "@o3co/auth-provider-federation-github";

const federationProviderFactory = createFederationProviderFactory();
registerGoogleFederation(federationProviderFactory);
registerGithubFederation(federationProviderFactory);

sessionModule({
  userRepository,
  express,
  federationProviderFactory,
});
```

`SessionModuleOptions` adds:

```ts
federationProviderFactory?: FederationProviderFactory;
```

Default behavior:

- If omitted, session creates an empty factory.
- If `config.federations` has enabled entries whose `type` is unregistered,
  boot fails with the existing adapter-factory "unknown type" error.
- The error should mention provider package registration when practical.

The current `_federationFactory` test-only option should be replaced with, or
made an alias of, the public `federationProviderFactory` option.

## Provider Package API

### Google

Package: `@o3co/auth-provider-federation-google`

Exports:

```ts
export type { GoogleProviderConfig };
export { createGoogleProvider, registerGoogleFederation };
```

Registration:

```ts
function registerGoogleFederation(factory: FederationProviderFactory): void;
```

The function registers type `"google"` and narrows builder config before calling
`createGoogleProvider`.

### GitHub

Package: `@o3co/auth-provider-federation-github`

Exports:

```ts
export type { GithubProviderConfig };
export { createGithubProvider, registerGithubFederation };
```

Registration:

```ts
function registerGithubFederation(factory: FederationProviderFactory): void;
```

The function registers type `"github"` and narrows builder config before calling
`createGithubProvider`.

Function names intentionally use `Github` to match existing code style. Package
names use lowercase `github`.

## Dependency Graph

Allowed:

```text
@o3co/auth-provider-federation-google
  -> @o3co/auth-provider-session
  -> @o3co/auth-provider-core

@o3co/auth-provider-federation-github
  -> @o3co/auth-provider-session
  -> @o3co/auth-provider-core
```

Forbidden:

```text
@o3co/auth-provider-session
  -> @o3co/auth-provider-federation-google
@o3co/auth-provider-session
  -> @o3co/auth-provider-federation-github
```

Provider packages depend on session for the public contract and helper exports.
Session must remain provider-agnostic.

## Version Policy

During monorepo development:

- package dependencies use `workspace:*`.

At publish time:

- provider packages declare `@o3co/auth-provider-session` as a peer dependency
  with the same minor line, starting with `^0.5.0`.
- provider packages also use session as a dev dependency for local tests/builds.
- `openid-client` belongs in each provider package's regular dependencies, not
  in session.

Because 0.x semver is intentionally conservative, any breaking change to
`FederationProvider` or capability types must be released in lockstep across
session and provider packages.

## Migration

Before v0.5.0:

```ts
import { sessionModule } from "@o3co/auth-provider-session";

sessionModule({ userRepository, express });
```

Google/GitHub worked because session registered built-ins internally.

After v0.5.0:

```ts
import {
  createFederationProviderFactory,
  sessionModule,
} from "@o3co/auth-provider-session";
import { registerGoogleFederation } from "@o3co/auth-provider-federation-google";
import { registerGithubFederation } from "@o3co/auth-provider-federation-github";

const federationProviderFactory = createFederationProviderFactory();
registerGoogleFederation(federationProviderFactory);
registerGithubFederation(federationProviderFactory);

sessionModule({
  userRepository,
  express,
  federationProviderFactory,
});
```

No codemod is required for v0.5.0. The migration is small enough for a guide
section in `CHANGELOG.md`, `packages/session/README.md`, and
`packages/session/README.ja.md`.

`templates/standalone` must install and register provider packages when its
default config includes Google/GitHub federation examples. If the default
template disables all federations, it can still show commented registration
examples.

## CLI Relationship

`add-federation <name>` is deferred to v0.6.0 or later.

v0.5.0 still needs to be CLI-ready:

- One provider equals one npm package.
- Registration function names follow a predictable pattern.
- README snippets show the exact install/import/register steps.
- Package names are stable enough for a future CLI registry map.

## Tests

Move provider-specific tests:

- `packages/session/src/federations/__tests__/google.test.mts`
  -> `packages/federation-google/src/__tests__/google.test.mts`
- `packages/session/src/federations/__tests__/github.test.mts`
  -> `packages/federation-github/src/__tests__/github.test.mts`

Keep in session:

- factory creation tests for empty factory behavior
- session module tests that inject a configured factory
- route tests using fake providers
- capability guard tests
- helper tests for redirect validation and PKCE helpers

Add contract checks:

- session has no import path containing `federation-google`, `federation-github`,
  `./federations/google`, or `./federations/github`
- built package declarations for session do not expose provider-specific types
- provider packages compile against only session public exports, not session
  internal subpaths

## Release and Documentation Work

Implementation planning must include:

- `pnpm-workspace.yaml` includes the new packages through existing
  `packages/*`.
- new package `package.json` files contain:
  - `exports`
  - `files`
  - `repository.directory`
  - `license`
  - `build`, `typecheck`, `test`, `test:coverage`
- root `pnpm -r run test` still passes; every workspace must define `test`.
- typedoc config includes the new packages or intentionally excludes provider
  packages with a documented reason.
- `CHANGELOG.md` has a v0.5.0 breaking migration section.
- `templates/standalone/src/app.mts` registers the provider packages.
- `create-app` scaffolding includes provider package dependencies when the
  standalone template requires them.
- downstream composition roots, especially dplaas auth repos, are searched for:
  - `registerBuiltinFederations`
  - `createGoogleProvider`
  - `createGithubProvider`

## Acceptance Criteria

- `@o3co/auth-provider-session` exposes no Google/GitHub provider factories.
- `@o3co/auth-provider-session` has no runtime dependency on `openid-client`
  unless another session-owned feature requires it.
- Google and GitHub provider packages can be used independently.
- A consumer can boot with no federation packages installed when no federations
  are enabled.
- A consumer with enabled Google/GitHub config must explicitly install and
  register the matching provider package.
- Existing Google/GitHub behavior is preserved after explicit registration.
- The default standalone template remains runnable.

## Open Follow-Ups

- Decide whether provider packages should be included in generated API docs in
  v0.5.0.
- Decide whether unregistered provider errors should be enriched in
  `AdapterFactory` globally or wrapped only by `sessionModule`.
- Revisit separate repositories after v1.0 or after a third-party-maintained
  provider appears.
