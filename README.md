# auth-provider

[![CI](https://github.com/o3co/auth.provider/actions/workflows/ci.yml/badge.svg?branch=develop)](https://github.com/o3co/auth.provider/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@o3co/create-auth-provider/next)](https://www.npmjs.com/package/@o3co/create-auth-provider)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

An OAuth 2.0 and OpenID Connect provider, built from small modules that a generated app assembles. You choose the modules a deployment needs; each one brings its routes, its settings and its stores, and refuses to boot when what it needs is missing.

0.18 is a rewrite of 0.17 under new package names. To move a 0.17 deployment, read the [migration guide](docs/migration.md) first.

## What it does, and what it leaves to others

The provider holds the signing keys and the session state, so relying parties never hold a key that can mint tokens, and the layers that decide and enforce access can change on their own.

It does:

- **Sign users in and keep their sessions**: by password checked against your user ledger, through upstream identity providers (OpenID Connect, Google, GitHub, Apple), or by passkey; with a second factor (an authenticator app, a code by email, recovery codes, a security key) when you compose one. It ends sessions by logout, including logout started by a relying party.
- **Authenticate clients**: by secret, by signed assertion, as public clients with PKCE, and by client ID metadata documents.
- **Issue and manage tokens**: authorization code, refresh, client credentials, JWT bearer, device authorization and token exchange grants; ID tokens and userinfo; consent; introspection and revocation; tokens bound to a key (DPoP) or a certificate (mTLS).
- **Publish** its signing keys and its discovery document.
- **Hold** the tokens upstream providers issue, and the grants users give to use them.
- **Send mail** for the email second factor and for proving an account's address.

It leaves to others:

- **Deciding** what a token allows: the policy verifier.
- **Enforcing** that decision inside services: the service interceptors, or a token-validating proxy in front.
- **The user ledger**: who the users are and their passwords. The provider asks your ledger (over HTTP, or a list in its settings) and keeps only what it needs beside it, such as links to upstream identities and proven contacts.
- **Pages**: the login and consent pages are the deployment's.
- **Sign-up and account recovery.**

## Quick start

Generate a deployment from one of the patterns:

```sh
npx @o3co/create-auth-provider@next my-provider --pattern simple-web
cd my-provider
```

Then follow the generated `README.md`. It names the settings the pattern needs, and the project comes with a Dockerfile.

- **Patterns.** Each pattern is one kind of deployment; `simple-web`, a password login, needs no outside system. The [patterns card](modules/scaffold/create-app/src/patterns/README.md) and each pattern's own card say what they are for, and a name not known is refused with the names that are. `--add` adds a feature to a pattern, and `--help` tells the other options.
- **Your own selection.** Name the modules instead of a pattern, and the app assembles those, with the wirings and bridges they need added for you.

The [create-app card](modules/scaffold/create-app/README.md) describes what is generated.

## How it is built

- **Modules.** Each concern is one module under `modules/<group>/<name>`. Its README, the module's card, is its contract: what it does, what it offers, what it promises, and what it depends on.
- **The owner map.** [modules/README.md](modules/README.md) says which module owns each contract, setting, extension point and word. Look things up there before searching.
- **The kernel.** Modules declare contracts and extension points and contribute to others' through the [kernel](modules/foundation/kernel/README.md), which boots them, reads their configuration sections and refuses boot with every problem at once.
- **Composition.** [combinations](modules/scaffold/combinations/README.md) decides which wirings, adapters and bridges come with a selection.
- **The guard.** `pnpm check` runs the [guard](modules/tooling/guard/README.md), which holds the workspace to its rules: dependency direction, the public surface of each package, and the size of each module and its card.

## Extending

A module of your own is assembled the same way as the provided ones:

- **Contracts and extension points** are described in the [kernel card](modules/foundation/kernel/README.md); each feature's card lists the extension points it offers.
- **Adapters and bridges** declare what they stand in for or join in their manifest, as [combinations](modules/scaffold/combinations/README.md) describes.
- **Contract tests.** Each module publishes its contract tests at `./testing`, for an implementation of your own to run against.

## Packages

0.18 is published as one package per concern, `@o3co/auth-provider-<concern>`, all at the same version, with each module as a subpath. You rarely name them yourself: the generated app depends on what it composes. The [migration guide](docs/migration.md#packages) maps the 0.17 packages to these.

## Configuration

Each module reads its own section of HOCON configuration, and refuses boot on an unknown key, a section for a module that is not loaded, or a value it cannot use. A project generated from a pattern reads its scalar settings from the environment; the [configuration reference](docs/configuration.md) lists every key, its default and what it means.

## Operating

- [Operations runbook](docs/runbook.md): what the deployment must provide, Redis, rotating keys, upgrading, revoking a user, stopping.
- [Security model](docs/security-model.md): what the provider guarantees, and what it leaves to the deployment.
- [Audit events](docs/audit-events.md): every event and its attributes.
- [Configuration reference](docs/configuration.md).
- [Migrating from 0.17](docs/migration.md).

## Versions

Releases before 1.0 may break in a minor version; each breaking release has a migration guide. Release candidates are published under the npm `next` tag.

## Development

```sh
pnpm install
pnpm check
```

`pnpm check` runs the type check, lint, tests, the guard and the distribution check. Tests that need Docker run with `pnpm test:integration`.

## Related projects

- [auth](https://github.com/o3co/auth): the umbrella repository, with the architecture and end-to-end tests across components.
- [auth.policy-verifier](https://github.com/o3co/auth.policy-verifier): the policy engine that makes authorization decisions.
- [auth.proxy](https://github.com/o3co/auth.proxy): an optional reverse proxy that validates tokens in front of services.
- [protobuf.interceptors](https://github.com/o3co/protobuf.interceptors): authorization inside gRPC and ConnectRPC services, asking this provider to introspect and the policy verifier to decide.

## License

[Apache License 2.0](LICENSE).

Copyright 2026 1o1 Co. Ltd. Licensed under the Apache License, Version 2.0.
