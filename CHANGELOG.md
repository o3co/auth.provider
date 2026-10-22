# Changelog

Notable changes, newest first, in the form of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). What an operator must do for each change is in the [migration guide](docs/migration.md).

Changes up to 0.17.0 are in [the 0.17.0 changelog](https://github.com/o3co/auth.provider/blob/v0.17.0/CHANGELOG.md).

## [Unreleased]

### Added

- `tokens` offers the access-token lifetime it applies where a grant gives none, as `accessTokenLifetimeSeconds()` on its contract. A grant with a lifetime ceiling can read it at build time and refuse boot, naming both values, when it is above the ceiling (#2076). An implementation of `Tokens` of your own adds the member, and the `./testing` contract test now checks it against the issued `expiresIn`.

## [0.18.1] - 2026-10-22

### Security

- A generated app pins pnpm 11.28.7 in its manifest (`packageManager`), which its image installs with, and the repository builds with it; both named 11.3.0. The 2026-10-21 pnpm security release refuses registry metadata that names another package than the one asked for, applies `trustPolicy` to the pinned pnpm, and caps a package's unpacked size (`maxTarballUnpackedSize`). An app generated before changes its `packageManager` to `pnpm@11.28.7`, as [From 0.18.0](docs/migration.md#from-0180) says.

## [0.18.0] - 2026-10-22

A rewrite of 0.17 as modules assembled by a generated app, published as one package per concern under new names. Configuration is rewritten, stored state does not carry over, and several settings and requests that 0.17 accepted are refused. Read the [migration guide](docs/migration.md) before moving a 0.17 deployment.

**Release candidates.** `0.18.0-rc.1` to `0.18.0-rc.5` were pre-releases, published on npm under the `next` dist-tag. This section covers every change since 0.17.0 and supersedes them; what each candidate changed is in [the 0.18.0-rc.5 changelog](https://github.com/o3co/auth.provider/blob/v0.18.0-rc.5/CHANGELOG.md). A deployment on a candidate reads the migration guide's section from its candidate, beginning at [From 0.18.0-rc.1](docs/migration.md#from-0180-rc1), and each after it; the changes since rc.5 are below.

### Security

- A generated app's image builds on `node:24-alpine`, Node 24's latest, with neither patch nor digest pinned, so each build takes Node's security fixes; it pinned Node 24.21.0, which the 2026-10-21 Node.js security release left vulnerable. An app generated before changes its Dockerfile's `FROM` to `node:24-alpine` and builds its image again. See [From 0.18.0-rc.5](docs/migration.md#from-0180-rc5).

### Changed

- **Breaking**, for a Redis store, since rc.5: `redis` refuses boot, named, where `redis.replication` is set and the confirming connection reaches another server than the operations, as a DNS name or a load balancer over several servers may send it, and where the server cannot run the store's scripts, as one whose Lua lacks `cjson`; rc.5 booted and answered `503` to the writes. Either, found later, makes `/readyz` answer `503`, named under `redis.settings_unmet`. See [From 0.18.0-rc.5](docs/migration.md#from-0180-rc5).
