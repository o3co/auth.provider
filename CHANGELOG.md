# Changelog

Notable changes, newest first, in the form of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Release candidates have sections of their own; what an operator must do for each change is in the [migration guide](docs/migration.md).

Changes up to 0.17.0 are in [the 0.17.0 changelog](https://github.com/o3co/auth.provider/blob/v0.17.0/CHANGELOG.md).

## [0.18.0-rc.2] - Unreleased

What to change from rc.1 is in [From 0.18.0-rc.1](docs/migration.md#from-0180-rc1).

### Security

<!-- The kinds of hole closed since rc.1, by module, once this version's security review ends. -->

### Changed

- **Breaking**: time and size settings are written with a unit, and lost their unit suffixes.
- **Breaking**: the sealing keys are `seal.current` and `seal.previous`; `seal.keys` is refused.
- **Breaking**: a subject is 1 to 255 ASCII characters.
- **Breaking**: each JWT bearer issuer says how its assertions' subject is read.
- **Breaking**: an upstream link in the settings names an upstream a composed module declares.
- **Breaking**: under `required`, boot is refused unless a composed second factor counts and adds one.
- **Breaking**: the routes that manage factors come from the `mfa-management` module.
- **Breaking**: `introspect.store_unavailable` is now `introspection.unavailable`.
- **Breaking**, for modules and adapters of your own: the `store` contract lost the calls nothing used, `Cookies.read` is replaced by `lookup`, and `secretChecker` by `secretCheckers`.
- A written link to an upstream identity lets in only a subject the users or the ledger know.
- Removing a factor or reissuing recovery codes asks for a second factor proven recently.
- A first factor bound while another was bound meanwhile is refused, not bound beside it.
- `federation-tokens` answers a refresh the upstream refuses until the user acts there with `403 upstream_interaction_required`.
- A managed Redis that refuses `CONFIG` is declared in `redis.server-settings`.
- A configuration file that does not parse is refused at its line and column.
- The command that generates an app is `create-auth-provider`.

### Added

- `subject-revocation-http`: an outside ledger ends a user's sessions and tokens here.
- `federation-grants.sweep-interval`: each instance erases the credentials of ended grants, though no request reads them.
- `users-http.subject-url`, for a ledger that looks users up by subject; `verify-url` is now optional.
- `idp-google.hosted-domains`.

## [0.18.0-rc.1] - 2026-10-17

A rewrite of 0.17 as modules assembled by a generated app, published as one package per concern under new names. Configuration is rewritten, stored state does not carry over, and several settings and requests that 0.17 accepted are refused. Read the [migration guide](docs/migration.md) before moving a 0.17 deployment.
