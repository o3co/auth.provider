# Changelog

Notable changes, newest first, in the form of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). What an operator must do for each change is in the [migration guide](docs/migration.md).

Changes up to 0.17.0 are in [the 0.17.0 changelog](https://github.com/o3co/auth.provider/blob/v0.17.0/CHANGELOG.md).

## [0.18.3] - 2026-10-23

### Security

- `address-reach`: four cloud addresses in `fc00::/7` were taken as private, so `outbound.internal-hosts` and `outbound.plain-internal` reached them where a listed name came to resolve there: AWS EKS Pod Identity's credential endpoint over IPv6 (`fd00:ec2::23`), and the metadata services over IPv6 of Akamai Cloud (Linode, `fd00:a9fe:a9fe::1`), Scaleway (`fd00:42::42`) and Oracle Cloud (`fd00:c1::a9fe:a9fe`). Each is now refused as a special address, as the other cloud metadata addresses are.
- `address-reach`: Azure's platform address `168.63.129.16`, public but the host node's in every region (WireServer, the platform's DNS and DHCP), was reached under `outbound.allow-any-public`, or through an allowed name that came to resolve there; it is now refused as a special address.

## [0.18.2] - 2026-10-22

### Added

- `outbound.plain-ipv4`, a list of `host:port` pairs of `plain-loopback` or `plain-internal`: plain http to such a pair resolves its name to IPv4 addresses alone, checks every one of them and reaches the first, and neither checks nor reaches an IPv6 one. With ECS Service Connect, which writes each name in the hosts file with an IPv4 address and an IPv6 one that in the environment reported does not reach, a `plain-internal` pair was refused as `plain-public`; naming it here too takes it. A pair is named by its host name, never an address. Unset, nothing changes. A configuration naming the key is refused at boot by an earlier version, which does not know it.

### Fixed

- A generated app's `witness-backfill` script told a refused boot by the kernel's class, so where the kernel was bundled twice it threw the refusal on as a crash instead of writing each refusal and exiting 78, as the app's entry and `reseal` already did; it now tells it by the kernel's mark (`BootRefused.is`). An app generated before changes one line of `src/witness-backfill.ts`, as [From 0.18.1](docs/migration.md#from-0181) says, or is generated again.

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
