# outside

## Responsibilities
- Reads the packages outside the release an operator had pnpm install into a project: each one's record, its declaration and its files.
- Holds each to what composing it beside the release asks: one copy of the release and of zod, the app's, and nothing run when installed.

## Not here
- Fetching, authenticating and the age of a version: pnpm's, in the operator's project.
- Holding a lockfile to a record: `app-output`'s `outsideLock`. Composing the declarations beside the release: `combinations`' `combinationsWith`.
- Writing the app: `app-output`.

## Offers
- `readOutside` (project, names, release, and how pnpm is asked: its command and time): each package read (`Outside`: its declaration, its record, and its fragment, card and section defaults where it ships them), and the registries the project installs from. It refuses, naming each, every reason at once.
- `Release`: the release's version, the app's zod, and the bundle a module of the release ships in.

## Invariants
- A name is an npm package's and outside the release's scopes (`@o3co/`, `@mod/`).
- Its record (version, integrity) is the one the project's lockfile resolves from its registry; its manifest names that package and version.
- It lies where pnpm installed it, inside the project's `node_modules`, judged by path after resolving links, never by text.
- Only `package.json`, `config.example`, `README.md` and `reference.conf` are read, each a file (not a link) of at most 64 KiB.
- Its `authProvider` is of format 1, a feature, an adapter or a wiring, holding no field it does not read, each of its shape (an empty one too); it exports `./module` as node's resolver would load it for an app's import (`exported`). No package code is run.
- It runs no install script (`preinstall`, `install`, `postinstall`).
- The release's packages and zod are peers, never its dependencies of any kind, bundled or aliased (each map read on its own); no such peer is optional; each holds the release's version, zod the app's. zod is a peer, and so is the bundle of each module it needs.
- The project's lockfile resolves the manifest's dependencies as it declares them (`outsideLock`, no overrides).
- The registries are pnpm's settings in the project: `registry` (npm's when unset) and each read scope's and `@o3co`'s own, each its origin alone. What pnpm says beside its answer, and an address refused, are never told: either may hold a secret. pnpm not found, not answering in time or answering over 64 KiB is said so.

## Depends on
- `exported`; `app-output` (`outsideLock`, `namesPackages`), `combinations` (`Declaration`), `semver`; pnpm, for its settings.

## Vocabulary
- the project: where the operator had pnpm install the packages, read before generating.
- record: a package's name, version, integrity and declared dependencies, as checked here.
