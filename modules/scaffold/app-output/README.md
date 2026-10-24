# app-output

## Responsibilities
- Writes a generated project: a deployment of the modules it is given, with its configuration from their fragments, the environment's and the local layer's examples, an image and the operator's guide.
- Maps each fragment's keys to the environment and the local layer, through the internal module `fragments`: the boundary that keeps module words out of the environment's.
- Holds what every generated project shares: the target's check, the package name check, the manifest, the app's entry and its entries besides `start` (`reseal`, `witness-backfill`, `passkey-backfill`).
- States what it takes from where the packages come from (`Packages`); the caller implements it.

## Not here
- Where the packages come from (a workspace or a bundle's index), and what the app depends on to have them: the caller's, through `Packages`.
- Which modules a project composes, and the values of its guide's template marks of its own (a pattern's use and card, the full template's opt-ins): the caller's.
- What each module's configuration means, and its fragment (`config.example` beside its package.json): each module's.

## Offers
- `writeDeployment(target, modules, packages, readme)`: writes the project assembling `modules`, the kernel and `config-files` first, from `packages` into `target`.
  - It writes the manifest and app, the configuration file, the local layer's and the environment's examples, a Dockerfile, a `.dockerignore`, a `.gitignore`, a README from `readme`'s template in `templates/` and values, and `AGENTS.md`.
  - Its guide templates are `full-readme.md`, `pattern-readme.md` and `listed-readme.md`; the caller fills each one's own marks (the full template's opt-ins; a pattern's name, use, card, choices, receivers and deployment; a listed app's list, choices and the values the operator decides).
  - The README lists each composed module's card as installed, and points at the `## Deployment` section of each card that has one, and at the release's walk to a first login where its repository is stated.
  - `AGENTS.md` indexes where each composed module's card and section defaults lie as installed, and where the release's configuration and route references lie; it states nothing of its own.
- `Packages`: each name's fragments, the app's dependencies for the names, what the app imports a name under, each name's card as installed (`Card`), and the release (`Release`).
- `namesPackages` and `vacant`, for a caller to refuse a plan before it composes; `mainSource`, the app's entry; `kernel` and `configFiles`, the packages every app depends on (its entry reads its configuration files through `config-files`).
- `fragmentsIn`, `fragmentsOf`, `fragmentFile` and `settingsOf`: the internal module `fragments`'s.
- `outsideLock`: see the internal module `lockfile`.
- `Packages.outside`, where the caller has packages outside the release: what the app is given beside them, see the internal module `outside`; `appZod`, the zod every app depends on.

## Invariants
- A target that holds anything is refused, never overwritten; a missing or empty one is taken. Every file is made before any is written.
- A name not an npm package is refused by `namesPackages`, before anything is written.
- The manifest names the pnpm the workspace builds with, and the app also depends on `zod` at the packages' version.
- A scalar its owner's example gives in several lines is still read from env, but left out of the env example and listed among the keys written in the local layer; the guide and the env example say such a value goes in the local layer.
- With `seal` composed, the project has a `reseal` script: the same modules, built and never started, running their resealers.
- With `mfa-witnessing` composed, the project has a `witness-backfill` script, built and never started the same way. It settles each subject read from standard input, one a line, empty lines skipped, each other line used as sent, through `witnessBackfill`, and writes only how many were marked, held, none, unclaimed, inconsistent, unknown (an answer it does not know) and failed (unavailable), never a subject.
- The `witness-backfill` script exits 0 where none failed and none was unknown, else 1, and 78 on a refused boot, told by the kernel's mark as the app's is.
- With `passkey-witnessing` composed, the project has a `passkey-backfill` script, read and exiting as `witness-backfill` does, through `passkeyBackfill`: it writes only how many were marked, held, none, pending, inconsistent, unknown and failed.
- Git leaves out every env file but `.env.example`, the local layer, `*.pem` and `*.key`; the image's build context leaves out those, `.env.example` and `.git`.
- The image follows Node 24's latest, neither patch nor digest pinned, so a build takes Node's security fixes over repeating the last build; it pins corepack by version, installs the locked production dependencies in a stage of their own, and runs node under `tini` as a user other than root.
- Only an app composing `http` is given its port and interface in the image and the guide, and only one composing `http-ops` is checked for liveness (`/_healthcheck`, after a start period) or told of its endpoints.
- The app reads the configuration files `APP_CONFIG` lists, comma-separated, layered in order; the generated configuration file when unset.
- The app exits 78 on a refused boot, told by the kernel's mark (`BootRefused.is`), writing each refusal on standard error.
- The app's entries check, as they boot, the variables 0.17 read that the environment sets and no configuration file reads, by `config-files`' `legacyVariablesCheck` alone: its warning goes once to standard error as `warn config-files:` and boot goes on; its refusal refuses boot. `APP_LEGACY_VARIABLES` (`warn`, `refuse`, `ignore`) chooses, read there.
- SIGTERM or SIGINT stops the app, draining; one that comes while it starts stops it once started.

## Data
- Writes the target only; reads its templates and the fragment files it is pointed at.

## Depends on
- The HOCON library, through `fragments`.

## Vocabulary
- output: a project written from the templates.
- fragment: a module's example of its section, placeholders only; a secret's is `REPLACE-…` text its section refuses.
- local layer: the operator's configuration file layered first, for lists and values the environment does not carry.
