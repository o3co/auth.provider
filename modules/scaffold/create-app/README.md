# create-app

## Responsibilities
- Generates a new project: a minimal app that assembles the modules asked for through their `./module`, with the wirings and bridges `combinations` adds by default.
- Generates the full template: what `combinations` composes in full, with the features added, its configuration from the modules' fragments, an image and the operator's guide.
- Generates a pattern's deployment the same way, from what `combinations` composes of the pattern's selection and the operator's choice; its internal module `patterns` holds the patterns.
- Maps each fragment's keys to the environment and the local layer: the boundary that keeps module words out of the environment's.
- Adds one log sink to a listed app: `log-stdout`, unless the plan names another.
- Writes a start script, a `reseal` script with `seal` (built, not started, running its resealers; exit 0 only when previous keys may go), and what git leaves out (`node_modules/`, local configuration files, and for full and a pattern the env files and key files).
- The app reads the configuration files `APP_CONFIG` lists, comma-separated, layered in order; the generated configuration file when unset.

## Not here
- What each module's configuration means, and its fragment (`config.example` beside its package.json): each module's.
- What the full template and a selection compose: `combinations`.
- The local layer that boots a generated app for a test or a conformance run: `trial`.

## Offers
- `generate`, and the `create-app` command around it (also `run`, the command on given arguments, answering its exit status, for a package that runs it): packages listed make their app; none makes a pattern's, `--pattern` naming it (default `full`), `--add` naming features to add, `--axis <owner>=<module>` an axis's choice and `--<group>` a group's features, comma-separated (not for full).
- `--list` names, one a line, what `--add` takes: `combinations`' `addable`.
- `patterns()`: each pattern's name, use, conformance areas and what conformance adds for its run.
- The configuration reference and each package's `reference.conf` (its section's defaults as HOCON, for reading only), from each section's schema and fragment, written by `pnpm --filter @mod/create-app run configuration`; their tests check each key's description and default, how time and size are written, and that no `.default()` is left (internal module `references`).
- The audit event reference beside it: each module's events as its `./audit-events` declares them through `audit`, written by the same command and held to the committed file the same way.
- A kind two modules declare must be declared alike in the audit event reference.
- For full and a pattern: the project's manifest and app, the configuration file, the local layer's and the environment's examples, a Dockerfile, a `.dockerignore`, a README and `AGENTS.md`; a pattern's README opens with its use and carries its card.
  - The README lists each composed module's card as installed, and points at the `## Deployment` section of each card that has one (the index marks those when published).
  - The README tells how to try the app over plain http on this machine, and that a deployment keeps an https origin.
  - `AGENTS.md` indexes where each composed module's card and section defaults lie as installed, and where the release's configuration and route references lie; it states nothing of its own.

## Invariants
- A target that holds anything is refused, never overwritten; a missing or empty one is taken.
- A module, sink, added feature or axis choice not named as an npm package is refused, before anything is written; so is a name the workspace lacks, one that is not a feature, a pattern or group not known, and axes or groups for full.
- With a workspace, each dependency links to the workspace's package; a module the workspace does not hold is refused. Built into a bundle and given none, it reads the bundle's index: the app depends on each public bundle at the index's version, imports public entries, and takes the fragments the index holds; a module it does not hold is refused.
- A listed app's configuration file holds `kernel`'s section only, and no secret values.
- A pattern whose store is kept in memory says in its README that the deployment runs as one instance.
- The full template's and a pattern's configuration file reads the collected fragments' scalar keys from env only, holding no values; each variable is the section and key path joined by `_`, upper-cased, `-` as `_`.
- Two keys reading one variable refuse generation, naming both.
- Neither example holds a live value line: the local layer's holds each fragment list with its placeholders and each value spanning sections (`audit.receivers`), the environment's each variable, all as comments; a copy sets nothing, and boot refuses each key still needed. A value spanning sections never goes to env.
- The guide and the env example say a value of several lines, such as a PEM key, goes in the local layer, as an env file holds one line a variable.
- A scalar its owner's example gives in several lines is still read from env, but left out of the env example and listed among the keys written in the local layer.
- Git leaves out every env file but `.env.example`, the local layer, `*.pem` and `*.key`; the image's build context leaves out those, `.env.example` and `.git`.
- The image pins Node by version and digest and corepack by version, installs the locked production dependencies in a stage of their own, runs node under `tini` as a user other than root, and checks liveness (`/_healthcheck`, after a start period).
- The app exits 78 on a refused boot, writing each refusal on standard error.
- SIGTERM or SIGINT stops the app, draining; one that comes while it starts stops it once started.

## Data
- Writes the target only; reads the workspace's package list, and the fragments of the modules the full template composes.

## Depends on
- `kernel`, `combinations` (the modules it assembles become dependencies of the output), `trial` (the references assemble on its layer); the HOCON library, to read the fragments.

## Vocabulary
- output: a project created from the template.
- fragment: a module's example of its section, placeholders only; a secret's is `REPLACE-…` text its section refuses.
- local layer: the operator's configuration file layered first, for lists and values the environment does not carry.
