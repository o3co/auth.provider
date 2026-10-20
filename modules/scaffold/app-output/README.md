# app-output

## Responsibilities
- Writes a generated project: a deployment of the modules it is given, with its configuration from their fragments, the environment's and the local layer's examples, an image and the operator's guide; or a listed app of them.
- Maps each fragment's keys to the environment and the local layer: the boundary that keeps module words out of the environment's.
- Holds what every generated project shares: the target's check, the package name check, the manifest, the app's entry and its `reseal` entry.
- States what it takes from where the packages come from (`Packages`); the caller implements it.

## Not here
- Where the packages come from (a workspace or a bundle's index), and what the app depends on to have them: the caller's, through `Packages`.
- Which modules a project composes, and the values of its guide's template marks of its own (a pattern's use and card, the full template's opt-ins): the caller's.
- What each module's configuration means, and its fragment (`config.example` beside its package.json): each module's.

## Offers
- `writeDeployment(target, modules, packages, readme)`: writes the project assembling `modules`, the kernel first, from `packages` into `target`.
  - It writes the manifest and app, the configuration file, the local layer's and the environment's examples, a Dockerfile, a `.dockerignore`, a `.gitignore`, a README from `readme`'s template in `templates/` and values, and `AGENTS.md`.
  - The README lists each composed module's card as installed, and points at the `## Deployment` section of each card that has one, and at the release's walk to a first login where its repository is stated.
  - `AGENTS.md` indexes where each composed module's card and section defaults lie as installed, and where the release's configuration and route references lie; it states nothing of its own.
- `Packages`: each name's fragments, the app's dependencies for the names, what the app imports a name under, each name's card as installed (`Card`), and the release (`Release`).
- `writeListed(target, modules, packages)`: writes a listed app, the modules' entry and manifest, and `kernel`'s section alone as its configuration file.
- `namesPackages` and `vacant`, for a caller to refuse a plan before it composes; `mainSource`, the app's entry; `kernel`, the package every app depends on.
- The fragments: `fragmentsIn` and `fragmentsOf` read them (`fragmentFile` names the file), and `settingsOf` names each scalar key's environment variable.

## Invariants
- A target that holds anything is refused, never overwritten; a missing or empty one is taken. Every file is made before any is written.
- A name not an npm package is refused by `namesPackages`, before anything is written.
- The manifest names the pnpm the workspace builds with, and the app also depends on `zod` at the packages' version.
- A fragment holds exactly one section, and no section has two fragments; either is refused, naming the fragment.
- The configuration file reads the fragments' scalar keys from env only, holding no values; each variable is the section and key path joined by `_`, upper-cased, `-` as `_`.
- Two keys reading one variable, or a key no variable can name, refuse generation, naming both or it.
- Neither example holds a live value line: the local layer's holds each fragment list with its placeholders and each value spanning sections (`audit.receivers`), the environment's each variable, all as comments; a copy sets nothing. A value spanning sections never goes to env.
- A scalar its owner's example gives in several lines is still read from env, but left out of the env example and listed among the keys written in the local layer; the guide and the env example say such a value goes in the local layer.
- With `seal` composed, the project has a `reseal` script: the same modules, built and never started, running their resealers.
- Git leaves out every env file but `.env.example`, the local layer, `*.pem` and `*.key`; the image's build context leaves out those, `.env.example` and `.git`.
- The image pins Node by version and digest and corepack by version, installs the locked production dependencies in a stage of their own, runs node under `tini` as a user other than root, and checks liveness (`/_healthcheck`, after a start period).
- The app reads the configuration files `APP_CONFIG` lists, comma-separated, layered in order; the generated configuration file when unset.
- The app exits 78 on a refused boot, writing each refusal on standard error.
- SIGTERM or SIGINT stops the app, draining; one that comes while it starts stops it once started.

## Data
- Writes the target only; reads its templates and the fragment files it is pointed at.

## Depends on
- `kernel`, for a listed app's configuration file (its section's defaults); the HOCON library, to read the fragments.

## Vocabulary
- output: a project written from the templates.
- fragment: a module's example of its section, placeholders only; a secret's is `REPLACE-…` text its section refuses.
- local layer: the operator's configuration file layered first, for lists and values the environment does not carry.
