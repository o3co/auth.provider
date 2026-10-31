# app-output

## Responsibilities
- Writes a generated project: a deployment of the modules it is given, with its configuration from their fragments, the environment's and the local layer's examples, an image and the operator's guide.
- Maps each fragment's keys to the environment and the local layer, through the internal module `fragments`: the boundary that keeps module words out of the environment's.
- Holds what every generated project shares: the target's check, the package name check and the manifest.
- States what it takes from where the packages come from (`Packages`); the caller implements it.

## Not here
- Where the packages come from (a workspace or a bundle's index), and what the app depends on to have them: the caller's, through `Packages`.
- Which modules a project composes, and the values of its guide's own template marks: the caller's.
- What each module's configuration means, and its fragment (`config.example` beside its package.json): each module's.
- The app's entries and how they boot: `app-entries`.

## Offers
- `writeDeployment(target, modules, packages, readme)`: writes the project assembling `modules`, the kernel and `config-files` first, from `packages` into `target`.
  - It writes the manifest and app, the configuration file, the local layer's and the environment's examples, a Dockerfile, a `.dockerignore`, a `.gitignore`, a README from `readme`'s template in `templates/` and values, and `AGENTS.md`.
  - Its guide templates are `full-readme.md`, `pattern-readme.md` and `listed-readme.md`; the caller fills each one's own marks (the full template's opt-ins; a pattern's name, use, card, choices, receivers and deployment; a listed app's list, choices and the values the operator decides).
  - The README lists each composed module's card as installed, and points at the `## Deployment` section of each card that has one, and at the release's walk to a first login where its repository is stated.
  - The guide lists what the composed modules ask of the deployment, and the values the operator decides, from each one's own declaration, through the internal module `asked`.
  - `AGENTS.md` indexes where each composed module's card and section defaults lie as installed, and where the release's configuration and route references lie; it states nothing of its own.
- `Packages`: each name's fragments, the app's dependencies for the names, what the app imports a name under, each name's card as installed (`Card`), the release (`Release`), and, where the caller has them, what each name declares for the guide (`asks`, as `Asked`).
- `namesPackages` and `vacant`, for a caller to refuse a plan before it composes; `kernel` and `configFiles`, the packages every app depends on (its entry reads its configuration files through `config-files`).
- `fragmentsIn`, `fragmentsOf`, `fragmentFile` and `settingsOf` (internal module `fragments`); `outsideLock` (`lockfile`).
- `Packages.outside`, where the caller has packages outside the release: what the app is given beside them, see the internal module `outside`; `appZod`, the zod every app depends on.

## Invariants
- The manifest's `bundledInside` names each bundled file the package ships, by its path in the package, with every package from outside it holds inside, for the release's list of what it ships: the package's test holds it to the files there and to the packages each bundle's own regions name.
- A target that holds anything is refused, never overwritten; a missing or empty one is taken. Every file is made before any is written.
- A name not an npm package is refused by `namesPackages`, before anything is written.
- The manifest names the pnpm the workspace builds with, and the app also depends on `zod` at the packages' version.
- A scalar its owner's example gives in several lines is still read from env, but left out of the env example and listed among the keys written in the local layer; the guide and the env example say such a value goes in the local layer.
- Git leaves out every env file but `.env.example`, the local layer, `*.pem` and `*.key`; the image's build context leaves out those, `.env.example` and `.git`.
- The image follows one Node 24 minor, patch and digest unpinned, so a build takes its patches; a minor is fixed only until a newer one is out, so the operator moves `FROM` to the latest 24.x minor at each Node security release.
- It pins corepack by version and installs the locked production dependencies in a stage of their own; the stage the app runs in starts again from Node's image and takes out the corepack and the yarn Node's image bundles, so no package manager but npm is in it, and runs node under `tini` as a user other than root.
- Only an app composing `http` is given its port and interface in the image and the guide, and only one composing `http-ops` is checked for liveness (`/_healthcheck`, after a start period) or told of its endpoints.

## Data
- Writes the target only; reads its templates and the fragment files it is pointed at.

## Depends on
- `app-entries`: the app's entries, and `kernel` and `configFiles`, which this package offers again.
- The HOCON library, through `fragments`; `yaml` and `semver`, through `lockfile` and `outside`.

## Vocabulary
- output: a project written from the templates.
- fragment: a module's example of its section, placeholders only; a secret's is `REPLACE-…` text its section refuses.
- local layer: the operator's configuration file layered first, for lists and values the environment does not carry.
