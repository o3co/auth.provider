# create-app

## Responsibilities
- Generates a listed app: the modules asked for through their `./module`, with what they need to run and the wirings and bridges they come with (`combinations`' `needed`), written as a pattern's deployment is.
- Generates the full template: what `combinations` composes in full, with the features added, its configuration from the modules' fragments, an image and the operator's guide.
- Generates a pattern's deployment the same way, from what `combinations` composes of the pattern's selection and the operator's choice; its internal module `patterns` holds the patterns.
- Gives `app-output`, which writes the project, the packages: the workspace's, or the bundle's index's.
- Adds one log sink to a listed app: `log-stdout`, unless the plan names another.
- Reads packages outside the release from where pnpm installed them, through its internal module `outside`.

## Not here
- What each module's configuration means, and its fragment (`config.example` beside its package.json): each module's.
- What the full template and a selection compose: `combinations`.
- The local layer that boots a generated app for a test or a conformance run: `trial`.
- The project's files, from the configuration and its examples to the image, the guide and the app's entry, and what they are held to: `app-output`.
- The configuration, audit event and route references, and each package's `reference.conf`: `references`.

## Offers
- `generate`, and the `create-app` command around it (also `run`, the command on given arguments, answering its exit status, for a package that runs it): packages listed make their app, `--sink <package>` naming its log sink; none makes a pattern's, `--pattern` naming it (default `full`), `--add` naming features to add, `--axis <owner>=<module>` an axis's choice and `--<group>` a group's features, comma-separated (not for full). `--workspace <root>` names a workspace whose packages it links.
- A package outside the release is named `npm:<name>` (a package listed, `--add`, an axis's module) and read from `--outside-from <project>`, where the operator had pnpm install it; `--allow-fresh <name>` lets one published within the last day be installed.
- `--list` names, one a line, what `--add` takes: `combinations`' `addable`. `--help` (`-h`) writes the usage.
- `patterns()`: each pattern's name, use, conformance areas and what conformance adds for its run.
- A pattern's README opens with its use and carries its card; the full template's names the opt-in features not added; a listed app's names the modules listed.

## Invariants
- A target that holds anything is refused, never overwritten; a missing or empty one is taken.
- A module, sink, added feature or axis choice not named as an npm package is refused, before anything is written; so is a name the workspace lacks, one that is not a feature, a pattern or group not known, and axes or groups for full.
- With a workspace, each dependency links to the workspace's package; a module the workspace does not hold is refused. Built into a bundle and given none, it reads the bundle's index: the app depends on each public bundle at the index's version, imports public entries, and takes the fragments the index holds; a module it does not hold is refused, but a package outside the release named `npm:`.
- A package outside the release is composed beside the published release alone, through `combinations`' `combinationsWith`: never with a linked workspace, nor from the workspace. The app depends on it at its recorded version, imports it by its name, and its fragment is read with the release's in one reading.
- It is composed beside a release whose index records the integrity of its bundles and of zod, and passes them to `app-output` for the app to be held to. An index that records none, a zod other than the app's, and a package outside the release taking as a peer a bundle the index records no integrity of are refused.
- `npm:` without `--outside-from`, `--outside-from` with no `npm:` name, `npm:` with a linked workspace, and `--allow-fresh` of a name not named `npm:` are usage errors.
- A pattern or a listed app whose store is kept in memory says in its README that the deployment runs as one instance.
- A listed app takes no axis default but one declared to replace its owner: its store is kept in memory unless a store adapter is listed.

## Data
- Writes the target only, through `app-output`; reads the workspace's package list or the bundle's index, and the cards and fragments of the modules it composes.

## Depends on
- `app-output` (it writes the project, from the packages create-app gives it), `combinations` (the modules it assembles become dependencies of the project); `semver`, through `outside`.

## Vocabulary
- fragment: a module's example of its section, placeholders only; a secret's is `REPLACE-…` text its section refuses.
