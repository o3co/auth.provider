# Contributing

Thank you for helping. This guide covers how the repository is laid out, what a change must pass, and how commits and pull requests are shaped.

## Before you start

- **Node 24 or later** (`.nvmrc` names 24), and **pnpm** at the version `packageManager` in `package.json` names; `corepack enable` gives you that one.
- `pnpm install`, then `pnpm check` should pass on a clean checkout.
- **English only**, in code, comments, documents and commit messages; the Japanese README is the one exception (see Commits).
- **A vulnerability** is reported privately, as the [security policy](SECURITY.md) says, never in an issue or a pull request.

## Where a change goes

- **Modules.** Each concern is one module under `modules/<group>/<name>`, a package of its own. Its README, the module's card, is its contract: responsibilities, what is not its own, what it offers, its invariants, its data, what it depends on and its vocabulary.
- **The owner map.** [modules/README.md](modules/README.md) says which module owns each contract, setting, extension point and word. Before adding something, find its owner there and change that module; when a concern has no owner yet, the change says which module takes it.
- **One word, one meaning.** A word keeps one meaning inside its module. Where a module meets another's words, it maps them at its boundary rather than taking them in.
- **Cards hold the current contract only.** Plans, moves in progress and removals to come are not written in a card; the guard refuses their usual phrases.

## Checks

| Command | What it runs | Where CI runs it |
|---|---|---|
| `pnpm check` | type check, lint (Biome), unit tests (Vitest), the guard, the distribution check | every pull request, on Node 24 and 26 |
| `pnpm test:integration` | the tests that need Docker: Redis, and the generated apps run in full | every pull request |
| `pnpm conformance` | each module's conformance scenes against the assembled apps | the main and release branches |
| `pnpm release:check` | packs every published package, generates each pattern from the packed tarballs, type-checks and boots it | the main and release branches, and each release |

Generated documents (`docs/configuration.md`, `docs/audit-events.md`, `docs/routes.md` and each module's `reference.conf`) are written by `pnpm --filter @mod/references run configuration`; run it after changing a section, an audit event, a route or a route's policy, and commit the result. Their tests fail when the committed files are behind.

CI also checks, on each pull request, that every commit's `package.json` files parse and hold no conflict marker, and that no file or commit message holds a path into a local workspace or a reference to an unrelated project.

## The guard

The [guard](modules/tooling/guard/README.md) holds the workspace to its rules: no dependency cycles, dependencies pointing one way between kinds, what each package exports, the size of each module, its tests and its card, and what documents may point at. It reads the repository as it stands on each run. There is no list of exceptions to add to: when a change goes over a limit, make the module deeper (an internal module with its own card) or split it along a real boundary, rather than trimming what the card says.

## Tests

- **Write the test first**, and see it fail for the reason you expect.
- **Contract tests.** A module publishes the tests of its contract at `./testing`; an implementation, such as a store adapter, runs them against itself.
- **Integration tests** end in `.integration.test.ts`, and fail rather than skip when the outside system is missing.

## Commits

- **The README in two languages.** `README.ja.md` is a full translation of `README.md`; a commit that changes one changes the other.
- A commit says why, not only what; the diff shows what.

In a pull request into `develop`:

- **Conventional Commits**: `feat(<module>): …`, `fix(<module>): …`, `docs: …`, with `!` after the type for a breaking change.
- **One module per commit.** The card changes in the same commit as the code it describes. A row of the owner map changes in its own commit, right after the module's.
- **Changing an interface** takes three commits, each in one module: the provider adds the new form, each user switches to it, then the provider removes the old one.

On `main`, each release is one commit per package, in the order of their dependencies, holding the package's whole change in that version: its subject is in the same form, of the change's main type (`feat` where it adds, `fix` where it only repairs, `!` where it breaks), and its body names the pull requests into `develop` it gathers. The repository's root files and generated documents follow, and the version's commit is last. [Releasing](docs/releasing.md#before-the-tag) says how the release branch is built.

## Pull requests

- Open pull requests against `develop`. `main` takes releases.
- `develop` is reset to `main` after each release, so the commits of a merged pull request are not kept on either branch: the pull request holds them, and its description says why the change was made. After a release, move an open branch onto the new `develop` with `git rebase --onto develop <the old develop's head> <branch>`, and push it with `git push --force-with-lease`, your own branch alone.
- The required check is `build-and-test`, which passes when both `checks` and `integration` pass.
- Describe the change, how you tested it, and any setting, route or behavior an operator would notice; a change an operator must act on also adds its line to [the migration guide](docs/migration.md).

## Change records

A change that fixes a finding, or a design fix an audit would ask about, carries a change record: what the two commits differ in, and what was run again ([findings and fixes](docs/audit/findings.md)).

- `pnpm --filter @mod/guard run change-record <base> <head>` writes its machine rows as Markdown: the modules touched, the contract's changes by structure, the dependency edges and the budget measures that moved. It reads each commit in a worktree of its own and keeps nothing.
- Add by hand the owner's confirmation of each contract change, the checks run again with their runs, and whether a design review was needed.
- A finding not yet fixed is never described in public: its fix and its record are made privately, as `SECURITY.md` says. A pull request's description holds a change record only for a finding already fixed, or a fix of no finding.
