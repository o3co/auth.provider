# release-notes

Internal module of `distribution`: the release's notes, from the version's section of the changelog.

## Responsibilities
- Where the release publishes, before its draft is made, writes the notes the release carries: the body of the version's section of `CHANGELOG.md`.

## Not here
- What a changelog line says: `docs/releasing.md` and the changelog's maintainers. Making and publishing the release: the release workflow.

## Offers
- `pnpm release:notes <version> <file>`: writes the notes, or prints the problem and exits 1.
- `notesOf` (the changelog, the version, the repository's URL) → the notes, or the problem.

## Invariants
- The section is the one whose heading is `## [<version>] - <date>`, the version matched as written, so a prerelease takes its own section; it runs to the next version's heading or the end of the file.
- No section, two sections, a heading not dated (`YYYY-MM-DD`) or an empty section refuses it.
- A link relative to the repository points at the file in the version's tag (`<repository>/blob/v<version>/<path>`), the repository as the workspace's `package.json` states it, as the release page has no repository to resolve it in; a link with a scheme, or led by `#` or `/`, stays as written, and no repository stated refuses it. `CHANGELOG.md` keeps its links relative.
- It loads Node's own modules and the package's files alone, as it runs where the release publishes.
