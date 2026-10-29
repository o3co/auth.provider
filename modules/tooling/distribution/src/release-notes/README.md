# release-notes

Internal module of `distribution`: the release's notes, from the version's section of the changelog.

## Responsibilities
- Where the release publishes, before its draft is made, writes the notes the release carries: the body of the version's section of `CHANGELOG.md`.

## Not here
- What a changelog line says: `docs/releasing.md` and the changelog's maintainers. Making and publishing the release: the release workflow.

## Offers
- `pnpm release:notes <version> <file>`: writes the notes, or prints the problem and exits 1.
- `notesOf` (the changelog, the version) → the notes, or the problem.

## Invariants
- The section is the one whose heading is `## [<version>] - <date>`, the version matched as written, so a prerelease takes its own section; it runs to the next version's heading or the end of the file.
- No section, two sections, a heading not dated (`YYYY-MM-DD`) or an empty section refuses it.
- It loads Node's own modules and the package's files alone, as it runs where the release publishes.
