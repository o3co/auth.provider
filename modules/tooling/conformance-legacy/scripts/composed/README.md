# composed

Internal module of `conformance-legacy`: the composed entry, the legacy standalone build's start-up with the extra packages a part asks for.

## Responsibilities
- Starts the legacy standalone build (v0.17.0) as its own `dist/app.mjs` does, with the extra packages `LEGACY_EXTRA` names appended.
- Sends the requests of a type that fixes its hosts in code (GitHub, Google, Apple) to the fake upstream a part names.
- Puts Google's type, which the standalone build loads, in place of the build's own.

## Not here
- Which extra packages exist and the legacy directories each needs: the package's list (`scripts/extras.mjs`), which the preparation script reads too.
- Starting the build, collecting fragments and choosing this entry: the package's driver.

## Offers
- `composed-entry.mjs`, run by node with `LEGACY_DIR` (required), `LEGACY_EXTRA` (a comma list of the list's names) and `LEGACY_GITHUB_BASE`, `LEGACY_GOOGLE_BASE`, `LEGACY_APPLE_BASE` (each optional, a fake's base).

## Invariants
- It is harness code, not legacy code: it imports the build's own files and packages by file URL, as they are, and changes nothing in the checkout.
- Every other variable is read by the legacy code exactly as under `node dist/app.mjs`.
- A name `LEGACY_EXTRA` holds that the list does not know refuses the start.

## Depends on
- The legacy checkout, and the package's list of extra packages.
