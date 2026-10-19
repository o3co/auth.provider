# conformance-recipes

## Responsibilities
- Keeps each recipe in the documents from going stale: a recipe's scene generates the app with the recipe's own command, starts it, and makes the recipe's requests over HTTP, as a user of the provider would.
- Records the scene's exchanges and writes them, with the command, into the recipe's generated blocks.

## Not here
- A recipe's text, which is written by hand around its generated blocks; the module cards hold the facts it points to.
- Generating and starting apps (`create-app`, `conformance`). The fake ledger's answers (`users-http`'s `./testing`).

## Offers
- Area `recipes`: its part names the modules a recipe's command composes, set up on Redis where the command composes it and with a second factor required where it composes `mfa`, and `localConf`, the `config/local.conf` its reader writes, which the app boots as written, below the set-up's sections. It has no legacy set-up: recipes run on the new system only.
- `commands`: each recipe's generate command after the target, and `shownCommand`, the command as a reader types it. `scripts`: the scripts a reader runs with `node -e`, and `shownScript`, a script as typed.
- `composedBy` (command, workspace → the modules the app it generates depends on), `transcript` (a recorder of a scene's exchanges, by block), `withBlocks` (a document and its blocks' text → the document rewritten).
- `pnpm --filter @mod/conformance-recipes run examples`: rewrites each recipe's generated blocks from a run.
- `pnpm --filter @mod/conformance-recipes run external`, with `RECIPES_TARBALLS` naming the packed release (`pnpm bundles`, then `.github/scripts/pack-published.sh <dir>`): the recipes written against the published packages, built and run from the tarballs alone; with `RECIPES_WRITE=1` it rewrites their blocks.

## Invariants
- A recipe's generate command, and each script it has its reader run, is one constant, shown in its document and run by its scene.
- A generated block sits between `<!-- generated:<name> -->` and `<!-- end generated -->`. Only the text between marks is rewritten; a block with no marks, marks with no block, a name marked twice and an unclosed mark are each refused.
- A recipe on the workspace's modules runs on every pull request, as an integration test; one written against the published packages runs in the release check, against the packed release. Each fails when a committed block differs from what its run records, naming the command that rewrites it.
- A recipe's outside package is a fixture compiled against the published packages' declarations; its source is kept out of the workspace's own type check, and shown in the recipe as its author writes it.
- An exchange is shown as a reader repeats it: the request's method, path, the headers needed to repeat it and its body, then the answer's status, the headers acted on and its body. Cookies are the browser's and left out.
- Values that differ between runs are shown under fixed names, and no secret is shown.
- A recipe's file boots below the keys the driver sets for every scene (the port, the audit receivers and sink, outbound's loopback hosts): such a key in the file is shown as its reader writes it, and its run takes the driver's (`audit.receivers` in recipe-first-login).
- Touches only the HTTP interface and boot refusals.

## Depends on
- `conformance`, `create-app`; in tests, the areas whose parts a recipe's scene composes, `users-http`'s fake ledger, and `trial`'s layer.

## Vocabulary
- recipe: a document a user follows to build something with the provider, written by hand around generated blocks.
- generated block: the part of a recipe the scene writes: a command, or the exchanges of a step.
