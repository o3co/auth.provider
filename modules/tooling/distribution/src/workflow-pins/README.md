# workflow-pins

Internal module of `distribution`: every workflow, and every action this repository holds, runs another repository's code only at a commit and an image only at its digest.

## Responsibilities
- Holds every workflow under `.github/workflows` (`.yml` and `.yaml`) and every `action.yml` or `action.yaml` under `.github` to naming another repository's action or workflow at a full commit with its version in a comment (`@<40 hex> # v…`), and an image at its digest (`@sha256:`): a tag can move to other code, a commit and a digest cannot.

## Not here
- Which actions, at which commits, CI's and the release's runs may use, and how they cache: `workflow-caches`.
- Images a step's script starts (`docker run` through `docker-client`, the images pinned in `sbom.json` and `scan.json`): their owners pin them.
- Whether a pin's comment names the version the commit really is: review checks that, and `workflow-caches` takes the evidence runs' actions at their commits alone.

## Offers
- `pinFiles(root)` → the files read, by the rule above; `pinProblems(path, text)` → each place in one that names code or an image by what can move.

## Invariants
- The files read are found by the rule, never listed: a workflow or action added later is held without an edit here.
- Read are a step's `uses` and a job's (another workflow), `docker://` in either, a job's `container` (written alone or as its `image`), each of its `services`' `image`, and an action's `runs.steps` and `docker://` `runs.image`; `./` is this repository's own and passes.
- A ref that is not 40 hex characters, a pin with no `# v…` comment, an expression where a pin goes, or a file that is not YAML is a problem. The comment is read as the YAML reader keeps it.
- Held by a test that reads every file the rule finds.

## Depends on
- `yaml` (reading a file as GitHub reads it, its comments kept).
