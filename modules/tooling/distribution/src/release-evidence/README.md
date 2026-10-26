# release-evidence

Internal module of `distribution`: the evidence a release keeps, from the CI run that tested what the tag publishes.

## Responsibilities
- Before anything is published, finds the run of CI that tested the tag's tree, keeps its evidence and compliance artifacts with a manifest, and stops the release where no run will do.
- Holds CI's and the release's workflows to restoring no cache in a run whose evidence a release may take, or in the release's own run: whoever saved a cache is not known.

## Not here
- Making the evidence: CI's jobs, through `spec-checklist`'s reporter and its `compliance`.
- What else the release keeps beside it, packing it and attaching it to the release: the release workflow's.

## Offers
- `pnpm release:evidence <dir>`, in the tag's checkout with `gh` able to read the repository's runs and `GITHUB_REPOSITORY` set: writes the run's artifacts under `dir/ci`, each in a directory named as it is, and `dir/manifest.json` (the tag's commit and tree, the run's id, attempt and URL, the commit it tested and that commit's tree, the artifacts' names). Prints each problem and exits 1.
- `releasePullOf`, `candidatesOf`, `artifactsOf`, `testedCommitOf` and `firstTaken`: the choice, apart from the calls.
- `cacheProblems(path, run, read)`: each place in a workflow, and in the workflows of this tree it calls, that could restore a cache in that run, uses an action not known, or calls a workflow outside this tree; `evidenceRuns(version)` (a push to `release/<version>`, a pull request to main) and `releaseRun(version)` (a push of the tag) are the runs it is asked of.

## Invariants
- The release pull request is the pull request to main that the tag's commit merged; a tag on no such commit stops the release.
- A candidate is CI's run of that pull request, from its head commit and branch, whose conclusion is success. Candidates are examined in turn, the newest first: the first that will do is taken and no older one is examined; one that cannot be examined (a download, an archive or an answer that fails) is told and the next is examined.
- A run is the release pull request's only where its `conformance`, `release-check` and `compliance` jobs, which CI runs on a pull request to main alone, passed in its latest attempt: a run of a pull request to develop from the same head and branch skipped them.
- A run's tested commit is the one commit its reports name; its tree, as the repository holds that commit, must be the tag's: main moved after the run otherwise, and what it tested is not what the tag publishes.
- Of a run's artifacts, each job's evidence is taken from its newest attempt (the number CI ends the name with) and the compliance table is the newest; only those taken are held to be there and unexpired, an older attempt's expiry stopping nothing.
- Over the tag's tree, the evidence taken is read again by the release's compliance (`spec-checklist`'s `compliance --release`, as that run and the commit it tested), which must let the release go on: an artifact gone since CI passed leaves an expected run unreported, and stops it.
- The release workflow's evidence job is held, by a test reading it, to read permissions alone (contents, actions, pull requests), the only job reading runs, with no credential kept in its checkout, no install script run, an upload a re-run may write over, and publish needing it.
- Every stop names the run, what is missing (no run, another tree, compliance not passed, an artifact missing or expired) and what to do.
- A workflow uses only the actions its internal list names, each at a ref the list takes; a local action, an image or another repository's workflow is refused, and a workflow of this tree a job calls is read in the caller's run, a loop refused.
- An action's cache is read from its inputs as GitHub reads them, its default where one is not written (setup-go's on, pnpm's off); an expression is decided by the run's `github` context alone, and one it does not decide counts as restoring.
- What GitHub might read otherwise is left undecided: text as a number but in JSON's syntax (`''` as 0), text beyond printable ASCII compared or searched, a number cast to text, and a pull request's ref, its number unknown. An `if:` left empty runs.
- CI's workflow, in either run a release may take evidence from, and the release's own workflow restore no cache, held by a test; CI hands the legacy build to each area as the run's own artifact, by the id the job that built it gave, and lets a re-run write over the compliance table.

## Depends on
- `spec-checklist`'s `compliance`, and `gh`, `git` and `unzip`, run.
- `yaml` (reading a workflow as GitHub reads it).
