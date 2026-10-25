# release-evidence

Internal module of `distribution`: the evidence a release keeps, from the CI run that tested what the tag publishes.

## Responsibilities
- Before anything is published, finds the run of CI that tested the tag's tree, keeps its evidence and compliance artifacts with a manifest, and stops the release where no run will do.

## Not here
- Making the evidence: CI's jobs, through `spec-checklist`'s reporter and its `compliance`.
- What else the release keeps beside it, packing it and attaching it to the release: the release workflow's.

## Offers
- `pnpm release:evidence <dir>`, in the tag's checkout with `gh` able to read the repository's runs and `GITHUB_REPOSITORY` set: writes the run's artifacts under `dir/ci`, each in a directory named as it is, and `dir/manifest.json` (the tag's commit and tree, the run's id, attempt and URL, the commit it tested and that commit's tree, the artifacts' names). Prints each problem and exits 1.
- `releasePullOf`, `candidatesOf`, `artifactsOf`, `testedCommitOf` and `firstTaken`: the choice, apart from the calls.

## Invariants
- The release pull request is the pull request to main that the tag's commit merged; a tag on no such commit stops the release.
- A candidate is CI's run of that pull request, from its head commit and branch, whose conclusion is success. Candidates are examined in turn, the newest first: the first that will do is taken and no older one is examined; one that cannot be examined (a download, an archive or an answer that fails) is told and the next is examined.
- A run is the release pull request's only where its `conformance`, `release-check` and `compliance` jobs, which CI runs on a pull request to main alone, passed in its latest attempt: a run of a pull request to develop from the same head and branch skipped them.
- A run's tested commit is the one commit its reports name; its tree, as the repository holds that commit, must be the tag's: main moved after the run otherwise, and what it tested is not what the tag publishes.
- Of a run's artifacts, each job's evidence is taken from its newest attempt (the number CI ends the name with) and the compliance table is the newest; only those taken are held to be there and unexpired, an older attempt's expiry stopping nothing.
- Over the tag's tree, the evidence taken is read again by the release's compliance (`spec-checklist`'s `compliance --release`, as that run and the commit it tested), which must let the release go on: an artifact gone since CI passed leaves an expected run unreported, and stops it.
- The release workflow's evidence job is held, by a test reading it, to read permissions alone (contents, actions, pull requests), the only job reading runs, with no credential kept in its checkout, no install script run, an upload a re-run may write over, and publish needing it.
- Every stop names the run, what is missing (no run, another tree, compliance not passed, an artifact missing or expired) and what to do.

## Depends on
- `spec-checklist`'s `compliance`, and `gh`, `git` and `unzip`, run.
