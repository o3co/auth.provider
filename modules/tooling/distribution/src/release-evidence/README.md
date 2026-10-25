# release-evidence

Internal module of `distribution`: the evidence a release keeps, from the CI run that tested what the tag publishes.

## Responsibilities
- Before anything is published, finds the run of CI that tested the tag's tree, keeps its evidence and compliance artifacts with a manifest, and stops the release where no run will do.

## Not here
- Making the evidence: CI's jobs, through `spec-checklist`'s reporter and its `compliance`.
- What else the release keeps beside it, packing it and attaching it to the release: the release workflow's.

## Offers
- `pnpm release:evidence <dir>`, in the tag's checkout with `gh` able to read the repository's runs and `GITHUB_REPOSITORY` set: writes the run's artifacts under `dir/ci`, each in a directory named as it is, and `dir/manifest.json` (the tag's commit and tree, the run's id, attempt and URL, the commit it tested and that commit's tree, the artifacts' names). Prints each problem and exits 1.
- `releasePullOf`, `candidatesOf`, `artifactsOf`, `testedCommitOf` and `verdictOf`: the choice, apart from the calls.

## Invariants
- The release pull request is the pull request to main that the tag's commit merged; a tag on no such commit stops the release.
- A candidate is CI's run of that pull request, from its head commit and branch, whose conclusion is success; candidates are tried the newest first.
- A run's tested commit is the one commit its reports name; its tree, as the repository holds that commit, must be the tag's: main moved after the run otherwise, and what it tested is not what the tag publishes.
- A run is taken only with its compliance job ended success, a compliance artifact and at least one evidence artifact, none expired; of each name the newest is taken.
- Every stop names the run, what is missing (no run, another tree, compliance not passed, an artifact missing or expired) and what to do.

## Depends on
- `gh`, `git` and `unzip`, run.
