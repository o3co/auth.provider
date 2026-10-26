# release-evidence

Internal module of `distribution`: the evidence a release keeps, from the CI run that tested what the tag publishes.

## Responsibilities
- Before anything is published, finds the run of CI that tested the tag's tree, keeps its evidence and compliance artifacts with a manifest, and stops the release where no run will do.

## Not here
- Making the evidence: CI's jobs, through `spec-checklist`'s reporter and its `compliance`.
- What else the release keeps beside it, packing it and attaching it to the release: the release workflow's.
- Who may create, move or delete a release tag: the repository's tag rules, the boundary of what may be released.

## Offers
- `pnpm release:evidence-fetch <fetched>`, in the tag's checkout with `gh` able to read the repository's runs and `GITHUB_REPOSITORY` set: writes `fetched/fetched.json` (CI's runs of a push of the tag's commit's second parent, and the jobs and artifacts of each that succeeded) and their evidence artifacts under `fetched/zips`. Exits 1 where GitHub's answer cannot be had.
- `pnpm release:evidence-judge <fetched> <dir>`, in the tag's checkout with main's history and `GITHUB_REPOSITORY` and `GITHUB_REF_NAME` set, holding no credential: writes the run's artifacts under `dir/ci`, each in a directory named as it is, and `dir/manifest.json` (the tag's name, commit and tree, the run's repository, id, attempt, URL and branch, the commit it tested and that tree, the artifacts' names). Prints each problem and exits 1.
- Both read the repository named by `EVIDENCE_REPOSITORY`, else `GITHUB_REPOSITORY`. The judge writes `route=public` or `route=security` to `GITHUB_OUTPUT`, as the run taken is this repository's or the security repository's; where the tag declares a security release, this repository's judge writes `route=security` and keeps nothing, for the security repository's run to be judged next.
- `tagOf`, `versionOf`, `candidatesOf`, `artifactsOf`, `testedCommitOf` and `firstTaken`: the choice, apart from the calls.

## Invariants
- The tag names its version as `v<version>`; its commit is a merge of two parents, the first on main and the second the release branch's head, whose tree is the tag's; and its CI workflow restores no cache in a push to `release/<version>`. Any other tag stops the release. That the tag's tree is what was reviewed is no fact a tree holds: who may create a release tag is the boundary.
- A candidate is a run GitHub states is of `.github/workflows/ci.yml`, for a `push`, at the release branch's head, on the branch `release/<version>` as written (never normalized), in this repository from this repository, and successful in its latest attempt. Candidates are examined in turn, the newest first: the first that will do is taken and no older one is examined; one that cannot be examined (an archive or a file that fails) is told and the next is examined.
- A process the steps run (git, gh, the compliance) has succeeded only where it exited 0 with no error: past its buffer, it can exit 0 beside ENOBUFS with its output cut short, its last lines (a tag's `Release-Evidence`, say) lost, so that is a failure.
- A run's reports must name, as the one commit tested, the commit GitHub ran it on: a report is never taken for what GitHub states.
- A run is taken only where its `conformance`, `release-check` and `compliance` jobs passed in its latest attempt.
- Of a run's artifacts, each job's evidence is taken from its newest attempt (the number CI ends the name with) and the compliance table is the newest; only those taken are held to be there and unexpired, an older attempt's expiry stopping nothing.
- Over the tag's tree, the evidence taken is read again by the release's compliance (`spec-checklist`'s `compliance --release`, as that run and the commit it tested), which must let the release go on, having written its table: an artifact gone since CI passed leaves an expected run unreported, and stops it.
- Fetching imports node's own modules alone and decides nothing; an answer it cannot have stops it, never read as no runs. Judging refuses to run holding a credential, and reads only what fetching brought and the checkout.
- A release goes to the security repository's run only where its tag declares one, a line `Release-Evidence: security` in the message of the annotated tag as pushed, which only the owner may make; never by what ran here. A tag unread, of another commit than the one checked out and the event's, or declaring another value stops it.
- That run is judged in a job of its own, in the approved `security-evidence` environment, with an App token reading that one repository's runs, used by fetching alone and seen refused before anything is installed.
- What fetching writes can be rewritten by any later step of the job, so its integrity rests on the job running only the tag's tree and its locked dependencies: the same boundary the release's other jobs rest on.
- An artifact's archive is read from its directory before it is unpacked, and takes only plain files and directories as MS-DOS or Unix mark them, as CI's archives hold: any other host or mode, a link among them, a name its local header or an extra field gives otherwise, or one landing outside its directory refuses the run; anything else unpacked anyway does too.
- Every report naming a run must name this one: a report of another run beside a full set refuses it.
- The release workflow's evidence job is held, by a test reading it, to read permissions alone (contents, actions), the only job reading runs, with no credential kept in its checkout, the token given to fetching alone, before anything is installed, no install script run, judging after, an upload a re-run may write over, and publish needing it.
- Every stop names the run, what is missing (no run, no release tag, compliance not passed, an artifact missing or expired, reports not the run's) and what to do.

## Depends on
- `spec-checklist`'s `compliance`, and `gh`, `git` and `unzip`, run.
- `workflow-caches` (the tag's CI workflow held to restoring no cache).
