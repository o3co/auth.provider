# workflow-caches

Internal module of `distribution`: CI's and the release's workflows held to restoring no cache in a run a release takes evidence from, and every workflow of this tree to writing none from a job that may check out other than its run's own commit.

## Responsibilities
- Holds CI's and the release's workflows to restoring no cache in a run whose evidence a release may take, or in the release's own run: whoever saved a cache is not known.
- Holds every workflow of this tree to writing no cache from a job that may check out other than its run's own commit: its `cache-mode`, or the workflow's, is `read` or `none`; a branch's cache is shared by all its workflows.

## Not here
- Which run a release takes its evidence from, and judging it: `release-evidence`.
- Running CI, and what each job tests: the workflows themselves.

## Offers
- `cacheProblems(path, read, runs)`, `runs` `ci` or `release`: each place in a workflow, and in the workflows of this tree it calls, that uses an action not known, could restore a cache written otherwise than set out, or calls a workflow outside this tree; `offInEvidence` (the one `if:` a cache step may carry, and the one `cache:` of an action caching by default) and `mavenOffInEvidence` (setup-java's one maven `cache:`), both false in a push to a release branch and in a pull request to main.

## Invariants
- A workflow uses only the actions its internal list names, each at a commit the list takes, never a tag that can move; a local action, an image or another repository's workflow is refused, and a workflow of this tree a job calls is read in the caller's run, a loop refused.
- Nothing is evaluated: a step of `actions/cache` carries `if:` written exactly as `offInEvidence`; setup-go's `cache`, on by default, is written `false` or exactly as `offInEvidence`; setup-java's is left out, empty or exactly `mavenOffInEvidence`; setup-node's and setup-python's are left out or empty; pnpm's `cache` and `run_install` are left out or `false`. Any other writing is refused, however it would evaluate.
- In the release's own workflows, and those they call, these forms, which turn a cache off in CI's evidence runs alone, are refused too: no cache step at all, setup-go's `cache` `false`, setup-java's left out or empty.
- An input's name is read without regard to case, as GitHub reads it; one written twice is refused.
- CI's workflow, in either run a release may take evidence from, and the release's own workflow restore no cache, held by a test; CI hands the legacy build to each area as the run's own artifact, by the id the job that built it gave, and lets a re-run write over the compliance table.
- In every workflow of this tree, a job with a checkout whose `ref` is written non-empty and names other than the event's own commit (`github.sha`, `github.ref`), whatever it would evaluate to (one an earlier job computed, a release tag a caller names, or develop on the schedule, which runs in main's context), has `cache-mode` `read` or `none`, its own or the workflow's, held by a test that finds such jobs by that writing, not by name.
- That holding reads a job's checkout steps alone: a `run:` step that moves to another commit (`git checkout`, `git switch`, `git worktree`) is not held. A workflow of this tree that a job calls is held as a workflow of its own, its jobs by their own checkouts. A workflow outside this tree that a job calls is not read, so not held.

## Depends on
- `yaml` (reading a workflow as GitHub reads it).
