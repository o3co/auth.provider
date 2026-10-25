# evidence

Internal module of `spec-checklist`: what a CI run's tests proved of the checklist's items.

## Responsibilities
- Writes each vitest run's results as a report named by what ran them (`reporter`).
- Reads a CI run's reports against the runs it was expected to make, and tells each item's status (`runs`, `compliance`).

## Not here
- Which tests name which items, and an item's mark: the package's.
- The runs themselves and their jobs: CI's.

## Offers
- `evidenceReporter` (through the package's `./testing`), a vitest reporter: with `SPEC_EVIDENCE_DIR` set, each run writes one JSON report there: its identity (the commit tested, `GITHUB_RUN_ID`, `GITHUB_RUN_ATTEMPT`, `GITHUB_JOB`, the entry, the target, `legacy` where `CONFORMANCE_TARGET` says so), each test's file, names (suites first) and state with a skipped test's note, and the count of errors no test owns. Without the variable it writes nothing.
- An entry names the run: `unit` and `integration` for the root's two configs; else the package beside the config, then `@<pattern>` with `CONFORMANCE_PATTERN` and `#<run>` with `SPEC_EVIDENCE_RUN`.
- `run expected [--release]`: the runs a CI run must report, a release's own too with `--release`, as JSON.
- `run plan <kind>`: the values a kind of job's matrix takes, as JSON, from the same runs.
- `run compliance <dir> [--release]`: reads every report under `dir` against the expected runs (a release's with `--release`), writes `compliance.json` and `compliance.md` beside them; with `--release`, fails where an expected run did not report or an item is `failed`, `incomplete` or `unverified`.
- `compliance.json` holds each item's status and role with the identity of each report its tests ran in, and of each that gave a failure no test owns with its reason, the runs that did not report, the counts by class and status, and by role.

## Invariants
- Every vitest config the workspace tracks registers the reporter, its fixtures' aside.
- The commit a report names and compliance takes is `SPEC_EVIDENCE_COMMIT` where set, else the checkout's HEAD; never the event's `GITHUB_SHA`.
- A job writes, before it can fail, the mark `{ attempted: { run, attempt, job, kind, matrix? } }` beside its reports; a report older than the last attempt its entry's job was marked in does not count, so a job attempted again that did not report leaves its entry missing.
- Only this run's reports count: the commit tested and the run of `GITHUB_RUN_ID`, the new system's target, and every report of each entry and job's last attempt.
- A test counts once for each item its names give, however many of its names give it.
- The runs are `unit`, `integration`, each package with a `conformance` script (kind `area`), and each run a package's `evidence-runs` script prints as a JSON list of `{ entry, kind, matrix?, releaseOnly?, files?, noSkip? }` (entries `<package>@<pattern>`, `<package>#<run>`).
- A CI run expects every run, but a `releaseOnly` one only where it is a release's; its jobs' matrices are the runs' `matrix` values by kind.
- A test file runs in: `integration` for `.integration.test.ts`; the runs of its package whose `files` suffix it bears; a harness package's other printed runs; an area's own run and its pattern runs for its `.case.ts`; `unit` for any other `.test.ts`; its package's run otherwise.
- An item's status, the first that holds: its mark; `hole` with no test; `failed` where a test naming it failed, its file did not load, or a run of its tests had an error no test owns; `incomplete` where an expected run of its tests did not report; `passed` where one passed; else `unverified`.
- `incomplete` also where a run of a test's file reported without that test (a suite's title is met by a test in it), named `<entry>: <file> > <title>`; and `failed` where a test naming the item was skipped or left todo in a `noSkip` run, excused or not, with that reason.
- A test in a suite or a file that failed outside its tests, such as in a hook, is reported `failed`, whatever it did itself.
- A test skipped with a note `excused: <class>` is counted apart by its class, neither passed nor failed.

## Depends on
- the package's checklist, its reading of the workspace's tests, and `vitest`'s reporter types
