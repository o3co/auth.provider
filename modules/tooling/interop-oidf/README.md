# interop-oidf

## Responsibilities
- Runs the OpenID Foundation's conformance suite, at a pinned version, against the provider: its OP plans Basic and Config, on the `simple-web` pattern's app behind an https front.
- Reports each suite test as a vitest test, its result excused only by an expected entry the checklist lets it take.
- Its internal modules: `pkce` gives PKCE to requests that carry none, `login` is the login page, `expected` judges the expected entries, `results` reads each test's outcome, `scene` is the app's scene, `suite` starts and stops the suite, `harness` runs a plan.

## Not here
- The front itself (`conformance-front`), the app's start (`conformance`), and what an exception may be (`spec-checklist`'s `exceptionProblems`).
- A certification: the shim changes the requests, so a result is "OIDF (PKCE adaptation)", never a certified pass.

## Offers
- `pnpm --filter @mod/interop-oidf run plan [basic|config]`: runs the plans (Docker, `git`, `openssl` and Python 3.9 or later on the path).
- `run evidence-runs`: the runs the package's evidence comes from, as JSON: `{ entry: "@mod/interop-oidf#<plan>", kind: "oidf-plan", matrix: "<plan>" }`, one per plan.
- `suite-pin.json`: the suite's release tag, the commit the tag must name, and the Python packages its scripts run on, each at one version.
- `plans/op.json`: the plans' configuration, which the harness fills at run time (origin, alias, secrets, user).
- `expected/<plan>.failures.json` and `expected/<plan>.skips.json`: the suite's expected entries, each with its class.
- `OIDF_ARTIFACTS_DIR`: where a run keeps its records (the runner's output, the export, each suite test's result and log, every container's log, what the shim added); a directory of its own otherwise, named in a failure.

## Invariants
- The pattern is `simple-web`, set by the package's vitest configuration; a run on any other refuses to start.
- An expected entry names its test, variant and configuration file, and a failure's block and condition, without a wildcard; a test's entries share one class; each holds as the checklist judges it. Any that does not refuses the run before the suite starts.
- A failure or warning is excused only by an entry matching it exactly; a suite test excused is skipped as `excused: <class>`, one the suite leaves for a person's review as `review: …`; neither is passed.
- A suite test that never ran or did not finish fails; so does an entry no test used, and a plan the suite's runner fails.
- The suite's tag must name the pinned commit. Everything a run starts is stopped and its directories removed, however it ends.
- The plans run one at a time: the suite takes fixed ports.
- The app is told one sender, a documentation address, for every request the suite makes: on a desktop the suite reaches the front from loopback, the app's trusted proxy.

## Depends on
- `conformance` (the pattern's app), `conformance-code` (the code flow's scene), `conformance-front` (the https front), `spec-checklist` (the checklist and the exception rule), `vitest`.
