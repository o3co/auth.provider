# harness

Internal module of `interop-oidf`: one plan run end to end, reported as tests.

## Offers
- `runPlan`: the expected entries judged, the suite, the front (the login page, the shim on the authorization and token endpoints, every redirect told to the shim), the app behind it, the suite's runner, and each test's outcome read back from the suite's API.
- `reportRun`: one vitest test per suite test, then one for the unused entries and one for the runner's own word.

## Invariants
- A plan's setup and run share one deadline (twenty-five minutes, the suite's runner fifteen of them); everything it started then stops in reverse order, its records kept first, by budgets of its own past the deadline. Every stop is tried; any that failed is told, and the run fails with it, its work directory kept for the next run to take down. A suite's start that failed and could not stop the suite keeps it too.
