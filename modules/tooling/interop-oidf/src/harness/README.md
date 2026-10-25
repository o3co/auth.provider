# harness

Internal module of `interop-oidf`: one plan run end to end, reported as tests.

## Offers
- `runPlan`: the expected entries judged, the suite, the front (the login page, the shim on the authorization and token endpoints, every redirect told to the shim), the app behind it, the suite's runner, and each test's outcome read back from the suite's API.
- `reportRun`: one vitest test per suite test, then one for the unused entries and one for the runner's own word.

## Invariants
- A run ends within fifteen minutes; everything it started stops in reverse order, its records kept first.
