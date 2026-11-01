# harness

Internal module of `interop-oidf`: one plan run end to end, reported as tests.

## Offers
- `runPlan`: the expected entries judged, the suite, the front (the login page, the shim on the authorization and token endpoints, every redirect told to the shim), the app behind it, the suite's runner, and each test's outcome read back from the suite's API.
- `pattern` (`simple-web`): the pattern every OP plan meets.
- `titleOf`: an OP plan's title in the report, its results adapted by the PKCE shim. The run is reported by `report`, the suite's own runner named as its driver.

## Invariants
- A plan's setup and run share `lifecycle`'s deadline, the suite's runner fifteen minutes of it; everything it started then stops through `lifecycle`, in reverse order, its records kept first, by budgets of its own past the deadline. A stop that failed, or a suite's start that could not stop the suite, fails the run and keeps its work directory for the next run to take down.
