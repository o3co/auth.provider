# client-plan

Internal module of `interop-oidf`: one relying party plan run end to end, the provider as the suite's OP's relying party.

## Offers
- `runClientPlan` (a plan's definition) → the report's run, and the app's side of each test it ran: its start, its answer to the callback, and whom the browser was logged in as after.
- `ClientPlanDefinition`: the suite's plan and variant, its configuration, the tests the harness runs and the ones it does not, each named; of those it runs, the ones the app is only started for and the ones it reads no UserInfo for. `declarationProblem` (the tests the suite's plan holds, the definition) → why they do not match, or none.
- `clientPattern` (`sso-federated`) and `clientTitleOf` (`OIDF <the suite's plan>`).

## Invariants
- A run on any pattern but `clientPattern` refuses to start.
- Before any test is made, every test the suite's plan holds is declared run or not run, never both, nothing is declared that it does not hold, and a test run otherwise is declared run; else the plan fails.
- Each test run is made, waited on until it waits for the app, and gone through with the app started for it alone, started after the test waits (the suite's OP answers only then) and stopped after; the suite then ends it. A test the suite ends on the app's first reads asks the app no more than those: the configuration at its start, or the keys of a login read without UserInfo; any request after fails it.
- The front tells the app one sender, a documentation address: the harness reaches it from loopback, the app's trusted proxy.
- The tests not run go to the results as declared, their test and variant as the suite's plan names them; the declaration comes from the definition, never from the expected entries.
- The results are read back by the plan's id. The app's answer to each callback is kept as the test's review page.
- Its tunnel reaches the suite's origin alone; the suite's certificate reaches the app through the driver's `trustedCertificates`.
