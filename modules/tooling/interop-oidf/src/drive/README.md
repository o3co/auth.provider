# drive

Internal module of `interop-oidf`: a relying party plan's tests driven one at a time over the suite's API, where the suite's own runner cannot reach the app.

## Offers
- `makePlan`: a plan the suite makes under a variant and a configuration, and the tests it holds.
- `drive`: one of its tests made, waited on until it waits for the app, gone through at the app by the harness's act, then waited on until the suite ends it.
- `stateOf`: a test's state by the suite's long poll, one no longer running read from its info.
- It calls the suite's API through `suite`'s `call`, and judges each status itself: a plan and a test made are `200` or `201`, a test no longer running is `404` to its wait, read from its info.

## Invariants
- The app never acts on a test that ended before it waited.
- Every wait is held to its time and to the signal given.
