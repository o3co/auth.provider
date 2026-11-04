# conformance-ops

## Responsibilities
- Owns the conformance scenes of operations: liveness, readiness, the metrics scrape and its dependency gauge, the log level, their boot refusals, and the security headers on every answer.
- Checks that the operations routes do not change how authentication and rate limits count.
- Owns the fault scenes of what a readiness probe and a scrape cost the store and when they show a change, on a Redis topology and a deployment of their own.
- Sets up the ops area's part on each of the legacy and new targets.

## Not here
- Scene composition and drivers (`conformance`). Starting the legacy system (`conformance-legacy`). Key and OAuth parts (`conformance-keys`, `conformance-oauth`).

## Offers
- Area `ops` and the shape of its part (where the scrape answers, the log level)
- The need `scrapePathSetting`, which the legacy target cannot meet
- The fault run (`conformance:faults`): the `*.faults.case.ts` scenes alone, failing where one did not run only with `CONFORMANCE_FAULTS=1`, as CI sets and the script does not; named to the evidence as `@mod/conformance-ops#faults` by the run itself; the area's own run and its pattern runs leave them out

## Invariants
- The legacy set-up, and the needs it cannot meet, live only in `src/legacy.ts`.
- Touches only the HTTP interface and boot refusals; a fault scene also the Redis it runs on, counting what its relay saw and changing a setting.
- Reads the scrape as text, never the order of its labels.

## Depends on
- `conformance`, `conformance-legacy`, `conformance-keys`, `conformance-oauth`
