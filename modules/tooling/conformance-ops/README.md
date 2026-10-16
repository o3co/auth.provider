# conformance-ops

## Responsibilities
- Owns the conformance scenes of operations: liveness, readiness, the metrics scrape and its dependency gauge, the log level, their boot refusals, and the security headers on every answer.
- Checks that the operations routes do not change how authentication and rate limits count.
- Sets up the ops area's part on each of the legacy and new targets.

## Not here
- Scene composition and drivers (`conformance`). Starting the legacy system (`conformance-legacy`). Key and OAuth parts (`conformance-keys`, `conformance-oauth`).

## Interface
- Area `ops` and the shape of its part (where the scrape answers, the log level)
- The need `scrapePathSetting`, which the legacy target cannot meet

## Invariants
- The legacy set-up, and the needs it cannot meet, live only in `src/legacy.ts`.
- Touches only the HTTP interface and boot refusals.
- Reads the scrape as text, never the order of its labels.

## Depends on
- `conformance`, `conformance-legacy`, `conformance-keys`, `conformance-oauth`
