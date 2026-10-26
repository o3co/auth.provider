# report

Internal module of `interop-oidf`: a plan's run, reported as vitest tests.

## Offers
- `PlanRun`: a plan as it ran, each suite test's outcome, the expected entries no test used, what drove the plan and how it ended, and where its records are kept.
- `reportRun`: under the title given, one vitest test per suite test, then one for the unused entries and one for the driver's own word.

## Invariants
- A test excused by a class is skipped as `excused: <class>`, one waiting for a person's review as `review: …`; neither is passed.
- A failed test says why, and where the records are; the driver's test names its record.
