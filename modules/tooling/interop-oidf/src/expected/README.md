# expected

Internal module of `interop-oidf`: whether the expected entries may go to the suite.

## Offers
- `expectedProblems` (why entries may not be taken) and `suiteEntries` (the entries in the suite's fields alone).

## Invariants
- An entry names its test and configuration file without `*`, `?` or brackets, and its variant as an object; a failure names its block, condition and kind.
- Its class holds as `spec-checklist`'s `exceptionProblems` judges it; one test's entries share one class; none is written twice.
