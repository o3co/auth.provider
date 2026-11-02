# expected

Internal module of `interop-oidf`: whether the expected entries may go to the suite.

## Offers
- `expectedProblems` (why entries may not be taken) and `suiteEntries` (the entries in the suite's fields alone).
- `expectedOf`: a plan's expected entries read from its files and judged against the checklist, the plan refused where any may not be taken.

## Invariants
- An entry names its test and configuration file without `*`, `?` or brackets, and its variant as an object; a failure names its block (empty for one outside any block), condition and kind.
- Its class holds as `spec-checklist`'s `exceptionProblems` judges it; one test's entries share one class; none is written twice. A test is its name, its variant and its configuration file, the variant's keys in any order, as the outcomes match it.
