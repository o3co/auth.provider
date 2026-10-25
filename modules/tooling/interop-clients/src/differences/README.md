# differences

Internal module of `interop-clients`: the differences accepted between a library and the provider.

## Responsibilities
- Reads `known-differences.json`, holds each difference to the checklist's exception rules, and tells a run which of its checks a difference excuses.

## Offers
- `readDifferences` and `differencesIn`: the differences, or every way they break the rules, together.
- `differencesOf`: for one library's run, the difference that excuses a check, and the ones no check met.

## Invariants
- A difference names its library, flow, the check's title and a reason, none of them empty, and passes `spec-checklist`'s `exceptionProblems`.
- A check is excused only by a difference naming its library, flow and exact title.

## Depends on
- `spec-checklist` (`exceptionProblems`).
