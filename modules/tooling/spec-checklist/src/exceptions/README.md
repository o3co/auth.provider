# exceptions

Internal module of `spec-checklist`: whether an accepted difference in a run against another implementation may be taken.

## Responsibilities
- Holds an exception a harness records (a suite's expected failure, a library's known difference) to the checklist: its class, the item or section it names, and the decision it cites.

## Offers
- `exceptionProblems`: an exception, what the checklist holds (its items, decisions and, for an optional one, its ledgers) and the items the excused test names → why it may not be taken, none where it may.
- The classes: `deviates`, `noncompliant` and `out-of-scope` for an item's mark; `adaptation` and `third-party`; `optional`.

## Invariants
- An exception for an item's mark names that item, marked so, a deviation's a SHOULD with a decision the decisions hold; an adaptation's or a third party's names no item, and carries its name or an https issue URL.
- An optional exception (a behaviour a spec leaves optional that the provider does not give, or gives otherwise) names a spec whose ledger the checklist holds and its section, no item, a decision only one the decisions hold, and its test names no item a MUST or SHOULD row of that section names or restates; its results count neither as passed nor as failed.

## Depends on
- the package's checklist (items, decisions, ledgers) and its keywords' classes.
