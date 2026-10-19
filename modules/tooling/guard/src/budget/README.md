# budget

Internal module of `guard`: G7, how much each unit may hold and make a reader read, with G9 and G17 on what it measures.

## Responsibilities
- Measures each unit against the budget numbers, and reports each place over one.

## Not here
- The numbers themselves: the configuration. What the public surface holds: `guard`'s surface reading.

## Offers
- `budgetRules` (G7, G9, G17), `dependencyCards` (each unit's dependency cards, in bytes) and `branchingImports` (the internal modules reported as branches).

## Invariants
- The budget is measured per unit: the package, and each internal module (a directory with a card) apart from it; a file belongs to the innermost one.
- A unit's reading scope is its own files, the cards of the modules it lies in, and the cards of the packages it depends on (the package's declared ones, an internal module's imported ones).
- The public surface counts per package, with a wider member limit for the kinds other modules are built on. Dependencies count per unit, as the workspace packages its shipped code imports, common ones aside; their cards together are limited too.
- A package many depend on at run time has its card held to fewer lines.
- Every card item, a line opening with `- ` (nested ones too), is held to its bytes; a refusal names the item's opening.
- Comment lines, the doc comments of the public surface aside, may reach the larger of a share of the source lines or a fixed count, so that making a module smaller does not make it trip.
- Fixtures count as test lines; other test tables, such as vectors, are data. A contract test suite published as `./testing` counts as test lines; every other rule checks it as shipped code.
- An internal module whose shipped code imports nothing another unit of its package imports is reported as a branch, not refused.

## Depends on
- None (guard's own units, sources and surfaces)
