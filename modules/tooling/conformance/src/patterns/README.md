# patterns

Internal module of `conformance`: running every pattern's areas on its app.

## Responsibilities
- Runs each pattern's areas, as `create-app`'s `patterns()` gives them, with `CONFORMANCE_PATTERN` naming the pattern.

## Offers
- The script `patterns`: every pattern, `full` both ways, or one pattern on the areas named.
- `full` (the full template) and `full+opt-ins` (with every feature that opts in), the names the package's drivers read.

## Invariants
- Prints each area's tests line, and its scenes left out by reason.
- A pattern with no areas fails.
- Any failure exits non-zero.

## Depends on
- `create-app`.
