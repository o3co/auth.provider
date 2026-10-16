# guards

Internal module of `http`: the policies each route uses, matched to the rules modules contribute.

## Responsibilities
- Guards each route with the rules of the policies it uses.

## Not here
- What a policy decides and answers (its owner's).
- Refusing boot (the package's module, from what this finds).

## Offers
- `withPolicies`: the routes and the rules → the routes guarded, the routes using a policy with no rule, or a policy with two rules.

## Invariants
- A route's policies run in its order before its handler, and the first answer ends the request.
- Policies match by value, and a label only names one in a report.

## Depends on
- `http` (its contract).
