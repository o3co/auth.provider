# guarantees

Internal module of `http`: whether each route keeps what it declares about the requests it lets through.

## Responsibilities
- Checks each route's `changesState`, `crossSite` and `unlimited` against the marks policy owners contribute.

## Not here
- What a policy decides (its owner's), or whether a mark or a reason is true: a mark is its owner's claim, and a reason is for review.
- Refusing boot (the package's module, from what this finds).

## Offers
- `brokenGuarantees`: the routes and the marks → each route that breaks what it declares, or declares too little, and how.

## Invariants
- A GET says whether it changes state; any other method does, and `changesState: false` on one is a break.
- A route that changes state uses a policy marked for its method for each guarantee, or gives a reason in that guarantee's field, never both; a reason is never empty, and none is given where nothing changes.
- Its `own-site` policy runs before its `per-source` one, so a request from another site spends no count.
- Policies match marks by value; a route that declares nothing is checked as well.

## Depends on
- `http` (its contract).
