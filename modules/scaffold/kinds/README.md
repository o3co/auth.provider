# kinds

## Responsibilities
- Names the kinds a package's manifest may be, and which way a dependency between kinds may point: the one place either is written. That the bottom level (common, protocol) depends on nothing at all is `guard`'s G2, beside `mayNeed`, which answers by level alone.

## Not here
- Composing modules by their kinds: `combinations`.
- Checking each package's dependencies against them, and the budget's other words for kinds: `guard`.

## Offers
- `kinds`: the words a manifest's `kind` may name, each one word; `Kind`, one of them.
- `protocol`: the contract of a wire an outside system speaks with the provider: types, constants that never change, and fixed schemas and their validation; no workspace dependency, and not product.
- `kindOrder`: the kinds from the bottom up, a level holding one or more; a kind may depend on its own level and those below.
- `capabilityBlind`: the kinds kept off a capability, though it sits below them.
- `mayNeed` (from, to): whether a package of one kind may depend on one of another, by `kindOrder` and `capabilityBlind`.

## Invariants
- Every kind a package of the workspace declares is named here, each once, and ordered once.
- `mayNeed` is never true where either word is no kind.

## Depends on
- Nothing in the workspace.
