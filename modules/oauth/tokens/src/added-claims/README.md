# added-claims

Internal module of `tokens`: the rules of the claims a grant adds to its access token, and the one checker that copies them at issue and when a token is read back.

## Responsibilities
- Checks a grant's added claims and copies them into a new frozen record, or refuses them: the same at `issue`, at `admits` and when a verified payload is read back.

## Not here
- Writing them into the payload, signing, and reading a token: the package's.

## Offers
- `AddedClaims`, `AddedValue`: JSON values by name.
- `addedClaimsOf` (what a grant gives) → the frozen copy, none for none or an empty set; throws TypeError on anything outside the rules.
- `addedClaimsIn` (a verified payload) → its members `tokens` does not write, for `addedClaimsOf` to check.
- `reserved`, `unwritten`, `limits`.

## Invariants
- The rules themselves, the reserved names and the limits, are the package card's and `AddedClaims`'; here, how one walker holds to them.
- One walker checks and copies, at `issue`, at `admits` and when a verified payload is read back, so the three never differ.
- Nothing given is called: an object's own keys are counted before any property is read, and each property is read by its descriptor, so an accessor, a proxy or a `toJSON` is refused unread.
- A string or a name is measured by its length first: one past twice the limit is refused before it is walked, and the code points are counted only up to the limit.
- Each count, values and bytes, is checked as it grows, before the walk goes on, so a large set stops at the first limit it passes. An object met twice on one path is refused as a cycle.

## Depends on
- Node's `util` (to tell a proxy).
