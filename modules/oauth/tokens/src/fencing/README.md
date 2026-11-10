# fencing

Internal module of `tokens`: the fence a bundle of credentials passes before any of it is answered.

## Responsibilities
- Passes a bundle through every issuance fence, once, under one receipt id.

## Not here
- What a fence checks, and what its receipt keeps: the module contributing it (`subject-tokens`, over `subject-revocation`'s erasure fence). Where a bundle is fenced: its issuer (`token-endpoint`).

## Offers
- `fencingOver` (the fences, the kernel's random) → `issuanceFencing.pass({ subject })`: passed, or refused by the fence named.

## Invariants
- One receipt id per bundle, 16 random bytes from the kernel, base64url; with no fence, nothing is made and the bundle passes.
- Fences are asked in collect order; the first to refuse ends it, the rest not asked. A fence that cannot tell is unavailable, never passed.
- `tokens` holds no gate of its own: whether erasure is enabled, and whether a composition guards it, are `subject-revocation`'s.

## Depends on
- None; the package's contract.
