# upstream-handoff-seal

## Responsibilities
- Gives `upstream-handoff` the seal it keeps a held login's tokens under, bridging `upstream-handoff` and `seal`.

## Not here
- What is sealed, and when: `upstream-handoff`. How sealing works and its keys: `seal`.

## Offers
- Contribution to `upstream-handoff`'s `handoffSealing`: the composed `seal`.

## Invariants
- Boot is refused where `seal` is not composed.
- Where no module receives upstream tokens, the handoff keeps nothing and the contribution goes unused.

## Data
- None.

## Depends on
- `kernel`, `upstream-handoff`, `seal`
