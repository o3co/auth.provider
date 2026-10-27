# constrained

Internal module of `claims-selection`: the run over the families whose kept selection holds constraints, and the sweep of their list.

## Responsibilities
- Hands each listed family whose selection is still kept to the caller of `constrainedFamilies`, and unlists it once handled; unlists without it one whose selection ran out.
- Sweeps the list hourly of the families whose selection ran out, best effort.

## Not here
- Listing a family, done by `follow` once the family's selection is written (the package's root). Revoking a family (whoever handles it, `claims-revocation`). The list's store (the store interface).

## Offers
- `constrainedOver` (the list, the log, whether off, a family's record by its id) → `constrainedFamilies` and `sweep`.

## Invariants
- A family is listed only after its selection is written, so a listed family without one has run out: neither the run nor the sweep unlists a family whose selection is still kept.
- A family whose record reads as anything but none, whatever its value, is handed on; only a read that fails is counted as one.
- What fails stays listed and is counted by kind: a part of the list that cannot be read (`shards`), a selection that cannot be read (`reads`), a handling (`handles`), an unlisting (`removals`); a later run finishes it.
- The sweep never revokes, and warns `claims-selection.sweep_failed` with the count alone where it could not read; it bounds nothing, so a full list is refused at `follow`.
- Off, neither touches a store.

## Depends on
- `kernel` (the log); the package's contract and store interface
