# contract-harness

Internal module of `store`: the contract test's shared part: the spaces it declares, the harness an implementation gives, and what every other part uses.

## Responsibilities
- Declares the contract test's spaces (`contractSpaces`) and the harness an implementation gives (`StoreHarness`): how a test opens a store, a second connection, and, where the implementation has them, stopped replicas, a lost reply, a restart and a failover.
- Builds what one run of the contract shares across its parts (`contractKit`): the spaces, a partition no other test uses, fresh keys in it, a key kept for ever, and two connections to the same data.
- Holds the helpers the parts use: `overwrite` (also offered to other packages' tests), and reading until the store clock passes a time, retrying, racing two connections, and a write's version.

## Not here
- What each part tries: the other contract test parts.
- The implementations: `memory`, `simulated`, and each adapter.

## Offers
- `contractSpaces`, `StoreHarness`, `overwrite`, `contractKit` (`ContractKit`), and the helpers above.

## Depends on
- `store`'s contract, for its types.
