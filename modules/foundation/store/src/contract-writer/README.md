# contract-writer

Internal module of `store`: the contract test's subject writer.

## Responsibilities
- Holds every implementation to the store contract on the subject writer: a change to a space of the four categories `checks` names (here `online-indexed`) without it is refused, as a `TypeError`, before anything is written, by every change port, `mutate` through them, and a batch or a batch across touching such a space, a key it only reads included; a batch carrying it is taken there and in any other space.

## Not here
- Single keys, marks, batches, walking and input, faults: the other parts.

## Offers
- `writerContract(harness, kit)`, run by `storeContract`.

## Depends on
- `contract-harness`, `writer`; `store`'s contract.
