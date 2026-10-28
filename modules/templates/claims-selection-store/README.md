# claims-selection-store

Wires `claims-selection`'s store interface to `records`: selections as records in a space of their own, which declares a guarantee for each need `claims-selection` states. A need with nothing mapped to it fails the type check, and `claims-selection`'s store contract, run on a store that loses what a missing guarantee allows, checks what each guarantee means. The wiring only maps, with no branches or loops. Depends on `kernel`, `claims-selection`, `records` and `store`.
