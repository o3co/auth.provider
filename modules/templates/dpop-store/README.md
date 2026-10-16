# dpop-store

Wires `dpop`'s store interface, spent proofs, to `records`' records. Its one space declares a guarantee for each need `dpop` states. A need with nothing mapped to it fails the type check, and `dpop`'s store contract, run on a store that loses what a missing guarantee allows, checks what each guarantee means. The wiring only maps, with no branches or loops. Depends on `kernel`, `dpop`, `records` and `store`.
