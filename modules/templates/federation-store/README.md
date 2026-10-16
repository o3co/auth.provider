# federation-store

Wires `federation`'s store interface, transactions, to `records`' records under a secret, so a transaction's cookie never reaches the store. Its one space declares a guarantee for each need `federation` states. A need with nothing mapped to it, a guarantee or records under a secret, fails the type check, and `federation`'s store contract, run on a store that loses what a missing guarantee allows, checks what each guarantee means. The wiring only maps, with no branches or loops. Depends on `kernel`, `federation`, `records` and `store`.
