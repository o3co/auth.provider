# mfa-flows-store

Wires `mfa-flows`' store interface, transactions, to `records`' records under a secret, so a transaction's identifier never reaches the store. Its one space declares a guarantee for each of the other needs `mfa-flows` states. A need with nothing mapped to it fails the type check, and `mfa-flows`' store contract, run on a store that loses what a missing guarantee allows, checks what each guarantee means. The wiring only maps, with no branches or loops. Depends on `kernel`, `mfa-flows`, `records` and `store`.
