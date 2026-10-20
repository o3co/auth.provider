# upstream-handoff-store

Wires `upstream-handoff`'s store interface, held logins, to `records`' records under a secret, so a held login's carry never reaches the store. Its one space declares a guarantee for each need `upstream-handoff` states. A need with nothing mapped to it, a guarantee or records under a secret, fails the type check, and `upstream-handoff`'s store contract, run on a store that loses what a missing guarantee allows, checks what each guarantee means. The wiring only maps, with no branches or loops. Depends on `kernel`, `upstream-handoff`, `records` and `store`.
