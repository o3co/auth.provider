# client-assertion-store

Wires `client-assertion`'s store interface, spent assertions, to `records`' records. Its one space declares a guarantee for each need `client-assertion` states. A need with nothing mapped to it fails the type check, and `client-assertion`'s store contract, run on a store that loses what a missing guarantee allows, checks what each guarantee means. The wiring only maps, with no branches or loops. Depends on `kernel`, `client-assertion`, `records` and `store`.
