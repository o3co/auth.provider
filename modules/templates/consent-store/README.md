# consent-store

Wires `consent`'s store interfaces to `records`: grants as records, and asks as records under a secret, so an ask's key never reaches the store. Each interface has a space of its own, which declares a guarantee for each need `consent` states for it. A need with nothing mapped to it fails the type check, and `consent`'s store contracts, run on a store that loses what a missing guarantee allows, check what each guarantee means. The wiring only maps, with no branches or loops. Depends on `kernel`, `consent`, `records` and `store`.
