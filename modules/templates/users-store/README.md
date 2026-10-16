# users-store

Wires `users`' store interfaces, links and verified contacts, to `records`' records, kept without end. Each interface has a space of its own, which declares a guarantee for each need `users` states for it. A need with nothing mapped to it fails the type check, and `users`' store contracts, run on a store that loses what a missing guarantee allows, check what each guarantee means. The wiring only maps, with no branches or loops. Depends on `kernel`, `users`, `records` and `store`.
