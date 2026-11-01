# subject-revocation-store

Wires `subject-revocation`'s store interface, boundaries by subject, to `records`' records, kept without end, each write handing on the deadline `records` writes it with. Its one space declares a guarantee for each need `subject-revocation` states. A need with nothing mapped to it fails the type check, and `subject-revocation`'s store contract, run on a store that loses what a missing guarantee allows, checks what each guarantee means. The wiring only maps, with no branches or loops. Depends on `kernel`, `subject-revocation`, `records` and `store`.
