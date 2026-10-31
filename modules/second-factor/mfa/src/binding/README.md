# binding

Internal module of `mfa`: a factor begun, its pending proof, and its binding.

## Responsibilities
- Begins a binding for a kind the subject may bind, its secret sealed for the subject as a pending binding; proves it; and binds it as written, a first binding only while it is still the first.

## Not here
- Whether factors stand: `standing`. The mark settled and a first binding refused: `clearing`. The rules of a binding: `mfa-binding`'s contract.

## Offers
- `bindingWith` (the shared parts, `standing`, `clearing`) → `begin`, `provePending` and `bind`, as `factorBinding` names them.

## Invariants
- A pending binding is sealed to the subject with the fence it began at: a reset or a fence since leaves it nothing to bind.
- Of two first bindings at once, one binds; a factor of a unique value is written with its claim, as one.

## Depends on
- `mfa-binding` (its contract), `mfa-extensions`, `mfa-reading` (`Fence`), `labels`; `standing`, `clearing`; `mfa`'s records and shared parts.
