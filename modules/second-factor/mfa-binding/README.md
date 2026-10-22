# mfa-binding

## Responsibilities
- Owns the contract for binding a new second factor: beginning it, judging its first proof, and writing it. The proofs asked before a first binding are another thing: `mfa-binding-proof`.

## Not here
- The records, and the decisions made over them: `mfa`, which provides the contract. The gates asked before a first binding: `mfa-extensions`' `firstBindingGates`. Recovery codes: `mfa-managing`'s `reissue`. The enrollment routes: `mfa-enrollment`.
- What a counting factor is, and `Shown` and `Fence`: `mfa-reading`.

## Offers
- `factorBinding` (`mfa.factor-binding`), provided by `mfa`: `begin`, given what the caller holds for the gates (begun with what to show / unknown kind / full / limited / refused / duplicate / binding proof required / first binding closed); `provePending` (valid with the proof's own amr / invalid / unknown); `bind` (bound, with the fence it began under and whether codes are due / full / unknown / malformed label / duplicate / fenced).
- `Begun`, `PendingProved`, `Bound`.

## Invariants
- A binding whose unique value another factor holds, of any subject, is refused as duplicate and leaves nothing, even when two bind at once; `begin` refuses it already when the secret alone tells the value. A binding begun before a reset or a `fence` of the subject writes nothing (`fenced`), checked in the write itself.
- A binding begun while the subject held no counting factor binds only if none counts when it is written; else it writes nothing, answers `first-binding-closed`, and records `mfa.first_binding_conflict` (`kind`, `reason`). Of two first bindings at once, one binds.
- A binding asked from a login holds the password alone: it begins and binds only as the subject's first counting factor, whenever it began; once one counts, `begin` and `bind` answer `first-binding-closed` and record the conflict.
- A first counting factor begins only where every gate contributed admits it, given what the caller holds (`mfa-binding-proof`'s asks its proof); `begin` asks the kind for nothing before. With no gate, the first factor trusts whoever binds it.
- `bind` writes no recovery codes; a binding of a subject holding none keeps them a place. A label not of its shape is refused before anything is read.
- With a witnessing, its standing judges a first binding, each binding settles it after its write, and a first binding whose factor a reset took is `first-binding-closed`.

## Depends on
- `kernel`, `mfa-extensions` (`AskedFrom`), `mfa-reading` (`Shown`, `Fence`)
