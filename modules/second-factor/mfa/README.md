# mfa

## Responsibilities
- Owns each subject's second factors: a kind's secret, sealed, and its state.
- Answers decisions about factors with their outcome; a record or a secret never leaves.
- Owns the extension points for factor kinds, the steps that prove them, and the proofs asked before a first binding.

## Not here
- Judging a proof or sending a challenge (the kind). Transactions, enrollment and step-up routes, and lockouts (`mfa-flows`). The routes managing factors (`mfa-management`). Judging sessions against second factors (`mfa-entry`). Sessions (`session`). Sealing (`seal`).

## Offers
- `proofSteps`: at least one, or `mfa` refuses to boot.
- Through `mfa-extensions`: `factorKinds`, asked at each binding and proof; `firstBindingGates`, asked by `begin`, with what the caller gave, while no counting factor is held; `witnessing` (at most one, two refusing boot).
- `factors`, its decisions:
  - Reading: `held`; `countingHeld` (judged against the witness); `countingWritten` (as written, a unique value's claimed); `secondFactorRequired`; `asks` (nothing / proof / binding); `guessable`; `guessableBoundAfter` (whether every factor of a guessable kind was bound after a time; an unknown kind, or a record with no time, as bound before).
  - Proving: `challenge` (sent with the kind, what to show and the challenge sealed / none / limited / refused with the kind, and `contact-changed` when the kind gives it / unknown); `prove`, given the sealed challenge (valid with amr / invalid / replayed / raced).
  - Binding: `begin`, given what the caller holds for the gates (begun with what to show / unknown kind / full / limited / refused / duplicate / binding proof required / first binding closed); `provePending` (valid with the proof's own amr / invalid / unknown); `bind` (bound, with the fence it began under and whether codes are due / full / unknown / malformed label / duplicate / fenced); `fence` (no binding begun before binds).
  - Managing: `rename`; `remove`; `clear` (every factor of the subject, of any kind → how many, and their kinds sorted once each); `reissue` (the first set too; `full` past `max-factors`). `remove` and `reissue`, given a fence read before (`fenceOf`'s, or a binding's), change nothing (`fenced`) once it moved past it. The fence stops `bind`, `remove` and `reissue` only: `rename` and `prove` do not read it.
- `fenceFollower`: the name what moves the fence on a revocation goes by among its followers.
- Extension point `enforcers`: the modules holding sessions to the factors (`mfa-entry`); without one, whatever the mode, boot is refused.
- Audit events, with the subject, once written (never for a refused or raced decision but a first binding another factor beat, nor a reset, never with a secret, proof or code): declared in `./audit-events`, listed in the audit event reference.
- Contributions: `login-gates` amr (each kind's, and `mfa` if one adds it); `seal`'s `resealers`, a resealer sealing again what a `previous` key sealed.
- Section: `mode` (`optional`, or `required` by default), `max-factors` (default 10).
- Store interface `factorStore`: factor lists and claims on unique values, by keys mfa makes, contents opaque; save once, read, change from what it holds, kept without end. Needs: never evicted, survives a crash and a failover, reads only what is confirmed. `./testing`: its contract test, and a config builder.

## Invariants
- A counting factor is one of a kind declared counting. "optional" stops only subjects holding a factor; "required" asks one with no counting factor for a first binding, and never removes the last (`last`), one of a unique value not yet claimed not counting as one.
- "required" refuses to boot unless a composed kind counts.
- Removing the last counting factor removes the recovery codes in the same write. Recovery codes are written by `reissue` alone, handed once in that call, and count toward `max-factors`: a binding of a subject holding none keeps them a place.
- A factor's state is written only over the state judged, so one proof passes once; a factor gone meanwhile is raced. A store that cannot answer is unavailable, never a refusal.
- A sealed value given back comes only from mfa's records or `mfa-flows`' transactions, so one that will not open is unavailable.
- A binding whose unique value another factor holds, of any subject, is refused as duplicate and leaves nothing, even when two bind at once; `begin` refuses it already when the secret alone tells the value. A binding begun before a reset or a `fence` of the subject writes nothing (`fenced`), checked in the write itself.
- A way back that will not enrol fails `reissue` as unavailable.
- A binding begun while the subject held no counting factor binds only if none counts when it is written; else it writes nothing, answers `first-binding-closed`, and records `mfa.first_binding_conflict` (`kind`, `reason`). Of two first bindings at once, one binds.
- A binding asked from a login holds the password alone: it begins and binds only as the subject's first counting factor, whenever it began; once one counts, `begin` and `bind` answer `first-binding-closed` and record the conflict.
- A proof adds its own amr kept to its kind's (else its kind's), and `mfa` when its kind adds it. A label not of its shape is refused before anything is read.
- A first counting factor begins only where every gate contributed admits it, given what the caller holds (`mfa-binding-proof`'s asks its proof); `begin` asks the kind for nothing before. With no gate, the first factor trusts whoever binds it.
- With a witnessing, its standing judges login, a first binding and credentials (a subject marked with nothing counting is unavailable), each binding settles it after its write, a first binding whose factor a reset took is `first-binding-closed`, the last counting factor is never removed, and `clear` removes the factors, then has the mark go. Without one, a lost store reads as never enrolled.
- A witness composed (`mfa-witness`) with no witnessing refuses boot, so it is never left unasked.

## Depends on
- `kernel`, `login-gates`, `seal`, `audit`, `mfa-extensions` (the kinds, gates and witnessing), `mfa-witness` (only to refuse a witness left unasked), `labels` (the label's shape)
