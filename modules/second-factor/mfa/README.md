# mfa

## Responsibilities
- Owns each subject's second factors: a kind's secret, sealed, and its state.
- Answers decisions about factors with their outcome; a record or a secret never leaves.
- Owns the extension points for factor kinds, the steps that prove them, and the proofs asked before a first binding.
- Sets the entry requirements for a recent second factor.

## Not here
- Judging a proof or sending a challenge (the kind). Transactions, enrollment and step-up routes, and lockouts (`mfa-flows`). The routes managing factors (`mfa-management`). Sessions (`session`). Sealing (`seal`).

## Offers
- `factorKinds`: name; the amr it can add; `addsSecondFactor` (whether its proofs add `mfa`); `guessable`; `counts`; optional `uniqueSecret` (a value no two factors of the kind may hold); `enroll` (subject, its factors of the kind → secret and what to show once / limited / refused / duplicate); optional `challenge` (subject, factor, latest end → sent with what to show and what to keep / limited / refused); `verify` (secret, state, proof, what the challenge kept → valid with the next state, optional amr and optional remaining / invalid / replayed).
- `AskedFrom` (a login with its stated email and whether the ledger vouches for it, or a session's handle): passed to kinds, proofs and gates unread.
- `proofSteps`: at least one, or `mfa` refuses to boot. `firstBindingGates`: asked by `begin`, with what the caller gave, while no counting factor is held.
- `factors`: `held`; `countingHeld`; `asks` (nothing / proof / binding); `guessable`; `guessableBoundAfter` (whether every factor of a guessable kind was bound after a time; an unknown kind, or a record with no time, as bound before); `recent` (whether a proof at a time is within `session`'s recent-authentication window); `provenRecently` (a second factor proven within it; a sign-in alone never); `challenge` (sent with the kind, what to show and the challenge sealed / none / limited / refused with the kind, and `contact-changed` when the kind gives it / unknown); `prove`, given the sealed challenge (valid with amr / invalid / replayed / raced); `begin`, given what the caller holds for the gates (begun with what to show / unknown kind / full / limited / refused / duplicate / binding proof required / first binding closed); `provePending` (valid with the proof's own amr / invalid / unknown); `bind` (bound / full / unknown / malformed label / duplicate); `rename`; `remove`; `clear` (every factor of the subject, of any kind → how many, and their kinds sorted once each); `reissue`.
- `isLabel` (1 to 64 code points, well formed, nothing that breaks or reorders a line) and `secondFactorAmr` (`mfa`).
- Audit events, with the subject, once written (never for a refused or raced decision but a first binding another factor beat, nor a reset, never with a secret, proof or code): declared in `./audit-events`, listed in the audit event reference.
- Contributions: `session` entry requirements, judging `use` and `credentials`; `login-gates` amr (each kind's, and `mfa` if one adds it).
- Section: `mode` (`optional`, or `required` by default), `max-factors` (default 10).
- Store interface `factorStore`: factor lists and claims on unique values, by keys mfa makes, contents opaque; save once, read, change from what it holds, kept without end. Needs: never evicted, survives a crash and a failover, reads only what is confirmed. `./testing`: its contract test, and a config builder.

## Invariants
- A kind is guessable unless it says not, as in 0.17.
- A factor list's record holds its subject, so its secrets can be sealed again; the store's key is the subject's hash.
- A secret a `previous` key sealed is sealed again in the write a proof of its factor makes, and by the resealer `mfa` at `seal`'s `resealers`, which walks every list and writes only over the secret read; one no key opens, or a list whose subject is not its key's, is left.
- A counting factor is one of a kind declared counting. "optional" stops only subjects holding a factor; "required" asks one with no counting factor for a first binding, and never removes the last (`last`).
- "required" refuses to boot unless a composed kind both counts and adds `mfa`, since no session could then be used.
- Removing the last counting factor removes the recovery codes in the same write. Recovery codes come with the first counting factor, are shown once, and count toward `max-factors`.
- A factor's state is written only over the state judged, so one proof passes once; a factor gone meanwhile is raced. A store that cannot answer is unavailable, never a refusal.
- A secret, and what a challenge kept, are sealed to the subject and the factor; a pending binding, to the subject. A sealed value given back comes only from mfa's records or `mfa-flows`' transactions, so one that will not open is unavailable.
- A binding whose unique value another factor holds, of any subject, is refused as duplicate and leaves nothing, even when two bind at once; `begin` refuses it already when the secret alone tells the value.
- A way back that will not enrol fails a first binding as unavailable.
- A binding begun while the subject held no counting factor binds only if none counts when it is written; else it writes nothing, answers `first-binding-closed`, and records `mfa.first_binding_conflict` (`kind`). Of two first bindings at once, one binds.
- A binding asked from a login holds the password alone: it begins and binds only as the subject's first counting factor, whenever it began; once one counts, `begin` and `bind` answer `first-binding-closed` and record the conflict.
- A proof adds its own amr kept to its kind's (else its kind's), and `mfa` when its kind adds it. A label not of its shape is refused before anything is read.
- Changing credentials needs `mfa` added recently (as `session`'s `recent` tells), or a recent login while no counting factor is held; else `step_up_required`. A login at a time the upstream did not give is never recent, nor is the `mfa` it says it proved. Under "required", using a session needs `mfa`.
- A first counting factor begins only where every gate contributed admits it, given what the caller holds (`mfa-binding-proof`'s asks its proof); `begin` asks the kind for nothing before. With no gate, the first factor trusts whoever binds it.

## Depends on
- `kernel`, `session`, `login-gates`, `seal`, `audit`
