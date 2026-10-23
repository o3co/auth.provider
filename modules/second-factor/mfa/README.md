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
- Provides `mfa-reading`'s `factorReading`, `mfa-binding`'s `factorBinding` and `mfa-managing`'s `factorManaging`, one implementation in each app; their cards hold the members and their rules.
- `fenceFollower`: the name what moves the fence on a revocation goes by among its followers.
- Extension point `enforcers`: the modules holding sessions to the factors (`mfa-entry`); without one, whatever the mode, boot is refused.
- Audit events, with the subject, once written (never for a refused or raced decision but a first binding another factor beat, nor a reset, never with a secret, proof or code): declared in `./audit-events`, listed in the audit event reference.
- Contributions: `login-gates` amr (each kind's, and `mfa` if one adds it); `seal`'s `resealers`, a resealer sealing again what a `previous` key sealed.
- Section: `mode` (`optional`, or `required` by default), `max-factors` (default 10).
- Store interface `factorStore`: factor lists and claims on unique values, by keys mfa makes, contents opaque; save once, read, change from what it holds, kept without end; a list and a claim changed as one (`updateTogether`), a binding writing its factor and the claim on its unique value at once; mfa refuses to start over a store without it. Needs: never evicted, survives a crash and a failover, reads only what is confirmed.
- `./testing`: the store's contract test, a config builder, and `updatingTogether`, a place's `updateTogether` over records' stand-in.

## Invariants
- "required" refuses to boot unless a composed kind counts.
- The rules of each decision are its contract's (`mfa-reading`, `mfa-binding`, `mfa-managing`): what a counting factor is, duplicates, first bindings, the fence, the recovery codes, and how a witnessing judges and is settled.
- A witness composed (`mfa-witness`) with no witnessing refuses boot, so it is never left unasked.

## Depends on
- `kernel`, `login-gates`, `seal`, `audit`, `mfa-reading`, `mfa-binding`, `mfa-managing` (the contracts it provides), `mfa-extensions` (the kinds, gates and witnessing), `mfa-witness` (only to refuse a witness left unasked), `labels` (the label's shape)
