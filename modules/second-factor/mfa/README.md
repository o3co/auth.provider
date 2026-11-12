# mfa

## Responsibilities
- Owns each subject's second factors: a kind's secret, sealed, and its state.
- Answers decisions about factors with their outcome; a record or a secret never leaves.
- Owns the extension points for factor kinds, the steps that prove them, and the proofs asked before a first binding.

## Not here
- Judging a proof or sending a challenge (the kind). Transactions, enrollment and step-up routes, and lockouts (`mfa-flows`). The routes managing factors (`mfa-management`). Judging sessions against second factors (`mfa-entry`). Sessions (`session`). Sealing (`seal`).

## Offers
- `proofSteps`: at least one, or `mfa` refuses to boot.
- Through `mfa-extensions`: `factorKinds`, the kinds taken asked at each binding and proof; `firstBindingGates`, asked by `begin`, with what the caller gave, while no counting factor is held; `witnessing` (at most one, two refusing boot).
- Provides `mfa-reading`'s `factorReading`, `mfa-binding`'s `factorBinding` and `mfa-managing`'s `factorManaging`, one implementation in each app; their cards hold the members and their rules.
- `fenceFollower`: the name what moves the fence on a revocation goes by among its followers.
- Extension point `enforcers`: the modules holding sessions to the factors (`mfa-entry`); without one, whatever the mode, boot is refused.
- Audit events, with the subject, once written (never for a refused or raced decision but a first binding refused (`mfa.first_binding_conflict`), nor a reset, never with a secret, proof or code): declared in `./audit-events`, listed in the audit event reference. A removal or reissue whose store answer is lost is recorded once a read after it shows it landed, and still answers unavailable.
- Contributions: `login-gates` amr (each kind taken's, and `mfa` if one adds it); `seal`'s `resealers`, a resealer sealing again what a `previous` key sealed.
- Section: `mode` (`optional`, which every start warns of as `mfa.not_required`, or `required` by default), `max-factors` (default 10).
- Store interface `factorStore`: factor lists and claims on unique values, by keys mfa makes, contents opaque; save once for a subject, read, change from what it holds, kept without end; a list and a claim changed as one, a binding writing its factor and the claim on its unique value at once; its ports' one statement, refused at build: `records`' card. Needs: never evicted, survives a crash and a failover, reads only what is confirmed.
- `./testing`: the store's contract test, a config builder, and `updatingAsOne` and `updatingTogether` (deprecated), a place's `updateAsOne` and `updateTogether` over records' stand-in.

## Invariants
- "required" refuses to boot unless a composed kind counts.
- The kinds it takes are those composed; under "required", a composed kind whose proof adds no `mfa` is left out of its table at boot, a standing rule: a login proving it would open a session nothing may use. Every decision looking up a kind (`begin`, `provePending`, `bind`, `held`, `asks`, `challenge`, `guessable`, `guessableBoundAfter`) answers for it as for a kind not composed, and its amr is not contributed; `remove` and `rename`, by a factor's id, still reach its record.
- A kind left out under "required" is warned of at every start (`mfa.kind_not_taken`, with its kind), from the judgment that leaves it out, and boot goes on.
- That warning is the one exception to refusing at boot a setting that does nothing, narrowed by the owner to this condition alone (#2666): a refusal would stop the deployments composing a code by mail as 0.19's `mfa-web` did, and push their operators to `mfa-email.adds-second-factor = true`, which loosens what a second factor assures.
- `kinds` means those composed where another module collects `factorKinds` (`mfa-entry`, `mfa-enrollment`); here, those taken.
- The rules of each decision are its contract's (`mfa-reading`, `mfa-binding`, `mfa-managing`): what a counting factor is, duplicates, first bindings, the fence, the recovery codes, and how a witnessing judges and is settled.
- A witness composed (`mfa-witness`) with no witnessing refuses boot, so it is never left unasked.
- A reissue whose store answer is lost may have replaced the set unseen: the codes, shown only in the answer and kept nowhere to show again, are then gone, and the user reissues.
- Only a gate's `true` admits a first binding; any other answer does not.

## Depends on
- `kernel`, `login-gates`, `seal`, `audit`, `mfa-reading`, `mfa-binding`, `mfa-managing` (the contracts it provides), `mfa-extensions` (the kinds, gates and witnessing), `mfa-witness` (only to refuse a witness left unasked), `labels` (the label's shape), `erasure-extensions` (the store ports' erasure types)
