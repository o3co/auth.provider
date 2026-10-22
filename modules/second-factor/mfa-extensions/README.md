# mfa-extensions

## Responsibilities
- Owns what a module implements for `mfa`: a kind of second factor, a gate asked before a subject's first counting factor, and the witnessing, with the types they take and give.

## Not here
- What `mfa` decides with them, and the steps that prove factors: `mfa`.
- Each kind and each gate: the module that contributes it.

## Offers
- `factorKinds`, keyed by name: what a kind declares and does.
  - Declares: the amr it can add; `addsSecondFactor` (whether its proofs add `mfa`); `guessable`; `counts`; optional `uniqueSecret` (a value no two factors of the kind may hold).
  - `enroll` (subject, its factors of the kind → secret and what to show once / limited / refused / duplicate).
  - Optional `challenge` (subject, factor, latest end → sent with what to show and what to keep / limited / refused).
  - `verify` (secret, state, proof, what the challenge kept → valid with the next state, optional amr and optional remaining / invalid / replayed).
- `AskedFrom` (a login with its stated email and whether the ledger vouches for it, or a session's handle): passed to kinds, proofs and gates unread.
- `firstBindingGates`: asked by `begin`, with what the caller gave, while no counting factor is held; a gate refusing answers `binding-proof-required`.
- `secondFactorAmr` (`mfa`): the amr a proof adds when its kind adds a second factor (RFC 8176).
- `witnessing` (at most one, two refusing boot): who tells, beside the store, that a subject enrolled; `mfa-witnessing` contributes it over the witness composed (its card holds the rules). `Asked`: where a standing is asked (`login`, `binding`, `credentials`). After a reset, `cleared` is given `after`, read anew each time: `counting` (a factor stands, written since), `none` (none written, the reset's write held), else `unsure`.

## Invariants
- A kind is guessable unless it says not, as in 0.17.
- Nothing here runs: `mfa` collects the kinds, gates and witnessing, and decides with them.

## Depends on
- `kernel`
