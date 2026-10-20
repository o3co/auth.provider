# mfa-witnessing

## Responsibilities
- Keeps the enrollment witness in line with `mfa`'s counting factors, so that losing `mfa`'s store never reads as never enrolled. Bridges `mfa` and the witness composed (`mfa-witness`'s `enrollmentWitnesses`).
- Fills the mark of a subject that enrolled before the witness was composed (`witnessBackfill`).

## Not here
- The factors and every decision on them, and when the witness is asked: `mfa`. The witness's promises: `mfa-witness`. Carrying the marks to a ledger: the witness's adapter (`mfa-witness-http`).

## Offers
- Contribution to `mfa`'s `witnessing`:
  - `standing`: `held` for a subject holding a counting factor; `none` where the witness marks nothing either; a mark beside nothing counting is recorded as `mfa.enrollment_inconsistent` (`at`), logged, and unavailable, as is a witness that cannot be read.
  - `settle`, after a binding's write: a counting factor with no mark is marked under a new token; a mark beside nothing counting goes only where this call set it (a reset took the factor meanwhile). It reads again after each change, settles twice at most, then is unavailable while they still differ.
  - `cleared`, after a reset: the mark goes.
- Contract `witnessBackfill`: `settle(subject)` → `marked` (filled), `held`, `none`, or `inconsistent` (a mark beside nothing counting, left as it is); unavailable where the witness or `mfa` cannot answer.
- Audit event `mfa.enrollment_inconsistent`, declared in `./audit-events`.

## Invariants
- A mark follows a written factor: between a binding's write and its mark the factor stands unwitnessed, and a write that fails leaves no mark.
- A mark this package did not set is never cleared but by a reset; it may be a store that lost its factors.
- Boot is refused without exactly one witness composed.
- Comes once `mfa` and `mfa-witness-http` are both composed, through `combinations`; an app composed by hand with another witness composes it too.

## Depends on
- `kernel`, `audit`, `mfa` (its `witnessing` point and factor decisions), `mfa-extensions` (which kinds count), `mfa-witness` (the witness)
