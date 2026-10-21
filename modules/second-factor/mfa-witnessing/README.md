# mfa-witnessing

## Responsibilities
- Keeps the enrollment witness in line with `mfa`'s counting factors, so that losing `mfa`'s store does not read as never enrolled, but for a factor lost between its write and its mark, or between a clear here that took its mark and the mark anew. Bridges `mfa` and the witness composed (`mfa-witness`'s `enrollmentWitnesses`).
- Fills the mark of a subject that enrolled before the witness was composed (`witnessBackfill`).

## Not here
- The factors and every decision on them, and when the witness is asked: `mfa`. The witness's promises: `mfa-witness`. Carrying the marks to a ledger: the witness's adapter (`mfa-witness-http`).

## Offers
- Contribution to `mfa`'s `witnessing`:
  - `standing`: `held` for a subject holding a counting factor; `none` where the witness marks nothing either; a mark beside nothing counting is recorded as `mfa.enrollment_inconsistent` (`at`), logged, and unavailable, as is a witness that cannot be read.
  - `settle`, after a binding's write: a counting factor with no mark is marked under a new token; a mark beside nothing counting goes only where this call's last mark is its own (a reset took the factor meanwhile). After that clear it reads the factors again and marks anew where one counts. Every mark it makes is checked so, its own going where nothing counts; it marks twice at most, then is unavailable while they still differ.
  - `cleared`, after a reset: the mark goes.
- Contract `witnessBackfill`:
  - `settle(subject)` → `marked` (this call filled it), `held` (marked already, or by another meanwhile), `none`, or `inconsistent` (a mark it did not set beside nothing counting, left as it is).
  - It reads the factors again after marking: a mark it set beside nothing counting (a reset took the factors meanwhile) goes. After that clear it reads again and marks anew where one counts, three times at most; every mark it makes is checked so, and past the last it is unavailable, leaving at worst a factor unmarked.
  - Unavailable where the witness or `mfa` cannot answer, named `mfa` as `mfa` names it.
  - Unavailable too where a reset lands between its last read of the factors and its last read of the witness, though neither then holds anything; asked again, it answers `none`.
- Audit event `mfa.enrollment_inconsistent`, declared in `./audit-events`.

## Invariants
- A mark follows a written factor: between a binding's write and its mark the factor stands unwitnessed, and a write that fails leaves no mark.
- This package never decides to clear a mark it did not set, as it may be a store that lost its factors; a reset does. The witness's clear takes whatever mark stands, so its clear of its own may still take another's (below).
- At either limit, a clear of its own mark is not followed by a mark anew: the call is unavailable, and the factor stands unmarked.
- A clear of its own mark can take a binding's mark set just before it; where the store also loses that binding's factor before the next read, the subject reads as never enrolled.
- Boot is refused without exactly one witness composed.
- Comes once `mfa` and `mfa-witness-http` are both composed, through `combinations`; an app composed by hand with another witness composes it too.

## Depends on
- `kernel`, `audit`, `mfa` (its `witnessing` point and factor decisions), `mfa-witness` (the witness)
