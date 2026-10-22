# mfa-witnessing

## Responsibilities
- Keeps the enrollment witness in line with `mfa`'s counting factors, so that losing `mfa`'s store does not read as never enrolled, but for a factor lost between its write and its mark, or between a removal here that took its mark and the mark anew. Bridges `mfa` and the witness composed (`mfa-witness`'s `enrollmentWitnesses`).
- Fills the mark of a subject that enrolled before the witness was composed (`witnessBackfill`).

## Not here
- The factors and every decision on them, and when the witness is asked: `mfa`. The witness's promises: `mfa-witness`. Carrying the marks to a ledger: the witness's adapter (`mfa-witness-http`).

## Offers
- Contribution to `mfa`'s `witnessing`:
  - `standing`: `held` for a subject holding a counting factor; `none` where the witness marks nothing either; a mark beside nothing counting is recorded as `mfa.enrollment_inconsistent` (`at`), logged, and unavailable, as is a witness that cannot be read.
  - `settle`, after a binding's write: a counting factor with no mark is marked under a new token; a mark beside nothing counting goes only where this call's last mark is its own (a reset took the factor meanwhile), by the witness's `withdraw` where offered. After that removal it reads the factors again and marks anew where one counts. Every mark it makes is checked so, its own going where nothing counts; it marks twice at most, then is unavailable while they still differ.
  - `cleared`, after a reset, given `after`: it reads the mark's token once, then `after`. It withdraws that token's mark only where `none` stands, sent again with the same token, never reading again; a factor standing (`counting`) keeps the mark. `unsure` keeps it, recorded as `mfa.enrollment_inconsistent` (`at: reset`), logged, and unavailable.
    - After its withdraw it reads `after` again: beside a factor standing it fills a mark as backfill does; `unsure` is recorded and unavailable.
    - Given no `after`, it withdraws the token it read. Over a witness without `withdraw` or `markedWith`, it clears.
- Contract `witnessBackfill`:
  - `settle(subject)` → `marked` (this call filled it), `held` (marked already, or by another meanwhile), `none`, `unclaimed` (a factor written and none claimed, `mfa`'s `writtenStanding`; the mark as it is), or `inconsistent` (a mark it did not set beside nothing written, left as it is).
  - It reads the factors again after marking: a mark it set beside nothing counting (a reset took the factors meanwhile) goes, by `withdraw` where offered; a mark still standing beside nothing counting after a withdraw is `inconsistent`. After that removal it reads again and marks anew where one counts, three times at most; every mark it makes is checked so, and past the last it is unavailable, leaving at worst a factor unmarked.
  - Unavailable where the witness or `mfa` cannot answer, named `mfa` as `mfa` names it.
  - Unavailable too where a reset lands between its last read of the factors and its last read of the witness, though neither then holds anything; asked again, it answers `none`.
- Audit event `mfa.enrollment_inconsistent`, declared in `./audit-events`.

## Invariants
- A mark follows a written factor: between a binding's write and its mark the factor stands unwitnessed, and a write that fails leaves no mark.
- This package never decides to remove a mark it did not set, as it may be a store that lost its factors; a reset does, the token it read alone and only where `after` is `none`. It keeps its mark's token only while its enroll answered the mark is that token's, and removes nothing without it.
- Where the witness offers `withdraw`, its removal takes its own mark alone. Where it does not, it clears, which takes whatever mark stands, so its clear of its own may still take another's (below).
- A binding that took this call's mark for its own, by its enroll or its read, is left with no mark by this call's removal; this call then reads again and marks anew. A withdraw unavailable is sent again with the same token.
- At either limit, or where the read again, the mark anew or the withdraw stays unavailable, or the process stops, a removal of its own mark is not followed by a mark anew: the factor stands unmarked until a later binding or backfill marks it.
- Without `withdraw`, a clear of its own mark can also take a binding's mark set just before it; where the store also loses that binding's factor before the next read, the subject reads as never enrolled.
- Boot is refused without exactly one witness composed.
- Comes once `mfa` and `mfa-witness-http` are both composed, through `combinations`; an app composed by hand with another witness composes it too.

## Depends on
- `kernel`, `audit`, `mfa` (its factor decisions), `mfa-extensions` (the `witnessing` point), `mfa-witness` (the witness)
