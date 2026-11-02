# passkey-witnessing

## Responsibilities
- Keeps the passkey witness's mark in line with what `passkeys` holds, so losing the passkey store never reads as holding none, but for a passkey lost between its write and its mark. Bridges `passkeys` and the witness composed (`passkey-witness`'s `passkeyWitnesses`).
- Fills the mark of a subject that registered before the witness was composed (`passkeyBackfill`).

## Not here
- The passkeys, every decision on them, and when the witness is asked: `passkeys`, which hands its reads (`holds`, `after`). The witness's promises: `passkey-witness`. Carrying the marks to a ledger: the witness's adapter (`passkey-witness-http`).

## Offers
- Contribution to `passkeys`' `passkeyWitnessing`:
  - `settle`: a subject holding a passkey with no mark is marked under a new token; a mark beside none goes where this call set it, by `withdraw`. It reads both again after each write and marks twice at most, then is unavailable while they still differ. It answers whether the subject holds a passkey, as the read the mark agreed with saw it.
  - `emptied`, after a write that emptied the list: it reads the mark's token, then `after`. It withdraws that token only where `after` answers `none`, asked again with the same token, never reading again. `passkey` and `pending` keep the mark. Once withdrawn it reads `after` again and marks anew where a passkey came meanwhile, a pending one marking once admitted.
- Contract `passkeyBackfill`:
  - `settle(subject)` → `marked` (this call filled it), `held` (marked already, or by another meanwhile), `none`, `pending` (only pending ones written; the mark as it is), or `inconsistent` (a mark it did not set beside nothing written, left as it is). It reads what is written through `passkeys`' `passkeyReading`.
  - It reads the passkeys again after marking: a mark it set beside none (a reset took them meanwhile) goes by its token; a mark still standing beside none after that withdraw is `inconsistent`. After that withdraw it reads again and marks anew where a passkey stands, three times at most; every mark it makes is checked so, and past the last it is unavailable.
  - Unavailable where the witness or `passkeys` cannot answer, their failure passed on as it is; past its last mark anew, or where its mark is gone though a passkey stands, it throws its own (`passkeys`). It records nothing.
- Audit event `passkey.enrollment_inconsistent` (`at`), declared in `./audit-events`.

## Invariants
- A mark follows a written passkey: between a registration's write and its mark the passkey stands unwitnessed, and a write that fails leaves no mark.
- This package never removes a mark it did not set, but the token it read after an emptying write, and only on `none`: a mark beside none may be a store that lost its passkeys.
- A mark beside none, read once more, and `after` answering `unsure` before the withdraw, are recorded as inconsistent and logged, the mark kept, and unavailable; `unsure` after the withdraw is recorded and unavailable alike, the mark gone. The record names the subject and where it was asked, never a token.
- A withdraw unavailable past its retries, or a read again that stops, may leave a passkey unmarked until a later settle; the call is unavailable.
- Boot is refused without exactly one witness composed.
- Comes once `passkeys` and `passkey-witness-http` are both composed, through `combinations`; an app composed by hand, or with another witness, composes it too, or `passkeys` refuses to boot.

## Depends on
- `kernel`, `audit`, `passkeys` (composed with it; its `passkeyWitnessing` and `passkeyReading`), `passkey-witness` (the witness)
