# mfa-reading

## Responsibilities
- Owns the contract for reading a subject's second factors and proving one: what is held and counts, what a login asks, and a proof, which updates the factor's state.
- Owns the words the factor contracts share: `Shown`, a factor as the user sees it, and `Fence`, where a subject's fence stood, compared across binding and managing.

## Not here
- The records, and every decision made over them: `mfa`, which provides the contract. Binding a factor: `mfa-binding`. Managing factors: `mfa-managing`. Judging a proof or sending a challenge: the kind (`mfa-extensions`).

## Offers
- `factorReading` (`mfa.factor-reading`), provided by `mfa`:
  - Reading: `held`; `countingHeld` (judged against the witness, given where it is asked, `mfa-extensions`' `Asked`); `countingWritten` (as written, a unique value's claimed); `writtenStanding` (as written: counting / unclaimed, written and none claimed / none); `secondFactorRequired`; `asks` (nothing / proof / binding); `guessable`; `guessableBoundAfter` (whether every factor of a guessable kind was bound after a time; an unknown kind, or a record with no time, as bound before).
  - Proving: `challenge` (sent with the kind, what to show and the challenge sealed / none / limited / refused with the kind, and `contact-changed` when the kind gives it / unknown); `prove`, given the sealed challenge (valid with amr / invalid / replayed / raced).
- `Shown`, `Fence` (compared, never computed with), `Proved`, `Challenged`.

## Invariants
- A counting factor is one of a kind declared counting. "optional" stops only subjects holding a factor; "required" asks one with no counting factor for a first binding, one of a unique value not yet claimed not counting as one.
- A factor's state is written only over the state judged, so one proof passes once; a factor gone meanwhile is raced. A store that cannot answer is unavailable, never a refusal.
- A sealed value given back comes only from mfa's records or `mfa-flows`' transactions, so one that will not open is unavailable.
- A proof adds its own amr kept to its kind's (else its kind's), and `mfa` when its kind adds it.
- With a witnessing, its standing judges login and credentials: a subject marked with nothing counting is unavailable. Without one, a lost store reads as never enrolled.

## Depends on
- `kernel`, `mfa-extensions` (`Asked`, `AskedFrom`, `RefusedReason`)
