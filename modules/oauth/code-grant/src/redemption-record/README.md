# redemption-record

Internal module of `code-grant`: each redemption's record, which holds its token and outlives its code.

## Responsibilities
- The redemption record's format, and its steps in a redemption: created once the code is used up, bounding its token's end, then holding its token; marked void on a reuse.

## Not here
- Deciding a code was used up or came again (the grant). Revoking the token (`voiding`). Where the record is kept (the Store).

## Offers
- `createRedemptionRecord` (the records, the redemption's name, the subject) → `created`, `exists` or `erased`, for `storedRecordMaxMs`; `tokenEndFor` (when its creation was read) → the latest its token may end; `noteToken`, `markVoid` → the record after, or none where it is gone; `isRedeemed` → whether one is kept under the name.
- `RedemptionRecord` and its stored form (`toStoredRedemptionRecord`, `fromStoredRedemptionRecord`, checked on every read).

## Invariants
- Use-up, then the record is created, under its subject's tombstone, then the token is issued, then noted on the record: a reuse that finds no token has nothing yet to revoke, right only by that order. A subject erased meanwhile gets no record, so no token: the code is refused and voided.
- Its token ends at least 120 s before the record, the creation's time read before its write; it ends no later than its session as well.
- A note or a mark rewrites what the record holds and keeps its end; a record gone is never written back.
- Until 0.22, the token is noted on the code's own record too, keeping the code's end and never deciding a use, so a 0.19 instance that takes a reuse while the code lives revokes it.
- Left in the upgrade window (owner, accepted): a reuse a 0.19 instance takes after the code ends revokes nothing, and a 0.19 sweep, which runs without traffic, drops a failed revocation's listing once the code ends. Either token ends at its normal end.

## Depends on
- `zod`; the package's store interfaces and `storedRecordMaxMs`.
