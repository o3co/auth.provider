# redemption-record

Internal module of `code-grant`: each redemption's record, which holds its token and outlives its code.

## Responsibilities
- The redemption record's format, and its steps: created for its subject, bounding its token's end, then holding its token; marked void.

## Not here
- Deciding a code was used up or came again (the grant). Revoking the token (`voiding`). Where the record is kept (the Store).

## Offers
- `createRedemptionRecord` (the records, the redemption's name, the subject) → `created`, `exists` or `erased`, for `storedRecordMaxMs`; `tokenEndFor` (when its creation was read) → the latest its token may end; `noteToken`, `markVoid` → the record after, or none where it is gone; `isRedeemed` → whether one is kept under the name.
- `RedemptionRecord` and its stored form (`toStoredRedemptionRecord`, `fromStoredRedemptionRecord`, checked on every read).

## Invariants
- A token ends at least 120 s before its record, the creation's time read before its write.
- A note or a mark rewrites what the record holds and keeps its end; a record gone is never written back.

## Depends on
- `zod`; the package's store interfaces and `storedRecordMaxMs`.
