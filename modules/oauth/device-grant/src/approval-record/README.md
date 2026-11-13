# approval-record

Internal module of `device-grant`: a device's approval, kept apart from the device, for its subject.

## Responsibilities
- Holds the approval record's format and its steps: keeping one, and reading it back.

## Not here
- Deciding the device (`verification`, on the device's record). Issuing from the approval (`grant`). Where it is kept (the store, `ApprovalRecords`).

## Offers
- `createApproval` (the approvals, the device's name, the approval, the device's end, now) → `created`, `exists` or `erased`: kept for its subject until the device's end and 120 s of drift, at least 1 ms. Nothing calls it yet.
- `approvalOf` (the approvals, the device's name) → the approval kept, or none. Nothing calls it yet.

## Invariants
- An approval is kept in format 1, holding the subject, the approval time, the amr, the authentication time (or that it is unknown) and the approving session.
- One of another format or shape is unavailable, never none: a device whose approval cannot be read is never issued.

## Depends on
- `kernel` (`Unavailable`); the package's `Approval` and store interfaces
