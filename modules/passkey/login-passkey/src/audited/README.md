# audited

Internal module of `login-passkey`: what it records.

## Responsibilities
- Records the package's audit events, each with the request's source.

## Not here
- When an event is recorded (`routes`, `opening`, `gate`). Which events there are (the package's `./audit-events`).

## Offers
- `recordedIn` → `session` (request, `opened` / `held` / `refused`, the subject where known, the reason) and `passwordRefused` (request, subject).

## Invariants
- The source is `request-source`'s where it determined one, and none otherwise. Nothing else of the request is recorded.

## Depends on
- `audit`, `request-source`, `http` (the request); the package's audit events
