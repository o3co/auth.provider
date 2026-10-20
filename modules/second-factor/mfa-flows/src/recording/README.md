# recording

Internal module of `mfa-flows`: the audit events a request records, with where it came from.

## Responsibilities
- Records `mfa.<kind>` through the package's declaration of its audit events, adding the request's source.

## Not here
- Which event a flow records, and when (`proof`, `release`, and `mfa-enrollment` through `flowParts`). The reset's event, which has no request (`mfa-reset`). Deciding a request's source (`request-source`).

## Offers
- `auditedBy` (`audit`'s record) → a recorder taking the kind without `mfa.`, the subject, the request and the other attributes.

## Invariants
- Only the kinds and attributes the package declares (`./audit-events`) can be recorded.
- The source is added only when `request-source` determined it; an undetermined source is left out.

## Depends on
- `audit` (the declared recorder); `http` (the request type); `request-source` (the determined source); the package's declaration of its audit events
