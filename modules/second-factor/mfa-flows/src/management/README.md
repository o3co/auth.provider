# management

Internal module of `mfa-flows`: the session's routes for its own factors.

## Responsibilities
- Lists, names and removes factors, and reissues recovery codes.

## Not here
- The decisions on factors and the label's shape (`mfa`).

## Offers
- `managementOver` (`mfa`'s factor decisions, `session`) → the handlers of the list, renaming, removal and reissue.

## Invariants
- The list needs a live session; the others enter it at the credential-changing level (`mfa` contributes the requirement).
- Renaming takes `mfa`'s refusal of a label, after the session enters and before the factor; a missing label is refused too.

## Depends on
- `http` (the request type); `mfa` (factor decisions); `session` (entry); the package's routing helpers
