# logout

## Responsibilities
- Provides the session logout endpoint.

## Not here
- The closing order and cookie handling: `session`.
- Cleanup by the other participants: theirs.

## Offers
- Composition definition: route `POST /session/logout`, taking a form, a JSON body or none; it reads no field itself.
- Audit events, with the subject and `sid` of the session closed where `session` names one, and the request's `source` where `request-source` determined it: declared in `./audit-events`, listed in the audit event reference.

## Invariants
- `csrf`'s policy is declared on the route (`403`).
- The route counts no source, with the reason declared: it closes only the requester's own session, so there is nothing to guess or spend.
- `session` closes the session the request's cookie points to, whatever its state, and the cookie is cleared, on a pending close too. Without a cookie it does nothing and answers `200`.
- A pending close, or `session` unavailable, answers `503` `temporarily_unavailable`. No answer is cached.

## Depends on
- `kernel`, `http`, `request-source`, `session`, `csrf`, `audit`
