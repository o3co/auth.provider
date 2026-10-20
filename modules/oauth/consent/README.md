# consent

## Responsibilities
- Keeps each subject's grants, per client, as the union of the ranges agreed to.
- Keeps pending consents as one-time challenges tied to the session that asked.

## Not here
- When to ask for consent, and what the destinations do next (the caller decides).
- The consent page itself (the deployment runs it).
- Normalizing a range, such as Unicode forms (the caller does it).

## Offers
- `granted`: the range a subject agreed to for a client, from a confirmed read.
- `covers`: whether a grant holds the range; an empty range still needs a grant.
- `grant`: widens the grant to the union, answering after a confirmed write.
- `ask`: parks a request for the session's subject and answers the consent page URL with a `challenge` query parameter; only while `asking`, which a set page makes true.
- `ask` refuses with `TypeError` a destination that is not an https URL on the `http` public origin, or holds whitespace or a control character.
- `ask` refuses with `TypeError` a range entry that is empty, repeated, or holds whitespace or a control character.
- `GET /oauth/consent?challenge=`: the client id, the asked `scopes`, the `granted_scopes` and `expires_in`.
- The GET answer adds `client_name` and `client_uri` when set, and `client_id_host` only for a client from another source.
- `POST /oauth/consent`: takes `challenge` and `decision` (`accept` or `deny`) as a form or a JSON object.
- The POST answers `303` to the destination for the decision; a JSON member that is not a string counts as absent.
- Error codes: `no_session` (401), `unknown_challenge` (400), `invalid_decision` (400), `repeated_parameter` (400), `csrf` (403), `temporarily_unavailable` (503).
- Audit events, with the subject: declared in `./audit-events`, listed in the audit event reference.
- Client metadata section `consent`: `first-party` (default false), `name` (trimmed, cut to 200 characters), `uri` (an https URL) and `host`; from a document, `client_name` (refused absent, not a string or blank), `client_uri` as written, and the host its source checked, never `first-party`.
- `isFirstParty`: true only for a client the operator registered with `first-party` set.
- Operator section: `page` (an https URL without userinfo or fragment; unset by default, so nobody is asked) and `challenge-lifetime` (written with its unit, `1m` to `1h` in whole seconds, default `10m`).
- Store interfaces for grants and asks: save once, read, and update from what the record holds.
- `./testing`: configuration builders, both store interfaces on `records` stand-ins, and the store contract tests.

## Invariants
- Only the session that asked can see or answer its pending consent.
- The first answer marks the pending consent with its decision.
- The same decision sent again gets the same answer, so a lost response can be recovered by resending.
- The other decision, an expired challenge or an answered one (on the page) gets `unknown_challenge`.
- A CSRF failure or an invalid decision leaves the challenge usable.
- After a `503`, resending the same POST is the only way to recover, as the page may no longer show the challenge.
- The page shows a pending consent only while its client exists.
- A deadline counts on `kernel`'s clock, whatever the store still holds.
- An event is recorded for every completed answer, resends included.
- An acceptance is recorded only after its grant is written.
- Without a public origin, the module refuses to start.

## Data
- Grants: one record per subject and client, distinct and sorted, kept without end.
- A client registered again under the same id keeps its grants.
- Pending consents: one record per session and challenge, holding the request, subject, deadline and any answer, for the challenge's lifetime.
- The grant store must never evict, survive crashes and failovers, and confirm reads.
- The ask store needs the same except confirmed reads, and must not keep the key in clear.

## Depends on
- `kernel`, `http`, `url-setting`, `request-source`, `session`, `csrf`, `clients`, `audit`

## Vocabulary
- Consent range: a set of strings from the caller; consent only takes unions of it.
- Pending consent: what the caller asked (`Asked`) with the subject, the deadline and any answer.
- Ask: one pending consent as the ask store keeps it.
- First-party: a client the operator runs, which needs no consent.
