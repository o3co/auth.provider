# consent

## Responsibilities
- Keeps each subject's grants, per client, as the union of the ranges agreed to.
- Keeps pending consents as one-time challenges tied to the session that asked.
- Its internal modules: `grants` reads and writes the grant records; `page` answers the consent page's two routes.

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
- Routes `GET` and `POST /oauth/consent`, answering the consent page (`page`'s card).
- Audit events, with the subject: declared in `./audit-events`, listed in the audit event reference.
- Client metadata section `consent`: `first-party` (default false), `name` (trimmed, cut to 200 characters), `uri` (an https URL) and `host`; from a document, `client_name` (refused absent, not a string or blank), `client_uri` as written, and the host its source checked, never `first-party`, by `clientCopy`, contributed to `client-documents`' `documentCopies`.
- `isFirstParty`: true only for a client the operator registered with `first-party` set; every start warns `consent.first_party` for each such client.
- Operator section: `page` (an https URL without userinfo or fragment, or plain http on a loopback host outside production, as `authorize`'s login page; unset by default, so nobody is asked) and `challenge-lifetime` (written with its unit, `1m` to `1h` in whole seconds, default `10m`).
- Store interfaces for grants and asks: save once, read, and update from what the record holds.
- `./testing`: configuration builders, both store interfaces on `records` stand-ins, and the store contract tests.

## Invariants
- A deadline counts on `kernel`'s clock, whatever the store still holds.
- Without a public origin, the module refuses to start.

## Data
- Grants: as `grants` keeps them.
- Pending consents: one record per session and challenge, holding the request, subject, deadline and any answer, for the challenge's lifetime.
- The grant store must never evict, survive crashes and failovers, and confirm reads.
- The ask store needs the same except confirmed reads, and must not keep the key in clear.

## Depends on
- `kernel`, `http`, `url-setting`, `request-source`, `session`, `csrf`, `clients`, `client-documents`, `audit`

## Vocabulary
- Consent range: a set of strings from the caller; consent only takes unions of it.
- Pending consent: what the caller asked (`Asked`) with the subject, the deadline and any answer.
- Ask: one pending consent as the ask store keeps it.
- First-party: a client the operator runs, which needs no consent.
