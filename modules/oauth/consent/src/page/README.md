# page

Internal module of `consent`: the two routes the deployment's consent page calls.

## Responsibilities
- Shows the session's pending consent to the page, and takes the user's decision on it.

## Not here
- The page itself (the deployment runs it). Grant records (`grants`). Parking a pending consent (the package).

## Offers
- `GET /oauth/consent?challenge=`: the client id, the `redirect_hosts`, the asked `scopes`, the `granted_scopes` and `expires_in`.
- `redirect_hosts`: every destination of the client's redirect URIs, for every client, as `redirect-uris`' `redirectsShown` says: `host` and `kind` (`web`, `loopback` or `app`), so the user sees all of what the agreement holds for, not the one a request names.
- The GET answer adds `client_name` and `client_uri` when set, and `client_id_host` only for a client from another source.
- `POST /oauth/consent`: takes `challenge` and `decision` (`accept` or `deny`) as a form or a JSON object.
- The POST answers `303` to the destination for the decision; a JSON member that is not a string counts as absent.
- Error codes: `no_session` (401), `unknown_challenge` (400), `invalid_decision` (400), `repeated_parameter` (400), `csrf` (403), `temporarily_unavailable` (503).
- `path`, `showOver` and `answerOver` (the build context → each route's handler), which the package's module declares.

## Invariants
- Only the session that asked can see or answer its pending consent.
- The first answer marks the pending consent with its decision.
- The same decision sent again gets the same answer, so a lost response can be recovered by resending.
- The other decision, an expired challenge or an answered one (on the page) gets `unknown_challenge`.
- A CSRF failure or an invalid decision leaves the challenge usable.
- After a `503`, resending the same POST is the only way to recover, as the page may no longer show the challenge.
- The page shows a pending consent only while its client exists and, for a client from another source, only while its section says the `under` the pending consent holds.
- An answer is taken on the same terms, so a stale page replaces no newer grant, and leaves the challenge unanswered: `unknown_challenge`, a resend's too. An acceptance writes under the `under` the pending consent holds.
- An event is recorded for every completed answer, resends included. A refused acceptance, its grant refused as its subject was erased meanwhile, is no completed answer: it is answered `401 no_session`, as the erasure ended the sessions, records nothing and sends on nothing; the pending consent stays marked `accept`, with no grant.
- An acceptance is recorded only after its grant is written.

## Depends on
- `http` (answers, the route's type), `session`, `clients`, `redirect-uris` (the section `authorize` composes, read through `redirectsShown`), `audit`, `request-source`, `kernel` (the build context, the clock, `Unavailable`); `grants`; the package's ask store, pending consents and audit events
