# upstreams

## Responsibilities
- Says what an upstream IdP is to this provider: the IdP types that open one, what an opened upstream does, and who receives a login's upstream tokens.

## Not here
- Logging a browser in through an upstream, the IdPs' settings and opening them at boot (the implementation).
- What differs per IdP: discovery, keys, the token request, the id_token checks (the type).
- What IdP types share as OAuth clients of an upstream (`upstream-client`).
- Keeping upstream tokens (the receivers).

## Offers
- Extension point `idpTypes`: type name → settings schema, and opening an IdP at boot → upstream; `idpType` types what `open` receives by the type's schema
  - A type sees only its own settings, never `type` or the others the implementation reads.
  - `open` throws `UpstreamMismatch(reason, at)` to say why it refuses the settings and at which of their keys; the reason names no configuration value.
- An upstream: how it answers (in the query or a posted form), its clock allowance, authorization URL, and code exchange → upstream login, with its tokens and profile if the type gives them
  - The code exchange gets the verifier, nonce, redirect URI and the callback's `iss`.
- An upstream's exchanges and refreshes throw `UpstreamRefused` for an answer that does not hold, and `Unavailable` when it cannot be reached or fails (5xx); a delegation's start is refused as a value, never thrown.
- An upstream may also offer a refresh, an end-session URL and an offline delegation
- An offline delegation: its authorization URL, or a refusal of the start as a value; its code exchange given the scopes and resource its start asked for; and its refresh
- `upstreams.of` (IdP name → its upstream's refresh, end-session URL and delegation, where the type offers them / nothing)
- Extension point `upstreamLoginReceivers` (name → `received` (session, IdP, upstream tokens) once the session opens, or once a link joins it to the session; `withdrawn` (session, IdP) when a later step fails)

## Invariants
- A login's receivers are told in name order; one that throws is logged by name and error kind, and the rest are still told.
- A link's receivers are told in name order; when one fails, those told are withdrawn, the rest are not told, and the link is unavailable.
- A login's tokens are taken once and go only to a session of the subject that logged in; their lifetime counts from the hand-over.

## Depends on
- `kernel`, `session` (the session a receiver is told); implemented by `federation`.

## Vocabulary
- IdP type: what one kind of upstream IdP does differently.
- upstream login: what an upstream says of a login it made: the upstream subject (`users`' word, as is upstream identity), its amr, when, and its profile of the user.
