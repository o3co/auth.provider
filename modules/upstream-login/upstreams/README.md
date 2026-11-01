# upstreams

## Responsibilities
- Says what an upstream IdP is to this provider: the IdP types that open one, what an opened upstream does, and who receives a login's upstream tokens.

## Not here
- Logging a browser in through an upstream, the IdPs' settings and opening them at boot (the implementation; see the owner map).
- What differs per IdP: discovery, keys, the token request, the id_token checks (the type).
- What IdP types share as OAuth clients of an upstream (`upstream-client`).
- Keeping upstream tokens (the receivers).

## Offers
- Extension point `idpTypes`: type name → settings schema, and opening an IdP at boot → upstream; `idpType` types what `open` receives by the type's schema
  - A type sees only its own settings, never `type` or the others the implementation reads.
  - `open` gets the IdP's name as `idp`, the word `upstreams.of` and the receivers use, and its redirect URI.
  - `open` throws `UpstreamMismatch(reason, at)` to say why it refuses the settings and at which of their keys; the reason names no configuration value.
- An upstream: its issuer, how it answers (in the query or a posted form), its clock allowance, authorization URL, and code exchange → upstream login, with its tokens and profile if the type gives them
  - The code exchange gets the verifier, nonce, redirect URI and the callback's `iss`.
- Exchanges and refreshes throw `UpstreamRefused` for an answer that does not hold (an exchange's 5xx too), `Unavailable` when unreachable (a refresh's 5xx too); a delegation's start refuses as a value, never throws.
- `UpstreamRefused.is` and `UpstreamMismatch.is` tell each by a mark, which every copy of upstreams in a bundle shares; a caller tells them so, never by its class.
- An upstream may also offer a refresh, an end-session URL and an offline delegation
- A refresh answers new tokens, `invalid_grant` (the grant is gone), `interaction_required` (the grant stands, but the user must act at the upstream first) or `limited` (with when to ask again, where said).
- `refreshedExpiry` (the answer's access token and end, what was held): where the upstream hands the same access token again, the earlier of the two ends, so a refresh never lengthens a token; else the answer's end. Every holder of refreshed tokens reads them by it.
- An offline delegation: its authorization URL, or a refusal of the start as a value; its code exchange given the scopes and resource its start asked for; and its refresh
- `upstreams.of` (IdP name → its upstream's refresh, end-session URL and delegation, where the type offers them / nothing)
- Extension point `upstreamLoginReceivers` (name → `received` (session, IdP, upstream tokens) once the session opens, or once a link joins it to the session, answering a receipt of what it kept or none; `withdrawn` (session, IdP, the receipt) when a later step fails)
  - A receipt is the receiver's alone to read; a caller holds it and hands it back. `withdrawn` deletes only what that `received` kept, and nothing written since; with none, nothing.
- Extension point `upstreamContinuations` (name → `begin` (request, IdP) refusing the start or keeping JSON in the round trip; `complete` (the request, IdP, upstream login, what it kept, where the browser lands, the source and user agent, the cookie cleared) answering the browser; `failed` for a refusal after the take): where a round trip goes besides a login, chosen by name at its start.

## Invariants
- A login's receivers are told in name order; one that throws is logged by name and error kind, and the rest are still told.
- A link's receivers are told in name order; when one fails, those told are withdrawn, the rest are not told, and the link is unavailable.
- A login's tokens are taken once and go only to a session of the subject that logged in; their lifetime counts from the hand-over.

## Depends on
- `kernel`, `session` (the session a receiver is told), `http` (what a continuation is asked and answers)

## Vocabulary
- IdP type: what one kind of upstream IdP does differently.
- upstream login: what an upstream says of a login it made: the upstream subject (`users`' word, as is upstream identity), its amr, when, and its profile of the user.
