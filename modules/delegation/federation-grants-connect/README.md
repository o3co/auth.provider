# federation-grants-connect

## Responsibilities
- Joins `federation-grants`: runs its browser half, the link a client sends the user to, the question, the user's decision and the upstream's callback, over the intents federation-grants owns (`grantIntents`).
- Decides whose upstream account a callback reached, under the identity check.
- Internal modules: `connect` (the browser half), `upstream-account` (the account reached).

## Not here
- The grants and their intents, records, sealing and audit, and the browser routes' declarations (paths, `csrf`, counting, other sites' reasons, return paths): `federation-grants`.
- Session entry (`session`), round trips (`upstream-round-trip`), the upstream's requests (`upstreams`' IdP type), who holds an upstream account (`users`).

## Offers
- Composition definition: a contribution at `federation-grants`' `grantsBrowsers`. It joins an app composing federation-grants, and no other.
- Operator section:
  - `page`, `login-page`, `step-up-page` (https; http only on a loopback host, and never in production)
  - `identity-check` (`required`)

## Invariants
- Connections refuse boot without the page that asks the user.
- A browser sent to the login page or the step-up page comes back to the connect it opened.
- A connection's upstream round trip is `upstream-round-trip`'s, taken before its code is exchanged, at its own connection; the intent, browser session and subject are checked before and after the exchange, after the tokens are judged.
- The upstream account matches the grant's and the client's `upstream_sub`; with `identity-check: required`, another holder or no answer refuses; `none`, every start warns `federation-grants-connect.identity_unchecked`.
- Tokens, secrets and upstream text reach neither answers nor logs.

## Depends on
- `kernel`, `http`, `url-setting`, `request-source`, `session`, `users`, `upstreams`, `upstream-round-trip`, `federation-grants`

## Vocabulary
- intent, connection, grant: as `federation-grants` names them.
