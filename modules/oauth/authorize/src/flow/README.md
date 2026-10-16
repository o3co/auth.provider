# flow

Internal module of `authorize`: the steps a request goes through once its redirect URI is trusted, up to its code.

## Responsibilities
- Runs the steps in order, sends a request without a fresh enough session to the login page, and has `code-grant` issue the code.

## Not here
- Reading the request and answering it (`route`). What each step decides (`checks`, `reauth`, `step-up`, `consent-decision`).

## Offers
- `flowOver` → `flowWith` → a trusted request → a decision.
  - `flowOver` takes the build context, the issuer's URL and the endpoint's.
  - `flowOver` builds `reauth`, `step-up`, `consent-decision` and the target check.
  - `flowWith` takes the issuer's URL and the endpoint's, `session`'s entry, `code-grant`'s issuing, `tokens`' admits, the clock, the package's `login-page`, whether `openid` is required, the steps `reauth`, `step-up` and `consent-decision`, and `checks`' target check.
  - A trusted request: client, redirect URI, single values, parameters, the request.
  - A decision: a refusal, a page to go to, or the code and its subject.

## Invariants
- The order: a denial coming back from consent, the request's form, acr_values and `claims`, the scope, taking the re-authentication record, the session's entry and freshness, the step-up, a client consent cannot serve, the issuance policies, consent, the audience asked, the code.
- `tokens`' `admits` is asked as the code's exchange will ask: the subject, the client, the scope, the audience asked (the default while it is refused), the session's amr and authentication time (marked when it is unknown), the met acr, grant type `authorization_code` and the session. A refusal is `access_denied` with the policy's description, recorded with the policy's name and reason.
- Without a session fresh enough, the browser goes to the login page with `redirect_to` back to the endpoint, without the old record's name and carrying a new re-authentication record when `prompt=login`, `max_age` or an essential `auth_time` was asked.
- A request back from its login, its record taken, whose session's authentication time is still unknown while one of those is asked, is refused with `login_required`, not sent to log in again.
- The audience asked is read before the issuance policies, so they judge the code's audience; its refusal (`invalid_target`) goes back with `state` and `iss`, unrecorded and with no code, only after consent and the policies.
- Each step returns its decision as data; only `route` builds answers.
- `code-grant` is asked for a code for the client, redirect URI, PKCE challenge, nonce, session, subject and the met acr.

## Depends on
- `session` (entry); `code-grant` (issuing the code); `tokens` (the issuance policies); `clients` (the client type); `kernel` (the build context, the clock); `checks`, `reauth`, `step-up`, `consent-decision`
