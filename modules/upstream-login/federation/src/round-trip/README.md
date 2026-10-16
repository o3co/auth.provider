# round-trip

Internal module of `federation`: one round trip through an upstream IdP, a login's or a link's, from its start to its callback.

## Responsibilities
- Answers a start: checks what the browser asked, asks the continuation (the link when `link` is `1` or `true`, else the login), makes the transaction, and sends the browser to the upstream.
- Answers a callback: takes the transaction once, has the upstream exchange its code, and hands the upstream login to the continuation the transaction names (the link when it records a session, else the login), so neither ends in the other; the login (`login.ts`) hands it to `login-gates`.
- Decides whether an upstream login is fresh enough, finds the local user, and maps the amr and the profile.
- Freshness is judged here on `kernel`'s clock, never by a type.
- Records each callback that took its transaction to `audit`.

## Not here
- Opening the IdPs at boot (`idps`). Handing over the upstream tokens (`handoff`). The route's declaration and its rate limit (the package's). What differs per IdP (the type).

## Offers
- `roundTripIn` (the build context, the login and link continuations) → the round trip's handler; `landingIn`: the landing, or the public origin's root; `federationIdps`: the opened IdPs' contract.
- `federated` (the opened IdPs, the transaction store, `cookies`' contract, `login-gates`' return check, the login continuation, `kernel`'s runtime, the landing, the transaction lifetime) → a request under the federation path → its answer.
- `recorderOf` (`audit`, kind prefix): records a federation event in federation's words: `idp`, then `source`, `userAgent` and `reason` when known.
- `Continuation`: at the start, a refusal or what the transaction carries; after the take, exchange and freshness, the answer; a refusal in between, recorded its way. `loginWith` (`login-gates`' logins, `users`, `audit`, `handoff`, the landing) is the first; `loginIn` builds it from the build context.
- `Completing`, `Carried`, `Recorded`, `Flow`, `answer`, `sent` and `secondOf`: what the continuations take, carry, record and answer with, and the whole second a time falls in.
- `Idp`: what an opened IdP gives the round trip. `base` and `callbackPath` (IdP name → its callback's path). `proves`: what every federation login proves.

## Invariants
- Any other path is `not_found`. The start is GET only; the callback takes only its IdP's answer method; any other method is 405 with `allow`. A repeated parameter is refused next.
- The start refuses a return target `login-gates` does not allow, and a `max_age` that is not 1 to 9 digits. Only `prompt=login` is passed on.
- The cookie, state, nonce and PKCE verifier are 256 random bits each. The challenge is the verifier's S256.
- The transaction is saved under the cookie for `transaction-seconds`; finding one there already is unavailable.
- The cookie is named per IdP. It is cross-site only for an IdP that answers in a posted form.
- A callback takes the transaction in one rewrite, only at the same IdP and with its state (compared in constant time). Without the cookie or state, or with no transaction to take, it is `invalid_state` and spends nothing.
- From the take on, every answer clears the cookie, unavailable included.
- An `error` or no code is `upstream_refused`, with no exchange. The exchange gets the verifier, nonce, redirect URI and the callback's `iss`.
- A failed exchange is `exchange_failed`, logged with the IdP and its kind (`refused` or `failed`) only. An unavailable upstream is 503.
- With `prompt=login` or `max_age`, the upstream must say when the user logged in. That time, plus the type's clock allowance, is not before the start's whole second and is within the max age of now.
- The local user is found by the IdP's name and the upstream subject only. The amr is `fed` plus the mapped upstream values, once each.
- The session gets the upstream profile's email (verified only where the type says so), name and picture under `login-attributes`' source name for the IdP, nothing else of it.
- Audit records come only after the take, with `idp` and the source when `request-source` determined it: the local subject on success or hold, the reason on failure. None records an unavailable answer.
- Success is a 302 to the transaction's return target or the landing. A held login is a 403 with the gate's answer and cookies.

## Data
- Transaction record, by its cookie: format 1, the IdP, the state, nonce and PKCE verifier, the return target, `prompt` and max age, the start time on `kernel`'s clock, and whether it was taken. For a link, the session entered at its start and its subject. Checked on every read: another format or shape is none.

## Depends on
- `http` (the site for the landing, the request and answer, no-store); `cookies`; `request-source` (the source); `kernel` (the runtime, unavailable); `login-attributes` (the source name); `login-gates` (logins); `users` (the lookup); `audit`; `handoff`; `upstreams` (the upstream, its login, its refusal); `federation`'s section and store interface
