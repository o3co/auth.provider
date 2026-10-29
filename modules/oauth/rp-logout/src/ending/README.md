# ending

Internal module of `rp-logout`: the logout a client starts (OpenID Connect RP-Initiated Logout 1.0).

## Responsibilities
- Ends the session an ID token hint names where the browser holds it, and sends the browser on: to the front-channel page, the upstream's end of session, the client's return, or a plain answer.

## Not here
- Judging the hint (`oidc`). The close itself, what it reads first and what it records (`closing`), and closing the session and its cookie (`session`). Building the page (`page`). Back-channel notices (`notices`, through `session-participants`' participant).

## Offers
- `endingFrom` (the build context, the upstream end if one is contributed, `confirm`'s carried request, the route's path) → the handler of `GET` and `POST /oauth/logout`.

## Invariants
- Reads `id_token_hint`, `client_id`, `post_logout_redirect_uri` and `state`, from the query on a `GET` and the form on a `POST` (no other body is taken), and a carried request (`request`) on a `GET`; nothing else.
- A parameter sent more than once, whichever it is, is `400 invalid_request` (`repeated parameter`) before any is read, nothing closed: a value sent twice would read as none and pass the checks above.
- A `client_id` beside the hint that is not the client the hint was issued to, or beside a hint naming no one client, is `400 invalid_request`, nothing closed (RP-Initiated Logout 1.0 §2).
- No hint is `303` to the person's confirmation (`confirm`), whatever return or client it names, none of them read and nothing closed, so it never returns; a hint naming no session is `400 invalid_request`; one `oidc` refuses, or one issued more than 24 hours ago, is `400 invalid_token`; a hint that cannot be judged, or any other check that cannot tell, is `503`, logged as `rp-logout.unavailable` (warn) with what failed.
- `sid` is taken from outside only in a hint the provider signed, or a request `confirm` signed carrying one, and only to close that session, where the request's cookie opens it (`session`'s handle). Another session's cookie, or none, is `303` to the person's confirmation carrying the checked request, nothing closed (RP-Initiated Logout 1.0 §2).
- A hinted `POST`, its checks passed, is `303` to this route's `GET` carrying the checked request, never the hint, nothing closed: a `POST` from the client's site carries no SameSite=Lax cookie, and the `GET` it leads to does.
- A carried request closes only the session the browser holds, and goes back only to a return its client still registers when it comes back (`carried`'s `current`, through `confirm`).
- A carried request sent beside `id_token_hint`, `client_id`, `post_logout_redirect_uri` or `state` is `400 invalid_request`, as is one that does not hold as `confirm` checks it; nothing closed. A carried request's failed close is recorded without the subject, as the confirmation's is: the token carries none, so none is put in the URL.
- The return is used only when it exactly matches one the hint's client registered; otherwise, or where the hint names no one client, the request is `400 invalid_request` and nothing is closed. `state` goes with it. A client record that cannot be read leaves out its frame, logged as `rp-logout.client_unavailable`; one a return is judged by answers `503`, nothing closed.

## Depends on
- `audit`, `clients`, `http`, `issuer`, `oidc` (hints), `request-source` (the source), `session` (close, the cookie's handle); the package's contract, store interfaces, `closing`, `page` and `registration`
