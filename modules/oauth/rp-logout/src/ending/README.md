# ending

Internal module of `rp-logout`: the logout a client starts (OpenID Connect RP-Initiated Logout 1.0).

## Responsibilities
- Ends the session an ID token hint names, and sends the browser on: to the front-channel page, the upstream's end of session, the client's return, or a plain answer.

## Not here
- Judging the hint (`oidc`). The close itself, what it reads first and what it records (`closing`), and closing the session and its cookie (`session`). Building the page (`page`). Back-channel notices (`notices`, through `session-participants`' participant).

## Offers
- `endingFrom` (the build context, the upstream end if one is contributed) → the handler of `GET` and `POST /oauth/logout`.

## Invariants
- Reads `id_token_hint`, `client_id`, `post_logout_redirect_uri` and `state`, from the query on a `GET` and the form on a `POST` (no other body is taken); nothing else.
- A parameter sent more than once, whichever it is, is `400 invalid_request` (`repeated parameter`) before any is read, nothing closed: a value sent twice would read as none and pass the checks above.
- A `client_id` beside the hint that is not the client the hint was issued to, or beside a hint naming no one client, is `400 invalid_request`, nothing closed (RP-Initiated Logout 1.0 §2).
- No hint, or one naming no session, is `400 invalid_request`; one `oidc` refuses, or one issued more than 24 hours ago, is `400 invalid_token`; a hint that cannot be judged, or any other check that cannot tell, is `503`, logged as `rp-logout.unavailable` (warn) with what failed.
- `sid` is taken from outside only in a hint the provider signed, and only to close that session.
- The return is used only when it exactly matches one the hint's client registered; otherwise, or where the hint names no one client, the request is `400 invalid_request` and nothing is closed. `state` goes with it. A client record that cannot be read leaves out its frame, logged as `rp-logout.client_unavailable`; one a return is judged by answers `503`, nothing closed.

## Depends on
- `audit`, `clients`, `http`, `issuer`, `oidc` (hints), `request-source` (the source), `session` (close); the package's contract, store interfaces, `closing`, `page` and `registration`
