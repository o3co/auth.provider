# ending

Internal module of `rp-logout`: the logout a client starts (OpenID Connect RP-Initiated Logout 1.0).

## Responsibilities
- Ends the session an ID token hint names, and sends the browser on: to the front-channel page, the upstream's end of session, the client's return, or a plain answer.

## Not here
- Judging the hint (`oidc`). Closing the session and its cookie (`session`). Building the page (`page`). Back-channel notices (`notices`, through `session-participants`' participant).

## Offers
- `endingFrom` (the build context, the upstream end if one is contributed) → the handler of `GET` and `POST /oauth/logout`.

## Invariants
- Reads `id_token_hint`, `post_logout_redirect_uri` and `state`, from the query on a `GET` and the form on a `POST` (no other body is taken); nothing else.
- No hint, or one naming no session, is `400 invalid_request`; one `oidc` refuses, or one issued more than 24 hours ago, is `400 invalid_token`; a hint that cannot be judged, or any other check that cannot tell, is `503`, logged as `rp-logout.unavailable` (warn) with what failed.
- `sid` is taken from outside only in a hint the provider signed, and only to close that session.
- The return is used only when it exactly matches one the hint's client registered; otherwise, or where the hint names no one client, the request is `400 invalid_request` and nothing is closed. `state` goes with it. A client record that cannot be read leaves out its frame, logged as `rp-logout.client_unavailable`; one a return is judged by answers `503`, nothing closed.
- The session's clients and the upstream's end of session are read before the close, which forgets the upstream tokens.
- Nothing reads the session itself before its close: a read can end one past its lifetime without its participants. Whether it is the logout comes from what the close found.

## Depends on
- `audit`, `clients`, `http`, `issuer`, `oidc` (hints), `request-source` (the source), `session` (close); the package's contract, store interfaces, `page` and `registration`
