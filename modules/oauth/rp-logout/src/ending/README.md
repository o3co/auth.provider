# ending

Internal module of `rp-logout`: the logout a client starts (OpenID Connect RP-Initiated Logout 1.0).

## Responsibilities
- Ends the session an ID token hint names, and sends the browser on: to the front-channel page, the upstream's end of session, the client's return, or a plain answer.

## Not here
- Judging the hint (`oidc`). Closing the session and its cookie (`session`). Building the page (`page`). Back-channel notices (`notices`, through the session's participant).

## Offers
- `endingFrom` (the build context, the upstream end if one is contributed) → the handler of `GET` and `POST /oauth/logout`.

## Invariants
- The session's clients and the upstream's end of session are read before the close, which forgets the upstream tokens.

## Depends on
- `audit`, `clients`, `http`, `issuer`, `oidc` (hints), `request-source` (the source), `session` (close); the package's contract, store interfaces, `page` and `registration`
