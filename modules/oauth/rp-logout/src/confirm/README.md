# confirm

Internal module of `rp-logout`: the confirmation of a logout `ending` could not close without asking (OpenID Connect RP-Initiated Logout 1.0 §2), and the request `ending` carries in the browser's URL.

## Responsibilities
- Asks the person, on a page of the provider's own, whether to log out of the provider, bound to the session the browser holds; closes that session once they agree, and moves on to the client's return.
- Signs and checks a carried request: a logout `ending` checked, which closes nothing by itself.

## Not here
- Which requests come here, and checking the hint and the return a carried request holds (`ending`). The close itself and what it records (`closing`). The CSRF check (`csrf`'s policy, declared on the route) and its token (`csrf`). Resolving the browser's session (`session`'s `handleOf`). Signing (`keys`).

## Offers
- `confirmPath` (`/oauth/logout/confirm`), `carriedParam` (`request`), `CarriedRequest` (the hint's session, its client, the return and `state`).
- `confirmWith` (the browser's session handle, the shared close, keys, form tokens, the issuer's, this endpoint's and the logout's URLs) and `confirmFrom` (the composition, the logout's path) → `carry` (a carried request → its token), `carried` (a token → the carried request / none), `show` (the `GET`) and `take` (the `POST`).

## Invariants
- A carried request is signed by `keys` as `logout-request+jwt`, with `iss` the issuer, `aud` the logout endpoint, `exp` 300 seconds on, `sid`, and the client, return and `state` where there are; `carried` holds each claim itself. `show` reads it from `request`; one that does not hold is no return.
- `show` asks only where the browser holds a session; one without says the person is not signed in, moving on to the carried return by the page's script. The asking page has no script, posts its one form to this origin alone (`form-action 'self'`), and carries the form's CSRF token and a confirmation bound to the session.
- The confirmation is signed by `keys` as `logout-confirm+jwt`, with `iss` the issuer, `aud` the confirmation endpoint, `sid` the session's handle, `exp` 300 seconds on, and the carried return and `state`; `take` holds each claim itself, as `keys` checks the signature, the type and the key alone.
- `take` closes only where the confirmation holds and its `sid` is the session the browser holds now, never the session a carried request names; otherwise it closes nothing and asks again, for that session. The return is read from the confirmation alone, never from the query again.
- After a close, the answer is always a page: the front-channel page, or one saying the person is logged out, moving on by its script to the upstream's end of session, or else the carried return with its `state`, since the form's policy holds a redirect after the post. A field sent twice is `400`; a close left pending, or one that cannot be made, is `503`.

## Depends on
- `csrf` (the form's token), `http`, `keys`, `session` (`handleOf`); `closing` and `page`
