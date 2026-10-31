# confirm

Internal module of `rp-logout`: the confirmation of a logout `ending` could not close without asking (OpenID Connect RP-Initiated Logout 1.0 §2), and the request `ending` carries in the browser's URL.

## Responsibilities
- Asks the person, on a page of the provider's own, whether to log out of the provider, bound to the session the browser holds; closes that session once they agree, and moves on to the client's return.
- Takes a carried request (`carried`): a logout `ending` checked, which closes nothing by itself, and hands `ending` its `carry`, `carried` and `current`.

## Not here
- Which requests come here, and checking the hint and the return a carried request holds (`ending`). The close itself and what it records (`closing`). The CSRF check (`csrf`'s policy, declared on the route) and its token (`csrf`). Resolving the browser's session (`session`'s `handleOf`). Signing (`keys`).

## Offers
- `confirmPath` (`/oauth/logout/confirm`); `carriedParam` and `CarriedRequest`, as `carried` gives them; `unavailable`, the `503 temporarily_unavailable` the package's routes declare for Unavailable.
- `confirmWith` (the browser's session handle, the shared close, keys, form tokens, the issuer's, this endpoint's and the logout's URLs) and `confirmFrom` (the composition, the logout's path) → `carry`, `carried` and `current` (`carried`'s), `show` (the `GET`) and `take` (the `POST`).

## Invariants
- `show` reads a carried request from `request`; one that does not hold, as `carried` checks it, is no return.
- `show` asks only where the browser holds a session; one without says the person is not signed in, moving on to the carried return by the page's script. The asking page has no script, posts its one form to this origin alone (`form-action 'self'`), and carries the form's CSRF token and a confirmation bound to the session.
- The confirmation is signed by `keys` as `logout-confirm+jwt`, with `iss` the issuer, `aud` the confirmation endpoint, `sid` the session's handle, `exp` the package's `confirm-within` on, or the carried request's own where it carries a return (never later), and the carried client, return and `state`; `take` holds each claim itself, as `keys` checks the signature, the type and the key alone.
- `take` closes only where the confirmation holds and its `sid` is the session the browser holds now, never the session a carried request names; otherwise it closes nothing and asks again, for that session. The return is read from the confirmation alone, never from the query again.
- A carried return is held to its client's registration as it is now (`carried`'s `current`) before every move on to it, on the page without a session and after the close, and before the close hands it to the upstream's end of session: a client gone, or one no longer registering it, leaves no return, the page stopping where it is.
- After a close, the answer is always a page: the front-channel page, or one saying the person is logged out, moving on by its script to the upstream's end of session, or else the carried return with its `state`, since the form's policy holds a redirect after the post. A field sent twice is `400`; a close left pending, or one that cannot be made, is `503`. A check that cannot tell throws Unavailable on, answered by the routes' declared `unavailable` after `http`'s warning `http.unavailable`.

## Depends on
- `clients` (the client's record now), `csrf` (the form's token), `http`, `keys`, `session` (`handleOf`); `carried`, `closing` and `page`
