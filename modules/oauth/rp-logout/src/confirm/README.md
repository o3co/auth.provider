# confirm

Internal module of `rp-logout`: the confirmation of a logout a client started without a hint (OpenID Connect RP-Initiated Logout 1.0 §2).

## Responsibilities
- Asks the person, on a page of the provider's own, whether to log out of the provider, bound to the session the browser holds; closes that session once they agree.

## Not here
- Which requests come here (`ending`). The close itself and what it records (`closing`). The CSRF check (`csrf`'s policy, declared on the route) and its token (`csrf`). Resolving the browser's session (`session`'s `handleOf`). Signing (`keys`).

## Offers
- `confirmPath` (`/oauth/logout/confirm`), and `confirmWith` (the browser's session handle, the shared close, keys, form tokens, issuer and endpoint URLs) and `confirmFrom` (the composition) → `show` (the `GET`) and `take` (the `POST`).

## Invariants
- `show` asks only where the browser holds a session; one without says the person is not signed in. The page has no script, posts its one form to this origin alone (`form-action 'self'`), and carries the form's CSRF token and a confirmation bound to the session.
- The confirmation is signed by `keys` as `logout-confirm+jwt`, with `iss` the issuer, `aud` the confirmation endpoint, `sid` the session's handle, and `exp` 300 seconds on; `take` holds each claim itself, as `keys` checks the signature, the type and the key alone.
- `take` closes only where the confirmation holds and its `sid` is the session the browser holds now; otherwise it closes nothing and asks again, for that session.
- After a close, the answer is always a page: the front-channel page, or one saying the person is logged out, moving on to the upstream's end of session by its script where there is one, since the form's policy holds a redirect after the post. A field sent twice is `400`; a close left pending, or one that cannot be made, is `503`.

## Depends on
- `csrf` (the form's token), `http`, `keys`, `session` (`handleOf`); `closing` and `page`
