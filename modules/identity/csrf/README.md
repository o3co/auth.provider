# csrf

## Responsibilities
- Checks that a state-changing request came from this deployment's origin (the CSRF check).
- Hands out the double-submit token and its cookie.

## Not here
- Session records (`session`).
- Whether cookies can be made secure (`http` answers).

## Offers
- The CSRF policy for routes (`http`'s policies). A `GET` passes. Any other method passes only on the evidence below.
  - A refused request is answered `403` with `{"error":"csrf"}`, not cacheable.
  - Its mark at `http`'s `marks`: `own-site`, for every method but `GET`. The stand-in contributes it too.
- Origin evidence (`sameOrigin(request)`), for routes that take no token. It is true only when `Origin` is the public origin or `Sec-Fetch-Site` is `same-origin`.
  - A request with neither is false.
- Route `GET /session/csrf`: the token and its cookie, not cacheable. A valid token the request already holds is reused.
- `formTokens`: the same token for a form the server draws itself, with the field it is posted in (`csrf_token`) and its cookie; a valid token the request holds is reused. The stand-in hands them out too.
- Test stand-in (`./testing`): the policy and the origin evidence, decided by the module's own code. It serves no route.
  - Without a public origin it boots and refuses every unsafe request.

## Invariants
- The policy needs same-origin evidence (Origin and Referer) or the double-submit token.
- The token is 43 base64url characters. It comes in the cookie and the header, or else in the request's `csrf_token` field (as `http` reads fields), sent once.
- In the policy, an `Origin` or a `Referer` naming another origin means refusal, even with the token; the policy reads no `Sec-Fetch-Site`.
- Origin evidence also counts any `Sec-Fetch-Site` other than `same-origin` as cross-origin.
- `Origin: null` and an unreadable Referer count as no evidence, so the policy falls through to the token.
- The origin compared against is `http`'s public origin. Without one, boot is refused.
- Cookies go through `cookies`.
- In a deployment that can make cookies secure (`http` answers), requests that are not HTTPS are refused.
- Double submit relies on other subdomains being unable to set the cookie, in a deployment that can make cookies secure.
- The route URL `/session/csrf` is an external contract. Outside users get the token there, so it keeps "session" in its name.

## Depends on
- `kernel`, `http`, `cookies`
