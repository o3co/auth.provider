# security-headers

Internal module of `http`: the security headers every answer carries, and a page's policy.

## Responsibilities
- Sets the security headers of every answer in one place.

## Not here
- What a page loads (the route's `loads`).

## Offers
- `secured`: an answer's headers → the same with the security headers, the policy in place of the route's.

## Invariants
- A Content-Security-Policy whose default source is none: scripts from this origin, styles and fonts from it or over https (styles inline too, fonts and images as data URLs), images from it, forms posted to it; no object, no inline script attribute, and no one framing the answer.
- HSTS, `nosniff`, `X-Frame-Options`, `Referrer-Policy: no-referrer` and the cross-origin ones.
- A route's own values of them, its policy included, are replaced.
- Only `loads` widens a page's policy.
- A page's policy allows the frames and scripts it declares and nothing else.
- A frame a policy cannot name makes the answer `500`.

## Depends on
- `http` (its contract).
