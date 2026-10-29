# rp

Internal module of `interop-oidf`: the provider as a relying party, logging a browser in through the suite's OP.

## Offers
- `rpScene`: a federation login through one OpenID Connect IdP (`oidf`), the suite's OP, reached through a CONNECT proxy, reading its UserInfo where asked (most of the suite's tests end once it is read) and asking `profile` and `email` besides `openid`, taking its callbacks without `iss` (`accept-missing-iss`: the suite's OP, at the pinned release-v5.3.3, neither offers nor sends it); the suite's one subject linked to one local user; a first-party probe client.
- `browser`: a harness's browser that trusts each origin's own certificate alone, follows the redirects it is told to among them, and keeps each host's cookies.
- `signIn`: a federation login started at the app and taken through the suite's OP, stopped at the app's answer to its callback; whether it sent the browser on to the return target.
- `loggedInAs`: the local subject a browser is logged in as, by the probe client's silent authorization request and its code's id_token, none where it is not.

## Invariants
- The browser goes only to origins whose certificate it was given, follows at most ten redirects, and holds each visit to a time and to the signal given.
- A redirect to the return target is never followed: the app's answer to its callback is what a sign-in judges.
- A probe reads as logged out only on an explicit `login_required`: one not sent back to the probe client's redirect URI, refused otherwise, or whose exchanged code's id_token names no subject (none, empty, not text) fails.
