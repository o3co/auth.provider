# notices

Internal module of `rp-logout`: back-channel notices that a session closed.

## Responsibilities
- Keeps a notice for each client a closing session holds, and sends each a logout token until it is settled or too old, a failed try not tried again until a `sweep-interval` after it was last due, or made.

## Not here
- Which clients a session holds (written by the package on each redemption). When a session closes (`session`).

## Offers
- `noticesFrom` (the build context) → `closing` (a session → its notices, once all are written), `deliver` (notices → one try each) and `sweep` (one try at every kept notice whose wait is over).

## Invariants
- The logout token is signed by `keys` under `logout+jwt`, so with the algorithm of the client's ID tokens, which `oidc` holds to the one `keys` signs with (OpenID Connect Back-Channel Logout 1.0 §2.6); with `iss`, `sub`, `aud` (the client), `iat`, `exp` the package's `logout-token-lifetime` on, the notice's `jti` (the same on every try, so a client can tell a repeat), the back-channel logout event, and `sid` unless the client said no (OpenID Connect Back-Channel Logout 1.0 §2.4).
- Each host sweeps the kept notices every `sweep-interval`, logging how many it keeps; a notice whose try failed is not tried again until a `sweep-interval` after it was last due, or made, whichever host tried it, a late sweep trying it at once (Back-Channel Logout 1.0 §2.5); a session's close never waits for a client.
- It is posted as a form through `outbound`, which follows no redirect. A 2xx settles it; 408, 429, 5xx or a failure to reach the client keeps it; a destination `outbound` refuses or any other status settles it, logged.
- A client gone or without a back-channel URL settles it.

## Depends on
- `clients`, `issuer`, `keys`, `outbound`, `session` (the session's type); the package's store interfaces, section and `registration`
