# cors

Internal module of `http`: the answers to cross-origin requests, for the routes that declare them.

## Responsibilities
- Lets the origins the operator lists read the routes that take cross-origin requests.

## Not here
- Which routes take cross-origin requests (the route's declaration), and which origins are listed (the operator's).

## Offers
- `crossOrigin`: a declared route's answer, made readable by a listed origin.
- `preflight`: the answer to a preflight on a path with a declared route.

## Invariants
- Answers vary by `Origin`, a route's own `Vary` kept.
- An answer names the request's origin only when it is listed.
- An answer never names `*`.
- An answer never allows credentials.
- A preflight from a listed origin, for a method a declared route takes, names the methods of the path's declared routes, the request headers the route takes, and a max age of 600 seconds.
- Any other preflight on such a path gets `204` with nothing to read by.

## Depends on
- `http` (its contract).
