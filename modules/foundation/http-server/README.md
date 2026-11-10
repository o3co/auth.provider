# http-server

## Responsibilities
- Serves the routes `http` declares, as the server `http` takes through `httpServers`: reads each request, applies the policies its route uses, and writes the answer.
- Checks at boot the policies' rules and marks against the declared routes.

## Not here
- The routes, their declarations and the words they are written in; the `http` section, `site`, `listening`, start and stop (`http`).
- What a policy decides and answers (its owner's).

## Offers
- `policies`, `applying`, `PolicyRule`, `marks`, `Mark` and `Guarantee`: the same objects as `http`'s, so a policy's owner may import them from either while they move here.
- Serving as `http`'s card describes it: reading what a request sends, its bodies, cross-origin routes, `loads`, the security headers, the answers to Unavailable, to a path no route reaches and to a method none takes, and each request's end told to `requestEnds`.
- Composition definition: comes by default with `http`.

## Invariants
- Serves requests (`network`: `serves-http`), on the host and port, behind the proxies, with the origins and the limits `http`'s section gives.
- Boot is refused, naming the route and the policy, when a route uses a policy no module applies, a policy has two rules, or a route breaks what it declares; policies match by value, and a label only names one in a report.
- Stop refuses new connections and closes idle ones; requests in flight finish (`Connection: close`) until its deadline cuts them.

## Depends on
- `kernel`, `http`, `request-source`, `client-certificate`.
