# http

## Responsibilities
- Owns the HTTP entry point: the routes that modules contribute, the words they are written in, and the section the one server serves by.
- Hands the routes to the one server contributed (`httpServers`) at start, and drains it at stop.

## Not here
- Reading requests, applying policies and writing answers (the server's: `http-server`).
- What a route means and its error vocabulary (the contributing module's); what a policy decides and answers (its owner's).
- Any name taken from request headers: the public origin comes only from configuration.

## Offers
- `routes`: a method, a path and a handler, with the policies used (and their options), the bodies taken and cross-origin use when declared; how paths match, HEAD, and `unavailable`/`noted` are in `Route`'s doc comment.
- Policies: `policy` makes one, unique as a value; `use` is a route's use of one with its options, copied and frozen at boot.
- A route says whether it changes state (`changesState`), and, changing it, why it takes other sites' requests (`crossSite`) or any number from one source (`unlimited`).
- The request type, with its source; `Values`, made by `valuesOf` (a map), `fieldsOf` (a JSON object's members: its strings the fields, the others `mistyped`) or `readOnly` (a map whose writes throw): values with the same name keep the order sent, `single` gives a name's only value, `repeated` the names with more; whether one must be single is the route's.
- `loads`: what a page declares it loads (the origins it frames, its inline scripts, and whether its forms post to this origin).
- `listening` (the port) and `site` (the public origin; cookies can be made secure unless it is http, which boots only with `insecure-origin`; `proxied`, whether `trusted-proxies` names a proxy, without which no request's scheme is https); `client-certificate`'s `certificateForwarding` is provided from this section.
- The section's other keys, each described in the settings list: `host`, `port`, `public-origin`, `cors-origins`, `headers-timeout`, `request-timeout`, `max-connections`, `proxy-hops`.
- `requestEnds`: each request's end, once, answered or closed: the method sent, the declared path of the route reached (none when none), the status written or `closed` when the client closed first, and the milliseconds taken (never negative); its observers are told after the request, asynchronously, and what they throw or reject is dropped.
- `httpServers`: the one server, given the declared routes, the settings, the observers, the log and the clock at start, and drained at stop.
- `jsonAnswer`: status, a JSON value, and any cookies and headers → an answer kept out of caches (`noStore`), but where the headers given replace its `cache-control` or `pragma`.
- `./testing`: test configuration and request builders with working defaults, read-only as a server gives a request.

## Invariants
- Boot is refused when two routes take one method and path, or when no server, or two, is contributed; with none, the refusal says to compose `http-server`.
- Every start under `insecure-origin` is warned of, as `kernel` warns each value a production deployment refuses: the session's cookie goes in the clear.

## Depends on
- `kernel`, `request-source`, `client-certificate`, `url-setting`.
