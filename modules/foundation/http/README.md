# http

## Responsibilities
- Owns the HTTP entry point: it connects the routes that modules contribute and applies the policies each route declares.
- Reads what a request sends (query, form, JSON, headers) once at the boundary into read-only maps; a query or form whose percent-escapes decode to invalid UTF-8 is refused with `400`.
- Answers unavailable with `503`: retryable, with no body, kept out of caches (`noStore`: `no-store`, `Pragma: no-cache`).

## Not here
- What a route means and its error vocabulary (the contributing module's); what a policy decides and answers (its owner's).
- Any name taken from request headers: the public origin comes only from configuration.

## Offers
- `routes`: a method, a path and a handler, with the policies used (and their options), the bodies taken and cross-origin use when declared; a GET route also answers HEAD, with the same headers and no body.
- Paths: an exact path comes first, then the longest `/*` above it; a handler reads the URL parser's path (dot segments resolved, percent-encoding kept as sent), and a `/*` handler checks the segments under it by its own rules.
- Bodies: a route may take a form, JSON, none, or several, and any other body is `415`, refused only after the route's policies have seen the request.
- A form and a JSON body share one size limit of 64 KiB: a larger form is read as empty, and a larger JSON body is `413`.
- A JSON body is one object in well-formed UTF-8, frozen, naming no member twice in one object; anything else is `400`.
- Values with the same name keep the order sent: `single` gives a name's only value, `repeated` the names with more, and whether one must be single is the route's.
- A request's fields are its body's values by name; a JSON member that is not a string is told apart as `mistyped`, its meaning the route's.
- Cross-origin routes: a preflight is answered before the policies, and answers vary by `Origin`, naming the request's origin only when listed, never `*` and never with credentials.
- A preflight from a listed origin, for a method a declared route takes, names the methods of the path's declared routes, the request headers the route takes, and a max age of 600 seconds.
- Any other preflight on such a path gets `204` with nothing to read by.
- `loads`: what a page declares it loads (the origins it frames, its inline scripts); its answer's policy allows those and nothing else, and a frame a policy cannot name makes the answer `500`.
- Policies: `policy` makes one, unique as a value; `use` is a route's use of one with its options; `policies` takes one rule per policy, which passes the request on or answers it; a route's policies run in its order before its handler, and the first answer ends the request.
- The request type, with its source as `request-source` decides it from the direct peer, the headers and this section's trusted proxies.
- `listening` (the port) and `site` (the public origin; cookies can be made secure unless it is http; `proxied`, whether `trusted-proxies` names a proxy, without which no request's scheme is https nor its source told past a proxy); an answer's `cookies` are sent one `Set-Cookie` each; `client-certificate`'s `certificateForwarding` is provided from this section.
- `requestEnds`: each request's end, once, answered or closed: the method sent, the declared path of the route reached (none when none), the status written or `closed` when the client closed first, and the milliseconds taken (never negative); an observer's throw is dropped.
- Observers are told after the request, asynchronously, and what they throw or reject is dropped.
- `jsonAnswer`: status, a JSON value, and any cookies and headers → an answer kept out of caches (`noStore`).
- `./testing`: test configuration and request builders with working defaults.

## Invariants
- Boot is refused, naming the route and the policy, when two routes take one method and path, a route uses a policy no module applies, or a policy has two rules; policies match by value, and a label only names one in a report.
- Every answer it writes carries the security headers, set in one place: a Content-Security-Policy that loads nothing by default and lets no one frame the answer, HSTS, `nosniff`, `X-Frame-Options`, `Referrer-Policy: no-referrer` and the cross-origin ones; a route's own values of them, its policy included, are replaced; only `loads` widens a page's policy.
- Stop refuses new connections and closes idle ones; requests in flight finish (`Connection: close`) until its deadline cuts them.
- A request target that is not a URL gets `400`, an answer whose headers cannot be written gets `500`, no request stops the process, and error answers never show exception text or internal values.
- A path no route reaches gets `404`, and a path whose routes take other methods gets `405` naming them in `Allow`.

## Depends on
- `kernel`, `request-source`, `client-certificate`.
