# http-server

## Responsibilities
- Serves the routes `http` declares, as the server `http` takes through `httpServers`: reads each request, applies the policies its route uses, and writes the answer.
- Reads what a request sends (query, form, JSON, headers) once at the boundary into read-only maps; a query or form whose percent-escapes decode to invalid UTF-8 is refused with `400`.
- Answers Unavailable from a route's policy or handler with the route's declared answer, else `503` `service_unavailable`: retryable, kept out of caches (`noStore`: `no-store`, `Pragma: no-cache`).
- Checks at boot the policies' rules and marks against the declared routes.

## Not here
- The routes, their declarations and the words they are written in; the `http` section, `site`, `listening`, start and stop (`http`).
- What a route means and its error vocabulary (the contributing module's); what a policy decides and answers (its owner's).

## Offers
- Policies' rules: `policies` takes one rule per policy (`applying` makes one, a `PolicyRule`), which passes the request on or answers it; a route's policies run in its order before its handler, the first answer ends the request, and what a route gives them is copied and frozen at boot.
- `marks`: one per guarantee (`Guarantee`: `own-site`, `per-source`), a policy owner's claim (`Mark`) that its policies keep it for the methods named, never a proof; every route's `changesState`, `crossSite` and `unlimited` are checked against them at boot (`guarantees`).
- Bodies: a route may take a form, JSON, none, or several, and any other body is `415`, refused only after the route's policies have seen the request.
- A form and a JSON body share one size limit of 64 KiB: a larger form is read as empty, and a larger JSON body is `413`.
- A JSON body is one object in well-formed UTF-8, frozen, naming no member twice in one object; anything else is `400`.
- A request's fields are its body's values by name, in the order sent; a JSON member that is not a string is told apart as `mistyped`.
- Cross-origin routes: a preflight is answered before the policies, and answers vary by `Origin`, naming the request's origin only when listed, never `*` and never with credentials; a route's own `access-control-*` headers pass as it wrote them.
- A preflight from a listed origin, for a method a declared route takes, names the methods of the path's declared routes, the request headers the route takes, and a max age of 600 seconds.
- Any other preflight on such a path gets `204` with nothing to read by.
- `loads`: what a page declares it loads; its answer's policy allows those and nothing else, and a frame a policy cannot name makes the answer `500`.
- An answer's `cookies` are sent one `Set-Cookie` each; each request's end is told to `requestEnds`' observers, as `http`'s card says.
- A client certificate is read only as a trusted proxy forwards it; one from a peer not trusted is ignored, with a warning once a minute.
- Composition definition: comes by default with `http`.

## Invariants
- Serves requests (`network`: `serves-http`), on the host and port, behind the proxies, with the origins and the limits `http`'s section gives.
- Boot is refused, naming the route and the policy, when a route uses a policy no module applies, a policy has two rules, or a route breaks what it declares; policies match by value, and a label only names one in a report.
- Every answer it writes carries the security headers, set in one place: a Content-Security-Policy whose default source is none, taking scripts, styles, images and fonts from this origin (styles and fonts also over https) and letting no one frame the answer, HSTS, `nosniff`, `X-Frame-Options`, `Referrer-Policy: no-referrer` and the cross-origin ones; a route's own values of them, its policy included, are replaced; only `loads` widens a page's policy.
- Stop refuses new connections and closes idle ones; requests in flight finish (`Connection: close`) until its deadline cuts them.
- A request target not read as an origin-form path gets `400`, an answer whose headers cannot be written gets `500`, no request stops the process, and error answers never show exception text or internal values.
- A path no route reaches gets `404`, and a path whose routes take other methods gets `405` naming them in `Allow`.

## Depends on
- `kernel`, `http`, `request-source`, `client-certificate`.
