# serving

Internal module of `http`: the server that answers each request with the route it reaches.

## Responsibilities
- Reads a request's head, finds the route its path reaches, has the route's policies and handler answer, and writes the answer.

## Not here
- What a request's body holds (`bodies`), how policies apply (`guards`), cross-origin answers (`cors`), the security headers (`security-headers`), and telling a request's end (`ending`).
- Checking the segments under a `/*` path: a `/*` handler checks them by its own rules.

## Offers
- `serve`: the routes, guarded by their policies, answered on a Node HTTP server.
- `drain`: stops the server, cutting what is left once the stop's deadline passes.

## Invariants
- Paths: an exact path comes first, then the longest `/*` above it.
- A handler reads the URL parser's path (dot segments resolved, percent-encoding kept as sent).
- A GET route also answers HEAD, with the same headers and no body.
- A path no route reaches gets `404`, and a path whose routes take other methods gets `405` naming them in `Allow`.
- A preflight to a cross-origin route is answered before the policies.
- A body the route does not take is refused only after the route's policies have seen the request.
- The request a policy or handler gets is frozen, and its maps cannot be written to.
- A policy's or handler's failure is logged by its kind only, never its message.
- Any other failure is answered `500` and logged as a warning, `http.unexpected_failure`, by the route reached (when known) and its kind only, never its message.
- A request target that is not a URL, or whose query is not well-formed UTF-8, gets `400` before any route.
- An answer whose headers cannot be written gets `500`, with none of its own headers.
- An answer's length is stated in bytes, so a HEAD answer carries the length its GET would.
- A request's headers must arrive within `headers-timeout` and the whole request within `request-timeout`, else it is answered `408` and its connection closed; a connection past `max-connections` is closed as it arrives.
- Stop refuses new connections and closes idle ones.
- A connection is closed only after what it still has to send, so stop never cuts an answer already written; one sent as keep-alive before stop is closed once it is sent.
- Requests in flight finish (`Connection: close`) until stop's deadline cuts them.

## Depends on
- `http` (its contract), `kernel`, `request-source`, `client-certificate`; `bodies`, `guards`, `cors`, `security-headers`, `ending`.
