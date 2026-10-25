# conformance-front

## Responsibilities
- Puts an https front before a running app, as a deployment's proxy is, for a harness whose outside party (a conformance suite, a client library) reaches the app over https.

## Not here
- What a harness answers or changes itself (a login page, a request rewritten): its own, through the hooks.
- Starting the app (`conformance`'s drivers), and judging a client's certificate (the app's).

## Offers
- `startFront`: an https server at `listen`, on a port it takes, whose origin is `https://<publicHost>:<port>`; the app is reached at `upstream()`, read for each request, so the front starts before the app and its origin can be the app's public origin.
- Hooks: `handle` answers a request at the front, `rewrite` gives the URL and body it goes on with, `answered` is told each answer of the app's with its request.
- `clientCertificate.header`: each client is asked for a certificate, and the one presented goes on URL-encoded as PEM in that header.
- `selfSigned`: a P-256 key and a self-signed certificate naming a host and loopback, made by `openssl`; the curve is named, never written as explicit parameters, which Java's TLS refuses.

## Invariants
- The app is told the scheme (`X-Forwarded-Proto: https`) and the sender's address (`X-Forwarded-For`) alone: those a client wrote, `Forwarded` and `X-Forwarded-Host` are dropped, and so is a client's own certificate header.
- A body goes on with its length as rewritten. A connection's own headers (`Connection`, `Keep-Alive`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`, the proxy ones) and those a `Connection` header names, in any case, are never passed, to the app or back.
- An answer the app cuts off midway ends the client's answer too.
- A certificate is carried, never judged.
- While the app cannot be reached, the answer is `502`.

## Depends on
- `openssl` on the path, for `selfSigned`. No workspace package.
