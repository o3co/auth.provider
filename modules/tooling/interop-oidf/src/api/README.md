# api

Internal module of `interop-oidf`: the suite's API, reached trusting its certificate alone.

## Offers
- `certificateAt`: the certificate a TLS server answers with, read without trusting it, within a time.
- `pinnedTo`: a check of a server's identity that takes one certificate alone, by its fingerprint.
- `getJson`: a JSON GET trusting one certificate alone, within a time; `pemOf`, a certificate as PEM.

## Invariants
- The suite's certificate names `localhost`, not the host it is reached by, so its name is no check: the fingerprint is.
- A handshake that never ends, an answer that never comes, and an answer cut off midway are each refused, never waited on.
