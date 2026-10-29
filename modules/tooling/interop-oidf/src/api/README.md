# api

Internal module of `interop-oidf`: the suite's API, reached trusting its certificate alone.

## Offers
- `certificateAt`: the certificate a TLS server answers with, read without trusting it, within a time.
- `pinnedTo`: a check of a server's identity that takes one certificate alone, by its fingerprint.
- `requestJson`: a GET, POST or DELETE, with a JSON body where given, trusting one certificate alone, answering its status whatever it is and its body; the whole request and its body held to a time and to the deadline given. `getJson`: its GET. `pemOf`, a certificate as PEM.

## Invariants
- The suite answers with the harness's certificate, one naming `localhost.emobix.co.uk` (the name `certificateAt` asks for); its name is still no check: the fingerprint is.
- A handshake that never ends, an answer that never comes or trickles in past its time, and an answer cut off midway are each refused, never waited on.
