# suite

Internal module of `interop-oidf`: the suite at its pinned version, started and stopped.

## Offers
- `startSuite`: the suite's source at the pinned tag, its store in memory (never a directory of this machine: a run's store is thrown away, and Docker Desktop's shared directories can refuse its writes), a Python of its own for the scripts, its containers under a Compose project of their own, named from the start's whole directory, in a directory of its own; its certificate, read from its nginx and trusted from then on; its API.
- `hostForSuite`: the name the suite's containers reach this machine by (`host.docker.internal`) and the address to listen on for it; on Linux the name is given the bridge's gateway, in IPv4 alone (`host-gateway` adds an IPv6 address the suite's Java may pick and find no route to).

## Invariants
- The tag must name the pinned commit, or the start fails.
- The suite's public origins are the harness's own (`BASE_URL`, `BASE_MTLS_URL`), never the runner's environment's: vitest sets `BASE_URL` to `/`.
- The suite must answer within 360 seconds, as long as its own runner waits; a connection that never finishes its TLS handshake, or an answer cut off midway, is tried again, never waited on.
- Its API is reached trusting the certificate first read from its nginx alone, by its fingerprint: that certificate names `localhost`, not the host the suite is reached by.
- Stopping keeps every container's state and log first, then takes the containers and their volumes down and removes the directory; a failed start stops what it started, its log kept too.
