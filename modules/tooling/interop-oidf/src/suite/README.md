# suite

Internal module of `interop-oidf`: the suite at its pinned version, started and stopped.

## Offers
- `startSuite`: the suite's source at the pinned tag, its store in memory (never a directory of this machine: a run's store is thrown away, and Docker Desktop's shared directories can refuse its writes), a Python of its own for the scripts, its containers under a Compose project of their own, named from the start's whole directory, in a directory of its own; its nginx answering with the harness's certificate (one naming the suite's host), trusted alone by its fingerprint; its API.
- `suiteOrigin`: the suite's public origin, `https://localhost.emobix.co.uk:8443`.
- `hostForSuite`: the name the suite's containers reach this machine by (`host.docker.internal`) and the address to listen on for it; on Linux the name is given the bridge's gateway, in IPv4 alone (`host-gateway` adds an IPv6 address the suite's Java may pick and find no route to).

## Invariants
- The tag must name the pinned commit, or the start fails.
- The suite's public origins are the harness's own (`BASE_URL`, `BASE_MTLS_URL`), never the runner's environment's: vitest sets `BASE_URL` to `/`.
- The suite must answer within 360 seconds, as long as its own runner waits; an answer cut off midway is tried again, never waited on.
- Each request to its API, while it starts and after, is held to the plan's deadline besides its own time. `api` is a GET that takes only a 200; `call` sends any method the API takes and answers the status as it comes, for the caller to judge.
- Its nginx answers with the harness's certificate, mounted read only: the image's own names `localhost` alone, so no client that checks names could reach the suite by its host. The harness trusts that certificate alone, by its fingerprint.
- Stopping keeps every container's state and log first, the commands' stderr beside their stdout, then takes the containers and their volumes down and removes the directory.
- A failed start stops what it started, its log kept too; one that fails before Compose was asked for a container removes what it prepared alone.
- A stop that fails, a failed start's own too, is told as `SuiteStopFailed`, every step that failed in it; where the containers were not taken down, the directory stays, holding what stops them.
