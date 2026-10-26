# compose

Internal module of `interop-oidf`: how the suite's containers are composed beside the suite's own compose file.

## Offers
- `composeOverride`: the compose file beside the suite's own: the store in memory, the name the server reaches this machine by, each container labelled with its owner.
- `suiteEnv`: the compose file's environment: the pinned image tag and the suite's origins as the harness names them.
- `projectOf`: a start's Compose project, from a hash of its whole directory.

## Invariants
- The store is never a directory of this machine: a run's store is thrown away, and Docker Desktop's shared directories can refuse its writes.
- The server's name for this machine maps to IPv4 alone: `host-gateway` adds an IPv6 address the suite's Java may pick and find no route to.
- The origins never come from the runner's environment: vitest sets `BASE_URL` to `/` for Vite.
