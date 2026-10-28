# deployment

Internal module of `conformance`: a fault scene's app as a deployment runs it, on a Redis topology.

## Responsibilities
- Starts a scene's app as several instances from one generated app and one settings object, each behind a relay and a trace of its own, kills and restarts them, moves an instance's clock, and records what the scene ran on.

## Offers
- `startDeployment` (a scene, its name, a topology, a number of instances, the Redis section's other keys, where its record goes, and the start's options: the certificates its instances trust), giving its instances, its record and `stop`.
- An instance: its URL (its trace's), its relay, its audit trail (`audit`), the requests it was sent (`requests`), whether it runs, `kill` (SIGKILL, what it started with it; how and when it ended, on the relay's clock), `restart` (from the same settings and options, its trusted certificates among them, behind the same URL and relay, on the clock it had) and `clock` (started again on a clock moved by an offset such as `+2h`).
- `startTrace`: a plain HTTP proxy in front of one instance, recording each request's method and path, pointed at the instance started again.

## Invariants
- Every instance starts from the same generated app and settings, but for its port and its relay's URL; more than one runs as `kernel.deployment = multi`.
- Each instance talks to the topology's primary through its own relay, so a fault on one leaves the others' connections alone.
- Apps and relays start fresh for each scene; nothing in an app's process or a relay's rules crosses from one scene to the next.
- A scene's record names the Redis image, the replicas, the instances, the deployment, the issuer and keys the instances share, their clocks, the Redis section without its URL, a hash of each instance's settings, the commit it ran on as the evidence names it (`SPEC_EVIDENCE_COMMIT`, else the checkout's HEAD, never the event's), and the run where CI gives one; it goes to `CONFORMANCE_FAULTS_DIR` where set.
- Each instance has one audit sink for the deployment's life: every start of it sends there, so its trail runs on across restarts and moved clocks and is still read once it is killed.
- `stop` stops every instance, its audit sink, trace and relay, killed ones too, and fails where a relay failed or a fault asked for never happened.
- A start that fails at any step (an instance refused, its mark not written, a trace that cannot start, the identities differing, the set-up not written) stops everything it started before failing.
- The instances are one deployment: each names the same issuer and publishes the same keys, told apart by kid and RFC 7638 thumbprint, or the start fails naming the instance that differs. The metadata is read where the configured issuer publishes it (OpenID Connect's place under its path, then RFC 8414's), and the keys where its `jwks_uri` says: none where it names none, and a set it names that cannot be read (an error answer, no `keys` array) fails the start.
- An instance's clock moves only where the thread-safe libfaketime of glibc Linux is at hand (`CONFORMANCE_FAKETIME_LIB`, else the system's); elsewhere `clock` fails rather than run on the real clock. The record names each instance's clock and is written again as one moves.
- An instance a run left behind, its run killed mid-scene, is killed with its process group at the next start, only where its leader is the process marked (by when it started, as `ps` tells it); a group it cannot hold to its mark is left running and named on stderr.
- The app reads its public origin from configuration only, so the trace in front of it changes nothing it answers. An instance's answer cut short ends the client's too.

## Depends on
- `audit` (the sink), `drivers` (the generated app, its start on a sink it is given), `clock` (the moved clock's environment and library), `faults` (the topology), `relay`, `store-wire` (the relay's roles).
