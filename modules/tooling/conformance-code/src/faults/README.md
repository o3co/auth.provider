# faults

Internal module of `conformance-code`: what the area's fault scenes share, its scene deployed on a Redis topology and the store writes a fault is about.

## Responsibilities
- Deploys the code flow on the Redis store, on a topology of its own (2 replicas and 1 instance unless a scene says otherwise), each node needing one replica for a write.
- Runs the code flow against one instance: a code for a browser logged in there, and a request to its token endpoint, a refresh among them.
- Names a code's writes as the relay matches them, by the code's challenge: its use (the record turned consumed), and the token noted on it after; and a refresh token's rotation, by its family and secret.
- Waits for an instance to be ready again, or connected again to a server, and for the primary's replicas to be online again; points every instance's relay at the primary after a promotion or a crash.

## Offers
- `faultScene`, `deployed` (a scene's topology, instances and `stop`), `on` (a scene on a deployment of its own), `instanceOf`, `codeAt`, `tokenAt`, `redeemAt`, `refreshAt`, `said`, `codeUse`, `codeNoted`, `rotationFrom`, `successes`, `ready`, `reconnected`, `replicasOnline`, `failover`, `repointed`, and the scene's `issuer`, `callback`, `prefix` and client `app`.

## Invariants
- Each code has a challenge of its own, so a match on it never takes another code's write.
- A code's use is the write that turns its record consumed before any token is noted on it; a code that comes again voids its record and a noted token records the token, neither of which is its use.
- A refresh token's rotation is the write that moves its family's current secret off the token's, the family still live; a revocation keeps no current secret and is none.
- The relay is pointed at the primary only by switching its upstream and cutting every connection, so no connection stays on a server that is no longer the primary.

## Depends on
- The package's scene builder and browser; `conformance` (the deployment, topology, relay and store-wire); `conformance-oauth` (clients)
