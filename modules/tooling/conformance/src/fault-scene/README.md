# fault-scene

Internal module of `conformance`: what an area's fault scene does with its deployment, apart from the faults it causes, in no area's words.

## Responsibilities
- Deploys a scene on a topology of its own, 2 replicas and 1 instance unless the scene says otherwise, every node needing one replica for a write, and stops both however the scene ends.
- Waits for an instance to be ready again, or connected again to a server, and for the primary's replicas to be online again; points every relay at the primary after a promotion or a crash, and promotes a replica that has caught up.

## Offers
- `deployed` and `on` (a scene on a deployment of its own), `instanceOf`, `successes` (a match's successful executions on an instance's relay), `reconnected`, `ready`, `replicasOnline`, `repointed`, `failover`; the types `Deployed` and `Deploying`.

## Invariants
- A relay is pointed at the primary only by switching its upstream and cutting every connection, so no connection stays on a server that is no longer the primary.
- Every wait has its bound (10 s for a connection, 30 s for readiness or the replicas) and fails past it.
- Holds no feature vocabulary: the scene, its matches and its requests are the area's.

## Depends on
- `deployment`, `faults` (the topology), `relay` (a match, an upstream), `promotion` through the topology.
