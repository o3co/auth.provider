# store-rows

Internal module of `conformance-code`: the fault scenes of a store that cannot write, by a code redeemed, and of a Redis set to evict keys (`guarantee-3-j`, `guarantee-3-k`).

## Responsibilities
- Checks, each scene after a control with no fault (a code used up and a token given), that no token is given and the code is not used while the store cannot write, and that the code is redeemed once after:
  - Redis is out of its bounded memory, a write refused as OOM (`M`);
  - replication is replicas and the primary has no replica, the confirmation finding none or the write refused for want of one, until a replica follows again (`R0`);
  - one of two replicas is stopped, a confirmation by both timing out, the redemption stopping at its first write, unconfirmed (`Wt`);
  - both replicas are stopped past the lag allowed, writes refused as `NOREPLICAS` (`Nr`).
- Checks that a deployment boots where Redis does not evict keys, and that one is refused at boot, naming `maxmemory-policy`, once Redis is set to evict them (`Ev`).

## Depends on
- `faults`; `conformance` (the topology's nodes, the deployment, the relay's matches)
