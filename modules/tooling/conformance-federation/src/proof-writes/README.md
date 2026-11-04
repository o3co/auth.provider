# proof-writes

Internal module of `conformance-federation`: the fault scenes of a DPoP proof's count, on Redis.

## Responsibilities
- Checks, on Redis, a proof by another key: refused, with nothing counted or spent.
- Checks the holder's key, each request from a source of its own: counted by the token's subject, `429` over the count with its wait and no challenge, at the upstream logout too, the proof unspent and taken once the wait is over; `503` with nothing spent where the count cannot be made.

## Depends on
- `faults`; the package's scene builder, browser and fake upstream; `conformance` (the fault scene's deployment and the relay's matches); `conformance-oauth` (clients)
