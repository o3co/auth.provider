# descriptions

Internal module of `conformance-federation`: the fault scenes of an OpenID Connect IdP whose description cannot be read at boot, each a deployment of its own on one Redis.

## Responsibilities
- Checks that an IdP whose issuer refuses the connection, or answers its description 429, leaves boot going on, warned with outbound's word or the status: that IdP's start answers 503, and another IdP's login completes.
- Checks that one answered 503 at boot is read again once a start needs it, a minute on: the first start answers 503, and the next logs in, the read told.
- Checks that a description naming another issuer still refuses boot.

## Invariants
- The refused issuer is at a port no test takes and outbound reaches, port 2 at loopback, checked to refuse connections before the scenes.
- The minute is waited in real time: moving an instance's clock restarts it, and a restart reads the description at boot, not again.

## Depends on
- The package's scene builder, browser and fake upstream (its description switched by the scene); `grants` (the upstream's client); `conformance` (the deployment and the topology).
