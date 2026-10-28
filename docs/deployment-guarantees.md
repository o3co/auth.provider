# Guarantees by deployment

What a deployment of this provider can count on, in each shape it is deployed in: what is guaranteed, under what conditions, what is left to the deployment and to the servers beside it, and what is not shown yet. The mechanisms are in the [security model](security-model.md) and the [runbook](runbook.md); this page links to them rather than repeat them.

## How to read this page

Each statement carries one mark:

- **Tested**: a test or a conformance scene shows it. The [guarantee checklist](compliance/guarantee.md) lists each scene by the guarantee it shows and the fault it runs under.
- **Declared**: a contract and its module's card promise it, and boot or a guard rule keeps it where it can; no scene shows it yet.
- **Operator's**: the deployment must provide it. The provider cannot check it, or checks it only at boot.
- **Not yet shown**: nothing here shows it, or the evidence is not in yet.

## Deployment shapes

| Shape | Instances | Store | Use |
|---|---|---|---|
| Trial | one (`kernel.deployment = single`) | kept in the process (`store`, with `store.accept-volatile`) | trying the provider; a restart forgets every session, code and spent id |
| One instance | one | Redis | production on one host |
| Several instances | two or more (`kernel.deployment = multi`) | Redis, shared | production behind a load balancer |

Three choices cut across these shapes and change what the sections below say: whether resource servers verify access tokens themselves or ask introspection, which audit receivers are composed, and what stands in front of the provider (its proxy and TLS).

## Availability when a dependency fails

The provider fails closed: a dependency that cannot answer never grants anything, and the request is refused, `503`, or for the authorization endpoint a redirect with `error=temporarily_unavailable` ([promise 3](security-model.md#promises-across-modules)). Availability is what it trades for this.

- **Tested** under Redis faults, each guarantee under the faults named with it:
  - The authorization endpoint gives no code while a dependency its decision waits on cannot answer, with the network to or from Redis cut, the connection closed, Redis late or slow, a failover, and Redis killed (guarantee 3-a).
  - The token endpoint gives no token for a JWT bearer assertion while a dependency its decision waits on cannot answer, under the same faults (guarantee 3-d).
  - The token endpoint gives no token for a code while the store cannot write (memory full, a write's confirmation by the replicas timed out or refused, replication chosen with no replica), and redeems the code once it can write again (guarantee 3-j, shown for a code alone).
  - The provider does not boot on a Redis set to evict keys (guarantee 3-k).
- **Declared:** nothing else is issued while the store cannot write either, and a request made once it can write again passes (guarantee 3-j); the scenes above show it for a code alone.
- **Tested** with a store that refuses, by each area's "the store failing" scenes (code, exchange, oauth, federation, second factor, passkey) and the identity area's password login over a failing user ledger.
- **Not yet shown** under the injected Redis faults: the token endpoint for a code, a refresh token and a device code; a password login; the revocation routes; request and attempt limits (guarantees 3-b, 3-c and 3-e to 3-i).
- **What stops and what goes on.** Every request whose decision needs the store or a ledger answers `503` while it cannot answer. What needs neither goes on: the discovery document, the key set, and a resource server verifying a token itself. `/readyz` answers `503` while the Redis probe fails ([runbook: Outages](runbook.md#outages)).
- **Declared exceptions, the operator's choice:** `rate-limit.fail-mode = open` lets a request limit pass requests uncounted while its store cannot count (an attempt limit still refuses), and `mtls.revocation.on-unavailable = allow` binds a certificate while its revocation cannot be told.
- **Operator's:** Redis's availability (replicas, `redis.replication`, failover that never promotes a lagging replica), the probes and the alerts ([runbook: Redis](runbook.md#redis), [Probes and alerts](runbook.md#probes-and-alerts)).
- **Not yet shown:** how long a failure lasts as seen by clients, and how fast service comes back. The scenes show that nothing is granted during a fault and that requests pass after it; they measure no recovery time and promise no service level.

## Revocation at resource servers

Where a revocation is checked decides how long what it revoked can still be used ([Revocation delays](security-model.md#revocation-delays)).

- **Tested:** at this provider, the next check after a revocation is recorded refuses what it revoked: a subject the ledger revokes, by every way to a token (the code, exchange, federation and second factor areas' scenes, [promise 4](security-model.md#promises-across-modules)).
- **Declared:** a resource server that asks introspection learns at its next call of what this provider's own checks refuse, unless it keeps the answer (at most to the token's `exp`). Introspection checks no more than they do: a subject's revocation stops an access token only with `subject-tokens` composed, and a token revoked by id only with `tokens.revocation = denylist`. Under `tokens.subject-check = none`, an access token not bound to a session stays active at introspection until it expires.
- **Operator's:** a resource server that verifies a JWT access token itself takes it until it expires, whatever was revoked meanwhile. Where that is too long, have resource servers ask introspection and compose `subject-tokens` and choose `tokens.revocation = denylist` with it, or shorten `tokens.access-token-lifetime`.
- **Not yet shown:** a revocation boundary held across instances under Redis faults (guarantee 4-a); no scene runs a resource server outside the provider.

## Audit

Audit is best effort ([Audit](security-model.md#audit)).

- **Tested** (the audit module's tests): every event a receiver loses is counted per receiver as `auth_audit_events_lost_total`, with one warning naming the receiver and the kind of failure, never the event; past a receiver's `max-pending`, an event is not queued and is counted lost; at stop, deliveries under way are awaited until `kernel.stop-deadline`, and those still under way then are counted lost.
- **Not guaranteed:** delivery. A request is answered without waiting for its events, and `audit-http` never sends an event again.
- **Operator's:** a collector that keeps up, and an alert on `auth_audit_events_lost_total` ([runbook: What to alert on](runbook.md#what-to-alert-on)). An audit trail that must be complete, for a regulator say, needs what the provider does not offer: a durable path to the collector, and resending or detecting gaps beyond the lost-event count.
- **Not yet shown:** scenes that stop, slow or fill a receiver against a running provider.

## Several instances

- **Tested** on two instances sharing Redis, under a lost answer, all answers lost, a failover, Redis killed, an instance killed after a write and before its answer, and two instances acting on the same thing at once:
  - An authorization code is redeemed once (guarantee 5-a), also with an instance's clock moved forward or back.
  - A refresh token is rotated once (5-b).
  - A JWT bearer assertion's, a client assertion's and a DPoP proof's `jti` is spent once (5-c, 5-d, 5-e).
  - A session left closing is closed by its logout or a later sweep on any instance, and a logout that cannot finish answers `503` (1-a).
- **Declared, not yet shown under these faults:** a device code decided and redeemed once, a recovery code used once, a passkey challenge used once, a login lockout's count, an id_token exchanged once (5-f to 5-j), and a subject's revocation boundary (4-a).
- **Declared:** boot refuses a module that declares itself unsafe on several instances, as [promise 5](security-model.md#promises-across-modules) says, with what it takes of a module that declares nothing; check your own modules before setting `kernel.deployment = multi`.
- **Operator's:** the same configuration on every instance (the signing keys, the issuer, Redis's URL and prefix, the seal key, the registered clients and users), and host clocks synchronized, with no skew allowed between hosts ([Trust assumptions](security-model.md#trust-assumptions), [runbook: Many instances](runbook.md#many-instances)).

## Outside the provider

The provider takes the word of what stands beside it, as the [trust assumptions](security-model.md#trust-assumptions) state each, and an audit of the provider leaves those servers out ([audit scope](audit/scope.md)).

- **Operator's:** the proxy in front (stripping what clients forge of the forwarded source, scheme and client certificate, and named in `http.trusted-proxies`), TLS, the hosts' clocks, Redis's persistence and replicas, the upstream identity providers' word on their own authentication as far as it is mapped, the ledgers, the outbound proxy's resolution of names, and the secrecy of the configuration.
- **Tested** at boot, where the provider can see it: Redis's eviction policy (guarantee 3-k), its append-only file, and its replication settings, each refused at boot when it does not hold (the `redis` module's tests; the [runbook](runbook.md#what-the-server-must-be) lists what boot checks).
- **Not yet shown:** the safety of a whole deployment, the provider with its proxy, Redis, upstreams and ledgers, run end to end as one reference deployment.

## Not yet shown

Gathered from the sections above:

- Under injected Redis faults: the token endpoint for a code, a refresh token and a device code, password login, revocation routes and rate limits failing closed (guarantees 3-b, 3-c and 3-e to 3-i); a subject's revocation boundary (4-a); a device code, a recovery code, a passkey challenge, a lockout and an exchanged id_token used once (5-f to 5-j).
- Recovery times and a service level under failure.
- A resource server outside the provider verifying tokens after a revocation.
- An audit receiver stopped, slowed or filled against a running provider.
- A reference deployment run end to end with its proxy, Redis, upstreams and ledgers.
