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

The provider fails closed: a dependency that cannot answer never grants anything, and the request is refused, `503`, or for the authorization endpoint, once it has found the browser's session, a redirect with `error=temporarily_unavailable` ([promise 3](security-model.md#promises-across-modules)). Availability is what it trades for this.

- **Tested** under Redis faults, each guarantee under the faults named with it:
  - The authorization endpoint gives no code while a dependency its decision waits on cannot answer, with the network to or from Redis cut, the connection closed, Redis late or slow, a failover, a failover whose confirmations stay on the old primary, and Redis killed (guarantee 3-a). Until it has found the browser's session it sends the client no outage's answer and answers `503` itself, for `prompt=none` too; once it has, it sends `temporarily_unavailable` back. A silent request's refusals before the session (`invalid_scope`, a repeated parameter, an unknown `reauth`) are no outage's answer: they go back to the redirect URI without the session read, as [U-0.19-89](migration.md#u-0.19-89) says. A slow Redis is shown both before the session is found and after.
  - The token endpoint gives no token for a code, a refresh token, a JWT bearer assertion or a device code while a dependency its decision waits on cannot answer, under the same faults and a failover whose confirmations stay on the old primary (guarantees 3-b, 3-c, 3-d, 3-e).
  - The token endpoint gives no token for a code while the store cannot write (memory full, a write's confirmation by the replicas timed out or refused, replication chosen with no replica), and redeems the code once it can write again (guarantee 3-j, shown for a code alone).
  - The provider does not boot on a Redis set to evict keys (guarantee 3-k).
  - A password login opens no session, and an attempt limit lets no attempt by whatever `rate-limit.fail-mode` is, while the store cannot answer, under the same faults and a failover whose confirmations stay on the old primary (guarantees 3-f, 3-i).
  - A request limit lets no request by where `rate-limit.fail-mode = closed`, under the same faults but that split failover, which its windows, asking no replication, cannot meet (guarantee 3-h).
  - A revocation route answers done only once its revocation is kept, under the same faults and a failover whose confirmations stay on the old primary: the token revocation endpoint (3-g), and the ledger's subject revocation route, which tells a boundary not confirmed (`unknown`) from one written whose followers did not finish (`incomplete`) (3-l).
- **Declared:** no other grant that keeps in the store what it issues or what issuing spends issues anything while the store cannot write either, and a request made once it can write again passes (guarantee 3-j); the scenes above show it for a code alone. A grant that keeps nothing in the store to issue, as client credentials (the token endpoint's request count aside), is outside 3-j: it stops only where a dependency its decision waits on cannot answer, as [promise 3](security-model.md#promises-across-modules) says.
- **Tested** with a store that refuses, by each area's "the store failing" scenes (code, exchange, oauth, federation, second factor, passkey) and the identity area's password login over a failing user ledger.
- **What stops and what goes on.** Every request whose decision needs the store or a ledger answers `503` while it cannot answer. What needs neither goes on: the discovery document, the key set, and a resource server verifying a token itself. `/readyz` answers `503` while the Redis probe fails ([runbook: Outages](runbook.md#outages)).
- **Declared exceptions, the operator's choice:** `rate-limit.fail-mode = open` lets a request limit pass requests uncounted while its store cannot count (an attempt limit still refuses), and `mtls.revocation.on-unavailable = allow` binds a certificate while its revocation cannot be told.
- **Operator's:** Redis's availability (replicas, `redis.replication`, failover that never promotes a lagging replica), the probes and the alerts ([runbook: Redis](runbook.md#redis), [Probes and alerts](runbook.md#probes-and-alerts)).
- **Not yet shown:** how long a failure lasts as seen by clients, and how fast service comes back. The scenes show that nothing is granted during a fault and that requests pass after it; they measure no recovery time and promise no service level.

## Revocation at resource servers

Where a revocation is checked decides how long what it revoked can still be used ([Revocation delays](security-model.md#revocation-delays)).

- **Tested:** at this provider, the next check after a revocation is recorded refuses what it revoked: a subject the ledger revokes, by every way to a token (the code, exchange, federation and second factor areas' scenes, [promise 4](security-model.md#promises-across-modules)).
- **Declared:** a resource server that asks introspection learns at its next call of what this provider's own checks refuse, unless it keeps the answer (at most to the token's `exp`). Introspection checks no more than they do: a subject's revocation stops an access token only with `subject-tokens` composed, and a token revoked by id only with `tokens.revocation = denylist`. Under `tokens.subject-check = none`, an access token not bound to a session stays active at introspection until it expires, unless it is revoked by id (`tokens.revocation = denylist`).
- **Operator's:** a resource server that verifies a JWT access token itself takes it until it expires, whatever was revoked meanwhile. Where that is too long, have resource servers ask introspection and compose `subject-tokens` and choose `tokens.revocation = denylist` with it, or shorten `tokens.access-token-lifetime`.
- **Tested** under Redis faults, with Redis shared by several instances, each read at another instance while the revocation's followers are still to run, so the boundary alone refuses:
  - Once a subject's boundary is written, the session and its tokens made before it are refused, the boundary's write under a lost answer, all answers lost, a failover, Redis killed, an instance killed after writing it, and two instances at once; a revocation whose boundary is not confirmed never answers done (guarantee 4-a, and 3-l for the ledger's route).
  - With two instances, one revoking and another reading, and two revoking at once: a device code (4-b), a federation grant, which with `keep-on-subject-revocation` and delegations kept answers to the `delegations` boundary alone (4-c), a token exchange (4-e), and a second factor change a session asked as the revocation overtook it (4-d) made before the boundary are refused; the boundary's write is the one 4-a's faults hold.
- **Not yet shown:** no scene runs a resource server outside the provider.

## Audit

Audit is best effort ([Audit](security-model.md#audit)).

- **Tested** (the audit module's tests): every event a receiver loses is counted per receiver as `auth_audit_events_lost_total`, with one warning naming the receiver and the kind of failure, never the event; past a receiver's `max-pending`, an event is not queued and is counted lost; at stop, deliveries under way are awaited until `kernel.stop-deadline`, and those still under way then are counted lost.
- **Not guaranteed:** delivery. A request is answered without waiting for its events, and `audit-http` never sends an event again.
- **Operator's:** a collector that keeps up, and an alert on `auth_audit_events_lost_total` ([runbook: What to alert on](runbook.md#what-to-alert-on)). An audit trail that must be complete, for a regulator say, needs what the provider does not offer: a durable path to the collector, and resending or detecting gaps beyond the lost-event count.
- **Not yet shown:** scenes that stop, slow or fill a receiver against a running provider.

## Several instances

- **Tested**, with Redis shared:
  - An authorization code is redeemed once (guarantee 5-a), a refresh token is rotated once (5-b), and a JWT bearer assertion's, a client assertion's and a DPoP proof's `jti` is spent once (5-c, 5-d, 5-e).
  - A session left closing is closed by its logout or a later sweep on any instance, and a logout that cannot finish answers `503` (1-a). Declared exception: a session the cap pushed out while the store could not keep its close ends without its participants or a back-channel notice, and its access tokens live until they expire ([design.md's Decisions](design.md#decisions)).
  - A device code is decided and redeemed once, a recovery code is used once, a passkey challenge is used once (5-f, 5-g, 5-h), a login lockout's count holds, each attempt counted once (5-i), and an id_token is exchanged once, by the token exchange or as a JWT bearer assertion (5-j).
  - A subject's revocation boundary refuses, at any instance, what was made before it (4-a to 4-e, under [Revocation at resource servers](#revocation-at-resource-servers)).
- **The faults each ran under.** On one instance: a lost answer, all answers lost (but for 1-a and 5-i), a failover, and Redis killed; for 5-a, 5-b and 1-a also a failover whose confirmations stay on the old primary. On two instances: an instance killed after a write and before its answer, and two instances acting on the same thing at once; for 5-a also an instance's clock moved forward or back, and for 1-a all answers to a closing lost, another instance's sweep closing it. A scene on one instance shows what Redis's faults do, not what a second instance does at the same time.
- **Declared:** boot refuses a module that declares itself unsafe on several instances, or declares nothing of them, as [promise 5](security-model.md#promises-across-modules) says; a declaration is its author's word, so check your own modules' before setting `kernel.deployment = multi`.
- **Declared:** where the upstream ends a federation grant while the store answers reads but refuses writes, only the instance that heard the end refuses the grant; another hands out the upstream access token it holds until that token ends or the end is written. Where the store answers no reads, every instance answers unavailable.
- **Operator's:** the same configuration on every instance (the signing keys, the issuer, Redis's URL and prefix, the seal key, the registered clients and users, the trusted proxies and public origin, the DPoP nonce secret, each IdP's settings, and the shard counts and per-shard limits of the work the sweeps walk: code-grant-store's `void-shards`, session-store's `closing-shards`, refresh-store's `settle-shards`, rp-logout-store's `notice-shards` and session-tokens-store's `pending-shards`, each with its `*-per-shard` limit; and, once set, `mfa-witness-http.withdraw-url`, and `login-passkey.password` with `login-passkey.password-exempt-group`, as the runbook's steps for them say), and host clocks synchronized, with no skew allowed between hosts ([Trust assumptions](security-model.md#trust-assumptions), [runbook: Many instances](runbook.md#many-instances)).

## Outside the provider

The provider takes the word of what stands beside it, as the [trust assumptions](security-model.md#trust-assumptions) state each, and an audit of the provider leaves those servers out ([audit scope](audit/scope.md)).

- **Operator's:** the proxy in front (stripping what clients forge of the forwarded source, scheme and client certificate, and named in `http.trusted-proxies`), TLS, the hosts' clocks, Redis's persistence and replicas, the upstream identity providers' word on their own authentication as far as it is mapped, the ledgers, the outbound proxy's resolution of names, and the secrecy of the configuration.
- **Operator's:** an upstream certificate's revocation, which `outbound` does not check: the egress proxy or the platform checks it, or the operator accepts that risk ([trust assumptions](security-model.md#trust-assumptions)).
- **Tested** at boot, on a server that answers `CONFIG GET`: Redis's eviction policy (guarantee 3-k), its append-only file, and its replication settings, each refused at boot when it does not hold (the `redis` module's tests; the [runbook](runbook.md#what-the-server-must-be) lists what boot checks). Boot checks the settings, not that a replica is online: with `redis.replication = replicas` and none following, the provider boots and answers `503` to what must write until one follows (guarantee 3-j).
- **Operator's:** on a server that refuses `CONFIG`, the settings declared in `redis.server-settings`, which boot takes unchecked ([runbook: A managed Redis that refuses `CONFIG`](runbook.md#a-managed-redis-that-refuses-config)); and with `redis.durability = none`, the append-only file is not checked at all, and a crash loses the latest writes.
- **Operator's:** `DEBUG` left without `ioredis` (or `*`) in production: the Redis client's own debug log writes what it sends, AUTH's password among it. Every boot warns `redis.client_debug_log`, with no value, while it is set so.
- **Not yet shown:** the safety of a whole deployment, the provider with its proxy, Redis, upstreams and ledgers, run end to end as one reference deployment.

## Not yet shown

Gathered from the sections above:

- Recovery times and a service level under failure.
- A resource server outside the provider verifying tokens after a revocation.
- An audit receiver stopped, slowed or filled against a running provider.
- A reference deployment run end to end with its proxy, Redis, upstreams and ledgers.
