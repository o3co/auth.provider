# Operations runbook

How to run auth-provider 0.18: Redis, rotating keys, upgrading, and what to watch. The settings named here are listed in the [configuration reference](configuration.md).

## Contents

- [Before you deploy](#before-you-deploy)
- [Redis](#redis)
- [Rotating the signing key](#rotating-the-signing-key)
- [Rotating the sealing key](#rotating-the-sealing-key)
- [Upgrading](#upgrading)
- [Revoking a user from the ledger](#revoking-a-user-from-the-ledger)
- [Keeping the second-factor witness at the ledger](#keeping-the-second-factor-witness-at-the-ledger)
- [Probes and alerts](#probes-and-alerts)
- [Stopping](#stopping)

## Before you deploy

The app relies on the deployment for these. Each is required, not advice.

1. **The proxy in front strips and sets forwarded headers.** It removes any `X-Forwarded-For`, forwarded scheme or client-certificate header a client sent, and sets its own. The app trusts them from `http.trusted-proxies` alone, so a proxy that passes a client's own lets the client choose its source address and certificate.
2. **Outbound through a proxy leaves address checks to the proxy.** With `outbound.proxy` set, the app checks a destination's name, and an address written in its URL, but never resolves a proxied name: the proxy must refuse private, loopback, link-local and metadata addresses itself. Boot warns of this.
3. **The proxy in front bounds slow requests and connections per client.** The app bounds a request's headers and the whole request (`http.headers-timeout`, `http.request-timeout`) and the connections it holds (`http.max-connections`), all clients together. Limit upload rate, header size and connections per client in front of it.
4. **Host clocks are synchronized (NTP).** Sessions, codes, tokens, lockouts and key expiry are judged on each host's clock, and only federation grants allow for skew between hosts.
5. **`rate-limit.fail-mode = open` lets requests through uncounted while the store is down.** Keep the default `closed` unless an outage must not refuse requests.
6. **`signer-keys-http` asks the ledger once for every assertion.** Each JWT bearer assertion from its issuer is one `POST` to `keys-url`, made before the assertion's signature can be checked and never cached, so a revoked device stops at once. Only the token endpoint's requests per source (`token-endpoint.requests` per `window`) bound these calls: size the ledger for that rate, from every source together.
7. **RP-initiated logout by GET closes the session without asking** when it carries an `id_token_hint` issued within the last 24 hours, as the specification allows. A relying party, or a page that can make the browser follow its link, can log the user out.
8. **Keep Node's threadpool at 4 threads or more where `clients-cimd` runs.** Name lookups run on the threadpool, and `outbound` resolves at most half of it at once, giving names an outside party chose (a client's metadata document) half of that, rounded down. With `UV_THREADPOOL_SIZE` at 2 or less, they get none, and `clients-cimd` refuses boot, naming it. The default, 4, gives them one.

## Redis

### What the server must be

The `redis` module checks the server once, at boot, and refuses to start when any of these does not hold:

- Redis 7.0 or later, answering as a primary. Cluster mode is refused, and so is a proxy that splits keys across nodes.
- `maxmemory-policy noeviction`, where any composed module keeps data that must never be evicted (sessions, the token denylist, lockouts, DPoP proof ids).
- `appendonly yes` and `appendfsync always`, where any composed module keeps data that must survive a crash. RDB snapshots are not enough.
- With `redis.replication = replicas`: `min-replicas-to-write` and `min-replicas-max-lag` of at least 1.
- With `redis.replication = none`: no replica connected.

The check reads the server's settings with `CONFIG GET`, and `ROLE` and `INFO` always.

### A managed Redis that refuses `CONFIG`

Where the server refuses `CONFIG GET` for good (`NOPERM`, or the command renamed or missing), declare its settings in `redis.server-settings` (`maxmemory-policy`, `appendonly`, `appendfsync`, `min-replicas-to-write`, `min-replicas-max-lag`). The check then takes them as declared and judges them as it judges the ones it reads; a setting it needs and you left out refuses boot, naming it. Every boot logs `redis.settings_declared` with the names taken from the declaration, since nothing confirmed them. Any other error, such as `BUSY` while a long script runs, refuses boot rather than taking the declaration; start again once the server answers.

Declare only what the server really has: a declaration is your statement, and the check cannot see past it. Where `CONFIG GET` does answer, a declared value that differs refuses boot.

A server that does not fsync every write cannot give the durable guarantee. Set `redis.durability = none` to state so and accept the loss: a crash then loses the latest writes, among them spent assertion and DPoP proof ids (a replay window) and lockout records. Every boot then logs `redis.durability_none` naming the durable spaces. Without it, boot is refused.

- Amazon ElastiCache: append-only files are not available, so declare `appendonly no` and set `durability = none` where a durable space is composed.
- Other managed services: check in each service's documentation which of these settings you can set and what they hold before declaring them.

Connect with `rediss://` for TLS. The password goes in the URL. The URL is never logged, and a refusal never quotes it.

### Managed Redis/Valkey with replicas

A managed, non-cluster Redis or Valkey with replicas and automatic failover serves `redis.replication = replicas` when three things hold.

**Set these in the service's own configuration**, then declare the same values in `redis.server-settings` where it refuses `CONFIG`:

- `min-replicas-to-write` of 1 or more, and `min-replicas-max-lag` of 1 or more, so a primary cut off from its replicas stops taking writes;
- `maxmemory-policy noeviction`;
- for the durable spaces, `appendonly yes` and `appendfsync always`, or `redis.durability = none` where the service offers neither (see [A managed Redis that refuses `CONFIG`](#a-managed-redis-that-refuses-config)).

Where the service keeps these in a parameter group whose defaults are 0 or another policy, make a group of your own with these values: declaring them while the server holds the defaults is a statement the check cannot see past.

**Allow these commands and keys**: `EVAL`; the commands its scripts call (`TIME`, `INFO server` and `INFO replication`, `EXISTS`, `GET`, `HGET`, `HMGET`, `PTTL`, `PEXPIRETIME`, `SET`, `INCR`, `HSET`, `HINCRBY`, `PEXPIRE`, `PEXPIREAT`, `DEL`); `SCAN`; `ROLE` and `INFO`; and the keys under `redis.prefix`. Where `redis.replication` is set, a write is confirmed by a round of `ROLE`, `INFO server` and a `SET` of `<prefix>:#confirm`, and with `replicas` a `WAIT`, so allow that key and `WAIT` too. Boot sends each of these once, a script's on keys of the store's own (`<prefix>:{#check}:…`) that it then removes (where the service refuses both `PEXPIRE` and `DEL`, they stay until you remove them), and is refused naming a command or the keys the service refuses; the readiness probe sends them again, so one refused later answers `/readyz` 503 and logs `redis.settings_unmet` naming it. A replica that is missing or lags still shows only as 503s on replicated writes, as [Choosing `replication`](#choosing-replication) says: a write refused for want of replicas leaves a command unjudged.

**Know what the service's failover keeps.** A write to a replicated space is confirmed only once every replica `ROLE` shows has it, and a primary that sees no replica confirms nothing. So a confirmed write is on every replica that was connected when it was confirmed, and survives the service promoting any of them. It can be lost only where the service promotes a replica that had already dropped out of replication (one `ROLE` no longer showed), as it then holds nothing confirmed since. On a managed service you cannot keep such a replica from promotion yourself: check how the service picks the replica to promote, and prefer one that promotes the most up-to-date. A request that reaches the new primary in the middle of a failover answers 503 rather than an answer the new server did not compute, and versions never repeat across the failover.

### Choosing `replication`

- `replicas`: writes that must survive a failover wait until every replica has them. While no replica is seen, or replicas lag, those writes are unavailable and the requests that need them answer 503. The system denies rather than allows.
- `none`: you state there is no failover. A failover then loses even confirmed writes, and a replica seen at boot or at runtime is refused or unavailable.

Keeping a detached or lagging replica from being promoted is the operator's job, and so are the replicas' own disk settings. A `CONFIG SET` after boot is not seen.

### Outages

Nothing is queued or retried. A dropped connection fails at once, and the request that needed Redis answers 503 with `Cache-Control: no-store`; nothing ends the process. `/readyz` answers 503 while the `redis` probe (a `PING` on both connections) fails, and the gauge `auth_dependency_up{dependency="redis"}` shows which dependency is down.

When an outage hits a login whose subject already holds as many sessions as the listing keeps, the sessions the login pushed out cannot be closed through their participants. Each is listed again for what it has left; one that cannot be, or that taking one back pushes out, is ended in its record without its participants. Access tokens issued in such a session stay valid until they expire (`tokens.access-token-lifetime`). Watch `session-lifecycle.listing_ended` and `session-lifecycle.listing_put_back_failed` (counts); to end those tokens at once, revoke the subject.

Rate limits fail closed by default (`rate-limit.fail-mode = closed`), so an outage never lifts a limit. Attempt limits, such as login attempts, always answer 503 while they cannot count.

### Many instances

Each instance walks every federation grant kept every `federation-grants.sweep-interval` (default `1h`), erasing the credentials of grants past their end or ended by their subject's revocation that no request reads. A pass reads every grant record kept (each lives its lifetime and 30 days more) and, for each grant holding credentials, the subject's revocation boundary once or twice; every instance makes its own passes. Lengthen the interval where there are many grants or many instances.

Set `kernel.deployment = multi` when more than one instance runs. Boot then refuses any module that keeps state in the process, such as the in-memory `store` and the logging-only `mail`. A pattern created with an in-memory store says in its README that it runs as one instance.

## Rotating the signing key

Tokens name the key that signed them (`kid`). An instance verifies a token by the key it names and publishes the public keys as its key set (the `jwks_uri` its metadata names), which verifiers may cache for 300 seconds.

`keys.signing` signs, `keys.next` is published but never signs, and each `keys.previous` entry is published until its `expires-at`. The ring is read at boot, so every step ends with restarting every instance.

1. **Publish the new key.** Write the new key in `keys.next`, then restart every instance. Tokens are still signed with the current key.
2. **Wait for caches.** Wait at least 300 seconds after the last instance restarted, so every verifier that cached the key set has the new key.
3. **Sign with the new key.**
   - Move the new key from `keys.next` to `keys.signing`.
   - Move the old key to `keys.previous`, with an `expires-at` later than now plus the longest token lifetime. The access-token lifetime is 3600 seconds by default; count refresh and ID tokens if they are verified by this key.
   - Restart every instance. During a rolling restart, the instances not yet restarted already publish and verify the new key, because of step 1.
4. **Retire the old key.** After its `expires-at`, remove it from `keys.previous` at the next restart. Tokens it signed are refused with `kid_expired` from that time.

An HS256 secret is not published and has no `previous` or `next` form: changing it refuses every token signed with the old secret at once. Where policy-verifier checks the same tokens with the same secret, set `keys.signing.secret-encoding = utf8`: the verifier takes the text's own bytes.

None of these steps needs a new image. Keep the ring in a HOCON file of its own, outside the image (a mounted secret, say), and name it first in `APP_CONFIG`, which lists files comma-separated with the first winning: `APP_CONFIG=/run/secrets/keys.conf,config/application.conf`. An array is replaced from one file to the next, never added to, so that file holds the whole `keys.previous` list, and `seal.previous` too where it holds the sealing ring. A single value can also come from the environment where the file writes `${VAR}`, as `public-key = ${NEXT_PUBLIC_KEY}`; a PEM spans several lines, so its variable must carry them, which an env file read one line per variable does not.

## Rotating the sealing key

`seal` encrypts stored secrets with AES-256-GCM under a key ring: `seal.current` seals new values; `seal.next` opens but never seals; `seal.previous` keys only open. Each sealed value names the key that sealed it.

The ring can be kept in a file of its own outside the image, as [the signing key's](#rotating-the-signing-key) can.

1. **Add the new key as `next`** and restart every instance.
2. **Make sure every instance runs with it** before going on: each now opens values the new key seals, before any instance seals with it.
3. **Move it up.** Make it `current`, put the old `current` first in `previous`, and restart every instance. New values are sealed with the new key. A value read and written anyway (a renewed upstream token, a proved MFA factor) is sealed again with it as it is written.
4. **Make sure every instance runs with the new `current`** before going on: an instance still sealing with the old key writes values a walk started meanwhile would miss.
5. **Seal the rest again.** Run `pnpm run reseal` in the app, with its configuration. It builds the app without serving anything, walks every holder of long-lived sealed values (`federation-tokens`, `federation-grants`, `mfa`), seals again what a `previous` key sealed, and prints each holder's counts, never an id or a value. Running it while traffic flows is safe: each value is written only over what was read. Run it until it exits 0, which it does only when no holder failed, nothing was sealed again and nothing is left; it then prints `previous keys may be retired`. It exits 1 when a holder failed, and 3 when it sealed values again: run it again either way, as a walk across a failover or restart can miss a value, which the next run then seals.
   - On 2, do not go on: a value sealed with a key no longer in the ring remains, left by an earlier rotation (or damaged). Put back the key you retired last as `previous`, restart every instance, and run `reseal` again until it exits 0.
6. **Retire the old key** only after a `reseal` run that exited 0. Wait out short-lived values first: transactions and held logins sealed with the old key end within an hour (the longest `transaction-lifetime`). Then remove it from `previous` and restart every instance. A value it still sealed becomes unavailable (503, not refused), and putting the key back opens it again.

Only a value a `previous` key sealed is sealed again; one `next` sealed is newer than `current` and is left as it is, so values never move back while a rollout is under way.

## Upgrading

> **A rolling upgrade under `kernel.deployment = multi` makes sessions unavailable while old and new instances run together.** An instance cannot read a session record that a newer instance wrote: it lets nobody in on it and answers a login or logout on that cookie with 503. The cookie stays, and the session works again once every instance runs the new version. Upgrade all instances together, or expect 503s on session routes until the rollout ends.

- Stored records keep their names within a version. A new version that changes a record's shape reads the old one for the record's lifetime.
- Changing `redis.prefix` starts from empty state: every key, sessions, refresh tokens, the denylist, lockouts and MFA factors included, lives under the prefix.
- `create-auth-provider` never writes into a non-empty directory. To add a feature to an existing app, generate again (`create-auth-provider <target> --add <feature>`) and carry your configuration over.
- A boot that refuses exits with status 78 and prints each refusal on stderr, by setting path and never by value. Fix every refusal it lists; they are reported together.

## Revoking a user from the ledger

When the outside user ledger suspends a user, its answers stop new logins and grants, but sessions already open and tokens already issued go on. To stop those too, compose `subject-revocation-http` and have the ledger call it.

**Setting it up.**

- The provider must sit behind a proxy it trusts (`http.trusted-proxies`), which ends TLS. Without one, boot is refused: no request can be told as https. The network between that proxy and the provider must be your own.
- Make the credential random, at least 32 bytes (for example `openssl rand -base64 32`), and set it as `subject-revocation-http.credential`. The ledger sends it as `Authorization: Bearer`.
- List the ledger's addresses in `subject-revocation-http.sources` (IP addresses or CIDR blocks). Addresses of your trusted proxies there are never matched: a request's source is told past them.
- Throttle floods at the proxy. Bodies the provider cannot read (`400`, `413`, `415`) are answered before any count.
- Compose an audit receiver that keeps what it is given, such as `audit-http`, to keep each revocation's result and source. Events a receiver does not take are counted in `auth_audit_events_lost_total`.

**Calling it.** `POST /ledger/subject-revocations` with `{"subject": "...", "delegations": "end"}` (`keep` leaves delegations to `federation-grants.keep-on-subject-revocation`).

- `200 {"complete": true}`: recorded, and every follower finished.
- `503` with `state: "incomplete"`: recorded (everything that reads the revocation now refuses), but a follower did not finish. `state: "unknown"`: whether it was recorded is not known. No `state`: the rate limits could not count. Resend after `Retry-After` in every case until `200`; recording again is safe.
- `429`: wait as `Retry-After` says. `401`, `403`, `400`: fix the call; resending the same will not help.

**Reinstating a user.** A resend that arrives after reinstatement revokes again and closes the new sessions. Cancel the ledger's pending resends before reinstating.

**Rotating the credential.** Put the old value in `previous-credential` and the new one in `credential`, roll out, switch the ledger to the new one, then remove `previous-credential`.

**What it stops, and what it leaves.**

- Stopped: the subject's open sessions (and with them the session's refresh tokens, its access tokens, and the local copy of its upstream tokens; relying parties are sent logout notices), and from then on every refresh, device poll, JWT bearer grant, exchange, passkey login and second-factor step; access tokens too where `subject-tokens` is composed. With `delegations: "end"`, federation grants end.
- Left until they expire: access tokens not bound to a session where `tokens.subject-check = none`, JWTs a resource server checks itself, and tokens already handed to an upstream. A request already past its checks when the revocation is recorded may finish.
- Every subject revoked keeps its record with no end, so the records grow with the subjects you revoke. With `mfa-revocation`, each revocation also writes the subject's factor list in `mfa`'s store, empty for a subject who never enrolled, so that store grows with them too.
- With second factors composed, `mfa-revocation` makes a revocation complete only once no enrollment begun before it can bind; an app composed by hand must compose it, as `combinations` does.
- Likewise `mfa-entry` holds sessions to second factors; `mfa` refuses to boot without it, whatever the mode, so an app composed by hand must compose it.

## Keeping the second-factor witness at the ledger

Compose `mfa-witness-http` to have the outside user ledger remember which subjects hold a second factor, apart from the provider's own records: losing those records then never reads as a subject that never enrolled one. The provider asks the ledger whenever a subject holding no counting factor logs in, starts a first enrollment or changes their credentials, so the ledger's answers gate those steps for those subjects. `mfa-witnessing` keeps the marks in line with the factors; `combinations` composes it with the two, and an app composed by hand must compose it too.

**Setting it up.**

- Serve `read-url`, `enroll-url` and `clear-url` on one origin, over https (or plain http at a `host:port` named in `outbound.plain-loopback`, at loopback, or in `outbound.plain-internal`, at private addresses on a network you trust). Boot is refused on URLs at two origins. Allow the host in `outbound.allow`; over https, list it in `outbound.internal-hosts` too when it has a private address. A `plain-internal` pair needs no `internal-hosts` entry.
- Make the credential random, at least 32 bytes (for example `openssl rand -base64 32`), and set it as `mfa-witness-http.credential`. The provider sends it as `Authorization: Bearer` on every call.

**What the ledger must do.** The provider cannot check any of this; it is yours to keep.

- `POST read-url` with `{"subject"}`: answer `200 {"enrolled": true|false}`, whether the subject carries the mark.
- `POST enroll-url` with `{"subject", "token", "deadline"}`: set the subject's mark to `token` unless one is set, as one atomic step, and answer `200 {"owner": true|false}`, whether the mark is that token's. The same token sent again answers alike.
- `POST clear-url` with `{"subject", "deadline"}`: remove the mark and answer `204`. The provider asks it when an operator resets a subject's second factors, and where a mark it set itself stands beside no counting factor (a reset took the factor while it marked).
- Per subject, the three calls take effect one at a time, in the order they are answered. An answered write survives a crash or a failover, and no read answers older than the last answered write: no lagging replica or cache answers a read.
- Never carry out an enroll or a clear received after its `deadline` (epoch milliseconds on the provider's clock): the provider stopped waiting for it then. Keep the ledger's clock synchronized with the provider's hosts.
- Any other answer, `404` included, makes the call unavailable (`503`), never "not enrolled".

**The deadline.** It is the time a write is sent plus `mfa-witness-http.timeout` (default `5s`, as `outbound.timeout`'s). Keep `outbound.timeout` no shorter: the provider gives up at the shorter of the two, and a deadline past that leaves the ledger time to carry out a write the provider no longer waits for.

**When the provider marks.** Once a binding has written a counting factor, the provider marks the subject where no mark is there, under a new token; between that write and the mark the factor stands unwitnessed. It then reads the factors again: where a reset took them meanwhile it clears the mark it set, and where that clear took the mark of a binding just after, it marks anew. A mark it did not set it never clears; only a reset does. Where the mark and the factors still differ after two marks, the binding answers unavailable though its factor is written, and the next binding fills the mark.

**Composing it where subjects already hold a factor.** A subject who enrolled before the witness was composed, and has bound nothing since, carries no mark: if its factor records are then lost, the subject reads as one who never enrolled, and under `mfa.mode = optional` logs in without a second factor. Once the witness is composed on every instance, run `pnpm run witness-backfill` in the app, with its configuration, giving it the subjects on standard input, one a line (for example `pnpm run witness-backfill < subjects.txt`). It builds the app without serving anything and marks each subject that holds a counting factor and carries no mark. It prints how many it marked, found marked already (`held`), found holding none (`none`), found marked though holding none (`inconsistent`, left as they are: see below) and could not settle (`failed`), never a subject. It exits 0 when none failed, else 1: run it again on the same list until it exits 0. It exits 78 when the app's boot is refused.

**A mark left with no factor.** A reset that cleared the subject's factors but stopped before the ledger cleared the mark (the ledger unavailable), or factor records the provider lost, leaves the mark with no factor: that subject is refused as inconsistent until an operator resets its second factors, which clears the mark.

**While the ledger cannot answer.** Subjects holding no counting factor get `503` at login, when they start their first enrollment and when they change their credentials, until it answers; subjects holding one are let through without asking it.

## Probes and alerts

### Probes

- **Liveness**: `GET /_healthcheck` answers `200` while the process serves requests, and checks no dependency. Restart an instance on it alone; the generated image checks it.
- **Readiness**: `GET /readyz` answers `200` when every probe the composed modules contribute (Redis's, for one) passed within `http-ops.readiness-deadline`, and `503` otherwise, never naming what failed. Take an instance out of the load balancer on `503`, and do not restart it for that: it is ready again once the dependency is.

### What to alert on

`metrics-prometheus` publishes the counts at `metrics-prometheus.path` (default `/metrics`); limit who may scrape it at the proxy.

- **`auth_dependency_up` is 0** for a probe: that dependency is down, and `/readyz` answers `503`. The probe's name says which.
- **`auth_rate_limit_uncounted_total` rises**, by `limit` (`requests` or `attempts`): a rate limit could not count, usually because the store is down. Attempt limits then refuse with `503`; request limits refuse too, or let requests through uncounted where `rate-limit.fail-mode = open`.
- **`auth_audit_events_lost_total` rises**, by `receiver`: a receiver is not taking events, so the audit trail has a gap. The warning `audit receiver losing events` says why.
- **`http_request_duration_seconds`**: the rate of `5xx` answers and the latency, by method and route. A `499` is a client that closed before the answer.
- **The process**: the Node defaults, prefixed `auth_provider_` (event loop lag, memory, handles).
- **Warnings in the log**: a failed periodic run, probe or stop hook is one warn line naming it.

## Stopping

On SIGTERM or SIGINT the app stops taking new connections, lets requests in flight finish, and runs each module's stop hook, all within `kernel.stop-deadline` (default `30s`). Give your orchestrator a longer grace period than that.

Audit events still being delivered at stop are awaited until the same deadline. Any still under way then are lost and counted: watch `auth_audit_events_lost_total`, by `receiver`, and the warning `audit receiver losing events` with `failure: stopped`.
