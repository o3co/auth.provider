# redis

## Responsibilities
- Implements the `store` contract with Redis, with one script per shape of basic operation and none per feature.
- Maps each partition to a hash tag, so a batch and a consistent read run in one slot. A batch across partitions runs in one script on the one server, over the slots of every partition it touches.
- Checks, once at boot, that the Redis configuration gives the declared spaces their guarantees.
- Confirms an answer before giving it, for spaces that need replicated or confirmed reads (internal module `round`).

## Not here
- Space names and meanings, and the shapes of values. Which feature uses it.

## Offers
- Composition definition only.
- The probe `redis` at `kernel`'s `probes` (internal module `probe`), given what boot checked of the server to check again.
- Operator section:
  - `url` (`redis` or `rediss`, with no query), `accept-plaintext` (false), `address-family` (`ipv4`, `ipv6`, or either unset), `prefix` (lower-case letters, digits and `-`; default `store`).
  - `connect-timeout` (default `2s`), `command-timeout` (default `1s`), `replication-timeout` (default `1s`); times written with their unit, a bare number refused.
  - `replication`: `replicas` or `none`, required when a space needs replicated or confirmed reads.
  - `durability`: `none`, or unset.
  - `server-settings`: the server's `maxmemory-policy`, `appendonly`, `appendfsync`, `no-appendfsync-on-rewrite`, `min-replicas-to-write` and `min-replicas-max-lag`, as the operator declares them.

## Invariants
- Connects to Redis itself, through its client, apart from `outbound`, which carries HTTP alone (`network`: `redis`).
- Boot is refused, naming what is unmet, when the server is not what Deployment states.
- Boot sends once every command the store sends, a script's on keys of the store's own (`<prefix>:{#check}:…`) it then removes, unless the server refuses that too; one the server refuses for good (`NOPERM`, or unknown or renamed), or keys it refuses the user, refuse boot, named. A write refused for want of replicas leaves a command unjudged, never refused.
- Boot then runs once what a confirmation would and a store script does: with `replication`, the confirming connection reaching another server than the operations (their run ids differ, and the operations' did not change meanwhile, as in a failover), and a store script (`read`, `batchAcross`) the server cannot run, refuse boot, named. A replica missing or lagging is neither.
- Boot reads the server's settings as internal module `settings` does: each it takes as declared, the server not showing it, is warned of at every boot as `redis.settings_declared`; one it cannot judge refuses boot.
- `durability` `none`: the operator states the server does not fsync every write, so a crash loses the latest writes, spent assertion and proof ids and lockout records among them; every boot warns `redis.durability_none` naming the durable spaces.
- A refusal or a warning never tells the URL, which may hold a password; a failure is told by its code alone, never its message: an error event as `redis.error` with `code`, and a refused connection in `redis.url`'s reason.
- `replicas`: no replica seen is unavailable, a confirmed read at boot too, so a module reading at boot refuses a restart.
- `none`: the operator states there is no failover, so even confirmed writes are lost by one; a replica seen at runtime is unavailable; every boot warns `redis.replication_none` naming the replicated spaces.
- A timeout, too few replicas, or another server than the one that answered is unavailable, the answer then unknown.
- Internal module `client`: boot warns `redis.plaintext` where the URL is in the clear, deprecated in production without `accept-plaintext`. Production refuses `url` while `DEBUG` covers ioredis. Another floor refuses boot.
- Every script first deletes keys whose expiry is at or before its time, as Redis still holds them then.
- Versions are `server.epoch.n` and never repeat after a restart, a failover, or the end of the key counting them.
- Nothing a connection does ends the process.
- The store clock is Redis's time; values and counts are kept in separate keys, values untouched.
- A scan walks Redis's SCAN over the space's value keys alone, which one server holds; a value at its very expiry may still be listed, and a read then finds none.

## Deployment
- With `rediss`, a certificate for the URL's host, trusted by the platform.
- Redis 7.0 or later, answering as a primary: no cluster, and no proxy splitting keys across nodes (boot runs `batchAcross` over two partitions, and refuses, named, a server that answers it `CROSSSLOT`; a key answered `MOVED`, `ASK` or `CLUSTERDOWN` is refused as a cluster).
- One primary holding every key, whatever is composed, with no setting to loosen it: a scan sees one server's keys, so on a server holding part of them a sweep or a reseal would silently miss records.
- `maxmemory-policy noeviction`, where a composed module keeps a space that must not be evicted.
- `appendonly yes`, `appendfsync always` and `no-appendfsync-on-rewrite no`, where a composed module keeps a durable space, unless `durability` is `none`.
- With `replication` `replicas`: `min-replicas-to-write` and `min-replicas-max-lag` of 1 or more. With `none`: no replica connected.
- `CONFIG GET` allowed, or the settings it would read declared in `server-settings`.
- Allowed: `EVAL`, `PING`, the commands the scripts call (`TIME`, `INFO`, `EXISTS`, `GET`, `HGET`, `HMGET`, `PTTL`, `PEXPIRETIME`, `SET`, `INCR`, `HSET`, `HINCRBY`, `PEXPIRE`, `PEXPIREAT`, `DEL`), `SCAN`, `ROLE` and the keys under the prefix; with `replication`, `SET` of `<prefix>:#confirm`, and with `replicas` `WAIT`.
- The operator's, outside these checks: keeping a detached or lagging replica from promotion, replicas' disk writes, and what a `CONFIG SET` or a failover after boot lets through until a probe answers unready.

## Data
- Keys under the prefix, one hash tag per space and partition, holding values, counts, versions and marks.

## Depends on
- `kernel`, `store`, `tls-options` (`tlsOptions`, `isFloor`; more inside `client`), `url-setting` (inside `client`)

## Vocabulary
- slot: the range of keys one node holds; a partition fits in one.
