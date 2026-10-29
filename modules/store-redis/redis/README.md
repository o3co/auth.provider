# redis

## Responsibilities
- Implements the `store` contract with Redis, with one script per shape of basic operation and none per feature.
- Maps each partition to a hash tag, so a batch and a consistent read run in one slot. A batch across partitions runs in one script on the one server, over the slots of every partition it touches; it is what keeps this adapter off a cluster.
- Checks, once at boot, that the Redis configuration gives the declared spaces their guarantees.
- Confirms an answer before giving it, for spaces that need replicated or confirmed reads.

## Not here
- Space names and meanings, and the shapes of values. Which feature uses it.

## Offers
- Composition definition only: the `store` contract's implementation.
- The probe `redis` at `kernel`'s `probes`, which PINGs both connections and checks again what boot checked of the server, logging `redis.settings_unmet` with what no longer holds when that changes.
- Operator section:
  - `url` (`redis` or `rediss`; no query: boot names the setting for each option), `address-family` (`ipv4` or `ipv6`; either when unset), `prefix` (lower-case letters, digits and `-`; default `store`).
  - `connect-timeout` (default `2s`), `command-timeout` (default `1s`), `replication-timeout` (default `1s`); times written with their unit, a bare number refused.
  - `replication`: `replicas` or `none`, required when a space needs replicated or confirmed reads.
  - `durability`: `none`, or unset.
  - `server-settings`: the server's `maxmemory-policy`, `appendonly`, `appendfsync`, `min-replicas-to-write` and `min-replicas-max-lag`, as the operator declares them.

## Invariants
- Connects to Redis itself, through its client, apart from `outbound`, which carries HTTP alone (`network`: `redis`).
- TLS holds to BCP 195 (RFC 9325) alone: under `rediss`, `tls-options`' floor's `minVersion` and `ciphers`, copied last; under `redis`, no TLS options, as the client takes up TLS for any. A floor not `tls-options`' own refuses boot.
- Boot is refused, naming what is unmet, when the server is not what Deployment states.
- Boot sends once every command the store sends, a script's on keys of the store's own (`<prefix>:{#check}:…`) it then removes, unless the server refuses that too; one the server refuses for good (`NOPERM`, or unknown or renamed), or keys it refuses the user, refuse boot, named. The probe sends them again, answering unready and warning `redis.settings_unmet` with the name. A write refused for want of replicas leaves a command unjudged, never refused.
- Boot then runs once what a confirmation would and a store script does: with `replication`, the confirming connection reaching another server than the operations (their run ids differ, and the operations' did not change meanwhile, as in a failover), and a store script (`read`, `batchAcross`) the server cannot run, refuse boot, named; the probe runs both again, answering unready. A replica missing or lagging is neither.
- A setting is read by `CONFIG GET`. Where the server refuses it for good (`NOPERM`, or an unknown command or subcommand), the declared value is taken, a needed one left undeclared refusing boot, and every boot warns `redis.settings_declared` with the names taken so; where it answers, a declared value that differs refuses boot; any other error (`BUSY`, say) refuses boot.
- `durability` `none`: the operator states the server does not fsync every write, so a crash loses the latest writes, spent assertion and proof ids and lockout records among them; every boot warns `redis.durability_none` naming the durable spaces.
- Boot is refused on a space needing replicated or confirmed reads without `replication`.
- A refusal or a warning never tells the URL, which may hold a password; an error event is logged by its name alone.
- `replicas`: at runtime, no replica seen is unavailable.
- `none`: the operator states there is no failover, so even confirmed writes are lost by one; a replica seen at runtime is unavailable.
- A timeout, too few replicas, or another server than the one that answered is unavailable, the answer then unknown.
- Internal module `round` (the confirmation round).
- Every script first deletes keys whose expiry is at or before its time, as Redis still holds them then.
- Versions are `server.epoch.n` and never repeat after a restart, a failover, or the end of the key counting them.
- A command whose reply was lost is never sent again; a dropped connection fails at once, and nothing ends the process.
- The store clock is Redis's time; values and counts are kept in separate keys, values untouched.
- A scan walks Redis's SCAN over the space's value keys alone, which one server holds (clusters are refused); a value at its very expiry may still be listed, and a read then finds none. A failover or restart during a walk loses its cursor's place, so a key may not come; a later walk lists it.

## Deployment
- With `rediss`, a certificate valid for the URL's host, trusted by the platform, at what `tls-options`' floor takes.
- Redis 7.0 or later, answering as a primary: no cluster, and no proxy splitting keys across nodes (boot runs `batchAcross` over two partitions, and refuses, named, a server that answers it `CROSSSLOT`).
- `maxmemory-policy noeviction`, where a composed module keeps a space that must not be evicted.
- `appendonly yes` and `appendfsync always`, where a composed module keeps a durable space, unless `durability` is `none`.
- With `replication` `replicas`: `min-replicas-to-write` and `min-replicas-max-lag` of 1 or more. With `none`: no replica connected.
- `CONFIG GET` allowed, or the settings it would read declared in `server-settings`.
- Allowed: `EVAL`, the commands the scripts call (`TIME`, `INFO`, `EXISTS`, `GET`, `HGET`, `HMGET`, `PTTL`, `PEXPIRETIME`, `SET`, `INCR`, `HSET`, `HINCRBY`, `PEXPIRE`, `PEXPIREAT`, `DEL`), `SCAN`, `ROLE` and the keys under the prefix; with `replication`, `SET` of `<prefix>:#confirm`, and with `replicas` `WAIT`.
- The operator's, outside these checks: keeping a detached or lagging replica from promotion, replicas' disk writes, and what a `CONFIG SET` or a failover after boot lets through until the next probe answers unready.

## Data
- Keys under the prefix, one hash tag per space and partition, holding values, counts, versions and marks.

## Depends on
- `kernel`, `store`, `tls-options` (`tlsOptions`, `isFloor`)

## Vocabulary
- slot: the range of keys one node holds; a partition fits in one.
