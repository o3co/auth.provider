# redis

## Responsibilities
- Implements the `store` contract with Redis, with one script per shape of basic operation and none per feature.
- Maps each partition to a hash tag, so a batch and a consistent read run in one slot.
- Checks, once at boot, that the Redis configuration gives the declared spaces their guarantees.
- Confirms an answer before giving it, for spaces that need replicated or confirmed reads.

## Not here
- Space names and meanings, and the shapes of values. Which feature uses it.

## Offers
- Composition definition only: the `store` contract's implementation.
- The probe `redis` at `kernel`'s `probes`, which PINGs both connections.
- Operator section:
  - `url` (`redis` or `rediss`), `prefix` (lower-case letters, digits and `-`; default `store`).
  - `connect-timeout` (default `2s`), `command-timeout` (default `1s`), `replication-timeout` (default `1s`); times written with their unit, a bare number refused.
  - `replication`: `replicas` or `none`, required when a space needs replicated or confirmed reads.
  - `durability`: `none`, or unset.
  - `server-settings`: the server's `maxmemory-policy`, `appendonly`, `appendfsync`, `min-replicas-to-write` and `min-replicas-max-lag`, as the operator declares them.

## Invariants
- Boot is refused on Redis below 7.0, a server that is no primary, or a cluster, proxies splitting keys across nodes included.
- Boot is refused on a no eviction space without `noeviction`, and on a durable space without `appendonly yes` and `appendfsync always` unless `durability` is `none`.
- A setting is read by `CONFIG GET`. Where the server refuses it, the declared value is taken, a needed one left undeclared refusing boot, and every boot warns `redis.settings_declared` with the names taken so; where it answers, a declared value that differs refuses boot.
- `durability` `none`: the operator states the server does not fsync every write, so a crash loses the latest writes, spent assertion and proof ids and lockout records among them.
- Boot is refused on a space needing replicated or confirmed reads without `replication`.
- A refusal or a warning never tells the URL, which may hold a password; an error event is logged by its name alone.
- `replicas`: at boot, `min-replicas-to-write` and `min-replicas-max-lag` are 1 or more; at runtime, no replica seen is unavailable.
- `none`: the operator states there is no failover, so even confirmed writes are lost by one; a replica seen, at boot or at runtime, is refused or unavailable.
- A confirmation writes the confirmation key on a connection of its own, then waits until every replica ROLE shows has it.
- A timeout, too few replicas, or another server than the one that answered is unavailable, the answer then unknown.
- A confirmation asked during a round rides on the next round.
- Every script first deletes keys and set members whose expiry is at or before its time, as Redis still holds them then.
- Versions are `server.epoch.n` and never repeat after a restart, a failover, or the end of the key counting them.
- A command whose reply was lost is never sent again; a dropped connection fails at once, and nothing ends the process.
- The store clock is Redis's time; values, counts and sets are kept in separate keys, values untouched.
- A scan walks Redis's SCAN over the space's value keys alone, which one server holds (clusters are refused); a value at its very expiry may still be listed, and a read then finds none. A failover or restart during a walk loses its cursor's place, so a key may not come; a later walk lists it.
- Outside the guarantees, the operator's: keeping a detached or lagging replica from promotion, replicas' disk writes, `CONFIG SET` after boot.

## Data
- Keys under the prefix, one hash tag per space and partition, holding values, counts, sets, versions and marks.

## Depends on
- `kernel`, `store`

## Vocabulary
- slot: the range of keys one node holds; a partition fits in one.
- confirmation key: one key per prefix, written in a confirmation round, apart from idempotency marks.
- round: one write to the confirmation key and one WAIT.
