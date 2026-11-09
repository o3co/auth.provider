# settings

Internal module of `redis`: what the server's settings give the declared spaces, read as the server shows them or as the operator declares them.

## Responsibilities
- Reads the server's settings and role, and tells which guarantees of the declared spaces they fail to give.

## Not here
- When they are checked (boot, the probe), and the refusals and warnings: the package's.

## Offers
- `serverSettings` (the client, the declared settings): `read` one setting, `rest` to compare every declared one left unread, the `problems` found and the settings `used` as declared.
- `roleOf`, `replicasOf`: the server's `ROLE`, and the replicas it lists.
- `evictionProblems`, `replicationProblems`, `durabilityProblems` (the settings, the declared spaces, what the operator stated): what the settings fail to give those spaces.
- `refusedForGood` (an error): whether the server refuses a command for good.

## Invariants
- A setting is read by `CONFIG GET`. Where the server refuses it for good (`NOPERM`, or an unknown command or subcommand) or answers it empty, not showing it, the declared value is taken, and a needed one left undeclared is a problem; where it answers, a declared value that differs is a problem; any other error (`BUSY`, say) is thrown.
- Durable needs `appendonly yes`, `appendfsync always` and `no-appendfsync-on-rewrite no`, each read, so a problem names every setting left undeclared at once; `durability` `none` waives it.
- No eviction needs `maxmemory-policy noeviction`. Replicated or confirmed reads need `replication` stated: with `replicas`, `min-replicas-to-write` and `min-replicas-max-lag` of 1 or more; with `none`, no replica connected.

## Depends on
- `store` (spaces); `ioredis`
