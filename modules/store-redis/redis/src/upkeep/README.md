# upkeep

Internal module of `redis`: `store`'s upkeep on Redis, the control record and the ledger of spaces.

## Responsibilities
- Offers `storeControl` and `storeUpkeep` as `store`'s upkeep contract holds them, on the server the store runs on.

## Not here
- Running a script, the store's keys and the epoch the store's changes carry: the package's, which hands them in. What `honours` reads of the server: the package's boot checks, handed in.

## Offers
- `redisUpkeepWith` (the script runner, the confirmations, the keys, the declared spaces, the epoch taken, randomness, the check of the guarantees): the control read, the upkeep, `start` and `recheck`.

## Invariants
- The control record is a hash at `<prefix>:{#control}` (epoch, maintenance key, the spaces required, the marks); the ledger, one JSON map at `<prefix>:{#ledger}` of each space's fields, now `subjectDataEver`. Neither is a key of any space.
- Every script that changes data, the store's and these, first checks the record's epoch against the one the process took, before deleting what expired and before any replay: under another epoch it changes nothing, and is unavailable.
- A change here is confirmed where replication is declared; so is the control read.
- `start` takes the record's epoch, then adds each declared space to the ledger before the process's first other change. Neither waits for replicas, so a start with none yet still boots; any later confirmed write confirms the ledger's entry.
- `recheck`, for the probe: the record's epoch moved from the one taken is a problem; a declared space missing from the ledger, as a failover can lose that entry, is added again.
- A new epoch is 16 random bytes from the kernel's randomness, so data restored from an old backup never holds a later epoch.
- `require` and `retire` hold under the maintenance key alone, answering `not-in-maintenance` otherwise; `retire` refuses a space the process declares.
- `sweep` runs SCAN over the space's value keys within a script, deletes each expired key it meets, answers the page's run id as its server, and is confirmed for a replicated space.

## Depends on
- `kernel` (unavailable, randomness), `store` (the upkeep contract, `checkedUpkeep`)
