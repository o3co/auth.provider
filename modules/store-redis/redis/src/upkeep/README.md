# upkeep

Internal module of `redis`: `store`'s upkeep on Redis, the control record and the ledger of spaces.

## Responsibilities
- Offers `storeControl` and `storeUpkeep` as `store`'s upkeep contract holds them, on the server the store runs on.

## Not here
- Running a script, the store's keys and the epoch the store's changes carry: the package's, which hands them in. What `honours` reads of the server: the package's boot checks, handed in.

## Offers
- `redisUpkeepWith` (the script runner, the confirmations, the keys, the declared spaces, the epoch taken, randomness, the check of the guarantees): the control read, the upkeep, `start`, `recheck`, and `ready`, which the store's changes await.

## Invariants
- The control record is a hash at `<prefix>:{#control}` (epoch, maintenance key, the spaces required, the marks); the ledger, one JSON map at `<prefix>:{#ledger}` of each space's fields, now `subjectDataEver`. Neither is a key of any space.
- Every script that changes data, the store's and these, first checks the record's epoch against the one the process took, before deleting what expired and before any replay: under another epoch it changes nothing, and is unavailable.
- A change here is confirmed where replication is declared; so is the control read.
- `start` takes the record's epoch and tries to add each declared space to the ledger; where writes are refused, as while too few replicas are good, it boots all the same. Until the spaces are added, the process changes nothing: each change, the store's and these, first tries once more, and is unavailable where that fails.
- The ledger's entry waits for no replica: replication keeps order, so data that outlives a failover was written after its entry, which outlives it too; any later confirmed write confirms it.
- `recheck`, for the probe: the record's epoch moved from the one taken, or the declared spaces not yet added, tried again, is a problem; a space lost from the ledger, as a failover can lose that entry, is added again.
- A new epoch is 16 random bytes from the kernel's randomness, so data restored from an old backup never holds a later epoch.
- `require` and `retire` hold under the maintenance key alone, answering `not-in-maintenance` otherwise; `retire` refuses a space the process declares.
- `sweep` runs SCAN over the space's value keys within a script, deletes each expired key it meets, lists none already gone, answers the page's run id as its server, and is confirmed for a replicated space.

## Depends on
- `kernel` (unavailable, randomness), `store` (the upkeep contract, `checkedUpkeep`)
