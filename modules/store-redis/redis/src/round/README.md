# round

Internal module of `redis`: the confirmation round.

## Responsibilities
- Confirms that every replica has what the primary did before an answer, in rounds on a connection of its own.

## Not here
- Which spaces need a confirmation, and whether the answer came from the server confirmed on: the package's.

## Offers
- `confirmationRounds` (the confirming connection; the prefix, the replication timeout and the replication the operator declared) → a confirmation, answering the run id of the server it confirmed on, or unavailable.
- `sharedRounds`: rounds shared by the calls that ask while one runs.

## Invariants
- A confirmation writes the confirmation key on a connection of its own, then waits until every replica ROLE shows has it.
- A confirmation asked during a round rides on the next round.

## Depends on
- `kernel` (unavailable), the Redis client.

## Vocabulary
- confirmation key: one key per prefix, written in a confirmation round, apart from idempotency marks.
- round: one write to the confirmation key and one WAIT.
