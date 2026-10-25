# store-wire

Internal module of `conformance`: the Redis adapter's wire, read in one place, so a scene names a store write in a store's words and the relay matches it.

## Responsibilities
- Turns a space, an operation, a key's name and what a write puts into a relay match, and reads what a call and its answer tell.
- Kept here for now: the wire belongs to the Redis adapter. Once the adapter offers a description of its own wire for tests, this goes, and an area passes the owner's matches to the relay; this package still imports no adapter.

## Offers
- `storeWrite` (a write to a space's key, by operation, name, partition and what it puts; succeeded where its answer's kind wrote) and `storeRead` (a read of a space's key; succeeded unless an error).
- `keysOf` (the keys a call reaches, by space, partition and name), `writtenValues` (what a write puts, by key), `runIdOf` (the server an answer came from), `sameMark` (whether a call is a resend of another, by its mark).
- `roleOf` (a connection's role: a confirmation's `WAIT` or its key's `SET` is the confirming one's, a script the operations one's), `confirmation` (a confirmation's `WAIT`, succeeded where as many replicas as the scene has acknowledged), `isNoReplicas` and `isOutOfMemory` (a write's refusals).

## Invariants
- An operation is told by the shape of its call (its keys and arguments), never by the script's text.
- A write took effect only where its answer's kind is `written`, `removed`, `taken`, `committed` or `counted`, as the adapter counts them.
- A call without a mark is the resend of nothing.
- Its tests hold copies of the wire as it is now; each scene's control checks the real one, so a change of the wire fails a scene rather than passing it.

## Depends on
- The relay's match, command and answer.
