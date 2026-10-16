# fetching

Internal module of `clients-cimd`: how often a document is fetched, and how long its answer is kept.

## Responsibilities
- Keeps found values, remembers refusals for a while, joins fetches of the same id, and bounds the fetches running at once.

## Not here
- What is fetched and how an answer is judged (`document`).

## Offers
- `fetchingOver` (a loader, the limits, the clock) → `find(id)` → the value, or none.
- A loader answers found (with the answer's own max age, if any), refused, or failed.

## Invariants
- A found value is kept for the shorter of its max age and `cacheMs`; past it, it is never used, even when fetching again fails.
- A refusal is remembered for `refusedMs`; a failure (or a loader that rejects) is not.
- Both times count from the start of the fetch; a value that comes after its time is given to the finds waiting for it, and not kept.
- Each map holds at most `entries` ids, dropping the one set longest ago.
- One fetch runs per id; a fetch past `concurrent` running ones is none at once, without waiting.

## Data
- Kept values, refusals and running fetches, in this process only.

## Depends on
- `kernel` (the clock)
