# lockout

Internal module of `rate-limit`: the lockout counter, over the states one store space keeps.

## Responsibilities
- Holds keys after failures by a caller's policy, reserves and hands back attempts, and releases holds, each as one write of a key's whole state.

## Not here
- The policy's numbers and the names: the caller's. Dropping a subject's keys: the internal module `drop`, writing the value this module reads as dropped.

## Offers
- `lockoutCounter` (the states) → `lockouts`; `storedStates` (the store) and the space `rate-limit.lockouts`; `parsed`, the one reading of a stored value (absent, dropped, a state, another shape), and `dropped`, the value a dropped key holds.

## Invariants
- Lockout times are the store's: a hold ends at its time; a fixed hold ends only by release, and a dropped key's never.
- Handing back the attempt that fixed a hold lifts it; handing back any other keeps it.
- Attempt times are unique within a key and never go back, so a reservation names one attempt.
- A success ends the run but keeps failures in the budget; the budget's window is the caller's.
- A lockout that keeps losing races is unavailable; a reservation it cannot hand back stays a failure, the safe side. A stored lockout state of another shape is unavailable, never read as no hold.
- Every entry point, for input it takes, reads the key through the one parse, inside its read or inside the decision `mutate` runs: absent is no hold, a state is judged, and a dropped key or another shape is unavailable, a throw that writes nothing. A release's terms it refuses are refused before the read, writing nothing.

## Data
- Lockouts: one state per name and key, rewritten whole, under a one-way hash of both; no eviction, durable, replicated, and confirmed reads, as a release is read by another request; declared `pseudonymous`, erased by `rate-limit`. A state expires unless its hold is fixed or it counted a release. A dropped key holds `{ "dropped": 1 }` and never expires.

## Depends on
- `store` (`mutate`)
