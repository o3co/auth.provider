# drop

Internal module of `rate-limit`: its eraser, dropping a subject's lockout keys.

## Responsibilities
- Drops a subject's key under each lockout name composed through `subjectLockouts`, for account erasure.

## Not here
- What a dropped key answers: the lockout counter, through the one parse. Which names lock by subject: the modules contributing them. When erasure runs: `account-erasure`.

## Offers
- `lockoutEraser(states, composed)` → the eraser `rate-limit`: `online` (one subject), `window` (each subject, with no walk), `migrate` (nothing to put in an index: `[]`). `erasable`, as it writes through the composition's own store, and follows no other eraser.

## Invariants
- Each key is written `dropped` with expiry `never`, whatever it held: absent, expired, a state, dropped already or another shape, so a write that lands later meets it and writes nothing.
- One report, `forgotten` for `rate-limit.lockouts`: `removed` counts the keys that held a state in this run; absent, expired, dropped and other values count 0, so a run after a partial one counts only what it dropped.
- Names go in sorted order; a run cut short throws the signal's reason, before its first key or between keys, with no report, and the keys already dropped stay. Run again, it finishes. `migrate` throws it too.
- It covers keys under the names composed at erasure: a name composed later starts empty for a subject already erased.
- In a fleet of mixed versions a node from before `dropped` was read fails closed on one: a 0.20 node throws Unavailable, reading it as a state of another shape; v0.19.1 throws a TypeError.

## Depends on
- `erasure-extensions` (the eraser, `forgottenIn`)
