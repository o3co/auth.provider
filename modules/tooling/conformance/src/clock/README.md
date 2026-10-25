# clock

Internal module of `conformance`: a process on a moved clock, by libfaketime.

## Responsibilities
- Builds the image a process on a moved clock runs, and gives the environment that moves its clock.

## Offers
- `clockImage` (an Alpine image given, with the pinned libfaketime added), `faketimeEnv` (the preload and the offset, such as `+2h`), `libfaketime` (the package by version).

## Invariants
- The image is built once, its tag a hash of how it is built, so it is the same wherever it runs.
- The wall clock moves by the offset from the process's start; its monotonic clock is left alone.

## Depends on
- Docker.
