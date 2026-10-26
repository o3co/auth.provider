# clock

Internal module of `conformance`: a process on a moved clock, by libfaketime.

## Responsibilities
- Builds the image a process on a moved clock runs, and gives the environment that moves its clock: a Redis node's (Alpine) and an app's (Node on glibc Linux, where alone libfaketime moves Node's clock).

## Offers
- `clockImage` (an Alpine image given, with the pinned libfaketime added), `faketimeEnv` (the preload and the offset, such as `+2h`), `libfaketime` (the package by version).
- For an app: `appClockImage` (Node on Debian, with the pinned libfaketime added), `appLibfaketimeIn` (where the thread-safe library sits in it), `hostLibfaketime` (the library on this host: `CONFORMANCE_FAKETIME_LIB`, else glibc Linux's own, else none), `appClockEnv` (the preload of the thread-safe library, the offset, the monotonic clock left alone).

## Invariants
- The image is built once, its tag a hash of how it is built, so it is the same wherever it runs.
- The wall clock moves by the offset from the process's start; its monotonic clock is left alone.
- An app's clock moves only by the thread-safe library on glibc: on musl, or by the other library, Node's clock stays where it is.

## Depends on
- Docker.
