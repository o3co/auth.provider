# ending

Internal module of `http`: tells the observers of `requestEnds` each request's end.

## Responsibilities
- Tells each request's end, once, answered or closed.

## Not here
- What an observer does with an end (its owner's).

## Offers
- `ending`: a request and its answer → the observers told at its end, and the function naming the route it reached.

## Invariants
- An end names the method sent.
- An end names the declared path of the route reached (none when none).
- An end names the status written, or `closed` when the client closed first.
- An end names the milliseconds taken (never negative).
- Observers are told after the request, asynchronously.
- What an observer throws or rejects is dropped.

## Depends on
- `http` (its contract), `kernel` (the clock).
