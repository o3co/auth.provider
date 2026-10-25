# ask

Internal module of `conformance`: Redis at hand, for the topology and the scenes that check a node themselves.

## Responsibilities
- Sends a command, or several in one write, on a connection of its own and answers the replies.

## Offers
- `ask` one command, `askAll` several in one write (their replies in order), each within a time given; `microsOf` a `TIME` reply, as microseconds on Redis's clock.

## Invariants
- A connection that closes, errs or runs out of time before every reply has come is refused, at once.
- Several commands in one write reach Redis in that order, on one connection: a `WAIT` among them counts the writes before it.

## Depends on
- The relay's RESP reader and its upstream.
