# client

Internal module of `redis`: the client's options, and what the URL and the environment say of its connection.

## Responsibilities
- Makes the Redis client's options from the section and `tls-options`' floor.
- Tells what of the URL and the environment the package refuses or warns of: a query, a connection in the clear, the client's own debug log.

## Not here
- Connecting, checking the server, the store's commands, and the refusals and log lines themselves: the package's.

## Offers
- `clientOptions` (the section's URL and timeouts, and a floor) → the client's options.
- `queryRefusal` (a URL) → why it is refused, if it is; `inTheClear` (a URL); `clientDebugs` (`DEBUG`'s value).
- `plaintextWarning` (a URL, `accept-plaintext`, the environment) → why boot warns of a URL in the clear, if it does.

## Invariants
- Under `rediss`, TLS is held to `tls-options`' floor (BCP 195) by its `heldToFloor`, and no other TLS option is given: the floor alone. Under `redis`, no TLS options at all, as the client takes up TLS for any it is given.
- A URL with a query, an empty one too, is refused, as the client takes each name of it as an option over the ones given it. The reason names where each option the table holds is written instead, never a value nor another name.
- In the clear: `redis` at a host not loopback by its name (`url-setting`'s `isLoopbackName`), so what the store keeps and the URL's password are readable and changeable on the way. It is warned of at every start: as accepted under `accept-plaintext`, and in production without it, as deprecated.
- `DEBUG` is read as the `debug` library reads it, for `ioredis:redis`, the log that writes the commands sent, AUTH's password among them.
- A command whose reply was lost is never sent again, and a dropped connection fails at once: the client resends, retries and queues nothing.
- `address-family` is passed only when set, so the client resolves either family as before.

## Deprecated
- In production, `redis://` at a host not loopback by its name without `accept-plaintext`: warned at every start, and a later release refuses boot for it. Write `rediss`, or set `accept-plaintext` where the server has no TLS.

## Depends on
- `tls-options` (the floor's type, `heldToFloor`), `url-setting` (`isLoopbackName`), the Redis client (its options' type).
