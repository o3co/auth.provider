# request-source

## Responsibilities
- Decides a request's source (address, scheme, whether it was determined) from the direct peer and the headers a trusted proxy sets.

## Not here
- Reading the client's certificate a trusted proxy forwards (`client-certificate`).
- Where the settings live (`http`'s section takes `sourceSettings`).

## Offers
- `Source`: the address, the scheme, whether it was determined, and the client's certificate as `client-certificate` reads it.
- `sourceSettings`: a schema part with `trusted-proxies` and `proxy-hops`, its keys in the settings list.
- `proxiesOf`: those settings → the trusted proxies.
- `addressList`: a schema for a setting holding IP addresses or CIDR blocks, as `trusted-proxies` takes them, a block of every address included; `addressesOf`: such entries → whether an address is among them (none for one that is not an address).
- `sourceOf`: the trusted proxies, the direct peer and the headers → `Source`.
- `determinedSource`: a request → its source address, only when it was determined.
- `ignoredForwarding`: whether to warn now of `X-Forwarded-For` from a peer not trusted.

## Invariants
- A trusted proxy covering every address of a family (`/0` however written, or every IPv4 address mapped into IPv6, as `::ffff:0:0/96` or `::/1`, since a mapped peer is checked as IPv4) refuses boot at its entry, and entries that together cover every address of a family (their blocks joined as intervals, an IPv6 block's share of the mapped addresses counting as IPv4) refuse it at the list: every client would be a proxy, so every source would be undetermined.
- A trusted proxy is an IP address without a zone, or a CIDR block with one decimal prefix length without a leading zero.
- No proxy is trusted by default.
- `proxy-hops` is a whole number from 1 to 10, and 1 by default.
- The source follows `X-Forwarded-For`, with or without ports, only when the direct peer is a trusted proxy.
- `X-Forwarded-For` from another peer is ignored.
- Ignored `X-Forwarded-For` is logged at most once a minute.
- The source follows at most `proxy-hops` trusted proxies.
- The source stops at a forwarded value that is not an address.
- If the source ends on a trusted proxy, it is undetermined.
- `Forwarded` is not read, so behind a proxy that sends only that, the source is undetermined.
- The scheme takes only a single `X-Forwarded-Proto` value from a trusted peer; otherwise it is `http`.
- A client's certificate is taken only from a trusted peer.
- The source address is in canonical form: lower case, zeros compressed, IPv4-mapped IPv6 as IPv4, no zone.
- The source and the trusted proxies are frozen.

## Depends on
- `kernel` (the clock of the warning), `client-certificate`, `address-reach` (an address as a connection reaches it), `zod`.

## Vocabulary
- source: where a request comes from, as the trusted proxies decide.
