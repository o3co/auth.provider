# host-entries

## Responsibilities
- How an operator writes a host in configuration (a name, `.name` for it and the names under it, an address, or a `host:port` pair), and whether a host is among such entries.

## Not here
- Whether a destination may be reached, and how (`outbound-policy`); which addresses are special-purpose, private or loopback (`address-reach`); a configured URL and its form (`url-setting`).

## Offers
- `hostEntryOf` (an entry, or taking a port a `host:port` pair) → `HostEntry`: a name (`under` for `.name`) or an address, with its `port` when read as a pair; none where the entry is no host or no pair.
- `hostEntry`: a setting holding one host or `.name` entry, refused as "not a host, or a name led by a dot"; `hostList`: a list of them, none unless set.
- `hostPair`: a setting holding one `host:port` pair, refused as "not a host:port pair".
- `listed` (a host as `normalized` spells it, entries): whether it is among entries read by the operator's entry rule, `hostEntryOf`.
- `withinHosts` (a URL, hosts): whether its host is among hosts in the caller's spelling, each compared normalized; `.name` is read as an entry.
- `normalized` (a host): its one spelling to compare by, or none.
- `pairOf` (a pair): its one spelling, the host normalized and the port as written.

## Invariants
- An entry is read as written: letters (with the marks that write them), digits, hyphens and dots, or a whole address; only case and Unicode are corrected, as the URL parser reads a host (IDNA); a joiner is kept only where its script's rules allow it. An address with no canonical form, such as one with a zone, is none. A pair's host is read so, never `.name`, an IPv6 address in brackets; its port is 1–65535 without a leading zero.
- A character the parser would drop, such as a variation selector, makes no entry.
- Hosts compare lowercase, in punycode, without a trailing dot, in canonical IP form, with IPv4 carried in IPv6 as IPv4; a host with an empty label has no spelling.
- Nothing here resolves a name, reads settings or sends anything.

## Depends on
- `address-reach` (`carriedIPv4`), `zod`.
