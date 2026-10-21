# address-reach

## Responsibilities
- Owns what an IP address reaches by its kind: special-purpose, private, loopback, judged without settings and without resolving a name.

## Not here
- Which addresses a request may reach, and for whom: `outbound-policy`. Whether a host's name is a loopback one: `url-setting`.

## Offers
- `isSpecialAddress`: whether an IP address is special-purpose: IANA's blocks not globally reachable, multicast, and IPv6 outside global unicast.
- `isPrivateAddress`: whether an IP address is private, as a connection reaches it: 10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7, but the cloud metadata addresses in them (100.100.100.200, fd00:ec2::254, fd20:ce::254).
- `isLoopbackAddress`: whether an IP address, however written, reaches loopback (127/8, `::1`, or 127/8 mapped into IPv6; never a form that carries it unmapped, nor a name), the one judgement of a loopback address every module uses; the literal is judged by url-setting's `isLoopbackName`.
- `carriedIPv4`: the IPv4 address an IPv6 address in canonical form carries, mapped, translated or compatible.

## Invariants
- A connection reaches IPv4 mapped into IPv6 (`::ffff:a.b.c.d`) as its IPv4 address, and no other IPv6 form that carries one: a compatible or translated form reaches neither 127/8 nor a private network.
- Nothing here reads settings, resolves a name or sends anything.

## Depends on
- `url-setting` (`isLoopbackName`)
