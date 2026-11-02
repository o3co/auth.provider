# address-reach

## Responsibilities
- Owns what an IP address reaches by its kind: special-purpose, private, loopback, judged without settings and without resolving a name.

## Not here
- Which addresses a request may reach, and for whom: `outbound-policy`. Whether a host's name is a loopback one: `url-setting`.

## Offers
- `isSpecialAddress`: whether an IP address is special-purpose: IANA's blocks not globally reachable, multicast, IPv6 outside global unicast, and Azure's platform address (168.63.129.16), public but the host node's.
- `isPrivateAddress`: whether an IP address is private, as a connection reaches it: 10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7, but the cloud metadata and credential addresses in them (100.100.100.200, fd00:ec2::254, fd00:ec2::23, fd20:ce::254, fd00:a9fe:a9fe::1, fd00:42::42, fd00:c1::a9fe:a9fe).
- `isLoopbackAddress`: whether an IP address, however written, reaches loopback (127/8, `::1`, or 127/8 mapped into IPv6; never a form that carries it unmapped, nor a name), the one judgement of a loopback address every module uses; the literal is judged by url-setting's `isLoopbackName`.
- `carriedIPv4`: the IPv4 address an IPv6 address in canonical form carries, mapped, translated or compatible.
- `reachedAddress`: an IP address as a connection reaches it, unbracketed, IPv6 compressed in lower case, IPv4 mapped into IPv6 as that IPv4 address; the form `isPrivateAddress` judges.

## Invariants
- A connection reaches IPv4 mapped into IPv6 (`::ffff:a.b.c.d`) as its IPv4 address, and no other IPv6 form that carries one: a compatible or translated form reaches neither 127/8 nor a private network.
- Nothing here reads settings, resolves a name or sends anything.

## Depends on
- `url-setting` (`isLoopbackName`)
