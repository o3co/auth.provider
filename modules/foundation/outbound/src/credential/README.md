# credential

Internal module of `outbound`: how a request's credential is sent, and the headers a caller may not write.

## Responsibilities
- Turns a request into the one sent: its credential as the `Authorization` header, or as the header its `credentialHeader` names, under one set of rules, the value never told.

## Not here
- Where a credential may go (more than one origin, neither https nor a named plain pair): `outbound-policy`'s credential policy, which outbound answers at boot.
- The headers outbound sets alone and how the message is framed: the package's transport, whose names this module reads.

## Offers
- `sentRequest` (request, signed) → the request as sent, for plain or signed material.
- `credentialHeaderRefusal` (name), offered on the package's contract: why a credential may not go as that header, in the words a request naming it is refused with, or none; for a caller refusing its own setting at boot.

## Invariants
- A credential goes as `Authorization`, or as the header `credentialHeader` names, lowercased, its value as given; a caller writing either header itself, in any case, is a TypeError.
- A named header is a header token, never one outbound sets alone (its own, the host, the framing) nor `content-type`, `cookie` or `proxy-authorization`, in any case; `authorization` is the default named; a name without a credential is a TypeError.
- Signed material never carries a credential (`DestinationRefused` `credential`); a credential is one printable line.
- A TypeError or refusal tells no header's value.

## Depends on
- The package's request type and transport (the headers it sets alone); `outbound-policy` (`DestinationRefused`).
