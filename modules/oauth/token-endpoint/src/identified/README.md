# identified

Internal module of `token-endpoint`: the client of a request naming none, as a grant identifies it.

## Responsibilities
- Tells which grant, if any, identifies the client of a request, and holds the client it identifies to one with no credentials.

## Not here
- Whether a request carries credentials (`clients`' `bare`). What a grant checks to identify (the grant's own `identify`). The checks before and after it, and the answers and records (`route`).

## Offers
- `identifierOf` (`clients`, the grants by type, the request, its grant type) → the grant that identifies its client, or none: only for a request `clients` finds `bare` (never authenticated, refused as `no_credentials` alone), whose one `grant_type` names a grant with `identify`.
- `identifiedClient` (`clients`, the grant, its parameters' reader) → the client with what the grant identified, or the grant's refusal as it gives it.

## Invariants
- A client a grant identifies is one registered with no credentials (method `none`, public alone); any other, a source's included, is unavailable, as it would skip its own authentication.

## Depends on
- `clients`, `grants`, `http` (the request type), `kernel` (unavailable)
