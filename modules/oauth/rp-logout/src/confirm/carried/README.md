# carried

Internal module of `confirm`: the request `ending` carries on in the browser's URL, a logout it checked that closes nothing by itself.

## Responsibilities
- Signs and checks a carried request, and holds the return it carries to its client's registration as it is when used.

## Not here
- Checking the hint and the return the first time (`ending`). Which session closes (`ending`, `confirm`). What the client registers (`registration`). Signing (`keys`).

## Offers
- `carriedParam` (`request`), `CarriedRequest` (the hint's session, its client, the return and `state`), `Carried` (a client, return and time a token carries).
- `carriedWith` (keys, client records, the issuer's and the logout's URLs, the clock) → `carry` (a carried request → its token), `read` (a token → the request and its time / none), `carried` (a token → the request / none), `current` (a client and its return → the return where the client, as its record is now, still registers it / none).
- `carriedClaims` and `carriedFrom`, the client, return and `state` a token's claims carry, both ways; `heldClaims`, a token's claims where the provider signed it as the kind asked, for the audience asked, and it has not expired.

## Invariants
- A carried request is signed by `keys` as `logout-request+jwt`, with `iss` the issuer, `aud` the logout endpoint, `exp` 300 seconds on, `sid`, and the client, return and `state` where there are. It holds no subject, so none goes into a URL.
- `heldClaims` holds each claim itself, as `keys` checks the signature, the type and the key alone: the issuer, the audience, and a finite `exp` still to come. A carried request without a `sid` is none.
- `current` keeps a return only where the client is found now and registers it exactly (`registration`'s `returnsTo`); a client gone, one no longer registering it, or a return with no client, leaves none.

## Depends on
- `clients` (the client's record now), `keys`; the package's contract and `registration`
