# id-jag

Internal module of `jwt-bearer`: the ID-JAG profile's rules (Identity Assertion JWT Authorization Grant), read off a verified assertion and held against the request.

Preview: the ID-JAG profile follows draft-ietf-oauth-identity-assertion-authz-grant-04; a later revision may change it in a minor version.

## Responsibilities
- Reads what a verified ID-JAG names (the client, scope, resources, the DPoP key) and refuses one of no form.
- Tells whether the request may present it: the client it names, the key it names.
- Gives the scope asked and the ceiling the ID-JAG holds an issuance to, and checks again what is about to be issued.

## Not here
- The signature, the issuer, the audience's value, the times and the `jti` (`assertion`, `external-jwt`, the package). How a `typ` compares (`external-jwt`'s `typOf`).
- Narrowing by every ceiling and the client's defaults (`client-allowance`). Proving a key (`dpop`, `sender-binding`). An issuer's conditions (`conditions`).
- When each is asked (the package).

## Offers
- `idJagTyp`: `oauth-id-jag+jwt`.
- `read` (the verified header and claims) → the client id, scope, resources and key thumbprint it names, or why it is refused.
- `admit` (it, the request's client and binding) → admitted, or why not.
- `asked` (it, the scope requested) → the scope asked and the ceiling it holds an issuance to.
- `recheck` (it, the scope and audience about to be issued) → ok, `invalid_scope` or `invalid_target`.

## Invariants
- Pure: no state, no input or output.
- Its verified header's `typ` is the ID-JAG's, as `typOf` reads it (`untrusted signer` otherwise).
- An `aud` list holds one audience (`wrong audience`). A `tenant` or `aud_tenant` is refused (`tenant not taken`).
- `iat` is a number, and `client_id` a string of 1 to 255 characters. An `act` has a string `sub`. A claim of no such form is `missing or malformed claims`, as are those below.
- A `scope` is a non-empty RFC 6749 scope: one signed empty is refused, as it would read as none and let the client's defaults stand in.
- A `resource` is an absolute URI with no fragment (RFC 8707 §2), or a non-empty list of them. A `cnf` names `jkt` alone, a 43-character thumbprint.
- `authorization_details` is a list of objects each with a non-empty `type`. None is served, so they are dropped, and refused where no `scope` says what was allowed (`authorization details are not served`).
- A claim is read as the claims' own alone, never one an object inherits.
- Presented by a confidential client alone (`the profile needs a confidential client`), the one its `client_id` names (`assertion is for another client`). With a `cnf`, the request proves that key by DPoP, a binding whose token type is DPoP, as `delegated` tells one; no other binding or key stands in (`the request does not prove the key the assertion names`). Without one, any binding the request proves, or none.
- The scope asked is the request's where it names one, else the ID-JAG's. Its ceiling holds its scope and resources, each where it names them; what is about to be issued must lie within both.

## Depends on
- `client-allowance` (`parseScope`, a ceiling's form), `external-jwt` (`typOf`), `grants` (the client's and binding's types)
