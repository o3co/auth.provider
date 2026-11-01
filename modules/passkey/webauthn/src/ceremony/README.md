# ceremony

Internal module of `webauthn`: the WebAuthn ceremonies, over a pinned version of `@simplewebauthn/server`.

## Responsibilities
- Makes creation and request options, and verifies attestations and assertions.

## Not here
- Where challenges and credentials are kept, and which subject they belong to (the package).

## Offers
- `ceremoniesFor` (relying party, randomness, clock) → the package's `Ceremonies`. No library type crosses it.
- `algorithmNames`: the algorithms a credential may use (`EdDSA`, `ES256`, `RS256`), by the names `keys` gives them; the package's `algorithms` setting takes from them, all of them by default.
- `challengeOf` (response) → the challenge the client data names, read by the library's decoder, the one that verifies it.

## Invariants
- A challenge is 32 random bytes. Options list the relying party's algorithms in its order, as COSE names them, ask for no attestation, and require a discoverable credential unless the caller asks for one that need not be.
- A challenge ends the relying party's timeout after it was made.
- Before the library runs: an end given that the clock has reached is `challenge`; client data the library cannot read is `malformed`; a challenge other than the one given is `challenge`; a reported top origin that is not listed, or not in a frame, is `top-origin`, and so is any frame when none is listed.
- The library's refusals map by how its messages start; any other is `malformed`. The library never judges the count (it is handed 0).
- After the signature: a handle carried must be the credential's (none carried passes only where the kept challenge carries the request's `.listed` mark), the backup eligibility must be the credential's, and the count must go up (0 after 0 passes).
- An assertion by a credential other than the one given is `malformed`; one by a key whose COSE algorithm is not the relying party's, or cannot be read, is `algorithm`, which the library does not check at assertion.

## Depends on
- `@simplewebauthn/server`; the package's contract
