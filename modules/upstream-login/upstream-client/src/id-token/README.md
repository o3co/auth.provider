# id-token

Internal module of `upstream-client`: reading an upstream's OpenID Connect id_token for a login.

## Responsibilities
- Checks an id_token against the type's rules and the login's nonce (OpenID Connect Core §3.1.3.7).
- Reads the login from it: the subject, the login time and the profile.
- Completes the login's profile from the upstream's UserInfo answer for the same subject (OpenID Connect Core §5.3.2, `userinfo.ts`).

## Not here
- Checking the JWT's signature and times (`external-jwt`). Which issuer, key set, algorithms and `email_verified` values a type takes (the type). What the login is used for (`federation`).

## Offers
- `idTokenReaderOf` (`external-jwt`, the type's rules, a clock) → a reader: (id_token, the login's nonce, the access token answered beside it if any) → the login and the checked claims, and `withUserinfo` (the UserInfo answer) → the login, its profile completed. `IdTokenRules`, `IdTokenLogin`.

## Invariants
- An id_token is checked by `external-jwt` with the type's key set, algorithms and allowance, expecting its issuer and the client among the audiences. A reason it gives refuses; no key set is unavailable.
- It must also carry a non-empty `sub`, a numeric `iat`, and the login's nonce. Every audience it names is the client: another, trusted by no rule here, refuses. With several, `azp` is the client; with one, a given `azp` is the client too, unless the type takes cross-client identity.
- Its `auth_time`, where given, is a number from 0, and is no later than the clock plus the allowance.
- Given the access token, an `at_hash` it gives is the left half of that token's digest by the signature's algorithm (SHA-2 by size; SHA-512 for Ed25519, SHAKE256 for Ed448; `EdDSA`, whose key's curve is not known here, takes a half of either); one that is not, or not text, refuses. Without one, the id_token is read as before.
- The profile is `email`, `name` and `picture` where they are text; the email is verified only by an `email_verified` value the type names.
- Every refusal is `UpstreamRefused`; unavailable names the type's `what`.

## Depends on
- `external-jwt` (the signature and times), `federation` (the login's words), `kernel` (what is unavailable, the clock)
- A UserInfo answer is taken only as a JSON object of a 200 as `application/json` whose `sub` is exactly the id_token's; any other, a signed or encrypted one among them, refuses, and none of its values is used. Its profile is `email`, `name` and `picture` where they are text that is not empty, the email verified only by the boolean `true`.
- The completed profile takes each claim the id_token's checked claims give, however they give it, from the id_token, and UserInfo's only where they give none; the email goes with the verification of the answer that gave it.
