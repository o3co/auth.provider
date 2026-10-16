# id-token

Internal module of `upstream-client`: reading an upstream's OpenID Connect id_token for a login.

## Responsibilities
- Checks an id_token against the type's rules and the login's nonce (OpenID Connect Core §3.1.3.7).
- Reads the login from it: the subject, the login time and the profile.

## Not here
- Checking the JWT's signature and times (`external-jwt`). Which issuer, key set, algorithms and `email_verified` values a type takes (the type). What the login is used for (`federation`).

## Offers
- `idTokenReaderOf` (`external-jwt`, the type's rules, a clock) → a reader: (id_token, the login's nonce) → the login and the checked claims. `IdTokenRules`, `IdTokenLogin`.

## Invariants
- An id_token is checked by `external-jwt` with the type's key set, algorithms and allowance, expecting its issuer and the client among the audiences. A reason it gives refuses; no key set is unavailable.
- It must also carry a non-empty `sub`, a numeric `iat`, and the login's nonce. With several audiences, `azp` is the client; with one, a given `azp` is the client too, unless the type takes cross-client identity.
- Its `auth_time`, where given, is a number from 0, and is no later than the clock plus the allowance.
- The profile is `email`, `name` and `picture` where they are text; the email is verified only by an `email_verified` value the type names.
- Every refusal is `UpstreamRefused`; unavailable names the type's `what`.

## Depends on
- `external-jwt` (the signature and times), `federation` (the login's words), `kernel` (what is unavailable, the clock)
