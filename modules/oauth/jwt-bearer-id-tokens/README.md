# jwt-bearer-id-tokens

## Responsibilities
- Ties `jwt-bearer` and `exchange-id-tokens` together: Apple's and Google's id_tokens, sent as JWT bearer assertions, are checked and taken once by `exchange-id-tokens`' rules, for the apps already sent out that send them so.

## Not here
- The grant, which issuers are delegated, and what a client must prove: `jwt-bearer` (its `delegated-issuers`, its internal module `delegated`).
- The checks, the account, the clients each app's id_token is for, and the record of those taken: `exchange-id-tokens`.

## Offers
- Composition definition only: one contribution at `jwt-bearer`'s `delegatedAssertions`, for each `iss` of the kinds `exchange-id-tokens` takes. It opts in, and comes only where named, bringing both; composing both never brings it.

## Invariants
- Not RFC 7523 §3: an id_token's audience is the app's client ID upstream, never this server. The standard way for an app is the token exchange (`exchange-id-tokens`).
- An id_token `exchange-id-tokens` takes is a valid assertion for the one client it is for, with its account, `iat`, its standing time (`iat` less `exchange-id-tokens`' `clock-skew`), `exp` and holder digest; any other is invalid.
- An id_token is taken once across both grants, in `exchange-id-tokens`' one record: one taken by either is replayed at the other.
- Nothing is delegated until `jwt-bearer.delegated-issuers` names the issuers; one named that `exchange-id-tokens` does not take, or one it takes that is not named, refuses boot.

## Depends on
- `kernel`, `jwt-bearer`, `exchange-id-tokens`
