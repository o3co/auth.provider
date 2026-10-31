# external-jwt

## Responsibilities
- Checks a JWT signed by a key from outside (header, key, signature, times, issuer, audience, subject), and keeps each key set fetched from a URL once in the process; knows no feature.

## Not here
- What to expect (issuer, audiences, subject, algorithms, clock allowance, longest lifetime): the caller's, from its own section, the algorithms written by `algorithmsSetting`.
- Single use of a `jti`, and the meaning of any other claim: the caller's.
- Where requests may go, and the transport: `outbound`.

## Offers
- The `externalJwt` contract: a verifier from a key source and the caller's policy, and the asymmetric algorithms it knows, typed as `Algorithm` (`keys`' `VerifyAlgorithm`).
  - Key sources: JWKs written in; PEM keys, each for the algorithm it is given for; a key set at a URL, fetched through `outbound` from the caller's hosts, and as the operator's configured URL where the caller names one (`internal`).
  - Verifying answers valid (the header and claims, frozen), invalid with a reason, or unavailable when no key set can be had. An invalid answer found once the signature held (a claim's shape, a time, the issuer, audience or subject) carries `signed: true`; one before it (the header, the algorithm, the key, the signature) carries none.
  - Reasons: `malformed`, `algorithm`, `no-key`, `ambiguous-key`, `signature`, `expired`, `not-yet`, `future-iat`, `too-long`, `issuer`, `audience`, `subject`. A caller maps them to its own words.
- `algorithmsSetting(asymmetric, byDefault)`: the setting a caller's section names its algorithms by, a list, not empty, of the asymmetric ones given, `byDefault` where unwritten (a default outside them refused); `knownAlgorithms`, the ones a verifier knows, for a section declared before a verifier is had.
- `typOf` (a header) → its `typ` read as a policy's `typ` is compared, as a media type: its type alone, without parameters, the space around it, case or `application/`; none where it is no string. For a caller to sort tokens by before verifying; whether the header is verified is the caller's to know.
- Composition definition, with the operator section `key-set-max-age` (written with its unit, `1h` to `30d`, default `1d`), how long after its fetch a key set is used while no new one can be had.
- A test signer (`./testing`): a key pair as a JWK and PEM, signing claims or exact bytes with any header, as a sender might.

## Invariants
- A token not written in its one form (`keys`' rule for a JWS) is malformed, so one token has one string.
- Only asymmetric algorithms the caller allows are taken; none and shared secrets never are.
- A header with `b64` or `crit`, a `kid` that is no string, or a `typ` other than the caller's is malformed. `typ` compares as a media type, without parameters, space or case and with or without `application/`, by `typOf` alone.
- Keys are read and fit to the algorithm by `keys`' rules for outside keys, and must agree with the header's `kid`; exactly one must, else no key or an ambiguous key.
- Each key is read under one algorithm (RFC 8725 §3.1), by the caller's whole list and never the header: its own `alg` where allowed, else the one allowed algorithm its kind and curve fit. A key naming none that two allowed algorithms fit is used under neither, an answer of no key that fetching again does not change.
- The claims are one JSON object in UTF-8 with a numeric `exp`; `nbf` and `iat`, where given, are numeric.
- On `kernel`'s clock, with the caller's allowance on each side, a token is expired at `exp`, not yet valid before `nbf`, and refused for an `iat` in the future.
- With a longest lifetime, `exp` may be no further ahead than it with the caller's allowance, and `exp` − `iat` no longer than it without one, so `iat` may lie no further behind.
- An expected audience is met by any one of the token's audiences; a list of audiences holds only strings.
- A key set is fetched when first needed and used an hour from when its fetch began; before then, only for a key it lacks, never for one it holds twice.
- One fetch runs at a time, shared by every check waiting for it; fetches are at least a minute apart, whether they worked or not.
- Only a `200` answer holding a `keys` list is a set; entries that are no public key are skipped.
- While no set can be had, the last one is used until `key-set-max-age` after its fetch; past that, or with none, the answer is unavailable.
- A refused destination, an unreachable host, or an answer that is no JSON is an outage; any other error is thrown.

## Data
- Key sets, one per URL, set of hosts and configured URL (one fetched as the operator's URL is never shared with one that is not), held in the process; nothing is stored.

## Depends on
- `kernel`, `keys`, `outbound`; `jose` (`compactVerify` and `decodeProtectedHeader`, in the verifier)
