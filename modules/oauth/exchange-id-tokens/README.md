# exchange-id-tokens

## Responsibilities
- Contributes token-exchange's verifier of `urn:ietf:params:oauth:token-type:id_token`: Apple's and Google's id_tokens, exchanged for a token of the account users links the upstream subject to.
- Decides which client of this provider may exchange each app's id_token, and takes each id_token once.

## Not here
- The exchange itself, the client's allowance and the public client's key (`token-exchange`). The account an upstream subject is linked to (`users`). Fetching and keeping key sets (`external-jwt`). Signing in upstream (the app).

## Offers
- Composition definition only (a verifier for `token-exchange.verifiers`, the Space `exchange-id-tokens.used`, and to `users.upstream-names` each kind's upstream name with its issuer).
- Operator section, times written with their unit:
  - `max-age` (`1m` to `1h`, default `10m`): the oldest an id_token may be, from its `iat`. `clock-skew` (`0s` to `5m`, default `30s`).
  - `apple` and `google`, each optional, at least one: `upstream` (default the kind's name), the name users links the upstream subject under; `clients`, this provider's client IDs, each with `audiences` (one or more) and `authorized-parties` (default none).
- `./testing`: `exchangeIdTokensOver(issuers)`, the module over issuers whose keys a test holds; the composed module is over the fixed issuers alone.

## Data
- Space `exchange-id-tokens.used` (no-eviction, durable, replicated), contributed whenever the module is composed: each id_token taken, by kind, under the SHA-256 of its header and payload, kept until its last moment of being taken (`exp` or `iat` plus `max-age`, whichever is first) plus `clock-skew` and a minute.

## Invariants
- Issuers and key sets are fixed by the kind, never settings: Apple `https://appleid.apple.com` at `https://appleid.apple.com/auth/keys`; Google `https://accounts.google.com` or `accounts.google.com` at `https://www.googleapis.com/oauth2/v3/certs`. Only RS256 verifies.
- A client takes an id_token whose `aud` is one of its `audiences` and, without `authorized-parties`, whose `azp` is absent or its `aud`; with them, whose `azp` is one of them. An id_token exactly one client takes is that client's; one no client or two clients take is invalid.
- An id_token needs `iat`, no older than `max-age` with `clock-skew`, and is refused past `exp` or from the future, as `external-jwt` reads them.
- Its `sub` must have a subject's shape. The account is `users.byUpstream(upstream, sub)`; none is invalid. One issued before the account's `sessions` revocation boundary, widened by `clock-skew`, is invalid: an issuer's clock running ahead never lets one issued before it through.
- The answer is a `foreign` token: the account as subject, the issuer, the id_token's `exp` as its end, the one client as `clients`, and a `nonce` of a SHA-256 digest's shape as `holderDigest`; no scope or audience of its own.
- Boot is refused with neither `apple` nor `google`, with two clients of one kind taking one (`aud`, `azp`) pair (the second refused, naming the first by its key path), and with a client no registered client is. Users refuses it too where another module names the same upstream for another issuer; the same name for the same issuer (federation's `google`) boots.
- Users, the store and the key sets failing are Unavailable, never a refusal.
- The expected flow: the app signs in with Apple or Google, exchanges the id_token once for a short token, and proves a device key to the operator's API with it. A public app makes a DPoP key first and passes `BASE64URL(SHA-256(jkt))` as the sign-in `nonce`.

## Depends on
- `kernel`, `token-exchange`, `users`, `external-jwt`, `subject-revocation`, `clients`
