# dpop

## Responsibilities
- Checks DPoP proofs (RFC 9449) and contributes them to `sender-binding` as a binding kind.
- Spends each proof's `jti` once.

## Not here
- The token format. Where a binding is demanded: the caller's.

## Offers
- Composition definition only. The binding kind: `cnf` member `jkt`, named `dpop` for operators, token type `DPoP`, explicit (it wins over an ambient binding, such as a certificate, a request also proves).
- Contribution to `issuer`'s metadata: `dpop_signing_alg_values_supported`, the allowed algorithms.
- Store interface for spent proofs: save a name for a lifetime, answering `created` or `exists`.
  - Requirements: no eviction, survives a crash, never rolled back by failover.
  - Its contract test, and the section for tests, `dpopConfig` (`./testing`).
- Operator section `dpop`: `algorithms`, `proof-window`, and `nonce` (`required`: `as` by default, asked at the token endpoint, where a token is bound; `as+rs`, at resources too, is no default, as a resource server outside this provider would have to ask it as well; `never` is warned of at every start, `dpop.nonce_not_asked`; `ttl`; `secret`, then required), times written with their unit; its keys are in the configuration reference.

## Invariants
- Where a server-provided nonce is asked (RFC 9449 §8), a proof without one taken is refused `use_dpop_nonce` with the current nonce in `DPoP-Nonce`, before the token's hash is checked and before its jti is spent.
- A nonce is its time bucket and an HMAC under the shared secret, taken in that bucket and the next, and only in the very form it was handed out; nothing is kept, so any instance takes another's.
- The nonce secret is one, as in 0.17: once it is changed, a nonce handed out just before is refused once, and the client sends the proof again with the new nonce.
- One DPoP header only; repeated headers arrive joined by commas and are refused.
- A proof not written in its one form (`keys`' rule for a JWS) is no JWT.
- The header needs `typ` `dpop+jwt` and an allowed algorithm. None and shared secrets are never allowed.
- The key is rebuilt from its public members alone, by `keys`. A key of an unknown type, with any other member than `kid`, `alg`, `use` and `key_ops`, or with a member that is no string is refused.
- The payload is one JSON object with `htm`, `htu`, a numeric `iat`, and a `jti` of 1–256 characters that is well formed.
- `htm` is the request's method.
- `htu` is compared by scheme, host, port and path, ignoring query and fragment. A `htu` with user information is refused.
- The expected `htu` is the origin of the issuer `sender-binding` passes, with the request's path, never from Host or forwarding headers.
  - Where the issuer has a path that a proxy strips, every proof is refused.
- `iat` is taken within the window on either side of `kernel`'s clock, edges included.
- At a resource, `ath` is the hash of the token presented.
- The `jti` is spent last, after every other check, so a proof refused for its `ath` is not used up.
- A spent `jti` is refused. One the store cannot answer for is unavailable.
- A proof spent before the grant fails stays spent; the client signs again.

## Data
- Spent proofs, named by the key's thumbprint and the `jti`. A thumbprint holds no dot, so a name is one key's and one `jti`'s alone.
- Each is kept for twice five minutes, the widest `proof-window` the section takes, whatever is set, plus a minute for the store's clock: a `proof-window` widened later on the same store never takes it again.

## Depends on
- `kernel`, `http`, `issuer`, `keys`, `sender-binding`

## Vocabulary
- proof: a JWT the client signs for each request.
