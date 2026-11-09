# signing

Internal module of `keys`: the provider's own key ring, read at boot, signing and verifying with it.

## Responsibilities
- Reads the operator's `signing`, `next` and `previous` keys into the ring at boot, refusing any key unreadable or not of its `alg`'s kind; signs claims under a `typ` with the current key and verifies a token by the key its `kid` names.

## Not here
- Publishing the public keys (`jwks`). Reading an outside party's keys (`material`).

## Offers
- `sectionWith` (the operator section: the ring's keys, each `kid` unique, with the parts given beside them), `readRing` (the section → the ring), `signer` (the ring → `keys`), and the ring's `expired`.

## Invariants
- The next key verifies and is published but never signs; a previous key verifies until its `expires-at`.
- A `next` or `previous` `public-key` written as a certificate is taken for its key, as a private PEM is: the key is the provider's own, so no outside party's certificate is trusted, and the deprecation of certificates as outside keys does not reach it.
- A `kid` is unique in the ring; a token's `kid` names the key that verifies it, after its `typ`.
- Claims holding a null, at any depth, are never signed: the refusal, and the error `keys.null_claims` logged with it, name their key paths, never their values.

## Depends on
- None (`keys`' contract)
