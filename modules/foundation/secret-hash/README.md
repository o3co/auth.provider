# secret-hash

## Responsibilities
- Checks a secret against a stored bcrypt or scrypt hash, with the same work whether or not there is a hash to check against; knows no feature.

## Not here
- Where hashes are kept, and what a secret proves: the caller's.
- Making hashes for storage: the operator's tools.

## Offers
- `readSecretHash` (text → hash or none), the only maker of a hash; a hash names its `work`, alike for hashes that take equal work.
- `secretChecker` (the hashes in use, random bytes) → `check` (hash or none, secret → matched or not).
- Operator section `max-concurrent`: how many checks run at once in this process, every checker's together (1–1024, default 8).
- `./testing`: bcrypt and scrypt hashes at the cheapest work, a 72-byte secret, and a checker recording the work of each computation.

## Invariants
- A hash is bcrypt (`$2a$`, `$2b$`, `$2y$`; cost 4–14; its unused final bits zero) or scrypt (`$scrypt$ln=,r=,p=$salt$key`, in strict base64 without padding); anything else, plain text included, is none.
- scrypt's parameters come from the hash: ln 10 or more and below 16·r (Node's limit), at most 128 MiB per run, p at most 2, salt 16 to 64 bytes and key 32 to 64.
- The minimum is legacy's for bcrypt (scrypt, which legacy did not read, starts at ln 10); the strength is the operator's choice.
- A secret is compared as its UTF-8 bytes, with no Unicode normalization. One over 1024 bytes never matches, before any computation; past 72 bytes it never matches a bcrypt hash.
- Each check computes once per kind of work in use: the hash for its own kind, a decoy of that work (its answer dropped) for every other, so a check without a hash takes the same work as one with it.
- A hash whose work is not in use is computed besides the decoys; with no hash in use, a check without one computes nothing.
- A check past `max-concurrent` is unavailable before any computation; a secret over 1024 bytes takes no place, and a check keeps its place until each of its computations ends.
- The limit is one for the whole process, every assembly's together: each build of the module sets it, so the last assembly built decides; it is the default where the module is not composed.
- Decoys are made once, when the checker is made, from the given random bytes only.

## Depends on
- `kernel`
- `bcryptjs` (external). These rules are held here only: users and clients check their secrets through this module.

## Vocabulary
- work: what checking against a hash costs (bcrypt's cost; scrypt's ln, r, p and key length).
- decoy: a hash of a random secret with the work of one in use, checked where there is no hash of that work to check.
