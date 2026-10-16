# seal

## Responsibilities
- Seals and opens stored data with authenticated encryption (AES-256-GCM) under a key ring read at boot.

## Not here
- What sealed data means.
- Where it is stored.

## Offers
- `seal`: seal (plaintext and context, answering a sealed value) and open (sealed value and context, answering the plaintext or refused).
- Operator section: `keys`, a list of key ids and 32-byte base64 keys; the first seals, and any of them opens.
- Test configuration builders (`./testing`), with one key per test file.

## Invariants
- A sealed value is the key's id, a random 12-byte IV, the body and a 16-byte tag.
- The tag covers the key's id and the context, so a value moved to another owner or another id is refused.
- Sealing uses the first key; opening uses the key the value names.
- A value naming a key not in the ring is unavailable, not refused; putting the key back opens it.
- Tampering, a malformed value, a part not written in its one form, a short tag and another context all give the same refusal.
- A failed open never puts the stored content in its answer.
- Boot is refused without a key, for a key `keys`' `secretBytes` refuses (not 32 bytes of strict base64, fewer than 8 byte values, a `REPLACE-` sample), for an id that is not 1–32 of letters, digits, `_` and `-`, and for ids named alike.
- No sample keys, and no plaintext kept.

## Depends on
- `kernel`, `keys` (the rule for a secret's bytes)

## Vocabulary
- key ring: the current sealing key and past keys used only for opening.
- context: a name for the owner of a sealed value, decided by the using side.
