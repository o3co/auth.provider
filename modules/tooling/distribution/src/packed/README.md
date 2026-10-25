# packed

Internal module of `distribution`: a packed tarball read for what it is, its name, version and integrity.

## Responsibilities
- Reads a tarball's manifest for its name and version, and hashes its bytes as npm records a tarball's integrity.

## Not here
- Packing, sealing and checking the release: `release`. What is done with what is read: its callers.

## Offers
- `packedOf` (a tarball's path → `Packed`: name, version, integrity), `integrityOf` (bytes → `sha512-` and the SHA-512 in base64).

## Invariants
- It loads Node's own modules alone, as the release's publish job reads tarballs with it and loads nothing from outside.

## Depends on
- `tar`, run, to read a tarball's manifest.
