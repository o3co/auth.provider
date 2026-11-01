# pins

Internal module of `interop-clients`: the SHA-256 of each jar an adapter is built from.

## Responsibilities
- Hashes an adapter's runtime jars and compares them with the pins committed beside it, so a swapped jar from a registry fails the build.

## Offers
- `jarsIn`, `pinsText` (as `sha256sum` writes them), `pinProblems` (each jar whose hash is not its pin, each jar not pinned, each pin with no jar).
- The script's `verify-jars <adapter dir>`, which the Nimbus build runs before it compiles, and `pin-jars <adapter dir>`, which rewrites the pins after a reviewed version bump.
