# keys

Internal module of `client-assertion`: the client metadata section that holds a client's keys for its assertions.

## Responsibilities
- Reads a client's keys, written in or a key set's URL, and where they come from; checks at boot that `outbound` lets a registered client's key set URL through.

## Not here
- Checking an assertion and spending it (the package). Fetching the key set (`external-jwt`, through `outbound`).

## Offers
- `clientKeys`, the section; `keysOf` (the section) → where the keys come from; `clientKeysIn` (the build context) → the section with its boot check, `outbound`'s refusals taken from the composition.

## Invariants
- A written key is a public RSA, EC or OKP key for verifying signatures, read by `keys`' rules; written keys and a key set's URL are never both given.
- A key set is fetched from its URL's host alone.

## Depends on
- `clients` (the section's form), `external-jwt` (a key source), `keys`, `url-setting`, `outbound-policy` (the boot check), `kernel` (the build context)
