# secret

Internal module of `keys`: settings that hold a secret's bytes.

## Responsibilities
- Reads a secret written in a setting (a key's bytes, a bearer token) and refuses one too short, too uniform or left as a sample, never naming its value.

## Not here
- Where a secret goes, and how it is sent (the module that takes it).

## Offers
- `secretBytes` (exactly or at least n) and `bearerToken` (at least n), each a schema part; `bytesOf`, the bytes a secret setting holds.

## Invariants
- A refusal names the setting, never the value.
- A `REPLACE-` sample is refused as one left in place.

## Depends on
- None (`keys`' contract)
