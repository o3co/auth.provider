# vault

Internal module of `federation-tokens`: sealing a session's upstream tokens, and the shape of its record.

## Responsibilities
- Seals and opens one IdP's tokens, and reads and writes the record that holds them.

## Not here
- When entries are written or removed (`renewal`). How sealing works (`seal`).

## Offers
- `vaultWith` (seal) and `vaultFrom` (the composition): `entriesOf` (record → entries by IdP), `recordOf` (entries → record), `open` (session, IdP, entry → tokens / none), `read` (the same with one opening, and the entry sealed again under the current key where a past key sealed it), `seal` (session, IdP, tokens, version → entry)

## Invariants
- The context of a seal is `federation-tokens`, the session handle and the IdP, so an entry moved elsewhere does not open.
- A record of another shape holds no entries; tokens that do not open, or open to another shape, are none.
- A token type that is not text is kept empty, so it is no bearer.

## Data
- Record format 1: entries by IdP, each a version and the sealed tokens (access, type, refresh, id, end, when obtained, granted scope, scope).

## Depends on
- `seal`, `kernel`; the package's store interface
