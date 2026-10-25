# issuer

## Responsibilities
- Owns this provider's canonical name, the issuer: the configured URL, never derived from a request, the same for every module that names it.
- Checks it against `http`'s public origin.
- Owns the extension point of what this authorization server names itself by: its metadata items.

## Not here
- What is issued under the name: `tokens` and the other issuing modules.
- The meaning and value of each metadata item: the contributing side.
- Building and publishing the document: `discovery`.

## Offers
- `issuer`: its URL.
- Extension point: metadata items, name → value; an item without a value is left out of the document.
- Operator section: `url`, required; an http or https URL as `url-setting` takes it, without a query or a trailing /.
- Test configuration builders (`./testing`); the URL defaults to `https://issuer.example`.

## Invariants
- Boot is refused when the issuer's origin differs from `http`'s public origin, where one is written, and for a plain-http issuer where none is (plain http comes only with the public origin http takes by `insecure-origin`). A production deployment refuses a plain-http issuer.
- Frozen once at boot.
- Two contributions of one metadata item, or a contribution of the `issuer` item (it is the URL above), refuse boot, whether or not any module reads the items.

## Data
- None; the URL is read once from the section.

## Depends on
- `kernel`, `http`, `url-setting`

## Vocabulary
- issuer: this provider's canonical name.
- metadata item: one key and value of the authorization server's metadata document.
