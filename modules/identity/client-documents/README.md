# client-documents

## Responsibilities
- Owns how a `clients` section is filled from a client's metadata document: what a source that reads documents asks of each section's owner, and what the owner answers.

## Not here
- Fetching a document and trusting its client: the source that reads it (`clients-cimd`).
- A section's schema and what it means: its owner, through `clients`' `metadataSections`.

## Offers
- `documentCopies`, keyed by the name of the section each fills: `section` (the `clients` section), `reads` (the document's fields it reads, in RFC 7591's words) and `copy` (a document and its `DocumentSource` → the section's value before the schema, `refused` naming a field, or nothing).
- `DocumentSource`: the client id a document came from, and the host its source checked.

## Invariants
- A copy holds the section's own keys alone, never the document's, so where a record fails holds no document text; `refused` is a field's name, never its text.
- A section that widens what a client may do (first-party, keys, a binding, public exchange) takes from a document only what a document may say, or has no copy.
- Nothing here runs: the source that reads documents collects the copies and applies them.

## Depends on
- `kernel`, `clients` (the section a copy fills)

## Vocabulary
- document: client metadata in RFC 7591's names, as a source found it.
