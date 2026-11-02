# document

Internal module of `clients-cimd`: reading and judging a client's metadata document.

## Responsibilities
- Says whether a client id is a document URL.
- Fetches the document through `outbound`, judges the answer and the document, and gives the public client with each owner's section.

## Not here
- The id's host against `allow` and `deny`, and whether the code grant is composed (the package).
- Keeping answers and bounding fetches (`fetching`). What each section's values mean (the owners' schemas).

## Offers
- `documentUrl` (an id) → the URL, or none.
- `recordOf` (the URL, the document, the ceiling's scopes and audiences, the owners' copies) → the client record, or the reason it is refused; each copy is given the id, its host and `digestOf` the document; `neededFields` and `computedSections`, which boot checks the copies against.
- `readingOver` collects the copies from `client-documents`' `documentCopies`, refusing boot where none reads a needed field, where a copy's section is not among `metadataSections`, or where one copies a computed section.
- `readingOver` (the build context) → `readingWith` (`outbound`, the narrower, the ceiling, the log, `clients`' `checkRecord`, taken late) → a loader for `fetching`.

## Invariants
- `digestOf`: SHA-256, base64url, over the whole document as read, every field whether read or not, serialized as JSON with each object's members in one order at every depth. Two documents differ in it where they differ as JSON values, and not in how they are written: white space, member order, an escape.
- The loader answers found with the answer's max age, refused with a logged reason, or failed.
- The max age is zero under `no-store` or `no-cache`, else its `max-age`, else none.
- A refusal's reason is the field refused, the status, `not a JSON object`, `outbound`'s refusal or failure, or `record at` the paths where `checkRecord` refuses the record. A record is checked before it is kept; a check that throws rejects, which `fetching` takes as a failure.

## Depends on
- `outbound` (the fetch, its refusals, reading JSON), `client-allowance` (scope words, allowances within the ceiling), `code-grant` and `refresh` (the grants' names), `clients` (the record type, `metadataSections`, `checkRecord`), `client-documents` (the copies), `kernel` (the build context, the log)
- The package's section and `fetching`'s loader answer
