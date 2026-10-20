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
- `recordOf` (the URL, the document, the ceiling's scopes and audiences) → the client record, or the reason it is refused.
- `readingOver` (the build context) → `readingWith` (`outbound`, the narrower, the ceiling, the log, `clients`' `checkRecord`, taken late) → a loader for `fetching`.

## Invariants
- The loader answers found with the answer's max age, refused with a logged reason, or failed.
- The max age is zero under `no-store` or `no-cache`, else its `max-age`, else none.
- A refusal's reason is the field refused, the status, `not a JSON object`, `outbound`'s refusal or failure, or `record at` the paths where `checkRecord` refuses the record. A record is checked before it is kept; a check that throws rejects, which `fetching` takes as a failure.

## Depends on
- `outbound` (the fetch, its refusals, reading JSON), `redirect-uris` (the redirects section), `client-allowance` (scope words, allowances within the ceiling), `consent` (its section), `code-grant` and `refresh` (the grants' names), `clients` (the record type, `checkRecord`), `kernel` (the build context, the log)
- The package's section and `fetching`'s loader answer
