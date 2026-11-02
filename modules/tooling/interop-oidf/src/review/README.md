# review

Internal module of `interop-oidf`: the pages the suite's browser kept for a person to review.

## Offers
- `reviewPages`: each review entry of the tests the suite left for review, read from their logs: the page the browser kept (the suite keeps it in the entry, not among its images), what the suite asks of it, and the text the harness's browser waited for; each named as a file by its test.
- `keepPages`: pages kept in a directory, each in its file, with `index.json` naming every page, what the suite asks of it and its file (`null` where there is none); a driver that holds its pages itself hands them in. `keepReviewPages`: the pages of the tests the suite left for review, kept so.

## Invariants
- Only a test whose result is a review gives pages; a review entry without a page is still given, its page none, for a person to look at in the suite's log.
- A file is named by its test alone; a second of the same name is numbered, so none overwrites another.
- Keeping the pages first removes what an earlier run kept in the directory, a run with no review too, so no earlier page stands beside this run's records.
