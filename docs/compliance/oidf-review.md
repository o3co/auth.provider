# OpenID conformance suite: the pages a person reviewed

The OpenID Foundation's conformance suite leaves twelve tests for a person to review. This page records, for each release, what a person saw on each page and whether it showed what the test expects. The review procedure, `docs/oidf-review-procedure.md` in the repository, says how to get the pages and how to judge them.

Unlike the other pages here, this page is written by hand; the compliance report does not generate it.

## How a release's record is written

Add a section for each release, newest first, in this form:

```markdown
## <version>

- Commit: <the release's commit>
- Run: <where the pages came from: the CI run's link, or "local" with the records directory>
- Reviewed by: <name>, <date, YYYY-MM-DD>

| Plan | Test | Result | The text judged by | Issue |
|---|---|---|---|---|
| basic | oidcc-prompt-login | ok | … | |
| … | … | ng | … | #<issue> |
```

- Result is `ok` or `ng`, as the procedure's table says.
- "The text judged by" quotes what the page showed: the error, its description, or the page's heading.
- Issue names the issue a `ng` was opened as; it is empty for `ok`.
- Each section lists all twelve tests. A test the run did not reach is `ng`, with "not reached" as the text.

No release has been reviewed yet.
