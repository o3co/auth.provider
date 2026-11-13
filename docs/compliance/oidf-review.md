# OpenID conformance suite: the pages a person reviewed

The OpenID Foundation's conformance suite leaves some tests for a person to review; the review procedure lists them by plan. This page records, for each release, what a person saw on each page and whether it showed what the test expects. The review procedure, `docs/oidf-review-procedure.md` in the repository, says how to get the pages and how to judge them.

Unlike the other pages here, this page is written by hand; the compliance report does not generate it.

## How a release's record is written

Add a section for each release, newest first, in this form:

```markdown
## <version>

- Commit: <the release branch's head, which the run tested>
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
- A section is of the run reviewed for the release: before the tag, the run the tag takes; for a security release, the public run after it. A `ng` that sends the release back through a new run gets no section for that run: it stays in its issue or, where it is a security hole, in the ledger.
- In a section reviewed after publication, a `ng` that is a security hole holds the whole section out of a pull request for as long as `SECURITY.md` keeps the hole silent, as a test's name can tell where it is; its Issue then names the fix.

## 0.19.0

- Commit: b816a4d7c3cd184772733f7adda4c5572b968032
- Run: https://github.com/o3co/auth.provider/actions/runs/41989842650
- Reviewed by: DRAFT, read by Claude on 2026-11-06, for the owner's judgement

| Plan | Test | Result | The text judged by | Issue |
|---|---|---|---|---|
| basic | oidcc-prompt-login | ok | The login form: "Log in", fields "User" and "Password". | |
| basic | oidcc-max-age-1 | ok | The login form: "Log in", fields "User" and "Password". | |
| basic | oidcc-ensure-registered-redirect-uri | ok | `redirect_uri is not registered for the client` | |
| basic | oidcc-ensure-request-object-with-redirect-uri | ok | `redirect_uri is not registered for the client` | |
| rp-initiated-logout | oidcc-rp-initiated-logout-bad-post-logout-redirect-uri | ok | `post_logout_redirect_uri is not registered for the client` | |
| rp-initiated-logout | oidcc-rp-initiated-logout-query-added-to-post-logout-redirect-uri | ok | `post_logout_redirect_uri is not registered for the client` | |
| rp-initiated-logout | oidcc-rp-initiated-logout-bad-id-token-hint | ok | `invalid_token`, `id_token_hint verification failed` | |
| rp-initiated-logout | oidcc-rp-initiated-logout-modified-id-token-hint | ok | `invalid_token`, `id_token_hint verification failed` | |
| rp-initiated-logout | oidcc-rp-initiated-logout-no-id-token-hint | ok | "Do you want to log out of host.docker.internal:38481?" | |
| rp-initiated-logout | oidcc-rp-initiated-logout-no-params | ok | "You are logged out." | |
| rp-initiated-logout | oidcc-rp-initiated-logout-no-post-logout-redirect-uri | ok | `{"logged_out":true}` | |
| rp-initiated-logout | oidcc-rp-initiated-logout-only-state | ok | "You are logged out." | |
