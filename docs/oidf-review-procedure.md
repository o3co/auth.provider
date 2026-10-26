# Reviewing the OpenID conformance suite's pages

The OpenID Foundation's conformance suite leaves some of its tests for a person to review: it shows a page and asks someone to confirm the page says what the test expects. The harness in `modules/tooling/interop-oidf` reports each such test as skipped, `review: the suite asks a person to review the result`. It is neither passed nor failed until a person looks at it.

This page says how to look at those pages and how to record what you saw. Record your judgements in [compliance/oidf-review.md](compliance/oidf-review.md), never here.

## When to review

Review the pages once for each release, on a run of the release's commit. Twelve tests ask for a review: four in the Basic plan and eight in the RP-Initiated Logout plan.

## Get the pages

1. Check out the release's commit, then run the two plans with a records directory of your own:

   ```sh
   OIDF_ARTIFACTS_DIR="$PWD/oidf-records" pnpm --filter @mod/interop-oidf run plan basic rp-initiated-logout
   ```

   The run needs Docker, `git`, `openssl` and Python 3.9 or later. It takes the suite's fixed ports, so run nothing else that starts the suite at the same time.

2. Open `oidf-records/<plan>/review/index.json`, where `<plan>` is `basic` or `rp-initiated-logout`. It lists every review entry in order, with these fields:
   - `test`: the suite's test.
   - `condition`: the suite's check that asks for the review.
   - `asks`: what the suite asks the page to show.
   - `matched`: the text the harness's browser waited for before it kept the page. The harness chose this text; finding it is no judgement.
   - `file`: the page, in the same directory. It is `null` where the suite kept no page; see the test's log in `tests.json` instead.

3. Open each page's file as text. The provider answers some of these requests with JSON, which the browser wraps in a small HTML page.

## Judge each page

For each test, compare the page with the table below. Write `ok` where the page shows what the "ok when" column says, and `ng` otherwise. Note the text on the page that you judged by.

| Plan | Test | The suite asks | ok when the page shows |
|---|---|---|---|
| basic | `oidcc-prompt-login` | The user is asked to log in a second time. | The login form, with fields for the user and the password. |
| basic | `oidcc-max-age-1` | The user is asked to log in a second time. | The login form, with fields for the user and the password. |
| basic | `oidcc-ensure-registered-redirect-uri` | An error page: the redirect URI is not registered. | An error, without a redirect, saying the `redirect_uri` is not registered for the client. |
| basic | `oidcc-ensure-request-object-with-redirect-uri` | An error page: the redirect URI is not registered. | An error, without a redirect, saying the `redirect_uri` is not registered for the client. |
| rp-initiated-logout | `oidcc-rp-initiated-logout-bad-post-logout-redirect-uri` | An error page: the `post_logout_redirect_uri` is not registered. | An error saying the request is invalid because the `post_logout_redirect_uri` is not registered. A page saying the user was logged out is `ng`. |
| rp-initiated-logout | `oidcc-rp-initiated-logout-query-added-to-post-logout-redirect-uri` | An error page: the `post_logout_redirect_uri` is not registered. | An error saying the request is invalid because the `post_logout_redirect_uri` is not registered. A page saying the user was logged out is `ng`. |
| rp-initiated-logout | `oidcc-rp-initiated-logout-bad-id-token-hint` | An error page: the `id_token_hint` is not valid. | An error saying the `id_token_hint` is not valid. |
| rp-initiated-logout | `oidcc-rp-initiated-logout-modified-id-token-hint` | An error page: the `id_token_hint` is not valid. | An error saying the `id_token_hint` is not valid. |
| rp-initiated-logout | `oidcc-rp-initiated-logout-no-id-token-hint` | An error page: the `id_token_hint` is missing. | An error saying the `id_token_hint` is required. |
| rp-initiated-logout | `oidcc-rp-initiated-logout-no-params` | The user is logged out, and a page says so. | A page saying the user was logged out, or one asking whether to log out. An error is `ng`. |
| rp-initiated-logout | `oidcc-rp-initiated-logout-no-post-logout-redirect-uri` | The user is logged out, and a page says so. | A page saying the user was logged out. An error is `ng`. |
| rp-initiated-logout | `oidcc-rp-initiated-logout-only-state` | The user is logged out, and a page says so. | A page saying the user was logged out, or one asking whether to log out. An error is `ng`. |

A page that asks whether to log out, where the request carries no `id_token_hint`, is what RP-Initiated Logout 1.0 requires of the provider. Once the person agrees, the provider logs the user out.

## Record the result

Add a section to [compliance/oidf-review.md](compliance/oidf-review.md) for the release, in the form that page gives: the commit, the run, each test's `ok` or `ng` with the text you judged by, your name and the date. A test you judged `ng` is a finding: open an issue for it and name the issue in the record.
