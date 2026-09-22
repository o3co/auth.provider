# live-check — a real IdP login against this checkout

A hand-run check: boot the standalone template from the working tree with its
**default** configuration, sign in at a real identity provider in a browser,
and get a record of what the callback carried and what the provider did with
it — the record an issue like [#600](https://github.com/o3co/auth.provider/issues/600)
asks for before a release.

Nothing in the automated suites reaches a real IdP. They prove the provider's
handling of a callback the test wrote; this proves what the IdP actually sends
— which parameters, which `iss`, which shape of `code` — against the code that
will be tagged. Run it when a release touches a federation adapter, the
session's federation routes, the callback handling, or the RFC 9207 `iss`
rule, for every provider the template ships that the change concerns.

## What you need

- This repository installed and built (`pnpm install`, `pnpm run build`);
  `start` does both when it has to, and rebuilds a package whose `src` is
  newer than its `dist`.
- Node 22+, `curl`, `lsof`; Docker for the Redis the template's stores need,
  unless a Redis already listens on `localhost:6379` (used as is) or
  `LIVE_CHECK_REDIS_URL` names one.
- A client registered at the IdP, with **exactly** this redirect URI:

  ```
  http://localhost:3210/session/oauth/federation/<federation>/callback
  ```

  where `<federation>` is the template's name for it (`google`, `oidc`) and
  `3210` is `LIVE_CHECK_PORT`. Google accepts `http://localhost` redirect URIs
  on a "Web application" client; while its consent screen is in *Testing*, the
  account you sign in with has to be listed as a test user.

## Run

```bash
cd tools/live-check
cp profiles/google.env.example profiles/google.env   # fill in the client id and secret; *.env is git-ignored
./live-check.sh start google                          # prints the URL to open and the redirect URI to register
# … sign in at http://localhost:3210/ …
./live-check.sh report                                # the markdown to paste into the issue (also on the page)
./live-check.sh stop
```

`start` refuses, by name, what is missing: the profile, a taken port, a
provider that does not boot (its log is printed), a start route that does not
answer with a redirect to somewhere off this machine. `status` prints the
record as JSON; `logs` the tail of both logs; `stop` ends both processes,
removes the overlay it wrote and the Redis container it started (never one it
found running).

## What the page records — and does not

After the sign-in the page shows, and `report` prints:

- the callback's **query parameter names** (Google: `state, iss, code, scope,
  authuser, hd, prompt`) and the **`iss` value in full**, judged against the
  profile's `LIVE_CHECK_EXPECTED_ISS` when one is set;
- the **provider's answer**: `302` to the page means the login succeeded; a
  `4xx` comes with its JSON body (`error`, `error_description`), which is the
  provider's refusal and the thing to read;
- whether the **session cookie** was set, and what the user Store was asked
  for (`google:••••••••••••2336` — the last four characters of the `sub`).

`code` and `state` are recorded as **lengths only**. The `sub` is masked. No
token, no id_token claim, no profile field and no password ever reaches the
front: the id_token is exchanged and verified inside the provider, as in any
deployment. The record lives in the front's memory and is gone at `stop`.

A verdict of **OK** means: the login completed, and — when the profile sets
`LIVE_CHECK_EXPECTED_ISS` — the callback carried that `iss`. Without an
expected issuer the `iss` is recorded, not judged: an IdP whose metadata does
not advertise `authorization_response_iss_parameter_supported` may send none,
and the provider then does not require one. **NG — no iss** on a provider
whose default requires one (Google, #599) is the finding that stops a release
with that default on; the issue for the provider says what to do next.

## How it is wired

```
browser ──▶ :3210  live-check front (proxy.mjs)  ──▶ :3000  standalone template (develop, default config)
             │  /                 the page                    │  federations.<name>: enabled, your client,
             │  /__live-check/*   the record                  │    callbackURL → :3210, clientUrl → :3210/
             │  /__store/*        a user Store that accepts   │  repositories.user.http → :3210/__store/*
             │                    every <federation>:<sub>    │  Redis: :6379 (docker or yours)
             └─ everything else   relayed to :3000            │  session cookie: SESSION_SECURE=false, non-__Host-
```

- The front is the only process that sees the raw callback URL; it relays the
  request untouched and records the parts above. It binds `127.0.0.1` only.
- The provider runs the template's `src/app.mts` (`tsx`, no build) with
  `config/application.conf` as shipped plus one overlay,
  `config/live-check.local.conf` (`federations.<name>.clientUrl`, the one key
  a check needs that has no environment form), written at `start`, removed at
  `stop`, and git-ignored by the template as `config/*.local.conf`. Everything
  else goes in through the environment switches the template documents.
- The Store accepts every identity of the federation as a user, so the check
  never fails for want of a local account. **That is what makes this rig unfit
  for anything but a loopback check** — never expose either port.
- A throwaway Ed25519 key pair and session secret are generated into
  `.state/` on first `start` and reused after; `.state/` is git-ignored.

## Adding an IdP

A profile is an env file in `profiles/`: the federation's name in the
template (`LIVE_CHECK_FEDERATION`), the `iss` the callback must carry
(`LIVE_CHECK_EXPECTED_ISS`, empty to record without judging), and the
template's own `FEDERATIONS_<NAME>_*` switches for the client. `start` adds
`_ENABLED=true` and the `_CALLBACK_URL`.

- **Google** — `google.env.example`; exercised (#600).
- **Any OpenID Connect IdP** (Okta, Clerk, Entra ID, Auth0, Keycloak, …) —
  through the template's generic `federations.oidc` entry: copy
  `oidc.env.example` to `<idp>.env`, set the issuer, the client, and
  `LIVE_CHECK_EXPECTED_ISS` to the issuer, then `start <idp>`. Not yet
  exercised against a real IdP; the first run goes on its issue and that note
  goes away.
- A federation the template does **not** ship (`github`, `apple`) has no
  profile: the provider here is the template, and it composes only `google`
  and `oidc`. [#598](https://github.com/o3co/auth.provider/issues/598) (GitHub's
  `iss`) needs a composition of its own before this tool can observe it.

## Limits

- One federation per run, one sign-in at a time; `start` again after `stop`
  for another profile.
- No gateway: the browser talks to the loopback front. A deployment with a
  front end in front of the provider still has to confirm that it passes the
  callback's query through — this tool cannot stand in for that.
- The verdict is about the callback and the login, not about the claims or
  the tokens the provider went on to mint.

## Troubleshooting

- **`redirect_uri_mismatch` at the IdP** — the registered URI differs from the
  one `start` printed (scheme, host, port, path, all of it). Fix the
  registration and click the button again; nothing needs restarting.
- **`port 3210 is taken`** — set `LIVE_CHECK_PORT`; the redirect URI to
  register changes with it. `LIVE_CHECK_PROVIDER_PORT` likewise for `:3000`.
- **The provider refused to boot** — `start` prints its log; the refusal
  names the setting. A profile missing its client id or secret is the usual
  one.
- **`GET /session/oauth/federation/<name>` answered 404** — the federation is
  not composed: the profile's `LIVE_CHECK_FEDERATION` is not a federation the
  template ships, or an older provider process still holds `:3000` (`stop`
  kills the whole process tree it started; anything else is yours to end).
- **The login succeeded but the page shows nothing** — the callback did not
  pass through the front: the IdP redirected to a URI on `:3000` directly.
  Register the `:3210` URI.
