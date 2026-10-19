# Changelog

Notable changes, newest first, in the form of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Release candidates have sections of their own; what an operator must do for each change is in the [migration guide](docs/migration.md).

Changes up to 0.17.0 are in [the 0.17.0 changelog](https://github.com/o3co/auth.provider/blob/v0.17.0/CHANGELOG.md).

## [0.18.0-rc.2] - Unreleased

What to change from rc.1 is in [From 0.18.0-rc.1](docs/migration.md#from-0180-rc1).

### Security

- `mfa`: an enrollment begun at login could add a further factor after the account's first factor was registered; removing a factor or reissuing recovery codes could pass on what is allowed to an account with no factor while another request bound one; and two first enrollments at once could both bind.
- `mfa-flows`: recovery codes that were never shown could stay usable; an enrollment could complete after a reset or a revocation that came while it was under way; an enrollment begun before a subject revocation could still bind after the revocation completed; recovery codes from a first binding could be shown after a revocation completed.
- `mfa-management`: a session opened before a subject revocation could remove a factor, or reissue and receive recovery codes, after the revocation completed.
- `federation-grants`: a refresh could hand out a token after the grant had ended or its subject had been revoked, a request that waited for the refresh lock included; a grant past its end is treated as ended everywhere.
- `session-lifecycle`: an explicit close of a session past its lifetime did not revoke the session's tokens; a session revoked while its entry requirements were asked could still enter.
- `refresh`: an access token from a refresh could outlive the session of its family.
- `code-grant`, `device-grant`: an access token could live past the end of the session it was issued in.
- `rp-logout`: a close left pending was answered as a logout; the logout taken before authentication had no per-source limit; a retried logout could answer success while its revocation was still pending; a logout of a session past its lifetime but still kept could skip its participants.
- `jwt-bearer`, `exchange-id-tokens`: the allowance for the issuer's clock could let an assertion or an id_token from just before the subject's revocation boundary through; `jwt-bearer` checks the key id and the issuer more strictly.
- `keys`: a bearer token of too little randomness was accepted.
- `outbound`: an `Authorization` header a caller wrote could be sent without the credential rules.
- `users`: a link the ledger could not answer for could be read as absent.
- `authorize`: re-authentication was compared in whole seconds, so an authentication less than a second before the request counted as fresh.
- `signer-keys-http`: a key carrying a member that is not public, other than `d`, could be passed on; and an answer with no keys was read as unusable, where it is read as no keys (the old reading refused, so it was on the safe side).

### Changed

- **Breaking**: time and size settings are written with a unit, and lost their unit suffixes.
- **Breaking**: the sealing keys are `seal.current` and `seal.previous`; `seal.keys` is refused.
- **Breaking**: a subject is 1 to 255 ASCII characters.
- **Breaking**: each JWT bearer issuer says how its assertions' subject is read.
- **Breaking**: an upstream link in the settings names an upstream a composed module declares.
- **Breaking**: under `required`, boot is refused unless a composed second factor counts and adds one.
- **Breaking**: the routes that manage factors come from the `mfa-management` module.
- **Breaking**, for a user ledger over HTTP: on the password call, a `403` reads as unavailable (the login answers `503`); only a `401` says no such user or a wrong password.
- **Breaking**: audit and log names: `introspect.store_unavailable` is now `introspection.unavailable`, and the routes' own unavailable warnings are one, `http.unavailable`.
- A 503 a route does not declare carries `{"error":"service_unavailable"}`.
- A written link to an upstream identity lets in only a subject the users or the ledger know.
- Removing a factor or reissuing recovery codes asks for a second factor proven recently.
- A first factor bound while another was bound meanwhile is refused, not bound beside it.
- A session short of a requirement: the RP-initiated logout of one is a logout like any other, and a link it started is refused under its own reason.
- `federation-tokens` answers a refresh the upstream refuses until the user acts there with `403 upstream_interaction_required`.
- `audit-http` reaches a collector at a `plain-loopback` pair over plain http too.
- A managed Redis that refuses `CONFIG` is declared in `redis.server-settings`.
- A configuration file that does not parse is refused at its line and column.
- A required key left unset is refused as `required, and not set`; a missing or empty `audit.receivers` is refused saying what to name; an empty or unparsable public or CORS origin, WebAuthn origin, or upstream identity provider's endpoint is refused at boot instead of stopping the app with an error.
- A destination outbound refuses at boot says which of outbound's keys lets it through, naming no value; and a JWT bearer issuer refused at boot is named by its place in the settings, not by its value.
- The credentials routes read the subject's second factors whatever is composed, and answer unavailable when the factors' store cannot answer.
- `mfa` refuses to boot without `mfa-entry`, whatever its mode.
- The command that generates an app is `create-auth-provider`.

### Added

- Modules: `subject-revocation-http` (an outside ledger ends a user's sessions and tokens here), `signer-keys-http` (an outside ledger supplies JWT bearer signers' keys), `jwt-bearer-users` (a JWT bearer subject linked to a user), `exchange-id-tokens` (an upstream id_token exchanged for this provider's tokens), `mfa-management` (managing factors), `mfa-witness` (the contract of an enrollment witness kept apart from the factors' store), `mfa-witness-http` (that witness kept at the operator's ledger over HTTP; what the ledger must keep is in the [runbook](docs/runbook.md#keeping-the-second-factor-witness-at-the-ledger)), `mfa-revocation` (moves a revoked subject's second-factor fence before the revocation completes; composed through `combinations`), `mfa-entry` (judges a session against its second factors; the entry requirement keeps the name `mfa`; composed through `combinations`; `mfa` refuses to boot without it, so an app composed by hand must add it), and the store wirings `jwt-bearer-store` and `exchange-id-tokens-store`.
- `federation-grants.sweep-interval`: each instance erases the credentials of ended grants, though no request reads them.
- `users-http.subject-url` and `upstream-url`, for a ledger that looks users up by subject or by upstream identity; `verify-url` is now optional.
- `idp-google.hosted-domains`.
- The metric `auth_rate_limit_uncounted_total`, for each request a limit could not count.
- Each route declares whether it changes state, and why it takes other sites' requests or counts no source where it does not; `http` checks the declarations at boot, and the [route reference](docs/routes.md) lists them.
- For modules of your own: `session`'s `entryOf`, a route's declared `unavailable` answer, and `@mod/mfa-extensions` for second factors.
- Documents: the [route reference](docs/routes.md), a [login page guide](docs/login-page.md), a [recipe for a login page with a second factor](docs/recipe-mfa-page.md), recorded from a running app and checked on every change by the new `conformance-recipes` tests, a [release guide](docs/releasing.md), the [security policy](SECURITY.md), a [contributing guide](CONTRIBUTING.md) and the README in Japanese.

### Removed

- For modules and adapters of your own: `session`'s `stillOpen`, `openContext` and `endsAt`; `Cookies.read`; `secretChecker`; `answeringUnavailable`; `outbound`'s `outboundPolicy`, replaced by `outboundRefusals`; `mfa`'s `recent` and `provenRecently`, moved to `session` and `mfa-entry`; and the `store` calls nothing used. `mfa`'s `countingHeld` takes where it is asked, and its `remove` and `reissue` take the fence answered before the change. Each one's replacement is in [From 0.18.0-rc.1](docs/migration.md#from-0180-rc1).

## [0.18.0-rc.1] - 2026-10-17

A rewrite of 0.17 as modules assembled by a generated app, published as one package per concern under new names. Configuration is rewritten, stored state does not carry over, and several settings and requests that 0.17 accepted are refused. Read the [migration guide](docs/migration.md) before moving a 0.17 deployment.
