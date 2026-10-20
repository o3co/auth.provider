# Changelog

Notable changes, newest first, in the form of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Release candidates have sections of their own; what an operator must do for each change is in the [migration guide](docs/migration.md).

Changes up to 0.17.0 are in [the 0.17.0 changelog](https://github.com/o3co/auth.provider/blob/v0.17.0/CHANGELOG.md).

## [0.18.0-rc.3] - unreleased

What to change from rc.2 is in [From 0.18.0-rc.2](docs/migration.md#from-0180-rc2); coming from rc.1, read [From 0.18.0-rc.1](docs/migration.md#from-0180-rc1) first.

### Security

- `request-source`: a `http.trusted-proxies` entry covering every address of a family, any `/0` or every IPv4 address mapped into IPv6 (`::ffff:0:0/96`, `::/1`), made every client a proxy, so no source could be told; it now refuses boot at that entry.
- `session-tokens`: a token an add pushed out of a session near its cap could miss the sweep's retry, where a sweep took the session off its list at that moment; the session is now listed again after every such add.
- `mfa-enrollment`: a first factor's recovery codes could stay usable though never shown, where its login or its session's raise failed and taking them back failed too; they are now written only as they go out.
- `mfa-email`: a code by mail counted as a second factor though `mfa-email.adds-second-factor` was not set; by default it is now a way back only. An app generated from the `mfa-web` pattern does not set it: set it to keep a code by mail counting.
- `session-lifecycle`: an entry by a cookie a raise retired could, for one request racing the raise, be judged on the raised session; an entry now checks again that its cookie still names the session.
- `federation-grants`: under `identity-check: required`, an upstream account held by a local user whose subject read like the no-owner placeholder was taken for unheld, letting another subject's grant through; the ledger's answer is now judged as given.

### Changed

- **Breaking**: a federation login's or link's round trip, and a federation grant's connection, are kept by the new `upstream-round-trip`, and a held login's upstream tokens by the new `upstream-handoff`, each in a new space the store must replicate (`upstream-round-trip-store.round-trips`, `upstream-handoff-store.held-logins`). `federation-store` is gone, and `federation` refuses to boot without the round trips: an app generated with an earlier release candidate that composes `federation` is generated again, or adds the four modules and removes `federation-store`. Round trips under way at the upgrade start again.
- **Breaking**: a federation grant's connection sets a cookie of its own for its round trip, and its callback is taken only in the browser that began it.
- **Breaking**: published bundles take `zod` as a required peer (`^4.6.0`), and an app depends on `zod` itself; a generated app depends on it at the packages' version.
- **Breaking**: `outbound.proxy` takes an origin alone: no path, not even a trailing `/`, and no default port.
- **Breaking**, for an app composed by hand: `session`'s entry requirements and closing participants are kept by the bridges `session-requirements` and `session-participants`, and `session-lifecycle` refuses to boot without them; `authorize`'s redirect-URI rules and re-authentication records are the packages `redirect-uris` and `reauth`, and the `authorize-store` template wires `reauth`'s store; `mfa-flows`' enrollment and operator reset are the bridges `mfa-enrollment` and `mfa-reset`. `combinations` composes each with its host; routes and answers are unchanged, and the client metadata section keeps its name `authorize`.
- **Breaking**: `clients-cimd` builds a document client's sections from each owner's copy, and no longer depends on `authorize` and `consent`; it refuses to boot where no composed section copies `redirect_uris` or `client_name`. With the `a2a` pattern, add `@mod/authorize` beside `--add @mod/clients-cimd`.
- **Breaking**: passkey nicknames follow a second factor's label rule: 1 to 64 code points, well formed, no control or bidirectional characters.
- `clients-cimd` refuses a document whose record a section's schema refuses before keeping it, logging where the record fails and remembering it for `refused-lifetime`; a `client_uri` that is not a string is refused that way too. It refuses to boot where `max-size` or `timeout` is above outbound's cap.
- `records` refuses, when the composition builds, a space opened both for records and for records under a secret.
- Composing `users` no longer brings `mail`, nor `federation` `seal`, which it uses only where a module receives upstream tokens.
- A first factor's recovery codes are written only as they go out, once its login opened or its session's raise was written; where neither is, `POST /session/mfa/recovery-codes` issues them later, answering `409 mfa_factor_limit` to a first set past `max-factors`.
- A generated app's image copies a `pnpm-workspace.yaml` the operator writes, and its README names the audit receivers composed.
- For modules of your own: `Narrower.internal` takes the URL a module read through `url-setting`, in place of `true`, and allows a private address in `outbound.internal-hosts` only to that URL's origin; `token-exchange` reads a token's family and session through `grants`' `tokenTies`, so composing it no longer brings `refresh`, `session-tokens` and `session`; `factors.bind` answers the `fence` and `codesDue`, and `factors.reissue(subject, fence)` writes the first set of codes once it can be shown; a token-exchange verifier answers its `kind`; a code store names its void list's crowd `crowd.names`; a declared route's `*` within a path matches exactly one segment; and a session entry requirement or closing participant contributes to `session-requirements`' or `session-participants`' point.

### Added

- Modules: `upstream-round-trip` and `upstream-handoff`, with their store wirings `upstream-round-trip-store` and `upstream-handoff-store`; `outbound-policy` (outbound's destination policy, with `outboundLimits`); `redirect-uris` and `reauth`; `session-requirements` and `session-participants`; `mfa-enrollment` and `mfa-reset`.
- The audit event `refresh.family_revoked`, with the subject and the client, when a reused refresh token revokes its family; `authorize` and `token-endpoint` declare their audit events, so the audit event reference lists them.
- `federation.held-page`: the page on the public origin a browser goes to when a second factor holds its login through an upstream, to go on there; set it wherever a second factor is composed beside `federation`. The [login page guide](docs/login-page.md#a-login-through-an-upstream-that-a-second-factor-holds) says what the page does.
- For modules of your own: `keys`' `thumbprint` (RFC 7638), the same whatever form the key was written in; `clients`' `checkRecord`, and a metadata section's `fromDocument` and `reads`, to copy its value from a client's metadata document.
- The cards of packages that talk to a server the deployment provides (`redis`, `mail-smtp`) say what it must be, under Deployment.
- A [recipe for a first login](docs/recipe-first-login.md), from generation to a token.

### Fixed

- `federation-grants` audits a route the store cannot answer: the token and revoke routes as their refusal with the reason `unavailable`, the browser routes as `federation.grant.authorization_failed` with the outcome `unavailable`.
- `federation-grants` audits an authorization right after the grant is activated, so a failure tidying up afterwards no longer leaves it audited only as a failure; activation refuses an intent that lapsed during the upstream exchange.
- `mfa-witness-http`: a write's deadline fell after outbound gave the call up, where outbound's timeout was the shorter; it now ends when outbound gives up.
- A login through an upstream that a second factor held answered the upstream's callback with JSON a browser cannot act on; with `federation.held-page` set, the browser goes there to go on.
- A refused client authentication at the token, introspection, revocation and device authorization endpoints is recorded as `client.authentication.failure`, with `clients`' `reason` and `source`, never the client id claimed. `authenticateClient` takes the audit as its third argument.
- `passkey-registration` records `passkey.registered`, with the subject and `source`, once a passkey is kept; it needs `audit` composed.

### Removed

- `federation-store`.
- For modules of your own: `refresh`'s `lineage.of` and `lineage.adopt` (`start` remains); `consent`'s `displayed`, a client source writing consent's section itself or taking it from `clientSection.fromDocument`; `factors.bind`'s `recoveryCodes` and `recoveryCodesFactor`; and `mfaReset` from `mfa-flows`, imported from `mfa-reset` now.

## [0.18.0-rc.2] - 2026-10-20

What to change from rc.1 is in [From 0.18.0-rc.1](docs/migration.md#from-0180-rc1).

### Security

- `mfa`: an enrollment begun at login could add a further factor after the account's first factor was registered; removing a factor or reissuing recovery codes could pass on what is allowed to an account with no factor while another request bound one; and two first enrollments at once could both bind.
- `mfa-flows`: recovery codes that were never shown could stay usable; an enrollment could complete after a reset or a revocation that came while it was under way; an enrollment begun before a subject revocation could still bind after the revocation completed; recovery codes from a first binding could be shown after a revocation completed.
- `mfa-management`: a session opened before a subject revocation could remove a factor, or reissue and receive recovery codes, after the revocation completed.
- `federation-grants`: a refresh could hand out a token after the grant had ended or its subject had been revoked, a request that waited for the refresh lock included; a grant past its end is treated as ended everywhere.
- `session-lifecycle`: an explicit close of a session past its lifetime did not revoke the session's tokens; a session revoked while its entry requirements were asked could still enter.
- `refresh`: an access token from a refresh could outlive the session of its family.
- `code-grant`, `device-grant`: an access token could live past the end of the session it was issued in.
- `device-grant`: a device approval's token could be recorded nowhere, and outlive a logout, where no module recorded session tokens; such an app now refuses to boot.
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
- Boot refusals, in every module, name the setting by its place in the settings and never show its value. Each says what is wrong: a file that does not parse, at its line and column; a required key left unset, as `required, and not set`; a missing or empty `audit.receivers`, what to name; a destination outbound refuses, which of outbound's keys lets it through; and an empty or unparsable origin or endpoint is refused rather than stopping the app with an error.
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
- Documents: the [route reference](docs/routes.md), a [login page guide](docs/login-page.md), a [recipe for a login page with a second factor](docs/recipe-mfa-page.md), recorded from a running app and checked on every change by the new `conformance-recipes` tests, a [recipe for a grant of your own](docs/recipe-external-grant.md), in a package outside the repository, built and checked against the published packages before each release, a [release guide](docs/releasing.md), the [security policy](SECURITY.md), a [contributing guide](CONTRIBUTING.md) and the README in Japanese.

### Removed

- For modules and adapters of your own: `session`'s `stillOpen`, `openContext` and `endsAt`; `Cookies.read`; `secretChecker`; `answeringUnavailable`; `outbound`'s `outboundPolicy`, replaced by `outboundRefusals`; `mfa`'s `recent` and `provenRecently`, moved to `session` and `mfa-entry`; and the `store` calls nothing used. `mfa`'s `countingHeld` takes where it is asked, and its `remove` and `reissue` take the fence answered before the change. Each one's replacement is in [From 0.18.0-rc.1](docs/migration.md#from-0180-rc1).

## [0.18.0-rc.1] - 2026-10-17

A rewrite of 0.17 as modules assembled by a generated app, published as one package per concern under new names. Configuration is rewritten, stored state does not carry over, and several settings and requests that 0.17 accepted are refused. Read the [migration guide](docs/migration.md) before moving a 0.17 deployment.
