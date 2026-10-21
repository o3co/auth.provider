# Changelog

Notable changes, newest first, in the form of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Release candidates have sections of their own; what an operator must do for each change is in the [migration guide](docs/migration.md).

Changes up to 0.17.0 are in [the 0.17.0 changelog](https://github.com/o3co/auth.provider/blob/v0.17.0/CHANGELOG.md).

## [0.18.0-rc.5] - 2026-10-21

What to change from rc.4 is in [From 0.18.0-rc.4](docs/migration.md#from-0180-rc4); coming from an earlier release candidate, read its section first.

### Security

- `rp-logout`: a POST to `/oauth/logout` took an `id_token_hint` issued more than a day ago, so a page on another site holding an old ID token could close a session still open; a hint that old is now refused `400 invalid_token` by POST as by GET, and nothing is closed.
- `session-tokens`: a token an add pushed out of a session between the sweep's last read of that session and its taking the session off its list could still miss the sweep's retry; the sweep now reads again after taking a session off, and lists it again where a token awaits.
- `request-source`: `http.trusted-proxies` entries that together covered every address of a family, such as two `/1` halves or the IPv4 halves written as mapped IPv6, made every client a proxy, though each such entry alone refuses boot; such a list now refuses boot.
- `outbound`: slow names an outside party chose, such as a client's metadata document URL, could take every name lookup, leaving every other request by name refused as busy; those names now take at most half of outbound's lookups, rounded down, and requests for a name already being resolved share its one lookup.
- `federation`: a login's start that this deployment's own page did not make goes on with the browser's live round trip of that IdP instead of replacing it, so a start another site sends a browser to can no longer end the login it has under way. The start asks the upstream the first start's request whole, its return target and `prompt` too.
- `federation`: a link's callback checks the session at `credentials` before the link, right after it and after the tokens' hand-off; a session closed, short of a requirement or logged in as someone else meanwhile is answered `401 login_required` (`link_refused`, reason `session_closed_during_link`), and what the request wrote is undone (the tokens withdrawn, a link it wrote unlinked). A hand-off that fails while the session closes undoes the link too.
- `outbound-policy`: a `plain-loopback` pair whose name resolved to an IPv6 form that carries 127/8 unmapped (`::7f00:1`, `::ffff:0:7f00:1`) was taken as loopback, so plain http, a credential included, could go to an address no connection takes to loopback; such an address is now refused as special.

### Changed

- **Breaking**: `clients-cimd` refuses boot where Node's threadpool (`UV_THREADPOOL_SIZE`) is 2 or less, as outbound then gives a metadata document's names no lookup and every fetch would be unavailable; the runbook asks for 4 or more, and the default, 4, is enough.
- **Breaking**, for a module of your own: `keys.sign` and `keys.verify` refuse the access token type (`at+jwt`) with a `TypeError`, as only `tokens` signs and verifies access tokens. A module that signed one moves to `tokens`' `issue`, and one that verified one to `verifyAccess`; the migration guide says how to end the tokens it already signed.
- `tokens`' `verifyAccess` refuses an access token whose `exp` comes before its `iat`, whose `iat` is more than 60 seconds ahead of the clock, or with more than a day between them, as `tokens` never issues one.
- **Breaking**, for a module of your own that issues access tokens without `tokens`: `verifyAccess` refuses an `at+jwt` carrying a name reserved for what `tokens` never writes (`nbf`, `roles`, `email` and the like); a token over 16 KiB, or with an actor chain over 16 deep, is neither issued nor read.
- **Breaking**, for an app composed by hand: an enrollment witness composed beside `mfa` needs the new bridge `mfa-witnessing`, and boot is refused without it, so the witness is never silently dropped; `combinations` composes it wherever `mfa` and `mfa-witness-http` are composed.
- `users-http`, `mfa-witness-http`, `signer-keys-http` and `audit-http` give a credential refusal in `outbound-policy`'s words, which name `plain-internal` beside `plain-loopback`.
- `outbound.plain-internal`: a pair is reached where every address its name resolves to is private or loopback, so a sidecar answering on 127/8 or `::1` needs no list of its own; a public answer among them is still `plain-public`, and link-local, metadata and other special-purpose answers are still refused.
- `url-setting`: a URL that may use plain http on a loopback host now also takes a name under `localhost` (`http://app.localhost:3000/`), `localhost.` with its trailing dot, and 127/8 mapped into IPv6 (`http://[::ffff:7f00:1]/`); `localhost.localdomain`, `0.0.0.0` and any other host over http still refuse boot.
- `mail-smtp` with `security = none` boots for the same loopback hosts by name, and sends only where the connected peer is a loopback address, 127/8 mapped into IPv6 in any spelling included; an IPv6 host is written without brackets.
- `idp-apple`: a callback on a name under `localhost`, or on 127/8 mapped into IPv6, refuses boot, as `localhost` and 127/8 already did.
- `outbound` warns that a proxy's credentials go in the clear unless the proxy is written as a loopback address; a proxy named by a name, `localhost` included, now warns, as its name is never resolved before the credentials go.
- An address written in a URL is reached as written: an IPv6 form that carries an IPv4 address (`[::ffff:5db8:d70e]`, `[::5db8:d70e]`) is refused as a special address, as a resolved answer in that form already was, where rc.4 took it as the IPv4 address.
- `federation`: a link's callback asks the session at `credentials` (it asked at `use`). Without `mfa`, `credentials` is a sign-in within 300 s, so a link whose IdP step takes longer than that is now refused.
- **Breaking**, for an IdP reached over plain http: an OpenID Connect IdP's authorization and end-of-session endpoints, and a GitHub IdP's `authorization-endpoint`, where the browser goes, must be https, or plain http at a loopback name or at the origin of the issuer or a given endpoint whose `host:port` `outbound.plain-internal` names; any other refuses boot. An issuer on plain http no longer makes plain http right for every endpoint its description names.
- `upstream-round-trip`: `roundTrips.current` reads the browser's live round trip without taking it.
- `url-setting`: `urlsChecked` takes, at each key, the configured URL it is sent for.
- `federation-link`: the link to an upstream identity is a package of its own, `federation-link`, a bridge of `federation`; `combinations` and `create-auth-provider` compose it wherever `federation` is composed, as before. Its rules, answers and audit events (`federation.identity.linked`, `link_refused`) are unchanged.
- `federation`: a start asking `link=1` (or `true`) where no continuation named `link` is composed is refused `400 continuation_unavailable`, warned `federation.continuation_missing`; before, the link was always there.
- `federation`: a round trip carries the continuation it goes on to and what that kept, in place of a link's own fields; a link's round trip begun under rc.4 and taken after the upgrade is refused `invalid_state`, and is started again.
- `client.authentication.failure` is declared by `clients` (`@mod/clients/audit-events`), no longer by `token-endpoint`, with the same name and attributes; a route of your own that calls `authenticate` records its refusal through `clients`' `recordRefusedAuthentication`. A receiver needs no change.
- `loadConfig` and `ConfigSource` moved, unchanged, from the kernel to the new `config-files` module. A published app imports them from `@o3co/auth-provider-foundation/config-files` instead of `/kernel` and upgrades the foundation package, adding no dependency; an app in the workspace imports `@mod/config-files` and adds it. An app generated with an earlier release candidate changes `src/main.ts` (and `src/reseal.ts`), or is generated again.
- **Breaking**, for a Redis that refuses a command the store needs: `redis` refuses boot, naming the command, where the server refuses `WAIT` (with replication) or a command the store's script calls, as a managed Redis or Valkey may; rc.4 booted and failed every write with `503`. A refusal that comes later makes `/readyz` answer `503`, named under `redis.settings_unmet`.
- **Breaking**, for an app composed by hand: `code-grant` refuses boot where nothing records its tokens to their session (`session-tokens`), and `mfa-flows` where nothing moves `mfa`'s fence on a subject's revocation (`mfa-revocation`), as `device-grant` and `session-grant` already refused; `combinations` composes both wherever they are needed.
- `create-auth-provider` with modules listed composes what they need to run, as a pattern does, and writes the app as a pattern's: its configuration file reads each key from the environment and holds no value, beside `.env.example`, `config/local.conf.example`, a Dockerfile, a README and `AGENTS.md`. Such an app refuses boot until `kernel.deployment` and the keys its README names are set. A generated image is given a port only where `http` is composed, and a health check only where `http-ops` is.
- **Breaking**, for a user ledger over HTTP: `users-http` reads a lookup's (`subject-url`, `upstream-url`) `404` as no such user only with `{"error":"not_found"}` in its JSON body, and a `410` only with `{"error":"gone"}`; any other `404` or `410` is unavailable (`503`), logged as `users-http.ledger_failed` with `reason: "unmarked"`. A ledger that answers an unknown user with a bare `404` adds that body, and refuses a caller it does not accept with `401` or `403`, never `404`.

### Added

- `outbound.plain-internal`: the `host:port` pairs plain http may reach at private addresses, for a URL of the operator's own configuration such as a ledger, never for one an outside party chose; every address the name resolves to must be private. What goes there is in the clear, so each boot that names pairs warns `outbound.plain_internal` with their count.
- Module `mfa-witnessing`: keeps the enrollment witness in line with `mfa`'s counting factors, and offers `witnessBackfill` to fill the mark of a subject that enrolled before the witness was composed. It now declares the audit event `mfa.enrollment_inconsistent`, with the same attributes.
- A grant of your own may add claims to the access tokens it issues (`AccessGrant.claims`), checked against reserved names and limits (4 KiB in all, 8 deep); a refreshed or exchanged token carries none of them. `token.issued` names the added claims in `claims`, never their values, and how many names did not fit in `claims_left`.
- For modules of your own: an issuance policy's `judge` takes an abort signal as its optional second argument, aborted when `tokens.issuance-timeout` passes, so it can stop its own work; `outbound-policy`'s `Narrower.outsideChosen` marks destinations an outside party chooses, and `outboundLimits`' `lookupsOf` answers a caller's share of the name lookups.
- For modules of your own: `kernel`'s `readConfigured`, with its issue type `ConfigurationIssue`, the typed reading a section gets, for a value a section passes to a schema of its own.
- For modules of your own: `mfa`'s extension point `witnessing`, taking at most one contribution, which `mfa-witnessing` makes.
- For modules of your own: `url-setting`'s `isLoopbackName` and `address-reach`'s `isLoopbackAddress`, the one judgement of a loopback host by its name and of a loopback address; and `outbound.refusals`' optional `plainInternal`, whether a URL is let through as plain http to a `plain-internal` pair.
- Module `address-reach` (foundation): what an IP address reaches, as a connection reaches it: `isSpecialAddress`, `isPrivateAddress` (metadata excluded), `isLoopbackAddress` and `carriedIPv4`, taken out of `outbound-policy`, which keeps the destination rules.
- For modules of your own: `outbound-policy`'s optional `OutboundRefusals.browsedRefusal`, the judgement of a destination the browser is sent to: https anywhere, plain http only at a loopback name or where `plain-internal` takes it; `outbound` provides it.
- `contract(label, { takenBy })` names the modules that may take a contract; another module asking for it by `get` or `late` refuses boot, even when it catches the throw. `Assembly.get` is not bound.
- `keys.signing.secret-encoding` (`hex`, `base64` or `utf8`) names how an HS256 `secret` is read; unset, it is read as before, and named, only that reading is taken and a value it cannot read refuses boot. The strength rules apply to the bytes read. `utf8` reads it as 0.17 and the policy verifier do.
- A generated app's entry writes one warning on standard error at boot naming 0.17's environment variables that are set and that no configuration file reads, never their values, and boot goes on; `config-files` offers it as `unreadLegacyVariables` and `legacyVariablesWarning`. An app generated with an earlier release candidate gets it when generated again.
- For modules of your own: `upstreams`' extension point `upstreamContinuations`, where a round trip goes besides a login, chosen by name at its start.
- For modules of your own: `mfa`'s `fenceFollower`, the name the revocation follower that moves `mfa`'s fence goes by.
- For modules of your own: a failure another package throws is told by a mark rather than its class, so one thrown by a second bundled copy of that package is told too: `outbound`'s `isOutboundUnavailable`, `outbound-policy`'s `DestinationRefused.is`, `upstreams`' `UpstreamRefused.is` and `UpstreamMismatch.is`, and `kernel`'s `BootRefused.is`.

### Fixed

- `tokens`: an issuance policy that never answered held the token request open; the policies now answer within `tokens.issuance-timeout` together (default `10s`, from `1s` to `1m`), past which the issuance is unavailable (`503`).
- `mfa-email`: a right code failed its check where `users` kept no more verified contacts for the subject; it now passes, keeps no address, and logs `mfa-email.contact_not_kept`.
- `mfa`: with a witness composed, a first binding marked the witness before its write, so a write that failed left the subject unavailable until a reset; the mark now follows the write, and a first binding meeting a mark with no counting factor is unavailable before it writes, as its start is.
- `federation`: an IdP's own settings within `federation.idps` given by an environment variable or a quoted value, such as `discovery` or `require-iss`, were refused where the setting takes a boolean or a number; they are now converted as every section's settings are.
- `federation-tokens` and `federation-grants`: a refresh slower than its lock could race another host's; the lock is now kept while the upstream answers, and nothing is written once it is lost. `federation-tokens.lock-lifetime` is how long the lock lasts unless kept.
- `federation-tokens` and `federation-grants`: a refresh answering the access token already held, with a later end, made it live past its real end, handed out after the upstream would refuse it; the same token now keeps the earlier end.
- `device-grant`: a policy's refusal of an approval answers `403 access_denied` with its description shaped as every OAuth error's is: printable ASCII but `"` and `\`, any other character shown as `?`.
- For modules of your own: a login whose authentication time is neither epoch milliseconds from 0 to 8.64e15 nor `"unknown"` is refused with a `TypeError` before any session is closed or opened, by `session-lifecycle` and `session`'s stand-in alike; before, a negative or non-finite time reached what reads it, such as a device approval.
- `idp-oidc`, `idp-github`, `external-jwt`: an IdP at a private address (an OpenID Connect issuer and the endpoints you give it, its key set on the issuer's origin, a GitHub Enterprise's endpoints) is reached as the operator's configured URL, where `outbound.internal-hosts` lists its host, as 0.17 reached it. Boot checks each with the same narrowing as the request.
- `federation-grants`' client routes record a refused client authentication as `client.authentication.failure`, with `reason` and `source`, never the client id claimed.
- `users-http`, `mfa-witness-http` and `signer-keys-http` logged every outbound failure as `no-answer`, and `clients-cimd` fetched a refused metadata document again on every request, where outbound was bundled twice; outbound's failure is now read by its mark.
- Where `outbound-policy` was bundled twice, a destination refusal was missed: `users-http`, `mfa-witness-http` and `signer-keys-http` logged it as `no-answer`, `clients-cimd` fetched a refused metadata document again on every request, `mtls`, `external-jwt` and `rp-logout` threw it on as a fault (a back-channel notice was kept), and `idp-oidc` did not refuse boot under `issuer` with outbound's reason. Each now tells it by `DestinationRefused.is`.
- Where `upstreams` was bundled twice, an upstream's refusal or mismatch was missed: `federation` logged a refused exchange as failed and refused boot without the IdP type's own reason and key, `federation-grants` answered a refusal at a connection's callback or a refresh as a fault, and `upstream-client` put a new refusal in its place. Where the kernel was bundled twice, a generated app's entry threw a refused boot on as a crash, instead of writing each refusal and exiting 78; an app generated before gets this when generated again.
- `federation-tokens`: `post-logout-redirect-uris` are held to the rule every other source of redirect URIs follows: `javascript:`, plain http not at loopback, a fragment, userinfo and answer parameters refuse boot, and `https`, loopback `http` and reverse-domain schemes are taken.
- For modules of your own: `webauthn`'s `ceremonies.assert` refuses an assertion with no user handle (`user-handle`) for a request that named no credential, such as one made by `request([])`, as WebAuthn asks; the passkey login already refused it. A request naming credentials marks its challenge, so a caller keeps the challenge `request` returns and gives it back as kept, never one rebuilt from the client's answer.
- `clients-cimd` refuses a client id whose host has an empty label (`https://a..example/c`), as no DNS name.

### Removed

- **Breaking**, for a module of your own: `mfa` no longer re-exports `labels`' `isLabel`; take it from `labels`.

## [0.18.0-rc.4] - 2026-10-21

What to change from rc.3 is in [From 0.18.0-rc.3](docs/migration.md#from-0180-rc3); coming from an earlier release candidate, read its section first.

### Security

- `authorize`: the re-authentication a request asked for with `prompt=login` or `max_age` could be skipped by a login through an upstream, or loop there. The login page is now told of both beside `redirect_to`, and a request back from its login still not new enough, or carrying a re-authentication record that is not its own, is refused with `login_required`.
- `rp-logout`: a client's front-channel logout page, framed in the provider's logout page, could navigate the top window, submit forms or open popups; each frame is now sandboxed, keeping its scripts and its own origin.
- `outbound`: names that answer slowly, some of which an outside party chooses, could hold every thread of Node's threadpool, stalling hashing and the file system with them; at most half the threadpool now resolves names at once, and one lookup more is unavailable at once.
- `outbound-policy`: an address `outbound.deny` names was still reached through any name resolving to it; it is now refused wherever a name resolves to it.
- `tokens`: a caller changing its grant or limits while the issuance policies judged it had a token signed for what no policy judged; the policies and the signing now read one copy, taken before anything waits.
- `clients`: the time to refuse a client told whether its id existed; an unknown client, an invalid record and another method's client are now refused only after the work its credentials would cost.
- `mfa`: with a witness composed, a first binding whose value another factor held left the witness's mark with no factor, the subject unavailable until a reset; the value is checked again just before the mark.
- `federation-grants`: where an upstream answered a refresh `invalid_grant` or `interaction_required` and the grant's end could not be written, the held token was still handed out; the host whose write failed now refuses the grant under the upstream's reason until the held token ends, and a later request asks the upstream again.
- `federation-grants`: a client's renewals were not counted with its lodgings; they now share `lodges` per `lodge-window`, and past it a renewal answers `429` with `retry-after` and writes nothing.

### Changed

- Boot tells an upstream it could not reach from one that does not match its settings: an IdP whose opening is unavailable refuses boot as an upstream that could not be reached, under its key; a discovery document outbound refuses to fetch refuses boot at `issuer`, naming outbound's reason.
- An app `create-auth-provider` makes from listed packages is told to add the modules and settings they need before it starts, no longer to start as made.
- A login page that offers an upstream hands the `prompt` and `max_age` it is given to the upstream's start (`/session/oauth/federation/<idp>`).
- The issuer's metadata says `authorization_response_iss_parameter_supported: true`; every redirect answer already carried `iss`.
- An authentication method of your own may offer `decoy`, the work a verify would cost, which `clients` runs before refusing a client it cannot check.
- `federation` warns `federation.no_idps` at each boot where `federation.idps` names none, as every login then answers not found.
- An IdP's client id or secret of whitespace alone refuses boot, as an empty one does.

### Fixed

- The `oauth` bundle no longer installs `vitest`: `exchange-id-tokens` takes it as an optional peer, for the contract tests it offers.
- The migration guide says the shape of log and audit lines and the 0.17 filters that stop matching; that none of 0.17's environment variables is read or warned of, so they are removed before upgrading; that a user ledger refuses a caller with `401` or `403`, never `404`, as a lookup's `404` is no such user; that 0.18 decodes an HS256 secret where 0.17 took the string's own bytes, and how to keep 0.17's key; and that a client's session grant is under `sections.client-allowance.grants`, where it named a section that refuses boot.
- The runbook says what a managed Redis or Valkey with replicas must be set to, the commands it must allow, and what its failover keeps.
- The setting `keys.signing.secret` says its decoded bytes are the HMAC key, read as hex before base64.

## [0.18.0-rc.3] - 2026-10-20

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
