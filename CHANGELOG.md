# Changelog

Notable changes, newest first, in the form of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). What an operator must do for each change is in the [migration guide](docs/migration.md).

Changes up to 0.17.0 are in [the 0.17.0 changelog](https://github.com/o3co/auth.provider/blob/v0.17.0/CHANGELOG.md).

## [0.19.0] - 2026-11-01

Read the [migration guide](docs/migration.md) before upgrading from 0.18: each line below that links an upgrade notice is a change an operator or the author of a module of their own must act on, and the notice says what to do.

### Added

- `mfa-witness-http`: the second-factor witness at the ledger ([U-0.19-8](docs/migration.md#u-0.19-8)).
- `kernel`: the deployment's environment ([U-0.19-37](docs/migration.md#u-0.19-37)).
- `idp-oidc`: an OpenID Connect IdP can read its upstream's UserInfo ([U-0.19-56](docs/migration.md#u-0.19-56)).
- `claims-selection`, `authorize`, `oidc`, `userinfo`, `refresh`: the `claims` request parameter is taken for standard claims ([U-0.19-58](docs/migration.md#u-0.19-58)).
- `users-http`: the password call can answer no such user as a lookup does ([U-0.19-112](docs/migration.md#u-0.19-112)).

### Changed

- An app generated with 0.18 lists the modules it composes ([U-0.19-1](docs/migration.md#u-0.19-1)).
- `mfa`: upgrade every instance, then look for second factors left without their claim ([U-0.19-3](docs/migration.md#u-0.19-3)).
- `mfa`, `mfa-store`: a factor store of your own ([U-0.19-4](docs/migration.md#u-0.19-4)).
- `store`, `redis`: a store adapter of your own ([U-0.19-5](docs/migration.md#u-0.19-5)).
- `webauthn`: a passkey store of your own ([U-0.19-6](docs/migration.md#u-0.19-6)).
- `redis`: Redis stays one server ([U-0.19-7](docs/migration.md#u-0.19-7)).
- `mfa-witness-http`: the ledger's read answers the mark's token ([U-0.19-9](docs/migration.md#u-0.19-9)).
- `mfa-witness-http`: a second-factor witness of your own ([U-0.19-10](docs/migration.md#u-0.19-10)).
- `mfa-witnessing`: the `witness-backfill` script ([U-0.19-11](docs/migration.md#u-0.19-11)).
- Code that reads mfa's decisions ([U-0.19-12](docs/migration.md#u-0.19-12)).
- `mfa`, `mfa-witnessing`: a witnessing of your own ([U-0.19-13](docs/migration.md#u-0.19-13)).
- Passkeys are kept by `passkeys`, apart from `webauthn` ([U-0.19-14](docs/migration.md#u-0.19-14)).
- `webauthn-login`, `mfa-webauthn`: passkeys prove `pop`, never `hwk` or `swk` ([U-0.19-17](docs/migration.md#u-0.19-17)).
- `mfa-flows`: a login whose amr holds `mfa` passes the second-factor gate ([U-0.19-18](docs/migration.md#u-0.19-18)).
- A client metadata section of your own that a metadata document fills ([U-0.19-19](docs/migration.md#u-0.19-19)).
- `clients`: a `Clients` of your own ([U-0.19-20](docs/migration.md#u-0.19-20)).
- `kinds`: code that reads the package kinds from `combinations` ([U-0.19-21](docs/migration.md#u-0.19-21)).
- `mfa-reset`: an operator's reset of second factors ([U-0.19-22](docs/migration.md#u-0.19-22)).
- `mfa-email`: a code by email as a second factor ([U-0.19-23](docs/migration.md#u-0.19-23)).
- Federation grants' browser half is the package `federation-grants-connect` now ([U-0.19-24](docs/migration.md#u-0.19-24)).
- `acr`: an app composed by hand with `acr` ([U-0.19-25](docs/migration.md#u-0.19-25)).
- `client-credentials`: the client credentials grant is a module of its own ([U-0.19-26](docs/migration.md#u-0.19-26)).
- A client allowed a grant that nothing composed serves now refuses boot ([U-0.19-27](docs/migration.md#u-0.19-27)).
- Code that imports `clientCredentialsGrantType` ([U-0.19-28](docs/migration.md#u-0.19-28)).
- `users`: users asks for a link store in every composition ([U-0.19-34](docs/migration.md#u-0.19-34)).
- `kernel`: a module of your own declares what it takes ([U-0.19-35](docs/migration.md#u-0.19-35)).
- An app generated before 0.19 does not read `KERNEL_ENVIRONMENT` ([U-0.19-38](docs/migration.md#u-0.19-38)).
- `issuer`: a plain-http `issuer.url` ([U-0.19-39](docs/migration.md#u-0.19-39)).
- A registered client's back-channel logout URL ([U-0.19-40](docs/migration.md#u-0.19-40)).
- `kernel`: a `replicaSafe` function answers a boolean ([U-0.19-41](docs/migration.md#u-0.19-41)).
- `jwt-bearer`: a JWT bearer assertion is taken only while a second of its life is left ([U-0.19-46](docs/migration.md#u-0.19-46)).
- `client-assertion`: `accept-loose-audience` stays, and each start names the clients that set it ([U-0.19-49](docs/migration.md#u-0.19-49)).
- `rp-logout`: a logout request sending a parameter twice is refused ([U-0.19-54](docs/migration.md#u-0.19-54)).
- `session`: a `Sessions` of your own ([U-0.19-57](docs/migration.md#u-0.19-57)).
- `token-endpoint`: an app that composes `token-endpoint` and no grant refuses to boot ([U-0.19-60](docs/migration.md#u-0.19-60)).
- `authorize`: `offline_access` is ignored in every authorization request, whatever the client is allowed ([U-0.19-62](docs/migration.md#u-0.19-62)).
- `token-exchange`: token exchange takes the lifetime asked as `o3co_expires_in` ([U-0.19-68](docs/migration.md#u-0.19-68)).
- `federation-grants`: a federation grant connection's `resource` with a fragment or a query refuses to boot ([U-0.19-70](docs/migration.md#u-0.19-70)).
- `users`: a user's `email` is taken only as RFC 5322's addr-spec in ASCII, and a `name` only as text holding more than blanks ([U-0.19-71](docs/migration.md#u-0.19-71)).
- `keys`, `create-app`: a new project's signing key is RSA, for RS256 ([U-0.19-73](docs/migration.md#u-0.19-73)).
- `kernel`: a module of your own declares whether it is safe on several instances ([U-0.19-74](docs/migration.md#u-0.19-74)).
- `client-allowance`: `offline_access` in a client's allowed scopes refuses boot ([U-0.19-76](docs/migration.md#u-0.19-76)).
- `clients-cimd`: `offline_access` in the ceiling of Client ID Metadata Document clients refuses boot ([U-0.19-78](docs/migration.md#u-0.19-78)).
- `users`: a registered user's `email_verified` needs its `email` ([U-0.19-79](docs/migration.md#u-0.19-79)).
- `authorize`: `acr_values` is a voluntary request ([U-0.19-80](docs/migration.md#u-0.19-80)).
- `clients-cimd`, `outbound`: `clients-cimd` needs a share of the lookups for the names its clients' documents give ([U-0.19-84](docs/migration.md#u-0.19-84)).
- `http`, `keys`: a `null` member in JSON a module of your own answers or signs is refused ([U-0.19-85](docs/migration.md#u-0.19-85)).
- `authorize`: a browser with no session logs in before a refusal goes back ([U-0.19-87](docs/migration.md#u-0.19-87)).
- `oidc`: ID tokens are signed with RS256 unless the operator writes another, and a client is held to it ([U-0.19-88](docs/migration.md#u-0.19-88)).
- `authorize`: an outage before the browser's session is found is answered at the endpoint ([U-0.19-89](docs/migration.md#u-0.19-89)).
- `redis`: `redis.url` takes no query ([U-0.19-90](docs/migration.md#u-0.19-90)).
- `acr`: an acr named as an integer comes first in the table, and each start warns of it ([U-0.19-91](docs/migration.md#u-0.19-91)).
- `keys`: a `Keys` of your own ([U-0.19-92](docs/migration.md#u-0.19-92)).
- `acr`: an `Acr` of your own ([U-0.19-93](docs/migration.md#u-0.19-93)).
- `login-gates`: a login gate may refuse a login ([U-0.19-94](docs/migration.md#u-0.19-94)).
- `audit`: `audit.receivers = none` warns at every boot ([U-0.19-98](docs/migration.md#u-0.19-98)).
- `session`, `login-password`, `login-passkey`: a password or passkey login is authenticated when it completes, a gate's wait included ([U-0.19-99](docs/migration.md#u-0.19-99)).
- `redis`: a Redis reached in the clear off the host is warned of at every start ([U-0.19-102](docs/migration.md#u-0.19-102)).
- `app-output`: a generated app's image follows one Node 24 minor ([U-0.19-104](docs/migration.md#u-0.19-104)).
- `idp-google`: a Google IdP's setting for a callback without `iss` is `accept-missing-iss` ([U-0.19-105](docs/migration.md#u-0.19-105)).
- `mail`: `mail.accept-unsent` warns at every start ([U-0.19-106](docs/migration.md#u-0.19-106)).
- `store`: `store.accept-volatile` warns at every start that uses it ([U-0.19-107](docs/migration.md#u-0.19-107)).
- `rate-limit`: `rate-limit.fail-mode = open` warns at every start ([U-0.19-108](docs/migration.md#u-0.19-108)).
- `tokens`: `tokens.revocation = unsupported` warns at every start ([U-0.19-109](docs/migration.md#u-0.19-109)).
- `mtls`: `mtls.mode = self-signed` warns at every start ([U-0.19-110](docs/migration.md#u-0.19-110)).
- `tokens`: `tokens.subject-check = none` warns at every start ([U-0.19-111](docs/migration.md#u-0.19-111)).
- `userinfo`, `rp-logout`: unavailable warnings of userinfo and RP-initiated logout ([U-0.19-113](docs/migration.md#u-0.19-113)).
- Every setting that switches a protection off or widens whom a module trusts warns at every start where it takes effect ([U-0.19-114](docs/migration.md#u-0.19-114)).
- `host-entries`, `outbound-policy`, `outbound`, `idp-oidc`, `mtls`: `outbound`'s hosts and pairs are read as written ([U-0.19-116](docs/migration.md#u-0.19-116)).
- `audit`: audit receiver warnings are named as every other log event is ([U-0.19-118](docs/migration.md#u-0.19-118)).
- `kernel`: in development, every value a production deployment refuses is warned of at every start ([U-0.19-119](docs/migration.md#u-0.19-119)).
- `kernel`, `jwt-bearer`, `audit`, `mfa-witnessing`, `passkey-witnessing`: a warning names what it is about in a field a log line keeps ([U-0.19-120](docs/migration.md#u-0.19-120)).

### Deprecated

- `users-http`: the password call's `401` read as no user with that identifier and password, kept for 0.17's ledgers. Answer `404` with `{"error":"not_found"}` instead ([U-0.19-112](docs/migration.md#u-0.19-112)).
- `mfa-witness-http`: running without `withdraw-url`. Serve the ledger's withdraw route and set `mfa-witness-http.withdraw-url` ([U-0.19-8](docs/migration.md#u-0.19-8)).

### Removed

- `federation-grants.revocation-skew` is gone ([U-0.19-15](docs/migration.md#u-0.19-15)).
- `ledger-fakes`: the fake HTTP ledgers are gone from the published test helpers ([U-0.19-31](docs/migration.md#u-0.19-31)).

### Fixed

- A generated app's entry and `reseal` hand on what they write before they exit ([U-0.19-2](docs/migration.md#u-0.19-2)).
- `outbound`: a name is resolved as the URL writes it, a trailing dot kept ([U-0.19-30](docs/migration.md#u-0.19-30)).
- `kernel`: a boot refused after its modules were built runs their stop hooks first ([U-0.19-32](docs/migration.md#u-0.19-32)).
- `tokens`, `token-exchange`: no access token is issued with less than a second of life ([U-0.19-50](docs/migration.md#u-0.19-50)).
- `clients`, `client-assertion`, `token-endpoint`: a refused client assertion is answered `invalid_client` ([U-0.19-55](docs/migration.md#u-0.19-55)).
- `session-grant`: a session grant without a session is refused `400 invalid_grant` ([U-0.19-66](docs/migration.md#u-0.19-66)).
- `mtls`: a certificate refused at issuance is answered `invalid_client` ([U-0.19-67](docs/migration.md#u-0.19-67)).
- `resource-indicators`, `token-exchange`: a `resource` that is not an absolute URI, or carries a fragment, is refused `invalid_target` ([U-0.19-69](docs/migration.md#u-0.19-69)).
- `authorize`: a `request_uri` at the authorization endpoint is answered `request_uri_not_supported` ([U-0.19-82](docs/migration.md#u-0.19-82)).
- A generated app waits for its stop when the same signal comes again ([U-0.19-100](docs/migration.md#u-0.19-100)).

### Security

- A held login's upstream tokens are sealed through the bridge `upstream-handoff-seal` ([U-0.19-16](docs/migration.md#u-0.19-16)).
- Names resolve in two helper processes by default ([U-0.19-29](docs/migration.md#u-0.19-29)).
- `login-gates`: a login's `redirect_to` is taken only as written ([U-0.19-33](docs/migration.md#u-0.19-33)).
- A client's `federation-grants` return URIs ([U-0.19-36](docs/migration.md#u-0.19-36)).
- `jwt-bearer`: a JWT bearer assertion's `iss` is taken only as a string, and every refusal before its signature holds says `untrusted signer` ([U-0.19-42](docs/migration.md#u-0.19-42)).
- `external-jwt`, `client-assertion`, `idp-oidc`: each key is read under one algorithm ([U-0.19-43](docs/migration.md#u-0.19-43)).
- `exchange-id-tokens`: an id_token's record is kept by the longest `max-age` and `clock-skew` any section may give ([U-0.19-44](docs/migration.md#u-0.19-44)).
- `exchange-id-tokens`: each id_token's record lasts longer ([U-0.19-45](docs/migration.md#u-0.19-45)).
- `jwt-bearer`: a trusted issuer whose every signer becomes a subject names its subjects, or says it takes any ([U-0.19-47](docs/migration.md#u-0.19-47)).
- `jwt-bearer`: each spent JWT bearer assertion's record lasts longer, by no setting ([U-0.19-48](docs/migration.md#u-0.19-48)).
- `jwt-bearer`: an ID-JAG is refused at every trusted issuer but one that takes the profile ([U-0.19-51](docs/migration.md#u-0.19-51)).
- `rp-logout`: a logout asking an unregistered return is refused ([U-0.19-52](docs/migration.md#u-0.19-52)).
- `rp-logout`: a logout naming another client than its hint's is refused ([U-0.19-53](docs/migration.md#u-0.19-53)).
- `rp-logout`, `csrf`: `rp-logout` checks CSRF, so it needs `csrf` and `http.public-origin` ([U-0.19-59](docs/migration.md#u-0.19-59)).
- `authorize`, `oidc`: an `id_token_hint` names the only person a code may be for, and `prompt=select_account` is refused ([U-0.19-61](docs/migration.md#u-0.19-61)).
- `idp-oidc`: an OpenID Connect IdP's callback must carry `iss` ([U-0.19-63](docs/migration.md#u-0.19-63)).
- `clients-cimd`: Client ID Metadata Documents need their hosts chosen ([U-0.19-64](docs/migration.md#u-0.19-64)).
- `upstream-client`, `oidc`: an upstream id_token naming another audience is refused ([U-0.19-65](docs/migration.md#u-0.19-65)).
- `federation`, `federation-link`: a login through an upstream lands by `303` ([U-0.19-72](docs/migration.md#u-0.19-72)).
- `outbound`: outbound TLS takes TLS 1.2 or later with ECDHE and an AEAD cipher alone ([U-0.19-75](docs/migration.md#u-0.19-75)).
- `mail-smtp`, `redis`: the SMTP relay and Redis over TLS take the same floor as outbound ([U-0.19-77](docs/migration.md#u-0.19-77)).
- `rp-logout`: a logout without `id_token_hint` asks the person ([U-0.19-81](docs/migration.md#u-0.19-81)).
- `clients`: a method of your own at `authMethods` that would sign with nothing refuses boot ([U-0.19-83](docs/migration.md#u-0.19-83)).
- `rp-logout`: a logout closes without asking only the session the browser holds ([U-0.19-86](docs/migration.md#u-0.19-86)).
- `reauth`, `authorize`: `max_age` is checked as the last step before the code is issued ([U-0.19-95](docs/migration.md#u-0.19-95)).
- `federation-tokens`: a refresh answering a scope wider than its login granted, or one that cannot be read, is refused ([U-0.19-96](docs/migration.md#u-0.19-96)).
- `tls-options`, `outbound`, `redis`: `NODE_TLS_REJECT_UNAUTHORIZED` no longer switches off the provider's certificate checks ([U-0.19-97](docs/migration.md#u-0.19-97)).
- `external-jwt`, `jwt-bearer`, `client-assertion`: an assertion lives no longer than its lifetime setting, from `iat` to `exp` ([U-0.19-101](docs/migration.md#u-0.19-101)).
- `tokens`, `token-exchange`: token exchange refuses to boot where `tokens` checks no subject ([U-0.19-103](docs/migration.md#u-0.19-103)).
- `dpop`: DPoP asks a nonce at the token endpoint by default ([U-0.19-115](docs/migration.md#u-0.19-115)).
- `mfa-flows`: the second-factor lockout's numbers are bounded ([U-0.19-117](docs/migration.md#u-0.19-117)).
- Known gap: RFC 6750 §5.2's check that an upstream server's certificate has not been revoked is not done by `outbound`, which checks the chain and the name alone; it is left to the egress proxy or the platform ([#2519](https://github.com/o3co/auth.provider/issues/2519); [compliance report](docs/compliance/rfc6750.md)).

## [0.18.6] - 2026-10-25

### Security

- `client-assertion`: a client's assertion (`private_key_jwt`) must now name the issuer alone, as one string, as its `aud`. Until now it could also name the token endpoint URL, or an array with one matching member. That left clients open to the audience injection OpenID Foundation disclosed in 2025: a client that also uses the same key and `client_id` at a malicious or compromised authorization server could have an assertion collected there and redeemed first here. With `client_credentials` allowed, that issues tokens within the client's allowances. Clients that already send the issuer as a string keep working. Others must change how they build assertions; `sections.client-assertion.accept-loose-audience: true` on a client keeps the old acceptance for that client for now, warning `client-assertion.loose_audience` each time, and leaves it exposed while set. See the migration guide (From 0.18.5). Rolling back to 0.18.5 needs that key removed, since 0.18.5 refuses it.

## [0.18.5] - 2026-10-24

### Security

- `mail-smtp`: nodemailer 10.1.2 → 10.1.7, past three moderate advisories in nodemailer's address parser (GHSA-85x2-q946-cp5h, GHSA-8c8m-p3m8-cjg8, GHSA-m943-m63m-w62w): a nested comment, a `;` inside a quoted string or comment, or a `>` inside a quoted local part could end an address early, so a message could go to a recipient other than the one its header names. That is nodemailer's exposure; `mail-smtp` never parses a recipient (it writes `To` itself and passes its own envelope), so no deployment could misdeliver through it. The parser does read the configured `from`: a `from` that the old parser happened to accept but is no address, such as `(noreply@example.test)` written as a comment alone, now refuses boot. Write `from` as an address, optionally with a display name.

## [0.18.4] - 2026-10-23

### Fixed

- `federation-grants`: a browser that a connect sent to `login-page` (no session) or `step-up-page` (a session short of a requirement) could not come back to it. The connect's URL, given as `redirect_to`, was no return target of `login-gates`, so a login through an upstream or by password answered `400 invalid_redirect` and the connect did not go on. The connect's path is now a return path, on the public origin alone. Nothing to change; a login page that kept `redirect_to` itself and went back on its own keeps working.

## [0.18.3] - 2026-10-23

### Security

- `address-reach`: four cloud addresses in `fc00::/7` were taken as private, so `outbound.internal-hosts` and `outbound.plain-internal` reached them where a listed name came to resolve there: AWS EKS Pod Identity's credential endpoint over IPv6 (`fd00:ec2::23`), and the metadata services over IPv6 of Akamai Cloud (Linode, `fd00:a9fe:a9fe::1`), Scaleway (`fd00:42::42`) and Oracle Cloud (`fd00:c1::a9fe:a9fe`). Each is now refused as a special address, as the other cloud metadata addresses are.
- `address-reach`: Azure's platform address `168.63.129.16`, public but the host node's in every region (WireServer, the platform's DNS and DHCP), was reached under `outbound.allow-any-public`, or through an allowed name that came to resolve there; it is now refused as a special address.

## [0.18.2] - 2026-10-22

### Added

- `outbound.plain-ipv4`, a list of `host:port` pairs of `plain-loopback` or `plain-internal`: plain http to such a pair resolves its name to IPv4 addresses alone, checks every one of them and reaches the first, and neither checks nor reaches an IPv6 one. With ECS Service Connect, which writes each name in the hosts file with an IPv4 address and an IPv6 one that in the environment reported does not reach, a `plain-internal` pair was refused as `plain-public`; naming it here too takes it. A pair is named by its host name, never an address. Unset, nothing changes. A configuration naming the key is refused at boot by an earlier version, which does not know it.

### Fixed

- A generated app's `witness-backfill` script told a refused boot by the kernel's class, so where the kernel was bundled twice it threw the refusal on as a crash instead of writing each refusal and exiting 78, as the app's entry and `reseal` already did; it now tells it by the kernel's mark (`BootRefused.is`). An app generated before changes one line of `src/witness-backfill.ts`, as [From 0.18.1](docs/migration.md#from-0181) says, or is generated again.

## [0.18.1] - 2026-10-22

### Security

- A generated app pins pnpm 11.28.7 in its manifest (`packageManager`), which its image installs with, and the repository builds with it; both named 11.3.0. The 2026-10-21 pnpm security release refuses registry metadata that names another package than the one asked for, applies `trustPolicy` to the pinned pnpm, and caps a package's unpacked size (`maxTarballUnpackedSize`). An app generated before changes its `packageManager` to `pnpm@11.28.7`, as [From 0.18.0](docs/migration.md#from-0180) says.

## [0.18.0] - 2026-10-22

A rewrite of 0.17 as modules assembled by a generated app, published as one package per concern under new names. Configuration is rewritten, stored state does not carry over, and several settings and requests that 0.17 accepted are refused. Read the [migration guide](docs/migration.md) before moving a 0.17 deployment.

**Release candidates.** `0.18.0-rc.1` to `0.18.0-rc.5` were pre-releases, published on npm under the `next` dist-tag. This section covers every change since 0.17.0 and supersedes them; what each candidate changed is in [the 0.18.0-rc.5 changelog](https://github.com/o3co/auth.provider/blob/v0.18.0-rc.5/CHANGELOG.md). A deployment on a candidate reads the migration guide's section from its candidate, beginning at [From 0.18.0-rc.1](docs/migration.md#from-0180-rc1), and each after it; the changes since rc.5 are below.

### Security

- A generated app's image builds on `node:24-alpine`, Node 24's latest, with neither patch nor digest pinned, so each build takes Node's security fixes; it pinned Node 24.21.0, which the 2026-10-21 Node.js security release left vulnerable. An app generated before changes its Dockerfile's `FROM` to `node:24-alpine` and builds its image again. See [From 0.18.0-rc.5](docs/migration.md#from-0180-rc5).

### Changed

- **Breaking**, for a Redis store, since rc.5: `redis` refuses boot, named, where `redis.replication` is set and the confirming connection reaches another server than the operations, as a DNS name or a load balancer over several servers may send it, and where the server cannot run the store's scripts, as one whose Lua lacks `cjson`; rc.5 booted and answered `503` to the writes. Either, found later, makes `/readyz` answer `503`, named under `redis.settings_unmet`. See [From 0.18.0-rc.5](docs/migration.md#from-0180-rc5).
