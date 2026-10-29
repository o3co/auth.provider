# Migration guide

This guide covers two upgrades: from 0.17 to 0.18, from here to [From 0.18 to 0.19](#from-018-to-019); and from 0.18 to 0.19 in that section, whose upgrade notices `U-0.19-<n>` an operator of 0.18 checks off.

0.18 replaces the 0.17 application with a set of modules assembled by a small generated app. Most endpoints, grants and login flows behave as before, but configuration is rewritten, several settings that 0.17 accepted now refuse boot, and some requests that 0.17 accepted are now refused.

The sections before [From 0.18 to 0.19](#from-018-to-019) are for operators moving an existing 0.17 deployment. Read them once end to end before you start: there is no in-place upgrade, and stored state does not carry over.

## Contents

- [Before you start](#before-you-start)
- [Packages](#packages)
- [What carries over](#what-carries-over)
- [Migration steps](#migration-steps)
- [How configuration works now](#how-configuration-works-now)
- [Configuration mapping](#configuration-mapping)
- [Newly refused at boot](#newly-refused-at-boot)
- [Behavior changes](#behavior-changes)
- [From 0.18.0-rc.1](#from-0180-rc1)
- [From 0.18.0-rc.2](#from-0180-rc2)
- [From 0.18.0-rc.3](#from-0180-rc3)
- [From 0.18.0-rc.4](#from-0180-rc4)
- [From 0.18.0-rc.5](#from-0180-rc5)
- [From 0.18.0](#from-0180)
- [From 0.18.1](#from-0181)
- [From 0.18.5](#from-0185)
- [From 0.18 to 0.19](#from-018-to-019)
- [Operational notes](#operational-notes)

## Before you start

- **0.18 is a breaking release under new package names.** Its packages are published under the same `@o3co/auth-provider-` scope, one per bundle, with new names; the 18 packages of 0.17 are deprecated.
- **Stored state is not migrated, and 0.18 ships no migration tool.** 0.18 reads none of 0.17's records. Users sign in again, and what they set up is lost unless you move it yourself; see [What carries over](#what-carries-over).
- **A drain that runs past its time exits as any other stop does.** 0.17 told it apart by its exit code; 0.18 does not, so a supervisor cannot tell a timed-out drain from a clean one.
- **Client secrets stay hashed.** A client secret is a bcrypt hash, as in 0.17, or an scrypt hash (`$scrypt$ln=,r=,p=$salt$key`); existing bcrypt hashes work as they are. A plain secret refuses boot at `clients.registered.<i>.sections.client-secret.hash`, so hash it with bcrypt first.
- **A user ledger served over HTTP keeps 0.17's password call**, with a few answers read differently (see [users-http](#user-ledger-over-http)).

## Packages

0.18 is published as one package per concern, `@o3co/auth-provider-<concern>`, all at the same version. Each package offers its modules as subpaths named after them: `@o3co/auth-provider-oauth/authorize` (the contract), `/authorize/module` (what an app assembles), `/authorize/testing` (test builders and contract tests; vitest is an optional peer) and, where a module records audit events, `/authorize/audit-events`. You rarely name them yourself: generate the app (`npx @o3co/create-auth-provider <dir> …`, or `npm create @o3co/auth-provider -- <dir> …`), and it depends on the packages it composes.

Where each 0.17 package went:

| 0.17 | 0.18 |
|---|---|
| `@o3co/auth-provider-core` | split by concern: `-foundation` (kernel, configuration, HTTP, keys, stores, records, audit, outbound) and the package of each feature |
| `@o3co/auth-provider-oauth` | `-oauth` |
| `@o3co/auth-provider-device-grant` | `-oauth` (`/device-grant`) |
| `@o3co/auth-provider-dpop` | `-oauth` (`/dpop`) |
| `@o3co/auth-provider-oauth-token-exchange` | `-oauth` (`/token-exchange`) |
| `@o3co/auth-provider-session` | `-identity` (session, login, logout, CSRF) and `-upstream-login` (federation routes) |
| `@o3co/auth-provider-foundation` (the user store's HTTP client) | `-user-ledger-http` (`/users-http`) |
| `@o3co/auth-provider-federation-oidc` | `-upstream-login` (`/federation`, `/idp-oidc`) |
| `@o3co/auth-provider-federation-google`, `-federation-github`, `-federation-apple` | `-upstream-login` (`/idp-google`, `/idp-github`, `/idp-apple`) |
| `@o3co/auth-provider-federation-grants` | `-delegation` (`/federation-grants`) |
| `@o3co/auth-provider-mfa` | `-second-factor` |
| `@o3co/auth-provider-webauthn` | `-passkey` |
| `@o3co/auth-provider-mtls` | `-cert-binding` (`/mtls`) |
| `@o3co/auth-provider-redis` | `-store-redis` (`/redis`), with each store's wiring in `-templates` |
| `@o3co/auth-provider-standard` (mail senders) | `-smtp` (`/mail-smtp`); logging-only mail is `-foundation` (`/mail`) |
| `@o3co/auth-provider-test-kit` | each package's `/<module>/testing` |
| `@o3co/create-auth-provider` and the standalone template | `@o3co/create-auth-provider` (runs `-scaffold`'s create-app) and `-scaffold` |

The packages take `zod` 4.6.7. An app that writes sections of its own uses that version too, or pins it for every package with a pnpm `overrides` entry, so one copy of zod reads every section.

New in 0.18, with no 0.17 package: `-audit-receivers` (audit to stdout or HTTP), `-log-sinks`, `-metrics-publishers` (Prometheus) and `-templates` (the stores' wirings).

The 18 packages of 0.17 are deprecated.

## What carries over

0.18 reads none of 0.17's records: their shapes and key spaces differ. What the switch does depends on the kind of record.

### Lost unless you move it

These belong to users and do not come back by signing in again. To keep them, dump them from your 0.17 stores and write them into 0.18's with your own tooling.

- MFA factors: TOTP secrets and their last used step, and recovery code hashes. Recovery codes made again invalidate the codes users wrote down.
- Passkey credentials: public key, credential id, signature count and user handle.
- Links between users and upstream identities (IdP name and upstream subject): in `users.registered` for a settings ledger, or in the ledger's own records for users-http.
- Federation grant connections: the user's standing consent and the upstream tokens. Without them, users connect again.
- Passwords are the user ledger's, not the provider's: in `users.registered` for a settings ledger, or in the ledger's own records for users-http.

MFA factors and upstream tokens are sealed, so dumping them needs 0.17's sealing key.

### Rebuilt by signing in again, or by the next request

- Sessions and their cookie index: users sign in again.
- Refresh token families: a new sign-in starts a new one.
- Authorization codes, device codes, and MFA and federation transactions: one in progress fails.
- One-time records of DPoP and client assertion `jti`s.
- Rate-limit counts and holds: they start again from zero.
- Consents to OAuth clients: the next authorization asks again.
- Audit events not yet delivered.

### Ended by the switch

- Access tokens issued by 0.17 fail verification, unless you list 0.17's signing key in `keys.previous` until they expire. Such a token then verifies but is tied to no 0.18 session, so ending them at the switch is recommended.
- Subject revocation boundaries: with 0.17's tokens ended, they need not move.

### What users see

- They sign in again.
- Unless MFA factors are moved, they enroll a second factor again and write down new recovery codes.
- Unless federation grant connections are moved, they connect again.
- Where a consent page is set, clients that are not first-party ask for their consent again.

## Migration steps

1. Generate the app with `create-auth-provider`, naming the modules you use (for example `@mod/authorize`, `@mod/code-grant`, `@mod/refresh`, `@mod/oidc`). Their default wirings and bridges are added for you, and one log sink (`log-stdout`) unless you name another.
2. Write the app's `application.conf`, in its `config` directory, from your 0.17 settings, section by section, with the [mapping](#configuration-mapping) below. Start from the file `create-auth-provider` writes.
3. Remove 0.17's environment variables. 0.18 reads a variable only where your HOCON writes `${?VAR}`, so a 0.17 variable left in the environment has no effect, and the setting it controlled takes its 0.18 default: `OAUTH_ACCESS_TOKEN_EXPIRES_IN` left set, say, changes no access token's lifetime. Before you upgrade, delete every 0.17 variable from the environment, the orchestrator's manifests and the secret store, and write each value you keep into `application.conf`, or bind it there with `${?VAR}` under a name of your own. A generated app's entry warns once at boot of each 0.17 variable left set that no configuration file reads (`warn config-files: N variables named in 0.17 are set and never read: …`), naming it, never its value, and boot goes on. Set `APP_LEGACY_VARIABLES=refuse` to refuse boot on one instead, naming each, or `ignore` to skip the check. An entry you wrote yourself checks only where it calls `config-files`' `legacyVariablesCheck`.
4. Move `clients.yaml` entries into `clients.registered` and `users.yaml` entries into `users.registered`, keeping client secrets as their bcrypt hashes.
5. Point the app at an empty Redis (or a new `redis.prefix`) that meets the [requirements](#redis).
6. Start the app. A refused boot exits with status 78 and prints one `refused <where>: <reason>` line per problem on standard error; fix them and start again. Refusals name the setting, never its value.
7. Run your clients against it, paying attention to the [behavior changes](#behavior-changes).

## How configuration works now

| | 0.17 | 0.18 |
|---|---|---|
| Files | `config/{ENV}.conf` (by `CONFIG_ENV` or `NODE_ENV`), then `application.conf` there, then each package's `reference.conf` | The HOCON files `APP_CONFIG` lists, comma-separated, the first file winning; the app's `application.conf` (in `config`) when unset. The generated `.gitignore` leaves out `config/local*.conf` for per-machine overrides |
| Defaults | In `reference.conf` files | In each module's section; nothing ships as a file |
| Environment variables | Bound by each package's `reference.conf` (`${?VAR}` lines) | Read only where your HOCON writes `${?VAR}`; substitution reaches environment variables and the same file only |
| Features and adapters | `adapters.*`, `mfaMode`, `*.enabled` switches | The module list in the generated app's `main.ts` |
| Sections | Unknown sections were warned about | A section for a module that is not loaded, and an unknown key in a section, refuse boot |
| Clients and users | `clients.yaml`, `users.yaml` | `clients.registered`, `users.registered` in HOCON |

A value taken from an environment variable is read as the type its setting takes, so numbers and booleans can come from environment variables too: with `port = ${?PORT}`, `PORT=8081` listens on 8081. A value that does not convert refuses boot (`PORT=80x` gives `refused http.port: Invalid input: expected number, received string`, exit 78).

Most settings are renamed. Keys are kebab-case inside a section named after its module, for example `tokens.access-token-lifetime`.

## Configuration mapping

Only the settings an existing deployment is likely to carry are listed. Each module's section, with its bounds and defaults, is described in its own documentation.

### Kernel, logging and HTTP

| 0.17 | 0.18 | Notes |
|---|---|---|
| `core.deployment.mode` | `kernel.deployment` (`single` or `multi`) | Required |
| `logging.level` | `kernel.logging.level` | |
| `http.port` (default 3000) | `http.port` (default 8080) | |
| (all interfaces) | `http.host` (default `127.0.0.1`) | Set `0.0.0.0` in a container |
| `http.trustProxy` | `http.trusted-proxies` (IPs or CIDRs), `http.proxy-hops` | Named ranges and `true` are gone; list addresses. A block of every address of a family (any `/0`, or every IPv4 address mapped into IPv6, as `::ffff:0:0/96` or `::/1`) refuses boot, as every source would be undetermined |
| `http.readinessTimeoutMs` | `http-ops.readiness-deadline` | |
| `http.cors.allowedOrigins` | `http.cors-origins` | Exact https origins, as a HOCON list |
| (from the issuer) | `http.public-origin` | Cookies are `__Host-` and `Secure` when it is https |
| (Node's defaults: a minute for the headers, five for the request) | `http.headers-timeout` (default `10s`), `http.request-timeout` (default `30s`) | A request slower to arrive is answered `408` and its connection closed; raise them for clients on slow links |
| (no cap) | `http.max-connections` (default 10000) | A connection past it is closed as it arrives |
| `jwks.path`, `jwks.cacheMaxAge` | removed | Fixed at the key set's well-known path (`jwks.json` under `.well-known`), cached five minutes |

### Issuer and signing keys

| 0.17 | 0.18 | Notes |
|---|---|---|
| `oauth.jwt.issuer` | `issuer.url` | No trailing `/`, no query; where `http.public-origin` is set, its origin must be that |
| `key-store.local.algorithm` | `keys.signing.alg` | Required (`EdDSA`, `ES256`, `RS256`, `HS256`) |
| `key-store.local.kid` | `keys.signing.kid` | Required; 1–128 of `A-Za-z0-9._~-` |
| `key-store.local.privateKey`, `privateKeyPath` | `keys.signing.private-key` | PKCS #8 PEM text; no file paths |
| `key-store.local.secret` | `keys.signing.secret` | `oidc` needs an asymmetric key. 0.17 took the string's own bytes as the HMAC key; 0.18 decodes the value (hex where it is whole bytes of hex, else base64) and takes the decoded bytes, so a value copied as written boots with other key bytes, and every token 0.17 signed, and every party holding that string, no longer match. To keep the same key, set `keys.signing.secret-encoding = utf8` and copy the string as written, or write the hex of its UTF-8 bytes (`printf %s "$OLD" \| od -An -v -tx1 \| tr -d ' \n'`); the floor of 32 bytes of 8 byte values or more still applies, to the bytes read |
| `key-store.local.previousKeys` | `keys.previous` (`kid`, `alg`, `public-key`, `expires-at`) | `alg` per entry; asymmetric only |

### Clients

`clients.registered` holds `{ id, kind, method, sections }`, where `kind` is `public` or `confidential` and each feature reads its own entry under `sections`.

| `clients.yaml` field | 0.18 | Notes |
|---|---|---|
| (the map key) | `id` | |
| `tokenEndpointAuthMethod` | `method` | `private_key_jwt` needs `client-assertion` |
| `clientSecret` (bcrypt) | `sections.client-secret.hash` | bcrypt as is, or scrypt; a plain secret refuses boot |
| `jwks` | `sections.client-assertion.keys` | Public keys only |
| `jwksUri` | `sections.client-assertion.jwks-uri` | Not beside `keys`; outbound must allow its host, or boot is refused |
| `allowedRedirectUris` | `sections.authorize.redirect-uris` | |
| `allowedScopes`, `defaultScopes` | `sections.client-allowance.scopes`, `default-scopes` | |
| `allowedAudiences` | `sections.client-allowance.audiences` | |
| `allowedGrantTypes` | `sections.client-allowance.grants` | Always enforced: a client with no list gets no grant |
| `senderConstrained.required`, `methods` | `sections.sender-binding.required`, `kinds` | Kinds by name, `dpop` and `mtls`, as before; a kind not composed refuses boot |
| `firstParty` | `sections.consent.first-party` | |
| `allowExchangeOfTokensIssuedToOthers` | `sections.token-exchange.others-tokens` | |
| `allowPlainPkce` | removed | S256 only |

### Tokens, grants and consent

| 0.17 | 0.18 | Notes |
|---|---|---|
| `oauth.accessToken.defaultExpiresIn` | `tokens.access-token-lifetime` | At most `1d` |
| `oauth.revocation.accessToken` | `tokens.revocation` (`denylist` or `unsupported`) | Required |
| `oauth.revocation.subject` | compose `subject-revocation`, or `tokens.subject-check = none` | |
| `oauth.refreshToken.expiresIn` | `refresh.lifetime` | |
| `oauth.requireGrantTypeAllowlist` | removed | Always on |
| `oauth.authorize.acrValues` | `acr.values` | Lists of non-empty amr sets |
| `oauth.consentPage.url` | `consent.page` | Absolute https URL; without it, as in 0.17, a client that is not first-party is refused (`unauthorized_client`) |
| `*.grants.*.enabled` | compose `authorize` + `code-grant`, `refresh`, `jwt-bearer` | `client_credentials` is part of `token-endpoint`; from 0.19, compose `client-credentials` for it ([From 0.18 to 0.19](#from-018-to-019)) |
| code lifetime | `code-grant.code-lifetime` | |
| `oauth-token-exchange.maxActorChainDepth` | `token-exchange.max-actor-depth` | 1–10 |
| `device-grant.*` | `device-grant.*` (`verification-uri`, `complete-uri`, `code-lifetime`, `interval`, `attempts`) | `verification-uri` must be https |
| rate limiter `limits.token`, `limits.authorize`, `limits.introspect`/`revoke` | `token-endpoint.requests`/`window`, `authorize.*`, `token-control.*` | Per source address |

### Session, login and users

| 0.17 | 0.18 | Notes |
|---|---|---|
| `session-store.secret`, `name`, `secure`, `sameSite`, `domain` | removed | The cookie is fixed: `session`, `__Host-` and `Secure` on https, `SameSite=Lax` |
| `session-store.maxAge` (ms) | `session-lifecycle.lifetime` | Written with its unit |
| (none) | `session-lifecycle.recent-authentication` | Default `5m`, `30s` to `1h`; the one window every recent-authentication check counts in, `mfa`'s included |
| `core.sessionRequirements.expected`, `secondFactorAuthority` | removed | Without `mfa`, changing credentials needs a sign-in at a known time within `session-lifecycle.recent-authentication`; with `mfa`, it judges both using a session and changing credentials |
| `session.loginPage.url` | `authorize.login-page` | Absolute https URL, required |
| `session.rateLimit.login` | `login-password.attempts`, `window` | Written with its unit |
| (none) | `login-password.account-attempts`, `account-window`, `account-max-wait` | Failed attempts at one identifier from any source make each next one wait, doubling to the longest wait (defaults 10, `1h`, `5m`); anyone who knows an identifier can keep its password login waiting that long, while passkey and federation logins are not held back |
| `session.redirectAllowlist`, per-IdP `redirectAllowlist` | `login-gates.return-targets` | Exact https URLs, one list |
| `session.csrf.trustedOrigins` | removed | Same-origin evidence is checked against `http.public-origin` |
| `users.yaml` | `users.registered` (`identifier`, `subject`, `password-hash`, `attributes`, `upstream`) | Hashes are bcrypt or scrypt; plain passwords are refused |
| `repositories.user.http.*` | `users-http.verify-url`, `subject-url`, `upstream-url`, `credential`, `timeout` | [Some answers read differently](#user-ledger-over-http); `subject-url` and `upstream-url` are new: a user by subject, and by upstream identity (then the ledger, not `users`, holds the links) |

### MFA and passkeys

| 0.17 | 0.18 | Notes |
|---|---|---|
| `mfaMode` / `mfa.mode` | `mfa.mode` (`optional` or `required`) | `required` by default, as before; for `off`, leave the MFA modules out |
| `mfa.encryptionKeys` | `seal.current`, `seal.previous` (`id`, `key`) | The first key goes to `current`, the rest to `previous`; `id` is required |
| `mfa.transactionTtlSeconds`, `maxAttemptsPerTransaction`, `lockout.*` | `mfa-flows.transaction-lifetime`, `attempts-per-transaction`, `lockout.*` | |
| The routes `GET /session/mfa/factors`, `POST /session/mfa/factors/rename`, `POST /session/mfa/factors/remove`, `POST /session/mfa/recovery-codes` | compose `mfa-management` alongside `mfa-flows` | Same URLs and answers; `mfa-flows` no longer serves them |
| (`mfa-flows.requests`, `window` for the management POSTs) | `mfa-management.requests`, `mfa-management.window` | Defaults 60 per `5m`, as before; the budget is now counted apart from `mfa-flows`' routes |
| `mfa.manage.maxAgeSeconds`, `maxFactorsPerSubject` | `session-lifecycle.recent-authentication`, `mfa.max-factors` | A second factor is recent by the session's one window |
| `mfa-totp-factor.*`, `mfa-recovery-code-factor.*` | compose `mfa-totp`, `mfa-recovery` | Parameters are fixed (SHA-1, 6 digits, 30 s; 10 codes) |
| `webauthn.rpId`, `rpName`, `origin`, `topOrigin` | `webauthn.rp-id`, `rp-name`, `origins`, `top-origins` | `origins` is a list |
| `webauthn.challengeTtlMs` | `webauthn.challenge-lifetime` | Written with its unit |
| `webauthn.userVerification` | `webauthn.user-verification` | |
| `mfa.page.url` (the step-up page `/authorize` sends to) | `authorize.step-up-page` | Absolute https URL; without it, a session short of the asked acr gets `unmet_authentication_requirements` (from 0.19, only for an acr asked as essential: [U-0.19-82](#u-0.19-82)). Federation grants have their own `federation-grants.step-up-page` (`federation-grants-connect.step-up-page` from 0.19) |

### Upstream login (federation)

`core.federations.<name>` becomes `federation.idps.<name>`, with the type module (`idp-google`, `idp-oidc`, `idp-github`) composed. There is no `enabled` flag. The callback path is unchanged and derived from `http.public-origin`.

| 0.17 | 0.18 | Notes |
|---|---|---|
| `clientId`, `clientSecret` | `client-id`, `client-secret` | |
| `trustUpstreamAmr` | `upstream-amr` (upstream amr → local amr) | See [upstream amr](#upstream-amr) |
| google `accessType`, `requireAuthorizationResponseIss` | google `access`, `require-iss` | |
| oidc `issuer`, `discovery`, `endpoints.*` | oidc `issuer`, `discovery`, `authorization-endpoint`, `token-endpoint`, `jwks-uri`, `end-session-endpoint` | Endpoints on another host need `endpoint-hosts`: a host, or `.name` for the name and the names under it; `*.name` refuses boot |
| oidc `scopes` | oidc `scopes` | Default is now `openid` only |
| oidc `clockToleranceSeconds` | `clock-skew` | |
| `callbackMeetsFreshness` (every type) | removed | A `prompt=login` or `max_age` login needs the upstream's `auth_time`, and the session takes its sign-in time from it |
| `clientUrl` (every type) | `federation.landing` | Absolute https URL, one for every IdP; the public origin's root by default |
| `authCallbackUrl` (every type) | removed | The callback sends the browser straight to the return target |
| `redirectAllowlist` (every type) | `login-gates.return-targets` | Already in the session table |
| `sessionDomain` (every type) | removed | Return targets are exact https URLs; no domain narrows them |

### Sender binding

| 0.17 | 0.18 | Notes |
|---|---|---|
| `dpop.algWhitelist`, `iatWindowSeconds` | `dpop.algorithms`, `proof-window` | Window at most `5m` |
| `dpop.nonce.required`, `ttlSeconds`, `secret` | `dpop.nonce.required` (`never` by default, `as`, `as+rs`), `ttl` (at most `1h`), `secret` | The secret is base64 of at least 32 bytes of 8 byte values or more, its decoded bytes the HMAC key; a nonce from 0.17 is refused once. The generated configuration reads `DPOP_NONCE_REQUIRED`, `DPOP_NONCE_TTL` and `DPOP_NONCE_SECRET`; the `OAUTH_DPOP_NONCE_*` names are gone |
| `mtls.source = header`, `certHeader`, `certHeaderDialect`, `trustedProxies` | `http.client-certificate` (`dialect`: `xfcc`, `pem` or `rfc9440`), `http.trusted-proxies` | `envoy` is `xfcc`, `plain-pem` is `pem` |
| `mtls.source = tls-layer` | removed | Certificates arrive only from a trusted proxy |
| `mtls.mode = full-pki` | `mtls.mode = pki` | |
| `mtls.trustedCas`, `fullPki.revocation.*` | `mtls.anchors`, `mtls.revocation.*` | |

### Storage

| 0.17 | 0.18 | Notes |
|---|---|---|
| `adapters.*` store slots | compose `redis` (or keep the in-memory `store`) | One store for every feature |
| `redis-clients.url` | `redis.url` | Required |
| `redis-*.keyPrefix` | `redis.prefix` | One prefix |
| `redis-clients.assumeNoEviction` | removed | Boot checks the server itself |

### Federation tokens

Compose `federation-tokens` beside `federation`. Its records go in the composition's store (`redis`, or the in-memory `store`) and are sealed with the `seal` key ring.

| 0.17 | 0.18 | Notes |
|---|---|---|
| `adapters.federationTokenStore` (`memory` / `redis`) | compose `federation-tokens`; its store is `redis` or `store` | One store for every feature |
| `redis-federation-token-store.keyPrefix` (`ft:`) | `redis.prefix` | One prefix |
| `redis-federation-token-store.encryptionKey` | `seal.current` (`id`, `key`) | One shared key ring, 32-byte base64 keys; `id` is required |
| `redis-federation-token-store.encryptionMode`, `FEDERATION_TOKENS_ALLOW_INSECURE` | removed | Always sealed; plaintext is not possible |
| `redis-federation-token-store.ttl` (86400 s) | removed | A record lives as long as its session |
| upstream token lifetime cap (24 h, code only; refresh only) | `federation-tokens.max-lifetime` (default `1d`) | `1m` to `365d`; caps the upstream's stated lifetime at login and refresh, and stands for a refresh answer that states none |
| `redis-federation-token-store.scanFallback` | removed | No pre-index records to sweep |
| refresh buffer (30 s, code only) | `federation-tokens.refresh-before` (default `30s`) | `0s` to `1h`; refresh also waits until half the life is spent |
| refresh lock (5 s, 4 s wait; code only) | `federation-tokens.lock-lifetime` (default `5s`) | `1s` to `1m`; one value for holding and waiting |
| (none) | `federation-tokens.requests`, `window` (60 / `1m`) | Per source address |
| client `allowedAzpForFederationToken` | `sections.federation-tokens.receives` | Default false; registered clients only |
| client `postLogoutRedirectUris` (for the federation logout) | `sections.federation-tokens.post-logout-redirect-uris` | Its own list; exact match; an unlisted return is dropped and the logout still runs |
| `POST /oauth/federation/<name>/token` | same path | Same answer shape and error codes, but `refresh_not_supported` is `410` (see [Federation tokens](#federation-tokens-and-sign-in-with-apple)) |
| `POST /oauth/federation/<name>/logout` | same path | `post_logout_redirect_uri`, `state` as before |

Settings with no counterpart: `encryptionMode`, `FEDERATION_TOKENS_ALLOW_INSECURE`, `scanFallback`, `ttl`, the lock's separate wait.

### Sign in with Apple

`core.federations.<name>` with `type = "apple"` becomes `federation.idps.<name>` with `type = "apple"`, with `idp-apple` composed. The common keys follow the upstream login table above.

| 0.17 | 0.18 | Notes |
|---|---|---|
| `clientId` (Services ID) | `client-id` | |
| `clientSecret` | `client-secret` | Give it, or the three signing keys, not both |
| `teamId`, `keyId`, `privateKey` | `team-id`, `key-id`, `private-key` | All three together; P-256 PKCS8 PEM |
| signed secret lifetime (180 days, code only) | `secret-lifetime` (default `5m`) | `1m` to `15777000s`; re-signed at half its life |
| fixed scope `name email` | `scopes` (`name`, `email`) | Default is now `email` only |
| Apple endpoints (fixed in code) | `authorization-endpoint`, `token-endpoint`, `jwks-uri` | Default to Apple's own |
| (none) | `clock-skew` (default `30s`) | `0s` to `5m` |
| `endSessionEndpoint` | `end-session-endpoint` | Optional; Apple has none |
| `callbackURL` | removed | Derived from `http.public-origin`; must be https and not loopback |

### Federation grants

Compose `federation-grants` and its store, `federation-grants-store`; there is no `enabled` flag. Credentials are sealed with the `seal` key ring, and connections need `http.public-origin`.

| 0.17 | 0.18 | Notes |
|---|---|---|
| `federation-grants.enabled` | compose `federation-grants` + `federation-grants-store` | |
| `federation-grants.consent.url` | `federation-grants.page` | Absolute https URL; 0.17 also took a path. Required once a connection is configured. `federation-grants-connect.page` from 0.19 |
| `session.loginPage.url` (for the connect flow) | `federation-grants.login-page` | Absolute https URL; without it, a browser with no session gets a plain `401`. `federation-grants-connect.login-page` from 0.19 |
| `defaultExpiresIn`, `maxExpiresIn` | `default-lifetime`, `max-lifetime` | Written with its unit; default `30d` each, at most `365d` |
| `refreshBuffer` | `refresh-before` | Default `30s` |
| `rotationBudget`, `rotationWindow` | `rotations`, `rotation-window` | Defaults 24 per `1h`, as before; at most 1000 per `1d` |
| `allowKeepOnSubjectRevocation` | `keep-on-subject-revocation` | Default false |
| `identityLookup` (`required` or `unsupported`) | `identity-check` (`required` or `none`) | `unsupported` is `none`. `federation-grants-connect.identity-check` from 0.19 |
| `ineligibleRetryAfter` | removed | Fixed: a `502` (`upstream_token_ineligible`, `upstream_rejected`) carries `Retry-After: 300` |
| `refreshFailureBackoff` | removed | A failed refresh keeps the credential and is tried again on the client's next call; `rotations` per `rotation-window` bound how often the upstream is asked, and the upstream's own `Retry-After` is passed on |
| `upstreamTimeoutMs`, `upstreamHardTimeoutMs` | `outbound.timeout` | Upstream calls go through `outbound`, whose one deadline covers resolving, connecting, the headers and the body |
| `refreshLockTtlMs`, `lockWaitMs` | removed | Fixed: the refresh lock lives 10 seconds and a request waits up to 5, then gets `503` `lock_timeout` |
| `persistRetryBudgetMs` | removed | Each write lands only over the grant it read; one that finds the grant changed gets `503` `grant_changed`, for the client to retry |
| rate limiter `limits.federation_grants`, `limits.federation_grants_browser` | `requests`, `window` (per source, client routes and pages alike); `lodges`, `lodge-window` (per client) | 0.17's `federation_grants` budget counted both addresses and clients; lodgings per client default 60 per `1m` |
| `connections.<name>` | `connections.<name>` | Names are now `a-z`, `0-9` and `-`, at most 32, starting with a letter or digit; the callback path follows the name |
| `connections.<name>.federation` | `connections.<name>.idp` | Names a `federation.idps` entry whose IdP offers delegation |
| `connections.<name>.scopes` | `connections.<name>.scopes` | Must hold `openid`, as before |
| `connections.<name>.maxAccessTokenLifetime` | `connections.<name>.max-access-token-lifetime` | Required; written with its unit, now at most `1d` |
| `connections.<name>.allowScopeSubsets` | `connections.<name>.scope-subsets` | Default false (was true); set `scope-subsets: true` on a connection to keep 0.17's behaviour |
| `connections.<name>.resource` | `connections.<name>.resource` | |
| `connections.<name>.callbackURL` | removed | Fixed at `/session/federation-grants/callback/<name>` on `http.public-origin` |
| `connections.<name>.boundary`, `identityClaims` | removed | |
| `redis-federation-grant-store.encryptionKeys` | `seal.current`, `seal.previous` | One ring for every sealed record |
| `redis-federation-grant-store.encryptionMode` | removed | Always sealed |
| `redis-federation-grant-store.keyPrefix`, `redis-federation-grant-intent-store.keyPrefix` | `redis.prefix` | One prefix for every store |
| `redis-federation-grant-store.listingAllowanceMs`, `tombstoneRetention`; `core-federation-grant-store-memory.tombstoneRetention` | removed | A revoked or ended grant answers its status for 30 days past the grant's end; fixed |
| `mfa.page.url` (the step-up page connect followed) | `federation-grants.step-up-page` | Absolute https URL; without it, a session short of a requirement gets `403`. `federation-grants-connect.step-up-page` from 0.19 |
| (none) | `federation-grants-store.pending-per-client-and-subject`, `grants-per-subject` | Defaults 16 and 100; past the cap the one ending first is pushed out |

`clients.registered` entries carry the client side under `sections.federation-grants`:

| `clients.yaml` field | 0.18 | Notes |
|---|---|---|
| `allowedFederationGrantConnections` | `sections.federation-grants.connections` | Confidential clients only |
| `federationGrantRedirectUris` | `sections.federation-grants.return-uris` | Exact URIs; none may carry `grant_id`, `state` or `error` in its query |

### Session grant

Compose `session-grant`, with `session-tokens` beside it: boot is refused when nothing records its tokens to their session.

A proxy in front of the session grant passes `Origin` and `Sec-Fetch-Site` through as the browser sent them, and overwrites `X-Forwarded-For` and `X-Forwarded-Proto` with its own values rather than appending to what the client sent.

| 0.17 | 0.18 | Notes |
|---|---|---|
| `oauth-session.enabled` | compose `session-grant` + `session-tokens` | |
| `allowedGrantTypes` holding `session` | `sections.client-allowance.grants` holding `session` | Always enforced; public clients may use it too |
| `oauth.requireEmailVerified` (for the session grant) | compose `verified-email` | One policy for every grant but `refresh_token` and `client_credentials`; refused as before (`invalid_grant`) |

### Client ID Metadata Documents

Compose `clients-cimd`. It fetches nothing unless `code-grant` is composed, and every fetch goes through `outbound`: its hosts must be let through there (see [Audit, mail, outbound and metrics](#audit-mail-outbound-and-metrics)).

| 0.17 | 0.18 | Notes |
|---|---|---|
| `oauth.clientIdMetadataDocuments.enabled` | compose `clients-cimd` | |
| `allowedScopes` | `clients-cimd.scopes` | Default empty |
| `allowedAudiences` | `clients-cimd.audiences` | Default empty. Empty now means the issuer as the audience; in 0.17 it was the client's own id |
| `allowedHosts`, `deniedHosts` | `clients-cimd.allow`, `deny` | Host names; `.name` also takes the names under it. `deny` wins. A non-empty `allow` also narrows `outbound` |
| `maxBytes` | `clients-cimd.max-size` | Default `5KiB`; capped by `outbound.max-response-size` |
| `timeoutMs` | `clients-cimd.timeout` | Default `5s`; capped by `outbound.timeout` |
| `cacheMaxAgeMs` (ms) | `clients-cimd.cache-lifetime` | Default `10m`; the document's `max-age` still caps it |
| `maxCacheEntries` | `clients-cimd.cache-entries` | Default 256 |
| `negativeCacheMs` (ms) | `clients-cimd.refused-lifetime` | Default `1m` |
| `maxConcurrentFetches` | `clients-cimd.max-concurrent` | Default 8 |
| `staleIfErrorMs` | removed | A document past its time is never used, as with 0.17's default `0` |

### Userinfo and RP-initiated logout

Compose `userinfo` and `oidc` for the userinfo endpoint and ID tokens, `rp-logout` with `rp-logout-store` for `/oauth/logout`, and `logout` for `POST /session/logout`. Back-channel notices go through `outbound`, so their hosts must be let through there.

| 0.17 | 0.18 | Notes |
|---|---|---|
| `/oauth/userinfo` (with the oauth endpoints) | compose `userinfo` + `oidc` | `userinfo` also needs `session-tokens` |
| (none) | (no setting) | A token issued without the `openid` scope is refused `403 insufficient_scope`; ask `openid` for a token that reads userinfo |
| (ID token lifetime fixed at 3600 s) | `oidc.id-token-lifetime` | Default `1h`; `1m` to `1d` |
| `oauth.oidcMode` | `authorize.oidc-mode` (`oidc-required` or `dual`) | Default `oidc-required`, as before |
| `/oauth/logout` (with the oauth endpoints) | compose `rp-logout` + `rp-logout-store` | `oidc` judges the `id_token_hint` |
| (an old `id_token_hint` led to a page asking to confirm) | (no setting) | A hint issued more than 24 hours ago is refused `400 invalid_token`, by GET or POST, and the session stays open; the RP sends a fresher hint, or the user logs out at `POST /session/logout` |
| `POST /session/logout` (session module) | compose `logout` | |
| upstream end-session from `/oauth/logout` | compose `rp-logout-federation` | Needs `federation-tokens` |
| `core.sessionLifecycle.sweepIntervalSeconds` | `session-lifecycle.sweep-interval` (pending closes), `rp-logout.sweep-interval` (pending notices) | Defaults `30s` and `1m`; `0` (no sweep) is gone |
| (none) | `rp-logout.remember-for` | Default `1d`; keep it at least `session-lifecycle.lifetime` |
| (no setting; a notice was retried until the closing record lapsed, after `oauth.refreshToken.expiresIn`) | `rp-logout.notify-within` | Default `1d`, `1m` to `7d`; how long an undelivered back-channel notice is retried, then dropped |

| `clients.yaml` field | 0.18 | Notes |
|---|---|---|
| `postLogoutRedirectUris` | `sections.rp-logout.post-logout-redirect-uris` | Same rule as `authorize`'s redirect URIs |
| `frontchannelLogoutUri`, `frontchannelLogoutSessionRequired` | `sections.rp-logout.frontchannel-logout-uri`, `frontchannel-logout-session-required` | Default true, as before. The URL's scheme, host and port must be those of one of the client's redirect URIs, or boot is refused |
| `backchannelLogoutUri`, `backchannelLogoutSessionRequired` | `sections.rp-logout.backchannel-logout-uri`, `backchannel-logout-session-required` | Default true, as before |

### Email and WebAuthn second factors

Compose `mfa-email` (with `mfa-email-wording`, a mail sender such as `mail-smtp`, and from 0.19 `mfa-email-proof`) for codes by mail, and `mfa-webauthn` (with `webauthn`) for WebAuthn as a second factor. The relying party keys are in [MFA and passkeys](#mfa-and-passkeys).

For a second factor by mail alone, with no other factor to enrol, set `mfa-email.adds-second-factor = true`: without it, a code by mail does not count as a second factor.

| 0.17 | 0.18 | Notes |
|---|---|---|
| `mfa-email-factor.enabled` | compose `mfa-email` + `mfa-email-wording` | Needs a mail sender, as before; from 0.19, `mfa-email-proof` too |
| `mfa-email-factor.addsMfa` | `mfa-email.adds-second-factor` | Default false |
| `mfa-email-factor.codeTtlSeconds` | `mfa-email.code-lifetime` | Default `10m`; `1m` to `30m` |
| (none) | (no setting) | Codes go to the account's `email` that `users` holds, else to the `email` an outside HTTP ledger gave at login. An `email` from an upstream IdP is never used: a user who signs in only through an IdP cannot bind codes by mail, and the account-email proof is not offered |
| `mfa.enrollment.requireEmailProof` (`when-mail`, `always`, `never`) | `mfa-binding-proof.mode` (`when-available`, `always`, `never`) | Compose `mfa-binding-proof`. `when-mail` is `when-available`. The account-email proof comes with `mfa-email`: without it, no proof is asked. From 0.19 the proof is `mfa-email-proof`'s, and `mfa-email` refuses boot without it or `mfa-binding-proof` ([From 0.18 to 0.19](#from-018-to-019)) |
| `webauthn-mfa-factor.enabled` | compose `mfa-webauthn` + `webauthn` | |
| `webauthn-mfa-factor.userVerification` | `mfa-webauthn.user-verification` | Default `preferred`; apart from `webauthn.user-verification` |
| (the account's username; none refused enrolment) | `mfa-webauthn.display-name` | The account's name, else this (default `Account`) |

### Settings with no counterpart

- `foundation-mfa-factor-store.*` (second factors kept on an outside HTTP service): factors are kept in the app's own store. Users enroll the factors they kept there again after moving.
- `key-store.local.previousSecrets` (HS256 key rotation): `keys.previous` takes asymmetric keys only.
- oidc `endpoints.userinfoEndpoint`.
- A per-IdP `callbackURL`: the callback is derived from `http.public-origin`.
- `session.csrf.ttlSeconds`: the CSRF token lives 7,200 s, fixed (0.17's default).
- The in-memory rate limiter's `maxBuckets`: counts are kept in the store, each ending with its window; in memory, one instance holds them, so a flood of distinct sources is bounded by the window, not by a count. Use `redis` where that matters.
- A trusted issuer's `profile: "id-jag"` (0.17's ID-JAG profile): 0.18 has none, and takes an ID-JAG as any assertion of its issuer. From 0.19, `profile = "id-jag"` takes it ([From 0.18 to 0.19](#from-018-to-019), U-0.19-52).
- `redis-refresh-token-family.casRetryLimit`: every store write that loses a race is tried again up to 8 times, within 10 seconds, then answered as unavailable.

### Audit, mail, outbound and metrics

| 0.17 | 0.18 | Notes |
|---|---|---|
| `adapters.auditSink` | `audit.receivers` (names, or `none`) | Required; compose `audit-stdout` or `audit-http` for those receivers |
| `standard-smtp-mail-sender.*` | `mail-smtp.host`, `port`, `security`, `user`, `password`, `from` | `secure` is now `security` |
| (development mail sender, let in by the environment's name) | none; to read codes while you develop, `mail-smtp` pointed at Mailpit on loopback ([Email codes on your machine](local-mail.md)), or the `mail` module with `mail.accept-unsent = true` to send nothing | 0.18 chooses no sender by the environment's name. `mail` logs the purpose, a hash of the address and the names of the message's values, never a value: a code or link in the message is never logged, unlike 0.17's |
| `core.outbound.allowedHosts` | `outbound.allow`, or `outbound.allow-any-public = true` | An empty list now reaches nothing. Entries as before: a host, or `.name` for the name and the names under it |
| `core.outbound.deniedHosts`, `timeoutMs`, `maxResponseBytes` | `outbound.deny`, `timeout`, `max-response-size` | `deny` takes entries as `allow` does |
| `core.outbound.internalHosts` | `outbound.internal-hosts`; `outbound.plain-loopback` (`host:port`) for plain http at loopback, `outbound.plain-internal` (`host:port`) for plain http at private or loopback addresses | `internal-hosts` reaches private addresses (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7) for the users-http ledger and the audit-http collector only; a client's URLs (key sets, back-channel logout) never reach a private, loopback or link-local address. `.name` still covers the name and the names under it |
| `core.outbound.internalHosts` | `outbound.internal-hosts`; `outbound.plain-loopback` (`host:port`) for plain http at loopback, `outbound.plain-internal` (`host:port`) for plain http at private addresses | `internal-hosts` reaches private addresses (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7) for the users-http ledger and the audit-http collector only; a client's URLs (key sets, back-channel logout) never reach a private, loopback or link-local address. `.name` still covers the name and the names under it |
| `core.outbound.internalHosts` | `outbound.internal-hosts`; `outbound.plain-loopback` (`host:port`) for plain http at loopback | `internal-hosts` reaches private addresses (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7) for URLs from your own configuration only: the users-http ledger, the audit-http collector, an OpenID Connect IdP's issuer and the endpoints you give it (with the key set its description names on the issuer's origin), and a GitHub Enterprise's endpoints; a client's URLs (key sets, back-channel logout) never reach a private, loopback or link-local address. `.name` still covers the name and the names under it |
| `core.outbound.egress = direct` | `outbound.direct-despite-proxy = true` | Only while every request goes direct; with a proxy, write `outbound.proxy` instead |
| `HTTPS_PROXY` with `NODE_USE_ENV_PROXY` | `outbound.proxy` (an http origin alone, such as `http://proxy:3128`), `outbound.proxy-authorization` | Every https request goes through it by CONNECT, key sets and back-channel notices included; the variables are never read |
| `NO_PROXY` | `outbound.direct-hosts` | The variable is never read: list each host here, as written (no `*`, `_`, spaces or short IPv4 forms); `.name` covers the name and the names under it |
| `/metrics` | compose `metrics-prometheus`; `metrics-prometheus.path` | |

### Times and sizes

Times and sizes are written with their unit (`30s`, `5m`, `64KiB`); a number without one refuses boot, so a value copied from 0.17 or from 0.18.0-rc.1 as a bare number is never read in a unit you did not choose. A key read in whole seconds takes whole seconds (`90s`, not `1500ms`). Each key below lost its unit suffix in 0.18.0; the sections above map it from 0.17.

| 0.18.0-rc.1 key | 0.18 key | Value | Environment variable |
|---|---|---|---|
| `authorize.window-seconds` | `authorize.window` | a duration, `1s` to `1d`, default `1m` |  |
| `client-assertion.max-lifetime-seconds` | `client-assertion.max-lifetime` | a duration, `1s` to `1d`, default `1h` |  |
| `client-assertion.clock-skew-seconds` | `client-assertion.clock-skew` | a duration, `0s` to `5m`, default `30s` |  |
| `clients-cimd.max-bytes` | `clients-cimd.max-size` | a size, `1B` to `16MiB`, default `5KiB` |  |
| `clients-cimd.timeout-ms` | `clients-cimd.timeout` | a duration, `1ms` to `1m`, default `5s` |  |
| `clients-cimd.cache-seconds` | `clients-cimd.cache-lifetime` | a duration, `0s` to `1d`, default `10m` |  |
| `clients-cimd.refused-seconds` | `clients-cimd.refused-lifetime` | a duration, `0s` to `1d`, default `1m` |  |
| `code-grant.code-seconds` | `code-grant.code-lifetime` | a duration, `10s` to `10m`, default `10m` |  |
| `code-grant.sweep-seconds` | `code-grant.sweep-interval` | a duration, `1s` to `1h`, default `30s` |  |
| `consent.challenge-seconds` | `consent.challenge-lifetime` | a duration, `1m` to `1h`, default `10m` |  |
| `device-grant.code-seconds` | `device-grant.code-lifetime` | a duration, `30s` to `1h`, default `10m` |  |
| `device-grant.interval-seconds` | `device-grant.interval` | a duration, `1s` to `1m`, default `5s` |  |
| `device-grant.attempts-window-seconds` | `device-grant.attempts-window` | a duration, `1m` to `1d`, default `5m` |  |
| `device-grant.window-seconds` | `device-grant.window` | a duration, `1s` to `1d`, default `1m` |  |
| `dpop.proof-window-seconds` | `dpop.proof-window` | a duration, `1s` to `5m`, default `1m` |  |
| `dpop.nonce.ttl-seconds` | `dpop.nonce.ttl` | a duration, `1s` to `1h`, default `5m` | `DPOP_NONCE_TTL` |
| `external-jwt.key-set-max-age-ms` | `external-jwt.key-set-max-age` | a duration, `1h` to `30d`, default `1d` |  |
| `federation.transaction-seconds` | `federation.transaction-lifetime` | a duration, `1m` to `1h`, default `10m` |  |
| `federation.window-seconds` | `federation.window` | a duration, `1s` to `1h`, default `1m` |  |
| `federation.idps.<name>.clock-skew-seconds` | `federation.idps.<name>.clock-skew` | a duration, `0s` to `5m`, default `30s`; for the oidc, google and apple IdPs |  |
| `federation.idps.<name>.secret-seconds` | `federation.idps.<name>.secret-lifetime` | a duration, `1m` to `15777000s`, default `5m`; for the apple IdP |  |
| `federation-grants.default-seconds` | `federation-grants.default-lifetime` | a duration, `1m` to `365d`, default `30d` |  |
| `federation-grants.max-seconds` | `federation-grants.max-lifetime` | a duration, `1m` to `365d`, default `30d` |  |
| `federation-grants.connect-seconds` | `federation-grants.connect-lifetime` | a duration, `1m` to `1h`, default `10m` |  |
| `federation-grants.refresh-before-seconds` | `federation-grants.refresh-before` | a duration, `0s` to `1h`, default `30s` |  |
| `federation-grants.rotation-window-seconds` | `federation-grants.rotation-window` | a duration, `1s` to `1d`, default `1h` |  |
| `federation-grants.lodge-window-seconds` | `federation-grants.lodge-window` | a duration, `1s` to `1d`, default `1m` |  |
| `federation-grants.revocation-skew-seconds` | `federation-grants.revocation-skew` | a duration, `0s` to `5m`, default `1s` | removed in 0.19: see [From 0.18 to 0.19](#from-018-to-019) |
| `federation-grants.window-seconds` | `federation-grants.window` | a duration, `1s` to `1h`, default `1m` |  |
| `federation-grants.connections.<name>.max-access-token-seconds` | `federation-grants.connections.<name>.max-access-token-lifetime` | a duration, `1s` to `1d`, required |  |
| `federation-tokens.refresh-before-seconds` | `federation-tokens.refresh-before` | a duration, `0s` to `1h`, default `30s` |  |
| `federation-tokens.max-lifetime-seconds` | `federation-tokens.max-lifetime` | a duration, `1m` to `365d`, default `1d` |  |
| `federation-tokens.lock-seconds` | `federation-tokens.lock-lifetime` | a duration, `1s` to `1m`, default `5s` |  |
| `federation-tokens.window-seconds` | `federation-tokens.window` | a duration, `1s` to `1h`, default `1m` |  |
| `http-ops.readiness-deadline-ms` | `http-ops.readiness-deadline` | a duration, `1ms` to `2147483647ms`, default `1s` |  |
| `jwt-bearer.max-assertion-lifetime-seconds` | `jwt-bearer.max-assertion-lifetime` | a duration, `1s` to `1d`, default `1h` |  |
| `jwt-bearer.clock-skew-seconds` | `jwt-bearer.clock-skew` | a duration, `0s` to `5m`, default `30s` |  |
| `kernel.stop-seconds` | `kernel.stop-deadline` | a duration, `1s` to `1h`, default `30s` | `KERNEL_STOP_DEADLINE` |
| `login-password.window-seconds` | `login-password.window` | a duration, `1m` to `1d`, default `15m` |  |
| `login-password.account-window-seconds` | `login-password.account-window` | a duration, `1m` to `1d`, default `1h` |  |
| `login-password.account-max-wait-seconds` | `login-password.account-max-wait` | a duration, `1s` to `1h`, default `5m` |  |
| `mail-smtp.deadline-ms` | `mail-smtp.deadline` | a duration, `100ms` to `10m`, default `40s` |  |
| `mfa.manage-seconds` | `session-lifecycle.recent-authentication` | a duration, `30s` to `1h`, default `5m` |  |
| `mfa-email.code-seconds` | `mfa-email.code-lifetime` | a duration, `1m` to `30m`, default `10m` |  |
| `mfa-flows.transaction-seconds` | `mfa-flows.transaction-lifetime` | a duration, `1m` to `30m`, default `10m` |  |
| `mfa-flows.window-seconds` | `mfa-flows.window` | a duration, `1s` to `1d`, default `5m` |  |
| `mfa-flows.lockout.backoff-seconds` | `mfa-flows.lockout.backoff` | a duration, default `15m` |  |
| `mfa-flows.lockout.max-backoff-seconds` | `mfa-flows.lockout.max-backoff` | a duration, default `1d` |  |
| `mfa-flows.lockout.budget-window-seconds` | `mfa-flows.lockout.budget-window` | a duration, default `7d` |  |
| `mfa-flows.lockout.memory-seconds` | `mfa-flows.lockout.memory` | a duration, default `1d` |  |
| `mtls.revocation.skew-seconds` | `mtls.revocation.skew` | a duration, `0s` to `1h`, default `5m` |  |
| `mtls.revocation.ocsp-fresh-seconds` | `mtls.revocation.ocsp-fresh` | a duration, `1s` to `1d`, default `10m` |  |
| `mtls.revocation.crl-ttl-seconds` | `mtls.revocation.crl-ttl` | a duration, `1s` to `1d`, default `1h` |  |
| `mtls.revocation.failure-seconds` | `mtls.revocation.failure-lifetime` | a duration, `1s` to `1h`, default `30s` |  |
| `mtls.revocation.timeout-ms` | `mtls.revocation.timeout` | a duration, `1ms` to `1m`, default `3s` |  |
| `oidc.id-token-seconds` | `oidc.id-token-lifetime` | a duration, `1m` to `1d`, default `1h` |  |
| `outbound.max-response-bytes` | `outbound.max-response-size` | a size, `1B` to `16MiB`, default `64KiB` |  |
| `outbound.signed-max-response-bytes` | `outbound.signed-max-response-size` | a size, `1B` to `16MiB`, default `1MiB` |  |
| `outbound.timeout-ms` | `outbound.timeout` | a duration, `1ms` to `1m`, default `5s` |  |
| `passkey-registration.window-seconds` | `passkey-registration.window` | a duration, `1s` to `1d`, default `5m` |  |
| `redis.connect-timeout-ms` | `redis.connect-timeout` | a duration, at least `100ms`, default `2s` |  |
| `redis.replication-timeout-ms` | `redis.replication-timeout` | a duration, `1ms` to `1m`, default `1s` |  |
| `redis.command-timeout-ms` | `redis.command-timeout` | a duration, `10ms` to `1m`, default `1s` |  |
| `refresh.lifetime-seconds` | `refresh.lifetime` | a duration, `1s` to `365d`, default `1d` |  |
| `refresh.sweep-seconds` | `refresh.sweep-interval` | a duration, `1s` to `1h`, default `30s` |  |
| `rp-logout.remember-seconds` | `rp-logout.remember-for` | a duration, `1m` to `30d`, default `1d` |  |
| `rp-logout.notify-seconds` | `rp-logout.notify-within` | a duration, `1m` to `7d`, default `1d` |  |
| `rp-logout.sweep-seconds` | `rp-logout.sweep-interval` | a duration, `1s` to `1h`, default `1m` |  |
| `session-lifecycle.lifetime-seconds` | `session-lifecycle.lifetime` | a duration, `1m` to `30d`, default `1h` |  |
| `session-lifecycle.sweep-seconds` | `session-lifecycle.sweep-interval` | a duration, `1s` to `1h`, default `30s` |  |
| `session-lifecycle.credentials-seconds` | `session-lifecycle.recent-authentication` | a duration, `30s` to `1h`, default `5m` |  |
| `session-tokens.sweep-seconds` | `session-tokens.sweep-interval` | a duration, `1s` to `1h`, default `30s` |  |
| `token-control.window-seconds` | `token-control.window` | a duration, `1s` to `1d`, default `1m` |  |
| `token-endpoint.window-seconds` | `token-endpoint.window` | a duration, `1s` to `1d`, default `1m` |  |
| `token-exchange.max-lifetime-seconds` | `token-exchange.max-lifetime` | a duration, `1s` to `1d` |  |
| `tokens.access-token-lifetime-seconds` | `tokens.access-token-lifetime` | a duration, `1s` to `1d`, default `1h` |  |
| `users-http.timeout-ms` | `users-http.timeout` | a duration, `1ms` to `1m` |  |
| `users-http.max-response-bytes` | `users-http.max-response-size` | a size, `1B` to `16MiB` |  |
| `webauthn.challenge-seconds` | `webauthn.challenge-lifetime` | a duration, `10s` to `10m`, default `2m` |  |
| `webauthn-login.window-seconds` | `webauthn-login.window` | a duration, `1s` to `1d`, default `1m` |  |

## Newly refused at boot

0.18 checks its settings at boot and refuses to start rather than run with a setting it cannot honor. The following were accepted by 0.17.

- **URLs in settings must be written in their canonical form**: no user information, fragment, surrounding whitespace, upper-case scheme or host, default port, or dot segments. This covers the issuer, page URLs, return targets, IdP endpoints and ledger URLs.
- **Page URLs must be absolute https**: `authorize.login-page`, `consent.page`, `login-gates.return-targets`, `federation.landing`, `device-grant.verification-uri`. An http public origin needs `http.insecure-origin = true`.
- **Times and sizes without their unit**: a bare number (`30`, or `"30"` from an environment variable) where a time or a size is read; write `30s` or `64KiB`. See [Times and sizes](#times-and-sizes).
- **Settings that now have no default**: `kernel.deployment`, `keys.signing.alg` and `kid`, `tokens.revocation`, `audit.receivers`, `redis.url`, `users-http.credential`, `authorize.login-page`.
- **Keys**: a private key where a trusted issuer's public key is expected, a client JWK whose `kid` is not a string, and a `kid` outside the allowed characters.
- **Users**: plain-text passwords, identifiers that differ only by case or Unicode form, and an upstream identity linked to two users.
- **acr**: an acr value that no composed way of logging in can meet.
- **Outbound**: `ALL_PROXY`, and the lower-case proxy variables, now refuse boot as `HTTP_PROXY` and `HTTPS_PROXY` already did, unless `outbound.proxy` or `outbound.direct-despite-proxy` is written; the variables are never read.
- **audit-http**: an `authorization` value with a URL that is neither https nor a `plain-loopback` or `plain-internal` pair outbound names, or a URL that outbound's policy refuses.
- **users-http**: a `verify-url` that outbound's policy refuses.
- **mail**: the logging-only sender without `mail.accept-unsent = true`.
- **Revocation**: a composition that issues refresh tokens or codes while access tokens cannot be revoked.
- **Redis**: a server that does not meet the [requirements](#redis).
- **Seal**: `seal.keys`, the key list of earlier 0.18 previews, is refused as an unknown setting. Write its first key as `seal.current` and the rest as `seal.previous`; see [Rotating the sealing key](runbook.md#rotating-the-sealing-key).

## Behavior changes

These are requests 0.17 accepted, or answered differently, that 0.18 refuses or answers otherwise. Clients that follow the specifications are not affected by most of them.

### Token endpoint and client authentication

- `GET /oauth/token` answers `405`.
- The token endpoint answers a JSON body with `400 invalid_request`, except for a grant that declares a JSON body, and other content types with `415`. Introspection, revocation and device authorization take form bodies only: anything else gets `415`.
- A repeated parameter gets `400 invalid_request` at the token, introspection, revocation and device authorization endpoints, and an `invalid_request` error at `/authorize`.
- More than one `resource` is refused, `invalid_target` with `resource-indicators` composed (`invalid_request` without it); a token is issued for one audience.
- A JSON body that names a member twice gets `400`.
- Client credentials sent by two methods at once (for example Basic and `client_secret` in the body) get `400 invalid_request`, even when they agree.
- A client assertion sent next to a `client_secret` gets `400 invalid_request`.
- A public client asking for `client_credentials` gets `400 unauthorized_client`.
- `scope` must follow RFC 6749 §3.3 exactly: extra spaces get `invalid_scope`. An empty `scope=` is the same as omitting it.
- A `401` from a grant carries `WWW-Authenticate`.
- A client that must bind its tokens (`sender-binding.required`) and sends no binding gets `400 invalid_request`; 0.17 answered `401 invalid_client`. A binding of a kind the client does not list is still `400 unauthorized_client`. Both are refused before the grant runs.
- An unreadable `Authorization: Basic` header (bad or unpadded base64, an empty secret) and a `client_secret` without `client_id` get `400`, without a challenge; 0.17 answered `401 invalid_client`.

### Access and refresh tokens

- **The access token names its client by `client_id`, never `azp`** (RFC 9068). A 0.17 access token carried `azp`, the client it was issued to, and no `client_id`; a 0.18 one carries `client_id` and no `azp`. A resource server that read `azp` reads `client_id`. Introspection answers `client_id` as before, and no longer `azp` beside it.
- **The access token names no session: it has no `sid`**, and no `family_id` either. 0.17 put the session's `sid`, and the refresh family's `family_id`, in both its tokens. A resource server that read `sid` to tie a token to its session, for example to stop honouring it once the user logs out, asks introspection (RFC 7662) instead: a session that closes ends the refresh families it started and the access tokens they issued, which introspection then answers `active: false` (where access tokens can be revoked, `tokens.revocation = denylist`). Neither `sid` nor `azp` can come back as a claim a module adds: both names are reserved.
- **The refresh token is opaque.** 0.17 issued a signed JWT (`typ` `rt+jwt`) holding the family, `sid`, `amr`, `acr`, `auth_time`, `azp`, `scope` and `exp`. 0.18 issues a string of a family's name and a secret (`<22 characters>.<43 characters>`, base64url), and keeps the rest itself, with only the secret's hash. Nothing tells when a refresh token ends: the token response's `expires_in` is the access token's lifetime, never the refresh token's, and no answer gives the family's end (`refresh.lifetime`). A client that decoded its refresh token keeps it opaque, as it came, and sends it back when its access token ends; where the refresh is answered `invalid_grant`, the family has ended, and the client asks for a new authorization. What was granted is the token response's `scope`, and the ID token's claims. Refresh tokens issued by 0.17 do not carry over (see [What carries over](#what-carries-over)).

### Introspection and discovery

- Introspection without a `token` gets `400 invalid_request`.
- For an issuer with a path, the discovery documents are served only at their path forms; the root `/.well-known/…` documents answer `404`, since they would name another issuer.

### Login

- A login that repeats a field gets `400` with `repeated_parameter`.
- A bcrypt password that is longer than 72 bytes no longer matches on its first 72 bytes alone; a password over 1024 bytes is refused.
- The audit event `session.admission.subject_mismatch` is gone. 0.17 recorded it when the user a cookie or a token named was not the user of the session record behind it. A 0.18 session is named only by its handle, a new random value each login, and keeps the subject its login gave until it closes, a raise included, so the two can never differ; a receiver that matches the event receives nothing.

#### User ledger over HTTP

`users-http` makes the same password call as 0.17's `authenticateUrl`; `verify-url` is that URL, used whole, with nothing added to it. Some answers are read differently:

| | 0.17 | 0.18 |
|---|---|---|
| Verify a password | `POST {authenticateUrl}` with `{"email","password"}` | `POST {verify-url}` with `{"email","password"}`, `Content-Type` and `Accept: application/json` |
| Credential | | `Authorization: Bearer {credential}` when `credential` is set; none sent otherwise |
| Find a user by subject | none | `POST {subject-url}` with `{"subject"}`: `200` with the user, its `id` the subject asked; `404` with the JSON object `{"error":"not_found"}`, or `410` with `{"error":"gone"}`: no such user; a `404` or `410` saying neither, and anything else, is unavailable (`503`), logged as `users-http.ledger_failed`. Without `subject-url`, every lookup by subject is one it cannot answer |
| Success | any `2xx` with the user | `200` with a JSON object: `id` (the subject) and a non-empty `username`; `email`, `name`, `picture`, `groups` and a boolean `emailVerified` (only beside `email`) are kept as attributes, other fields dropped |
| No such user, or a wrong password | `401` or `403` | `401` alone, unless a `credential` was sent and the answer carries a Bearer challenge: that refuses the credential, and reads as unavailable. A `403` reads as unavailable (`503`): answer a wrong password `401` |
| Anything else | | Any other status, `404` and other `2xx` included, or a `200` that is not such an object: the ledger is unavailable, and the login answers `503` |

Upstream links and MFA enrollment are no longer kept by the ledger. An upstream login through a link users keeps needs `subject-url` or `upstream-url`: without either, nothing can say who the link stands for, and that login answers `503`.

A ledger that suspends a user stops new logins and grants by its answers. To end the user's open sessions and issued tokens as well, compose `subject-revocation-http` and have the ledger post the subject to `/ledger/subject-revocations`; see [Revoking a user from the ledger](runbook.md#revoking-a-user-from-the-ledger).

A ledger can also be asked for a user by subject, so a user who signs in upstream has the ledger's attributes, such as the address `mfa-email` mails: set `users-http.subject-url`. It is posted `{"subject"}` the same way; a `200` with an `id` is the user (no `username` asked), a `404` with the JSON object `{"error":"not_found"}` or a `410` with `{"error":"gone"}` is no such user, and anything else, a `404` or `410` saying neither and `401` and `403` included, is unavailable. Likewise `users-http.upstream-url` is posted `{"idp", "subject"}` to look a user up by upstream identity, read the same way; with it, the ledger's answer is the last word, and links users keeps are not read. A `404` without that body (a mistyped `subject-url` or `upstream-url`, a route not deployed, a gateway's unknown route, a ledger hiding itself) is unavailable and logged as `users-http.ledger_failed` with its status and `reason: "unmarked"`, never no such user; the ledger refuses a caller it does not accept with `401` or `403`, never `404`. With a `credential`, every URL must be at one origin. Reading the password call's `401` as no such user is kept for 0.17's ledgers, and is to go in a later release, after which it reads as a lookup's does; a `403` is already unavailable.

### MFA and federation

- With `mfa.mode = optional`, removing the last second factor also removes the recovery codes. Where an enrollment witness is composed, the last counting factor is not removed, as with `required` (`409 mfa_last_factor`): only a reset ends an enrollment the witness marked.
- After a second factor completes a held login, the answer carries the return target.
- A federated login passes the same login gates as any other, MFA included, unless its amr holds `mfa` (from 0.19, where the IdP's `upstream-amr` maps a value to it). See [upstream amr](#upstream-amr).
- An upstream identity with no link to a user is refused (`401 unknown_user`); no account is created.
- Google logins forward `prompt=login` and `max_age`, and a Google login older than `max_age` is refused.
- A login whose time the upstream does not give (always GitHub's) is never a recent sign-in. Changing credentials then needs a recent second factor, so a GitHub-only user with no second factor gets `step_up_required`.

- A federated login keeps only `email`, `email_verified`, `name` and `picture` from the upstream; other claims, such as groups, are not taken. `email_verified` is true only where the IdP type vouches for it (never for GitHub).
- An upstream token that is not a bearer token no longer fails the login: the login goes through, and the federation token route answers `502 upstream_token_ineligible`.
- Refreshing an upstream token sends `scope` when the allowed scope is not empty.

#### Federation tokens and Sign in with Apple

- A `prompt=login` or `max_age` login through Apple now gets `401 login_required` unless Apple's id_token carries `auth_time` (conformance `apple-freshness-login-required`).
- Apple logins no longer read the user's name from the posted `user` field, and no longer ask for `name` unless `scopes` lists it.
- The signed Apple client secret now lives 5 minutes by default instead of 180 days, so it is signed far more often.
- Only a registered client in `clients.registered` can receive upstream tokens. A metadata-document client cannot.
- The token and upstream logout routes are limited per source (60 per 60 s by default).
- A token due for refresh whose upstream offers no refresh, or whose IdP is no longer configured, gets `410 refresh_not_supported` and the audit event `federation.token.failed` (reason `not_supported`). 0.17 answered it `503`, which reads as worth retrying, and recorded no event; log the user in again instead.
- A failed refresh is answered from memory for 30 s per process, as before. Locks and record lifetimes now follow `federation-tokens.*` rather than the store's own settings.

### Passkeys

- A framed registration whose browser reports no top origin, with no `top-origins` configured, gets `400 top_origin_mismatch`.
- A registration without the required user verification gets `400 user_verification_required`.
- Passkeys per subject are capped by `webauthn.max-credentials` (default 10).

### Consent

- The 200-character limit on a client's name on the consent screen counts code points; 0.17 counted UTF-16 units, which differs only for characters outside the BMP near the limit.

### Mail

- Recipient domains beyond ASCII are sent in their IDNA ASCII form. A domain whose ASCII form would name a different domain is refused, unsent.

### HTTP responses

- `/_healthcheck` still answers `200 {"status":"ok"}`, now with `Content-Type: application/json` (no charset) and `Cache-Control: no-store`. Probes that match the exact content type need updating.
- `/readyz` answers `{"status":"ready"}` or `{"status":"unready"}` only; the `checks` list is gone.

### Log and audit lines

Both streams are still one JSON object per line on standard output, but neither line keeps 0.17's shape. A log pipeline that routes or alerts on 0.17's fields stops matching without an error: a filter on `name == "audit"` no longer separates the audit trail, a numeric `level` threshold matches nothing, and `msg` and the `audit.*` fields are gone. Change those filters before you upgrade.

| | 0.17 | 0.18 |
|---|---|---|
| Log line (`log-stdout`) | pino's: `level` a number (`30`, `40`, …), `time`, `name: "provider"`, `msg` | `level` (a string: `trace`, `debug`, `info`, `warn`, `error` or `fatal`), `at` (epoch ms) and `event` first, then the line's fields; no `name`, `time` or `msg` |
| Audit line (`audit-stdout`) | pino's, with `name: "audit"`, the event type as `msg` and the event under `audit` | `kind`, `at` (epoch ms), and `subject` and `attributes` where given; no `level`, `name` or `msg` |
| Telling them apart | `name` (`provider` or `audit`) | A line with `level` is a log line; a line with `kind` and no `level` is an audit event |

```json
{"level":"info","at":1792502666577,"event":"http.listening","port":18080}
{"kind":"token.issued","attributes":{"client":"svc-client","source":"127.0.0.1","grant_type":"client_credentials"},"at":1792502671322}
```

A threshold on pino's numbers becomes a set of names: `level >= 40` is `level` in `warn`, `error` or `fatal`. An alert on `msg` matches `event` on a log line and `kind` on an audit line. An audit event's fields map as below; each event's attributes are in the [audit event reference](audit-events.md).

| 0.17 (`audit.*`) | 0.18 |
|---|---|
| `type` | `kind` |
| `timestamp` (an ISO time) | `at` (epoch ms) |
| `subject` | `subject` |
| `clientId` | `attributes.client` |
| `ip` | `attributes.source` |
| `userAgent` | `attributes.userAgent`, on the events that carry it |
| `details.*` | `attributes.*` |

## From 0.18.0-rc.1

Coming from rc.1, read this section, then [From 0.18.0-rc.2](#from-0180-rc2) and [From 0.18.0-rc.3](#from-0180-rc3).

- **Sealing keys**: `seal.keys` is refused at boot; write its first key as `seal.current` and the rest as `seal.previous`. Rotating a key now has a procedure, in the [runbook](runbook.md#rotating-the-sealing-key).
- **MFA factor lists written by rc.1** hold no subject, so `reseal` cannot seal their secrets again and counts them as left (exit 2) until the user next proves or changes a factor, which writes the subject. While such lists remain, do not retire a `previous` key that sealed them.
- **Times and sizes**: every time and size key lost its unit suffix and is written with a unit (`30m`, `64KiB`); a number without one refuses boot. The renamed keys are in [Times and sizes](#times-and-sizes), among them `federation-grants.connections.<name>.max-access-token-lifetime`, which was `max-access-token-seconds`.
- **Linked upstream identities**: a written link no longer lets in a subject that the settings' users or the ledger answer none for; that login is refused. Where the ledger cannot look users up by subject (`users-http` without `subject-url` or `upstream-url`), that login is now unavailable (`503`) rather than signing in a user with no attributes: set one of them.
- **Subjects**: a subject is 1 to 255 ASCII characters, as OpenID Connect bounds `sub`. A user in `users.registered` with no `subject` takes its identifier as the subject, so one whose identifier is outside ASCII (`Zoë`) now refuses boot at `users.registered.<i>.subject`; write a `subject` for it. A user ledger that answers a subject outside that bound is now unavailable.
- **JWT bearer issuers**: each of `jwt-bearer.issuers` needs `subject`: `"as-is"` (the assertion's `sub` is the subject, as rc.1 read it) or `"linked"` (the user `users` links to the signer, with `upstream` naming its IdP). An issuer without it refuses boot at `jwt-bearer.issuers.<i>.subject`; write `subject = "as-is"` to keep rc.1's reading.
- **Upstream links in settings**: each `idp` in `users.registered[].upstream` must be a name a composed module declares: a `federation` IdP, a linked `jwt-bearer` issuer's `upstream`, or one `exchange-id-tokens` takes. A link through any other name refuses boot at its `idp`; nothing would ever look it up.
- **JWT bearer assertions spent under rc.1**: they were kept in the `jwt-bearer.jti` space, and this version keeps them through `jwt-bearer-store`, so it does not see them. An assertion spent just before the upgrade could be exchanged again until it ends, at most `jwt-bearer.max-assertion-lifetime` plus `jwt-bearer.clock-skew` (about 1 hour 30 seconds by default). Stop taking the JWT bearer grant for that long before you upgrade, or accept a reuse within that window.
- **audit-http**: with `authorization`, a collector at a `plain-loopback` pair outbound names is now reached over plain http too; rc.1 took https alone, and any other plain http URL is still refused. The value may no longer end in a space.
- **id_tokens exchanged under rc.1**: `exchange-id-tokens` kept the id_tokens it took in its own space, and this version keeps them through `exchange-id-tokens-store`, so it does not see them. An id_token exchanged just before the upgrade could be exchanged again until it is no longer taken, at most `exchange-id-tokens.max-age` plus `exchange-id-tokens.clock-skew` (about 10 minutes 30 seconds by default), and while instances of both versions run, once on each. Stop the old version and wait that long before you start the new one, or accept a reuse within that window.
- **MFA under `required`**: boot is refused unless a composed kind both counts and adds a second factor. With `mfa-email` alone, set `mfa-email.adds-second-factor = true`.
- **Managed Redis**: where the server refuses `CONFIG GET`, declare its settings in `redis.server-settings`; where it keeps no append-only file, set `redis.durability = "none"`. See [A managed Redis that refuses `CONFIG`](runbook.md#a-managed-redis-that-refuses-config).
- **A user ledger over HTTP that answers a wrong password `403`**: users-http reads a password call's `403` as unavailable (the login answers `503`, counting no attempt), no longer as no such user, since a proxy before the ledger may send one while it fails; answer a wrong password or an unknown identifier `401`.
- **users-http**: `verify-url` is now optional, and `subject-url` is new. With a `credential`, every URL must share one origin, or boot is refused.
- **idp-google**: `hosted-domains` is new and optional; nothing to change.
- **Generated apps**: the command is `create-auth-provider`, and a generated README names the audit receivers of the adapters composed; an app already generated needs no change.
- **Configuration files**: a file that does not parse, or a substitution that does not resolve, is refused at its `file:line:col`; nothing to change.
- **Audit events**: `introspect.store_unavailable` is now `introspection.unavailable`, with the same `source`; a receiver that matches the old name needs it. Introspection answered unavailable also logs the warning `http.unavailable` with `route: "/oauth/introspect"`, as revocation does.
- **Managing factors**: the routes `GET /session/mfa/factors`, `POST /session/mfa/factors/rename`, `POST /session/mfa/factors/remove` and `POST /session/mfa/recovery-codes` now come from the `mfa-management` module. An app generated with rc.1 that composes `mfa-flows` must also compose `mfa-management` to keep them; its POSTs are counted per source under `mfa-management.requests` and `window`, apart from `mfa-flows`' routes.
- **A second factor of your own**: `factorKinds`, `firstBindingGates`, their types, `AskedFrom` and `secondFactorAmr` moved from `@mod/mfa` to `@mod/mfa-extensions`; import them from there.
- **Checking secrets in a module of your own**: `secretChecker` is gone from `secret-hash`; take `secretCheckers` from the build context and call `checkerOf`, whose checkers share the assembly's `max-concurrent` (rc.1 shared one limit across the process, set by the last assembly built).
- **Removing a factor or reissuing recovery codes**: both now ask a second factor proven recently. Under `optional`, a session signed in by password that binds its first factor must step up with it before it reissues the codes (rc.1 took the recent sign-in).
- **A first factor bound meanwhile**: a first binding begun while the subject held no counting factor no longer binds when another counting factor was bound before it finished. It writes nothing and records `mfa.first_binding_conflict` (`kind`); a login held for it gets `401 login_required`, a session `409 mfa_enrollment_conflict`. rc.1 bound it beside the other.
- **Federation grants**: `federation-grants.sweep-interval` is new (default `1h`, `1m` to `1d`): each instance erases, that often, the credentials of grants past their end or ended by their subject's revocation, though no request reads them. rc.1 erased them only when a grant was next read.
- **A store adapter of your own**: `put`, `getMany`, `setAdd`, `setMembers` and `setRemove` are gone from the `store` contract, with the helper `getFollowing`; nothing called them, so an adapter no longer offers them. To write whatever a key holds, read it and write on its version with `replaceIf`, or with `putIfAbsent` where it holds none, as `mutate` does.
- **A module of your own that checks a URL against outbound at boot**: `outboundPolicy` and its `refusalOf` are gone; take `outboundRefusals` and call `explained(url, narrower)`, which answers the refusal as `<reason>: <what to set>`, naming outbound's keys and no value, or nothing when the URL goes through. Boot refusals of a refused URL now say which key to set.
- **A module of your own that reads cookies**: `Cookies.read` is gone; call `lookup`, which answers the cookie (`found`), none (`absent`), or `withheld` with why (`plain-http` or `duplicate`). A hand-made `Cookies`, as in a test, offers `lookup` and no `read`.
- **A module of your own that asks a session by handle**: `stillOpen`, `openContext` and `endsAt` are gone from `session`; call `entryOf(handle)`, which answers the entry the session's cookie would get at `use`: `entered` (with its `session` and `endsAt`), `absent`, or `short` with the requirement it falls short of. rc.1's three answered a short session as a closed one.
- **A link refused for a short session**: `federation.identity.link_refused` records `reason: "session_short"` when the session that started the link is short of a requirement; rc.1 recorded `login_required`, as for a closed one. The answer is still `401 login_required`.
- **RP-initiated logout of a session short of a requirement**: it records `logout.success` and sends the browser on to the client's return, the upstream or the front-channel page, as for any live session; rc.1 closed it as one already gone, answering `{"logged_out":true}` with no event.
- **RP-initiated logout of a session past its lifetime**: where its record is still kept (a host's clock behind another's, or a shorter lifetime set since), the logout now closes it through its participants, ending its tokens and telling its clients, and records `logout.success`; rc.1 ended it with neither. A logout sent again while its close is pending answers `503` again, never done. A `session` of your own may say, in each close's `from`, the state it found the record in; rp-logout counts a close as the logout only when that is `open` or `closing`.
- **Revoking a user from the ledger**: `subject-revocation-http` is new: an outside ledger posts a subject, with a credential from a listed source over https, to end the user's open sessions and tokens here too. Nothing changes until you compose it; see the [runbook](runbook.md#revoking-a-user-from-the-ledger).
- **A refresh the upstream refuses until the user acts there** (`interaction_required`, `login_required`, `consent_required` or `account_selection_required`): `federation-tokens` now answers `403 upstream_interaction_required` and forgets that IdP's tokens, recording `federation.token.failed` with the reason `interaction_required`. `federation-grants` erases the grant's credentials and answers `410 reauthorization_required` (`upstream_interaction_required`). rc.1 read that refusal like any refused refresh: `federation-tokens` answered `500 refresh_failed` (reason `failed`) and kept the tokens, and `federation-grants` handed an access token it still held or answered `502 upstream_rejected`, keeping the credential.
- **Unavailable warnings**: `token-endpoint.unavailable`, `token-control.unavailable`, `device-grant.unavailable`, and `authorize.unavailable` before the redirect URI is confirmed, are now one warning, `http.unavailable`, with `what`, the route's path as `route` (`/oauth/revoke`, not `revoke`) and, from the token endpoint, the `grant_type` it dispatches to. A log alert that matches the old names needs the new one; `authorize.unavailable` stays only for an unavailable answered by redirect to the client.
- **A 503 a route does not declare**: it now carries the JSON body `{"error":"service_unavailable"}`, kept out of caches as before; rc.1 answered it with no body.
- **A route of your own that answers unavailable**: `answeringUnavailable` is gone from `@mod/token-endpoint`; declare `unavailable` on the route you contribute to `http`, with its answer and, in `noted`, the fields only the route knows.
- **A route of your own**: every route contributed to `http` declares what it guarantees, or boot is refused naming it. A `GET` says `changesState`. A route that changes state uses, for its method, a policy marked `own-site` (`csrfChecked`) or gives `crossSite`, the reason it takes other sites' requests, and a policy marked `per-source` (`attemptsPerSource`, `requestsPerSource`) or gives `unlimited`, the reason it counts no source. The [route reference](routes.md) shows each route's.
- **A grant of your own**: it declares `readsAmbient`: `cookie` when it reads the session's cookie, and then checks the request's origin itself, or `none`. A grant without it refuses boot.
- **HEAD on a GET that changes state** (`/oauth/authorize`, `/oauth/logout`, and the browser routes of `federation` and `federation-grants`) is answered `405` with the path's methods in `Allow`; rc.1 ran the GET.
- **Federation grants' consent**: a `POST /session/federation-grants/consent` from another site is refused before it is counted against the source's requests, so it no longer uses up the window.
- **Second factors and revocation**: `mfa-revocation` is new, a bridge of `mfa` and `subject-revocation` that `combinations` composes with them: a revocation is complete only once no second factor's enrollment begun before it can bind, and `503 incomplete` while `mfa`'s store cannot answer. An app composed by hand must add it. `mfa`'s `bind` answers `fenced` (a reset or a revocation since the binding began) where rc.1 had no such answer.
- **Second factors and sessions**: `mfa-entry` is new, a bridge of `mfa` and `session` that `combinations` composes with them; it now sets the entry requirement `mfa` (same name, same answers) and offers `secondFactors.provenRecently`. A module of your own that called `factors.provenRecently` takes it from `mfa-entry`, one that called `factors.recent` takes `session`'s `recent`, and `countingHeld` takes where it is asked (`login`, `binding` or `credentials`). Every credentials entry now reads the subject's factors first, so a factor store that cannot answer makes credentials routes unavailable. An app composed by hand must add `mfa-entry`: `mfa` refuses to boot without it.
- **Removing a factor or reissuing codes from a module of your own**: `factors.remove` and `factors.reissue` take the fence `factors.fenceOf` answered before the change was allowed, and answer `fenced`, changing nothing, once a reset or a revocation moved it since.

## From 0.18.0-rc.2

What changed since rc.2, before [From 0.18.0-rc.3](#from-0180-rc3). Coming from rc.1, read [From 0.18.0-rc.1](#from-0180-rc1) first.

- **Trusted proxies**: a `http.trusted-proxies` entry covering every address of a family (any `/0`, or every IPv4 address mapped into IPv6, as `::ffff:0:0/96` or `::/1`) now refuses boot at that entry, as it would make every client a proxy; list the proxies' own addresses.
- **zod**: the packages take `zod` as a required peer (`^4.6.0`); an app depends on `zod` itself, at the version the packages take.
- **Sessions in an app composed by hand, and an entry requirement or closing participant of your own**: `session`'s points for entry requirements and closing participants are gone; they are the bridges `session-requirements` and `session-participants`, which `combinations` composes with `session`, and `session-lifecycle` refuses to boot without them. Contribute to their points, importing the types from them.
- **`authorize` in an app composed by hand**: its redirect-URI rules and its re-authentication records are the packages `redirect-uris` and `reauth`, which `combinations` composes with it. `authorize` no longer re-exports `redirects`, `registrable` and `redirectsAt`, nor its store interface: import them from `redirect-uris` and `reauth`. The `authorize-store` template wires `reauth`'s store in the same space, so records written before carry over. The client metadata section keeps its name `authorize`.
- **outbound's destination policy in a module of your own**: `outboundRefusals`, `credentialPolicy`, their types and the host list readers come from `@mod/outbound-policy`, which `combinations` composes with `outbound`, and `outboundLimits` is new there; `@mod/outbound` keeps `DestinationRefused`, `Narrower` and `RefusalReason`.
- **A grant of your own that authenticates its client**: `token-endpoint`'s `authenticateClient` takes the audit (`Pick<Audit, "record">`) as its third argument, and records a refusal as `client.authentication.failure`; pass the `audit` your module takes.
- **outbound.proxy** is written as an origin alone, as the URL parser writes it: no path, not even a trailing `/`, no default port, the host in lower case (`http://proxy:3128`). Earlier release candidates also took a trailing `/` and other spellings, which now refuse boot at `outbound.proxy`.
- **A code by mail as a second factor**: it counts only where `mfa-email.adds-second-factor = true`; by default it is a way back only, as the [mapping](#configuration-mapping) says. Earlier release candidates counted it whatever that setting, so a user whose only factor is a code by mail no longer holds one that counts. An app generated from the `mfa-web` pattern does not set it; set it to keep a code by mail counting.
- **A code store of your own**: the place it gives `codeStoreContract` (`@mod/code-grant/testing`) names its void list's crowd `crowd.names`, no longer `crowd.hashes`; rename it.
- **A token-exchange verifier of your own**: its answer now says its `kind`. `own`: a token naming the client by issued-to or audience, with its own scope and audience (and binding, actor chain, `may_act`). `foreign`: another issuer's token for an app, with `clients` (at least one) and an optional `holderDigest`, its scope and audience the client's allowance; it never acts. `ceiling` is gone, and an answer without a `kind` is invalid.
- **A module of your own that reaches a private address through outbound**: a narrower's `internal: true` is gone; read your URL setting with `url-setting`'s `urlSetting` and pass that URL as `internal` (`{ internal: c.section["my-url"] }`). A private address in `outbound.internal-hosts` is then reached only at that URL's origin (scheme, host and port), not at another port of the same host.
- **A module of your own that reads refresh's families**: `lineage`'s `of` and `adopt`, with `FamilyHandle` and `TokenFamily`, are gone from `@mod/refresh`, and `lineage` offers `start` alone. What a token this provider issued is tied to is asked through `grants`' `tokenTies`: `refresh`'s `family` tie and `session-tokens`' `session` tie, each with a `join` for a token issued from it.
- **token-exchange in an app composed by hand**: it reads a token's family and session through those ties, so composing it no longer brings `refresh`, `session-tokens` and `session`; where they are composed, each contributes its tie and the checks are as before.
- **Client metadata documents** (`clients-cimd`): a document whose record a section's schema refuses (a redirect URI the redirects section refuses, a `client_uri` that is not https) is now logged as `clients-cimd.document_refused` with where the record fails (`record at sections.consent.uri`) and remembered for `refused-lifetime`; earlier release candidates kept it for `cache-lifetime` and logged nothing. A `client_uri` that is not a string is now refused that way too, no longer with the reason `client_uri`.
- **`clients-cimd` without `authorize` or `consent`**: each section now copies its own fields from a document, and boot is refused where no composed section copies `redirect_uris` (`authorize`'s) or `client_name` (`consent`'s). With the `a2a` pattern, add `@mod/authorize` beside `--add @mod/clients-cimd`.
- **A client source of your own that gave consent's section**: `displayed` is gone from `@mod/consent`; write the section's value (`name`, `uri` if any, `host`) yourself, or take it from `clientSection.fromDocument`.
- **A `Clients` of your own** (a stand-in of the contract): it offers `checkRecord`, which checks a record as `find` holds a source's. A metadata section of your own may give `fromDocument` and `reads` to be copied from a client's metadata document; nothing else changes.
- **Passkey nicknames**: a nickname is now 1 to 64 code points, well formed, with no control character, line separator or bidirectional control, the same rule as a second factor's label. A registration whose nickname breaks it gets `400 invalid_request`; earlier release candidates took any 1 to 64 UTF-16 units. Passkeys already kept keep their nicknames.
- **Binding a factor from a module of your own**: `factors.bind` writes no recovery codes and no longer answers `recoveryCodes` or `recoveryCodesFactor`; it answers the `fence` the binding began under and `codesDue`. Where `codesDue`, call `factors.reissue(subject, fence)` once the codes can be shown, and show what it answers: `reissue` writes the first set too, and answers `full` where another factor took the place the binding kept for them.
- **Recovery codes at enrollment**: a first factor's codes are written only as they go out, once its login opened or its session's raise was written. Where either fails, none are written, where earlier release candidates wrote them and took them back; a raise not written answers the factor alone, and `POST /session/mfa/recovery-codes` issues the codes later. That route answers `409 mfa_factor_limit` to a first set past `max-factors`.
- **An operator's reset of second factors**: `mfaReset` now comes from `mfa-reset`, a bridge of `mfa-flows` that `combinations` composes with it; import it from the `mfa-reset` subpath instead of `mfa-flows`. Binding a factor now comes from `mfa-enrollment`, composed alike; its routes and answers are unchanged. An app composed by hand must compose both beside `mfa-flows`, which refuses to boot without `mfa-enrollment`. `reset` answers only the number of factors it removed. The kinds removed are in the `mfa.reset` audit event (`kinds`, `count`), and where an unfinished run stopped is in its log line `mfa-flows.reset_incomplete` (`stoppedAt`); 0.17's report of where it stopped and whether it overran its deadline is not returned. A run that stops rejects, and running it again finishes it.
- **Upstream round trips** (a federation login or link, a federation grant's connection) are kept by the new `upstream-round-trip`, in a new space, `upstream-round-trip-store.round-trips`, which the store must replicate. Round trips in progress when the provider is upgraded are lost and start again. A federation grant's connection now sets a cookie of its own for its round trip: its callback is taken only in the browser that began it (another browser's takes nothing and spends nothing, where earlier release candidates refused it for the session and spent it), and starting a second connection to the same upstream in one browser ends the first one's.
- **Held logins** (a federation login a gate holds, its upstream tokens sealed until it opens) are kept by the new `upstream-handoff`, in a new space, `upstream-handoff-store.held-logins`, which the store must replicate; `federation-store.transactions` is no longer used. A login held before the upgrade and resumed after it, before its deadline, opens without handing its upstream tokens over; one resumed past its deadline is refused, as before. The log events of handing tokens over are renamed from `federation.*` to `upstream-handoff.*`: `receiver_failed`, `link_join_failed`, `link_join_undo_failed` and `held_login_refused`.
- **A login through an upstream that a second factor holds** used to answer the upstream's callback with JSON a browser cannot act on. Set `federation.held-page`, a page on the public origin that goes on with it, as the [login page guide](login-page.md#a-login-through-an-upstream-that-a-second-factor-holds) describes; `federation` refuses to boot where its origin is another. During a rolling upgrade, set it only once every instance runs this version: an earlier one answers that page's read `400`. Rolling back makes the logins held meanwhile answer `400` until their transactions end, 30 minutes at most.
- **An app generated with an earlier release candidate that composes `federation`**: its `src/main.ts` imports `federation-store` and none of `upstream-round-trip`, `upstream-round-trip-store`, `upstream-handoff` and `upstream-handoff-store`, and `federation` now refuses to boot without the round trips. Generate the app again, or add those four modules and remove `federation-store`. Its configuration is unchanged.

## From 0.18.0-rc.3

What changed since rc.3. Coming from an earlier release candidate, read the sections above first.

- **A login page that offers sign-in through an upstream**: the provider now adds `prompt=login` and `max_age` beside `redirect_to` when the client asked them. Hand them on to the upstream's start (`/session/oauth/federation/<idp>`), so the upstream logs the user in again; see the [login page guide](login-page.md).
- **A request carrying a re-authentication record that is not its own** (spent, unknown, or made for other parameters, as when a demand was taken out of its return): it is refused with `login_required`. A login page that returns to `redirect_to` as it was given is not affected.
- **A request back from its login still not new enough**: it is refused with `login_required` whether the session's authentication time is known or not. rc.3 sent it to the login page again.
- **Discovery**: the metadata says `authorization_response_iss_parameter_supported: true`; every redirect answer already carried `iss`.
- **0.17's environment variables** are not read: if the environment or secret store you carried from 0.17 still holds them, remove them as [Migration steps](#migration-steps) says, writing the values you keep into the configuration.
- **A user ledger's lookups** read a `404` as no such user, whatever sent it: refuse a caller the ledger does not accept with `401` or `403`, never `404`, and check that each URL reaches the route itself, as [User ledger over HTTP](#user-ledger-over-http) says.
- **Log and audit lines** have the shape they had in earlier release candidates, but no earlier guide described it, nor how 0.17's filters stop matching: see [Log and audit lines](#log-and-audit-lines).
- **An HS256 secret carried from 0.17**: 0.18 decodes `keys.signing.secret` and takes the decoded bytes as the key, where 0.17 took the string's own bytes; a value copied as written signs with another key. The [mapping](#issuer-and-signing-keys) says how to keep 0.17's.
- **A client's session grant** is allowed under `sections.client-allowance.grants`; an earlier guide named `sections.token-endpoint.grants`, which refuses boot as an unknown section.
- **An address in `outbound.deny`** is refused also where a name resolves to it, not only where a URL writes it: a name that resolves to an address you denied is no longer reached. An IPv4 address carried in IPv6 counts as the IPv4 one.
- **A federation grant's renewals** count with its lodgings: a client's renewals and lodgings together take `federation-grants.lodges` per `lodge-window`, and past it a renewal answers `429` with `retry-after`. Raise `lodges` where clients renew often.
- **`federation` with no IdP** still boots, but warns `federation.no_idps` at each boot, as every login answers not found.

## From 0.18.0-rc.4

What changed since rc.4. Coming from an earlier release candidate, read the sections above first.

Before you upgrade, do these three; each stops a deployment that upgrades first:

1. **Mark a user ledger's "no such user"**: have it answer `404` with `{"error":"not_found"}` and `410` with `{"error":"gone"}`, as [below](#a-running-deployment) says. rc.4 reads a marked `404` as it reads a bare one, so the ledger can change first.
2. **Allow a managed Redis the commands the store needs** (`WAIT`, `ROLE`, `INFO`, `EVAL`, and the commands its scripts call), as the [runbook](runbook.md#managed-redisvalkey-with-replicas) lists: this version refuses boot where one is refused.
3. **In an app composed by hand, compose the bridges**: `session-tokens` beside `code-grant`, `mfa-revocation` beside `mfa-flows`, `mfa-witnessing` beside a witness, and `federation-link` beside `federation`. An app made by `create-auth-provider`, or composed through `combinations`, has them already.

After upgrading an app with a second-factor witness, run its `witness-backfill` script once.

### A running deployment

- **A user ledger over HTTP**: every unknown user's federated login and lookup answers `503` until the ledger marks its "not found". users-http now reads a lookup's (`subject-url`, `upstream-url`) `404` as no such user only with the JSON object `{"error":"not_found"}`, and a `410` only with `{"error":"gone"}`. A `404` or `410` saying neither (a mistyped URL, a route not deployed, a gateway's unknown route, a ledger hiding itself) is unavailable, logged as `users-http.ledger_failed` with its status and `reason: "unmarked"`. Change the ledger before upgrading: rc.4 reads the marked answers as it reads bare ones. To keep logins working: have the ledger answer a user it does not know `404` with `{"error":"not_found"}` (`Content-Type: application/json`), and a user it knows but refuses `410` with `{"error":"gone"}`; refuse a caller it does not accept with `401` or `403`, never `404`. See [User ledger over HTTP](#user-ledger-over-http).
- **A Redis store on a managed service**: boot sends the commands the store needs once and is refused, naming the command, where the service refuses one (`WAIT`, `ROLE`, `INFO`, `EVAL`, or a command a script calls); rc.4 booted and answered 503 to every replicated write. Allow the commands the [runbook](runbook.md#managed-redisvalkey-with-replicas) lists before upgrading: a deployment rc.4 ran refuses boot under this version until they are allowed.
- **An HS256 secret**: `keys.signing.secret-encoding` names how `secret` is read (`hex`, `base64`, or `utf8`, the text's own bytes); unset, it is read as before, and a value not of the reading named refuses boot. To keep 0.17's key, or to share the secret with policy-verifier, which takes the text's own bytes, set `utf8`.
- **Linking an upstream identity**: the callback now checks the session at `credentials`, as the start did. Without `mfa`, that is a sign-in within `session-lifecycle.recent-authentication` (`5m` unless set), so a user who spends longer at the IdP is refused `401 login_required`; they sign in again and start the link anew. Nothing is written for the refused link.
- **A link under way during the upgrade**: its round trip, begun under rc.4, is read as `invalid_state` at the callback; the user starts the link again.
- **An IdP on a private network**: an OpenID Connect issuer or a GitHub Enterprise at a private address, refused since rc.1, is reached again where `outbound.internal-hosts` lists its host (and `outbound.allow` names it). Only the issuer's origin and the endpoints you give are reached privately; an endpoint the description names on another origin, another port included, reaches public addresses only. Where the description puts an endpoint on another origin, set `discovery = false` and give the endpoints (`authorization-endpoint`, `token-endpoint`, `jwks-uri`, and `end-session-endpoint` where it has one): over plain http, name each endpoint's `host:port` in `outbound.plain-internal`; over https, its host in `internal-hosts`.
- **An IdP endpoint the browser goes to over plain http now refuses boot unless outbound takes it for the browser**: an OpenID Connect IdP's authorization and end-of-session endpoints (described or given) and a GitHub IdP's `authorization-endpoint` must be https, or plain http at a loopback name (`localhost`, `127.0.0.1`, `[::1]`) or at the origin of the issuer or the given endpoint where `outbound.plain-internal` names its `host:port`; a Google or Apple IdP's `authorization-endpoint` and `end-session-endpoint` must be https, or plain http at a loopback name. An issuer on plain http no longer makes plain http right for every endpoint its description names, and a name that only resolves to loopback (say `idp.local:8080` in `outbound.plain-loopback`) is refused for the browser; the token endpoint and key set are still judged by `outbound.plain-loopback` and `outbound.plain-internal` as before.
- **A `plain-loopback` pair** is reached only where the address is loopback as written: a name that resolves to an IPv6 form that only carries 127/8 (`::7f00:1`, `::ffff:0:7f00:1`), or a URL that writes one, is refused as a special address; rc.4 took it as 127.0.0.1. A proxy named by a name, `localhost` included, now warns that `proxy-authorization` goes in the clear; write the proxy as a loopback address (`http://127.0.0.1:3128`) where it runs on the host.
- **An address written in a URL** is reached as written: a public IPv4 address written in IPv6 (`https://[::ffff:5db8:d70e]/`, or `[::5db8:d70e]`) is refused as a special address, as a name resolving to that form already was; rc.4 reached it as the IPv4 address. Write the IPv4 address itself (`https://93.184.215.14/`).
- **Sign in with Apple**: a callback on a name under `localhost` or on 127/8 mapped into IPv6 now refuses boot, as `localhost` and 127/8 already did.
- **mail-smtp with `security = none`** boots for the same loopback hosts by name (a name under `localhost`, `localhost.`), and sends only when the connected peer is a loopback address, 127/8 mapped into IPv6 in any spelling included. Write an IPv6 host without brackets (`::1`): a bracketed one refuses boot under `none`.
- **A URL that takes plain http on a loopback host** (a login or step-up page, a return target, a federation grant's page) now also takes a name under `localhost` (such as `http://app.localhost:3000/`), `localhost.` with its trailing dot, and 127/8 mapped into IPv6 (`http://[::ffff:7f00:1]/`): the host is judged by its name alone, by `url-setting`'s `isLoopbackName`. Such a name reaches loopback only where the browser's resolver keeps names under `localhost` there, as RFC 6761 asks and current browsers do. `localhost.localdomain`, `0.0.0.0` and any other host over http still refuse boot.
- **When the second-factor witness is marked**: a binding marks the subject after its factor is written, so a failed write no longer leaves a mark that refuses the subject until a reset. Subjects that enrolled before the witness was composed are marked with the app's new `witness-backfill` script, in place of marking them at the ledger by hand (see the [runbook](runbook.md#keeping-the-second-factor-witness-at-the-ledger)). An app generated before carries no such script: generate it again, or copy `src/witness-backfill.ts` and its script from a newly generated one.
- **0.17 variables left in the environment**: a generated app's entry writes `warn config-files: N variables named in 0.17 are set and never read: …` to standard error once when the environment sets a variable 0.17 read and none of the app's configuration files reads it, naming it, never its value; boot goes on. Such a variable has no effect: map its setting with the tables above, then remove it.

### A generated app or one composed by hand

- **An app's entry reads its configuration files from the `config-files` module**: `loadConfig` and `ConfigSource` moved there from the kernel, unchanged. An app generated with an earlier release candidate imports `loadConfig` from the kernel in `src/main.ts` (and `src/reseal.ts`, where it has one). An app on the published packages imports it from `@o3co/auth-provider-foundation/config-files` instead of `@o3co/auth-provider-foundation/kernel`, and upgrades `@o3co/auth-provider-foundation`; it adds no dependency. An app in the workspace imports it from `@mod/config-files` and adds that package to its dependencies. Or generate the app again. Its configuration is unchanged.
- **An app made from listed modules** (`create-auth-provider <target> <module>…`) now holds what those modules need to run, and is written as a pattern's app is: its configuration file reads each key from the environment and holds no value, beside `.env.example`, `config/local.conf.example`, a Dockerfile, a README and `AGENTS.md`. Generate it again and carry your settings into `.env` or the local layer: boot refuses until `kernel.deployment` and the keys its README names are set.
- **An app that composes its modules by hand** (its own `assemble`) composes `session-tokens` where it composes `code-grant`, and `mfa-revocation` where it composes `mfa-flows`, as `combinations` does by itself: without them, boot is refused (`code-grant`: its tokens must be recorded to their session; `mfa-flows`: a binding begun before a revocation would bind). An app generated by `create-auth-provider` has them already.
- **The second-factor witness in an app composed by hand**: `mfa-witnessing` now keeps the witness for `mfa`; compose it beside `mfa-witness-http` (or a witness of your own). Without it, `mfa` refuses boot ("an enrollment witness is composed without mfa-witnessing"), so a witness is never left unasked. `combinations` adds it. Once upgraded, run the app's `witness-backfill` script once to mark the subjects that enrolled before. `mfa.enrollment_inconsistent` is declared by `mfa-witnessing` now, with the same attributes.
- **Linking upstream identities in an app composed by hand**: compose `@mod/federation-link` (`@o3co/auth-provider-upstream-login/federation-link`) beside `federation`. Without it, boot goes through and logins work, but every start with `link=1` is refused `400 continuation_unavailable`, warned `federation.continuation_missing` each time, and nothing warns before such a start comes: check a link once after upgrading.

### A module of your own

- **`client.authentication.failure` is declared by `clients`** (`@mod/clients/audit-events`), no longer by `token-endpoint`, with the same name and attributes: a receiver needs no change, and a check of your own that reads the declarations finds it there. A route of your own that calls `clients`' `authenticate` records its refusal through `recordRefusedAuthentication`, handing it the `audit` your module takes.
- **A grant of your own that needs claims of its own in the access token**: put them in `AccessGrant.claims` and issue through `issue`. A module that signed an `at+jwt` with `keys.sign` moves to `issue`, and one that verified it with `keys.verify` to `verifyAccess`: both now refuse that type (a TypeError). Such a module's tokens still pass `verifyAccess` until their `exp`, which may lie up to a day after their `iat`, and an `iat` may stand up to 60 seconds ahead of the clock. A resource server that checks tokens against the published key set alone applies none of these checks. To end them at once, after upgrading [rotate the signing key](runbook.md#rotating-the-signing-key) and then remove the old key from `keys.previous` rather than waiting for its `expires-at`. The key set is advertised as cacheable for 300 seconds, but nothing makes a verifier drop it then.
- **Access tokens not issued by `tokens`**: an `at+jwt` carrying a name reserved for what `tokens` never writes (`nbf`, `roles`, `email` and the like) is refused by `verifyAccess`, which retires such tokens on purpose; so is one whose `exp` comes before its `iat`, whose `iat` is over 60 seconds ahead of the clock, or with over a day between them.
- **Added claims and restrictions**: a refreshed or exchanged token carries no added claim; never use one for a restriction that must hold on.
- **Audit**: `token.issued` may carry `claims`, the names of the claims a grant added, and `claims_left`, how many names did not fit.
- **A store of your own for revoked access tokens**: it still imports `revokedTokens` and `revokedTokensNeeds` from `tokens`, which passes on `token-denylist`'s; the contract test it runs, `revokedTokensContract`, moved from `tokens`' `./testing` to `token-denylist`'s. A boot with no such store names the contract `token-denylist.revoked-tokens`, where it named `tokens.revoked-tokens`.
- **A passkey assertion whose request named no credential needs the user handle**, as WebAuthn asks: `webauthn`'s ceremony refuses one without it (`user-handle`). Registered passkeys and second factors need no change. A module of your own that calls `ceremonies` directly keeps the challenge `request` returns on the server and hands it back as kept, never one the client sent. A second factor's challenge made before the update and answered without a handle is refused once; a new one passes.
- **`isLabel` is no longer exported by `mfa`**: a module of your own imports it from `labels` (`@mod/labels` in the workspace, `@o3co/auth-provider-foundation/labels` on the published packages), with the same rule.

## From 0.18.0-rc.5

What changed since rc.5. Coming from an earlier release candidate, read the sections above first.

- **A Redis store with replication**: boot is refused, named, where the confirming connection reaches another server than the operations, as a DNS name or a load balancer in front of several servers may send it; point both at one server. rc.5 booted and answered 503 to every replicated write.
- **A Redis server that cannot run the store's scripts**: boot runs one of them once and is refused, naming a store script, where the server cannot run it, as one whose Lua lacks `cjson`; rc.5 booted and failed the writes with 503. The [runbook](runbook.md#managed-redisvalkey-with-replicas) says what the server must offer.
- After boot, `/readyz` answers `503`, warning `redis.settings_unmet`, while either holds; a probe that finds them right again answers ready.
- **A generated app's image**: it now builds on `node:24-alpine`, Node 24's latest, so each build takes Node's security fixes. An app generated before pins Node 24.21.0, which the 2026-10-21 Node.js security release left vulnerable: change its Dockerfile's `FROM` line to `FROM node:24-alpine AS base` and build the image again, or generate the app again.
## From 0.18.0

- **A generated app's pnpm**: an app generated now names `pnpm@11.28.7` in its `package.json` (`packageManager`), which its image installs with. An app generated before names `pnpm@11.3.0`, short of the 2026-10-21 pnpm security release: change its `packageManager` to `pnpm@11.28.7` and build its image again, or generate the app again.

## From 0.18.1

- **A generated app's `witness-backfill` script**: where the kernel is bundled twice, a refused boot is now written and exits 78, as the app's entry does, where it was thrown on as a crash. In an app generated before, change the line `if (!(error instanceof BootRefused)) throw error;` in `src/witness-backfill.ts` to `if (!BootRefused.is(error)) throw error;`, or generate the app again.
- **A `plain-internal` pair whose name also answers an IPv6 address that does not reach**, as ECS Service Connect writes in the hosts file: 0.18.1 refused it as `plain-public`. Name the pair in `outbound.plain-ipv4` as well, and its name is resolved to IPv4 alone. An earlier version refuses boot on a configuration naming `outbound.plain-ipv4`, so a rollback takes the setting out with it.

## From 0.18.5

- **A client assertion (`private_key_jwt`) names the issuer alone.** Its `aud` must be the issuer identifier (`issuer.url`) as one string. One whose `aud` is the token endpoint's URL, or a list (`["<issuer>"]` included), is refused with `401 invalid_client`, logged as `client-assertion.refused` with the reason `audience`, and its `jti` is not spent. 0.18.5 took either URL, alone or in a list. A client that uses the same key and client id at another authorization server can be led, by that server's metadata, to sign an assertion for this server's token endpoint and hand it over there; whoever holds it could use it here first (the OpenID Foundation's notice of January 2025 on `private_key_jwt`).
  - A client that sends the issuer as a string changes nothing. Keys, client ids, stored state and issued tokens are not affected.
  - A client that sends the token endpoint's URL or a list changes what it signs, for every endpoint it authenticates at: the token endpoint, introspection, revocation, device authorization and federation grants.
  - Until it does, set `sections.client-assertion.accept-loose-audience = true` in that client's registration. Its assertions are then taken as 0.18.5 took them, each logged as the warning `client-assertion.loose_audience` with the client's id, and the client stays open to the attack above. Remove the setting once the warning stops. From 0.19 it is a lasting setting, and each registered client that sets it is warned of at every start (U-0.19-50).
  - A rollback to 0.18.5 refuses boot on a registration that carries `accept-loose-audience`, as a key its section does not know: take the setting out with the rollback.

## From 0.18 to 0.19

What changes from 0.18 to 0.19. A deployment that composes `code-grant` cannot go back to a release before 0.19 once it runs 0.19 ([U-0.19-59](#u-0.19-59)). The entries below are grouped by area, so their numbers do not run in order; the table is the checklist. Coming from a 0.18 release before 0.18.6, or from a release candidate, read the sections above from yours on first: [From 0.18.5](#from-0185)'s rule on a client assertion's `aud` refuses clients 0.18.5 and before let in.

**Upgrade notices.** Each change below that you must act on carries a notice, `U-0.19-<n>`. Check off each that affects your deployment:

| Notice | What to do | Affected |
|---|---|---|
| [U-0.19-1](#u-0.19-1) | Add the modules 0.19 composes beside others to `src/main.ts`, or generate the project again | An app generated with 0.18 that composes `code-grant`, `mfa-email`, `federation-grants`, `webauthn-login`, `passkey-registration`, `upstream-handoff` with `seal`, or serves the client credentials grant |
| [U-0.19-2](#u-0.19-2) | Generate the project again, or apply the difference to `src/main.ts` and `src/reseal.ts` | An app generated with 0.18 whose standard error goes to a pipe (a log collector, say) |
| [U-0.19-3](#u-0.19-3) | Once every instance runs 0.19, run `unclaimed-factors` and reset the subjects it names | An app that composes `mfa-webauthn` |
| [U-0.19-4](#u-0.19-4) | Offer `updateTogether` and run `factorStoreContract` | Code that provides `mfa`'s `factorStore` in place of `mfa-store` |
| [U-0.19-5](#u-0.19-5) | Offer `batchAcross` and run `storeContract` | An implementation of `store`'s `Store` of your own, where the app composes `mfa-store` or `webauthn-store` |
| [U-0.19-6](#u-0.19-6) | Import the contracts from `@mod/passkeys`, offer `updateTogether`, and run `passkeyStoreContract` | Code that provided `webauthn`'s `passkeyStore` or `challengeStore` in place of `webauthn-store` |
| [U-0.19-7](#u-0.19-7) | Point `redis.url` at one server | `redis.url` names a proxy that sends keys of different hash tags to different nodes |
| [U-0.19-8](#u-0.19-8) | Serve `withdraw-url` at the ledger, then set `mfa-witness-http.withdraw-url` once every instance runs 0.19 | An app that composes `mfa-witness-http` |
| [U-0.19-9](#u-0.19-9) | Have the ledger's read answer every mark's token before you set `withdraw-url` | An app that composes `mfa-witness-http` and sets `withdraw-url` |
| [U-0.19-10](#u-0.19-10) | Offer `withdraw` and `markedWith` | Code that contributes an `EnrollmentWitness` in place of `mfa-witness-http` |
| [U-0.19-11](#u-0.19-11) | Replace `src/witness-backfill.ts` with this release's before running it | An app generated with 0.18 that has a `witness-backfill` script |
| [U-0.19-12](#u-0.19-12) | Import `factorReading`, `factorBinding` or `factorManaging` in place of `factors` | Code that imports `factors` or `Factors` from `mfa`, or stands in for `mfa` |
| [U-0.19-13](#u-0.19-13) | Import from `@mod/mfa-extensions` and take `cleared`'s `after` | Code that contributes to `mfa`'s `witnessing` in place of `mfa-witnessing` |
| [U-0.19-14](#u-0.19-14) | Move the two keys to `passkeys`, compose `passkeys`, and import its contracts from `@mod/passkeys` | A configuration that sets `webauthn.user-verification` or `webauthn.max-credentials`; an app composed by hand or generated with 0.18 with `webauthn-login` or `passkey-registration`; code that imports the passkey contracts from `webauthn` |
| [U-0.19-15](#u-0.19-15) | Remove `federation-grants.revocation-skew` | A configuration that sets it |
| [U-0.19-16](#u-0.19-16) | Compose `upstream-handoff-seal` beside `seal`, and a held login store, or generate the project again | An app composed by hand or generated with 0.18 that composes `upstream-handoff` |
| [U-0.19-17](#u-0.19-17) | Replace `hwk` and `swk` with `pop` in `acr.values`, and in clients that read amr | `acr.values` names `hwk` or `swk`, or a client reads them in an amr |
| [U-0.19-18](#u-0.19-18) | Take `mfa` out of an IdP's `upstream-amr` where you do not trust its MFA | An IdP's `upstream-amr` maps a value to `mfa` |
| [U-0.19-19](#u-0.19-19) | Move `fromDocument` and `reads` to a `DocumentCopy`, and call the owners' copies | A `Section` of your own giving `fromDocument`, or a client source of your own calling one |
| [U-0.19-20](#u-0.19-20) | Offer `registered()` | Code that provides `clients`' contract in place of `clients` |
| [U-0.19-21](#u-0.19-21) | Import `kinds` and `Kind` from `kinds`, and take `protocol` | Code that imports `kinds` or `Kind` from `combinations` |
| [U-0.19-22](#u-0.19-22) | Call `run` in place of `reset`, and read its answer | Code that calls `mfaReset.reset` |
| [U-0.19-23](#u-0.19-23) | Compose `mfa-email-proof` beside `mfa-email`, or generate the project again | An app composed by hand or generated with 0.18 that composes `mfa-email` |
| [U-0.19-24](#u-0.19-24) | Compose `federation-grants-connect`, move its four keys, and rename its two variables | An app that composes `federation-grants`, composed by hand or generated with 0.18, or a configuration that sets `page`, `login-page`, `step-up-page` or `identity-check` under `federation-grants` |
| [U-0.19-25](#u-0.19-25) | Compose `login-gates` beside `acr` | An app composed by hand with `acr` and no `login-gates` |
| [U-0.19-26](#u-0.19-26) | Compose `client-credentials` beside `token-endpoint` | A client uses the client credentials grant, in an app composed by hand, generated with 0.18, or of a pattern that does not compose it |
| [U-0.19-27](#u-0.19-27) | Take the grant out of the client's `grants`, or compose the module named | A client in `clients.registered` allowed a grant no composed module serves |
| [U-0.19-28](#u-0.19-28) | Import it from `client-credentials` | Code that imports it from `token-endpoint` |
| [U-0.19-29](#u-0.19-29) | Set `outbound.resolution = in-process` where no process may be started | A host where the app may not start processes, or cannot spare about 100 MB |
| [U-0.19-30](#u-0.19-30) | Write the name without its dot where the search domains are to apply | A URL in the configuration whose host ends with a dot |
| [U-0.19-31](#u-0.19-31) | Serve a fake ledger of your own in the tests | Tests that import `usersLedger` or `witnessLedger` from the published test helpers |
| [U-0.19-32](#u-0.19-32) | Let a stop hook of your own run without `start()`, and stop ending the modules' work yourself after a refusal | A module of your own with a stop hook, or an entry or a test that catches the refusal |
| [U-0.19-33](#u-0.19-33) | Send back the `redirect_to` the page was given, or write the origin and the path as they are | A login page that builds `redirect_to` itself |
| [U-0.19-34](#u-0.19-34) | Compose a link store beside `users` (`users-store`) | An app composed by hand with a contact store of its own and no link store |
| [U-0.19-35](#u-0.19-35) | Name each contract and extension point the module takes in `takes` | A module of your own |
| [U-0.19-36](#u-0.19-36) | Change or remove a `federation-grants` return URI a client could not register to be sent back to | A client registration whose `sections.federation-grants.return-uris` holds a URI of another kind |
| [U-0.19-37](#u-0.19-37) | Offer `accessTokenLifetimeSeconds()` | Code that provides `tokens`' contract in place of `tokens` |
| [U-0.19-38](#u-0.19-38) | Set `kernel.environment = development` where a deployment tries the provider on one machine, or change the value refused | A deployment that sets a value now refused in production: `http.insecure-origin = true`, a plain-http `issuer.url`, a plain-http page on a loopback host, or an `http://localhost` WebAuthn origin |
| [U-0.19-39](#u-0.19-39) | Add `kernel.environment = ${?KERNEL_ENVIRONMENT}` to `config/application.conf`, or write the environment in its HOCON | An app generated before 0.19 that is to run in `development` |
| [U-0.19-40](#u-0.19-40) | Set `http.public-origin` to the same plain-http origin, or serve the issuer over https | A plain-http `issuer.url` without that `http.public-origin`, in development |
| [U-0.19-41](#u-0.19-41) | Allow the URL's host in `outbound`, or change the URL | A client whose `sections.rp-logout.backchannel-logout-uri` `outbound`'s destination policy refuses |
| [U-0.19-42](#u-0.19-42) | Have a `replicaSafe` function answer `true` or `false` | A module of your own whose `replicaSafe` is a function that can throw or answer anything but a boolean |
| [U-0.19-43](#u-0.19-43) | Send a JWT bearer assertion's `iss` as one string; read `untrusted signer` for every refusal before the signature | A client that sends a JWT bearer assertion's `iss` as a list, or a tool that reads the refusals' descriptions |
| [U-0.19-44](#u-0.19-44) | Write `alg` in each RSA client key before taking a second RSA algorithm, name in `client-assertion.algorithms` any algorithm past the defaults, and set `algorithms = ["PS256"]` for an IdP signing with PS256 | A client signing its assertions with RS384, RS512, PS256, PS384 or PS512; an IdP signing its id_tokens with PS256, or whose `algorithms` you wrote with two RSA algorithms while its keys name no `alg`; code of your own that calls `external-jwt` with such a policy over keys naming no `alg` |
| [U-0.19-45](#u-0.19-45) | Upgrade with the same `exchange-id-tokens.max-age` and `clock-skew`, and widen either only once the new `max-age`, the old and the new `clock-skew`, and `D` have passed since the last request a 0.18 instance took | An app that composes `exchange-id-tokens` and is to widen its `max-age` or `clock-skew` |
| [U-0.19-46](#u-0.19-46) | Allow for each id_token's record kept up to an hour and six minutes past its `iat` | An app that composes `exchange-id-tokens` |
| [U-0.19-47](#u-0.19-47) | Send a JWT bearer assertion with more than a second of its life left, and sign a new one where it is refused as `expired` | A client whose clock runs behind the server's, or that sends an assertion near its end |
| [U-0.19-48](#u-0.19-48) | Write `conditions` naming your subjects on a trusted issuer several organisations share, or `accept-any-subject = true` on one yours alone | An entry of `jwt-bearer.issuers` with `subject = as-is`, no `subject-is-key-thumbprint`, and its keys written, a `jwks-uri`, or keys contributed without `perSigner` |
| [U-0.19-49](#u-0.19-49) | Allow for each spent JWT bearer assertion's record kept up to six minutes past its `exp` | An app that composes `jwt-bearer` |
| [U-0.19-50](#u-0.19-50) | Expect the warning `client-assertion.accept_loose_audience` at each start for each client that sets `accept-loose-audience`, and keep the setting only on a client whose library names the token endpoint | A client registration that sets `sections.client-assertion.accept-loose-audience = true` |
| [U-0.19-51](#u-0.19-51) | Start the grant again where a token is refused as `expired` near the end of what it is issued from; set `tokens.access-token-lifetime` and `token-exchange.max-lifetime` to `2s` at least, and ask token exchange for an `expires_in` of `2` at least | A client that asks for a token in the last second of a refresh token's family, a subject token or an assertion; a deployment that sets either lifetime to `1s`; a client sending token exchange `expires_in=1`; code that calls or provides `tokens`' `issue` |
| [U-0.19-52](#u-0.19-52) | Write `profile = "id-jag"` on the issuer that sends ID-JAGs, compose `dpop`, and check the clients that send them | A trusted issuer of `jwt-bearer.issuers` whose assertions are ID-JAGs (`typ` `oauth-id-jag+jwt`) |
| [U-0.19-53](#u-0.19-53) | Register every `post_logout_redirect_uri` a client sends, exactly as it sends it | A client that starts a logout at `/oauth/logout` with a `post_logout_redirect_uri` it did not register |
| [U-0.19-54](#u-0.19-54) | Send as `client_id` only the client the `id_token_hint` was issued to, or send none | A client that starts a logout at `/oauth/logout` with a `client_id` other than the one its hint's ID token was issued to |
| [U-0.19-55](#u-0.19-55) | Send each parameter of a logout request once | A client that starts a logout at `/oauth/logout` sending a parameter more than once |
| [U-0.19-56](#u-0.19-56) | Read `401 invalid_client`, not `400 invalid_request`, where a client assertion is sent in part, twice, or beside another client authentication method | A client that sends such a request to the token, introspection, revocation or device authorization endpoint and reads its error; a method of your own at `authMethods` that authenticates by an assertion |
| [U-0.19-57](#u-0.19-57) | Nothing, unless an OpenID Connect IdP's UserInfo is to complete its users' profiles: set `read-userinfo = true` on it, with its description and UserInfo on https | An IdP of type `oidc` whose id_tokens leave out a user's `email`, `name` or `picture` that its UserInfo gives |
| [U-0.19-58](#u-0.19-58) | Offer `handleOf` | Code that provides `session`'s `sessions` in place of `session-lifecycle` or the stand-in |
| [U-0.19-59](#u-0.19-59) | Roll out with `authorize.claims-parameter = false`, and set it to `true` once every instance runs 0.19; there is no going back to a release before 0.19. Compose `claims-selection` and `claims-selection-store` beside `code-grant` in an app composed by hand or generated with 0.18, or generate it again | A deployment that composes `code-grant`; a client that sends `claims` with a `sub` value |
| [U-0.19-60](#u-0.19-60) | Set `http.public-origin`, and compose `csrf` where you list the modules yourself | An app that composes `rp-logout` and no other module that checks CSRF (such as `logout`, `login-password` or `consent`), without `http.public-origin`, or one composed by hand or generated with 0.18 that lists `rp-logout` without `csrf` |
| [U-0.19-61](#u-0.19-61) | Compose a grant, or leave `token-endpoint` out | An app that composes `token-endpoint` and no grant |
| [U-0.19-62](#u-0.19-62) | Send as `id_token_hint` only an ID token of the person signed in, or none; drop `prompt=select_account` | A client that sends `id_token_hint` or `prompt=select_account` in an OpenID Connect request |
| [U-0.19-63](#u-0.19-63) | Read the scope issued: `offline_access` is left out of it at authorization, never refused, unless asked alone | A client that asks for `offline_access` |
| [U-0.19-64](#u-0.19-64) | Remove `require-iss`; set `accept-missing-iss = true` on an IdP that never sends `iss` | A configuration that sets `require-iss` on an `oidc` IdP; an `oidc` IdP whose callbacks carry no `iss` and whose description does not offer it |
| [U-0.19-65](#u-0.19-65) | Set `clients-cimd.allow` to the hosts client documents come from, or `clients-cimd.allow-any-host = true` | An app that composes `clients-cimd` without `clients-cimd.allow` |
| [U-0.19-66](#u-0.19-66) | Have the IdP issue this provider's id_tokens to its client alone | An upstream IdP (`oidc`, `google`, `apple`) whose id_tokens name another audience beside this provider's client |
| [U-0.19-67](#u-0.19-67) | Read `400 invalid_grant` where a session grant was refused `401 unauthorized` | A client of the session grant that reads its refusal |
| [U-0.19-68](#u-0.19-68) | Read `invalid_client` where a certificate was refused `invalid_certificate` at issuance | A client presenting a certificate to bind its token (`mtls`) that reads its refusal |
| [U-0.19-69](#u-0.19-69) | Send the lifetime asked in a token exchange as `o3co_expires_in` | A client of token exchange that sends `expires_in` |
| [U-0.19-70](#u-0.19-70) | Send `resource` as an absolute URI without a fragment, and register audiences so | A client that sends a `resource` that is not an absolute URI, or one with a fragment, to a grant or token exchange |
| [U-0.19-71](#u-0.19-71) | Take the fragment and the query out of `federation-grants.connections.<name>.resource` | A deployment whose federation grant connection names a `resource` with a fragment or a query |
| [U-0.19-72](#u-0.19-72) | Write each user's `email` as an ASCII addr-spec (its domain in ASCII form) and give no empty `name` | A registered user, or a user a ledger answers, with an `email` outside ASCII or no dot-atom, or an empty `name` |
| [U-0.19-73](#u-0.19-73) | Accept a `303` where you read the status a login through an upstream lands with | A client, proxy or test of your own that expects an IdP's callback, or a link's, to answer `302` |
| [U-0.19-74](#u-0.19-74) | Place an Ed25519 key with `alg = EdDSA` where you mean to keep EdDSA; a deployment's own key needs nothing | A project generated with 0.19, or set up by the quick start or the first login recipe, whose clients or tooling expect EdDSA |
| [U-0.19-76](#u-0.19-76) | Declare `replicaSafe` on each module of your own | A module of your own |
| [U-0.19-78](#u-0.19-78) | Remove `offline_access` from each client's `sections.client-allowance.scopes` and `default-scopes` | A client registration that lists `offline_access` there |
| [U-0.19-80](#u-0.19-80) | Remove `offline_access` from `clients-cimd.scopes` | A configuration that lists it there |
| [U-0.19-81](#u-0.19-81) | Give `email` to a registered user that sets `email_verified`, or drop it | A registered user in `users.registered` whose attributes set `email_verified` and no `email` |
| [U-0.19-82](#u-0.19-82) | Check the `acr` in the ID token; ask for an acr as essential in `claims` where it must be met | A client that sends `acr_values` and relied on the provider refusing a sign-in that does not meet it |
| [U-0.19-83](#u-0.19-83) | Send `id_token_hint` wherever the user should come back | A client that starts a logout at `/oauth/logout` without `id_token_hint` |
| [U-0.19-84](#u-0.19-84) | Match `request_uri_not_supported` for a `request_uri` | A client that sends `request_uri` and reads its error |
| [U-0.19-85](#u-0.19-85) | Name the algorithms a method of your own signs with, never `none` | A module of your own that contributes at `authMethods` |
| [U-0.19-86](#u-0.19-86) | Set `outbound.max-lookups` to 2 or more (`max-concurrent` with it), and in process `UV_THREADPOOL_SIZE` to 4 or more | A deployment that composes `clients-cimd` with `outbound.max-lookups = 1`, `outbound.max-concurrent = 1`, or in-process resolution on a small threadpool |
| [U-0.19-87](#u-0.19-87) | Leave out a member with no value rather than writing `null` | A module of your own that answers JSON through `http` or signs claims through `keys` |
| [U-0.19-88](#u-0.19-88) | Follow the redirect a logout by `POST` now answers, as browsers do | A client that starts a logout at `/oauth/logout` by `POST` |

- <a id="u-0.19-38"></a>**U-0.19-38**: **The deployment's environment** (`kernel.environment`, new): `production`, the default, or `development`. A production deployment refuses at boot the values below, which are for trying the provider on one machine; nothing changes for one that uses none of them.
  - Refused in production, each at its key, naming the key and never the value: `http.insecure-origin = true` (a plain-http public origin); a plain-http `issuer.url`; a page on a loopback host over plain http at `authorize.login-page`, `authorize.step-up-page`, `federation-grants-connect.page`, `login-page` and `step-up-page`, `federation-link.step-up-page`, `login-gates.return-targets`, `federation.held-page` and `consent.page`; an `http://localhost` origin in `webauthn.origins` or `webauthn.top-origins`.
  - To try the provider over plain http on one machine, set `kernel.environment = development` as well as `http.insecure-origin = true`.
  - <a id="u-0.19-39"></a>**U-0.19-39**: An app generated before 0.19 has no `kernel.environment = ${?KERNEL_ENVIRONMENT}` line in `config/application.conf`, so setting the environment variable alone does nothing: add that line, or write `kernel.environment = development` in its HOCON. An app generated with 0.19 has the line. Affected: an app generated before 0.19 that is to run in `development`.
  - Not refused in production: plain http on a loopback host for an upstream identity provider's browser endpoints, and loopback and private-use redirect and logout URIs for clients.
  - Affected: a deployment that sets a value now refused in production: `http.insecure-origin = true`, a plain-http `issuer.url`, a plain-http page on a loopback host, or an `http://localhost` WebAuthn origin.
- **A module of your own** may declare `refusedInProduction` on `defineModule`: asked only in production with its checked section, it answers key paths below the section and reasons, never values, which boot is refused with alongside the other refusals before anything is built. A build context has `environment` for a check only a build can make.
  - <a id="u-0.19-42"></a>**U-0.19-42**: A `replicaSafe` function must answer a boolean; one that throws, or answers anything else, refuses its module with a fixed reason, as a `refusedInProduction` that throws or answers another shape does. Have it answer `true` or `false`. Affected: a module of your own whose `replicaSafe` is a function that can throw or answer anything but a boolean.
- <a id="u-0.19-40"></a>**U-0.19-40**: **A plain-http `issuer.url`** is taken only beside the same plain-http `http.public-origin`; without a public origin, boot is refused at `issuer.url`, in any environment. Affected: a plain-http `issuer.url` without that `http.public-origin`, in development (production refuses a plain-http `issuer.url` at [U-0.19-38](#u-0.19-38)).
- <a id="u-0.19-41"></a>**U-0.19-41**: **A registered client's back-channel logout URL** (`sections.rp-logout.backchannel-logout-uri`) that `outbound`'s destination policy refuses now refuses boot at that client's section, in any environment, where 0.18 took it and dropped every logout token for it. Allow its host in `outbound`, or change the URL. Affected: a client whose `sections.rp-logout.backchannel-logout-uri` `outbound`'s destination policy refuses.
- <a id="u-0.19-44"></a>**U-0.19-44**: **Each key is read under one algorithm** (`external-jwt`, `client-assertion`, `idp-oidc`): a key naming its `alg` under that one; a key naming none under the one allowed algorithm its kind and curve fit, and under none where two fit (RFC 8725 §3.1). 0.18 read a key naming none under any allowed algorithm its kind fit.
  - `client-assertion` takes a new operator setting, `client-assertion.algorithms`, by default RS256, ES256, ES384, ES512 and EdDSA: one for each kind of key. 0.18 took every asymmetric algorithm, so RS384, RS512, PS256, PS384 and PS512 are now taken only where you name them.
  - Naming one of them beside RS256 holds for every client: each client's RSA key naming no `alg` is then unused, for an RS256 assertion too. Write `alg` in every RSA client key (its JWK) first.
  - The algorithms the provider names for signed client authentication follow the setting: discovery's `token_endpoint_auth_signing_alg_values_supported`, and `introspection_endpoint_auth_signing_alg_values_supported` and `revocation_endpoint_auth_signing_alg_values_supported` where `token-control` serves them (each the algorithms of every composed method, together).
  - `idp-oidc`'s `federation.idps.<name>.algorithms` no longer holds PS256 by default (RS256, ES256, EdDSA). For an IdP signing its id_tokens with PS256 alone, set `algorithms = ["PS256"]`: one RSA algorithm, so the IdP's keys need not name `alg`, which you cannot change. Taking RS256 and PS256 together leaves the IdP's RSA keys naming no `alg` unused.
  - Affected: a client signing its assertions with RS384, RS512, PS256, PS384 or PS512, or whose RSA key names no `alg` where you take a second RSA algorithm; an IdP signing its id_tokens with PS256; an IdP whose `algorithms` you wrote with two or more RSA algorithms (RS256 and PS256, say) while its keys name no `alg`, even where it signs with RS256 alone: name the one it signs with; and code of your own that calls `external-jwt` with such a policy over keys naming no `alg`.
- <a id="u-0.19-74"></a>**U-0.19-74**: **A new project's signing key is RSA, for RS256** (`keys`, `create-app`): the examples a generated project carries, the README's quick start and the [first login recipe](recipe-first-login.md) make an RSA key of 2048 bits with `alg = RS256`, the algorithm every OpenID Connect provider is to sign ID tokens with (OpenID Connect Core §15.1), so any client can check them; 0.18's were an Ed25519 key with `EdDSA`. A deployment's own key is read as before, and EdDSA and ES256 stay. One key signs every token, so `id_token_signing_alg_values_supported` names its algorithm alone. Affected: a project generated with 0.19, or set up by the quick start or the recipe, whose clients or tooling expect EdDSA; it can still place an Ed25519 key with `alg = EdDSA`.
- <a id="u-0.19-1"></a>**U-0.19-1**: **An app generated with 0.18 lists the modules it composes** in its `src/main.ts`, so a module that 0.19 composes beside others does not come to it by itself. Generate the project again, or add to the list each of these that applies; the notice each item links says what happens without it:
  - `claims-selection` and `claims-selection-store`, where it composes `code-grant` ([U-0.19-59](#u-0.19-59));
  - `mfa-email-proof`, where it composes `mfa-email` ([U-0.19-23](#u-0.19-23));
  - `federation-grants-connect`, where it composes `federation-grants` ([U-0.19-24](#u-0.19-24));
  - `passkeys`, where it composes `webauthn-login` or `passkey-registration` ([U-0.19-14](#u-0.19-14));
  - `upstream-handoff-seal`, where it composes `upstream-handoff` and `seal` ([U-0.19-16](#u-0.19-16));
  - `client-credentials`, where a client uses the client credentials grant ([U-0.19-26](#u-0.19-26)).
  - Affected: an app generated with 0.18 that composes `code-grant`, `mfa-email`, `federation-grants`, `webauthn-login`, `passkey-registration`, `upstream-handoff` with `seal`, or serves the client credentials grant.
- <a id="u-0.19-2"></a>**U-0.19-2**: **A generated app's entry and `reseal` hand on what they write before they exit**: a refused boot's lines reach standard error before the exit 78, where a slow pipe (a log collector, say) could lose the last of them. An app generated with 0.18 writes and exits at once: generate the project again, or apply the difference to `src/main.ts` and `src/reseal.ts`. Affected: an app generated with 0.18 whose standard error goes to a pipe (a log collector, say).

- <a id="u-0.19-3"></a>**U-0.19-3**: **Upgrade every instance, then look for second factors left without their claim.** A WebAuthn second factor (`mfa-webauthn`) is now bound in one write that keeps the factor and its claim, on the pair of the subject's user handle and the credential id: a binding never leaves the factor without its claim, which keeps one subject from binding one credential twice. 0.18 wrote the two apart, and left a factor without its claim where the second write failed (the store unavailable between the two). A 0.18 instance still running, and the requests it holds, can leave more. Once every instance runs 0.19, find such factors with the app's `unclaimed-factors` script, which names each subject given that holds one, and reset them, as [Second factors left without their claim](runbook.md#second-factors-left-without-their-claim) says. An app generated with 0.18 has no such script: generate the project again. An app that composes no `mfa-webauthn` has none. Affected: an app that composes `mfa-webauthn`.
- <a id="u-0.19-4"></a>**U-0.19-4**: **A factor store of your own** (code that provides `mfa`'s `factorStore` in place of `mfa-store`): it must offer `updateTogether(listKey, claimKey, { watch, change })`, which changes a subject's list and a claim as one, from what both hold and the records `watch` names besides, holding every record read to what was read, and running `change` again on a race. `mfa` refuses boot over a factor store without it, at `mfa`: `its factor store cannot write a list and a claim as one (updateTogether)`. Run `factorStoreContract` (`@mod/mfa/testing`) against it: it now runs the change of the two as one. Over `records`, `pairedRecordsIn(place, where, refuse).changeTogether` writes it, as `mfa-store` does. Affected: code that provides `mfa`'s `factorStore` in place of `mfa-store`.
- <a id="u-0.19-5"></a>**U-0.19-5**: **A store adapter of your own** (an implementation of `store`'s `Store`, in place of `redis` or the in-memory store), where the app composes `mfa-store` or `webauthn-store`: `mfa-store` writes a factor and its claim, and `webauthn-store` a passkey's record and its subject's list, through `batchAcross`; each refuses boot over a store without it, at `mfa-store` or `webauthn-store`: `its store writes no records of two partitions as one`. `batchAcross(conditions, writes, options)` is a batch over keys of any partition, and of any spaces that declare the same guarantees (compared as sets); it answers as `batch` does. What it must keep:
  - It is checked whole before anything is written, never writes a key twice, and refuses spaces of other guarantees; a fault keeps it whole or drops it whole.
  - Its idempotency mark is kept in every partition it touches, the partitions it only reads as conditions included, with one answer and one end (the same absolute time) in each.
  - It looks for the mark in every partition before it judges the deadline: a resend meeting it in any partition gets the answer kept, another request meeting it is answered `reused` and rewrites no mark, and a `late` answer is never kept.
  - No key is given a version it had before. (The `redis` adapter counts versions per partition; the in-memory store counts once for the whole store.)
  - Run `storeContract` (`@mod/store/testing`) against it: it runs the batch-across tests wherever the store offers `batchAcross`.
  - Affected: an implementation of `store`'s `Store` of your own, where the app composes `mfa-store` or `webauthn-store`.
- <a id="u-0.19-6"></a>**U-0.19-6**: **A passkey store of your own** (code that provided `webauthn`'s `passkeyStore` (`webauthn.passkey-store`) in place of `webauthn-store`): the contract is `passkeys`' now (`passkeys.passkey-store`). Import `passkeyStore`, `challengeStore`, their needs and `StoredPasskey` from `@mod/passkeys` (`@o3co/auth-provider-passkey/passkeys`), and `passkeyStoreContract` and `challengeStoreContract` from `@mod/passkeys/testing`, in place of `@mod/webauthn` and `@mod/webauthn/testing`; a challenge store of your own moves alike (`passkeys.challenge-store`). The passkey store must offer `updateTogether(keys, { watch, change })`, which reads the records `keys` names in both spaces (`credentials`, `subjects`) and those `watch` names from them, holds every record read to what was read, runs `change` again on a race, and writes the next `change` answers for each, as one. `passkeys` refuses boot over a passkey store without it, at `passkeys`: `its passkey store cannot change both its spaces as one`. Run `passkeyStoreContract` (`@mod/passkeys/testing`) against it: it runs the change of both spaces as one. Over `records`, `pairedRecordsAcross(credentials, subjects, where, refuse).changeRecords` writes it, as `webauthn-store` does; a list holds up to `passkeys.max-credentials` ids (at most 100), so a reset writes at most 101 records in one batch. Affected: code that provided `webauthn`'s `passkeyStore` or `challengeStore` in place of `webauthn-store`.
- <a id="u-0.19-7"></a>**U-0.19-7**: **Redis stays one server**: a write across partitions runs as one script over the slots of every partition it touches, so the `redis` adapter will not run on a cluster, nor behind a proxy that splits keys across nodes. A cluster is refused at boot, as before; from 0.19, so is a proxy that sends keys of different hash tags to different nodes and refuses one script over them (`CROSSSLOT`), where 0.18 ran on it: point `redis.url` at one server. Nothing else to change: the script sends no command the store did not send before, so a managed Redis needs no new permission. Affected: `redis.url` names a proxy that sends keys of different hash tags to different nodes.
- **A second factor whose value the subject has bound already** (for WebAuthn, the same credential under the subject's handle): a binding sees, in the same write, whether the claim's own factor is still listed: a claim whose factor is gone is taken over, and one whose factor stands answers `duplicate` and writes nothing. 0.18 wrote the factor first and removed it again on a duplicate.
- <a id="u-0.19-8"></a>**U-0.19-8**: **The second-factor witness at the ledger** (`mfa-witness-http`): the provider removes a mark it set itself by withdrawing it by its token, where the ledger serves `withdraw-url`, so another binding's mark is never taken. Serve the route and check it as [Keeping the second-factor witness at the ledger](runbook.md#keeping-the-second-factor-witness-at-the-ledger) says, then set `mfa-witness-http.withdraw-url` on every instance; it must not be the same as `clear-url`. Set it once every instance runs 0.19: a 0.18 instance refuses boot on the key, as one its section does not know, so a rollback takes it out. Until you do, nothing changes but a warning at each boot (`mfa-witness-http.withdraw_missing`); a later release will require it. Affected: an app that composes `mfa-witness-http`.
- <a id="u-0.19-9"></a>**U-0.19-9**: **The ledger's read answers the mark's token** (`mfa-witness-http`, with `withdraw-url`): `{"enrolled": true, "token": "…"}`, the token exactly as enroll sent it. A reset then withdraws the mark by the token it read, only where nothing is written for the subject since, so a reset that stops or lands late never takes a binding's mark set after it; [When a reset removes the mark](runbook.md#when-a-reset-removes-the-mark) tells the two cases that remain. Have every server answering `read-url` answer the token of every mark, the marks set before included, before you set `withdraw-url`: with `withdraw-url` set, a marked read naming no token is unavailable. Without `withdraw-url`, the read is `enrolled` alone, as before. Affected: an app that composes `mfa-witness-http` and sets `withdraw-url`.
- **A reset that is not sure the mark is its to remove** keeps it and answers `stopped` at `factors`, recording `mfa.enrollment_inconsistent` with `at: reset` (a new value of `at`: mend a tool that reads it). Mend the subject as [After a reset answers `stopped`](runbook.md#after-a-reset-answers-stopped) says.
- <a id="u-0.19-10"></a>**U-0.19-10**: **A second-factor witness of your own** (an `EnrollmentWitness` contributed to `enrollmentWitnesses` in place of `mfa-witness-http`): it may offer two new members, `withdraw(subject, token)`, which removes the mark only where it is `token`'s and answers once that is settled, and `markedWith(subject)`, the token the mark is set to. A reset removes the mark by the token it read only where the witness offers both; with one or none, it clears the mark as 0.18 did, which can take a mark another binding set meanwhile. Boot and the witness's other calls are as before. Affected: code that contributes an `EnrollmentWitness` in place of `mfa-witness-http`.
- <a id="u-0.19-11"></a>**U-0.19-11**: **The `witness-backfill` script**: replace the app's `src/witness-backfill.ts` with this release's (generate the project again, or apply the difference) before you run it on 0.19. It counts `unclaimed` (a factor whose unique value is not claimed, left as it is) and `unknown` (an answer it does not know, which makes it exit 1). The one generated before reads `unclaimed` as nothing, prints no count for it, and exits 0. Its line is now `marked … held … none … unclaimed … inconsistent … unknown … failed …`: mend any tool that reads it. Affected: an app generated with 0.18 that has a `witness-backfill` script.
- <a id="u-0.19-12"></a>**U-0.19-12**: **Code that reads mfa's decisions** (`factors` from `@mod/mfa`): they are three contracts now, each in its own package, and `factors` and `Factors` are gone. Take the one whose members you use: `factorReading` from `@mod/mfa-reading` (`held`, `countingHeld`, `countingWritten`, `secondFactorRequired`, `asks`, `guessable`, `guessableBoundAfter`, `challenge`, `prove`, and the new `writtenStanding` and `unclaimedWritten`), `factorBinding` from `@mod/mfa-binding` (`begin`, `provePending`, `bind`), `factorManaging` from `@mod/mfa-managing` (`rename`, `remove`, `clear`, `reissue`, `fence`, `fenceOf`). Published, they are `@o3co/auth-provider-second-factor/mfa-reading`, `/mfa-binding` and `/mfa-managing`. Code that took several in one type makes the intersection where it uses them (for example `FactorBinding & Pick<FactorManaging, "reissue">`). `Shown`, `Fence`, `Proved` and `Challenged` come from `@mod/mfa-reading`; `@mod/mfa` no longer exports them. Add the package to the module's dependencies, and keep `@mod/mfa` there too, so `combinations` still composes mfa (a module built against the published bundle adds nothing: it is the one package). `proofSteps`, `enforcers`, `fenceFollower`, the store interface and `@mod/mfa/testing` stay in `@mod/mfa`. Composed apps change nothing: mfa provides the three contracts.
  - **A stand-in of your own in place of `mfa`** (code that provided `mfa`'s `factors`, a test's, say) provides the three contracts in its place. Its `FactorReading` offers two members `Factors` did not have, which the type requires: `writtenStanding(subject)`, the subject's written factors that stand for it, which `mfa-witnessing`'s backfill reads; and `unclaimedWritten(subject)`, how many of the subject's counting factors are written and stand for nothing (a unique value's claim missing or another's). Code that only reads `factorReading` changes nothing.
  - `mfa-reset` takes `factorManaging` and `factorReading` in place of `factors` (`factorReading` for `resetCandidates`): an assembly composing it with stand-ins in place of `mfa` provides both, or boot is refused for the one it lacks. An app that composes `mfa` has them.
  - Affected: code that imports `factors` or `Factors` from `mfa`, or stands in for `mfa`.
- <a id="u-0.19-13"></a>**U-0.19-13**: **A witnessing of your own** (code that contributes to `mfa`'s `witnessing` extension point in place of `mfa-witnessing`): import `witnessing` and `Witnessing` from `@mod/mfa-extensions` (`@o3co/auth-provider-second-factor/mfa-extensions`); `@mod/mfa` no longer exports them. The extension point keeps its name (`mfa.witnessing`), so nothing changes in an app that composes `mfa-witnessing`. Its `cleared` now takes the reset's `after` as well, `cleared(subject, after)`: a function answering, each time it is called, what stands after the reset (`AfterReset`: `counting`, `none` or `unsure`); remove the mark only where it answers `none`. `Asked` comes from `@mod/mfa-extensions` alone; `@mod/mfa` no longer exports it. Affected: code that contributes to `mfa`'s `witnessing` in place of `mfa-witnessing`.
- <a id="u-0.19-14"></a>**U-0.19-14**: **Passkeys are kept by `passkeys`, apart from `webauthn`.** `webauthn` now runs the ceremonies for its relying party alone; the new module `passkeys` keeps each subject's passkeys and answers their assertions and registrations.
  - What `webauthn` offered for them is `passkeys`' now: `passkeys`, `registrations`, `passkeyStore` and `challengeStore`, with their types (`Passkeys`, `Registrations`, `PasskeyStore`, `ChallengeStore`, `StoredPasskey`, `StoredChallenge`) and needs, come from `@mod/passkeys` (`@o3co/auth-provider-passkey/passkeys`), and `passkeyStoreContract` and `challengeStoreContract` from `@mod/passkeys/testing`; `@mod/webauthn` offers the ceremonies alone. The contracts are named `passkeys.*` in place of `webauthn.*` (`passkeys.passkeys`, `passkeys.registrations`, `passkeys.passkey-store`, `passkeys.challenge-store`), and boot's refusals name them so. `Registrations.register` takes `admitted`, and `listed`, `renamed` and `removed` are new.
  - Two keys move: `webauthn.user-verification` becomes `passkeys.user-verification`, and `webauthn.max-credentials` becomes `passkeys.max-credentials`, with the same values and defaults. Left under `webauthn`, they refuse boot at `webauthn`, naming each (`Unrecognized key: "max-credentials"`, or `Unrecognized keys: …` for both): move them, or remove them to take the defaults. `mfa-webauthn.user-verification` is unchanged.
  - An app composed by hand, or generated with 0.18 (its `src/main.ts` lists the modules it composes), that serves passkey logins or registration (`webauthn-login`, `passkey-registration`) composes `passkeys` beside `webauthn`, or is generated again; without it, boot is refused for the `passkeys` or `registrations` it lacks. `combinations` and `create-app` add it.
  - The passkeys kept are read as they are: `webauthn-store` keeps its name and its spaces, and the records keep their keys.
  - A removed passkey's record is kept stripped to its subject. While 0.18 and 0.19 hosts run side by side, a 0.18 host reads it as a broken record: an assertion naming that passkey answers `503` there, and the passkey is gone either way once every host runs 0.19.
  - A passkey being registered is kept pending until its registration ends, in a record a 0.18 host reads as broken: during the upgrade, an assertion there naming a passkey a 0.19 host is registering answers `503`. A registration a 0.18 host makes is usable on both.
  - `passkey-registration` comes wherever `passkeys` and a session are composed. An app the combinations compose, or generated with 0.19, that brought it only because `mfa-webauthn` brought `webauthn`, with no `passkeys`, no longer serves the passkey registration routes; one that composes `passkeys` and a session still does, with or without a passkey login. An app generated with 0.18 with `mfa-webauthn` lists `passkey-registration`: add `passkeys` to keep the routes, or take `passkey-registration` out of the list.
  - A passkey's record and the subject's list are written as one: a registration writes its pending record and the list's entry in one write, and the end of a registration that did not finish and a removal each change the record and the list in one write too. A registration now asks whether the subject was revoked since its challenge (`admitted`, a reset's revocation included) before anything is written: one revoked writes nothing, and the verify answers `401` `{"error":"unauthorized"}`, where 0.18 registered it.
  - **While 0.18 and 0.19 hosts run side by side**, a registration a 0.18 host makes still writes the record and the list apart, as before, and the list without a condition on the record: it can list an id a 0.19 host has taken meanwhile and answer it registered (that passkey is not usable), and race a removal. Registrations among 0.19 hosts never do. Upgrade every host and let the requests the 0.18 hosts took finish. Where a removal during the upgrade should have ended a passkey, have the user remove it again (`/remove`, by id), or reset the subject's passkeys as an operator (`passkeyReset.reset`, `passkey-reset`), which removes every passkey of the subject (see [Passkey list entries 0.18 left](runbook.md#passkey-list-entries-018-left)).
  - **`passkey-registration` serves three new routes**, for the session's subject: `GET /oauth/webauthn/registrations` lists its passkeys, `POST /oauth/webauthn/registrations/rename` renames one and `POST /oauth/webauthn/registrations/remove` removes one, by id. They come wherever `passkey-registration` does, with nothing to set, and record `passkey.renamed` and `passkey.removed`. A proxy or a firewall that lets through only the paths it knows lets them through, or keeps them closed, on purpose ([routes](routes.md)).
  - Affected: a configuration that sets `webauthn.user-verification` or `webauthn.max-credentials`; an app composed by hand or generated with 0.18 with `webauthn-login` or `passkey-registration`; an app the combinations compose with `mfa-webauthn` and no `passkeys`, which no longer serves the passkey registration routes; code that imports the passkey contracts from `webauthn`.
- **A passkey witness at the ledger** (`passkey-witness-http`, new and opt-in): the operator's HTTP ledger keeps, apart from the passkey store, a mark that a subject holds a passkey, so a passkey store that lost its records never reads as holding none. It is what `password = refused-when-held` needs (see `login-passkey` below). Nothing changes until it is composed.
  - It calls three URLs at the ledger: `passkey-witness-http.read-url`, `enroll-url` and `withdraw-url`, all required, with `credential`, `timeout` and `max-response-size`. What the ledger must answer is in [Keeping the passkey witness at the ledger](runbook.md#keeping-the-passkey-witness-at-the-ledger).
  - The bridge `passkey-witnessing` matches the mark with the passkeys and records `passkey.enrollment_inconsistent`. It comes wherever `passkeys` and `passkey-witness-http` are composed, through `combinations` and `create-app`. An app composed by hand with a passkey witness, or with a witness of your own (whose package joins nothing, so `combinations` does not add the bridge either), composes `passkey-witnessing` too. Without it, boot is refused at `passkeys`: a witness nothing asks would let a lost store read as holding none.
  - A witness of your own is a `PasskeyWitness` contributed to `passkeyWitnesses` (`@mod/passkey-witness`); its stand-in in memory and the contract test (`passkeyWitnessStandIn`, `passkeyWitnessContract`, `passkeyWitnessProblems`) are in `@mod/passkey-witness/testing`. A witnessing of your own contributes to `passkeys`' `passkeyWitnessing` (`@mod/passkeys`), at most one.
- **Fill the passkey witness's marks once, after composing it**: a subject who registered a passkey before the witness was composed, and nothing since, carries no mark, so losing the passkey store would read as it holding none. An app generated with 0.19 that composes `passkey-witnessing` has a `passkey-backfill` script: once every instance runs 0.19 with the witness, run it with every subject that may hold a passkey on standard input, as [Filling the passkey witness's marks](runbook.md#filling-the-passkey-witnesss-marks) says. It prints only counts (`marked`, `held`, `none`, `pending`, `inconsistent`, `unknown`, `failed`), never a subject, and exits 0, 1 or 78 as `witness-backfill` does; standard error gets only fixed lines (how many refusals refused the boot, that the boot failed or the run stopped, that 0.17's variables are left set), never a subject, a configured value or an error's words. An app generated with 0.18 has no such script: generate the project again to compose the witness.
- **A passkey login into a browser session** (`login-passkey`, new and opt-in): `POST /session/login/passkey/options` and `POST /session/login/passkey`, for a login page to offer a passkey beside the password ([your login page](login-page.md#a-login-with-a-passkey)). Nothing changes until it is composed.
  - It asks the user ledger for the user by subject: with `users-http`, set `subject-url`, or every passkey login answers `503`.
  - It proves the amr `pop`, and `mfa` too where the authenticator verified the user (`counts-as-mfa`, default true), so the second-factor gate lets it in without a factor, and `mfa.mode = required` is met. A subject with no second factor that registers a passkey from a session meets `required` without the binding proof a first factor needs. A synchronized passkey stolen with its platform account then stands for a second factor: set `counts-as-mfa = false` where it must not.
  - `password = refused-when-held` refuses password logins of subjects holding a passkey, but in `password-exempt-group`, and federated logins whose upstream amr is mapped to `pwd`. It needs a passkey witness (boot is refused without one), and is to be set once the backfill ran on every subject ([runbook](runbook.md#refusing-passwords-of-passkey-holders)).
- **An operator's reset of passkeys** (`passkey-reset`, new and opt-in): `passkeyReset.reset(subject, { requestedBy })` answers as `mfaReset.run` does, `done` with `removed` or `stopped` with `at` (`sessions` or `passkeys`), and records `passkey.reset`. What `done` promises, and how to reset after a leaked passkey, is in the [runbook](runbook.md#resetting-a-subjects-passkeys).
- **`mfaReset.run` removes passkeys too where `mfa-reset-passkeys` is composed** (new, opt-in): the bridge contributes the part `passkeys` to `mfa-reset`'s `resetParts`, so a `done` answer's `parts` carries `passkeys` (`{ passkeys: <count> }`) and the audit's `parts` `passkeys=<count>`, and a run stops at `parts` (`partsStopped: passkeys`) where the passkeys could not be removed. `combinations` composes it wherever `mfa-reset` and `passkey-reset` are. An app composed by hand with both composes it too: without it, nothing is refused, and `mfaReset.run` leaves passkeys as they are.
- <a id="u-0.19-15"></a>**U-0.19-15**: **`federation-grants.revocation-skew` is gone** (a breaking change): a configuration that sets it is refused at boot as an unknown key; remove it. Unset, it was `1s`, and now nothing is allowed: a grant or intent of a subject is compared with the subject's revocation in whole seconds, as sessions and tokens are, on the clocks of the hosts that wrote each. One made in the second after a revocation is no longer refused. This drops a guard: on a host whose clock runs ahead of the revoking host's, a grant or intent made just before the revocation can count as after it and outlive it; NTP keeps clocks close, not equal. See [Before you deploy](runbook.md#before-you-deploy). While 0.18 and 0.19 instances run together, with 0.18 at its default of `1s`, they judge alike everything but what was made in the second after a revocation: 0.18 counts it revoked, 0.19 does not; with an allowance of your own, 0.18's window is that long. A 0.18 instance that counts a grant revoked writes it so and erases its credentials, and 0.19 keeps that end: a revocation is never undone. Affected: a configuration that sets it.
- <a id="u-0.19-36"></a>**U-0.19-36**: **A client's `federation-grants` return URIs** (`sections.federation-grants.return-uris`) take only what a client may register to be sent back to, as `redirect-uris` reads one: https, http to `localhost` or a loopback address, or a private-use scheme. Any other (plain http to another host, `javascript:`, `data:`, a fragment, user information) refuses boot at that client's section; 0.18 took any URL. Change the URI, or remove it. Affected: a client registration whose `sections.federation-grants.return-uris` holds a URI of another kind.
- **`federation.idps.<name>.fresh-login-allowance`** (new, `0s` to `5m`): how far before a demand for a fresh login (`prompt=login`, `max_age`) the upstream may say the user logged in. Unset, it is the IdP's `clock-skew`, as before, so nothing changes until you set it. Set it below `clock-skew` to narrow that margin alone, keeping the id_token's checks: an upstream whose clock runs behind ours by more than the allowance then has its fresh logins refused `login_required`. See [the security model](security-model.md), promise 2.
- <a id="u-0.19-64"></a>**U-0.19-64**: **An OpenID Connect IdP's callback must carry `iss`** (`idp-oidc`; RFC 9207, RFC 9700 §4.4.2.2): `require-iss` (default `false`) is gone, and an answer without `iss` is refused unless the IdP's entry sets `accept-missing-iss = true` (new, default `false`) and the issuer's description does not offer `iss`. 0.18 took such an answer with a warning at boot, unless `require-iss` was set or the description offered `iss`. A configuration that sets `require-iss` on an `oidc` IdP is refused at boot as an unknown key; remove it, as `true` is now the default. The `google` type keeps its own `require-iss` (default `true`). For an IdP that never sends `iss`, set `accept-missing-iss = true`: its answers are then taken without `iss`, relying on its own callback alone against mix-up, and every start logs the warning `idp-oidc.iss_not_required` naming the IdP. Google's, Apple's and GitHub's types are unchanged. Affected: a configuration that sets `require-iss` on an `oidc` IdP; an `oidc` IdP whose callbacks carry no `iss` and whose description does not offer it.
- <a id="u-0.19-66"></a>**U-0.19-66**: **An upstream id_token naming another audience is refused** (`upstream-client`, for the `oidc`, `google` and `apple` types; OpenID Connect Core §3.1.3.7): 0.18 took an id_token listing other audiences beside the client where its `azp` named the client. 0.19 trusts no audience but the client, so such an id_token refuses the login, as an id_token that does not hold does. Google's cross-client identity (one audience, `azp` naming another client of the project) is taken as before. Affected: an upstream IdP (`oidc`, `google`, `apple`) whose id_tokens name another audience beside this provider's client; have it issue them to the client alone.
- <a id="u-0.19-73"></a>**U-0.19-73**: **A login through an upstream lands by `303`** (`federation`, `federation-link`; RFC 9700 §4.12): the answer to an IdP's callback that sends the browser on to its return target or the landing, and a link's to where it lands, is now `303 See Other`; 0.18 answered `302`. A callback can be a POST carrying the user's authorization response (Sign in with Apple's `form_post`), and a `303` has the browser follow it by GET, never posting it again. A browser follows either alike. The starts (an IdP's start, a link's start) stay `302`, and a held login's page was a `303` already. Affected: a client, proxy or test of your own that reads that answer's status; accept `303`.
- **`federation-link.step-up-page`** (new, optional): the page a link's start (an IdP's start with `link=1`) names when the session falls short of a requirement, such as a sign-in older than the recent-authentication window. Set, that start's `403` carries `page`: the page with `requirement` (the requirement's name) and `redirect_to` (the start itself, on the public origin), and a login may return there. An https URL; http only on a loopback host. Unset, the `403` names no page, as before. Set the same page as `authorize.step-up-page` to come close to 0.17's answer, which named the registered step-up page with nowhere to come back to and an `error_description`; 0.19 sends no `error_description`.
- <a id="u-0.19-16"></a>**U-0.19-16**: **A held login's upstream tokens are sealed through the bridge `upstream-handoff-seal`** (new): it comes wherever `upstream-handoff` and `seal` are composed, through `combinations` and `create-app`, so an app generated with 0.19 has it.
  - An app composed by hand, or generated with 0.18 (its `src/main.ts` lists the modules it composes), with a module receiving upstream tokens (`federation-tokens`, or a receiver of your own contributing to `upstreamLoginReceivers`) composes `upstream-handoff-seal` beside `seal`, or is generated again. Without it, boot is refused at `upstream-handoff`; 0.18 took the seal itself.
  - A sealing of your own contributes to `upstream-handoff`'s `handoffSealing` (`@mod/upstream-handoff`), at most one.
  - An app composed by hand with `upstream-handoff` composes a held login store too (`upstream-handoff-store`, its wiring), even with no module receiving upstream tokens: 0.19 takes the store in every assembly, so boot is refused without it, where 0.18 skipped it.
  - Affected: an app composed by hand or generated with 0.18 that composes `upstream-handoff`.
- <a id="u-0.19-17"></a>**U-0.19-17**: **Passkeys prove `pop`, never `hwk` or `swk`** (`webauthn-login`, `mfa-webauthn`): nothing asks an authenticator's attestation, so nothing told a key kept in hardware from one kept in software, and `hwk` claimed what was never checked. A passkey login, and the WebAuthn second factor whatever the credential's backup eligibility, now prove `pop` (OpenID Connect EAP ACR Values: possession of a key, how it is kept unsaid). In `acr.values`, replace `hwk` and `swk` with `pop` in every set meant for a passkey: an acr whose every set asks `hwk` or `swk` refuses boot at `acr.values.<acr>` where no other way of logging in proves them (a federation's `upstream-amr` may), and a set asking them beside another set is no longer met by a passkey, silently. A client that reads `hwk` or `swk` in an ID token's or an introspected token's amr reads `pop` in its place. Affected: `acr.values` names `hwk` or `swk`, or a client reads them in an amr.
- <a id="u-0.19-18"></a>**U-0.19-18**: **A login whose amr holds `mfa` passes the second-factor gate** (`mfa-flows`): nothing is asked of the subject's factors, and none is to be bound where one is required. 0.18 held such a login like any other. So a federated login whose IdP's `upstream-amr` maps an upstream value to `mfa` no longer asks a local second factor: it trusts that IdP's MFA in its place. Where you do not, take `mfa` out of the IdP's map, and its users complete a local second factor as before. See [Upstream amr](#upstream-amr). Affected: an IdP's `upstream-amr` maps a value to `mfa`.
- <a id="u-0.19-19"></a>**U-0.19-19**: **A client metadata section of your own that a metadata document fills** (a `Section` giving `fromDocument` and `reads`): `clients`' `Section` no longer has them, nor `clients` `DocumentSource`. Move them to a `DocumentCopy` from `@mod/client-documents` (`section`, the section itself; `reads`; `copy`, which was `fromDocument`, taking the same document and `DocumentSource` and answering the same), and contribute it to `documentCopies` from the module that contributes the section. `DocumentSource` comes from `@mod/client-documents` too (`@o3co/auth-provider-identity/client-documents`), and `reads` is required now. `clients-cimd` reads the copies there, and refuses boot where a copy's section is not composed. A `fromDocument` left on a section is not called, and nothing is copied for it; in plain JavaScript nothing refuses it. Nothing changes in an app that composes only this repository's modules.
  - A client source of your own that called a section's `fromDocument` (`clientSection.fromDocument`, as 0.18.0-rc.2 suggested, or `redirects.fromDocument`) calls the owner's copy in its place: `clientCopy.copy` from `@mod/consent`, `redirectsCopy.copy` from `@mod/redirect-uris`.
  - Affected: a `Section` of your own giving `fromDocument`, or a client source of your own calling one.
- <a id="u-0.19-20"></a>**U-0.19-20**: **A `Clients` of your own** (a stand-in of `clients`' contract) offers `registered()`: the clients the operator registered, in the settings' order. `token-endpoint` asks it at boot, so one without it does not type-check, and in plain JavaScript boot fails (`registered is not a function`). Affected: code that provides `clients`' contract in place of `clients`.
- <a id="u-0.19-37"></a>**U-0.19-37**: **A `Tokens` of your own** (an implementation of `tokens`' contract, a stand-in included) offers `accessTokenLifetimeSeconds()`: the access-token lifetime it applies where a grant gives none, in seconds, which a grant with a lifetime ceiling reads at build time to refuse boot above it. The type requires it; `tokensContract` (`@mod/tokens/testing`) checks it against the `expiresIn` issued. Affected: code that provides `tokens`' contract in place of `tokens`.
- <a id="u-0.19-51"></a>**U-0.19-51**: **No access token is issued with less than a second of life** (`tokens`, `token-exchange`): a token with less than a second left once signed, cut to the end of what it is issued from or signed slowly, is refused `400 invalid_grant` with `expired`, whatever the grant, where 0.18 issued it with an `expires_in` of 0, or of 1 living less than a second. The JWT bearer grant refused it already (U-0.19-47); a refresh token refused so is not rotated.
  - The shortest lifetime is two seconds: a token's `iat` is cut to the second, so one second left it less than one. `tokens.access-token-lifetime = 1s` and `token-exchange.max-lifetime = 1s` refuse boot, and token exchange answers an `o3co_expires_in` of `1` (U-0.19-69) `invalid_request`, as it does `0`.
  - Affected: a client that asks for a token in the last second of what it is issued from (a refresh token's family, a subject token, an assertion), which gets `expired` and starts the grant again; a deployment that sets either lifetime to `1s`, which sets `2s` or more; a client sending token exchange `o3co_expires_in=1`, which asks for `2` or more. Code that calls `tokens`' `issue` with a `lifetimeSeconds` of 1 gets a RangeError, as for 0; code that provides `tokens`' contract refuses such a token as `tokens` does (policy `tokens`, reason `no_lifetime_left`), which `tokensContract` (`@mod/tokens/testing`) checks.
- <a id="u-0.19-21"></a>**U-0.19-21**: **Code that reads the package kinds from `combinations`** (`kinds` or `Kind`): import them from `@o3co/auth-provider-scaffold/kinds` (`@mod/kinds` in the workspace) in place of `@o3co/auth-provider-scaffold/combinations`. They gain `protocol` ([the design's kinds](design.md)), so a `switch` over every `Kind` takes it too. The order of the kinds and which way a dependency between them may point (`kindOrder`, `capabilityBlind`, `mayNeed`), new in 0.19, are offered there alone. `combinations` still offers what it composes. Affected: code that imports `kinds` or `Kind` from `combinations`.
- <a id="u-0.19-22"></a>**U-0.19-22**: **An operator's reset of second factors** (`mfaReset` from `mfa-reset`): `reset` is now `run`, which answers how the run ended. Where `reset` answered the count, `run` answers `{kind: "done", removed, kinds, parts}`; where `reset` rejected as unavailable, `run` answers `{kind: "stopped", at}` (`sessions`, `factors`, `parts` or `lock`), with `removed` (`count`, `kinds`) where the factors' removal answered before it stopped (without it, whether the factors went is not known: a removal that failed may have taken them), and running it again finishes it as before. A failure that is not unavailable, at any step, and a malformed subject or requester, are still thrown. A reset now removes, beside the factors, what each module contributing to its `resetParts` holds: `parts` counts each by name (`{}` where none is composed), and a run stops at `parts` where one was unavailable; code that branches on every `at` or reads `done` whole must take both. The audit event `mfa.reset` gains `parts` (`name=count` of each part done) and `partsStopped` (each part stopped or failed), where there are any; the log line `mfa-flows.reset_incomplete` may say `stoppedAt: parts`. Affected: code that calls `mfaReset.reset`.
- <a id="u-0.19-23"></a>**U-0.19-23**: **A code by email as a second factor** (`mfa-email`): the proof of the account's address asked before a first binding (`account-email`) is the package `mfa-email-proof` now (`@o3co/auth-provider-second-factor/mfa-email-proof/module`), a bridge `combinations` composes wherever `mfa-email` is. An app composed by hand, or generated with 0.18 (its `src/main.ts` lists the modules it composes), composes `mfa-email-proof` beside `mfa-email`, or is generated again: without it, boot is refused at `mfa-email`, naming `mfa-email-proof`, rather than binding a first factor unproved. `mfa-email`'s imports, settings, mail purposes and wording are unchanged, and the proof's code, its ten minutes and the log line `mfa-email.contact_not_kept` are as before. Affected: an app composed by hand or generated with 0.18 that composes `mfa-email`.
- **A code by email that does not count binds, as a way back** (`mfa-email`, with `mfa-email.adds-second-factor = false`, the default): 0.18 refused to bind it at all. It stands for no second factor, so a login it holds passes no step-up that asks `mfa`. Recovery codes come with the first factor that counts: a subject whose only factor is the code by email holds none. Coming from 0.17, which made recovery codes for a first binding of it, that is a change: such a subject has no codes until it binds a factor that counts. With `adds-second-factor = true` the code counts, and gets codes, as before.
- <a id="u-0.19-24"></a>**U-0.19-24**: **Federation grants' browser half is the package `federation-grants-connect` now** (`@o3co/auth-provider-delegation/federation-grants-connect/module`): the link a client sends the user to, the question, the decision and the upstream's callback, and whose upstream account a callback reached. It is a bridge `combinations` composes wherever `federation-grants` is. An app composed by hand, or generated with 0.18 (its `src/main.ts` lists the modules it composes), composes `federation-grants-connect` beside `federation-grants`, or is generated again: without it, boot is refused at `federation-grants.browsers` (`needs exactly one contribution (0)`).
  - Four keys move from `federation-grants` to `federation-grants-connect`, with the same values and defaults: `page`, `login-page`, `step-up-page` and `identity-check`. Left under `federation-grants`, they refuse boot at `federation-grants`, naming each (`Unrecognized key: "page"`, or `Unrecognized keys: …` for several), never its value: move them. The variables a generated app reads for them are `FEDERATION_GRANTS_CONNECT_PAGE` and `FEDERATION_GRANTS_CONNECT_LOGIN_PAGE`, in place of `FEDERATION_GRANTS_PAGE` and `FEDERATION_GRANTS_LOGIN_PAGE`.
  - The routes, their paths, answers and audit events, the grants kept, and the connect a login or a step-up returns to are unchanged. Connections without the page refuse boot at `federation-grants-connect` now, in place of `federation-grants`, in the same words.
  - Affected: an app that composes `federation-grants`, composed by hand or generated with 0.18, or a configuration that sets `page`, `login-page`, `step-up-page` or `identity-check` under `federation-grants`.
- <a id="u-0.19-25"></a>**U-0.19-25**: **An app composed by hand with `acr`** composes `login-gates` too (`acr`'s dependency, which `combinations` and `create-app` compose with it): `acr` now names `login-gates`' `logins` among what it takes, so boot is refused without it at `acr` (`no module provides login-gates`), even with an empty `acr.values`. 0.18 asked `login-gates` only where the table held an acr. Affected: an app composed by hand with `acr` and no `login-gates`.
- **0.17's variables left in the environment**: the entries of an app generated with 0.19 read `APP_LEGACY_VARIABLES`: unset or `warn`, the warning as before; `refuse`, boot is refused where one is set, naming each, never its value; `ignore`, the check is skipped. Any other value refuses boot at `APP_LEGACY_VARIABLES`. An app generated with 0.18 warns as before, and takes the variable once generated again; its entry calls `config-files`' `unreadLegacyVariables` and `legacyVariablesWarning`, which 0.19 keeps.
- <a id="u-0.19-26"></a>**U-0.19-26**: **The client credentials grant is a module of its own** (`client-credentials`, `@o3co/auth-provider-oauth/client-credentials/module`): `token-endpoint` no longer serves it. The grant answers as before. An app generated with 0.18 (its `src/main.ts` lists the modules it composes), or composed by hand, serves it only once it composes `client-credentials` beside `token-endpoint`, or is generated again. Generated with 0.19, the full template and the `a2a` pattern compose it; the other patterns do not, so add it (`--add @mod/client-credentials`) where a client uses it. Affected: a client uses the client credentials grant, in an app composed by hand, generated with 0.18, or of a pattern that does not compose it.
- **`grant_types_supported` names only the grants composed** (discovery's metadata): 0.18 listed `client_credentials` in every app; 0.19 lists it only where `client-credentials` is composed. A client that reads `client_credentials` from discovery is affected as [U-0.19-26](#u-0.19-26) says.
- <a id="u-0.19-27"></a>**U-0.19-27**: **A client allowed a grant that nothing composed serves now refuses boot** (a breaking change), whichever grant it is. 0.18 started, and answered a request for that grant `unsupported_grant_type`; 0.19 refuses boot at `clients.registered.<i>.sections.client-allowance.grants.<j>`, naming the module that serves it, never the client's id: `no composed module serves this grant: compose client-credentials, or take it out of the client's grants`. So a configuration that did no harm in 0.18 can now be refused: a client allowed `refresh_token` in an app without `refresh`, or one allowed `client_credentials` in an app generated with 0.18, which composes no `client-credentials`. Fix it either way: take the grant out of that client's `grants`, or compose the module named. Only the clients registered in the settings (`clients.registered`) are checked at boot. Affected: a client in `clients.registered` allowed a grant no composed module serves.
- <a id="u-0.19-28"></a>**U-0.19-28**: **Code that imports `clientCredentialsGrantType`** from `token-endpoint` (`@o3co/auth-provider-oauth/token-endpoint`): import it from `client-credentials` (`@o3co/auth-provider-oauth/client-credentials`); its value is unchanged. `token-endpoint` no longer exports it. Affected: code that imports it from `token-endpoint`.
- <a id="u-0.19-29"></a>**U-0.19-29**: **Names resolve in two helper processes by default** (`outbound.resolution = helper`): a request whose lookup does not answer by its deadline stops waiting on it, and a helper is ended once no one waits on any of its lookups (within its limits on restarts), so a slow name no longer holds Node's threadpool. A lookup that others still wait on runs on in its helper, holding its place, until it answers. The answers and their order are the system's, as before. The helpers take about 100 MB and 35 ms more at boot, and none of the app's environment but the resolver's variables; where no process may be started, boot is refused at `outbound.resolution`. See [Name resolution](runbook.md#name-resolution). `outbound.resolution = in-process` keeps 0.18's resolving. Affected: a host where the app may not start processes, or cannot spare about 100 MB.
- **`outbound.max-lookups`** (new, 1 to `max-concurrent`) sets the names resolving at once: four unless set, at most `max-concurrent`, half of them for names an outside party chose. 0.18 took half the threadpool, two by default; with the helpers, four do not take the threadpool. With `in-process`, at most half the threadpool still resolves at once. A `max-lookups` above `max-concurrent` refuses boot.
- <a id="u-0.19-86"></a>**U-0.19-86**: **`clients-cimd` needs a share of the lookups for the names its clients' documents give** (`clients-cimd`, `outbound`): the outside party's share is half the lookups at once, rounded down, so with fewer than two it is none, and `clients-cimd` refuses boot at its name: "outbound resolves no name a metadata document chooses". That happens with `outbound.max-lookups = 1`; with `outbound.max-concurrent = 1`, which holds `max-lookups` to 1; and with `outbound.resolution = in-process` where the threadpool's half is under two. Set `outbound.max-lookups` to 2 or more (and `max-concurrent` with it, where that is 1), and, resolving in process, `UV_THREADPOOL_SIZE` to 4 or more, as the refusal says. Affected: a deployment that composes `clients-cimd` with `outbound.max-lookups = 1`, `outbound.max-concurrent = 1`, or in-process resolution on a small threadpool.
- <a id="u-0.19-30"></a>**U-0.19-30**: **A name is resolved as the URL writes it, a trailing dot kept.** A URL written `http://users.` was resolved as `users`, the resolver's search domains applied; it is now resolved as the name it writes, with none. Write a name without its dot where you mean the search domains to apply. Affected: a URL in the configuration whose host ends with a dot.
- **The proxy's own name** (`outbound.proxy` naming a host) is resolved as one of the deployment's lookups, bounded and within each request's deadline, and the proxy is reached at the addresses it answers, each family tried in turn as before. It now takes one of the deployment's lookups: count it when you set `outbound.max-lookups`.
- <a id="u-0.19-31"></a>**U-0.19-31**: **The fake HTTP ledgers are gone from the published test helpers**, with no published replacement: `usersLedger` (and `LedgerCall`, `LedgerAnswer`, `LedgerUser`) from `@o3co/auth-provider-user-ledger-http/users-http/testing`, whose subpath goes with them, and `witnessLedger`, `LedgerCall` and `LedgerAnswer` from `…/mfa-witness-http/testing`, which keeps its test configuration (`mfaWitnessHttpConfig`, `testCredential`). A test of your own that used a fake ledger serves its own, answering the calls as `users-http`'s card and the runbook's sections on the witness ledgers describe them. Affected: tests that import `usersLedger` or `witnessLedger` from the published test helpers.
- **The words of the HTTP ledgers' wire are a package of their own**, `ledger-wire` (`@o3co/auth-provider-user-ledger-http/ledger-wire`): the bodies `users-http`, `mfa-witness-http` and `passkey-witness-http` send and the answers they read. Nothing changes on the wire, and an app need not name it: the modules that speak it depend on it.
- **A jwt-bearer issuer's assertions can be used up in a ledger shared with another service** (new, opt-in): `jti-ledger-http` (`@o3co/auth-provider-user-ledger-http/jti-ledger-http`) contributes to `jwt-bearer`'s new extension point `jtiLedgers`, one per issuer, and the grant then uses that issuer's `jti`s up there, never in its own store. Without it nothing changes: each issuer's `jti`s go to the store as before. Use it where another service accepts the same assertions (the same `aud`), so neither can accept one the other has used.
  - The call, its answers and its settings are in the module's card: `POST {consume-url}` with `{"jti", "exp"}`, `204` first, `409` replayed, anything else unavailable; the credential as `Authorization: Bearer`, or as it is in the header `credential-header` names (`outbound`'s new `credentialHeader`).
  - The ledger records by `jti` alone, so every signer whose assertions it holds is in one trust domain: have them make each `jti` unique across all of them (128 bits or more at random), as a `jti` used up by one refuses it for all.
  - While the ledger cannot answer, that issuer's grant is unavailable (503): it never falls back to the store. An answer lost on the way may leave the assertion used up; the client signs another.
  - <a id="moving-an-issuer-between-the-store-and-a-ledger"></a>Moving an issuer from the store to a ledger, or back, splits its record in two unless every service switches at once. Let `L` be the issuer's `max-assertion-lifetime`, `S` its `clock-skew` (its entry's, where it narrows the section's), and `D` how far apart the hosts' clocks may be: an assertion accepted at a moment may be accepted again for up to `L + S` after it, never past a second before its `exp`, so wait `L + 2S + D` (a bound above that) from the last moment the old record could be used (the old version stopped and its requests drained).
    - From the store to a ledger the other service already uses: first lower `max-assertion-lifetime` to a short `L'` (rolling out is safe) and wait `L + 2S + D`; stop the issuer's grant on every instance (stop them, or roll out without the issuer, and without its `signer-keys-http` and `jti-ledger-http`, which refuse boot for an issuer not named); wait `L' + 2S + D`; start the version with `jti-ledger-http` on every instance at once, never rolling.
    - From one ledger to another: stop every service using it up (the grant and the others), copy the records once all have stopped, and start all on the new one at once; or stop all and wait for the longest of their windows, each service's `L + 2S + D` by its own lifetime and allowance (one that accepts assertions longer than the grant does sets the wait), then start all on the new one at once. A new `consume-url` at the same ledger rolls out as any change does.
    - Back to the store only where no other service accepts the issuer's assertions any more: the store is the grant's alone, so the record would split again for every new assertion. Stop the grant and every service that used the ledger, wait for the longest of their `L + 2S + D` (or until the latest `exp` the ledger holds, plus `S` and `D`), then start the store's version at once.
- <a id="u-0.19-32"></a>**U-0.19-32**: **A boot refused after its modules were built runs their stop hooks first** (`kernel`): the resolver's helpers end and Redis's connections close before `assemble` rejects, rather than being left until the process ends. The generated entry still exits 78 with the same refusals; a refused boot is longer by the time its hooks take, their waits held to `kernel.stop-deadline`. An entry or a test of your own that catches the refusal and lives on no longer ends them itself. A stop hook may now run without `start()`: one in a module of your own ends what its build started, whether or not the app ever started. Affected: a module of your own with a stop hook, or an entry or a test that catches the refusal.
- <a id="u-0.19-33"></a>**U-0.19-33**: **A login's `redirect_to` is taken only as written** (`login-gates`): a target is the public origin and a return path exactly, to the query. A spelling the URL parser rewrites to a return path (a dot segment, a backslash) answered as that path in 0.18, and is `invalid_redirect` now. A login page that sends back the `redirect_to` it was given changes nothing; one that builds it writes the origin and the path as they are. Affected: a login page that builds `redirect_to` itself.
- <a id="u-0.19-34"></a>**U-0.19-34**: **users asks for a link store in every composition** (`users`): an app composed by hand with a contact store of its own and no link store is refused at boot, naming `users.link-store`, though its user ledger looks users up by upstream identity and never uses the link store. Compose a link store beside it (`users-store` provides both stores). An app the combinations compose, a generated one included, composes `users-store` with `users` already, and changes nothing. Affected: an app composed by hand with a contact store of its own and no link store.
- <a id="u-0.19-72"></a>**U-0.19-72**: **A user's `email` is taken only as RFC 5322's addr-spec in ASCII, and a `name` only as text holding more than blanks** (`users`; OpenID Connect Core §5.1, §5.3.2): an `email` with a local part that is no dot-atom (two dots in a row, a leading or trailing dot, a quoted local part) or with characters outside ASCII, its domain's Unicode form included, is no longer one users takes; nor is an empty or blank `name`. A registered user holding one refuses boot at `users.registered.<n>.attributes.email` or `.name`, naming the attribute and never the value. A ledger's user (`users-http`, a ledger of your own) holding one still logs in: the value is left out, and `users.attribute_dropped` logged with its name. A domain written in its ASCII form (`xn--`) is taken as before; a local part outside ASCII (an RFC 6531 address) has no such form, so its user has no `email` claim from 0.19, nor the `email_verified` beside it.
  - Affected: a registered user, or a user a ledger answers, with such an `email` or `name`, and a client or a module of your own that reads that user's `email` claim. Write the email's domain in its ASCII form, or leave the email or name out.
- <a id="u-0.19-81"></a>**U-0.19-81**: **A registered user's `email_verified` needs its `email`** (`users`): boot is refused at `users.registered.<n>.attributes.email_verified`, "only beside the user's email", where a registered user's attributes set `email_verified` and no `email`. A verification says nothing without the address it is of: 0.19 already left one out from a ledger, and `verified-email` judged such a user by a verification of nothing. Give the user its `email`, or drop `email_verified`.
  - Affected: a user in `users.registered` whose `attributes` set `email_verified` (`true` or `false`) and no `email`.
- <a id="u-0.19-35"></a>**U-0.19-35**: **A module of your own declares what it takes** (`kernel`). `defineModule`'s head now needs `takes`: each contract its factories `get` or hold `late`, and each extension point they `collect`, from other modules (`[]` for none; a function of its checked section where the section decides). A contract the module provides itself is not named. Before any factory runs, boot names every gap at once: a contract no module provides, one whose `takenBy` refuses the module, a point with too few or too many contributions for its rule (`one`, `some`; duplicate keys at a `keyed` point are still named once the contributions are built), and a module that declares no takes. A factory taking what its `takes` do not name refuses boot. The release's modules declare theirs; a package of your own built against 0.18 no longer type-checks, and one in plain JavaScript is refused at boot (`refused <name>: declares no takes`), until its head names them. Where a helper of yours takes for the module, keep its list beside the helper and spread it into `takes`, as the release's modules do. Affected: a module of your own.
- <a id="u-0.19-76"></a>**U-0.19-76**: **A module of your own declares whether it is safe on several instances** (`kernel`). `defineModule`'s head now needs `replicaSafe`: `true` where what the module keeps across requests is in no process of its own (nothing beyond its configuration, or behind another module's contract or the store's interfaces), or where instances differing in it breaks nothing; `false` where it keeps in its own process what every instance must share, such as what is used once, a count or a limit; or a function of its checked section where the section decides. With `kernel.deployment = multi`, boot refuses a module that says `false` (as before) and one that says nothing: a package of your own built against 0.18 no longer type-checks, and one in plain JavaScript is refused at its name, "declares nothing about multiple instances: say replicaSafe". The declaration is your word: nothing checks it, and a module that says `true` while it keeps what is used once in its own process boots on several instances and lets it be used twice. The release's modules declare theirs.
  - Affected: a module of your own, composed with `defineModule`, a store wiring of your own included; with `kernel.deployment = multi`, also one in plain JavaScript.
- **Self-issued signers at a trusted issuer** (`jwt-bearer`, `self-issued-prefix`, new and opt-in): a signer that names itself, its assertion's `iss` and `sub` both the prefix and its key's JWK thumbprint (as a device signs with a key of its own), is read as that issuer's. Nothing changes until an issuer of `jwt-bearer.issuers` sets it.
  - The issuer needs `subject-is-key-thumbprint = true` and its keys contributed (`signer-keys-http`); boot refuses a prefix beside written keys or a key set, one that starts any issuer, and two that overlap, at each one's place.
  - The prefix is compared as written, and the rest must be 43 characters of base64url; the `sub` must be the same `iss`. The keys are asked of the ledger by the thumbprint, under the issuer's own `issuer`, and only the key whose own thumbprint it is verifies. The signer stands for the thumbprint, or, linked, for the account `users` finds by it, whose revocation holds.
  - Audience, times, lifetime, the client's allowance and the issuance policies hold as for any other assertion. Each `jti` is named by the `iss` as sent: in the store, a self-issued signer's assertions are spent apart from its issuer's own, which keep their names, so what is spent stays spent. A ledger keeps them apart only where it is told the `iss`; `jti-ledger-http` sends the `jti` and `exp` alone, so there both share one namespace, which refuses more and never lets a reuse through.
  - Boot logs `jwt-bearer.self_issued_signers` (info) with the places of the issuers that take them, never a prefix.
- <a id="u-0.19-43"></a>**U-0.19-43**: **A JWT bearer assertion's `iss` is taken only as a string, and every refusal before its signature holds says `untrusted signer`** (`jwt-bearer`). 0.18 read an `iss` that was a list holding one issuer as that issuer; it is refused now, before any key is asked for. A refusal before the signature (an assertion not read as a JWT, an algorithm not taken, a malformed header or `kid`, a `sub` of the wrong shape, no key, a signature that does not hold) answered why, so an unsigned probe could tell which signers have keys; each now answers `invalid_grant` with `untrusted signer`. A refusal after the signature keeps its words (`malformed assertion` for a signed one without `exp`). Have such a client send `iss` as one string, and read `untrusted signer` where a tool read `not a JWT`, `algorithm not taken`, `subject is no key thumbprint` or `missing or malformed claims` before the signature. Affected: a client that sends a JWT bearer assertion's `iss` as a list, or a tool that reads those descriptions.
- <a id="u-0.19-84"></a>**U-0.19-84**: **A `request_uri` at the authorization endpoint is answered `request_uri_not_supported`** (`authorize`), as OpenID Connect Core §6.2 asks of a provider that takes none; 0.18 answered it `request_not_supported`, as it still answers a `request` (and a request sending both). The redirect carries `state` and `iss` as before; no setting changes. A client that matched `request_not_supported` for a `request_uri` sees the new code. Affected: a client that sends `request_uri` and reads the error it gets.
- **Apple's and Google's id_tokens as JWT bearer assertions** (`jwt-bearer-id-tokens`, `jwt-bearer.delegated-issuers`, new and opt-in), for apps already sent out that send the id_token of their sign-in as the assertion of the JWT bearer grant, its `aud` their own client ID upstream. This is not RFC 7523 §3, whose audience is the authorization server; for a new app, exchange the id_token (`exchange-id-tokens`), the standard way.
  - Compose `jwt-bearer-id-tokens` beside `jwt-bearer` and `exchange-id-tokens` (it comes only where named, `create-app --add`, never with the two alone), write the app's client in `exchange-id-tokens` as for the exchange, name in `jwt-bearer.delegated-issuers` each `iss` of the kinds taken (`https://appleid.apple.com`; Google's `https://accounts.google.com` and `accounts.google.com`), and allow the client `urn:ietf:params:oauth:grant-type:jwt-bearer` in `client-allowance.grants`. Boot refuses an issuer named that no module checks, one checked and not named, and one that is a trusted issuer's or that a self-issued prefix starts.
  - The id_token is checked as the exchange checks it, for the one client its (`aud`, `azp`) names, and taken once across both grants, in `exchange-id-tokens`' one record.
  - A public app proves the key its id_token names: it makes a DPoP key first, passes `BASE64URL(SHA-256(jkt))` as the sign-in `nonce`, and sends a DPoP proof with the grant. For an app already sent out that makes no DPoP key, set `sections.jwt-bearer.accept-unbound = true` on its registered client: an id_token naming no key is then taken without a proof, so a leaked one can be used once, before its owner, while it is still taken (up to `max-age` and `clock-skew` past its `iat`, and before its `exp`: 10m30s by default), and its token is bound to no key. Boot logs `jwt-bearer.accept_unbound` (warn) for each such client, and each assertion so taken. One naming a key is proved still. Set it back to false once the app sends DPoP.
  - Moving from a grant of your own that takes the same id_tokens splits their record in two unless every instance switches at once. With `D` how far apart the hosts' clocks may be: stop your grant on every instance at once (not rolling out), wait from when its last request ended this grant's `max-age`, plus your grant's clock skew (an id_token it took may say it was issued that far ahead) and this one's `clock-skew`, plus `D`, and start every instance with this one. Copy its records instead only where each maps to the kind and the SHA-256 of the id_token's header and payload, after a last copy taken once every instance has stopped. Back to your own grant likewise, stopping this one on every instance at once, and waiting until no id_token taken here can pass yours. If your grant takes an id_token only up to its own age past its `iat`, wait from when the last request here ended your grant's age limit, plus this one's `clock-skew` (an id_token taken here may say it was issued that far ahead) and your grant's clock skew, plus `D`: with an hour and five minutes on each side, an hour and ten minutes and `D`. If it takes one up to its `exp`, or longer, an hour is not enough: wait past the last moment it could still take one taken here, the latest `exp` such an id_token could have (the longest an issuer gives one, after the last taken), plus however long past its `exp` your grant still takes one (its clock skew, or more), plus `D`. Or copy this record into yours, after a last copy taken once every instance has stopped.
  - Where the record's write fails on the way:
    - The store's answer is lost and the store settles it (it resends under the same mark): one token, as if nothing happened.
    - The write is applied but never settled before its deadline: the grant answers unavailable (503), the id_token may be used up, and a retry answers replayed. The app signs in again.
    - The grant's own answer is lost on the way to the app, after the token was issued: the id_token is used up, a retry answers replayed, and the app signs in again.
- <a id="u-0.19-45"></a>**U-0.19-45**: **An id_token's record is kept by the longest `max-age` and `clock-skew` any section may give** (`exchange-id-tokens`): to its `exp` or an hour past its `iat`, whichever is first, then five minutes and a minute. 0.18 kept it by the section's own values, so an instance on a longer `max-age`, or one after widening it, could take again an id_token whose record had gone. A record 0.18 wrote keeps its shorter life.
  - Upgrade with the same `max-age` and `clock-skew`; rolling out is safe, as the same settings take an id_token only while its record lasts.
  - Widen `max-age` or `clock-skew` only once `W = new max-age + old clock-skew + new clock-skew + D` has passed since the last request a 0.18 instance took ended (`D`, how far apart the hosts' clocks may be). An id_token 0.18 took may say it was issued up to the old `clock-skew` ahead, and its record went after `max-age` and that skew; the new settings take it up to the new `max-age` and `clock-skew` past that `iat`. The old `clock-skew` is the largest any 0.18 instance ran with, one narrowed during the upgrade included. To widen sooner, stop every instance, wait `W`, and start all on the widened settings. Narrowing both is safe at any time; widening `max-age` while narrowing `clock-skew` still waits `W`.
  - Affected: an app that composes `exchange-id-tokens` and is to widen its `max-age` or `clock-skew`.
- <a id="u-0.19-46"></a>**U-0.19-46**: **Each id_token's record lasts longer** (`exchange-id-tokens`): up to an hour and six minutes past its `iat`, whatever the section says; with the defaults (`max-age` `10m`, `clock-skew` `30s`), up to about 55 minutes longer than 0.18 kept it. Allow for that in the store holding `exchange-id-tokens-store.used`. Affected: an app that composes `exchange-id-tokens`.
- <a id="u-0.19-47"></a>**U-0.19-47**: **A JWT bearer assertion is taken only while a second of its life is left** (`jwt-bearer`): one with less than a second before its `exp` when its `jti` would be used up is refused as `expired`, its `jti` left unused; a token with less than a second left once it is issued is handed to no one, also `expired`, its `jti` used up. 0.18 took an assertion past its `exp` within `clock-skew`, and issued it a token with no life left. `clock-skew` still allows for `iat` and `nbf`. Affected: a client whose clock runs behind the server's, or that sends an assertion near its end: where it got a token that lived no time, it gets `expired`, and signs a new assertion.
- **A JWT bearer grant naming no client** (`jwt-bearer`, an entry's `client`, new and opt-in; RFC 7523 §3.1): a request carrying only `grant_type`, `assertion` and, if it likes, `scope` and `resource`, with no `client_id` and nothing a client authenticates with, is taken for the client an entry of `jwt-bearer.issuers` names in `client`. A sender that sends one is Claude Tag, whose guide asks the server it trusts to [register one client for its issuer that takes this grant without client authentication](https://claude.com/docs/claude-tag/admins/federated-access/authorization-server.md#configure-the-authorization-server). Nothing changes until an entry sets `client`.
  - Register the client: `kind = public`, `method = none`, its `client-allowance.grants` the JWT bearer grant alone, and its scopes and audiences the sender's tokens may carry. Leave out `sender-binding` for a sender that sends no DPoP proof.
  - Write the sender's issuer and keys (`keys` or `jwks-uri`) in `jwt-bearer.issuers`, with `client` naming that client and `conditions` naming your organisation, such as the `subject-prefix` its `sub` starts with (a `linked` entry, its subjects those `users` links, needs none). Set the section's `clock-skew` to the sender's (60 seconds for Claude Tag), and the entry's `max-assertion-lifetime` to its assertions' (`10m`). On the sender's side, give this server's issuer URL, or its token endpoint's, as the audience.
  - Boot refuses, at the entry's `client` and never by its value: a client not registered, one with credentials, one allowed another grant, and one two entries name; and `accept-any-subject` beside a `client`, as a request naming no client has no authentication to stand in for conditions. Each boot warns `jwt-bearer.clientless_issuer` with the entry's place.
  - An entry and its client are bound both ways, whether a request names the client by its `client_id` or names none: the entry's assertions are issued to that client alone, and the client takes its own entry's assertions alone, a delegated issuer's id_tokens none. Another is `assertion is for another client`, using up no `jti`. One `jti` is used up once, whether a request names the client or none.
  - A request naming no client is answered `invalid_grant` with `untrusted signer` for whatever fails before its subject is taken (the signature, its times or audience, an entry with no `client`, its conditions, its link), so it tells nothing of which issuers take it. A request naming the client keeps the grant's own words.
  - Once one entry has a `client`, a JWT bearer request carrying nothing a client authenticates with is answered `400 invalid_grant`, whatever its `iss` (a malformed one `400 invalid_request`), where it was `401 invalid_client`. Taking `client` off one entry leaves its requests `400 invalid_grant` while another entry keeps one; off every entry, `401 invalid_client` again. A request carrying a credential, even one no composed method reads, is authenticated as before.
- **Each trusted issuer's own policy** (`jwt-bearer.issuers`, new keys, each optional; nothing changes until an entry sets one):
  - `conditions` its assertions' verified claims must meet: `subject-prefix`, and `claims`, each a value or a list of values, compared by value and kind. The six registered names (`iss`, `aud`, `exp`, `nbf`, `iat`, `jti`) and an empty `conditions` are refused at boot. An assertion that does not meet them is refused `assertion does not meet its issuer's conditions`, after its signature and before a linked subject is looked up or its `jti` used up; the answer names no claim or value.
  - `ceiling` (`scopes`, `audiences`, each a list not empty) narrows its tokens within the client's allowance: past it is `invalid_scope` or `invalid_target`, as past the client's, the `jti` left unused; a default scope the ceiling leaves none of is refused, never issued empty.
  - `algorithms`, for a key set or keys contributed: by default EdDSA, ES256 and RS256, as before. To take PS256 or another, name it; where two algorithms fit one kind of key, write `alg` in each of the key set's keys (U-0.19-44).
  - `accept-key-set-elsewhere = true` takes a `jwks-uri` off the issuer's host, at https still; boot logs `jwt-bearer.key_set_elsewhere` (warn) with the entry's place.
  - Its own `max-assertion-lifetime` and `clock-skew`, which may narrow the section's and never widen them: a wider one refuses boot at that key. An entry's `clock-skew` narrows what is taken, never how far a revocation reaches: an assertion made before its subject's `sessions` boundary is held to it by the section's `clock-skew`, so narrowing the entry's lets none back. `max-assertion-lifetime` bounds how far ahead `exp`, and how far back `iat`, an assertion may be when it is taken, not `exp - iat`.
- <a id="u-0.19-48"></a>**U-0.19-48**: **A trusted issuer whose every signer becomes a subject names its subjects, or says it takes any** (`jwt-bearer`): an entry of `jwt-bearer.issuers` with `subject = as-is` and no `subject-is-key-thumbprint`, its keys written or a `jwks-uri`, now needs `conditions` or `accept-any-subject = true`; without either, boot is refused at that entry (`jwt-bearer.issuers.<i>`), never by its value. So does one whose keys a module contributes at `signerKeys` without declaring `perSigner`. 0.18 issued a token for any `sub` such an issuer signed, so an issuer several organisations share made tokens for the others' subjects too.
  - An issuer several organisations share: write `conditions` naming yours, a `subject-prefix` or a claim that names your organisation.
  - An issuer yours alone: write `accept-any-subject = true`. Each boot logs `jwt-bearer.any_subject` (warn) with the entry's place, never its issuer.
  - Or make the entry `linked`, its subjects those `users` links.
  - `accept-any-subject` beside `conditions`, or on an entry that needs neither (linked, a thumbprint, keys contributed per signer), refuses boot at that key. Nothing writes either for you: choose for each entry.
  - A module of your own contributing at `signerKeys`: declare `perSigner: true` where it answers each signer's own keys alone, or write `conditions` on its entry. `signer-keys-http` declares it, so its entries are unchanged.
  - Affected: an entry of `jwt-bearer.issuers` with `subject = as-is`, no `subject-is-key-thumbprint`, and its keys written, a `jwks-uri`, or keys contributed without `perSigner`.
- <a id="u-0.19-49"></a>**U-0.19-49**: **Each spent JWT bearer assertion's record lasts longer, by no setting** (`jwt-bearer`): to its `exp`, plus five minutes (the widest `clock-skew` there is) and a minute, in the store and as a ledger's `keepUntil`. 0.18 kept it to its `exp` plus the receiving instance's `clock-skew` and a minute, so an instance on a wider `clock-skew` could take again an assertion whose record had gone. Each record now lasts up to five minutes longer, four and a half with the default `clock-skew` (`30s`); what is taken does not change. Allow for that in the store holding `jwt-bearer-store.spent`, and in a ledger at `jtiLedgers` (`jti-ledger-http` sends that time as the wire's `exp`). Affected: an app that composes `jwt-bearer`.
- <a id="u-0.19-50"></a>**U-0.19-50**: **`accept-loose-audience` stays, and each start names the clients that set it** (`client-assertion`): a client's assertion still names the issuer alone by default. `sections.client-assertion.accept-loose-audience = true` lets a client name the token endpoint's URL or a list, as Nimbus and Spring Security do by default; 0.18.6 called it temporary, and from 0.19 it is kept. Each start logs `client-assertion.accept_loose_audience` (warn) once for each registered client that sets it, with the client's id, beside the `client-assertion.loose_audience` warning for each assertion taken that way. While it is set, an assertion that client made for another authorization server naming this server's token endpoint can be used here first. Set it only for a client whose library cannot send the issuer, and take it out once the client does. Affected: a client registration that sets `sections.client-assertion.accept-loose-audience = true`.
- <a id="u-0.19-56"></a>**U-0.19-56**: **A refused client assertion is answered `invalid_client`** (`clients`, `client-assertion`, `token-endpoint`; RFC 7521 §4.2.1): half of a client assertion (its type or the assertion alone, or an empty one), a part or `client_id` given twice, and a client assertion beside another client authentication method (a client secret, a Basic header) are answered `401 invalid_client`, with the Basic challenge where the request also sent a Basic header, where 0.18 answered them `400 invalid_request`. The token, introspection, revocation and device authorization endpoints answer alike. Two methods or malformed credentials with no client assertion among them stay `400 invalid_request`.
  - Affected: a client that sends such a request and reads its error, which reads `invalid_client` now.
  - A method of your own contributed at `authMethods` that authenticates by an assertion says so with `assertion: true`, and its refusals are answered alike.
- <a id="u-0.19-85"></a>**U-0.19-85**: **A method of your own at `authMethods` that would sign with nothing refuses boot** (`clients`; RFC 8414 §2): boot is refused at `clients.methods.<method>` for a method naming the JWS algorithm `none` among its signing algorithms (in any case), naming an empty list of them, or authenticating by an assertion (`assertion: true`) and naming none. The method a public client uses, named `none`, composes as before, and so does every method this release ships. Name the algorithms the method signs or MACs with. Affected: a module of your own that contributes at `authMethods`.
- <a id="u-0.19-87"></a>**U-0.19-87**: **A `null` member in JSON a module of your own answers or signs is refused** (`http`, `keys`; OpenID Connect Core §13.3): the provider leaves out a member with no value rather than writing it as null. A JSON answer holding a `null` member, at any depth, gets `500` with none of its route's headers, and `http.failed` (kind `null_member`) names the members' key paths, never their values. `keys.sign` and the access-token signing refuse claims holding a `null`, with a `TypeError` naming the key paths. No route or token of this release holds one. Leave the member out instead. Affected: a module of your own that answers JSON through `http` or signs claims through `keys`.
- **Two error answers say what the specifications ask** (`authorize`, `federation-tokens`; RFC 6749 §4.1.2.1, RFC 6750 §3.1): an authorization redirect's `error_description` is held to RFC 6749's characters, as the token endpoint's already was, each other character written `?`; and `federation-tokens`' `403 forbidden` carries `WWW-Authenticate` with `error="insufficient_scope"`, in the scheme the token was presented in. No setting changes.
- <a id="u-0.19-70"></a>**U-0.19-70**: **A `resource` that is not an absolute URI, or carries a fragment, is refused `invalid_target`** (`resource-indicators`, `token-exchange`; RFC 8707 §2, RFC 8693 §2.1): before it is compared with any audience, a `resource` without a scheme (`api.example`, `/v1`), holding a character outside printable ASCII (whitespace, a control character, or one RFC 3986 does not write, such as `ü`), or that `URL` cannot parse is refused `400 invalid_target`, described `resource is not an absolute URI`; one with a fragment is refused, described `resource carries a fragment`. An empty `resource` is still read as none (RFC 6749 §3.2), keeping the default audience. A JWT bearer ID-JAG's `resource` claim is read the same way. 0.18 compared it with the audiences as a string, so an audience registered in such a form was issued. The authorization endpoint answers the refusal on the redirect URI as before. Affected: a client sending such a `resource`, and a client whose `client-allowance.audiences` hold a value in such a form, which a `resource` can no longer ask; register audiences as absolute URIs.
- <a id="u-0.19-71"></a>**U-0.19-71**: **A federation grant connection's `resource` with a fragment or a query refuses to boot** (`federation-grants`; RFC 8707 §2): `federation-grants.connections.<name>.resource` is sent upstream as written, so it takes an absolute URI with no fragment and no query; boot is refused at that key otherwise (`resource must carry no fragment`, `resource must carry no query`), where 0.18 sent it upstream as written. Affected: a deployment whose connection names such a `resource`, which writes it without them.
- <a id="u-0.19-67"></a>**U-0.19-67**: **A session grant without a session is refused `400 invalid_grant`** (`session-grant`; RFC 6749 §5.2): a session grant with no same-origin evidence, or with no session to enter, is answered `400 invalid_grant`, described `session is not authenticated`, where 0.18 answered `401 unauthorized`, a code no registry holds. Affected: a client of the session grant (a backend for frontend) that reads the status or the error of its refusal.
- <a id="u-0.19-68"></a>**U-0.19-68**: **A certificate refused at issuance is answered `invalid_client`** (`mtls`; RFC 6749 §5.2): a certificate the token endpoint refuses to bind a token to (unreadable, or failing the PKI checks) is answered `400 invalid_client`, where 0.18 answered `400 invalid_certificate`, a code no registry holds. A refused certificate at a resource stays `401 invalid_token`. Affected: a client that presents a certificate and reads the error of its refusal.
- <a id="u-0.19-69"></a>**U-0.19-69**: **Token exchange takes the lifetime asked as `o3co_expires_in`** (`token-exchange`; RFC 6749 §8.2): the lifetime a token exchange asks is sent as `o3co_expires_in`, by the same rules (1–10 ASCII digits, from 2, cut to `max-lifetime`), as RFC 6749 registers `expires_in` for answers alone. A request's `expires_in` is an unknown parameter now and asks nothing: the exchange issues for the usual lifetime, and a malformed `expires_in` is no longer refused. `expires_in` in the answer is unchanged. Affected: a client of token exchange that sends `expires_in`, which sends `o3co_expires_in` in its place.
- <a id="u-0.19-61"></a>**U-0.19-61**: **An app that composes `token-endpoint` and no grant refuses to boot** (`token-endpoint`; RFC 8414 §2): boot is refused at `token-endpoint`, "no grant is composed: compose one, or leave the token endpoint out". With no grant, the endpoint would publish an empty `grant_types_supported`, which `discovery` leaves out and a client reads as `authorization_code` and `implicit`. A grant composed but allowed to no registered client opens no issuance. An app that `create-app` made always composes `token-endpoint`, so keep one of its grants selected.
- <a id="u-0.19-78"></a>**U-0.19-78**: **`offline_access` in a client's allowed scopes refuses boot** (`client-allowance`): offline access is not offered, so allowing a client `offline_access` allows nothing, for an OpenID Connect client and a plain OAuth one alike; 0.18 took it as any scope. A registration that lists it in `sections.client-allowance.scopes` or `default-scopes` is refused at boot at that entry (`clients.registered.<n>.sections.client-allowance.scopes.<i>`); remove it. Removing it is all: a client whose authorization requests ask `offline_access` beside another scope still works, the word dropped, and a client that wants refresh tokens has them by the `refresh_token` grant in its `grants`. At the token endpoint, a grant's request naming `offline_access` is read against the client's scopes, as before ([U-0.19-63](#u-0.19-63)); with no allowance able to hold it, such a request is always refused `invalid_scope` there. Affected: a client registration that lists `offline_access` there.
- <a id="u-0.19-80"></a>**U-0.19-80**: **`offline_access` in the ceiling of Client ID Metadata Document clients refuses boot** (`clients-cimd`): offline access is not offered, so a client allowed `offline_access` is allowed nothing by it. A configuration that lists it in `clients-cimd.scopes` is refused at boot at that entry (`clients-cimd.scopes.<i>`); remove it. 0.18 took it, and a document asking it got it as any scope. Affected: a configuration that lists `offline_access` in `clients-cimd.scopes`.
- <a id="u-0.19-65"></a>**U-0.19-65**: **Client ID Metadata Documents need their hosts chosen** (`clients-cimd`; RFC 9700 §4.11.2): with `clients-cimd.allow` empty (its default), 0.18 fetched a client id's document from any https host `deny` left, so any such host could become a client whose errors and refusals the provider redirects to. 0.19 refuses boot at `clients-cimd.allow` until you name the hosts a document may come from (`.name` also takes the names under it), or set `clients-cimd.allow-any-host = true` (new, default `false`) to keep taking any host. With it set, every start logs the warning `clients-cimd.any_host_allowed`; set beside a non-empty `allow`, it refuses boot at its key. Affected: an app that composes `clients-cimd` without `clients-cimd.allow`.
  - Affected: an app that composes `token-endpoint` and none of the modules that contribute a grant (`client-credentials`, `code-grant`, `refresh`, `jwt-bearer`, `token-exchange`, `device-grant`, `session-grant` and the like).
- <a id="u-0.19-59"></a>**U-0.19-59**: **The `claims` request parameter is taken for standard claims** (`claims-selection`, `authorize`, `oidc`, `userinfo`, `refresh`; OpenID Connect Core §5.5):
  - A claim a request names under `id_token` or `userinfo` beyond its scope is released there, in the ID token or at userinfo, where the client is allowed the claim's scope and the user agreed to it (a first-party client's is agreed to). One that is not is left out, essential or not, with no error.
  - A `value` or `values` asked holds back that target's claim where it does not match, a claim the scope releases included. In an OpenID Connect request, a `sub` value other than the signed-in user's is `login_required`. A claim request of no shape it takes is `invalid_request`. Discovery says `claims_parameter_supported: true`.
  - A new module, `claims-selection`, keeps what each request asked, for its code, its refresh family and each access token, and a refresh cuts the names to what is allowed and agreed to then. It joins `code-grant`: `combinations` composes it, with its store template `claims-selection-store`. An app composed by hand, or generated with 0.18 (its `src/main.ts` lists the modules it composes), composes both beside `code-grant`, or is generated again; without them, `authorize` and `code-grant` find no `claimsSelections` and boot is refused. Its store needs no eviction, durability and replication.
  - Its setting `authorize.claims-parameter`, true by default. False ignores a claims request's names and value constraints, the request still given its code, and discovery does not say the parameter is supported; boot logs `authorize.claims_parameter_off` (warn). The `sub` of an OpenID Connect request, the acr, an essential `auth_time` and the parameter's form hold either way, as do the scope's claims and the selections already kept.
  - `claims-selection` takes no section: a configuration that writes one, `claims-selection.mode` among them, is refused at boot.
  - An instance of 0.18 does not read the selections (names and value constraints) an instance of 0.19 kept. During a rolling upgrade, set `authorize.claims-parameter = false` on the 0.19 instances, so none keeps a selection a 0.18 instance would ignore, and set it to `true` (its default) once every instance runs 0.19.
  - Going back to a release before 0.19 is no path the provider takes, for any deployment that composes `code-grant`: a 0.18 instance would refresh a constrained family without its constraints.
  - Affected: a deployment that composes `code-grant`; an app composed by hand or generated with 0.18, which also composes the two modules; a client that sends `claims` with a `sub` value.
- <a id="u-0.19-62"></a>**U-0.19-62**: **An `id_token_hint` names the only person a code may be for, and `prompt=select_account` is refused** (`authorize`, `oidc`; OpenID Connect Core §3.1.2.1, §3.1.2.2): where `oidc` is composed, an OpenID Connect request's `id_token_hint` is checked. A hint naming someone other than the person signed in is `login_required`, `prompt=none` or not; 0.18 read no hint and gave a code for whoever was signed in. A hint that is no ID token this provider issued is `invalid_request`; one long expired is still taken. Without a session, the browser goes to log in as before. Like any parameter, a hint longer than 2048 characters is `invalid_request` (`parameter too long`). `prompt=select_account` is `account_selection_required`, as no page lets the person choose an account; 0.18 ignored the word. Affected: a client that sends `id_token_hint` or `prompt=select_account` in an OpenID Connect request.
- <a id="u-0.19-82"></a>**U-0.19-82**: **`acr_values` is a voluntary request** (`authorize`; OpenID Connect Core §3.1.2.1, §5.5.1.1): an `acr_values` value the provider does not know, or one the session does not meet, is no longer refused. The code is issued, carrying the first asked acr the session meets, or else the session's current acr, if any. A session that falls short goes to `authorize.step-up-page` once, where it is set and the request is not `prompt=none`. An `acr` asked in the `claims` parameter (`id_token.acr`, `userinfo.acr`) takes the place of `acr_values`, and is voluntary in the same way unless asked as essential. Only an essential one is refused: `unmet_authentication_requirements` for one the provider does not know, or one not met with no step-up page or after it; `interaction_required` under `prompt=none`. 0.18 refused an unknown or unmet `acr_values` with `unmet_authentication_requirements`. An RP checks the `acr` in the ID token: a sign-in weaker than it asked for now reaches it, and only the `acr` says so. To require an acr, ask for it as essential in `claims`. Affected: a client that sends `acr_values` and relied on the provider refusing a sign-in that does not meet it.
- <a id="u-0.19-63"></a>**U-0.19-63**: **`offline_access` is ignored in every authorization request, whatever the client is allowed** (`authorize`; OpenID Connect Core §11): the provider offers no offline access, so an authorization request that names `offline_access` gets a code for the rest of its scope. 0.18 refused it with `invalid_scope` where the client's `scopes` did not name `offline_access`, and issued it where they did. Only the scope changes: the token response always states the scope issued, without `offline_access`, as does the access token, and a refresh token still follows the client's `refresh_token` grant, as before, bound to the session. A request that names `offline_access` alone is refused with `invalid_scope` (`offline_access is not offered`), never given the client's default scope. This is the authorization request alone: at the token endpoint, a grant's request that names `offline_access` is read against the client's `scopes` as before. Affected: a client that asks for `offline_access`, whether it reads `invalid_scope` as its sign that offline access is not allowed or `offline_access` in the scope as one that it is.
- <a id="u-0.19-53"></a>**U-0.19-53**: **A logout asking an unregistered return is refused** (`rp-logout`): a request to `/oauth/logout` whose `post_logout_redirect_uri` is not exactly one the hint's client registered, or that asks a return with a hint naming no one client, is now `400 invalid_request`, and the session stays open. 0.18 dropped the return and ended the session. A client record the return is judged by that cannot be read now answers `503`, nothing closed. Register every return a client sends, written exactly as it sends it. Affected: a client that starts a logout at `/oauth/logout` with a `post_logout_redirect_uri` it did not register.
- <a id="u-0.19-54"></a>**U-0.19-54**: **A logout naming another client than its hint's is refused** (`rp-logout`): a request to `/oauth/logout` with a `client_id` that is not the client the `id_token_hint` was issued to, or with a `client_id` beside a hint naming no one client, is now `400 invalid_request`, and the session stays open. 0.18 read no `client_id`. Send as `client_id` only the client the hint was issued to, or send none. Affected: a client that starts a logout at `/oauth/logout` with a `client_id` other than the one its hint's ID token was issued to.
- <a id="u-0.19-55"></a>**U-0.19-55**: **A logout request sending a parameter twice is refused** (`rp-logout`): a request to `/oauth/logout` that sends any parameter more than once, by `GET` or `POST`, is now `400 invalid_request` (`repeated parameter`), and the session stays open. 0.18 read a repeated parameter as absent. Send each parameter once. Affected: a client that starts a logout at `/oauth/logout` sending a parameter more than once.
- <a id="u-0.19-83"></a>**U-0.19-83**: **A logout without `id_token_hint` asks the person** (`rp-logout`): `GET` or `POST /oauth/logout` without a hint, whatever `post_logout_redirect_uri`, `client_id` or `state` it names, is sent `303` to the new `GET /oauth/logout/confirm`, a fixed English page asking whether to log out. Its form posts to `POST /oauth/logout/confirm` with a CSRF token, and only then is the browser's session closed, its clients told and the upstream's end of session followed, as for a hinted logout. Both are counted with the logout's own requests per source (`rp-logout.requests` in `rp-logout.window`). The confirmation never returns to the client: without a hint, no return or client is read, since anyone could have written either, so the page ends on the provider's own logged-out page (RP-Initiated Logout 1.0 §3). 0.18 refused a request without a hint `400 invalid_request` (`id_token_hint is required`); a client that sends a return without a hint now sees its user asked and left on the provider's site, so send `id_token_hint` wherever the user should come back. The page a logout ends on now says the user is logged out. What the confirmation needs at boot is [U-0.19-60](#u-0.19-60). Affected: a client that starts a logout at `/oauth/logout` without `id_token_hint` and expects its user back, or reads the `400`.
- <a id="u-0.19-58"></a>**U-0.19-58**: **A `Sessions` of your own** (a stand-in of `session`'s contract) offers `handleOf(request)`: the handle of the session the request's cookie opens, read from your cookie index alone, without reading or changing the session; none for no cookie, one sent twice, a forged one or one retired, and Unavailable when the index cannot be read. `session-lifecycle` and the published stand-in and stub offer it. Affected: code that provides `session`'s `sessions` in place of `session-lifecycle` or the stand-in.
- <a id="u-0.19-60"></a>**U-0.19-60**: **`rp-logout` checks CSRF, so it needs `csrf` and `http.public-origin`** (`rp-logout`, `csrf`): the confirmation of a logout without a hint posts a form `csrf` checks, so `rp-logout` now takes `csrf`, which refuses boot without `http.public-origin`. An app generated by `create-app`, or composed through `combinations`, composes `csrf` with `rp-logout`, and one that composes `logout`, `login-password` or `consent` already needed both. Set `http.public-origin`; in a `src/main.ts` you wrote yourself, or one generated with 0.18 (where `rp-logout` did not take `csrf`), add `csrf` beside `rp-logout`, or generate the project again. Affected: an app that composes `rp-logout` and no other module that checks CSRF, without `http.public-origin`, or one composed by hand that lists `rp-logout` without `csrf`.
- <a id="u-0.19-88"></a>**U-0.19-88**: **A logout by `POST` takes one redirect more** (`rp-logout`; OpenID Connect RP-Initiated Logout 1.0 §2): a hinted `POST` to `/oauth/logout`, its checks passed, is answered `303` to the logout's own `GET`, carrying the checked request and never the hint. That `GET`, which the browser's session cookie comes with, logs out as before and sends the browser back to the return. A browser follows it by itself. Affected: a client that starts a logout at `/oauth/logout` by `POST`.
- **ID-JAGs from an enterprise IdP** (`jwt-bearer`, an entry's `profile = "id-jag"`, new, opt-in, preview): an Identity Assertion JWT Authorization Grant (draft-ietf-oauth-identity-assertion-authz-grant-04), which an IdP issues for one client and names what it allowed, is taken by its issuer's entry, and by no other entry. Preview: a later revision of the draft may change it in a minor version.
  - Each ID-JAG has the header `typ` `oauth-id-jag+jwt`, this server's issuer URL alone as its `aud` (never the token endpoint's), `iat`, and a `client_id` naming the client that presents it, which must be confidential. Its `scope` and `resource` are a ceiling beside the entry's `ceiling` and the client's allowance; with no `scope` in the request, its own is asked. A `cnf` naming a DPoP key (`jkt`) is proved by DPoP alone. `authorization_details` are dropped, and refused where no `scope` says what was allowed; `tenant` and `aud_tenant` are refused. No refresh token is issued, and the answer names the audience issued as `resource`.
  - Compose `dpop` with it: boot is refused at the entry's `profile` where no binding kind proves a DPoP key, as a proof none reads would bind nothing. Composing `dpop` checks the DPoP proofs every grant is sent, and binds their tokens; a client that sends none is answered as before, one whose proof was wrong is now refused.
  - Boot is refused at the entry's `profile` beside `subject-is-key-thumbprint`, a `self-issued-prefix` or a `client`. An `as-is` entry needs `conditions` or `accept-any-subject`, as any (U-0.19-48).
  - The metadata names `urn:ietf:params:oauth:grant-profile:id-jag` in `authorization_grant_profiles_supported` where an entry takes the profile, never which issuers.
  - From 0.17's ID-JAG issuer entries:
    - `allowedScopes`, `allowedAudiences` → the entry's `ceiling { scopes, audiences }`: each issuer's limits stay its own. 0.17 dropped what went past them; 0.19 refuses it (`invalid_scope`, `invalid_target`).
    - `allowedClients` → the entry's `conditions.claims.client_id`, the list of clients that may present its ID-JAGs; beside the check that `client_id` names the client presenting it, so a client allowed the grant that the list leaves out is refused (`assertion does not meet its issuer's conditions`). With an IdP other organisations share, write its subject condition in the same `conditions` (a `subject-prefix`, or a claim naming your organisation); with one yours alone, the client list alone, without `accept-any-subject`, which `conditions` refuses beside it.
    - `allowedClients` unwritten (any client): write no `client_id` condition. `allowedClients = []` (no client): leave the issuer out of `jwt-bearer.issuers`. Its ID-JAGs are then an unknown signer's, as no client could use them in 0.17. `conditions` takes no empty list, and an entry without the condition would let every client allowed the grant use them.
    - The entry's lifetime of an hour from `iat` → `max-assertion-lifetime` (the section's, or the entry's).
    - An `as-is` entry: `conditions` or `accept-any-subject` (U-0.19-48); 0.17 held no subject.
  - Where 0.19 answers otherwise than 0.17's profile: a scope or resource past what the ID-JAG and the entry allow is refused, not dropped; a `cnf` is held to a DPoP proof of that key, which 0.17 did not read; `authorization_details` are checked, and refused with no `scope`, which 0.17 did not read; and an ID-JAG is taken by its issuer's profile entry alone, where 0.17 took one at any entry of its issuer.
- <a id="u-0.19-52"></a>**U-0.19-52**: **An ID-JAG is refused at every trusted issuer but one that takes the profile** (`jwt-bearer`): an assertion whose header `typ` is `oauth-id-jag+jwt` is refused as an unknown signer is (`untrusted signer`) unless its `iss` is an entry with `profile = "id-jag"`, before anything is verified: delegated issuers, self-issued signers, a request naming no client and unknown issuers alike. 0.18 took it as any assertion of its issuer, its `client_id`, scope, `resource` and `cnf` unread, so another client allowed the grant could use it, for any scope the client was allowed. Write `profile = "id-jag"` on the issuer's entry and compose `dpop`; then a client other than the one its `client_id` names, a client that is not confidential, a scope or resource past it, and a request that does not prove its `cnf` key are refused, so check the clients that send it. Affected: a trusted issuer of `jwt-bearer.issuers` whose assertions are ID-JAGs.
- <a id="u-0.19-57"></a>**U-0.19-57**: **An OpenID Connect IdP can read its upstream's UserInfo** (`idp-oidc`, opt-in): `federation.idps.<name>.read-userinfo = true` has each login, once its id_token holds, read the IdP's UserInfo with the login's access token and take from it the `email`, `name` and `picture` the id_token leaves out. Nothing changes until you set it: by default the profile comes from the id_token alone, as before. A claim the id_token gives, however it gives it, stays the id_token's; the email comes with the verification of the answer that gave it, verified only by `email_verified: true`. Users are still found by the IdP and the id_token's `sub` alone, never by a UserInfo claim. What it adds reaches clients where the login's attributes are what the deployment releases: a user ledger over HTTP (`users-http`) with no `subject-url`, whose users the ID token and UserInfo then describe from the upstream's login; where `users` describes the user, its attributes are released as before. A UserInfo answer that names another `sub`, is not JSON, or is anything but a 200 refuses the login (`502 exchange_failed`); a 5xx or a UserInfo out of reach answers it `503`. UserInfo and the description it is read from must be https, even where `outbound` takes plain http for the IdP: on http, boot is refused at `issuer` or `userinfo-endpoint`. Without discovery, give `userinfo-endpoint` too. Affected: an IdP of type `oidc` whose id_tokens leave out a user's `email`, `name` or `picture` that its UserInfo gives.

## Operational notes

### Clocks

Every decision about time uses the host's clock, so keep hosts synchronized. Allowances for clock differences are configurable where a peer's clock matters: `client-assertion.clock-skew`, `jwt-bearer.clock-skew` and the IdPs' `clock-skew` (default 30 s), `dpop.proof-window` (default `1m`) and `mtls.revocation.skew` (default `5m`). Records kept in Redis expire by Redis's own clock, with margins for that.

### Upstream links in settings

A link from an upstream identity to a user written in `users.registered[].upstream` wins over one written at runtime for the same upstream identity; the runtime one is hidden and cannot be unlinked. Taking the upstream identity out of the settings lets the earlier runtime link take effect again, so check which user that link names before you remove it. Links match by IdP name and upstream subject only, never by email.

### Upstream amr

A federated login proves `fed` and nothing else, unless the IdP's `upstream-amr` maps the upstream's amr values to local ones. Where MFA is required, federated users then complete a local second factor, unless the map gives `mfa`: a login whose amr holds `mfa` passes the second-factor gate unasked. Mapping an upstream value to `mfa` trusts that IdP's claim for MFA, in place of a local second factor, and for every acr it satisfies; do so only for an IdP whose MFA you trust.

To keep the local second factor and still let the IdP's MFA meet an acr, as 0.18 did, map the upstream value to an amr of your own, such as `upstream-mfa`, and add a set holding it to that acr: `acr.values { "urn:o3co:acr:mfa" = [["mfa"], ["upstream-mfa"]] }`. The gate holds such a login as any other, where its subject has a factor to prove or must bind one, and the proof adds `mfa`; a login the gate lets through meets the acr by `upstream-mfa`. The operator's entry takes the place of the one `mfa-acr` offers, so keep `["mfa"]` in it.

### RP-initiated logout after an upstream login

When the session came from a federated login, logout goes on to the upstream IdP's end-session endpoint and passes the client's registered `post_logout_redirect_uri` to it unchanged. Register that URI as a post-logout redirect at the upstream IdP too, as 0.17 also required.

### Passkey logins and acr

A passkey login at the token endpoint (`webauthn-login`) proves the amr `pop` from 0.19 (`hwk` before), whether or not user verification took place: `pop` says only that the key was held, never how it is kept (no attestation is asked). That login opens no session and answers no acr. In a browser's login, an acr whose set includes `pop` is met by a passkey login into the session (`login-passkey`, from 0.19), and by the WebAuthn second factor (`mfa-webauthn`), which proves `pop` and `mfa` (`hwk`, or `swk` for a credential that can be backed up, before 0.19); a credential used without user verification meets it too, unless `mfa-webauthn.user-verification = required`.

### Passkeys and the WebAuthn second factor

A user who signs in with a passkey can satisfy the WebAuthn second factor with another credential on the same authenticator, as in 0.17. Where the two factors must be on separate devices, leave `mfa-webauthn` out of the app, and with `login-passkey`, set `login-passkey.counts-as-mfa = false`: otherwise a passkey that verified the user stands for both factors on its own.

### Changing credentials without mfa

Without `mfa`, registering a passkey or linking an upstream account (`?link=1`) needs a sign-in at a known time within `session-lifecycle.recent-authentication`. With `mfa`, its rule decides, counting in the same window.

### Outbound requests

Every host the app fetches from must be named in `outbound.allow` (or `allow-any-public = true`): IdP issuers and endpoints, key set URLs, the users-http ledger and the audit-http collector. Plain http is allowed only to a `host:port` named in `outbound.plain-loopback`, at loopback addresses, or in `outbound.plain-internal`, at private or loopback addresses and for a URL of your own configuration.

A deployment that reached its IdP through a proxy and its ledger at an internal load balancer wrote, in 0.17:

```
NODE_USE_ENV_PROXY=1
HTTPS_PROXY=http://proxy.corp.example:3128
NO_PROXY=.corp.example
```

```hocon
core.outbound.egress = "direct"
repositories.user.http.authenticateUrl = "https://users.corp.example/authenticate"
```

In 0.18 the proxy and the internal destination are settings, and the variables are left unset:

```hocon
outbound {
  allow = ["idp.example.com", "users.corp.example"]
  proxy = "http://proxy.corp.example:3128"
  // proxy-authorization = "Basic …" when the proxy asks for credentials
  direct-hosts = [".corp.example"]
  internal-hosts = ["users.corp.example"]
}
users-http.verify-url = "https://users.corp.example/authenticate" // the same call as authenticateUrl: see users-http
```

The proxy resolves the names it carries and checks their addresses itself, and boot warns so. An internal destination is listed in `direct-hosts` as well as `internal-hosts`, as only a direct request has its addresses checked and let through to a private one.

Where the ledger answers plain http on a network you trust against reading and changing what crosses it, name its `host:port` in `outbound.plain-internal`, keep its host in `allow`, and write the URLs with http. One pair serves every URL at that `host:port`, here the users, the second-factor witness and the signer keys of one ledger:

```hocon
outbound {
  allow = ["users.corp.example"]
  plain-internal = ["users.corp.example:8080"]
}
users-http.verify-url = "http://users.corp.example:8080/authenticate"
mfa-witness-http {
  read-url = "http://users.corp.example:8080/mfa-witness/read"
  enroll-url = "http://users.corp.example:8080/mfa-witness/enroll"
  clear-url = "http://users.corp.example:8080/mfa-witness/clear"
  withdraw-url = "http://users.corp.example:8080/mfa-witness/withdraw"
}
signer-keys-http.keys-url = "http://users.corp.example:8080/signer-keys"
```

Plain http never goes through the proxy. Every address the name resolves to must be private, as `internal-hosts` takes them, or loopback, as for a sidecar on the same host; one public address refuses the request (`plain-public`), and a link-local or metadata address refuses it as any special address. What goes there, users' passwords and the ledger's credential among it, is in the clear, and each boot warns `outbound.plain_internal` with the count of pairs. Prefer https with an internal CA and `internal-hosts` where the ledger can serve it.

An IdP on the same network over plain http is written the same way:

```hocon
outbound {
  allow = ["idp-internal"]
  plain-internal = ["idp-internal:9000"]
}
federation.idps.corp.issuer = "http://idp-internal:9000"
```

The browser goes to the IdP's authorization endpoint at that name too, by its own resolver and outside any mesh: the name must resolve for your users' browsers, and what crosses, the user's password and the IdP's cookies, is in the clear. An IdP whose description puts an endpoint on another origin is set as [From 0.18.0-rc.4](#from-0180-rc4) says, under "An IdP on a private network".

A request outbound refuses is logged with its `reason`:

| `reason` | What it means | What to do |
|---|---|---|
| `not-allowed` | The host is not in `outbound.allow`. | Name it there, or set `allow-any-public`. |
| `scheme` | Plain http to a `host:port` neither `plain-loopback` nor `plain-internal` names. | Name the pair in the list its addresses belong to, or write the URL with https. |
| `plain-public` | A `plain-internal` pair whose name resolved to a public address. | Point the name at the private network, or write the URL with https. Where the network answers the name with an IPv6 address that does not reach as well (ECS Service Connect, say), name the pair in `outbound.plain-ipv4` too. |
| `special-address` | The URL or its name reached a special-purpose address: link-local, metadata, or a private or loopback one no list names. | Name the host in `internal-hosts` (https) or the pair in `plain-internal` (plain http). Link-local and metadata addresses are never reached. |
| `denied` | The host matches `outbound.deny`. | Take it out of `deny`, if it is meant to be reached. |

### Reverse proxy

Behind a TLS-terminating proxy, set `http.trusted-proxies` and `http.proxy-hops`. Only `X-Forwarded-For` and the forwarded scheme are read from a trusted proxy; `Forwarded` is ignored. With an https public origin, browser requests that change state must arrive over https, so a missing proxy setting refuses them.

No setting trusts a proxy by its hop count alone: `http.proxy-hops` only bounds how many trusted proxies a request passes through. List the load balancer's subnet as CIDRs in `http.trusted-proxies`, and let only the load balancer reach the app's port.

Behind a CDN in front of the load balancer, list both: the load balancer's subnet and the ranges the CDN reaches the origin from, and set `http.proxy-hops = 2`:

```hocon
http.trusted-proxies = [
  "10.0.1.0/24",        // the load balancer's subnet
  "203.0.113.0/24",     // the CDN's ranges toward the origin, as the CDN publishes them
  "2001:db8:cd::/48",
]
http.proxy-hops = 2
```

A block of every address of a family (`0.0.0.0/0`, `::/0`, or every IPv4 address mapped into IPv6, as `::ffff:0:0/96`) refuses boot: it would trust every client as a proxy, so no source could be told. To pass a long list per environment, put it in its own file and name that file in `APP_CONFIG`, or `include file("trusted-proxies.conf")` it from the environment's file. An array is replaced from one file to the next, never added to, so the file that wins holds the whole list.

### Redis

The `redis` module checks the server at boot and refuses to start unless:

- it is Redis 7.0 or later, a primary, and not a cluster;
- `maxmemory-policy` is `noeviction` where the composed features need it;
- `appendonly yes` and `appendfsync always` are set where they need durability;
- `redis.replication` is set where they need replication, with `min-replicas-to-write` and `min-replicas-max-lag` of at least 1 for `replicas`;
- `INFO` and `ROLE` are allowed; where `CONFIG GET` is refused, the settings are declared in `redis.server-settings`, and `redis.durability = none` accepts a server that does not fsync every write. See the runbook.

### Several instances

`kernel.deployment = multi` refuses any module that cannot run on several instances, which today means the in-memory store and the logging-only mail sender. Use `redis` and `mail-smtp`.
