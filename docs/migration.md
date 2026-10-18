# Migrating from 0.17 to 0.18

0.18 replaces the 0.17 application with a set of modules assembled by a small generated app. Most endpoints, grants and login flows behave as before, but configuration is rewritten, several settings that 0.17 accepted now refuse boot, and some requests that 0.17 accepted are now refused.

This guide is for operators moving an existing 0.17 deployment. Read it once end to end before you start: there is no in-place upgrade, and stored state does not carry over.

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
- [Operational notes](#operational-notes)

## Before you start

- **0.18 is a breaking release under new package names.** Its packages are published under the same `@o3co/auth-provider-` scope, one per bundle, with new names; the 18 packages of 0.17 are deprecated.
- **Stored state is not migrated, and 0.18 ships no migration tool.** 0.18 reads none of 0.17's records. Users sign in again, and what they set up is lost unless you move it yourself; see [What carries over](#what-carries-over).
- **A drain that runs past its time exits as any other stop does.** 0.17 told it apart by its exit code; 0.18 does not, so a supervisor cannot tell a timed-out drain from a clean one.
- **Client secrets stay hashed.** A client secret is a bcrypt hash, as in 0.17, or an scrypt hash (`$scrypt$ln=,r=,p=$salt$key`); existing bcrypt hashes work as they are. A plain secret refuses boot at `clients.registered.<i>.sections.client-secret.hash`, so hash it with bcrypt first.
- **A user ledger served over HTTP keeps 0.17's password call**, with a few answers read differently (see [users-http](#user-ledger-over-http)).

## Packages

0.18 is published as one package per concern, `@o3co/auth-provider-<concern>`, all at the same version. Each package offers its modules as subpaths named after them: `@o3co/auth-provider-oauth/authorize` (the contract), `/authorize/module` (what an app assembles), `/authorize/testing` (test builders and contract tests; vitest is an optional peer) and, where a module records audit events, `/authorize/audit-events`. You rarely name them yourself: generate the app (`npx @o3co/create-auth-provider@next <dir> …`, or `npm create @o3co/auth-provider@next -- <dir> …`), and it depends on the packages it composes.

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

1. Generate the app with `create-app`, naming the modules you use (for example `@mod/authorize`, `@mod/code-grant`, `@mod/refresh`, `@mod/oidc`). Their default wirings and bridges are added for you, and one log sink (`log-stdout`) unless you name another.
2. Write the app's `application.conf`, in its `config` directory, from your 0.17 settings, section by section, with the [mapping](#configuration-mapping) below. Start from the file `create-app` writes.
3. Move `clients.yaml` entries into `clients.registered` and `users.yaml` entries into `users.registered`, keeping client secrets as their bcrypt hashes.
4. Point the app at an empty Redis (or a new `redis.prefix`) that meets the [requirements](#redis).
5. Start the app. A refused boot exits with status 78 and prints one `refused <where>: <reason>` line per problem on standard error; fix them and start again. Refusals name the setting, never its value.
6. Run your clients against it, paying attention to the [behavior changes](#behavior-changes).

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
| `http.trustProxy` | `http.trusted-proxies` (IPs or CIDRs), `http.proxy-hops` | Named ranges and `true` are gone; list addresses |
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
| `key-store.local.secret` | `keys.signing.secret` | `oidc` needs an asymmetric key |
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
| `*.grants.*.enabled` | compose `authorize` + `code-grant`, `refresh`, `jwt-bearer` | `client_credentials` is part of `token-endpoint` |
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
| `repositories.user.http.*` | `users-http.verify-url`, `credential`, `timeout` | [Some answers read differently](#user-ledger-over-http) |

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
| `mfa.page.url` (the step-up page `/authorize` sends to) | `authorize.step-up-page` | Absolute https URL; without it, a session short of the asked acr gets `unmet_authentication_requirements`. Federation grants have their own `federation-grants.step-up-page` |

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
| `federation-grants.consent.url` | `federation-grants.page` | Absolute https URL; 0.17 also took a path. Required once a connection is configured |
| `session.loginPage.url` (for the connect flow) | `federation-grants.login-page` | Absolute https URL; without it, a browser with no session gets a plain `401` |
| `defaultExpiresIn`, `maxExpiresIn` | `default-lifetime`, `max-lifetime` | Written with its unit; default `30d` each, at most `365d` |
| `refreshBuffer` | `refresh-before` | Default `30s` |
| `rotationBudget`, `rotationWindow` | `rotations`, `rotation-window` | Defaults 24 per `1h`, as before; at most 1000 per `1d` |
| `allowKeepOnSubjectRevocation` | `keep-on-subject-revocation` | Default false |
| `identityLookup` (`required` or `unsupported`) | `identity-check` (`required` or `none`) | `unsupported` is `none` |
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
| `mfa.page.url` (the step-up page connect followed) | `federation-grants.step-up-page` | Absolute https URL; without it, a session short of a requirement gets `403` |
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
| `allowedGrantTypes` holding `session` | `sections.token-endpoint.grants` holding `session` | Always enforced; public clients may use it too |
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

Compose `mfa-email` (with `mfa-email-wording` and a mail sender such as `mail-smtp`) for codes by mail, and `mfa-webauthn` (with `webauthn`) for WebAuthn as a second factor. The relying party keys are in [MFA and passkeys](#mfa-and-passkeys).

For a second factor by mail alone, with no other factor to enrol, set `mfa-email.adds-second-factor = true`: without it, a code by mail does not count as a second factor.

| 0.17 | 0.18 | Notes |
|---|---|---|
| `mfa-email-factor.enabled` | compose `mfa-email` + `mfa-email-wording` | Needs a mail sender, as before |
| `mfa-email-factor.addsMfa` | `mfa-email.adds-second-factor` | Default false |
| `mfa-email-factor.codeTtlSeconds` | `mfa-email.code-lifetime` | Default `10m`; `1m` to `30m` |
| (none) | (no setting) | Codes go to the account's `email` that `users` holds, else to the `email` an outside HTTP ledger gave at login. An `email` from an upstream IdP is never used: a user who signs in only through an IdP cannot bind codes by mail, and the account-email proof is not offered |
| `mfa.enrollment.requireEmailProof` (`when-mail`, `always`, `never`) | `mfa-binding-proof.mode` (`when-available`, `always`, `never`) | Compose `mfa-binding-proof`. `when-mail` is `when-available`. The account-email proof comes with `mfa-email`: without it, no proof is asked |
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
- `redis-refresh-token-family.casRetryLimit`: every store write that loses a race is tried again up to 8 times, within 10 seconds, then answered as unavailable.

### Audit, mail, outbound and metrics

| 0.17 | 0.18 | Notes |
|---|---|---|
| `adapters.auditSink` | `audit.receivers` (names, or `none`) | Required; compose `audit-stdout` or `audit-http` for those receivers |
| `standard-smtp-mail-sender.*` | `mail-smtp.host`, `port`, `security`, `user`, `password`, `from` | `secure` is now `security` |
| (development mail sender) | the `mail` module with `mail.accept-unsent = true` | |
| `core.outbound.allowedHosts` | `outbound.allow`, or `outbound.allow-any-public = true` | An empty list now reaches nothing. Entries as before: a host, or `.name` for the name and the names under it |
| `core.outbound.deniedHosts`, `timeoutMs`, `maxResponseBytes` | `outbound.deny`, `timeout`, `max-response-size` | `deny` takes entries as `allow` does |
| `core.outbound.internalHosts` | `outbound.internal-hosts`; `outbound.plain-loopback` (`host:port`) for plain http at loopback | `internal-hosts` reaches private addresses (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7) for the users-http ledger and the audit-http collector only; a client's URLs (key sets, back-channel logout) never reach a private, loopback or link-local address. `.name` still covers the name and the names under it |
| `core.outbound.egress = direct` | `outbound.direct-despite-proxy = true` | Only while every request goes direct; with a proxy, write `outbound.proxy` instead |
| `HTTPS_PROXY` with `NODE_USE_ENV_PROXY` | `outbound.proxy` (an http origin), `outbound.proxy-authorization` | Every https request goes through it by CONNECT, key sets and back-channel notices included; the variables are never read |
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
| `federation-grants.revocation-skew-seconds` | `federation-grants.revocation-skew` | a duration, `0s` to `5m`, default `1s` |  |
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
- **audit-http**: an `authorization` value with a URL that is not https, or a URL that outbound's policy refuses.
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
| Find a user by subject | none | none: the ledger is never asked, and `users-http` answers every lookup by subject as one it cannot answer |
| Success | any `2xx` with the user | `200` with a JSON object: `id` (the subject) and a non-empty `username`; `email`, `name`, `picture`, `groups` and a boolean `emailVerified` (only beside `email`) are kept as attributes, other fields dropped |
| No such user, or a wrong password | `401` or `403` | `401` or `403`, unless a `credential` was sent and the answer carries a Bearer challenge: that refuses the credential, and reads as unavailable |
| Anything else | | Any other status, `404` and other `2xx` included, or a `200` that is not such an object: the ledger is unavailable, and the login answers `503` |

Upstream links and MFA enrollment are no longer kept by the ledger. An upstream login through a link users keeps needs `subject-url` or `upstream-url`: without either, nothing can say who the link stands for, and that login answers `503`.

A ledger that suspends a user stops new logins and grants by its answers. To end the user's open sessions and issued tokens as well, compose `subject-revocation-http` and have the ledger post the subject to `/ledger/subject-revocations`; see [Revoking a user from the ledger](runbook.md#revoking-a-user-from-the-ledger).

A ledger can also be asked for a user by subject, so a user who signs in upstream has the ledger's attributes, such as the address `mfa-email` mails: set `users-http.subject-url`. It is posted `{"subject"}` the same way; a `200` with an `id` is the user (no `username` asked), `404` and `410` are no such user, and anything else, `401` and `403` included, is unavailable. Likewise `users-http.upstream-url` is posted `{"idp", "subject"}` to look a user up by upstream identity, read the same way; with it, the ledger's answer is the last word, and links users keeps are not read. With a `credential`, every URL must be at one origin. Reading the password call's `401` and `403` as no such user is kept for 0.17's ledgers, and is to go in a later release, after which they read as a lookup's do.

### MFA and federation

- With `mfa.mode = optional`, removing the last second factor also removes the recovery codes.
- After a second factor completes a held login, the answer carries the return target.
- A federated login passes the same login gates as any other, MFA included. See [upstream amr](#upstream-amr).
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

## From 0.18.0-rc.1

- **Sealing keys**: `seal.keys` is refused at boot; write its first key as `seal.current` and the rest as `seal.previous`. Rotating a key now has a procedure, in the [runbook](runbook.md#rotating-the-sealing-key).
- **MFA factor lists written by rc.1** hold no subject, so `reseal` cannot seal their secrets again and counts them as left (exit 2) until the user next proves or changes a factor, which writes the subject. While such lists remain, do not retire a `previous` key that sealed them.
- **Times and sizes**: every time and size key lost its unit suffix and is written with a unit (`30m`, `64KiB`); a number without one refuses boot. The renamed keys are in [Times and sizes](#times-and-sizes), among them `federation-grants.connections.<name>.max-access-token-lifetime`, which was `max-access-token-seconds`.
- **Linked upstream identities**: a written link no longer lets in a subject that the settings' users or the ledger answer none for; that login is refused. Where the ledger cannot look users up by subject (`users-http` without `subject-url` or `upstream-url`), that login is now unavailable (`503`) rather than signing in a user with no attributes: set one of them.
- **Subjects**: a subject is 1 to 255 ASCII characters, as OpenID Connect bounds `sub`. A user in `users.registered` with no `subject` takes its identifier as the subject, so one whose identifier is outside ASCII (`Zoë`) now refuses boot at `users.registered.<i>.subject`; write a `subject` for it. A user ledger that answers a subject outside that bound is now unavailable.
- **JWT bearer issuers**: each of `jwt-bearer.issuers` needs `subject`: `"as-is"` (the assertion's `sub` is the subject, as rc.1 read it) or `"linked"` (the user `users` links to the signer, with `upstream` naming its IdP). An issuer without it refuses boot at `jwt-bearer.issuers.<i>.subject`; write `subject = "as-is"` to keep rc.1's reading.
- **Upstream links in settings**: each `idp` in `users.registered[].upstream` must be a name a composed module declares: a `federation` IdP, a linked `jwt-bearer` issuer's `upstream`, or one `exchange-id-tokens` takes. A link through any other name refuses boot at its `idp`; nothing would ever look it up.
- **JWT bearer assertions spent under rc.1**: they were kept in the `jwt-bearer.jti` space, and this version keeps them through `jwt-bearer-store`, so it does not see them. An assertion spent just before the upgrade could be exchanged again until it ends, at most `jwt-bearer.max-assertion-lifetime` plus `jwt-bearer.clock-skew` (about 1 hour 30 seconds by default). Stop taking the JWT bearer grant for that long before you upgrade, or accept a reuse within that window.
- **MFA under `required`**: boot is refused unless a composed kind both counts and adds a second factor. With `mfa-email` alone, set `mfa-email.adds-second-factor = true`.
- **Managed Redis**: where the server refuses `CONFIG GET`, declare its settings in `redis.server-settings`; where it keeps no append-only file, set `redis.durability = "none"`. See [A managed Redis that refuses `CONFIG`](runbook.md#a-managed-redis-that-refuses-config).
- **users-http**: `verify-url` is now optional, and `subject-url` is new. With a `credential`, every URL must share one origin, or boot is refused.
- **idp-google**: `hosted-domains` is new and optional; nothing to change.
- **Generated apps**: the command is `create-auth-provider`, and a generated README names the audit receivers of the adapters composed; an app already generated needs no change.
- **Configuration files**: a file that does not parse, or a substitution that does not resolve, is refused at its `file:line:col`; nothing to change.
- **Audit events**: `introspect.store_unavailable` is now `introspection.unavailable`, with the same `source`; a receiver that matches the old name needs it. Introspection answered unavailable also logs the warning `token-control.unavailable` with `route: "introspect"`, as revocation does.
- **Managing factors**: the routes `GET /session/mfa/factors`, `POST /session/mfa/factors/rename`, `POST /session/mfa/factors/remove` and `POST /session/mfa/recovery-codes` now come from the `mfa-management` module. An app generated with rc.1 that composes `mfa-flows` must also compose `mfa-management` to keep them; its POSTs are counted per source under `mfa-management.requests` and `window`, apart from `mfa-flows`' routes.
- **Removing a factor or reissuing recovery codes**: both now ask a second factor proven recently. Under `optional`, a session signed in by password that binds its first factor must step up with it before it reissues the codes (rc.1 took the recent sign-in).
- **A first factor bound meanwhile**: a first binding begun while the subject held no counting factor no longer binds when another counting factor was bound before it finished. It writes nothing and records `mfa.first_binding_conflict` (`kind`); a login held for it gets `401 login_required`, a session `409 mfa_enrollment_conflict`. rc.1 bound it beside the other.
- **Federation grants**: `federation-grants.sweep-interval` is new (default `1h`, `1m` to `1d`): each instance erases, that often, the credentials of grants past their end or ended by their subject's revocation, though no request reads them. rc.1 erased them only when a grant was next read.
- **A store adapter of your own**: `put`, `getMany`, `setAdd`, `setMembers` and `setRemove` are gone from the `store` contract, with the helper `getFollowing`; nothing called them, so an adapter no longer offers them. To write whatever a key holds, read it and write on its version with `replaceIf`, or with `putIfAbsent` where it holds none, as `mutate` does.
- **A module of your own that reads cookies**: `Cookies.read` is gone; call `lookup`, which answers the cookie (`found`), none (`absent`), or `withheld` with why (`plain-http` or `duplicate`). A hand-made `Cookies`, as in a test, offers `lookup` and no `read`.
- **Revoking a user from the ledger**: `subject-revocation-http` is new: an outside ledger posts a subject, with a credential from a listed source over https, to end the user's open sessions and tokens here too. Nothing changes until you compose it; see the [runbook](runbook.md#revoking-a-user-from-the-ledger).
- **A refresh the upstream refuses until the user acts there** (`interaction_required`, `login_required`, `consent_required` or `account_selection_required`): `federation-tokens` now answers `403 upstream_interaction_required` and forgets that IdP's tokens, recording `federation.token.failed` with the reason `interaction_required`. `federation-grants` erases the grant's credentials and answers `410 reauthorization_required` (`upstream_interaction_required`). rc.1 read that refusal like any refused refresh: `federation-tokens` answered `500 refresh_failed` (reason `failed`) and kept the tokens, and `federation-grants` handed an access token it still held or answered `502 upstream_rejected`, keeping the credential.

## Operational notes

### Clocks

Every decision about time uses the host's clock, so keep hosts synchronized. Allowances for clock differences are configurable where a peer's clock matters: `client-assertion.clock-skew`, `jwt-bearer.clock-skew` and the IdPs' `clock-skew` (default 30 s), `dpop.proof-window` (default `1m`) and `mtls.revocation.skew` (default `5m`). Records kept in Redis expire by Redis's own clock, with margins for that.

### Upstream links in settings

A link from an upstream identity to a user written in `users.registered[].upstream` wins over one written at runtime for the same upstream identity; the runtime one is hidden and cannot be unlinked. Taking the upstream identity out of the settings lets the earlier runtime link take effect again, so check which user that link names before you remove it. Links match by IdP name and upstream subject only, never by email.

### Upstream amr

A federated login proves `fed` and nothing else, unless the IdP's `upstream-amr` maps the upstream's amr values to local ones. Where MFA is required, federated users then complete a local second factor. Mapping an upstream value to `mfa` trusts that IdP's claim for MFA and for every acr it satisfies; do so only for an IdP whose MFA you trust.

### RP-initiated logout after an upstream login

When the session came from a federated login, logout goes on to the upstream IdP's end-session endpoint and passes the client's registered `post_logout_redirect_uri` to it unchanged. Register that URI as a post-logout redirect at the upstream IdP too, as 0.17 also required.

### Passkey logins and acr

A passkey login proves the amr `hwk`, as in 0.17, whether or not user verification took place; `hwk` says only that the key was held. An acr in `acr.values` whose set includes `hwk` is therefore met by a passkey used without user verification, unless `webauthn.user-verification = required`. The WebAuthn second factor proves `hwk`, or `swk` for a credential that can be backed up, and `mfa`, as in 0.17.

### Passkeys and the WebAuthn second factor

A user who signs in with a passkey can satisfy the WebAuthn second factor with another credential on the same authenticator, as in 0.17. Where the two factors must be on separate devices, leave `mfa-webauthn` out of the app.

### Changing credentials without mfa

Without `mfa`, registering a passkey or linking an upstream account (`?link=1`) needs a sign-in at a known time within `session-lifecycle.recent-authentication`. With `mfa`, its rule decides, counting in the same window.

### Outbound requests

Every host the app fetches from must be named in `outbound.allow` (or `allow-any-public = true`): IdP issuers and endpoints, key set URLs, the users-http ledger and the audit-http collector. Plain http is allowed only to a `host:port` named in `outbound.plain-loopback`, at loopback addresses.

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

### Reverse proxy

Behind a TLS-terminating proxy, set `http.trusted-proxies` and `http.proxy-hops`. Only `X-Forwarded-For` and the forwarded scheme are read from a trusted proxy; `Forwarded` is ignored. With an https public origin, browser requests that change state must arrive over https, so a missing proxy setting refuses them.

No setting trusts a proxy by its hop count alone: `http.proxy-hops` only bounds how many trusted proxies a request passes through. List the load balancer's subnet as CIDRs in `http.trusted-proxies`, and let only the load balancer reach the app's port.

### Redis

The `redis` module checks the server at boot and refuses to start unless:

- it is Redis 7.0 or later, a primary, and not a cluster;
- `maxmemory-policy` is `noeviction` where the composed features need it;
- `appendonly yes` and `appendfsync always` are set where they need durability;
- `redis.replication` is set where they need replication, with `min-replicas-to-write` and `min-replicas-max-lag` of at least 1 for `replicas`;
- `INFO` and `ROLE` are allowed; where `CONFIG GET` is refused, the settings are declared in `redis.server-settings`, and `redis.durability = none` accepts a server that does not fsync every write. See the runbook.

### Several instances

`kernel.deployment = multi` refuses any module that cannot run on several instances, which today means the in-memory store and the logging-only mail sender. Use `redis` and `mail-smtp`.
