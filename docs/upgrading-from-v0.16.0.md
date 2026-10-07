# Upgrading from v0.16.0

This is the one place to start when you upgrade a deployment, a composition
root or an adapter from v0.16.0. It lists every breaking change merged since
v0.16.0, grouped by area, each with what to do and a link to where its
details live. The release's `CHANGELOG.md` section is written when the release
is cut ([release-policy.md](release-policy.md), R2); until then this guide and
the pull requests it cites are the record.

Changes to a surface that did not exist in v0.16.0 — the MFA ports, the
Store's MFA endpoints, session admission, the test kit — are not breaks for
you. Where you implement one of them, its current contract is what this guide
describes.

**Who reads what.**

| You | Read |
| --- | --- |
| Run the standalone template, or a scaffold made by `create-app` | [Your scaffold](#your-scaffold), [Configuration](#configuration), [What clients and operators see](#what-clients-and-operators-see), [Client records](#client-records-the-boundary-in-the-clientrepository-slot), [Rolling out](#rolling-out-across-a-mixed-fleet) |
| Run a composition root of your own | All of the above, and [Compositions and code](#compositions-and-code) |
| Implement a port: a store, a repository, a limiter, a refresher | [Stores and records you implement](#stores-and-records-you-implement) |
| Run the Store behind `@o3co/auth-provider-foundation` | [The Store implementer checklist](#store-implementer-checklist-before-switching-to-required) |
| Want multi-factor authentication | [Turning MFA on](#turning-mfa-on), after everything above |

**The order of work.**

1. Fix the configuration. Every moved or removed key, and every value now
   read strictly, refuses to start and names itself, so a start against a
   staging copy lists what is left. A refusal of a moved, removed or renamed
   key or variable points at this guide.
2. Check the data the provider reads from you: client records, redirect URIs,
   the users your Store answers.
3. Update code that implements a port or calls an API that changed, and run
   the conformance suites.
4. Upgrade the whole fleet onto the new release in one coordinated step:
   stop every v0.16.0 replica, then start the new one
   ([Rolling out](#rolling-out-across-a-mixed-fleet)); a rolling upgrade from
   v0.16.0 is not supported.
5. Only then decide on MFA, with `optional` before `required`.

## Your scaffold

A scaffold owns its `src/` and `config/`: upgrading the packages never
changes them, and never turns MFA on. Taking the new template's `config/`
does: its `reference.conf` defaults the MFA switch to `required` (#1264). The template's composition root changed
throughout this window — its own `logging`, `http`, `cors`, `redis-clients`
and `key-store` modules (#783), the `adapters {}` selections (#853), the
federation grant stores' defaults (#1177), the MFA switch (#1245) and a mail
sender override (#1241) — and core no longer ships the defaults and bindings
an old scaffold relied on (`logging`, `http`, `oauth.jwt.signingKey`,
`refreshTokenFamilyStore.redis`). An old `app.mts` fails `tsc` against the
new core, and its `createAppLogger` throws at run time.

Take the new template's `src/` whole, `src/__tests__/` included, and its
`config/` (`reference.conf`, `application.conf`, `development.conf`), then
re-apply your own edits. The new `src/` imports packages a v0.16.0 scaffold
does not list, whatever `MFA_MODE` says: `@o3co/auth-provider-mfa`,
`@o3co/auth-provider-standard` and `zod`, and its tests import the slots'
contract suites from `@o3co/auth-provider-test-kit`, a dev dependency.
Merge the template's dependency changes into your scaffold's `package.json`,
at their published versions rather than `workspace:*`, and refresh the
lockfile. Then:

- `HTTP_PORT` set to the empty string, or to anything but decimal digits,
  refuses the boot; it used to boot on a random port (#948).
- `ADAPTERS_FEDERATION_GRANT_STORE` and `ADAPTERS_FEDERATION_GRANT_INTENT_STORE`
  default to `none`. With `FEDERATION_GRANTS_ENABLED=true`, set both to
  `redis` (or `memory` on one replica), or the boot is refused naming the
  store (#1177).
- A mail sender of your own goes through `buildModules`'
  `overrides.mailSenderModules`, never into the module list (#1241).
- The new `application.conf` writes no section for a module a default boot
  does not load. If you keep an `application.conf` copied before this change,
  edit it in three places:
  - Replace the whole `federation-grants { … }` block with the single line
    `federation-grants.enabled = ${?FEDERATION_GRANTS_ENABLED}`. The feature
    stays off while the variable is unset, and the federation-grants
    package's `reference.conf` sets the rest of the section, bound to the
    same variables.
  - Delete the `redis-federation-grant-store { encryptionMode … }` block. The
    Redis package's `reference.conf` sets the same `"required"`, bound to the
    same variable.
  - Delete the two `limits.mfa` lines (`core-rate-limiter-memory.limits.mfa`,
    `redis-rate-limiter.limits.mfa`), and take the new `config/reference.conf`
    with them: it is the file that now sets both. Deleting the lines while
    keeping an older `reference.conf` loses the budget: the MFA routes fall
    back to the limiter's `defaultLimit`, 60 per 60 s, five times looser than
    the 60 per 300 s they had.

  Done this way, the values the loaded modules read do not change. A section
  written for a module the composition does not load reaches nothing.
- **BREAKING: federations are handled by their `type`** (#1291). The
  template's federation config bridges (`googleFederationConfigModule`,
  `oidcFederationConfigModule`) and its reading of the federation map before
  boot (`googleEnabled`, `oidcFederationNames` in `buildModules`,
  `core.federations` in `SWITCHES`) are gone. `buildModules` always lists
  `googleFederationTypeModule()` and `oidcFederationTypeModule()`, and core
  hands each enabled `core.federations` entry to the module of its `type`.
  - Every entry needs a `type`. The new `application.conf` writes
    `type = "google"` on `core.federations.google`, and an environment layer
    (`{env}.conf`) merges over it, so a `core.federations.google` written
    there inherits that type. A scaffold that keeps its own
    `application.conf`, or declares an entry of its own, writes the `type`
    on the entry, enabled or not, or the boot is refused at config
    validation (`config-validation-failed` at
    `core.federations.<name>.type`, [below](#values-read-more-strictly)).
  - A fork that composed `googleFederationModule` or
    `oidcFederationModule(name)` beside the new list removes it: both are
    gone from their packages
    ([exports](#exports-removed-and-signatures-changed)), and a module of
    its own that contributes `federations` or `federationRedirectPolicies`
    is refused as `contribution-kind-guarded`
    ([below](#compositions-and-code)). A module of its own that provided a
    bridge's slot (`googleFederationConfig`, `oidcFederationConfigs`) goes
    too: the packages no longer declare those slots, and nothing reads
    them.
  - Code of a fork's own that read `core.federations` from what
    `readSwitches` answers gets nothing there now. Read it at boot, from the
    parsed configuration (a module that requires `config`, as the bridges
    did), or let a federation type module handle the entry, which core
    hands it at boot: the template bundles Google's and OIDC's, and the
    GitHub and Apple packages ship `githubFederationTypeModule()` and
    `appleFederationTypeModule()`.
  - Each entry's keys are now read by its type's strict schema: a key the
    type does not name, or the keys nested under the type's name
    (`google { google { … } }`), refuse the boot at the key's path, where the
    bridges ignored the one and accepted the other. A missing Google
    `clientId`, `clientSecret` or `callbackURL` was refused by the bridge
    too; an empty one, which the bridge handed to the provider, is now
    refused at its path.
  - The Google entry's `endSessionEndpoint`, which the bridge never handed
    to the provider, now takes effect: a scaffold whose own layer still
    carries one sends RP-initiated logout to it, with the session's ID token
    as `id_token_hint`. Remove it unless that is what you want.
  - Every `CORE_FEDERATIONS_*` variable reads as before,
    `CORE_FEDERATIONS_GOOGLE_REQUIRE_AUTHORIZATION_RESPONSE_ISS`'s spellings
    and `CORE_FEDERATIONS_GOOGLE_ACCESS_TYPE`'s two values included.
  - A second Google client is now configuration alone: another entry with
    `type = "google"` ([template README](../templates/standalone/README.md#google-federation)).
- **BREAKING: the template reads only its own keys before it chooses its
  modules** (#728). `readSwitches` reads, from the scaffold's files over the
  template's `config/reference.conf`, the composition root's `adapters` and
  `mfaMode`, the user repository's HTTP settings, and whether federation
  grants are installed — nothing of core's section or of a package's.
  - The `config_key_deprecated` (warn) line for `oauth.accessToken.expiresIn`
    (`OAUTH_ACCESS_TOKEN_EXPIRES_IN`) is no longer logged: the key and the
    variable now refuse the boot instead ([Paths and variables that
    moved](#paths-and-variables-that-moved)). An alert on that line sees
    nothing now.
  - A `federation-grants.enabled` (`FEDERATION_GRANTS_ENABLED`) that does not
    read as a boolean installs the federation-grants modules and is refused at
    boot, `config-validation-failed` naming `federation-grants.enabled`. A
    `core.sessionRequirements` boot's
    schema refuses — `expected` not a list of names, or a key core does not
    declare — is refused the same way at its path, and so is a bad
    access-token lifetime (`OAUTH_ACCESS_TOKEN_DEFAULT_EXPIRES_IN`,
    `OAUTH_ACCESS_TOKEN_MAX_EXPIRES_IN`),
    which the template no longer reads before boot either. With MFA on, a
    written `core.sessionRequirements.secondFactorAuthority` other than `mfa`
    is still refused before boot.
  - What the template refuses of the configuration before boot — reading
    `adapters`, `mfaMode` and `logging`, and building what `resolveForBoot`
    hands boot — is a `BootError` under the reason boot raises for the same
    case, so an alert keyed on that reason sees it. An adapter selection at its old path
    (`rateLimiter.adapter`, …), and `redisFederationGrantStore.keyPrefix`
    where no loaded module reads it, are `config-path-relocated`; an old
    adapter variable (`RATE_LIMITER_ADAPTER`, …) or `FEDERATIONS_*` variable
    is `environment-variable-renamed`; a value the `adapters`, `mfaMode` or
    `logging` schema refuses, and the template's checks across keys — the
    MFA stores in memory outside development, `MFA_MODE` against a file's
    `mfaMode`, `mfa.mode`, the sample-key ring, `mfa.storeTimeoutMs`,
    `core.sessionRequirements.secondFactorAuthority`, the Redis intent
    store's key prefix — are `config-validation-failed`, each issue at its
    key's path; a module of your own named `adapters` or `mfaMode` is
    `module-section-path-invalid`. Some failures to start still carry no
    reason: a `CONFIG_ENV` (or `NODE_ENV`) naming a file outside `config/`
    (a plain `Error`), a missing `config/<env>.conf` or a file HOCON cannot
    parse (the HOCON library's error), and a failure after boot, such as a
    port the listener cannot bind.
  - `buildModules`' `overrides.logger` is removed: it carried only that
    warning. Drop it from your call; `app.mts` passes `{ environment }`.
  - For code of a fork's own: `SWITCHES`, `readSwitches`' second argument
    (`reads`, of type `SwitchesOptions`) and the configuration `Switches`
    carried are gone. `Switches` is `adapters`, `mfaMode`, `storeTransport`
    and `federation-grants.enabled`. A module you add reads its own section
    at boot (`deps.section`); code that read another key from what
    `readSwitches` answers reads it at boot, from the parsed configuration.
    `expectedSessionRequirements` takes the resolved
    `core.sessionRequirements` and the MFA switch, and answers
    `SessionRequirements | undefined` — `undefined` where `resolveForBoot`
    hands the section on as written — and the exported `SessionRequirements`
    type no longer includes `undefined`.
- Install MFA only through `MFA_MODE`
  ([Turning MFA on](#turning-mfa-on)).
- **MFA is on by default** in the new `config/reference.conf`
  (`mfaMode = "required"`): every password login needs a second factor, and
  outside development the boot is refused until MFA is configured. To keep
  v0.16.0's behaviour while you upgrade, set `MFA_MODE=off` in every
  replica's environment before the new configuration reaches it — or append
  `mfaMode = "off"`, then `mfaMode = ${?MFA_MODE}`, to the end of your
  `config/application.conf`, as `create-app --no-mfa` writes it, so that
  `MFA_MODE` still turns it on later. Keep it off until the whole fleet runs
  this release ([Rolling out](#rolling-out-across-a-mixed-fleet)), then turn
  it on as [Turning MFA on](#turning-mfa-on) says.
- **The template composes core's session lifecycle** (`sessionLifecycleModule`,
  over the session stores' `sessionLifecycleStore`). A login opens its
  session's record, a code exchange joins its relying party and family to
  it, and both `POST /session/logout` and `POST /oauth/logout` close the
  session through it. So `/session/logout` now revokes the session's
  refresh-token families and tells its relying parties, as `/oauth/logout`
  does, and answers `503 temporarily_unavailable` when the close cannot
  commit, keeping the cookie for a retry. It now waits on the relying
  parties' back-channel notices, each bounded by the notifier's timeout; a
  notice that fails still answers `200`, audited `logout.close_pending`, and
  the close is resumed later by a later close or the lifecycle's sweep,
  every 60 seconds (`core.sessionLifecycle.sweepIntervalSeconds`; `0` turns
  it off; see the runbook's
  [`session_lifecycle_sweep_*` row](operator-runbook.md#page--a-dependency-is-down-or-a-guarantee-is-not-being-met)).

## Configuration

### Paths and variables that moved

Every setting now lives under the name of the module that owns it (#728).
An old path refuses the boot, naming the new one and the variable bound to
it, while the module that owns it is loaded. A renamed variable refuses the
boot while its old name is set, alone or beside its new name, even at the
same value: set the new name and unset the old one. Sections are strict: a
key a module's section does not declare refuses the boot, naming its path,
where it used to be dropped — [Values read more strictly](#values-read-more-strictly) lists the
sections that still accept one.

| What moved | Where it is listed |
| --- | --- |
| Core's own settings under `core {}` (`deployment.mode` → `core.deployment.mode`, `DEPLOYMENT_MODE` → `CORE_DEPLOYMENT_MODE`; `sessionRequirements` → `core.sessionRequirements`), the JWKS settings under `jwks {}` (`JWKS_PATH`, `JWKS_CACHE_MAX_AGE`); an unknown key under `core` is refused (#796) | the [core README](../packages/core/README.md#configuration) |
| `dpop {}`, `mtls {}`, `device-grant {}` and `oauth-token-exchange {}` at the top level, camelCase; `OAUTH_DPOP_NONCE_*` → `DPOP_NONCE_*` (#804) | each package's README |
| Each in-process and Redis store's settings, and `federationGrants` → `federation-grants {}`, under their modules' names, with eight renamed variables (`RATE_LIMIT_FAIL_MODE` → `REDIS_RATE_LIMITER_FAIL_MODE` among them) (#811) | the [redis README](../packages/redis/README.md), the [federation-grants README](../packages/federation-grants/README.md) |
| The oauth and session settings: the grant switches, `oauth-session`, `session-store {}`, the login and consent pages, `OAUTH_CIMD_*` → `OAUTH_CLIENT_ID_METADATA_DOCUMENTS_*`; the PKCE key retired (#827) | [operator runbook §7](operator-runbook.md#before-you-upgrade), step 5 |
| The access-token default: `oauth.accessToken.expiresIn` → `oauth.accessToken.defaultExpiresIn`, `OAUTH_ACCESS_TOKEN_EXPIRES_IN` → `OAUTH_ACCESS_TOKEN_DEFAULT_EXPIRES_IN`. Move the value, do not delete it: without it the default is `3600`, which a deployment that set a shorter lifetime would not notice | [operator runbook §7](operator-runbook.md#before-you-upgrade), step 2 |
| The template's own settings, the adapter selections (`adapters.<slot>`), the repositories, `audit-sink`, `core.federations`, `key-store`, `redis-clients`, `LOG_LEVEL` → `LOGGING_LEVEL` (#853) | [operator runbook §7](operator-runbook.md#before-you-upgrade), step 6 |
| Module names are kebab-case, as their sections are (#738): boot error details and anything that finds a module by name see the new names | — |

Two changes in that table go beyond a rename. **The grant switches read the
boolean vocabulary every other switch reads**: a grant set to `"TRUE"`, `"1"`
or `" true "`, which used to leave it off, now turns it on (runbook §7,
step 5). And **unset `CLIENT_CODE_ENDPOINT_URI` and `CLIENT_CODE_PASSWORD`
first**: both were removed, and set at all they refuse the boot, even beside
the new names (step 6).

**A section is validated only by its own module** (#728). Core's schema
validates core's sections, `core` and `oauth`, and nothing else. A module's
section — `webauthn`, `federation-grants` (its `enabled` included),
`session-store`, a store's section — is checked by that module's schema
while the module is loaded. Without the module nothing reads or checks it: a
value that used to refuse the boot there (`webauthn.userVerification =
"optional"`, `federation-grants.enabled = "sometimes"`) now boots, kept as
written. An old path no loaded module relocates is kept the same way.

The only signal for a section nothing reads is one line at `warn`, naming
the sections and never a value, and only to the logger the composition
bootstraps beside the configuration (`bootstrapComponents.logger`): without
one, such a section boots silently. The line is `config_sections_ignored`, or
`config_sections_not_loaded` where the composition hands boot
`configDefaults` that hold the section and the configuration changed it; a
section left equal to those defaults is not named. After the upgrade, treat
either line naming a section you set as a setting nothing applies.

**A written `cors` refuses the boot.** Core reads no `cors`: a
composition's CORS origins come from the `httpSettings` slot, so move them
to where the module that provides it reads them (in the standalone template,
`http.cors.allowedOrigins`, `HTTP_CORS_ALLOWED_ORIGINS`). A loaded module
that relocates `cors` refuses it naming its new path
(`config-path-relocated`), as the standalone template's `http` does; without
one, core refuses a `cors` that sets anything (`config-validation-failed`),
naming `cors` and the slot and never a value, whether or not a logger is
bootstrapped — unless a loaded module's own section is `cors`, which reads
it. An empty `cors {}` sets nothing and boots.

### Keys removed

The table in [operator runbook §7](operator-runbook.md#before-you-upgrade),
step 2, lists every retired key and what you see. New since v0.16.0:

- `webauthn.allowCredentialsForKnownUser` and
  `WEBAUTHN_ALLOW_CREDENTIALS_FOR_KNOWN_USER`, at any value, refuse the boot
  wherever `webauthnModule` is installed (#1217). Every passkey assertion must
  carry the user handle the authenticator returned, so users on
  non-discoverable (non-resident) keys can no longer sign in through the
  passkey grant: re-enroll them with discoverable credentials.
  `POST /oauth/webauthn/authentication/options` no longer reads `userId`.
- `webauthn.rateLimit.authenticationOptions`, and its variables
  `WEBAUTHN_RATE_LIMIT_AUTHENTICATION_OPTIONS_LIMIT`,
  `WEBAUTHN_RATE_LIMIT_AUTHENTICATION_OPTIONS_WINDOW_SECONDS` and their older
  names `WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT` and
  `WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_WINDOW_SECONDS`, at any value, refuse
  the boot wherever `webauthnModule` is installed. The authentication options
  route is guarded by the deployment's `rateLimiter` alone, with no
  per-process fallback: wire a limiter and set the route's limit as
  `limits.webauthn-authentication-options` in its section
  (`core-rate-limiter-memory` or `redis-rate-limiter`), else its
  `defaultLimit` applies. Without a limiter the route is not throttled. The
  effective limit changes: a deployment that never set the key moves from 30
  per 60 s to the limiter's `defaultLimit`, 60 per 60 s in both bundled
  `reference.conf` files. To keep the old bound, set
  `limits.webauthn-authentication-options { limit = 30, windowSeconds = 60 }`
  in the limiter's section. In code, `AppConfig["webauthn"]` is `unknown`:
  core declares no part of the section (`AppConfig` below).
- `oauth.grants.authorization_code.pkce.*` and
  `OAUTH_GRANTS_AUTHORIZATION_CODE_PKCE_REQUIRE_S256` refuse the boot; S256
  is mandatory regardless (#827).
- `oauth.refreshToken.legacyRtPolicy`, at any value, refuses the boot
  wherever `oauthEndpointsModule` is installed (#728): a refresh token
  lacking `jti` or `family_id` while family rotation is wired is always
  refused. Delete the key.
- `oauth.refreshToken.legacyTokenCompat` and
  `oauth.authorize.allowUnmarkedClients` still refuse the boot, now wherever
  `oauthEndpointsModule` is installed, as `config-path-relocated`
  (`<key> was removed; see the upgrade guide (docs/upgrading-from-v0.16.0.md).
  Remove this field …`) instead of
  `config-validation-failed` naming the release that removed the key. An
  exported `OAUTH_AUTHORIZE_ALLOW_UNMARKED_CLIENTS` — any value, the empty
  string included — refuses it as `environment-variable-renamed`
  (`OAUTH_AUTHORIZE_ALLOW_UNMARKED_CLIENTS sets
  oauth.authorize.allowUnmarkedClients, which was removed`), captured by the
  oauth package's `reference.conf`, no longer by core's (#1500). Delete the
  key and unset the variable. For `allowUnmarkedClients`, first mark
  `firstParty: true` every client you operate that you would trust to
  receive a user's identity without the user being asked: `/authorize`
  refuses every other client. Without `oauthEndpointsModule` core refuses every key written under
  `oauth {}` but the few it reads (`oauth.jwt.issuer`, the access- and
  refresh-token lifetimes, `oauth.revocation.*`), these included, as
  `config-validation-failed` naming each path and the module.
- `oauth.jwt`'s flat key fields (`algorithm`, `kid`, `secret`, `privateKey`,
  `privateKeyPath`, `publicKey`, `publicKeyPath`, `previousKeys`,
  `previousSecrets`) are refused by the oauth module's strict section as
  `config-validation-failed`, `oauth.jwt: Unrecognized key: "<field>"`,
  instead of core's message pointing at `key-store.local` (#1500), and
  without `oauthEndpointsModule` by core, naming the module. Move each field to
  the key store's section, `key-store.local`, as before.
- `repositories.code.type` (`CLIENT_CODE_TYPE`) is refused; use
  `ADAPTERS_CODE_REPOSITORY` (#853).
- **BREAKING: the refresh grant's `unknownFamilyPolicy` is removed.**
  `oauth-authorization.grants.refreshToken.unknownFamilyPolicy`, and its
  v0.16.0 path `oauth.refreshToken.unknownFamilyPolicy`, at any value
  (`"reject"` included), refuse the boot wherever
  `oauthAuthorizationGrantsModule` is installed (`config-path-relocated`,
  `… was removed`), and so do
  `OAUTH_AUTHORIZATION_GRANTS_REFRESH_TOKEN_UNKNOWN_FAMILY_POLICY` and
  `OAUTH_REFRESH_TOKEN_UNKNOWN_FAMILY_POLICY`, exported at any value
  (`environment-variable-renamed`). A refresh token whose family no record
  holds is always refused (`400 invalid_grant`, `unknown_family`, logged as
  `unknown_family_rejected`); `unknown_family_accepted_legacy_mode` is no
  longer logged. **What to do:** delete the line and unset the variables. A
  deployment that ran `"accept"` signs out the holders of family-less chains
  at the upgrade. Refresh tokens bound to a v0.16.0 session are refused at
  admission anyway ([every user signs in again](#passkeys-users-and-sessions)),
  so what `"accept"` still redeemed was a chain without a `sid` from a
  deployment that ran without a family store. See the
  [oauth README](../packages/oauth/README.md#refresh_token).
- **BREAKING: `oauth.jwt.legacyTypAccept` is removed** (#767). The key, at
  any value (`false` included), refuses the boot wherever
  `oauthEndpointsModule` is installed (`config-path-relocated`,
  `oauth.jwt.legacyTypAccept was removed`), and so does
  `OAUTH_JWT_LEGACY_TYP_ACCEPT`, exported at any value, the empty string
  included (`environment-variable-renamed`,
  `OAUTH_JWT_LEGACY_TYP_ACCEPT sets oauth.jwt.legacyTypAccept, which was
  removed`). A token with no `typ` header is refused on every route that
  verifies a token this provider signed, as v0.16.0 already did with the key
  unset: a refresh token is `400 invalid_grant` (`invalid refresh_token`), an
  access token `401 invalid_token` at `/oauth/userinfo` and the federation
  routes, `active: false` at `/oauth/introspect`, and a subject token is
  refused by token exchange. `jwt_verify_legacy_typ` is no longer logged.
  The tokens it admitted were the typ-less ones minted by releases before
  v0.5.0, which stamped no `typ` header. **What to do:** delete the line and
  unset the variable; there is nothing to set in their place. A deployment
  that ran with the key on signs out the holders of such tokens at the
  upgrade: they obtain new tokens, which carry `typ`, by signing in again.
  In code, `JwtVerifyOptions` and `OAuthTokenSettings` lose
  `legacyTypAccept` ([Exports removed, and signatures changed](#exports-removed-and-signatures-changed)).
- `device-grant.store` (and `oauth.deviceAuthorization.store`), at any value,
  refuses the boot wherever `deviceAuthorizationGrantModule` is installed,
  the grant on or off (#728). Delete the line. An enabled device grant needs
  a `deviceCodeStore` component (`memoryDeviceCodeStoreModule` on one
  replica, `redisDeviceCodeStoreModule` otherwise); a disabled one needs
  nothing.
- `mfa.rateLimit.routes` is removed, and any key under `mfa.rateLimit`
  refuses the boot wherever `mfaModule` is installed (#807). The MFA routes
  are limited by your `rateLimiter` alone, under the prefix `mfa`: configure
  `limits.mfa` on it instead (`redis-rate-limiter.limits.mfa` or
  `core-rate-limiter-memory.limits.mfa`), or its `defaultLimit` (60 per 60 s
  on the bundled limiters) applies. The standalone template's
  `config/reference.conf` sets `limits.mfa { limit = 60, windowSeconds = 300 }`
  on both limiters, the old budget, so a scaffold keeps it; a composition of
  your own sets it on its limiter to keep it. Without a `rateLimiter` —
  declared in `core.declaredAbsent` — the MFA routes are no longer limited
  by a per-process fallback, and no longer refuse the boot under
  `core.deployment.mode = "multi"`: they pass every request through, as the
  OAuth endpoints do. Declaring the limiter absent is a choice with costs: an
  MFA email challenge, or an account-email proof resent, is then bounded only
  by the mail sender's own limit, and `@o3co/auth-provider-standard`'s SMTP
  sender has none — wire a limiter, or a sender with a limit of its own; and
  with the in-process MFA transaction store, one signed-in account can fill
  the store's cap (`maxEntries`) by beginning enrollments, after which new
  MFA transactions are refused until entries expire. The MFA lock (attempts
  per transaction, backoff, weekly failures) is unchanged.

### Values read more strictly

- **Numbers in decimal digits (#956).** The number settings of the packages
  below read only a number, or a whole number written in decimal digits. `"0x10"`,
  `"1e3"`, `"5.0"`, `"+5"` and `true`, which `z.coerce.number()` used to read
  as numbers, refuse the boot naming the key; so do `""` and blank strings
  where they used to read as `0` (`mtls.fullPki.revocation.cacheTtlSeconds`,
  the Client ID Metadata Documents' cache settings: write `0` to disable).
  This covers core (#1184), dpop (#1191), oauth-token-exchange (#1192), mtls
  (#1193), the Client ID Metadata Documents (#1194), session and
  session-store (#1195), webauthn (#1196), device-grant (#1197), the Redis
  modules (#1199), the Store transport's `timeout` and `maxResponseBytes`
  (#1200) and the template (#1201). Most refusals at these keys carry one
  message, `must be a whole number … in decimal digits`. The exceptions refuse
  in words of their own: `http.port` with the template's own text, and the
  Store transport's `timeout` and `maxResponseBytes` with the transport's
  constructor errors. Match an alert on the key the refusal names, not on its message. Core's exported `configuredNumber`
  answers `undefined` for those strings, so a rate-limit budget given as one
  is no budget, or a `RangeError` naming the key (#1208).
- **An issuer ending in a slash.** `oauth.jwt.issuer` with a trailing slash
  refuses the boot (#1150). Set it without the slash. Tokens then carry the
  slashless `iss`, which is what discovery already advertised.
- **Unknown keys.** A key under `oauth.clientIdMetadataDocuments` that the
  oauth package's `reference.conf` does not list refuses the boot (#1151).
- **BREAKING: an `oauth.authorize.acrValues` key is one value an
  `acr_values` request can name (#728).** `/authorize` reads `acr_values` as
  space-delimited RFC 6749 §3.3 scope-tokens, so a key is one or more
  printable ASCII characters other than the space, `"` and `\`. A key with
  any other character — whitespace, a quote, a backslash, a non-ASCII
  letter — was advertised in `acr_values_supported` and could never be
  requested; it now refuses the boot (`config-validation-failed` at
  `oauth.authorize.acrValues.<key>`), naming the key, every such key in one
  boot. Rename the entry to a value a client can send, such as a URN
  (`urn:example:acr:mfa`), and tell the relying parties that asked for it.
  Core's schema and the oauth module's (`oauthSectionSchema`) refuse the
  same keys with the same message, so a section parsed with either alone —
  a composition root's own check, a test — is refused as boot refuses it.
- **BREAKING: an empty `oauth.consentPage.url` refuses the boot (#728).** An
  `ENDPOINTS_CONSENT_URL` (now `OAUTH_CONSENT_PAGE_URL`) exported empty
  (`ENDPOINTS_CONSENT_URL=` in a `.env`, a compose file or a ConfigMap) used
  to boot, and every client that
  is not first-party was then redirected to `?challenge=<id>` relative to
  `/oauth/authorize` — a page that is not there. The old name is first
  refused as renamed (`environment-variable-renamed`); renamed to
  `OAUTH_CONSENT_PAGE_URL` and still exported empty or blank, it now refuses
  the boot (`config-validation-failed` at `oauth.consentPage.url`), as an
  empty `session.loginPage.url` already did. Unset the variable to keep the
  default, `/consent`, or set it to your consent page.
- **BREAKING: `oauth {}` refuses a key it does not declare, at every level
  (#728).** Wherever the oauth module is installed (the standalone template
  installs it), a key under `oauth` that its schema does not declare — a
  typo such as `oauth.nonce.maxLenght`, or a key a deployment kept that
  nothing reads — refuses the boot (`config-validation-failed`), naming its
  path. It used to be dropped unread. A path another section moved from
  (`oauth.grants`, `oauth.dpop`, `oauth.mtls`, `oauth.deviceAuthorization`,
  `oauth.tokenExchange`, `oauth.code`, `oauth.tokenBinding`,
  `oauth.jwt.signingKey`) may stay as an empty object or `null`; a key set under it is
  refused, naming its new path while the module it moved to is loaded, and
  as a key `oauth` does not declare otherwise. The keys, their defaults and
  their variables are unchanged; they are listed in the
  [oauth README](../packages/oauth/README.md#configuration).
  A key named after an `Object.prototype` member (`__proto__`,
  `constructor`, `toString`, …), at any depth, refuses the boot naming its
  path (#1216).
- **BREAKING: a key a module's section does not declare refuses the boot
  (#1325).** From this release, a key inside a module's own section that the
  module does not read — a typo, or a key an older version read — refuses the
  boot (`config-validation-failed`), naming the section or block that holds it
  and the key, where it used to be ignored. Before you upgrade, check every
  key you set against the module's README, and correct or delete the ones it
  does not list. `session-store.storage` holds `type` and the `redis` block
  alone, so a block for another storage type (`memory {}`, say) is refused —
  delete it (#1339). `mfa`, at every level, and `mfa-totp-factor` refuse one
  too (#1329): an empty `mfa.factors` block an older configuration leaves
  behind (the TOTP factor's old path, its variables unset) is such a key —
  delete it. So do `webauthn`, at every level (#1336), `session`, at every
  level (#728), and `federation-grants`, at every level: the keys under
  `federation-grants.connections` are the connections you name, and a
  connection's `authorizationParams` the upstream's parameters, so those stay
  open. So do `oauth-session` and `oauth-authorization`, the latter at every
  level: `grants` holds the four grants' blocks alone, and each block
  `enabled` alone (#728). The keys under `audit-sink` are the
  names of the sinks you register, and each sink's options are its own, so
  those stay open.
- **The session cookie.** A `SESSION_STORE_NAME` that is not an RFC 6265 token
  or is empty, a `__Secure-` or `__Host-` name (in any case) without what the
  prefix requires, and a `SESSION_STORE_DOMAIN` that is not a host name refuse
  the boot at config validation (#785). Before, browsers dropped the cookie.
- **The session requirements.** A composition that installs `oauthEndpointsModule`,
  `sessionModule`, `deviceAuthorizationGrantModule` or `federationGrantsModule` declares
  `core.sessionRequirements.expected` — `[]` until a requirement is installed
  — or the boot is refused (`session-requirements-undeclared`) (#715, #772,
  #796). The template's `application.conf` writes it; a deployment that
  replaced that file writes it itself.
  `core.sessionRequirements.secondFactorAuthority` is new and optional: once
  set, the boot is refused (`second-factor-authority-not-declared`) unless
  the requirement it names is expected, registered and declares the
  second-factor authority (#1249).

- **BREAKING: every federation names its `type`, and only its type's module
  handles it (#1309).** Every `core.federations` entry sets `type`, enabled
  or not: one without, or with an empty or blank one, refuses the boot at config
  validation (`config-validation-failed` at `core.federations.<name>.type`).
  Only the module registering that type under `federationTypes` handles an
  enabled entry; no module contributes a federation by its name any more
  (`contribution-kind-guarded`, [below](#compositions-and-code)). Write the
  `type` of the module that handles each entry — `"google"`,
  `"github"`, `"apple"`, `"oidc"`, or your own module's — and install that
  module.
- **An enabled federation nothing handles.** An enabled
  `core.federations.<name>` whose `type` no installed module registers under
  `federationTypes` refuses the boot (`federation-type-unhandled`), naming
  every such entry (#1273). It used to boot, and the federation's routes
  answered `404`. Install the module that handles it, correct its `type`, or
  set `enabled = false`.
- **BREAKING: two enabled federations cannot share a `callbackURL`.** Two
  enabled `core.federations` entries with the same `callbackURL` refuse the
  boot (`config-validation-failed` at `core.federations.<name>.callbackURL`).
  Only one of them could complete a login. Give each its own.
- **BREAKING: a composition with no rate limiter says so (#807).** When no
  module provides `rateLimiter` and an installed module reads it, the boot is
  refused (`component-absence-undeclared`, naming `rateLimiter`) unless
  `core.declaredAbsent` lists it: `core.declaredAbsent = ["rateLimiter"]`,
  beside `"auditSink"` if you list that. Declared absent, a route that keys
  the limiter lets every request through — no module falls back to a
  per-process limiter — so request-volume limits are then for what sits in
  front of the provider. The template wires a limiter
  (`adapters.rateLimiter`), so a scaffold needs nothing.
- **Federation grants no longer require a rate limiter (#807).** With
  `federation-grants.enabled = true` and no `rateLimiter` wired, the module
  no longer refuses the boot itself; its client routes and browser pages let
  every request through, and core's policy for the slot applies instead: list
  `"rateLimiter"` in `core.declaredAbsent`. With a limiter wired, both are
  throttled as before.
- **BREAKING: a first-time federation-grant lodging is also limited per client
  (#628).** After client authentication, `POST /oauth/federation-grants` asks
  the limiter again under `federation_grants:client:<client_id>`. One client
  lodging for many subjects, behind several egress IPs for example, is now
  capped at `limits.federation_grants` (else `defaultLimit`) across all of its
  addresses, and refused `429 rate_limited` / `provider` beyond it. The
  bundled limiters apply that one `limits.federation_grants` to the IP keys
  and the client keys alike; raise it if such a client lodges faster.
- **BREAKING: a limiter's `limits.login` and `limits.device_verification` are
  refused (#807).** `core-rate-limiter-memory.limits` and
  `redis-rate-limiter.limits` may not name either prefix while its owner, the
  session or the device-grant module, is loaded: each declares its prefix a
  verifier's own attempt limit, which no limiter module's configuration may
  loosen. Core names neither prefix itself. A limiter built with
  `registerBuiltinRateLimiters` or `redisRateLimiterBuilder` keeps the
  `limits` it is given.
  The boot is refused (`config-validation-failed`, naming the key and the
  setting). Move the numbers to the module's own setting:
  `session.rateLimit.login` for login, `device-grant.rateLimit` for device
  verification.
- **BREAKING: the login's limit is its own, counted on an attempt counter
  (#807).** `POST /session/login` is limited by `session.rateLimit.login`
  alone, counted per client IP on the `attemptCounter` slot; no rate limiter
  takes part. The setting keeps its name, shape and default (20 per
  900000 ms); `windowMs` above a day (86400000) now refuses the boot
  (`config-validation-failed` at `session.rateLimit.login.windowMs`), and a
  window that is not whole seconds is read rounded up. A limiter's
  `limits.login` no longer applies: set `session.rateLimit.login`. The
  session module claims the `login` prefix with no budget, so the limiter
  answers its `defaultLimit` if anything else keys it.
- **BREAKING: device verification's limit is its own, counted on an attempt
  counter (#807).** `POST /oauth/device/verification` is limited by
  `device-grant.rateLimit` alone, counted per signed-in subject on the
  `attemptCounter` slot; no rate limiter takes part. The setting keeps its
  name, shape and default (5 per 300 s); `windowSeconds` above a day (86400)
  now refuses the boot (`config-validation-failed` at
  `device-grant.rateLimit.windowSeconds`). A limiter's
  `limits.device_verification` no longer applies. An enabled grant no longer
  requires a `rateLimiter`: without one `/oauth/device_authorization` lets
  every request through, and `core.declaredAbsent` lists `"rateLimiter"`.
- **BREAKING: more than one replica needs a shared attempt counter (#807).**
  With no `attemptCounter` wired the login, and an enabled device grant's
  verification, count their attempts per process:
  `core.deployment.mode = "multi"` refuses the boot
  (`contribute-factory-failed`, its cause naming `attemptCounter` and
  `"login"` or `"device_verification"`), an unset mode warns
  `attempt_counter_not_shared`, `single` is silent. A shared limiter no
  longer covers either. In the standalone
  template set `adapters.attemptCounter = "redis"`
  (`ADAPTERS_ATTEMPT_COUNTER=redis`; a new selection, `memory` by default);
  a composition of your own installs `redisAttemptCounterModule` from
  `@o3co/auth-provider-redis`, whose client the template's `redis-clients`
  module provides as `attemptCounterClient`. Its Redis must run
  `maxmemory-policy noeviction` (the default), which the module holds it to
  as the next entry says.
- **BREAKING: the Redis stores that keep durable keys refuse to boot unless
  the server's `maxmemory-policy` is `noeviction` (#1541).** The attempt counter,
  the session lifecycle store, the federation token store and the two MFA
  stores are built only once the server reports `noeviction` (`INFO memory`,
  then `CONFIG GET maxmemory-policy`). Any other policy refuses the boot —
  `volatile-*` included, which the MFA stores used to accept with a warning,
  and a policy the check does not know, which the session lifecycle,
  federation token and MFA stores used to accept with a log line. So does a
  policy the server will not report (`INFO` and `CONFIG` refused or renamed
  for the connection's user), which every one of them used to accept with a
  log line, and a server that cannot answer at boot, which the session
  lifecycle and federation token stores used to accept. The refusal is a
  `provides-factory-failed` whose `cause` is a `RedisStoreEvictableError`
  (`reason` `<store>-evictable`, `maxmemoryPolicy`, `undefined` when unread).
  Set `maxmemory-policy noeviction`, or give these stores a Redis of their
  own. Where the server runs `noeviction` but will not say, assert it:
  `makeIoredisClients(io, { assumeNoEviction: true })` (or the same option
  on `makeIoredisMfaFactorStoreClient` / `makeIoredisMfaTransactionStoreClient`;
  in the standalone template, `REDIS_CLIENTS_ASSUME_NO_EVICTION=true`,
  `redis-clients.assumeNoEviction`). A policy the
  server does report always overrides the assertion. The log lines
  `attempt_counter_durability_unchecked`,
  `session_lifecycle_store_eviction_unchecked`,
  `federation_token_store_eviction_unchecked`,
  `mfa_factor_store_tombstone_evictable` and
  `mfa_transaction_store_lock_evictable` are gone; the MFA stores'
  `…_durability_unchecked` now names only the persistence it could not read
  (`appendonly`, `save`).
- **BREAKING: the Redis federation stores read the environment's name
  trimmed and in lower case (#826).** The plaintext guard of
  `redis-federation-token-store` and `redis-federation-grant-store` matched
  `production` and `staging` only as written, so `NODE_ENV=Production`, an
  environment name passed as `"STAGING"`, or one carrying whitespace
  (`"production\n"`) let `allow-plaintext` boot with a
  `federation_store_plaintext` warning. Such a name now refuses the boot
  (`[<store>] mode "allow-plaintext" is refused because the environment is
  "production"`, as a `provides-factory-failed` cause), and with
  `FEDERATION_TOKENS_ALLOW_INSECURE=1` logs
  `federation_store_plaintext_override` at error. The refusal and the log
  name the environment as read — `"production"` for `Production` — and the
  passed environment is read before `NODE_ENV`, so a passed `" Production "`
  is reported over a `NODE_ENV` of `staging`. This is the reading the MFA
  sample key's refusal and the standard package's development mail sender
  already used. Set `mode = "required"` with a key, or name the environment
  what it is.

The boot refusals you can meet, with their messages, are in
[operator runbook §1](operator-runbook.md#boot-refusals-you-will-meet).

## What clients and operators see

### `/authorize`, discovery and tokens

- **`response_mode`.** A request with a `response_mode` other than `query`,
  or one that repeats it, gets an `invalid_request` error redirect (#1214).
  Discovery advertises `response_modes_supported: ["query"]` (#1151).
- **`acr` and `claims`.** An `oauth.authorize.acrValues` entry nothing
  installed can satisfy is dropped from discovery and answered
  `unmet_authentication_requirements`, with one `acr_value_unsatisfiable`
  line at boot. A `claims` parameter that names `acr`, is not a JSON object,
  or is repeated is `invalid_request`; an empty `max_age=` is read as omitted
  (#706).
- **A federated session's `amr` is `["fed"]`.** An upstream IdP's `amr` is
  kept as `authentication.upstreamAmr` and no longer reaches a token or meets
  an `acr`, unless the federation sets `trustUpstreamAmr = true` (#707).
  Decide it per federation before you upgrade: [operator runbook §7](operator-runbook.md#before-you-upgrade),
  step 3, has what codes and refresh tokens issued before the upgrade keep,
  and the remedy.
- **A federated login's freshness is the upstream's (#1084).** `prompt=login`,
  `max_age` and the MFA module's first binding (a recent primary) now judge a
  federated session by the earlier of when this provider established it and
  when the upstream IdP last authenticated the user (the verified id_token's
  `auth_time`). Before, the callback alone counted as a fresh login, so an
  upstream single sign-on met `prompt=login` without the user signing in
  again. What changes:
  - Your login page should forward the `prompt` and `max_age` it finds in
    `redirect_to` to the federation start (its hints are under "Passkeys,
    users and sessions" below), so the upstream is asked to re-authenticate.
    The OIDC adapter forwards both. The Google, Apple and GitHub adapters
    forward neither, because their upstreams do not document them.
  - A federation whose upstream reports no `auth_time` meets no
    `prompt=login` or `max_age` (`login_required`), and its users never bind
    a first factor (they are sent to log in again each time), while the new
    core-owned key `core.federations.<name>.callbackMeetsFreshness` is
    `false`, the default. GitHub never reports one. Google reports one only
    when it is requested and enabled for the client, which the adapter does
    not do. Apple and a generic OIDC IdP report one when their id_token
    carries it.
  - **Set `core.federations.<name>.callbackMeetsFreshness = true`** for each
    such federation, Google included, if you need `prompt=login`, `max_age`
    or an MFA first binding through it. The callback then counts as the
    authentication, which is the behaviour before this release. The switch
    is read when the session is written, so sessions already live keep what
    they recorded.
  - `auth_time` in the id_token and access token is still when this provider
    established the session. Revocation still reads that too.
  - A custom `UserSessionStore` round-trips the new optional
    `authentication.upstreamAuthTime` (a `Date`, `null`, or absent;
    [upgrading-required-record-keys.md](upgrading-required-record-keys.md)).
    One that drops it reads as fresh as `authTime`. One that turns `null`
    into absent reads such a session as fresh.
- **`/authorize` exists only with the `authorization_code` grant.** Without
  it, `/oauth/authorize` and `/oauth/consent` answer `404` and discovery names
  no authorization endpoint (#775).
- **Session admission.** Every consumer reads the browser session through
  core's one decision point (#715–#719). What changes: `isAuthenticated` must
  be exactly `true`; a session record past its `expiresAt`, one without
  `user.id`, or one whose `sub` differs from it is not live; with
  `subjectRevocation` wired, the subject's revocation boundary applies at
  `/authorize`, consent, the code-minting grants, device verification and the
  link start; a session-store outage on an interactive `/authorize` is
  `temporarily_unavailable` on the redirect URI. A link transaction in flight
  across the upgrade is refused and the user starts it again. Log lines such
  as `authorize_session_liveness_unavailable` become
  `session_admission_unavailable`.
- **The re-authentication ask (#992).** A session still `reauthenticate`
  after the login trip `/authorize` sent it on is refused at the
  `redirect_uri` rather than sent to log in again. Every live session at the
  upgrade predates the record of how it was established: one whose `amr`
  holds `pwd` or `fed` is read as before; the rest are sent to log in by an
  `acr` `reauthenticate` verdict, a login trip that no longer signs the
  browser out.
- **`grantPolicy`.** A wired policy is consulted by the `session` grant, by
  `client_credentials` whether or not `oauth.resourceIndicator.enabled` is
  on (#1168), and by the device-code grant at the poll (#1169). Make sure it
  answers `allow` for those grant types wherever they should keep minting. A
  decision that is neither an exact `allow` nor an exact `deny` is
  `500 server_error` (`policy_decision_invalid`) (#874). A policy that throws
  at those three grants is `503`; at the device poll, a deny, a `503` or a
  `500` spends the approval.
- **Token exchange.** A policy refusal with `access_denied` is `400`, not
  `403` (#859). `token.issued.failure`'s `details.reason` is the refusal's
  description, or its error code: a dashboard keyed on `denied by policy` or
  `grant policy evaluation failed` stops matching (#889).
- **BREAKING: token exchange requires the caller to be an audience of the
  subject token by default.** A `subject_token` is accepted only when its
  `azp` is the calling client's id or its `aud` (a string or an array)
  contains it; otherwise the exchange is `400 invalid_request` /
  `subject_token azp and aud do not name this client`, logged at warn as
  `token_exchange_subject_not_for_client`. A resource server exchanging a
  token it received, and the client the token was issued to, keep working.
  **What to do:** grep for `token_exchange_subject_not_for_client` against a
  staging copy, and for each client that exchanges tokens issued to other
  clients — a gateway, an on-behalf-of service — add
  `allowExchangeOfTokensIssuedToOthers: true` to its client registration.
  Only a strict `true` counts. `may_act`, the scope and audience ceilings and
  the grant allowlist still apply to it. A subject-token validator you
  contribute (`tokenExchangeValidators`) must return the token's `aud` (as
  `ValidatedToken.aud`) and/or its `azp` (in `claims`) as the token carries
  them; an answer with neither is refused the same way. See the
  [oauth-token-exchange README](../packages/oauth-token-exchange/README.md#security-notes),
  note 18.
- **BREAKING: a refresh keeps the audience of the token it presents.** On
  `refresh_token`, the presented refresh token's `aud` is the ceiling and the
  default for the new tokens' audience, as its scope already is. A plain
  refresh (no `resource`, no audience from the policy) keeps the original
  `aud`; it used to issue for the client id. Once the client's
  registration (`allowedAudiences` ∪ `{client_id}`) no longer holds that
  `aud`, a refresh of the token is `400 invalid_grant` (`invalid_target`
  when it asks for a `resource` that derives nothing) and the family is left
  untouched; the user signs in again. A `resource` outside the
  original `aud` is `400 invalid_target`, even when the client's
  `allowedAudiences` lists it; it used to be issued. A policy's
  `grantedAudience` outside the original `aud` is `500 server_error`, as one
  outside `allowedAudiences` is. Narrowing applies only to the access token
  issued: the rotated refresh token keeps the presented token's scope and
  original audience, so a refresh that asks for less no longer narrows the
  refresh token for good, and the response's `scope` is the access token's
  (RFC 6749 §6). The policy receives the original audience as
  `GrantPolicyRequest.originalAudience` (#1567). **What to do:** a client that
  refreshes to reach a different resource than its authorization named
  requests that resource at `/authorize` instead. A resource server that
  expected refreshed access tokens to carry the client id as `aud` accepts
  the resource `aud` the original grant carried. See the
  [oauth README](../packages/oauth/README.md#refresh_token).
- **BREAKING: the code exchange issues a refresh token only where the client
  can redeem one.** The `authorization_code` grant returns a `refresh_token`,
  opens its family and joins the family to the session only when the
  `refresh_token` grant is registered and the client may use it by the rule
  `/oauth/token` applies when the token is redeemed: its `allowedGrantTypes`
  names `refresh_token`, or it has no list, `oauth.requireGrantTypeAllowlist`
  is off and the registered `refresh_token` grant does not deny by absence
  (`requiresExplicitGrantAllowlist`; the bundled one does not). Otherwise the response has no
  `refresh_token`, the access token carries no `family_id`, and only the
  client joins the session, so logout still reaches it. Such a client could
  not redeem the refresh token before either. An access token without
  `family_id` is refused by the federation token route
  (`401 invalid_token`, `missing family_id claim`), as the `session` grant's
  tokens are. **What to do:** for each client that refreshes, or that calls
  the federation token route, make sure its `allowedGrantTypes` names
  `refresh_token` (or that it has no list, where neither the switch nor the
  registered grant denies by absence), and that
  `oauth-authorization.grants.refreshToken.enabled` is on. See the
  [oauth README](../packages/oauth/README.md#authorization_code-the-session-sid-family_id-and-the-id_token).
- **Federation grants.** `/reauthorize` answers a removed connection, or a
  client that may no longer use it, `403 access_denied/connection_not_permitted`
  (#883), and a revoked or pending grant whose boundary cannot be read `410` /
  `400` rather than `503` (#963). A requirement's step-up at
  `GET /session/federation-grants/connect` is a `303` to the requirement's
  page (#1097). A refresh answer without a `tokenType` is refused as
  `upstream_token_ineligible` / `malformed_token_response` (#1228). An
  upstream answer's `expiresAt` and `expiresIn` are read together, and the
  earlier one ends the token: an adapter's `expiresAt` earlier than
  `calledAt + expiresIn` now ends the stored token at that instant, an answer
  with no life left makes the grant `upstream_token_ineligible` /
  `no_finite_lifetime` (retried after `ineligibleRetryAfter`) instead of
  being served, and the `expires_in` hint and the half-spent point come up to
  one call's duration earlier (#1021). With
  `federation-grants.enabled = false` nothing is mounted under either path,
  so the host's own fallback answers (#1174).
- **The federation token route** stores a refreshed upstream token for at
  most `maxTokenLifetimeMs`, 24 hours by default, so a long-lived one is
  refreshed upstream at least that often (#1060).
- **Token binding (#858).** Under `core.tokenBinding.dispatchPolicy =
  "intent-explicit"`, the v0.16.0 default, two mechanisms that both succeed
  at the deciding tier make a `/oauth/token` request `400 invalid_request`,
  bound to none, and log `token_binding_ambiguous` (warn); v0.16.0 bound the
  token in registration order. An ambient pair (a mechanism installed beside
  mTLS that fires on the same requests) refuses every such client until the
  deployment stops presenting both: [operator runbook §4](operator-runbook.md#4-alerts),
  `token_binding_ambiguous`. A `rateLimitBudgets` prefix named after an
  `Object.prototype` member refuses the boot (`contribution-malformed`).

### Passkeys, users and sessions

- **BREAKING: the login fails closed when its attempt counter is down
  (#807).** `POST /session/login` answers `503 service_unavailable`
  "Attempt counter temporarily unavailable" while the counter cannot answer,
  whatever `redis-rate-limiter.failMode` says — `open` no longer lets logins
  through an outage. It was "Rate limiter temporarily unavailable", or no
  limit under `open`. Operators see `attempt_counter_unavailable` (error)
  instead of `rate_limiter_failed_closed` / `_open`; the audit event stays
  `rate_limit.unavailable` (`tag: "login"`), its `details` gaining
  `failure`. A refused login is still `429 rate_limited`, now with
  `Retry-After` and `Cache-Control: no-store` and without `RateLimit-*`
  headers. The per-process warning is `attempt_counter_not_shared`, no longer
  `login_rate_limiter_not_shared`.
- **BREAKING: device verification fails closed when its attempt counter is
  down (#807).** `POST /oauth/device/verification` answers
  `503 service_unavailable` "Attempt counter temporarily unavailable" for
  every action while the counter cannot answer, whatever
  `redis-rate-limiter.failMode` says. It was "Rate limiter temporarily
  unavailable", or no limit under `open`. Operators see
  `attempt_counter_unavailable` (error, `tag: "device_verification"`) instead
  of `rate_limiter_failed_closed` / `_open`; the audit event stays
  `rate_limit.unavailable`, its `details` gaining `failure`. A refused
  attempt is still `429 slow_down`, logged `device_verification_rate_limited`
  and audited `device.rate_limited`, now with `Retry-After` and
  `Cache-Control: no-store`.

- **BREAKING: every user signs in again, and a refresh token bound to a
  v0.16.0 session stops working** (#1030). A session's record in core's
  session lifecycle is what makes it live, and a session established before
  the upgrade has none: it reads as closed. Its cookie no longer admits it,
  its access tokens no longer introspect active or reach `/userinfo`, nothing
  joins it, and a refresh token that names its `sid` is refused
  `400 invalid_grant` (`session_invalid`) before it rotates. Every refresh
  token the authorization-code grant mints names its session, so each one
  issued under v0.16.0 stops working at the upgrade; a refresh token without
  a `sid` (a sessionless composition) is unaffected.
- **WebAuthn.** An assertion whose user handle is not its credential owner's
  canonical handle is `400 invalid_grant` (`user_handle_mismatch`) (#863); one
  without a handle is refused too (#1153, #1217). Migrated passkeys and
  clients that pad or re-encode the handle are the ones to watch:
  `token.issued.failure` with `details.reason` `"user_handle_mismatch"` or
  `"user_handle_missing"`.
- **BREAKING: with `oauth.requireEmailVerified` on, passkey sign-ins of
  unverified users are refused (#710).** The WebAuthn grant now applies the
  gate `/authorize`, the session grant, jwt-bearer and device approval
  apply: after the assertion it reads the user behind the credential through
  the `userRepository` slot's new optional `findBySubject`, and a user the
  Store does not hold, or whose `emailVerified` is not `true`, is
  `400 invalid_grant` "email address is not verified", with no token or
  refresh-token family issued. A lookup that throws is
  `503 temporarily_unavailable` "identity resolution unavailable". With the
  setting on, a composition installing `webauthnModule` whose
  `userRepository` has no `findBySubject` refuses to start: implement it on
  your repository, answering the `User` for the `sub` the passkey grant
  issues (the credential's `userId`). With the setting off nothing changes.
  See the webauthn README, "SECURITY — a verified email".
- **The Store's users.** A `2xx` user with an empty `id` or `username` is
  refused as malformed, `503` on every login path (#862). A Store sends a
  stable label as `username` for a user without one.
- **`req.session.user`** holds the eight fields `User` declares and nothing
  else (#1100). A page of yours that reads another field of it fetches that
  from your user repository by `user.id`:
  [upgrading-required-record-keys.md](upgrading-required-record-keys.md#reqsessionuser-holds-the-declared-user-fields-alone).
- **The consent pages.** A consent page must not be served under
  `Referrer-Policy: no-referrer`: the standalone's `helmet()` sends it on
  every response, so a consent route served by that app sets `same-origin`
  itself. The federation-grants consent answer is held to the deployment's
  `csrfGuard`, which reads `http.trustProxy` and the forwarded headers (#784).
- **The CSRF token.** One whose expiry is more than `ttlSeconds` + 60 s ahead
  is refused, so after lowering `ttlSeconds` older tokens are refused until
  within the new bound (#774).
- **The federation start's freshness hints (#1084).** `GET
  /session/oauth/federation/:name` reads optional `prompt` (a space-delimited
  list, of which only `login` counts) and `max_age` (a non-negative integer
  no larger than 2^53−1).
  An empty value reads as omitted. A repeated or malformed one — a query
  parameter this route used to ignore — is now `400 invalid_request`. The
  hints are passed to the adapter as its freshness ask. A start from a browser
  that already holds an application session, and is not a link, is a
  re-authentication: `login` is asked whether or not the hint named it. A link
  start asks only what its hint names. The OIDC adapter forwards the ask as
  `prompt=login` / `max_age`, so its IdP prompts a signed-in user who starts a
  federated login again. A login page that links to the federation start
  should forward the `prompt` and `max_age` it finds in `redirect_to`.

### The users file (the `yaml` / `static` user repository)

Core's YAML user repository, the development and test adapter, now refuses at
boot an entry it could never sign in as written (#1560). An entry that breaks
the entry rules is refused as
`Invalid entry "<username>" in <file>: <field>: <reason>`, or, for a map
handed to `InMemoryUserRepository` directly,
`InMemoryUserRepository: invalid entry "<username>": <field>: <reason>`. The
refusals that look across entries (an empty username, a shared id, more than
one cost) come from `InMemoryUserRepository` and name the field, with the
users that share an id or, for costs, only the costs. None quotes a password
or a hash. Start against a copy of the file to list what is left.

- **BREAKING: a password starting with `$2` is read as a bcrypt hash, and one
  that is not well formed refuses the boot.** A well-formed hash is `$2a$`,
  `$2b$` or `$2y$`, a two-digit cost, a `$`, then 53 characters of bcrypt's
  alphabet (`./A-Za-z0-9`) — what `bcrypt.hash`, `htpasswd -B` or PHP's
  `password_hash` write. A truncated or edited hash, or a single-digit cost,
  used to boot and then fail every login for that user. Generate the hash
  again. A plain-text password starting with `$2` is refused too: change it.
- **BREAKING: `$2$` and `$2x$` hashes refuse the boot.** They used to be read
  as plain-text passwords. Hash the password again with `bcrypt` (`$2b$`).
- **BREAKING: a bcrypt cost outside 04 to 15 refuses the boot.** Below 04 and
  above 31 bcrypt computes nothing, so every login for that user failed.
  Above 15 a compare takes seconds (cost 15 is about 2 s, cost 10 about 60 ms)
  and holds a thread of Node's libuv pool for that long. Hash the password
  again at a cost from 04 to 15; 10 to 12 is usual.
- **BREAKING: an empty `id` refuses the boot.** The user signed in with the
  right password and was then refused with a `500`. Set a non-empty `id`, or
  remove the key to make the username the id. An entry keyed by an empty
  username (`"":`) is refused the same way, since its username would be its
  id: give it a username.
- **BREAKING: two users with the same id refuse the boot**, naming both
  usernames. The id is the entry's `id`, or its username when it sets none,
  so `alice: { id: bob }` beside a `bob` entry without an `id` is refused
  too. Give each user its own id.
- **BREAKING: bcrypt entries at more than one cost refuse the boot**, naming
  the field and the costs found (`password: bcrypt entries use costs 10 and
  12; every bcrypt entry must use one cost`). Hash the passwords again so
  every bcrypt entry uses one cost. Plain-text entries are unaffected.
- **BREAKING: a `username` key inside an entry refuses the boot.** The entry's
  key is its username; the key inside used to replace it. Remove the key, or
  rename the entry.
- **`$2y$` hashes now sign in.** `$2y$` is the same algorithm as `$2b$` under
  PHP's name, and is compared as `$2b$`. Such a user used to fail every login,
  so a users file migrated from `htpasswd -B` or PHP now works as it is.
- An unknown username, and a user with a plain-text password, pay a bcrypt
  compare at the cost the file's hashes share (cost 10 when it holds none),
  where it was cost 10 whatever the file held.
- Each start that builds this repository logs `user_repository_in_memory`
  at warn (`{ store: "userRepository", adapter: "yaml" }`, or `"static"`),
  whatever the environment: the users file is meant for development and
  tests.

### Redirect and logout URIs

Check every `allowedRedirectUris`, `postLogoutRedirectUris`,
`federationGrantRedirectUris` and `frontchannelLogoutUri`, and every Client ID
Metadata Document you depend on. A query name outside `[A-Za-z0-9_-]`, a
parameter with no name, a `;`, or a reserved name (`code`, `state`, `iss`,
`error`, `error_description`, and on a grant URI `grant_id`; on a
front-channel logout URI `iss` and `sid`) is refused, at boot for a `yaml` /
`static` client (#1044, #1053, #1157). A front-channel logout URI is held to
`http(s)` where it is used (#1096). The cases, their answers and the fix are
[operator runbook §7](operator-runbook.md#before-you-upgrade), step 7.

## Client records: the boundary in the `clientRepository` slot

Core installs its client-record boundary in the `clientRepository` slot, over
whatever repository a provider or the host puts there (#1120, #1167, #1180,
#1183). Every module that reads the slot — the `/oauth` router, client
authentication, the code exchange, token exchange, the federation-grants
connect and consent pages — reads each record once, through it:

- **The fields `PublicClient` declares, by name**, held to the rules a `yaml`
  / `static` client meets at boot, defaults filled, never `clientSecret`.
- **A record it refuses is `503 temporarily_unavailable` everywhere** except
  logout, which completes without the post-logout redirect,
  warned `client_record_refused` with the client id and the reasons, then
  logged `client_repository_unavailable` with `reason:
  "client_record_refused"`. It is never answered with a Client ID Metadata
  Document. Refused: a record breaking any registration rule (no
  `tokenEndpointAuthMethod`, a redirect URI the rules above refuse,
  `defaultScopes` outside `allowedScopes`, `firstParty: "true"` as a string,
  …), a value JSON does not hold as it is (a `Date`, a class instance), a
  `clientId` with a control character or over 256 characters, and a record
  whose `clientId` is not exactly the id looked up (a case-folding store).
- **What to do.** Run against a staging copy and grep for
  `client_record_refused`: each line names the fields to fix. Give
  `client_record_refused` its own alert, apart from the repository outage:
  until a record is fixed, anyone who knows its id gets `503`. A cache or a
  decorator over a `ClientRepository` lets a lookup's rejection through
  unchanged and never caches it. A repository you hand to a component
  yourself, outside the slot, is read as you hand it — except by
  `createOAuthRouter`, the client-authentication middleware and the
  authorization-code grant, which wrap a repository handed to them directly:
  wrap it with `validatedClientRepository`.
- **The Client ID Metadata Document fallback** is installed only by the
  `/oauth` router, from `oauth.clientIdMetadataDocuments` (#1186).
  `withClientIdMetadataDocuments`, `createClientIdMetadataDocumentResolver`
  and their option and resolver types are no longer exported. A deployment
  that built the fallback by hand passes its plain repository and sets
  `oauth.clientIdMetadataDocuments` (`enabled = true` and the same policy
  fields) instead: the [oauth README](../packages/oauth/README.md#client-id-metadata-documents-529).
  A document is resolved only when no registered client is found (#1128).

## Compositions and code

### A module switched off registers nothing

A module whose own switch is off registers nothing and runs none of its
factories (#1166, #728 B7): no routes, no slots, no budgets, no admission
actions.

- **device-grant** off: no `404` on its two paths, no `device_verification`
  budget, no requirement on `clientRepository` or `keyStore`, no absence
  policy. A deployment that leaves it off may drop `"auditSink"` from
  `core.declaredAbsent` if only the device grant asked for it (#1175), and
  deletes `device-grant.store` ([Keys removed](#keys-removed)).
- **federation-grants** off: nothing mounted; a composition that wants the
  JSON `404` mounts `createDisabledFederationGrantRouter()` at
  `FEDERATION_GRANTS_MOUNT_PATH` itself (#1174).
- **dpop**, **mtls**: a factory called directly, outside `createApp`, with a
  disabled section now builds the mechanism; read `dpopModule.section.isEnabled`
  / `mtlsModule.section.isEnabled` instead of relying on its answer (#1171,
  #1172).
- **An MFA factor module** off no longer claims its `mfaFactors` kind
  (#1173); `webauthn-mfa-factor` off registers nothing (#1217).
- Stage 1 parses the configuration before the manifest and wiring checks, so
  a configuration that fails to parse is reported first (#1166).

### Slots, admission and wiring

A composition root built by hand meets these; `createApp` with the bundled
modules fills them.

- **Session admission.** `createOAuthRouter`, the grant factories, the
  session router, `createDeviceVerificationHandler` and the federation-grants
  browser router require the requirements resolver (#715–#719). A consumer
  registers the actions it admits under `admissionActions`, each with one of
  core's grades; a hand-mounted handler registers the exported declarations
  (`DEVICE_GRANT_ADMISSION_ACTIONS`, `OAUTH_ROUTER_ADMISSION_ACTIONS`) (#793).
  A hand-written requirement that reaches or adds a second factor declares
  `secondFactorAuthority: true` (#781).
  `admitSession` refuses, with a `RangeError` before anything is read, a
  `remediation` action issued to a requirement its resolver does not hold
  (another composition's, or another boot's), as it refuses a literal or a
  copy; it no longer asks the requirements about it as `credential_change`,
  and `session_admission_remediation_undeclared` is no longer logged. Pass a
  route's own issued action to the resolver its requirement is registered
  in, read in the boot that registered it: a requirement object registered
  again (a second `createApp` with the same module instance) is issued new
  actions, which the earlier boot's resolver refuses (#798).
- **Slots one module owns.** An enabled device grant requires the
  `csrfGuard` slot, and enabled federation grants `csrfGuard` and
  `loginEntry` (#746, #784); `sessionModule` requires `csrfTokenSigner`, and
  `createCsrfProtection` takes `{ signer }` (#774); `deploymentMode` is core's
  and reserved (#773); `sessionCookiePolicy`, `httpSettings` and
  `oauthTokenSettings` are authoritative while their module is loaded (#783,
  #785). The `session` package's `createSessionCsrfGuard`, `createLoginEntry`
  and `createSessionCsrfTokenSigner` fill them without `sessionModule`.
- **A module's write to the `config` slot throws.** Every module that
  requires `config` is handed the configuration boot parsed as plain data
  frozen all the way down: one object those modules and core share. A
  factory that changes a value there, to steer what a later module or core
  reads, now throws a `TypeError` in strict-mode code (every ES module),
  which refuses boot as the factory's failure (`provides-factory-failed`,
  `contribute-factory-failed`); in sloppy-mode code the write is silently
  ignored. Either way the value does not change. Copy what the module needs,
  or set the value in the configuration (#1492).
- **A write to the audit fan-out throws.** When a module contributes
  `auditHooks`, the `auditSink` slot holds core's fan-out, and it is now
  frozen: assigning to it (`deps.auditSink.record = ...`) throws a
  `TypeError` in strict-mode code, which refuses boot when a factory does it.
  The sink the fan-out wraps — the host's or a provider's — is not frozen,
  and without a hook the slot holds that sink as it was given. Wrap the sink
  in a module of your own, or contribute a hook, instead (#1532).
- **Core checks the `csrfGuard` slot where boot fills it, and every reader
  receives a frozen copy of the guard.** Whatever fills the slot — a module's
  `provides`, or a `bootstrapComponents` or `overrideComponents` entry — boot
  reads each member of the guard once and requires `middleware` to be a
  function of at most three parameters (Express skips one of four or more as
  an error handler) and `check` to be a function. A member whose read throws
  refuses boot too, naming it. A module's guard that fails is refused as
  `provides-factory-failed` at `materializeComponents`; a host's, before any
  provider runs, with a `RangeError` naming the member (`csrfGuard.middleware
  is not a request handler`, `csrfGuard.check is not a function`,
  `csrfGuard.<member> could not be read`), as a host's `oauthTokenSettings` is.
  Before, the device grant and federation grants checked the guard in their
  own contributions (`contribute-factory-failed` at `applyContributions`,
  with their own wording), and the MFA routes did not check it. The slot
  then holds a frozen copy, not the object that filled it, so
  `deps.csrfGuard !== providedGuard`: compare members, not identity. The
  copy carries the guard's data members as read; its functions are core's
  own and call the guard's on the guard itself, so a guard written as a
  class, whose methods use `this`, works as before. `middleware` is core's
  request handler of three parameters in front of the guard's, so
  `deps.csrfGuard.middleware !== providedGuard.middleware` too, and the
  guard's `middleware` now runs with the guard as `this`. A
  `Symbol.asyncDispose` the guard carries still runs on dispose (#1090).
- **`AppHandle.components`, and the `deps` a factory is handed, have no
  prototype.** The component map boot builds is created with
  `Object.create(null)`, and so is each provider's and contribution's `deps`,
  every entry an own data property, so a component named after an
  `Object.prototype` member, `__proto__` included, is a key like any other
  and never a prototype. Read a component as a property or with
  `Object.hasOwn(map, key)`; `hasOwnProperty` and the other
  `Object.prototype` methods are no longer there. Spreading and destructuring
  work as before (#1090).
- **BREAKING: `sessionModule` reads the federations from the
  `federationSettings` slot, not `config` (#728).** It requires core's
  `federationSettings`, which core fills from `core.federations` in every
  composition, and no longer requires `config` or declares a `configSchema`:
  a composition booted with `createApp` sees no change. The federation routes
  take each enabled federation's callback URL, and whether an installed one's
  upstream `amr` counts, from the slot, and the origins an account link may
  be started from out of the module's own section
  (`session.csrf.trustedOrigins`). A deps object handed to the module's
  factories by hand carries `federationSettings` (in a test,
  `createTestFederationSettings()`) instead of `config`.
- **BREAKING: the oauth module reads the federations from the
  `federationSettings` slot, not `config`, and `createOAuthRouter` requires
  `section` and `federationSettings` (#728).** `oauthEndpointsModule`
  requires core's `federationSettings` in place of `config`: the `acr` table
  `/authorize` answers from and discovery advertises reads which installed
  federation trusts its upstream IdP's `amr` from the slot, which core fills
  from `core.federations` in every composition, so a composition booted with
  `createApp` sees no change. A router built by hand with `createOAuthRouter`
  no longer takes `config`: pass the module's parsed section as `section`
  (where you passed `config`, `section: config.oauth` as the oauth schema
  parses it) and core's view of the federations as `federationSettings` (in
  a test, `createTestFederationSettings()`). Without either the router
  refuses to build, naming the option; it no longer falls back to the
  `oauth {}` a `config` carries. A deps object handed to the module's
  factories by hand carries `federationSettings` instead of `config`.
- **BREAKING: an enabled TOTP factor requires the `oauthTokenSettings`
  slot (#1329).** `mfaTotpFactorModule` takes the deployment's issuer, which
  an unset `mfa-totp-factor.issuer` defaults to the host of, from the slot
  alone and no longer reads `oauth.jwt.issuer` from the whole configuration.
  `oauthEndpointsModule` provides the slot; a composition without it whose TOTP factor
  is on provides the slot itself, or the boot is refused
  (`missing-required-component`, naming `oauthTokenSettings`). A factor
  switched off by `mfa-totp-factor.enabled = false` requires nothing.
- **BREAKING: `mfaModule` requires core's session lifecycle beside its
  `userSessionStore` (#1030).** Without a `sessionLifecycleStore` (the port
  core's session-store modules fill, which `sessionLifecycleModule` requires)
  the boot is refused: `contribute-factory-failed`, the message naming
  `userSessionStore` and `sessionLifecycleStore`. Its routes' admission reads
  the session's lifecycle record, so a session closing or closed is admitted
  to nothing.
- **BREAKING: an enabled `authorization_code` grant with `subjectRevocation`
  wired requires `userSessionStore`.** Without one the boot is refused
  (`contribute-factory-failed`, naming both slots): wire a
  `userSessionStore` (core's `memorySessionStoresModule` or
  `redisSessionStoresModule`, which fill both), or remove
  `subjectRevocation`. The standalone template wires both.
- **The federation projections.** A name-keyed contribution factory (a
  `grants` or `mfaFactors` entry, say) that reads `federationProviders` or
  `federationRedirectPolicyResolver` while it runs refuses the boot
  (`contribute-factory-failed`, #1273), and so does a `federationTypes`
  factory that reads them while the entries are dispatched: the federations
  `core.federations` dispatches by type register after that pass, so it would
  miss them. Read them in a routes factory or at request time, as the bundled
  modules do.
- **BREAKING: a module no longer contributes or overrides `federations` or
  `federationRedirectPolicies` (#1314).** Core registers a federation's
  provider and redirect policy from its `core.federations` entry alone, with
  the factories of the type the entry names, so either kind in a module's
  `contributes` or `overrides` refuses the boot before any factory runs,
  whatever it holds and whether or not the module's section switches it off
  (`contribution-kind-guarded`, naming the module, the kind and the channel,
  and the entry's name when the kind holds a record with an entry: its
  first), and so does a collector for either in `createApp`'s
  `contributionKinds`. `ContributesMap` has no `federations` key, and the
  pairing check of a direct provider and policy is gone with them
  ([exports](#exports-removed-and-signatures-changed)). Register a type
  under `federationTypes` instead — `defineFederationType` with a `factory`
  that builds the provider and a `redirectPolicy` that builds its redirect
  policy, both given the entry — and write that type on each
  `core.federations.<name>` the module handles; a test registers one with
  `federationTypeForTests` from `@o3co/auth-provider-core/testing`. The
  provider a type's factory builds is named after its entry, or the boot is
  refused (`contribute-factory-failed`, naming the module, kind
  `federations` and the entry's name, #1283). A deployment that customised a
  federation's redirect policy through `federationRedirectPolicies` overrides
  the type instead (`overrides.federationTypes.<type>`, with its own
  `redirectPolicy`).
- **BREAKING: a contribution kind's container is its kind's shape (#911).**
  In `contributes` and in `overrides`, a name-keyed kind (`grants`,
  `tokenExchangeValidators`, `mfaFactors`, `sessionRequirements`,
  `rateLimitBudgets`, `federationTypes`, `admissionActions`,
  `sessionCloseNotifiers`, and a kind of your own whose collector is
  name-keyed) takes a record, and a list-shaped kind (`routes`,
  `auditHooks`, `grantPolicyHooks`, `grantMiddleware`,
  `tokenBindingMechanisms`, `discoveryMetadata`, and a list-shaped kind of
  your own) takes an array. A manifest that bypasses `ContributesMap`'s
  types — written in JavaScript, or cast — with an array under a name-keyed
  kind used to boot with those contributions dropped, filed under keys no
  reader reaches, or to fail with a plain `TypeError` when they were
  overrides or a factory failed; a record under a list-shaped kind failed
  with a `TypeError`, and `null` or a function was ignored for most kinds.
  Each is now refused before any factory runs (`contribution-malformed`,
  naming the module, the kind, the channel and what the container was).
  A record is a plain object — a literal, or `Object.create(null)`; a class
  instance, a `Map` or an object with another prototype is refused too,
  though `ContributesMap`'s types accept it. Write the kind's shape as a
  literal record or array. An array under `overrides.sessionCloseNotifiers`
  is now refused for its container (`contribution-malformed`) before the
  override guard (`contribution-kind-guarded`) that a record there still
  meets.
- **Rate limits.** The module that keys a prefix claims it
  (`rateLimitBudgets`) and sets no budget; the bundled limiters seed none
  (#782). No module overrides a prefix: an `overrides.rateLimitBudgets` entry
  refuses the boot (`contribution-kind-guarded`, #807). In code: the
  `failMode` options are gone from `createDeviceVerificationHandler`, the
  federation-grants routers, `RateLimitGuardOptions` and
  `RateLimitPolicyOptions`; `checkWithFailMode` takes a policy from
  `createRateLimitPolicy` and refuses any other object;
  `createMemoryRateLimiter`, `createRedisRateLimiter` and
  `createRateLimitBudgetLookup` (`RateLimitBudgetLookupOptions`) take no
  `budgets`, `memoryRateLimiterModule` requires nothing and
  `redisRateLimiterModule` only `rateLimiterClient`; set a prefix's limit as
  `core-rate-limiter-memory.limits.<prefix>` or
  `redis-rate-limiter.limits.<prefix>` (#807).
- **BREAKING: a `rateLimitBudgets` contribution is a prefix claim only
  (#807).** A module claims each prefix it keys with a factory that answers
  `null` (`verifierLimitClaim({ setting })` for a verifier's own limit) and
  contributes no budget. A key's budget is the limiter's own `limits` entry
  for its prefix, else its `defaultLimit`, the same on the in-process and the
  Redis limiter. A factory that answers a budget (`{ limit, windowSeconds }`)
  refuses the boot (`contribute-factory-failed`, naming the module, the
  prefix and the `limits` entry to set instead). The synthetic slot
  `rateLimitBudgetResolver` and its type `RateLimitBudgetResolver` are
  removed: a module that requires the slot refuses the boot
  (`missing-required-component`). If a module of your own contributed a
  budget, or your code reads `rateLimitBudgetResolver`, move the budget into
  the limiter's `limits` — `core-rate-limiter-memory.limits.<prefix>` or
  `redis-rate-limiter.limits.<prefix>` — and have the module's factory answer
  `null`. The boot line `rate_limit_budgets_registered` lists each claimed
  prefix with its module and no `budget` field.
  `createDeviceVerificationHandler`'s `subjectRevocation` is the full
  `SubjectRevocation`, no longer a `Pick` of `revokedBefore` (#717).
- **A switched-off grant or second factor is no override target (#728).** A
  `grants` or `mfaFactors` factory may answer `null` — switched off by its
  module's settings while the module is on; the entry stays claimed, and an
  `overrides.grants` or `overrides.mfaFactors` entry for it refuses the boot
  before the overriding module's factories run (`override-target-missing`, naming the kind, the
  name and the overriding module; the message says the entry is switched
  off), so an override never switches on what its owner switched off. Switch
  the entry on at its owner's setting and keep the override, or drop the
  override. A module that is itself off contributes nothing, so an override
  of its entries is refused as a missing target. An override may still
  answer `null`, switching off the entry it replaces.
- **BREAKING: an enabled `dpopModule` requires `oauthTokenSettings`, and
  no longer reads the configuration (#728).** It takes the issuer every
  proof's `htu` is checked against from the slot alone, and no longer falls
  back to `oauth.jwt.issuer` when no module provides it. With `oauthEndpointsModule`
  installed nothing changes. A composition with DPoP enabled and without
  `oauthEndpointsModule` puts an `oauthTokenSettings` value in `bootstrapComponents`
  (core's `OAuthTokenSettings`), or the boot is refused for the
  missing component. A deps object handed to the module's factories carries
  `oauthTokenSettings`; `config` is no longer read. Disabled, the module
  requires nothing.
- **BREAKING: `webauthnModule` provides the `webauthnConfig` slot from its
  own section, and requires `oauthTokenSettings` (#728).** Boot parses the
  `webauthn` section with `webauthnConfigSchema` — the same rules for the
  relying party's id and origins, now strict at every level — and the module
  provides the result as the slot, naming it `authoritative`. Remove the
  bridge module a composition wrote to fill the slot from `config.webauthn`:
  beside `webauthnModule`, a module providing the slot refuses the boot
  (`duplicate-provides`), as do a `bootstrapComponents` entry
  (`bootstrap-component-collision`) and an `overrideComponents` entry
  (`authoritative-component-overridden`). A composition that hard-coded the
  slot writes those values in the `webauthn` section instead. Without
  `webauthnModule` (the WebAuthn second factor alone), the composition still
  fills the slot itself. The module's grant reads the token lifetimes and the
  resource-indicator switch from the `oauthTokenSettings` slot alone and no
  longer falls back to `oauth.accessToken`, `oauth.refreshToken.expiresIn`
  or `oauth.resourceIndicator.enabled`: with `oauthEndpointsModule` installed nothing
  changes; a composition without it puts an `oauthTokenSettings` value in
  `bootstrapComponents`, or the boot is refused for the missing component.
  In code: `createWebAuthnGrant` requires `oauthTokenSettings` and throws a
  `RangeError` naming it when it is missing; a deps object handed to the
  module's factories carries the parsed section as `section` and
  `oauthTokenSettings`, and no `webauthnConfig`; `webauthnConfigSchema`
  refuses a key it does not declare, `allowCredentialsForKnownUser` included.
- **BREAKING: the WebAuthn grant reads the binding rule from the
  `tokenBindingSettings` slot, not `config` (#728).** `webauthnModule`
  requires core's `tokenBindingSettings`, which core fills from
  `core.tokenBinding` in every composition, and no longer requires `config`:
  a composition booted with `createApp` sees no change. Deps built by hand
  for `createWebAuthnGrant` or the module's grant factory carry
  `tokenBindingSettings` (`resolveTokenBindingSettings(config)`; in a test,
  `createTestTokenBindingSettings()`) instead of `config`; without it the
  grant throws a `TypeError` naming the slot when it is built.
- **BREAKING: `webauthnSessionSubjectModule` requires core's session lifecycle
  beside its `userSessionStore` (#1030).** Without a `sessionLifecycleStore`
  (the port core's session-store modules fill, which `sessionLifecycleModule`
  requires) the boot is refused: `contribute-factory-failed`, the message
  naming both slots. Its admission reads the session's lifecycle record, so a
  session closing or closed registers no passkey.
- **BREAKING: `dpopConfigSchema` fills no default (#728).** The `dpop`
  section's defaults live only in the package's `config/reference.conf`. A
  configuration that layers the modules' references (`moduleReferences`, as
  the template does) sees no change. One built by hand writes every key of a
  `dpop` section it sets — `iatWindowSeconds`, `algWhitelist`,
  `replayStoreTtlSeconds` and `nonce { required, ttlSeconds }` — or the boot
  is refused naming the missing key; an absent section, or one without
  `enabled`, is off. Parsed directly, an absent section is `undefined`.
- **BREAKING: `createDeviceVerificationHandler` takes an attempt limit, not a
  rate limiter (#807).** Its `rateLimiter` option is gone, and so is
  `DeviceGrantDependencies.rateLimiter`; it takes `attemptLimit`
  (`{ limit, windowSeconds }`), an optional `attemptCounter` and
  `deploymentMode`. The module requires `deploymentMode` instead of
  `rateLimitBudgetResolver` and reads `attemptCounter`, so a deps object
  handed to its factories carries them. `DEVICE_VERIFICATION_RATE_LIMIT_PREFIX`
  is now `DEVICE_VERIFICATION_ATTEMPT_TAG` (still `"device_verification"`),
  and `isDeviceVerificationRateLimitSpec` is removed: core's `isAttemptSpec`
  judges the limit.
- **BREAKING: the device grant is one module, `deviceAuthorizationGrantModule`,
  switched by its own section (#728).** List it as it is: it reads
  `device-grant.enabled` from the configuration boot parses, and an absent
  section or key is off. The refusal of a module built from a configuration
  that disagrees with the booted one about `device-grant.enabled` is gone, and a
  composition root no longer reads that key before boot.
- **BREAKING: an enabled device grant requires `oauthTokenSettings`, and no
  longer reads the configuration (#728).** It takes the issuer client
  authentication holds an assertion's audience to, the access-token lifetime
  it mints and `requireEmailVerified` from the slot alone, and no longer
  falls back to `oauth.jwt.issuer`, `oauth.accessToken` or
  `oauth.requireEmailVerified` when no module provides it. With `oauthEndpointsModule`
  installed nothing changes. A composition with the grant enabled and without
  `oauthEndpointsModule` puts an `oauthTokenSettings` value in `bootstrapComponents`,
  or the boot is refused for the missing component. A deps object handed to
  the module's factories carries `oauthTokenSettings` and `section`; `config`
  is no longer read. Disabled, the module requires nothing.
- **BREAKING: an enabled device grant requires core's session lifecycle beside
  its `userSessionStore` (#1030).** Without a `sessionLifecycleStore` (the
  port core's session-store modules fill, which `sessionLifecycleModule`
  requires) `deviceAuthorizationGrantModule` is refused at boot:
  `contribute-factory-failed`, the message naming both slots.
  `createDeviceVerificationHandler` throws the same refusal. The
  verification's admission reads the session's lifecycle record, so a session
  closing or closed approves nothing.
- **BREAKING: `deviceGrantConfigSchema` fills no default (#728).** The
  `device-grant` section's defaults live only in the package's
  `config/reference.conf`. A configuration that layers the modules'
  references sees no change. One built by hand writes every key of a
  `device-grant` section it sets — `verificationUriComplete`,
  `codeLifetimeSeconds`, `pollingIntervalSeconds` and
  `rateLimit { limit, windowSeconds }` — or the boot is refused naming the
  missing key. This holds with the grant off too: `device-grant { enabled =
  false }` alone, without the package's `reference.conf`, is refused; delete
  the section or layer the reference. Parsed directly, an absent section is
  `undefined`.
- **BREAKING: the `mtls` section, the Redis stores' sections, core's
  in-process rate limiter's section and the template's `redis-clients` fill
  no default (#728).** `mtls`, `core-rate-limiter-memory`, each Redis store's
  section (`redis-access-token-denylist`, `redis-attempt-counter`,
  `redis-challenge-store`, `redis-consent-store`, `redis-device-code-store`,
  `redis-federation-token-store`, `redis-mfa-factor-store`,
  `redis-mfa-transaction-store`, `redis-rate-limiter`,
  `redis-refresh-token-family-store`, `redis-replay-seen-set`,
  `redis-session-stores`) and the template's `redis-clients.assumeNoEviction`
  take their defaults only from the owning package's `config/reference.conf`.
  A configuration that layers the modules' references (`moduleReferences`, as
  the template does) sees no change. A configuration built by hand must write
  every key of each of these sections it loads, or the boot is refused naming
  the missing key. Parsed directly, `mtlsConfigSchema` reads an absent
  section as `undefined`, which the module treats as off. It still fills the
  tuning keys inside `fullPki.revocation`, a block that stays absent until
  the operator writes it. `redis-federation-grant-store` and
  `redis-federation-grant-intent-store` keep their `keyPrefix` default,
  because `resolveRedisFederationGrantStoreOptions` and
  `resolveRedisFederationGrantIntentStoreOptions` parse a section with no
  `reference.conf` beneath it.
- **BREAKING: the session grant is one module, `oauthSessionGrantModule`,
  switched by its own section (#728).** List it as it is: it reads
  `oauth-session.enabled` from the configuration boot parses, and an absent
  section or key is off. The refusal of a module built from a configuration
  that disagrees with the booted one about `oauth-session.enabled` is gone. The
  section is strict and its schema, `oauthSessionConfigSchema`, fills no
  default: the package's `config/reference.conf` ships `enabled = false`.
- **BREAKING: an enabled session grant requires `oauthTokenSettings`, and no
  longer reads the configuration (#728).** It takes the access-token
  lifetime it mints and `requireEmailVerified` from the slot alone, and no
  longer reads `oauth.accessToken` or `oauth.requireEmailVerified` from
  `config`. With `oauthEndpointsModule` installed nothing changes. A composition with
  the grant enabled and without `oauthEndpointsModule` puts an `oauthTokenSettings`
  value in `bootstrapComponents`, or the boot is refused for the missing
  component. In code: `createSessionGrant` requires `oauthTokenSettings` and
  throws a `RangeError` naming it when it is missing or breaks the slot's
  contract; `SessionGrantDeps` no longer has `config` (in a test,
  `createTestOAuthTokenSettings()`). Disabled, the module requires nothing.
- **BREAKING: an enabled session grant with a `userSessionStore` requires
  core's session lifecycle (#1030).** Without a `sessionLifecycleStore` (the
  port core's session-store modules fill, which `sessionLifecycleModule`
  requires) `oauthSessionGrantModule` is refused at boot:
  `contribute-factory-failed`, the message naming both slots, and
  `createSessionGrant` throws the same refusal. The grant's admission reads
  the session's lifecycle record, so a session closing or closed mints
  nothing. A sessionless grant is unaffected.
- **BREAKING: `subjectRevocationServiceModule` requires `oauthTokenSettings`,
  reads `federationGrantPolicy`, and no longer reads the configuration
  (#728).** It sizes the subject's revocation boundary from the token
  lifetimes in `oauthTokenSettings` and no longer falls back to
  `oauth.accessToken` and `oauth.refreshToken.expiresIn`; it reads whether
  federation grants are on, and whether a revocation may keep them, from the
  `federationGrantPolicy` slot the federation-grants module provides, not
  from `federation-grants {}`. With `oauthEndpointsModule` and the federation-grants
  module installed nothing changes. A composition without `oauthEndpointsModule` puts
  an `oauthTokenSettings` value in `bootstrapComponents`, or the boot is
  refused for the missing component. A composition that wires a
  `federationGrantStore` and holds no `federationGrantPolicy` — grants on
  without the federation-grants module, or the module installed but switched
  off (`federation-grants.enabled = false`) with a grant store still wired —
  is refused at boot (`provides-factory-failed`, naming both), where grants
  used to be read from `federation-grants.enabled`: install the
  federation-grants module and switch it on, or, to keep grants off with the
  store wired, put `federationGrantPolicy` `{ enabled: false,
  allowKeepOnSubjectRevocation: false }` in `bootstrapComponents`. A deps
  object handed to the module's provider carries `oauthTokenSettings` and,
  for grants, `federationGrantPolicy` (in a test,
  `createTestOAuthTokenSettings()` and `createTestFederationGrantPolicy()`);
  `SubjectRevocationServiceModuleDeps` no longer has `config`.
- **BREAKING: the authorization_code, refresh_token, client_credentials and
  jwt-bearer grants are one module, `oauthAuthorizationGrantsModule`,
  switched by its own section (#728).** List it as it is: it reads each
  `oauth-authorization.grants.<grant>.enabled` from the configuration boot
  parses, and an absent section or key is off. `oauthAuthorizationModule({
  config })` is removed: list `oauthAuthorizationGrantsModule` in its place.
  The refusal of a module built from a configuration that disagrees with the
  booted one about a grant's switch is gone, and the standalone template no longer reads
  `oauth-authorization.grants` before boot. A grant switched off registers nothing, but while the module is on it
  still claims its grant type: a composition that pairs the module with its
  own `client_credentials`, `refresh_token` or jwt-bearer grant, this
  module's switch for it off, is refused (`duplicate-contribute`) where it
  used to boot — and an override of a switched-off grant is refused
  (`override-target-missing`). Drop your grant, or switch every grant of
  this module off; with every grant off the
  module registers and requires nothing — no slot, and no `subjectRevocation`
  or `auditSink` absence policy. While any grant is on, the module declares
  both session-bound grants' actions (`oauth.code_exchange`,
  `oauth.refresh`), whichever is on. Its schema,
  `oauthAuthorizationConfigSchema`, fills no default: the package's
  `config/reference.conf` ships every switch off.
- **BREAKING: an enabled oauth-authorization grant requires
  `oauthTokenSettings` and `tokenBindingSettings`, and reads its settings
  from them, not from the configuration (#728).** The grants take the
  issuer, the lifetimes they mint, whether resource
  indicators are enforced and `requireEmailVerified` from
  `oauthTokenSettings`, and the refresh-token binding rule
  (`bindConfidentialClientRefreshTokens`) from core's `tokenBindingSettings`,
  which boot always fills. With `oauthEndpointsModule` installed nothing changes. A
  composition with a grant on and without `oauthEndpointsModule` puts an
  `oauthTokenSettings` value in `bootstrapComponents`, or the boot is refused
  for the missing component. The id_token's `iss` is the slot's issuer, so
  an id_token is issued whenever `openid` is granted and a session is read;
  before, a configuration built by hand without `oauth.jwt.issuer` got none.
  The module requires no `config`, and `createRefreshTokenGrant` takes none
  and no policy: a refresh token whose family no record holds is always
  refused. A deps object handed to
  the module's grant factories carries `section`, `oauthTokenSettings` and
  `tokenBindingSettings`; a factory refuses a missing or broken
  `oauthTokenSettings` with a `RangeError` naming it, and a
  `tokenBindingSettings` whose rule is not a boolean with a `TypeError`.
- **BREAKING: enabled federation grants require `oauthTokenSettings`, and
  `federationGrantsModule` no longer reads the configuration (#728).** It
  takes the issuer every route, `connect_uri` and callback check is built on
  from the slot alone, and no longer falls back to `oauth.jwt.issuer` when no
  module provides it. With `oauthEndpointsModule` installed nothing changes. A
  composition with `federation-grants.enabled = true` and without
  `oauthEndpointsModule` puts an `oauthTokenSettings` value in `bootstrapComponents`,
  or the boot is refused for the missing component. The federations a
  connection names — whether each is configured and on, its `issuer` and
  `clientId` — come from core's `federationSettings` slot, which core fills
  from `core.federations` in every composition: nothing to do under
  `createApp`, and the refusals are unchanged. A deps object handed to the
  module's route factories carries `oauthTokenSettings`,
  `federationSettings` and `section`; `config` is no longer read. The audit
  sink's declared absence is now core's guard: enabled with no `auditSink`
  and no `core.declaredAbsent = ["auditSink"]`, the boot is refused at
  manifest validation with core's `component-absence-undeclared`
  (`consumedBy` naming `federation-grants`), ahead of the module's other
  refusals, and no longer with the module's own
  `federationGrantsModule: … with no auditSink component` error; match on
  the reason. Disabled, the module requires nothing.
- **BREAKING: enabled federation grants require core's session lifecycle
  beside the `userSessionStore` (#1030).** Without a `sessionLifecycleStore`
  (the port core's session-store modules fill, which `sessionLifecycleModule`
  requires) `federationGrantsModule` is refused at boot:
  `contribute-factory-failed`, the message naming both slots. The connect
  flow's admission reads the session's lifecycle record, so a session closing
  or closed connects nothing.
- **Renamed variables.** A configuration handed to `createApp` carries core's
  `renamed-variables` captures: layer core's `reference.conf`, or call
  `renamedVariableCaptures({ modules, core: CORE_RELOCATIONS, env })` from
  `@o3co/auth-provider-core/testing` (#786, #796).
- **Shutdown.** A cleanup registers the allowance it needs; the template's
  `installGracefulShutdown` takes `cleanupAllowanceMs` (#797).
- **BREAKING: where a user-session store is wired, core's session lifecycle
  is required** (#1030). A composition that wires `userSessionStore`
  installs `sessionLifecycleModule` beside it (the standalone template does;
  see [Your scaffold](#your-scaffold)), with what that module requires:
  `sessionLifecycleStore`, `refreshTokenFamilyRevocation` and
  `federationTokenStore`. Without it the boot is refused, each message
  naming `userSessionStore` and `sessionLifecycle`: in the session package,
  `sessionModule`'s route factories with `contribute-factory-failed` and
  `loginCompletionModule`'s provider with `provides-factory-failed`; in the
  oauth package, the `authorization_code` grant
  (`oauthAuthorizationGrantsModule`) and `oauthEndpointsModule` with
  `contribute-factory-failed`, and `createOAuthRouter` throws the same
  refusal. `subjectRevocationServiceModule` requires `sessionLifecycle` in
  place of the six session-cascade slots. A sessionless composition (client
  credentials, jwt-bearer) wires neither and is unaffected. A test or
  composition of your own that fills the slots by hand provides a
  `sessionLifecycle` too. Where another package's module admits a session,
  it requires `sessionLifecycleStore` beside the store the same way; each
  such refusal is listed with that module's own entry in this section.
  - `sessionModule`'s federation routes are refused the same way when
    `userSessionStore` and `sessionLifecycle` are wired without a
    `sessionLifecycleStore`: `contribute-factory-failed`, the message naming
    both slots, and the federation router (`createRouter` in
    `routes/Federation.mts`) throws the same refusal.
  - The code exchange joins its session through the lifecycle alone: the
    grant no longer reads `sessionRPRegistry` or `sessionFamilyIndex`, and
    `oauthAuthorizationGrantsModule` no longer declares them, nor
    `sessionFederationIndex`.
  - The `refresh_token` grant (`oauthAuthorizationGrantsModule`) is refused
    the same way when no `sessionLifecycleStore` (the port core's
    session-store modules fill, which `sessionLifecycleModule` requires) is
    wired beside its `userSessionStore`: `contribute-factory-failed`, the
    message naming both slots, and `createRefreshTokenGrant` throws the same
    refusal. The grant's admission reads the token's session lifecycle
    record, so a session closing or closed refreshes nothing. A composition
    whose session-store module fills both is unaffected.
  - The `authorization_code` grant (`oauthAuthorizationGrantsModule`) and
    `oauthEndpointsModule` (`/authorize` and the consent step) are refused
    the same way when `userSessionStore` and `sessionLifecycle` are wired
    without a `sessionLifecycleStore`: `contribute-factory-failed`, the
    message naming both slots, and `createAuthorizationGrant` and
    `createOAuthRouter` throw the same refusal.
  - Introspection, `/oauth/userinfo` and `POST /oauth/federation/:name/token`
    read a session through the lifecycle alone. Their outage lines no longer
    carry `store: "user_session"`, nor (the federation-token route)
    `store: "session_federation_index"`; they carry
    `store: "session_lifecycle"` (`step: "liveness"` or `"federations"` on
    the federation-token route). Move an alert keyed on the old values.
  - The federation-token route lists the session's federations from the
    lifecycle. A federation logout removes that federation's tokens and
    leaves it listed, so the route answers it `404 federation_not_linked`,
    as a federation with no token record. A later close of the session may
    send that upstream an end-session request again; it is idempotent.
  - The boot warnings `session_family_index_without_session_end` and
    `refresh_token_family_rotation_without_revocation` are no longer logged.
  - A session lifecycle that rejects with its store's error is answered as
    the outage it is, where it was a `500`: the code exchange's join answers
    `503 temporarily_unavailable` ("session linking unavailable"), logged
    `authorization_grant_store_unavailable` with the error's projection, and
    `/oauth/logout`'s close answers `503` ("session store unavailable"),
    logged `logout_store_unavailable` with the projection and audited
    `logout.cascade_failed`. A federation listing that rejects only leaves
    the logout without its upstream hint.
  - A `RangeError` is no exception, as a store's own error can be one. A
    code exchange whose join rejects with one is that same `503`, where the
    throw was a `500`. A `/oauth/logout` whose close rejects with one is
    that same `503`, where it answered `200 {"logged_out": true}` as a
    session already gone, reporting a logout that revoked nothing. A sid the
    lifecycle cannot hold is therefore a `503` too; such a sid is never
    issued.
  - The `token_exchange` grant (`tokenExchangeModule`) is refused the same
    way, with `contribute-factory-failed`, and `createTokenExchangeGrant`
    throws the same refusal. The grant reads a presented token's session
    through the lifecycle's `liveness` alone: the `userSessionStore`
    fallback is removed, so `token_exchange_session_store_unavailable` no
    longer carries `store: "user_session"` (`step: "get"`), only
    `store: "session_lifecycle"` (`step: "liveness"`). Move an alert keyed
    on the old value.
- **BREAKING: `POST /session/logout` closes the session through the
  lifecycle only.** The path that deleted the `UserSession`, the subject-index
  entry and the federation tokens itself, without the lifecycle, is removed,
  and with it the log events `logout_user_session_delete_failed`,
  `logout_subject_session_index_remove_failed`,
  `logout_federation_token_remove_failed` and
  `logout_session_federation_index_remove_failed`: a failed step of the close
  is core's `session_close_item_failed`. A federated login and a link join
  their federation through the lifecycle only; the federated login no longer
  writes the `sessionFederationIndex` entry itself.
- **BREAKING: the session module no longer needs `sessionFederationIndex`.**
  `sessionModule` and the federation router no longer require the slot (the
  router's `sessionFederationIndex` option is removed). A link reads whether
  the session already carries the federation from core's session lifecycle
  (`sessionLifecycle.federations`) and no longer removes an index entry on
  rollback; the lifecycle's join records the federation. A link's outage
  there is logged as `federation_link_store_unavailable` with
  `store: "session_lifecycle"`, `step: "federations"`, in place of
  `store: "session_federation_index"`, `step: "list"` and `"remove"`.
- **BREAKING: every failed close at `POST /session/logout` is an outage.** A
  logout whose `sid` the session lifecycle cannot hold now answers
  `503 temporarily_unavailable` and keeps the cookie, as any close the
  lifecycle rejects does, instead of `200`. The warn
  `session_logout_sid_not_closable` is removed. A login never writes such a
  sid, so this is not expected in practice.
- **A login's rollback closes the session's lifecycle record.** When a login
  fails after its record was created (a cookie-session regeneration or save,
  a federation's token attach or join), the rollback closes the record it
  opened, cause `session_logout`, before it deletes the `UserSession`. A
  federated login whose join the lifecycle refuses (the session was closed
  during the sign-in) is still `401 login_required`, and logs nothing.
- **Core's session lifecycle rejects an outage with the store's own error,
  and logs nothing for it** (#1030). `open`, `join`, `close`, `federations`
  and `liveness` reject where they answered `{ outcome: "unavailable" }`,
  and the warn `session_lifecycle_unavailable` is no longer logged for them;
  each consumer logs its own event once, at error, with the error's
  projection. A caller of your own catches the rejection as an outage.
  `{ outcome: "unavailable" }` is removed from `SessionOpenOutcome`,
  `SessionJoinOutcome`, `SessionCloseOutcome`, `SessionFederations` and
  `SessionLiveness`: a comparison against it no longer compiles, and a
  lifecycle of your own rejects instead of answering it. The
  close work's and the sweep's own lines (`session_close_item_failed`,
  `session_lifecycle_unavailable` for a close-work completion or re-read,
  or a resumed session, `session_lifecycle_sweep_*`) are unchanged.
- **BREAKING: a session with no lifecycle record reads as closed**
  (#1030). Core's session lifecycle reads and writes its own record alone:
  `liveness` answers `not_live`, `join` answers `refused` (revoking the
  family and removing the federation's tokens it was handed, and writing
  nothing), and `close` answers `done` with no relying party or federation
  and nothing to run. Session admission answers `not_live` (`closing`) for a
  sid with no record wherever a `sessionLifecycleStore` is handed
  (`AdmissionDeps.sessionLifecycleStore`). A record that lapsed at its end on
  the store's clock, before the closing commit too, reads the same: such a
  close no longer runs the close work itself. Sessions established before
  the upgrade have no record, so they are refused for any join and by
  admission ([every user signs in again](#passkeys-users-and-sessions)).
  - The lifecycle no longer reads or writes the per-session stores
    (`sessionRPRegistry`, `sessionFamilyIndex` and its end mark,
    `sessionFederationIndex`), and adopts no session from them.
    `SessionLifecycleOptions` loses `sessionRPRegistry`,
    `sessionFamilyIndex` and `sessionFederationIndex`, and
    `sessionLifecycleModule` no longer requires those slots.
  - An enabled `core.federations.<name>` requires `sessionLifecycle` in place
    of `sessionRPRegistry`, `sessionFamilyIndex` and `sessionFederationIndex`:
    boot refuses one without `userSessionStore`, `sessionLifecycle`,
    `federationTokenStore` and `refreshTokenFamilyRevocation`
    (`federation-stores-incomplete`).
  - A test or composition of your own that set a session up by writing the
    user session alone opens it first, `sessionLifecycle.open(sid, { sub,
    expiresAt })`, as a login through the session package does.
- **The session lifecycle sweeps unless told not to.** Installing
  `sessionLifecycleModule` starts a sweep that resumes the closes left
  pending every 60 seconds; `core.sessionLifecycle.sweepIntervalSeconds`
  sets another interval, and `0` turns it off. It is stopped on dispose,
  and its timer never keeps the process alive.
- **BREAKING: the oauth logout routes close sessions through core's session
  lifecycle only** (#1030). `GET`/`POST /oauth/logout` ends the session with
  `sessionLifecycle.close`; the cascade over the per-session stores is gone.
  - The logout routes are mounted, and discovery advertises
    `end_session_endpoint`, where `userSessionStore`, `sessionLifecycle`,
    `federationTokenStore` and `refreshTokenFamilyRevocation` are wired.
    `createOAuthRouter` no longer takes `sessionRPRegistry`,
    `sessionFamilyIndex` or `sessionFederationIndex`, and
    `oauthEndpointsModule` no longer declares them; drop them from a router
    you build by hand.
  - `POST /oauth/federation/:name/logout` reads whether the session is live
    and which federations it joined from the lifecycle. A token whose `sub`
    differs from the live session's, or is absent, now gets
    `401 invalid_token` ("session not found"), where it disconnected before. It
    removes the federation's tokens and leaves the federation listed as
    having joined the session: the federation-token route then answers it
    `404 federation_not_linked`, and the session's close may end it upstream
    again, which is idempotent.
  - Log lines and audit details that described the cascade are gone:
    `logout_store_unavailable` with `store: "session_family_index"`,
    `"session_rp_registry"`, `"session_federation_index"` or
    `"logout_cascade"`, and its `cascadeStep`, `failures`, `left` and
    `alsoUnavailable` fields; the warns `logout_cascade_operation_failed` and
    `logout_cascade_cleanup_failed`; `logout.cascade_failed`'s `step` and
    `left` (it now carries `store: "session_lifecycle"` alone, for a close
    that could not commit); and the `"logout cascade failed"` description on
    the `503`. `federation_logout_store_unavailable` carries
    `store: "session_lifecycle"` (`step: "liveness"` or `"federations"`) where
    it carried `"user_session"` or `"session_federation_index"`. Move an
    alert keyed on the old values.

### Exports removed, and signatures changed

- **`cascadeLogout`, `CascadeLogoutOptions` and `CascadeLogoutResult`** are
  removed from `@o3co/auth-provider-oauth` (#1030). A session is ended
  through core's session lifecycle: `sessionLifecycle.close(sid, cause)`.
- **BREAKING: core no longer has the per-session store ports (#1030).**
  Core's session lifecycle record holds what they held. Removed from
  `@o3co/auth-provider-core`: the ports `SessionRPRegistry`,
  `SessionFamilyIndex` and `SessionFederationIndex`, the session-end
  capability `SupportsSessionEnd` and its guard `supportsSessionEnd`, the
  in-process stores `createInMemorySessionRPRegistry`,
  `createInMemorySessionFamilyIndex` and `createInMemorySessionFederationIndex`,
  the factory builders `createSessionRPRegistryFactory`,
  `createSessionFamilyIndexFactory` and `createSessionFederationIndexFactory`
  with their aliases `SessionRPRegistryFactory`, `SessionFamilyIndexFactory`
  and `SessionFederationIndexFactory`, and the `ComponentMap` slots
  `sessionRPRegistry`, `sessionFamilyIndex` and `sessionFederationIndex`
  (also gone from `GrantDependencies`). `memorySessionStoresModule` no longer
  provides those slots. `RegisteredRP` stays: a join names one
  (`SessionJoinRequest.rp`). A module of your own that provides or requires
  one of the slots drops it.
- **BREAKING: session admission requires the lifecycle store beside a
  user-session store (#1030).** `admitSession` handed a `userSessionStore`
  and no `sessionLifecycleStore` answers a live session
  `unavailable` (`session_lifecycle`), logged once as
  `session_admission_unavailable`, instead of reading it as before. Every
  bundled consumer already refuses to build without it; a caller of your own
  passes the `sessionLifecycleStore` slot in `AdmissionDeps`.
- **BREAKING: `@o3co/auth-provider-redis` no longer has adapters for the
  three per-session stores (#1030).** Core's session lifecycle holds what
  the RP registry, the refresh-token family index and the federation index
  held, so the package drops them:
  - Removed exports: `createRedisSessionRPRegistry`,
    `RedisSessionRPRegistryOptions`, `redisSessionRPRegistryBuilder`,
    `createRedisSessionFamilyIndex`, `RedisSessionFamilyIndexOptions`,
    `redisSessionFamilyIndexBuilder`, `createRedisSessionFederationIndex`,
    `RedisSessionFederationIndexOptions`, `redisSessionFederationIndexBuilder`,
    and the client interfaces `SessionRPRegistryClient`,
    `SessionRPRegistryMultiClient`, `SessionSidSortedSetClient`,
    `SessionSidSortedSetMultiClient` and `SessionFamilyIndexClient`.
  - `makeIoredisClients` no longer returns `sessionRPRegistryClient`,
    `sessionFamilyIndexClient` or `sessionFederationIndexClient`, and the
    package no longer declares those three `ComponentMap` slots: a
    composition that fills client slots by hand drops them.
  - `redisSessionStoresModule` requires `userSessionStoreClient`,
    `subjectSessionIndexClient`, `subjectRevocationClient` and
    `sessionLifecycleStoreClient`, and provides `userSessionStore`,
    `subjectSessionIndex`, `subjectRevocation` and `sessionLifecycleStore`;
    it no longer provides `sessionRPRegistry`, `sessionFamilyIndex` or
    `sessionFederationIndex`. The RP registry's warn
    `session_rp_registry_corrupt_envelope` is gone with it.
  - The keys those stores wrote are read by nothing; step 2 of
    [Rolling out](#rolling-out-across-a-mixed-fleet) says what to delete.
- **Core's public entries no longer export 42 undocumented names** (#1234):
  tuning defaults (most `DEFAULT_MEMORY_*` sweep and size defaults —
  `DEFAULT_MEMORY_MFA_TRANSACTION_STORE_MAX_ENTRIES` stays —
  `DEFAULT_REMOTE_JWKS_*`, `DEFAULT_JWKS_*`, `LOGGED_STACK_*`), `federationGrantRedirectUriReservedParameter`,
  `resolveJwksPath`, `resolveJwksCacheMaxAge`, `readConfiguredRateLimitSpec`,
  `revokedFamilyExpiresAtMs`, and on `./testing` `makeValidFullSections`,
  among others; the pull request lists all 42. Stop importing them; for a
  tuning default, pass the value explicitly. Core's surface is pinned by
  `packages/core/public-surface.txt` (#1225).
- **BREAKING: `AppConfigSchema`, `fullSectionsSchema`, `composeConfigSchema`
  and `readTransitionalConfig` are removed (#728).** Boot parses the
  configuration once: core's sections with `CoreConfigSchema`, each module's
  section with its own schema. Hand `createApp` the configuration you
  resolved, unparsed. Read core's own section before boot with
  `readCoreSection`, and the switches a composition root chooses its modules
  by from its own files (the standalone template's `readSwitches`). A schema
  composed with `composeConfigSchema` becomes each module's `section.schema`.
- **BREAKING: `AppConfig` narrows to `CoreConfig & Readonly<Record<string,
  unknown>>` (#728).** It keeps its name and stays the type of the `config`
  slot and of `bootstrapComponents.config`; no schema stands behind it. Core's
  sections are typed as before, and every other section is `unknown`: code
  that read `config.webauthn`, `config["federation-grants"]` or
  `config["session-store"]` off the slot's type reads the module's own
  section from `deps.section`, or narrows the value where it reads it.
  `makeValidAppConfig` and `makeValidCoreConfig` on `./testing` keep their
  names and contents, typed as the literals they build.
- **BREAKING: `oauth.accessToken.expiresIn` is no longer part of any type
  or resolver.** `AccessTokenConfig` (and so `OAuthSection["accessToken"]`)
  and `AccessTokenLifetimeSource` (`@o3co/auth-provider-core`) and
  `OAuthTokenSection` (`@o3co/auth-provider-oauth`) lose `expiresIn`;
  `AccessTokenConfig.expiresIn` was required, so code that read it reads
  `resolveAccessTokenLifetime(config).defaultExpiresIn` instead.
  `resolveAccessTokenLifetime` reads `defaultExpiresIn` alone, and its
  messages and the oauth section's no longer mention the old key. On the
  testing entries, `makeValidCoreConfig().oauth.accessToken` is
  `{ defaultExpiresIn: 3600 }`, and `oauthConfigForTests({ accessTokenExpiresIn })`
  writes `defaultExpiresIn`. A configuration built by hand for a composition
  that loads `oauthEndpointsModule` captures the module's two new renamed
  variables, `OAUTH_ACCESS_TOKEN_EXPIRES_IN` and
  `OAUTH_ACCESS_TOKEN_DEFAULT_EXPIRES_IN`, as every other rename
  (`renamedVariableCaptures` on core's `./testing` builds them), or the boot
  refuses it, `environment-variable-renamed` with `state: "uncaptured"`.
- **`establishSession`** (`@o3co/auth-provider-session`) refuses a
  `userSessionStore` handed without a `sessionLifecycle`, with a `TypeError`
  before anything is written, and `EstablishSessionDeps.sessionLifecycle` is
  now `Pick<SessionLifecycle, "open" | "close">`: a rollback closes the
  record it opened. Hand it the `sessionLifecycle` slot's value.
- **`isTrustedProxyEntry`**, exported in v0.16.0, is deleted (#734).
- **`DEVICE_CODE_STORE_ABSENCE_POLICY`** is removed from core (#728). An
  enabled device grant requires a `deviceCodeStore`, and nothing declares its
  absence: `device-grant` no longer attaches the policy, and
  `device-grant.store`, the key it named, is refused
  ([Keys removed](#keys-removed)). A module of your own that attached it
  requires `deviceCodeStore` instead, or reads the slot without a policy.
- **BREAKING: core's schema declares `core` alone, and core's `reference.conf`
  sets no `oauth {}` (#1500).** `oauth {}` is the oauth module's section, its
  defaults and `OAUTH_*` bindings in the oauth package's `reference.conf`
  alone: layer every loaded package's reference with
  `moduleReferences(modules)`, as the standalone template does. A
  composition loading no oauth-package module now boots without
  `oauth.jwt.issuer` unless something wires `grantPolicy`, and binds no
  `OAUTH_*` variable. What changes for one that reads `oauth.*` through core
  without the oauth module:
  - Core reads `oauth.jwt.issuer`, the access-token lifetime keys
    (`defaultExpiresIn`, `maxExpiresIn`, `expiresIn`),
    `oauth.refreshToken.expiresIn` and `oauth.revocation.accessToken` /
    `subject`, and refuses every other key written under `oauth {}` while no
    loaded module's section is `oauth` (`oauthEndpointsModule` not loaded):
    `config-validation-failed`, one issue per path, naming the module, never
    the value — a retired key, a misspelt one, or one only that module reads
    (`oidcMode`, `nonce`, `consentPage`, …). The oauth package's
    `reference.conf` sets such keys, so a composition that loads
    `oauthAuthorizationGrantsModule` or `oauthSessionGrantModule` loads
    `oauthEndpointsModule` too. A configured `oauth.jwt.issuer` that is not a
    canonical issuer is refused the same way, at the key, so a discovery
    document, the CORS table and a session requirement's page are built on a
    canonical issuer or on none.
  - `OAUTH_REVOCATION_SUBJECT` and `OAUTH_REVOCATION_ACCESS_TOKEN` no longer
    declare an absence: a module that attaches
    `SUBJECT_REVOCATION_ABSENCE_POLICY` or
    `ACCESS_TOKEN_DENYLIST_ABSENCE_POLICY` (mfa, oauth-token-exchange,
    oauth-authorization, device-grant, or one of your own) over an unfilled
    slot refuses the boot (`component-absence-undeclared`) unless an
    oauth-package module is loaded — whose reference binds them — or
    `oauth.revocation.subject` / `oauth.revocation.accessToken =
    "unsupported"` is written in your own files. A written value counts only
    as exactly `"unsupported"`.
  - A `grantPolicy` from any source needs a canonical `oauth.jwt.issuer`
    (`checkCanonicalIssuer`: an absolute https URL, http only for loopback, no
    query, fragment, credentials or trailing slash), else
    `grant-policy-without-issuer` for a missing one, `config-validation-failed`
    at the key for one that is not canonical; it used to be held only to
    non-empty there. With no issuer, no discovery document is served, the CORS
    table guards no discovery path — `browserFacingCorsRoutes` lists none
    without an issuer, where it used to list the root forms — and a
    requirement's page is held to no issuer's origin.
  - The token lifetimes core sizes its revoking records by
    (`oauth.accessToken.*`, `oauth.refreshToken.expiresIn`) are read as
    written: an environment string no section schema coerced is refused, not
    read as a number. A host's `oauthTokenSettings` over a configuration that
    resolves no lifetime refuses the boot as `config-validation-failed`
    naming the key, and the default refresh-token family modules as
    `provides-factory-failed`, and so is the default refresh-token family
    revocation module a session lifecycle requires. The refusal names
    `OAUTH_ACCESS_TOKEN_DEFAULT_EXPIRES_IN`, which only the oauth package's
    reference binds. Without the oauth module, do one of: write the lifetimes
    as numbers in your own files (`oauth.accessToken.defaultExpiresIn`,
    `oauth.refreshToken.expiresIn`); load `oauthEndpointsModule`, whose
    reference sets and binds them; or provide a refresh-token family
    revocation of your own that reads no configuration.
  In code, `CoreConfig` loses `oauth` (`AppConfig["oauth"]` is `unknown`:
  read the oauth module's section from `deps.section`, or its settings from
  the `oauthTokenSettings` slot). On core's `./testing`, `makeValidCoreConfig`
  and `makeValidAppConfig` carry only the keys of `oauth {}` core reads (the
  issuer, the lifetimes, the revocation modes; `oauth.oidcMode` is gone), so
  they boot a composition without the oauth module; a test that loads it adds
  `oidcMode`, as the oauth package's `oauthConfigForTests` now does. Both are
  typed as written. `unreadableModuleLeaves` is stricter: a module's leaf that
  core's schema used to read first — any key of `oauth {}` — is no longer
  counted as covered, so the leaf must read the environment's string itself.
- **BREAKING: a configuration handed to `createApp` must be plain data
  (#1500).** Stage 1 takes one frozen copy of `bootstrapComponents.config`
  with `copyPlainJson` before anything reads it, and reads only the copy: a
  getter runs once. A configuration built in code that holds what JSON would
  not give back as it is — a `Date`, a class instance, a symbol's field, a
  cycle, a getter or Proxy trap that throws — is refused as
  `config-validation-failed`, naming where and never what a read threw. A
  configuration resolved from HOCON is plain data and boots as before.
- **BREAKING: `GrantDependencies` no longer carries `config` (#1500).** Its
  required slot is `keyStore`. A grant of your own that read `deps.config`
  reads the oauth module's settings from `oauthTokenSettings`, core's
  token-binding settings from `tokenBindingSettings`, and its own from its
  module's section; a module that still lists `config` in `requires` keeps
  compiling.
- **`ModuleSpec.configSchema`, the `ConfigSchema` type and `ModuleSection.at`
  are removed: a module's section is at its name** (#1478, #728, #777). A
  module reads its configuration as its own section, the top-level key named
  exactly as the module (never split on its dots), declared with
  `section.schema`. No module parses the whole configuration, and a section is
  read and written back only at its own top-level name. Core's own keys are
  under `core`, a name no module may take, so no section's write-back reaches
  them (`core.deployment.mode`, for one); `oauth {}` is the oauth module's
  section, which core's schema does not declare, and core reads `oauth.*`
  afterwards from that module's output.
  A module named after a key configuration cannot carry (`__proto__`,
  `constructor`, …) is refused, and so is a module's `relocatedFrom` naming a
  path at or under `core`. Move a `configSchema`'s keys into the
  module's section, and a section that sat at `section.at` under the module's
  name, declaring the old path in `section.relocatedFrom` so a configuration
  still setting it is refused naming the new one. A manifest that still
  carries `configSchema`, or a `section` that still carries `at` — whatever
  the value, the module's own name included — refuses boot at stage 1 with
  `module-section-path-invalid`, naming the module, the field and that the
  section is at the module's name; TypeScript refuses both at compile time.
  `ConfigValidationFailedDetails.modules` is empty when core's own parse
  refuses, and names each refused section's module with its name as
  `schemaPath`.
- **A manifest's `replicaSafety` may be a function of the module's section**
  (#1371, #728). A declaration written as `{ unsafe: true, reason }` is read
  as before. Code that reads the field off a `Module` (`module.replicaSafety.reason`)
  no longer compiles, since the field may now be a function, and the exported
  `ReplicaSafetyModuleRef.replicaSafety` widened the same way: ask
  `replicaUnsafeReason(module, section)` instead, which answers both forms
  and throws for a declaration made from the section when no section is
  given. A composition root that runs `checkReplicaSafety` itself hands it
  the parsed sections (`sections`) once any module declares from its section.
- **The session package's `sessionStoreModule` declares its replica safety
  from its own section** (#1381, #728): replica-unsafe when
  `session-store.storage.type = "memory"`, nothing for any other type. So the
  replica-safety guard refuses it by name under `core.deployment.mode = "multi"`,
  warns when the mode is unset, and says nothing under `"single"`: boot
  answers it for the section it parses. `replicaUnsafeReason(sessionStoreModule)`
  with no section, and `checkReplicaSafety` without its `sections`, now throw
  a `TypeError` naming `session-store`: pass the parsed section. A
  composition that already listed `sessionStoreModule` (which declared
  nothing) now sees memory storage under `multi` refused while manifests are
  validated, as `replica-unsafe-adapter`, where the route factory used to
  refuse it (`contribute-factory-failed`); and an unset mode now warns. The
  module no longer requires the `deploymentMode` slot: its route reads no
  mode, since the guard decides by the section the route mounts.
- **BREAKING: the session package no longer exports `extractFederationSection`**
  (#1313), and reads federation entries flat only: each enabled entry's
  `callbackURL` beside `enabled`, with no `type` defaulted to the entry's name
  and no `[type] { … }` sub-section. A key named after the type is handed to
  the type's schema like any other key (a strict schema, as every bundled
  type's is, refuses it), so session no longer refuses it as a "mixed shape".
  Read `core.federations` with core's
  `federationsOf` or `enabledFederationsOf` and take the flat keys, or
  register a type under `federationTypes`, whose factories receive the entry's
  name, its `callbackURL` and its keys as the type's schema parsed them.
- **Core's unwired MFA surface** (`createMfaRouter`, `MfaProvider`,
  `createMfaProviderFactory` and their types) is gone, and `BootErrorReason`
  loses `"mfa-partial-wiring"` (#702). MFA is `@o3co/auth-provider-mfa`.
- **Direct federation contributions** (#1314): `FederationFactory` and
  `FederationRedirectPolicyUnpairedDetails` are gone, and `BootErrorReason`
  loses `"federation-redirect-policy-unpaired"`; a federation registers
  through its type ([above](#slots-admission-and-wiring)).
- **The contract suites of the slots core fills itself**
  (`deploymentModeContract`, `tokenBindingSettingsContract`,
  `federationSettingsContract`, `outboundPolicyContract` and their
  `…ContractInput` types), new since v0.16.0 and on `./testing` in the 0.17
  release candidates, leave core's `./testing` with no replacement (#1580): no module or host provides those slots, so
  there is no provider of yours to run them over. The slots' test doubles stay.
- **The contract suites of the slots a module provides, and the session
  requirement's** (`csrfGuardContract`, `csrfTokenSignerContract`,
  `loginCompletionContract`, `loginEntryContract`,
  `sessionCookiePolicyContract`, `httpSettingsContract`,
  `oauthTokenSettingsContract`, `federationGrantPolicyContract`,
  `rateLimiterContract` and `sessionRequirementContract`, their
  `…ContractInput` types — the requirement's is `RequirementContractInput` —
  and `ContractCase`), new since v0.16.0 and on `./testing` in the 0.17
  release candidates, leave core's `./testing` for
  `@o3co/auth-provider-test-kit` (#1582, #1595): import them from there, under
  the same names, with the kit's own `ContractCase`. The slots' test doubles
  (`createTestCsrfGuard`, `createRecordingLoginCompletion` and the rest) stay
  on core's `./testing`.
- **BREAKING: each federation package ships only its type module** (#1297,
  #1299, #1300, #1301). Removed, each with the `ComponentMap` slot it
  required: `googleFederationModule` and `googleFederationConfig` from
  federation-google; `githubFederationModule` and `githubFederationConfig`
  from federation-github; `appleFederationModule` and
  `appleFederationConfig` from federation-apple; and
  `oidcFederationModule(name)`, `oidcFederationNames`,
  `readOidcFederationConfigs` and `oidcFederationConfigs` from
  federation-oidc. Compose `googleFederationTypeModule()`,
  `githubFederationTypeModule()`, `appleFederationTypeModule()` or
  `oidcFederationTypeModule()` instead, drop the module that filled the
  slot, and write each client as a
  `core.federations.<name> { type = "<type>", … }` entry with the flat keys
  its type's schema names (each package's README). The entry's name is the
  federation's, so `core.federations.google` keeps its routes under
  `/session/oauth/federation/google`; a second client of a type is another
  entry of that type. A test that handed the provider a `fetch` through the
  slot passes it to the type module instead
  (`oidcFederationTypeModule({ fetch })`, and so for each), which sends every
  upstream request of every entry of its type through it.
  - **Apple's key goes inline.** The Apple README's bridge read the key from
    the file `privateKeyPath` named; an entry takes the `.p8` file's PEM
    contents as `privateKey`, for example through an environment
    substitution (`privateKey = ${APPLE_PRIVATE_KEY}`), and refuses
    `privateKeyPath` as a key its schema does not name. An entry's
    `privateKey` is the PEM the configuration held at boot, so a key
    replaced under the type module takes effect at the next restart.
    Rotating the key without a restart (a `privateKey` getter that re-reads
    the file) and a `clientSecret` resolver remain available only through
    `createAppleProvider`, in code: a federation type of your own whose
    factory builds the provider with it
    ([Apple README](../packages/federation-apple/README.md#the-rotating-client-secret)).
- **BREAKING: token exchange reads `oauthTokenSettings`, not the
  configuration** (#1331). `tokenExchangeModule` requires the
  `oauthTokenSettings` slot and no longer requires `config` or declares a
  `configSchema`: the issuer a subject token is held to,
  and the lifetimes it mints within, are the slot's. A composition with
  `oauthEndpointsModule` changes nothing, since the module provides the slot; one
  without it fills the slot itself, or the boot is refused
  (`missing-required-component`, naming `oauthTokenSettings`).
  `createTokenExchangeGrant` takes `oauthTokenSettings`, required, in place of
  `config`, and holds it to its contract only: a caller building the grant
  outside `createApp` passes the snapshot
  `checkOAuthTokenSettings(value, config)` answers, which also holds the
  lifetimes within the configuration's. The grant no longer refuses a
  `config` setting `oauth.tokenExchange`; the boot refuses that path
  (`config-path-relocated`) wherever the module is installed, and a
  hand-built grant takes the bound as `section.maxActorChainDepth`
  ([token-exchange README](../packages/oauth-token-exchange/README.md#public-api)).
- **Rate-limit helpers** (`resolveSeededLimitSpecs`, `resolveLoginLimitSpec`,
  the per-feature prefixes and specs) are gone from core; the prefixes are
  exported by the packages that key them (#782).
- **BREAKING: `oauthTokenSettingsFrom` takes `oauth {}`, not the
  configuration (#728).** A composition that provides the `oauthTokenSettings`
  slot itself calls `oauthTokenSettingsFrom(config.oauth)` where it called
  `oauthTokenSettingsFrom(config)`.
- **BREAKING: `OAuthSection` loses `refreshToken.unknownFamilyPolicy` and
  `refreshToken.legacyRtPolicy`; both are optional in `AppConfig` and
  `CoreConfig` (#728).** The oauth module's section declares neither, and
  boot refuses either set ([Keys removed](#keys-removed)).
  Core's schema holds their shape, the same enums, and no default, and
  core's `reference.conf` no longer sets them or binds
  `OAUTH_REFRESH_TOKEN_UNKNOWN_FAMILY_POLICY`. Code that reads either key off
  `AppConfig` or `CoreConfig` handles `undefined`; a configuration built by
  hand drops both.
- **BREAKING: `legacyTypAccept` is gone from every type that carried it
  (#767).** `JwtVerifyOptions` (core's `verifyJwt` refuses a token with no
  `typ` header unless the caller passes `expectedTyp: null`, which skips the
  `typ` check altogether), `OAuthTokenSettings` and core/testing's
  `TestOAuthTokenSettingsOverrides`, the oauth package's `OAuthSection` and
  `OAuthTokenSection`, and token exchange's
  `CreateSelfIssuedAccessTokenValidatorOptions` lose it. A slot filled by
  hand drops the member; `checkOAuthTokenSettings` no longer asks for it.
  `verifyJwt` no longer reads a typ-less token's `payload.type`. Code that
  passed `legacyTypAccept: false` drops the line: the behaviour is the same
  ([Keys removed](#keys-removed)).
- **The oauth module is one value, `oauthEndpointsModule` (#728).** The
  module reads every `oauth.*` setting from its own parsed
  section; `createOAuthRouter` takes that section as `section` (typed
  `OAuthSection`), which it requires (under "Slots, admission and wiring",
  above).
- **BREAKING: the module factories that only answered a module are removed
  (#728).** List the module in their place:
  `deviceGrantModule({ config })` (`@o3co/auth-provider-device-grant`) is
  `deviceAuthorizationGrantModule`; `oauthSessionModule({ config })` and
  `oauthModule({ config })` (`@o3co/auth-provider-oauth`) are
  `oauthSessionGrantModule` and `oauthEndpointsModule`; and
  `sessionStoreModuleFor(config)` (`@o3co/auth-provider-session`) is
  `sessionStoreModule`, which declares its replica safety from the section
  boot parses; `SessionStoreModuleConfig`, the type of its argument, is
  removed with it. Each module switches or declares from its own section, so
  nothing changes but the name.
- **BREAKING: the standalone template's `storesModule` (`stores`) and
  `buildModules`' `storesModule` override are removed (#728).** The bundle
  required the whole `config`. Compose the two modules it bundled,
  `inMemorySessionStoresModule` and `inMemoryFederationTokenStoreModule`
  (`templates/standalone/src/modules.mts`), which `buildModules` already
  selects through `adapters.userSessionStores` and
  `adapters.federationTokenStore`; a test that passed the bundle sets
  those adapters instead. `BuildModulesOverrides` has no seam for a session
  store of your own any more: compose it in your own module list.
- **Signatures.** `renderFrontchannelLogoutHtml` takes
  `postLogoutRedirect: { uri, state? }` (#1096); `createDeviceCodeGrant`
  requires a `grantPolicy` key, `undefined` for none (#1169); the federation
  token route's `createRouter` throws when `refreshBufferMs` is 24 hours or
  more without a larger `maxTokenLifetimeMs` (#1060);
  `resolveRedisFederationGrantStoreOptions` takes `deploymentMode` (#773).
  Compared with v0.16.0, `FederationGrantLodgingRefused` has no `connection`
  field: read a `connection_not_configured` refusal from
  `FederationGrantConnectionNotConfigured` (#996).
- **Unions that grew.** `IssuerRejection` gains `"trailing-slash"` (#1150),
  `RedirectUriRejection` `query-name-invalid` and `reserved-parameter` (#1044);
  `FederationGrantReauthorizationResult` loses `connection_not_configured`
  (#963). An exhaustive `switch` over one needs the change.
- **BREAKING: the Redis factories of the stores that keep durable keys are
  async (#1541).** `createRedisAttemptCounter`, `createRedisSessionLifecycleStore`,
  `createRedisFederationTokenStore`, `createRedisMfaFactorStore` and
  `createRedisMfaTransactionStore` return a `Promise` of the store, and so
  does `redisFederationTokenStoreBuilder`: each resolves once the server
  passes the eviction gate (the entry under
  [Values read more strictly](#values-read-more-strictly)), and an option it
  refuses rejects rather than throws. `await` them. A client of your own
  that implements `durability()` may report the operator's assertion as
  `RedisDurability.assumeNoEviction`. `redisAttemptCounterModule` no longer
  reads the `logger` slot.

## Stores and records you implement

The records a store hands back name every field, and the ones added in this
window — `CodeData.amr`, `UserSession.authentication`,
`DeviceAuthorization.approvedAtMs`, `amr` and `authTimeMs`,
`FederationTokens.obtainedAt`, a federation-grant credential's
`effectiveExpiresAt` — are rows of
[upgrading-required-record-keys.md](upgrading-required-record-keys.md#what-changed),
with what a store of yours records and refuses. Per port:

- **`CodeRepository`.** Round-trip `amr` (#932): the `amr` `/authorize`
  vouched for, which `/token` stamps on the code's tokens. Callers of
  `createCode` pass it, `undefined` without a user-session store. A repository
  that drops it yields tokens without `amr`, and their refresh family carries
  none forward; under `MFA_MODE` (template) / `mfa.mode` `required` such a
  family is refused at its first refresh. Round-trip `authentication` as well
  (#935): the primary and `mfaAt` `/authorize` read of the session, which the
  exchange judges the code on with its `amr`, so a step-up recorded between
  `/authorize` and `/token` does not reach the exchange. Where a user-session
  store is wired, a code that carries none is refused at the exchange
  (`400 invalid_grant` `session_invalid`).
- **`UserSessionStore`.**
  - `authentication`, how the session was established
    (`UserSession.authentication`): round-trip it and
    record what `recordableSessionAuthentication` answers —
    [`UserSession.authentication`](upgrading-required-record-keys.md#usersessionauthentication).
    Implement `recordSecondFactor` (`supportsSecondFactorUpdate`), or a step-up
    asks for a new login instead.
  - `enrollmentFacts` (#836):
    [`UserSession.enrollmentFacts`](upgrading-required-record-keys.md#usersessionenrollmentfacts).
  - `authTime`: record what `recordableAuthTime(sid, authTime, now)` answers,
    never your input (#1155).
  - `renewalNonce` (#923): round-trip `UserSession.renewalNonce`, and in
    `recordSecondFactor` record the event only while the session's nonce is
    the event's `expectedRenewalNonce`, in the same atomic step, answering
    `null` otherwise. A store that drops it leaves a stepped-up session
    unbound from the cookie session it was renewed into
    ([core's `user-sessions` README](../packages/core/src/user-sessions/README.md)).
  - Run the suites in
    `packages/core/src/user-sessions/__tests__/userSessionStore.contract.mts`:
    `runUserSessionStoreContract`, and `runSecondFactorUpdateContract` if
    your store implements `recordSecondFactor`. They are not exported: copy
    the file into your store's tests.
- **A `loginCompletion` of your own** implements `renewSession` (#923), the
  renewal of a signed-in session's id a step-up finishes with: the
  [session README](../packages/session/README.md#renewing-a-signed-in-sessions-id).
- **`SessionRPRegistry`, `SessionFamilyIndex`, `SessionFederationIndex`.**
  The ports are removed (#1030, above): an adapter of your own for them has
  nothing to implement and nothing reads it.
- **`DeviceCodeStore`.** Record `approvedAtMs`, and what
  `recordableDeviceApproval({ amr, authTime }, nowMs)` answers (#1093).
- **`FederationTokenStore`.** Implement the conditional members
  `getVersioned`, `replaceIf` and `removeIf` (#1176); `update` is gone, and
  `obtainedAt` is a required key read back as a `Date` or `undefined`, never
  left out and never `null` (#1215). Run
  `federationTokenStoreConditionalContract`. Records written by v0.16.0 stay
  readable and get a generation at their first versioned read.
- **`FederationGrantStore`.** Implement `takeRotation` and `refundRotation`,
  now required members (#1032). `takeRotation` bumps the version once, in the
  same atomic step as the count, and answers the grant at the new version:
  core accepts only a grant answered at exactly the version it read plus one,
  and treats anything else as a storage outage, without asking the upstream.
  `refundRotation` gives one rotation back as the port's contract says: at the
  version the take left, for the window `since` it names, never below zero,
  bumping the version, so once per attempt. Persist `rotations`, a required
  key of the usage fields, `undefined` until the first take and reset by
  `activate`. Run the contract suite in
  `packages/core/src/federation-grants/__tests__/store.contract.mts`. It is
  not exported, and core's copy imports through core's own `#/` alias, so
  start from the Redis package's copy,
  `packages/redis/__tests__/adapters.federation-grant-store.contract.mts`,
  which imports only `@o3co/auth-provider-core`. A store without the two
  members no longer type-checks, and `federationGrantsModule` refuses to boot
  with one that lacks either.
- **`FederationGrantStore` callers** give an access token's
  `effectiveExpiresAt` on `activate` / `replaceCredentials` (#1078). A
  **`FederationGrantRefresher`** of your own reports `tokenType` (#1228); its
  `expiresAt` and `expiresIn` are read together, and the earlier one ends the
  token (#1021).
- **`UserRepository`.** A login reads the eight declared `User` fields by
  name, once, so an ORM entity or a getter-backed `User` logs in (#1100,
  #1206). A Store answers `mfaEnrolled` on both reads (#903): the
  [checklist](#store-implementer-checklist-before-switching-to-required).
- **`ClientRepository`.** Its records pass core's boundary
  ([above](#client-records-the-boundary-in-the-clientrepository-slot)).
- **`RateLimiter`.** One that declares no `failMode` fails closed, whatever
  `redis-rate-limiter.failMode` says (formerly `rateLimit.failMode`, now a
  retired path that refuses the boot); a wrapper forwards `failMode` (#782).
  It also meets a second key shape (#628): `federation_grants:client:<client_id>`,
  with `ctx.clientId` set, on a first-time federation-grant lodging, beside
  `federation_grants:ip:<ip>`. Its prefix is the same, so a limiter that
  budgets by prefix applies one budget to both; one that wants a separate
  per-client budget tells the `:client:` keys apart.
- **Redis clients of your own.** `SubjectRevocationClient` implements
  `advanceRevocationBoundaries`, and `setRevocationBoundaries` is gone (#993):
  add the method on the current release first.
  `UserSessionStoreClient` implements `replaceIfUnchanged` (#707). A
  `FederationTokenStoreClient` wrapper implements `attachRecord`,
  `readVersioned`, `replaceIfGeneration`, `removeIfGeneration`, `pExpireGT`
  and `durability` (#1176, #1149). A `FederationGrantStoreClient` implements
  `takeRotation` and `refundRotation`, now required (#1032).
  `makeIoredisClients` provides them all.
- **The MFA ports**, new since v0.16.0. An `MfaFactorStore`'s membership
  writes are `createIf`, `removeIf` and the reset `removeAllForSubject`, at
  the generation `listVersioned` answered; it has no unconditional `create`
  or `remove` (#1121, #1179, #1236). An `MfaTransactionStore` answers
  `rebindAfterMs` on every subject-recovery answer (#1238). One written
  against a 0.17 release candidate implements
  `consumeEmailProofRequirement(subject, { leaseToken })` in place of
  `consumeEmailProofRequirement(subject)`: consuming the email-proof
  requirement is checked against the subject's lease, atomically, the lease
  checked and the requirement cleared in one step. It answers
  `{ outcome: "consumed" }`, `{ outcome: "absent" }` or
  `{ outcome: "refused", reason: "lease_not_held" }`, and refuses a call
  without a lease token with a `RangeError`
  (`checkEmailProofRequirementConsume`). Run
  `runMfaEmailProofRequirementContract` beside the store's suite: copy
  `packages/redis/__tests__/adapters.mfa-email-proof-requirement.contract.mts`,
  which imports only `@o3co/auth-provider-core`. Such a store's `noteFirstBinding`
  answers the mark that stood before the note, as `firstBindingAnswer` reads
  it on the store's clock (its `atMs`, or `null` when none stood), read and
  replaced in one atomic step, in place of answering nothing; a held value
  that is not a mark is answered as an outage. Run
  `runMfaFirstBindingNoteContract` too, from
  `packages/redis/__tests__/adapters.mfa-first-binding-note.contract.mts`.
  The contracts and
  their suites are in [adapter-surface.md](adapter-surface.md#conditional-writes)
  and the [test kit](../packages/test-kit/README.md). An
  `MfaTransactionStoreClient` of your own, written against a 0.17 release
  candidate, implements `consumeEmailProof(keys, leaseToken)` in place of
  `consumeEmailProof(key)`: it removes the email-proof requirement at
  `keys.proof` only while the lease at `keys.lease` holds `leaseToken`, in one
  atomic step, and answers `{ held: false }` or `{ held: true, removed }`.
  `makeIoredisMfaTransactionStoreClient` provides it. Its
  `noteFirstBinding` answers, with a kept note, what stood before it, read
  in the same atomic step (`earlier`: `{ atMs }` for a mark whose end is
  after the server's clock, `null` for none, or `"unreadable"` for a value
  the note replaced).
- **A second factor of your own (`MfaFactor`)** answers each challenge's and
  enrollment start's `response` as a plain JSON-shaped object — no class
  instance, list or `-0`, every own key an enumerable string, at any depth —
  an `ok` that is the literal `true` or `false`, and a refusal `reason` its
  type names (#1406). Any other answer is the factor's failure: a `503`.
  `mfaFactorContract` in the test kit holds a factor to the same, and now
  fails one that answers otherwise (#1442).

## Store implementer checklist (before switching to `required`)

For the Store behind `@o3co/auth-provider-foundation`: its user endpoints,
and, where the factors are kept in it, its MFA endpoints. The wire is
foundation's README,
[The Store's MFA endpoints](../packages/foundation/README.md#the-stores-mfa-endpoints);
the rules every store with conditional writes keeps are
[adapter-surface.md, Conditional writes](adapter-surface.md#conditional-writes).
Do every item before `MFA_MODE` (template) / `mfa.mode` `optional` if you
can, and before `required` at the latest. What a missed item opens depends
on the witness. Where the witness still says the user enrolled and no
counting factor remains, the login is refused `503` under either mode
([operator runbook §3](operator-runbook.md#3-what-fail-closed-looks-like-on-each-path)).
Where a lost enrollment is not reliably witnessed — the Store answers no
witness, or one it cannot keep — a user whose factors were lost reads as
never enrolled: under `optional` a password-only login goes through, and
under `required` whoever holds the password binds a first factor.

**The enrollment witness.**

1. **Both reads answer `mfaEnrolled`**: `authenticate` and
   `authenticateByToken` alike, a boolean, left out until the subject is
   first marked (#903). A federated login records the witness from
   `authenticateByToken`; a Store that answers it on `authenticate` alone
   leaves every federated session reading "not enrolled".
2. **The Store provides the `markMfaEnrolledUrl` endpoint**
   (`REPOSITORIES_USER_HTTP_MARK_MFA_ENROLLED_URL`), which gives the user
   repository the `markMfaEnrolled` capability. Without it, boot warns once
   (`mfa_enrollment_witness_unwritable`) and nothing but the Store keeps a
   subject's factor list whole.
3. **Backfill `mfaEnrolled = true`** in the Store for every subject that
   holds a counting factor, when you set that URL
   ([foundation's README](../packages/foundation/README.md#the-witness-written-through-the-user-repository)).
4. **Run the test kit's witness contract suite in the Store's CI**
   (`mfaEnrollmentWitnessContract`): it is the only guard on
   `authenticateByToken`
   ([the suite](../packages/test-kit/README.md#the-enrollment-witnesss-contract-suite)).

**The factor store, where the factors are kept in the Store.**

5. **Conditional writes.** A factor create (`createIf`) and a single removal
   (`removeIf`) carry `expectedGeneration` and `deadlineMs`, and each is one
   atomic step in your database: applied only while the subject's factor set
   is at that generation, answered `409 { outcome: "conflict" }` otherwise,
   and answered `408` without being applied at or after `deadlineMs` on the
   Store's own clock. `expectedGeneration: null`, on a create only, means
   "only while the set is absent", and a tombstone counts as present. A
   removal answers `404 { outcome: "missing" }` for an absent set, or, at
   the right generation, for a record the set does not hold. The list answers `generation` from the same snapshot as
   `factors`, never from a cache or a lagging replica. Every membership
   write, the reset included, mints a new random generation; an update keeps
   it.
6. **A factor create or a single removal without `expectedGeneration`** is
   one the Store may refuse with `400`, as the convention does. The provider sends none
   (#1232, #1235); the only unconditional write is the reset,
   `{ subject, all: true }`.
7. **The write-lifetime bound, and the tombstone.** A write conditional on a read is valid only within the store's write-lifetime bound of that read: the bound runs from the versioned read that produced the write's expected generation to the write's commit or failure, transport and queues included. The port's owning module keeps it; callers outside it never hold a generation. An emptied set's tombstone is kept for at least that bound (`BUNDLED_STORE_WRITE_LIFETIME_MS`, 24 h, for the bundled stores).
   A Store bounds its own write commit server-side (SQL statement/transaction timeout; HTTP deadline never retried after it passes). For MFA the factor-set writer keeps the bound under its lease.
8. **No rollback.** A generation is never issued again, a failover or a
   restore included (adapter-surface rule 8). A Store either re-mints the
   generation of everything it restores, or runs so that acknowledged state
   never rolls back, and its documentation says which. Where it is the
   second, the operational assumption to state is: “this store assumes acknowledged writes are not rolled back (persistence plus a failover setup that keeps acked writes); a deployment that accepts acked-write loss on failover also accepts that a conditional write may see a restored older generation”.
   If your factor store can lose acknowledged writes on failover, a failover may restore a factor that was removed or undo a reset; after such a failover, re-run any operator reset performed in the lost window, and have affected users review their factors.
   That line is [operator runbook §5](operator-runbook.md#key-families),
   "When the factor store loses writes"; the procedure is
   [operator runbook §3](operator-runbook.md#keeping-mfa-factors-in-the-store),
   "Failover and restore".
9. **Run the factor store's suites in the Store's CI**:
    `mfaFactorStoreContract` and `mfaFactorStoreConditionalContract`, against
    `HttpMfaFactorStore` over your Store, with `second` — another adapter on
    the same Store — so the races prove the fence across processes
    ([the factor store's suite](../packages/test-kit/README.md#the-factor-stores-contract-suite),
    [the factor set's conditional writes](../packages/test-kit/README.md#the-factor-sets-conditional-writes)).
10. **The Store, and anything in front of it, answers `421` only for a
    request it did not apply**: the HTTP client may send it again.

**Timeouts.**

11. **Raise `mfa.storeTimeoutMs` together with the user repository's HTTP
    timeout** (`MFA_STORE_TIMEOUT_MS`, `REPOSITORIES_USER_HTTP_TIMEOUT`). The
    template refuses the boot while the first is below the second where the
    Store is called; above 37500 ms it is refused too.

## Turning MFA on

**To turn MFA on in production, set `adapters.mfaFactorStore` and
`adapters.mfaTransactionStore` (`ADAPTERS_MFA_FACTOR_STORE`,
`ADAPTERS_MFA_TRANSACTION_STORE`) to `redis` or `store`** — `store`, the
factors kept in the Store, is for the factor store alone, so the transaction
store is `redis`. The template's default for both is `memory`, which is
refused while MFA is on outside development and test: the start is refused,
naming each store left in `memory` and its variable, unless the
configuration's name says `development` or `test`, and so do `CONFIG_ENV` and
`NODE_ENV` wherever they are set. With no name set at all, `memory` is
refused too, and core refuses it under `CORE_DEPLOYMENT_MODE=multi` whatever
the name. A restart of a
`memory` store loses every factor, every lock and every recorded email proof,
after which whoever holds a password can bind a factor of their own.

MFA is new since v0.16.0. The standalone template now requires it by
default; a scaffold upgraded as [Your scaffold](#your-scaffold) says keeps
`MFA_MODE=off` until it is ready. Roll the whole fleet
onto this release first ([below](#rolling-out-across-a-mixed-fleet)), work
through the [Store implementer checklist](#store-implementer-checklist-before-switching-to-required)
if you run a Store, then go `optional` — users enroll at their own pace — and
`required` once most have. Switching to `required`, a live password session
of a user with no counting factor is asked to log in again, and that login
binds their first factor.

**A first factor bound without the account-email proof counts from the next
sign-in.** Where no proof is asked — no mail sender wired under `when-mail`,
an account with no address, or `MFA_ENROLLMENT_REQUIRE_EMAIL_PROOF=never` — a
user's first factor adds nothing to the sign-in it is bound in. At a login,
`POST /session/mfa/enrollment/complete` answers `200` with the factor and its
recovery codes, no `message`, and establishes no session: your login page
shows the codes, then sends the user to sign in again, with the password and
the factor just bound. From the account page the session stays as it signed
in, and codes and tokens issued from it carry its `amr` without the factor
until it steps up with the factor. A first factor bound with the proof, and
every later factor, count at once as before. MFA is new since v0.16.0, so
this is no break of a v0.16.0 surface; pre-releases of 0.17.0 counted every
first binding at once, and a page built against one that navigates to
`redirect_to` on any `200` from the completion checks `message` first
([The MFA page's contract](../packages/mfa/README.md#the-mfa-pages-contract)).

**Email factors enrolled on a 0.17.0 pre-release, for an address whose local
part has upper-case letters, are enrolled again.** The provider now keeps an
address's local part in the case the user record holds it, and lower-cases
only the domain (`normaliseMailAddress`): a code goes to the local part as it
is written, and the digest an email factor records is of that spelling. A
factor such a pre-release enrolled for `Alice@example.com` recorded the
digest of `alice@example.com`, so it now reads as `address_changed`: no
login code is sent for it. The user enrolls a replacement factor first — the
address again, or another factor — and then removes the stale one; under
`mfa.mode = "required"` removing it while it is the only counting factor is
`409 mfa_last_factor`, since neither it nor a recovery set stands in for a
usable counting factor. A user with no other usable factor gives the recent
MFA the enrollment needs with a recovery code, or an operator resets the
subject ([operator runbook §3](operator-runbook.md#multi-factor-authentication-the-lock-mail-and-notices)).
Factors for addresses whose local part is all lower case are not affected.

### The standalone template

`MFA_MODE` binds the template's own key, `mfaMode` (#1245), default
`required` (#1264). `off` installs nothing of MFA, and discovery is as it
was. `optional` and `required` install the MFA package's modules, the operator reset, the session
package's login completion and the two MFA stores `adapters` selects; declare
`mfa` in `core.sessionRequirements.expected` and name it
`core.sessionRequirements.secondFactorAuthority`; write `mfa.mode`; and add
`"urn:o3co:acr:mfa" = ["mfa"]` to the acr table unless yours writes it.
Turning it on — or leaving the default on — needs:

- **Durable MFA stores**, [above](#turning-mfa-on).
- **`MFA_ENCRYPTION_KEY`**, canonical base64 of 32 bytes
  (`openssl rand -base64 32`). In development, write your own key in
  `config/development.conf` rather than exporting it beside the sample key.
  The sample key is accepted only in an explicit development or test
  environment: the name the configuration was selected by and `NODE_ENV`,
  each where set, must say `development` or `test`, and at least one must be
  set. A composition that uses the sample key outside an explicit development
  or test environment — under another name such as `prod` or `local`, or
  under no name at all — refuses to boot. Some pre-release builds accepted
  it there.
- **`MFA_PAGE_URL`** (default `/mfa`): your MFA page, on the issuer's origin.
  The template ships none; what it keeps is
  [The MFA page's contract](../packages/mfa/README.md#the-mfa-pages-contract).
- **SMTP**, outside development: `STANDARD_SMTP_MAIL_SENDER_HOST` and
  `STANDARD_SMTP_MAIL_SENDER_FROM`, with `_PORT`, `_SECURE`, `_USER` and
  `_PASSWORD` as your relay needs.
- **`MFA_STORE_TIMEOUT_MS`** at least `REPOSITORIES_USER_HTTP_TIMEOUT` where
  the Store is called, and `REPOSITORIES_USER_HTTP_MARK_MFA_ENROLLED_URL` with
  `ADAPTERS_USER_REPOSITORY=http`.

Outside development, a deployment that sets none of these is refused before
boot, by the first of them, the stores: the refusal names each store,
`MFA_ENCRYPTION_KEY`, the SMTP relay, `MFA_PAGE_URL` and `MFA_MODE=off`.
In development (`make dev`) the default needs nothing more: the sample key in
`config/development.conf`, the sender that logs each code, and
`docker-compose.yml`'s Redis for the two stores; your MFA page is still yours
to serve.

Install MFA only through `MFA_MODE`: do not add its modules to
`buildModules`, and do not write `mfa.mode`, a contradicting `mfaMode`, or a
`secondFactorAuthority` other than `mfa`. The variables and what each refuses
are the template README's
[Multi-factor authentication](../templates/standalone/README.md#multi-factor-authentication).

### A composition of your own: the port checklist

1. Add `@o3co/auth-provider-mfa`, and `@o3co/auth-provider-standard` for
   mail, to `package.json`.
2. Port the template's MFA switch (`src/mfaSwitch.mts` and its calls in
   `configPath.mts` and `buildModules.mts`), or install what the
   [MFA README's Installing](../packages/mfa/README.md#installing) lists. Port
   the configuration with its `${?…}` lines: the `mfa` section
   ([its keys](../packages/mfa/README.md#configuration)); the
   `core.sessionRequirements` block, `expected` naming `mfa` and
   `secondFactorAuthority = "mfa"`; the two MFA store selections; the acr
   table. The page is `mfa.page.url` (`MFA_PAGE_URL`): `endpoints.mfa.url` and
   `ENDPOINTS_MFA_URL`, which some pre-release builds read, refuse the boot.
3. Set `MFA_ENCRYPTION_KEY`, and `STANDARD_SMTP_MAIL_SENDER_*` where mail is
   sent. The development sample key boots only where `mfaModule({ environment })`
   and `NODE_ENV`, each where set, say `development` or `test`, with at least
   one set. There is no `MFA_NOTICES`: notices to the account holder are yours,
   built from the audit events
   ([operator runbook §3](operator-runbook.md#multi-factor-authentication-the-lock-mail-and-notices)).
4. Make the Redis the factor store uses durable; give the Store `mfaEnrolled`
   and `markMfaEnrolledUrl` ([the checklist](#store-implementer-checklist-before-switching-to-required)).
   With the factors in the Store, keep the Store transport's `timeout`
   (`repositories.user.http.timeout`, which the user repository shares) at
   most 85 500 000 ms: `HttpMfaFactorStore` refuses a larger one at
   construction with a `RangeError`, and `foundationMfaFactorStoreModule`
   refuses the boot ([foundation's README](../packages/foundation/README.md#constructor-validation)).
5. Teach the login page `403 mfa_required` / `mfa_enrollment_required`; build
   the MFA page and the account page.
6. Teach BFFs using the `session` grant its `step_up` member, and the
   device-verification page `403 step_up_required` with its `requirement`;
   install `webauthnSessionSubjectModule` in place of a `req.webauthnSubject`
   middleware of your own.
7. Decide `trustUpstreamAmr` per federation.
8. Set `mfa.mode = "optional"`; move to `required` later.

## Rolling out across a mixed fleet

**A rolling upgrade from v0.16.0 is not supported: upgrade the fleet in one
coordinated step, with no mixed fleet** (#1030). v0.16.0 records the relying
parties and refresh-token families a session joins in the per-session stores
(`sessionRPRegistry`, `sessionFamilyIndex`, `sessionFederationIndex`); this
release records them in the session's lifecycle record and ends a session
from that record alone. A v0.16.0 replica serving beside this release, for
example redeeming a code a new replica issued, writes what it hands out where
this release's logout does not look: that logout tells no relying party of it
and leaves its family unrevoked. So:

1. Stop every v0.16.0 replica, draining its traffic.
2. With none running, you may delete the keys of the three per-session
   stores v0.16.0 wrote; this release reads none of them, and each expires
   with its session if left. Delete by prefix (`SCAN MATCH <prefix>*`, then
   `UNLINK` what it returns), never with `FLUSHDB` or `FLUSHALL`: the same
   database holds keys this release reads, the MFA factors among them, whose
   loss cannot be undone. With the shipped prefix
   (`redis-session-stores.keyPrefix` `ss:`;
   [operator runbook, Key families](operator-runbook.md#key-families) lists
   the keyspace):

   | Keys | What they held |
   | --- | --- |
   | `ss:rp:*`, `ss:fi:*`, `ss:fi-ended:*`, `ss:fed:*` | v0.16.0's RP registry, refresh-token family index (and its "ended" marks) and federation index, whose adapters `@o3co/auth-provider-redis` no longer has |

   **Never delete the refresh-token family records (`rtfam:*`).** A revoked
   family's record is what keeps the access tokens issued under it refused:
   a family with no record reads as not revoked, so deleting one would let
   an unexpired access token it revoked pass introspection and token
   exchange again. Leave them to expire on their own. The upgrade needs
   nothing of them: every refresh token bound to a v0.16.0 session is
   refused at admission anyway
   ([every user signs in again](#passkeys-users-and-sessions)), and a
   refresh token without a `sid` is not affected by the upgrade: no logout
   ever reached it, and the subject's revocation boundary
   (`revokeAllForSubject`, which a password reset calls) or its expiry ends
   it, as before.
3. Start this release on every replica, every package at the same release.

What carries across the step:

- **Upgrade every package together, onto the same release:** core and every
  adapter package at one release in each replica.
- **Move the access-token default before the upgrade.** v0.16.0 already reads
  `oauth.accessToken.defaultExpiresIn` and `OAUTH_ACCESS_TOKEN_DEFAULT_EXPIRES_IN`
  first, so on v0.16.0: write the value at the new key, export the new
  variable at the value the old one carries, then delete the old key and
  unset the old variable. This release refuses the old key at any value, and
  the old variable while it is set, beside the new one or not. Move the value
  rather than deleting it: without it, the default is `3600`.
- **The federation-grant rotation budget counts from the upgrade** (#1032).
  v0.16.0 took no rotation, so the refreshes it made are not counted against
  a grant's budget.
- **Codes do not cross the step.** A code v0.16.0 issued and nobody redeemed
  names a session with no lifecycle record and carries no `authentication`,
  so its exchange is refused, and the relying party authorizes again.
- **Keep `MFA_MODE` (template) / `mfa.mode` off for the first start**, as
  [Your scaffold](#your-scaffold) says, and turn it on as
  [Turning MFA on](#turning-mfa-on) says.
- **Fix the client records the boundary refuses before the upgrade.** From
  it, such a client is answered `503`
  ([above](#client-records-the-boundary-in-the-clientrepository-slot)).
- **Federated sessions** live at the upgrade stamp `["fed"]` until the user
  logs in again ([operator runbook §7](operator-runbook.md#before-you-upgrade),
  step 3).
- **Redis.** Records v0.16.0 wrote stay readable: a federation token record
  gets a generation at its first versioned read, and one without `obtainedAt`
  reads it as `undefined`, which is refreshed within the buffer. Scripts
  whose text changed load by `EVAL` on `NOSCRIPT`. The per-session keys
  v0.16.0 wrote beside its sessions are the exception: nothing reads them
  (step 2 above).

