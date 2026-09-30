# Adapter surface contract

Every capability this library does not implement itself is a **typed component
slot**: a named entry in `ComponentMap` with a declared interface, filled by a
composition root and consumed by whichever modules declare it. This document is
the one place that lists them, says what each is for, and states the boundary
that decides what may become one.

A port's slot is one of four ways a package changes the provider — the
adapter axis, beside plugins, capabilities and extensions. Not every slot below
is a port's: the boot infrastructure, the synthetic keys the contribution kinds
are read through, and hook slots such as `grantPolicy` are listed too.
[AGENTS.md](../AGENTS.md#extension-surface-four-axes) names the four axes, and
the question that picks one for a new policy: does more than one owner add to
the same decision?

It is enforced, not aspirational: `packages/core/src/__tests__/adapterSurface.drift.test.mts`
checks both directions — every slot declared in source appears here, and every
slot named here still exists. A slot added without an entry fails that test.

## The boundary: verify-only

Adapter freedom applies **within** authentication and token issuance. It is not
a licence to grow the responsibility.

`UserRepository` is the clearest case, and the shape of the rule. It is
`authenticate` / `authenticateByToken`, plus optional members for the flows this
library drives. Creating users, changing passwords, flipping verification
state, linking a device to a user, upgrading an anonymous identity to a
registered one — all of that belongs to the Store, and for all of it the library
only ever *reads the result*. The two exceptions are below.

`linkFederatedIdentity` (#482) is one of two calls through which the library
causes a write, and it passes the document's own test: the `?link=1` flow is one
this library drives end to end, so the flow needs the seam. What still holds is the
part that matters — the **Store decides**. The library relays the verified
identity and the session it is bound to, and relays `refused` / `conflict` back
unchanged; it never merges accounts, never links implicitly, and never links on
an unverified or relay e-mail on its own authority. Three call sites already say
so where the temptation is highest:

- `grants/emailVerifiedGate.mts` — the Store "issues the token, delivers it, and
  flips the state; this library only reads".
- `repositories/types.mts` — "Issuing the verification token, delivering it, and
  flipping…" is not this library's.
- `user-sessions/revokeAllForSubject.mts` — the Store issues the reset token,
  delivers it, writes the new credential, and *then* calls in to invalidate what
  was already minted.

`markMfaEnrolled` is the other, the MFA enrollment witness (the MFA ADR's
D12), and it passes the same test from the opposite side. Enrollment, removal
and the operator reset of a second factor are this library's own flows, end to
end, so here **the provider decides and the Store only persists**: after the
first counting factor is written the provider marks the subject enrolled, and
after the last is removed it clears the mark — in that order, so a crash leaves
a factor without a witness, never a witness without a factor. The Store answers
the mark back as `User.mfaEnrolled` on `authenticate`, read only through
`readMfaEnrollmentWitness`: a value that is neither a boolean nor absent is
malformed, answered `503`, and never read as "not enrolled". Why it is a Store write at
all: the witness has to survive the factor store it vouches for. A factor store
that loses its records — a Redis restarted without persistence, an eviction, a
restore from an old backup — would otherwise read as "never enrolled", and every
affected account would accept a first binding from whoever holds its password.
A repository without the capability (`supportsMfaEnrollmentWitness`), and a
Store that answers no field, leave the witness absent; the factor store's
durability is then the whole defence.

`revokeAllForSubject`, the last of the three call sites above, is the pattern
for anything that looks like it needs a new slot: the library is downstream of
the action, never the one taking it. **Message
delivery is the worked example of where the line falls.** The one flow this
library drives end to end that must send is multi-factor authentication: the
one-time codes of its email factor and proof, and the security notices it owes
a user whose factors changed (the MFA ADR's D5). So there is a delivery port,
`mailSender`, and it is that narrow: a rendered message — one recipient, a
subject, plain text — handed to whatever delivers it. Templates, links, sign-up,
password reset and account recovery by e-mail stay the Store's and the
deployment's; a deployment that delivers through its own mail service implements
`send` and nothing else. Full IdPs ship more because they own the flows that
send; this library owns only these.

The line also cuts the other way, and `assertionVerifier` is the example. A
device presenting a signed credential *is* an authentication modality, so
verifying possession belongs here — but resolving that credential to a person
does not. The RFC 7523 grant (#301) verifies, then hands an opaque handle to
`authenticateByToken` and takes whatever subject the Store returns. Device
registration, device→user linking and anonymous→registered continuity stay
outside; the provider never learns they happened.

Before adding a slot, the question is not "could this be pluggable" but "does a
flow *this library owns* need it". If the answer is that an operator's component
would call it, the slot belongs in the operator's composition, not here.

## Two tiers

Slots come in two layers, and conflating them is how a vendor ends up in
everyone's dependency closure.

**Component slots** are what modules consume — `KeyStore`, `RateLimiter`,
`AuditSink`. They are vendor-neutral by construction: the interface says what the
capability is, never who provides it.

**Client slots** are what a *specific adapter package* needs from a driver —
`accessTokenDenylistClient`, `sessionRPRegistryClient`. They exist so
`@o3co/auth-provider-redis` can be handed one ioredis socket and build every
store on it, rather than opening a connection per store. A core module never
requires one.

## Boot infrastructure

Not adapters. These are the boot machinery every composition has.

| Slot | Type | Wiring | Declared in | Purpose |
| --- | --- | --- | --- | --- |
| `config` | `AppConfig` | required | `core/boot/types.mts` | The parsed application config. Every module that reads a knob requires it, until it declares its own section in its manifest (`section`, #728): boot parses that section out of this config and hands it to the module as `deps.section`, which is not a slot. |
| `lifecycleRegistrar` | `LifecycleRegistrar` | required | `core/boot/types.mts` | Where a component registers its shutdown work, so `dispose()` drains in reverse-topological order. |
| `logger` | `Logger` | optional | `core/logging/Logger.mts` | Structured logger. Optional to wire; bundled modules fall back to a console logger rather than going silent. |
| `pathResolver` | `PathResolver` | required | `core/boot/types.mts` | Resolves a package-relative path (normally `import.meta.resolve`), so `reference.conf` is found without assuming a layout. |
| `readinessRegistrar` | `ReadinessRegistrar` | required | `core/boot/types.mts` | Where a component registers a readiness probe. Distinct from liveness: this answers *can it serve*, not *is it up*. |

## Synthetic keys

Assembled by the boot planner from module contributions rather than supplied by
a composition root. Listed because a module may `require` them. `deploymentMode`
is a synthetic key too, but boot derives it from the configuration's
`deployment.mode`, not from contributions: it is listed with the settings slots,
under [What one module owns and others read](#what-one-module-owns-and-others-read).

| Slot | Type | Wiring | Declared in | Purpose |
| --- | --- | --- | --- | --- |
| `federationRedirectPolicyResolver` | `ReadonlyMap<string, FederationRedirectPolicy>` | optional | `session/federations/contributes.mts` | Synthetic key: the assembled per-federation `redirect_to` policies. |
| `grantHandlerResolver` | `GrantHandlerResolver` | optional | `core/modules/manifest/synthetic-keys.mts` | Synthetic key: the assembled grant registry, resolved from every module's `contributes.grants`. |
| `mfaFactorResolver` | `MfaFactorResolver` | optional | `core/modules/manifest/synthetic-keys.mts` | Synthetic key: every second factor contributed as `contributes.mfaFactors`, by kind. A factory that answered `null` (the factor switched off by its configuration) claims its kind and is absent from the resolver. In place before the `provides` factories run and filled as the contributions register, so a factory that runs earlier holds it and reads it later — the MFA package's `mfa` requirement reads it for its `reach`, which core reads once every factor has registered; a read while the provides factories run refuses the boot. A factor whose `kind` is not its key refuses boot. |
| `rateLimitBudgetResolver` | `RateLimitBudgetResolver` | optional | `core/modules/manifest/synthetic-keys.mts` | Synthetic key: every rate-limit budget contributed as `contributes.rateLimitBudgets`, by prefix (#728) — the default limit and window each module reads from its own settings for the prefixes it keys. A module claims every prefix it keys, with a budget or with `null` (no budget of its own, or one its settings switch off): a `null` prefix is absent from the resolver yet claimed, and two modules contributing one prefix refuse boot (`duplicate-contribute`), so none can claim another's. A budget that is not a positive whole limit and a window of at most a year (`isBoundedRateLimitSpec`, independent of the clock), a prefix no key can carry, and an override that loosens the budget it replaces — a higher `limit` or a shorter `windowSeconds`, a `null` side counting as the wired limiter's `defaultLimit`, and refused when none is declared — fail their contribution. Boot logs `rate_limit_budgets_registered` with each prefix, its contributed budget and the module that set it; a limiter's own `limits` entry wins over that budget and is not shown. Read at request time, like every projection: a read while the provides factories run refuses the boot. Both bundled limiter modules require it and read it through `createRateLimitBudgetLookup` (`core/ratelimit/budgetLookup.mts`), reading each budget it answers once into a frozen copy and checking it: the limiter's own `limits` entry for a prefix wins over a contributed budget, and a prefix with neither falls to its `defaultLimit`. The device grant requires it too, and refuses boot unless the contributed `device_verification` budget, after any override, is its configuration (a limiter's own entry is not compared); WebAuthn reads it for its mismatch warning. Each package's README names the prefixes it claims. |
| `sessionRequirementResolver` | `SessionRequirementResolver` | optional | `core/modules/manifest/synthetic-keys.mts` | Synthetic key: every session requirement contributed as `contributes.sessionRequirements`, by name, in registration order (the session-admission ADR's D3) — what every consumer of session admission requires, and what `admitSession` reads the requirements through — and every action contributed as `contributes.admissionActions`, by name (`action(name)`), which `admitSession` reads an action's grade from. A grade is its registering module's own statement; `grants_nothing` exempts an admission a record carries (a cookie, a code, a link) from the MFA requirement's baseline — a token is judged on its own `amr` whatever the grade — and the boot line `admission_actions_registered` names each action's grade and module. Branded by the planner: `admitSession` refuses any other object, and `resolverForTests` (`@o3co/auth-provider-core/testing`) is the one other builder. Neither overridable nor replaceable: an `overrides.sessionRequirements` entry, and a host `contributionKinds` collector for it or for `mfaFactors`, are refused at stage 1 (`session-requirement-kind-guarded`). A composition that installs a consumer declares what it expects in `sessionRequirements.expected`, compared as a set with what registered at the end of stage 4. |
| `tokenExchangeValidatorResolver` | `TokenExchangeValidatorResolver` | optional | `core/modules/manifest/synthetic-keys.mts` | Synthetic key: the assembled RFC 8693 subject/actor token validators. |

## What one module owns and others read

A key several modules read has one owner (#728): the owning module parses its
own section and provides what the others need through a slot whose contract is
core's, and they require the slot instead of reading the owner's section — in
code a package imports only core. Each contract ships a suite on
`@o3co/auth-provider-core/testing`, which the owner's tests run over what it
provides, and all but `deploymentMode` a test double there, which a reader's
tests fill the slot with instead of importing the owner's package. The session
package's modules provide theirs: the session module `loginEntry` and
`csrfGuard`, the login-completion module `loginCompletion`, the session store's
module `sessionCookiePolicy` and `csrfTokenSigner`. The oauth module provides
`oauthTokenSettings`, and the standalone template's `http` module
`httpSettings`. Core fills `deploymentMode` itself, from the configuration's
`deployment.mode`, and reserves the key.
The settings slots a module provides — `oauthTokenSettings`, `httpSettings`
and `sessionCookiePolicy`; not `deploymentMode`, which no module provides — are
authoritative for their owner: the owner names each in
`authoritative`, and while the owner is loaded no composition may substitute
it — boot refuses an `overrideComponents` entry for it
(`authoritative-component-overridden`), since the owner's own code reads its
section and a second source would split what its readers see; a composition
without the owner fills the slot itself. The oauth module names
`oauthTokenSettings`, the session store's module `sessionCookiePolicy` and
the standalone template's `http` module `httpSettings`.

`rateLimit.failMode` sits in core's `rateLimit` block and is read by
`redisRateLimiterModule` alone, as the outage policy of the limiter it builds;
the guard reads the policy from the wired limiter, never from the key.

| Slot | Type | Wiring | Declared in | Purpose |
| --- | --- | --- | --- | --- |
| `oauthTokenSettings` | `OAuthTokenSettings` | optional | `core/token-settings/types.mts` | What other modules read of the oauth module's token settings, resolved and frozen: the canonical issuer, `legacyTypAccept`, the access-token default and max, the refresh-token lifetime, whether resource indicators are enforced, and `requireEmailVerified`. Provided by the oauth module (`oauthTokenSettingsFrom`, `oauth/tokenSettings.mts`), eagerly: filled whenever the module is installed, so core's machinery reads it too. The module names it `authoritative`: while it is loaded an `overrideComponents` entry for the slot refuses boot (`authoritative-component-overridden`), and a composition without it fills the slot itself. Read, when the composition holds it, by `device-grant`, `dpop`, `federation-grants`, `mfa` (the TOTP issuer's default), `oauth-token-exchange`, `webauthn`, the subject revocation service's horizon, and core — the discovery document's issuer and the CORS table's discovery paths, a session requirement's page. Each lists it as optional and reads the configuration when no module provides it, as before: every one of them runs in a composition without the oauth module. A slot a composition holds is read whole, never a member of it beside the configuration: each reader holds it first to what readers read with core's `checkOAuthTokenSettings`, which refuses a member a hand-filled slot lacks or gets wrong, naming it (`oauthTokenSettings.<member>`), rather than letting `undefined` stand for it. A held slot, whoever provides it, names no lifetime longer than the one core resolves from the configuration: the refresh-token family modules and the subject revocation boundary size their retention from that value and cannot read the slot, so `checkOAuthTokenSettings` refuses a longer access-token maximum or refresh-token lifetime, naming the member and both values, and boot refuses a host map's at stage 1 (`token-settings-lifetime-exceeds-configuration`). The oauth module resolves its lifetimes with the same resolvers, so its value never exceeds them. Still read from the configuration: the stage-1 grant-policy issuer check, which runs before any provider, and the default refresh-token family modules' horizon. The planner's graph is module-level, so no module in the oauth module's dependency set — the providers of its `requires` and its `optional` keys, and what those depend on — can read the slot without a cycle: the revocation module is one, since the oauth module reads the `refreshTokenFamilyRevocation` it provides; the rotation module is not, and reads the configuration beside it on purpose, so that the two retain a revoked family for the same horizon. Providing the slot from a module that depends on none of them would lift the constraint, and is left for later. Not in it: the token-binding settings — the dispatch policy and `bindConfidentialClientRefreshTokens` — which apply across every mechanism at core's token-binding extension point and so are core's, the point's owner: core reads them from the configuration with its one reader of the section, `resolveTokenBindingSettings`, in every composition — boot the policy, the oauth and WebAuthn grants the binding rule; the contract refuses a value that carries either, and where the keys live, `oauth.tokenBinding.*` today, is for the move of the configuration. Nor `requireGrantTypeAllowlist`, which only the oauth module reads, nor the revocation modes, `oauth.revocation.accessToken` and `.subject` — the declarations core's declared-absence guard reads for the policies `oauth-token-exchange`, `session` and `webauthn` attach as well as oauth (the absence table below), at validation, before any provider runs, so a slot cannot serve them; where they live once `oauth {}` is the oauth module's alone is for that move. Suite `oauthTokenSettingsContract`, double `createTestOAuthTokenSettings`. |
| `loginCompletion` | `LoginCompletion` | optional | `core/session-admission/login-completion.mts` | The tail of a login (the session-admission ADR's D5): the session package's `establishSession` and `answerInterruption`, with what the provider holds — the session stores, the session's lifetime, the CSRF mechanism — out of their arguments. A requirement's completion (the MFA package's, after `resumePrimary`) is to require it instead of importing `packages/session`. Provided by the session package's login-completion module (`session/modules/loginCompletionModule.mts`), over the session stores and the `csrfGuard` it requires, and `session.maxAge` — its own module because it answers with the deployment's guard, whoever filled the slot, and the session module cannot require a slot it fills itself. Each refuses, before the session is touched, an `Establishment` or interruption core did not build; every outage is reported to the caller's reporter once and leaves the browser not signed in. The interruption's `403` carries a fresh token from the deployment's `csrfGuard` (the MFA ADR's D27); `establishSession` leaves the answer, and the token on it, to its caller. Suite `loginCompletionContract` (with `records`, what a call writes; with `csrfCookieName`, the `403`'s token), double `createRecordingLoginCompletion`. |
| `loginEntry` | `LoginEntry` | optional | `core/browser-session/types.mts` | The deployment's login page and how a browser that is not signed in is sent there to come back: `urlFor(returnTo)` adds `redirect_to`, the target encoded whole, to the page's own query, before any fragment; a page whose query already carries `redirect_to` is refused (the provider refuses it when built, oauth's configSchema for its fallback). Provided by the session module from `endpoints.login.url` (`session/login-entry.mts`): built when no page is configured, and failing where the page is read. The federation-grants connect flow requires it once grants are enabled; `/authorize` sends its login trips through it when a module provides it and reads `endpoints.login.url` otherwise, since the oauth module boots without the session module. Suite `loginEntryContract`, double `createTestLoginEntry`. |
| `csrfGuard` | `CsrfGuard` | optional | `core/browser-session/types.mts` | The one policy for whether a browser may change state, in its two forms. **A request** (`check`, `middleware`): a foreign `Origin` — or, without one, `Referer` — is refused whatever else the request carries, this origin or a trusted one is accepted, and with neither a signed double-submit token decides, echoed in `headerName` or in `bodyField` of a form body. **A navigation that starts a flow** (`checkNavigation`, the link start's GET): `Sec-Fetch-Site` `same-origin` or `none` accepted, `cross-site` refused, otherwise the `Origin` or `Referer` decides, and a token never counts. `issue` sets a fresh token in a cookie as the session cookie is set. Provided by the session module (`createSessionCsrfGuard`, `session/csrf.mts`): `middleware` is the guard `/session/login` runs, with its `403` and its `csrf_origin_rejected` / `csrf_token_rejected` lines; `check` is its rule as a verdict and writes nothing, so a route that asks it answers and logs a refusal itself; `checkNavigation` is the account-link start's rule, and `bodyField` is `csrf_token`. Required once their feature is enabled by device verification, which runs `middleware`, and by federation grants, whose consent answer asks `check`, answers a refusal in its own vocabulary (`403 invalid_request`) and logs it (`federation_grant_consent_csrf_refused`). The token's signing key is derived from `session.secret`, which the session store's module owns: the guard signs and checks the token through `csrfTokenSigner`, and the session routes through the same signer: a token the guard issues passes the routes' check, and one the routes issue passes the guard's. Neither reads `session.secret`. A token is well signed only when the signer's `verify` answers `true` (a promise, another truthy value or a throw is a refusal), and one expiring more than `session.csrf.ttlSeconds` and 60 s of clock skew ahead is refused. Suite `csrfGuardContract` (a token's expiry only when the provider takes a clock, `withClock`), double `createTestCsrfGuard`. |
| `csrfTokenSigner` | `CsrfTokenSigner` | optional | `core/browser-session/types.mts` | The CSRF token's signature: `sign(payload)`, a base64url signature of `CSRF_SIGNATURE_MIN_LENGTH` (22 characters, the fewest that carry 128 bits) to `CSRF_SIGNATURE_MAX_LENGTH` (512, far inside a cookie) characters, both exported by core, the same for the same payload, and `verify(payload, signature)`, compared in constant time and never throwing. The key has one owner — the module that owns `session.secret`, the session store's — and is derived from the secret for this purpose alone, so a token's signature is never a session cookie's. The derivation is the owner's, not the contract's: providers that derive differently do not verify each other's tokens, so a switch between them invalidates the short-lived tokens outstanding, and a provider that must keep verifying an earlier one's pins the derivation in its own tests; neither the secret nor the key leaves the signer, a plain object (its prototype `Object.prototype` or `null`) that carries `sign` and `verify` alone, own or inherited, and is frozen. Provided by the session store's module (`createSessionCsrfTokenSigner`, `session/csrf-token-signer.mts`): HKDF-SHA256 over `session.secret`, no salt, info `o3co.auth.provider/session-csrf/v1`, 32 bytes, then HMAC-SHA256, base64url — pinned by literal vectors, so a token verifies for as long as the secret is kept, across a deploy in either direction: a token issued before the deploy verifies after it, and one issued after it verifies under the release it replaced. `createSessionCsrfTokenSigner` holds the secret to core's entropy floor (`assertSecretEntropy`, naming `session.secret`). Not named `authoritative`: an `overrideComponents` entry replaces it, and when the override derives its key differently, tokens the store's signer issued stop verifying. The session package's `createCsrfProtection` probes the signer it is built with — two payloads, their signatures and their length bounds, a changed signature and another payload's — and refuses one that breaks the contract, an asynchronous one included, so the session module refuses at boot; it reads `sign` and `verify` off the signer once, so a signer object changed afterwards changes nothing it mints or accepts. Required by the session module, whose `csrfGuard` and `/session/*` routes sign and check through it and read no `session.secret`; a composition that loads the session module without the session store's fills the slot itself — `createSessionCsrfTokenSigner(secret)` signs as the store does — or boot refuses it (`missing-required-component`). Suite `csrfTokenSignerContract` (with `other`, a signer built with another key; with `sessionSecret`, the check that the signature is not an HMAC under the secret itself), double `createTestCsrfTokenSigner` (a random key). |
| `sessionCookiePolicy` | `SessionCookiePolicy` | optional | `core/browser-session/types.mts` | The session cookie's attributes — name, `secure`, `sameSite`, domain and the session's lifetime — for a module that sets a cookie of its own beside the session's, or sizes what must outlive a session: the subject revocation service sizes its horizon from `maxAgeMs` when the composition holds the slot, and from `session.maxAge` when not. Named for the session cookie, not the CSRF token's. Held to what browsers keep: `sameSite: none` and a `__Secure-` name only secure, a `__Host-` name only secure and host-only (either prefix in any case), a domain a cookie can carry (a host name, one leading dot allowed). The session cookie's signing secret is not in it. Provided by the session store's module, which owns the session cookie (`session/session-cookie-policy.mts`), built once per section; the store's route mounts its cookie from the same value, so a new session's cookie is the slot's. A section that would break the contract is refused at config validation (`config-validation-failed`, the issue naming `session.name`, `session.domain`, `session.secure` or `session.maxAge`), whatever the composition installs. The module names it `authoritative`: while it is loaded an `overrideComponents` entry for the slot refuses boot (`authoritative-component-overridden`), since the store would go on mounting the cookie `session.*` describes; a composition without it fills the slot itself. The subject revocation service lists it as optional, which is enough for the planner to start its provider. Suite `sessionCookiePolicyContract`, double `createTestSessionCookiePolicy`. |
| `httpSettings` | `HttpSettings` | optional | `core/deployment/types.mts` | What every module's HTTP behaviour depends on of the `http` module's settings: `trustProxy` — which forwarding hops `req.ip` and `req.protocol` trust — and the CORS origins core's middleware lets read the token, userinfo, revocation, discovery and JWKS responses. Provided by the standalone template's `http` module (`templates/standalone/src/modules.mts`), from its `http {}` section and the list its `cors` module parses from `cors {}`, eagerly, and named `authoritative`. Core's CORS middleware reads the slot's origins when the composition holds it — read once, each held to the contract's rule, a slot that breaks it refusing the boot with a `RangeError` naming the member and the index — and `cors.allowedOrigins` from the configuration when it holds none, since core runs in compositions without the `http` module (`core/boot/http-settings.mts`); it reads nothing else of the slot. The template's host process applies `trustProxy` to Express from the slot. Suite `httpSettingsContract`, double `createTestHttpSettings`. |
| `deploymentMode` | `DeploymentMode` | optional | `core/deployment/types.mts` | How many replicas the operator says run: `single` or `multi` as `deployment.mode` states it, `unset` when it states nothing. Filled by core for every composition, before any provider runs, with its one reading of the key (`deploymentModeOf`, `core/deployment/mode.mts`) — the value the replica-safety guard decides by too. A synthetic key: a module that provides it, and a `bootstrapComponents` or `overrideComponents` entry for it, refuse boot (`synthetic-key-collision`). Required by every module that refuses or warns by the mode, each because it refuses under `multi` and a mode read as absent would lift that: the session module (the `/session/login` throttle's per-process fallback), the session store's module (memory storage), `webauthn` (the authentication/options throttle's fallback), the Redis federation-token and federation-grant stores (the plaintext guard), `mfa` (the development sample key). None of them reads `deployment` off the configuration, and each holds the value it is handed to `checkDeploymentMode` (`core/deployment/mode.mts`): anything but the three values, absence included, is a TypeError naming its source. A composition root that builds one by hand passes `deploymentModeOf(config)`, which core exports — the Redis grant store's `resolveRedisFederationGrantStoreOptions` takes it as its third argument, and the token store's `createRedisFederationTokenStore` and `redisFederationTokenStoreBuilder` as their required `deploymentMode` option. Suite `deploymentModeContract`, which core's tests run over what it fills; a reader's test fills the slot with the literal. |

## Component slots

| Slot | Type | Wiring | Declared in | Purpose |
| --- | --- | --- | --- | --- |
| `accessTokenDenylist` | `AccessTokenDenylist` | optional | `core/access-token-denylist/types.mts` | RFC 7009 access-token revocation by `jti`. Absence must be declared (#375). |
| `consentStore` | `ConsentStore` | optional | `core/consents/types.mts` | What an end-user agreed a client that is not first-party may obtain, read by `/authorize` and written by `POST /oauth/consent`. Absent, such clients are refused as before #527 — nothing to declare. Bundled adapters: memory (single replica) and Redis (`redisConsentStoreModule`, #561). |
| `pendingConsentStore` | `PendingConsentStore` | optional | `core/consents/types.mts` | The `/authorize` request parked under a challenge while the consent page asks; `consume` hands it to exactly one answer, so two answers in flight apply one (#552). Wired with `consentStore` — the bundled memory and Redis modules each provide both, and the OAuth router refuses a composition with one and not the other. Holds each session to `PENDING_CONSENT_PER_SESSION_LIMIT` parked requests. |
| `appleFederationConfig` | `AppleProviderConfig` | optional | `federation-apple/apple.mts` | Config slice for the bundled Sign in with Apple federation module. Carries either a `clientSecret` (string or resolver) or the `.p8` key material the module signs one from — Apple's secret is an ES256 JWT that expires. |
| `assertionVerifier` | `AssertionVerifier` | optional | `core/assertions/types.mts` | Proves possession of a presented assertion (device JWT, platform attestation) and returns the opaque handle the Store resolves. Required once the RFC 7523 jwt-bearer grant is enabled — there is no default, because the only possible one accepts things (#301). `createRegistryAssertionVerifier` over an `AssertionIssuerRegistry` is the bundled one for several issuers, each with its own keys and terms; `createJwtAssertionVerifier` is its one-entry form (#525). A verifier whose credential expires reports `expiresAt` (epoch seconds): the grant caps the issued token there, so it never outlives the assertion. The field is optional for compatibility, and omitting it asserts a credential with no expiry (auth.proxy#90). |
| `auditSink` | `AuditSink` | optional | `core/audit/types.mts` | Where security events go. Optional to wire, **not optional to decide** — an unfilled slot must be declared absent (#363). |
| `challengeCeremony` | `ChallengeCeremony` | optional | `core/challenges/types.mts` | The ceremony driver — issue and verify — kept separate from its storage. |
| `challengeStore` | `ChallengeStore` | optional | `core/challenges/types.mts` | In-flight WebAuthn ceremony challenges. |
| `clientRepository` | `ClientRepository` | required | `core/repositories/ClientRepository.mts` | Registered OAuth clients. Read-only from this library's side. |
| `codeRepository` | `CodeRepository` | optional | `core/repositories/CodeRepository.mts` | Authorization codes. Single-use, and replica-shared in any deployment that scales. Required with the `authorization_code` grant, which redeems the codes `/authorize` issues into it; a composition without that grant wires none. |
| `deviceCodeStore` | `DeviceCodeStore` | optional | `core/device-authorization/types.mts` | Pending RFC 8628 device authorizations. Written as atomic operations rather than read-then-write pairs: `poll` reads the status *and* consumes an approval in one step, because two concurrent polls that both observe `approved` mint two tokens from one human approval. Absence must be declared (#298). |
| `federationProviders` | `ReadonlyMap<string, FederationProvider>` | optional | `core/modules/manifest/synthetic-keys.mts` | Upstream IdP protocol adapters, contributed per federation module. The value type is the adapter port in `core/src/federations/types.mts`; it read `unknown` until that contract moved into core (#626 P1). |
| `federationRedirectPolicies` | `{ readonly [name: string]: FederationRedire…` | optional | `session/federations/contributes.mts` | Per-federation `redirect_to` allowlist factories. Paired with the provider at boot; an unpaired one refuses. |
| `federationTokenStore` | `FederationTokenStore` | optional | `core/federation-tokens/types.mts` | Upstream tokens held on behalf of a session. Encrypted at rest by the bundled adapter. |
| `federationGrantBackground` | `FederationGrantBackground` | optional | `federation-grants/background.mts` | Not an adapter seam but lifecycle infrastructure, for work the provider itself starts and deliberately does not make a caller wait for (#593, D12): letting go of a refresh lock, telling the sink, recording a use, and a refresh that outlived the soft deadline and is still holding its lock until the rotated credential is written down. One per application. Its cleanup drains, and its dependency edges on `federationGrantStore`, `subjectRevocation` and `auditSink` are what put that drain ahead of their cleanups — an adapter that closed first would fail the write being waited for. Filled by `federationGrantBackgroundModule`; a deployment mounting it wants at least 45 seconds of cleanup allowance, not the standalone's default ten. |
| `federationGrantIntentStore` | `FederationGrantIntentStore` | optional | `core/federation-grants/intentStore.mts` | Acquisition's records (#593, D16, slice 6), the second port of federation grants: the intent a confidential client lodged, the consent challenge the deployment's page answers, the connect transaction the upstream callback consumes, and the bound on live first-time intents per `(client, subject)` — the only admission control in front of `createPending`, which is why it refuses at capacity instead of evicting. Its keys share a tag of their own and no operation spans this port and the grant store: supersession is settled by the grant's current-intent pointer, and core orders the two writes once. One deadline governs a whole acquisition — the intent's — and the consent and the transaction carry it rather than one of their own, because nothing extends a `pending` grant's pointer. Every operation takes the time from its caller and reclaims on the adapter's own clock; a record it cannot read is refused rather than healed. Bundled adapters: memory (`memoryFederationGrantIntentStoreModule`, single replica) and Redis (`redisFederationGrantIntentStoreModule`). Its consumer is the acquisition routes of #593 slice 6. |
| `federationGrantStore` | `FederationGrantStore` | optional | `core/federation-grants/store.mts` | Federation grants (#593): one user's consent that one client may obtain upstream access tokens through one connection, which outlives the session — the records, the upstream credentials kept beside each (sealed at rest by an adapter that persists them; the bundled one holds them in memory, unsealed), and the lock a refresh holds. Every transition is a guarded write inside the store. Every operation on a record takes the time from its caller, and what a caller is told is judged on that time alone; what an adapter reclaims is judged on its own clock. Its consumer is the federation grant routes of #593. Bundled adapters: memory (single replica) and Redis (`redisFederationGrantStoreModule`, #593 slice 4 — configured by `federationGrants` for what a grant may be, and `redisFederationGrantStore` for this adapter's own layout). |
| `githubFederationConfig` | `GithubProviderConfig` | optional | `federation-github/github.mts` | Config slice for the bundled GitHub federation module. |
| `googleFederationConfig` | `GoogleProviderConfig` | optional | `federation-google/google.mts` | Config slice for the bundled Google federation module. |
| `grantPolicy` | `GrantPolicyHook` | optional | `core/policy/types.mts` | Deployment-supplied hook consulted at grant dispatch, for policy this library does not model. |
| `keyStore` | `KeyStore` | required | `core/keys/KeyStore.mts` | Signing and verification keys. `sign()` is the seam a KMS/HSM implements without surrendering the private key (#303). |
| `mfaFactorStore` | `MfaFactorStore` | optional | `core/mfa/factorStore.mts` | Enrolled second factors (the MFA ADR's D7): one record per factor, keyed by subject and id, whose `data` the MFA package seals before it arrives and every store keeps byte for byte without reading. `update` is a compare-and-set on the record's `version`; a store that cannot answer throws, because an outage read as "no factors" would open a first binding. Bundled adapters: memory (`memoryMfaFactorStoreModule`, single replica; a restart empties it, which it warns about) and Redis (`redisMfaFactorStoreModule`: one hash per subject with no TTL; it refuses a server whose `maxmemory-policy` is `allkeys-*` at boot and warns when the server keeps no AOF, D12). |
| `mfaTransactionStore` | `MfaTransactionStore` | optional | `core/mfa/transactionStore.mts` | MFA transactions and the subject lock (the MFA ADR's D8, D21). A transaction is the single-use record of one second-factor ceremony, bound to what started it through a typed `binding` (`MfaTransactionBinding`, a union discriminated by `kind`: `{ kind: "session", id }`, a browser session, alone today; #742) that a store keeps whole and every use compares whole, kind included (`isMfaTransactionBoundTo`; `getBoundMfaTransaction` answers a transaction bound to anything else as an unknown id); every operation a race could split is atomic in the store — `reserveAttempt` spends an attempt before a proof is checked, `takeChallenge` answers a challenge once, `consume` gives the transaction to one verification. The subject state bounds guessable proofs across transactions on the time the caller passes: the consecutive run with its short backoff and hard limit, the weekly budget no success refunds, and the browsers an exempt success trusts against the weekly hold. It also keeps the email proof an operator reset requires at the subject's next first binding (D25), which must last as the enrolled factors do. No Store variant: this is verification state. Bundled adapters: memory (`memoryMfaTransactionStoreModule`, single replica) and Redis (`redisMfaTransactionStoreModule`: one script per atomic operation, D21's lock over a hash and a sorted set under the subject's tag, and the factor store's boot check). |
| `mailSender` | `MailSender` | optional | `core/mail/types.mts` | Where multi-factor authentication's one-time codes and security notices leave the provider (the MFA ADR's D5; the boundary section says why it is here). `send` takes a rendered message and resolves only when the relay accepted it; a rejection is never "sent", and its loggable projection carries no part of the message and none of the relay's reply, under each way a relay refuses. In core because its implementer and its consumer must not depend on each other. A factor never calls it: a challenge or an enrollment answers the `mail` it sends, and the MFA package sends it within the factor's `mailLimits`. No sender is bundled: `@o3co/auth-provider-smtp` (private) declares `smtpMailSenderModule` and its section, `smtp-mail-sender`, and provides no sender. Suite `mailSenderContract`, double `createRecordingMailSender` (`@o3co/auth-provider-core/testing`). |
| `oidcFederationConfigs` | `Readonly<Record<string, OidcProviderConfig>>` | optional | `federation-oidc/module.mts` | Config of every generic OpenID Connect federation instance, keyed by federation name; each `oidcFederationModule(<name>)` reads its own entry. `readOidcFederationConfigs` builds it from `config.federations` (#524). |
| `rateLimiter` | `RateLimiter` | optional | `core/ratelimit/types.mts` | Shared counters for the OAuth endpoints and the login brute-force guard. Its optional `failMode` is the limiter's own outage policy (#728) — `open` or `closed`, what the guard does when `check` throws — owned by the module that builds the limiter, and the only place the guard reads the policy: read once when the guard or a policy is built, absent meaning `closed`, as on the in-process limiter, which has no backend to lose, and any other value refusing the build. Its optional `defaultLimit` is the budget a key falls to when nothing covers its prefix; boot holds an override of a switched-off budget to it. The Redis limiter module answers `rateLimit.failMode`; any other limiter answers its own, whatever that key says, and boot warns `rate_limit_fail_mode_not_applied` when the key says `open` and the wired limiter does not. A wrapper around a limiter forwards `failMode` and `defaultLimit`, or the guard fails closed and overrides of switched-off budgets are refused. Suite `rateLimiterContract`, double `createTestRateLimiter`. |
| `refreshTokenFamilyRevocation` | `RefreshTokenFamilyRevocation` | optional | `core/refresh-token-family/types.mts` | Family-wide revoke, used on replay detection and on the credential-change cascade. |
| `refreshTokenFamilyRotation` | `RefreshTokenFamilyRotation` | optional | `core/refresh-token-family/types.mts` | Atomic rotate-or-detect-replay. Wired separately so a deployment can have the store without the CAS path. |
| `refreshTokenFamilyStore` | `RefreshTokenFamilyStore` | optional | `core/refresh-token-family/types.mts` | Refresh-token family records — the state rotation and replay detection read. |
| `replaySeenSet` | `ReplaySeenSet` | optional | `core/replay-seen-set/types.mts` | The generic seen-set primitive the replay stores are built on: one atomic check-and-mark per single-use value, scoped per consumer. Records `private_key_jwt` `jti`s, consumed WebAuthn challenges and every accepted DPoP proof (`dpop-proof:<jkt>`); DPoP enabled with the slot empty refuses to boot. The jwt-bearer ID-JAG verifier takes its seen-set as an option from the composition, not from this slot. |
| `sessionFamilyIndex` | `SessionFamilyIndex` | optional | `core/user-sessions/types.mts` | Session → refresh-token families, so logout can revoke them. |
| `sessionFederationIndex` | `SessionFederationIndex` | optional | `core/user-sessions/types.mts` | Session → upstream federations, so logout can propagate. |
| `sessionRPRegistry` | `SessionRPRegistry` | optional | `core/user-sessions/types.mts` | Which RPs a session has authenticated to, for back-channel logout. |
| `subjectRevocation` | `SubjectRevocation` | optional | `core/user-sessions/types.mts` | Per-subject not-before watermark: what a credential change stamps so tokens minted before it stop verifying. Absence must be declared (#406). |
| `subjectRevocationService` | `SubjectRevocationService` | optional | `core/user-sessions/subjectRevocationService.mts` | Not an adapter seam: the composed operation a Store calls to end everything one subject holds (#593, D13) — the boundary, their sessions, and their federation grants. It is a component rather than the free `revokeAllForSubject` because building it needs every session store plus the cascade, and because the one decision it carries — whether a caller MAY ask for the subject's established grants to be kept — belongs to the operator (`federationGrants.allowKeepOnSubjectRevocation`) and not to the caller. Filled by an explicitly installed module in `@o3co/auth-provider-oauth`, where `cascadeLogout` lives. |
| `subjectSessionIndex` | `SubjectSessionIndex` | optional | `core/user-sessions/types.mts` | Subject → live sessions, so a credential change can enumerate what to cascade over. Absence must be declared (#406). |
| `userRepository` | `UserRepository` | required | `core/repositories/UserRepository.mts` | **The verify seam.** `authenticate` / `authenticateByToken`, plus the optional `linkFederatedIdentity` a `?link=1` flow relays to the Store, which decides, and the optional `markMfaEnrolled`, the MFA enrollment witness the provider writes and the Store answers back as `User.mfaEnrolled` — see the boundary section. The optional pair `supportsFederatedIdentityLookup` / `findSubjectByFederatedIdentity` is what a federation-grant callback asks (D7 check 5, #611): whether the Store covers a registration with the claims its connection names — asked at boot — and who holds an identity from it, given the registration, the `sub` and those verified claims (Entra's `tid`/`oid` for a directory Store), as `linked` / `unlinked` / `indeterminate`. The bundled `InMemoryUserRepository` covers none. |
| `userSessionStore` | `UserSessionStore` | optional | `core/user-sessions/types.mts` | The session records themselves, keyed by `sid`. A record round-trips `authentication` (how the session was established, the MFA ADR's D9). The step-up capability `SupportsSecondFactorUpdate` (`recordSecondFactor`, detected by `supportsSecondFactorUpdate`) is optional; without it a step-up asks for a re-authentication. |
| `webauthnConfig` | `WebAuthnConfig` | optional | `webauthn/config.mts` | The WebAuthn relying party (`rpId`, `rpName`, the allowed origins) and the rest of the webauthn package's settings, as `webauthnConfigSchema` parses them — the one slot for the relying party (#728). Only the webauthn package's modules read it — the grant, and the WebAuthn second factor the MFA ADR places in that package (D4) — so its contract stays there rather than in core. A composition root's bootstrap module provides it today; the webauthn package is to provide it from its own section. |
| `webauthnCredentialStore` | `WebAuthnCredentialStore` | optional | `core/webauthn-credentials/types.mts` | Registered passkeys. |

## Client slots

| Slot | Type | Wiring | Declared in | Purpose |
| --- | --- | --- | --- | --- |
| `accessTokenDenylistClient` | `AccessTokenDenylistClient` | optional | `redis/clients.mts` | Vendor-facing half — what `@o3co/auth-provider-redis` needs from a driver, not what a module consumes. |
| `challengeStoreClient` | `ChallengeStoreClient` | optional | `redis/clients.mts` | Vendor-facing half — what `@o3co/auth-provider-redis` needs from a driver, not what a module consumes. |
| `codeRepositoryClient` | `CodeRepositoryClient` | optional | `redis/clients.mts` | Vendor-facing half — what `@o3co/auth-provider-redis` needs from a driver, not what a module consumes. |
| `consentStoreClient` | `ConsentStoreClient` | optional | `redis/clients.mts` | Vendor-facing half — what `@o3co/auth-provider-redis` needs from a driver, not what a module consumes. Semantic operations (`find` / `grant` / `revoke`), because `grant` is the port's union and a read-then-write loses a concurrent grant (#561). |
| `deviceCodeStoreClient` | `DeviceCodeStoreClient` | optional | `redis/clients.mts` | Vendor-facing half — what `@o3co/auth-provider-redis` needs from a driver, not what a module consumes. Semantic operations (`create` / `findPending` / `decide` / `poll` / `remove`) rather than commands, because each must be indivisible (#433). |
| `federationGrantIntentStoreClient` | `FederationGrantIntentStoreClient` | optional | `redis/clients.mts` | Vendor-facing half of acquisition's records (#593, D16, slice 6). Five of its seven operations are single scripts — admission against the bound, parking a challenge, answering it, consuming a transaction, finishing a flow — because each reads, decides and writes across keys, which Redis makes one step only with a script or with WATCH/MULTI on a connection of its own (the cost #449 is removing elsewhere). The two reads are plain commands: whatever they conclude, the write that follows checks again. Every key shares the `{intents}` tag, so a script routed by one key may derive the others. It may be the grant store's own connection. |
| `federationGrantStoreClient` | `FederationGrantStoreClient` | optional | `redis/clients.mts` | Vendor-facing half — what `@o3co/auth-provider-redis` needs from a driver, not what a module consumes. Semantic operations rather than commands, because each write is one guarded script; the subject index is reserved and pruned separately, since it is a key of its own and no script may touch it together with a record on a Cluster (#593, D16). |
| `federationTokenStoreClient` | `FederationTokenStoreClient` | optional | `redis/clients.mts` | Vendor-facing half — what `@o3co/auth-provider-redis` needs from a driver, not what a module consumes. |
| `mfaFactorStoreClient` | `MfaFactorStoreClient` | optional | `redis/clients.mts` | Vendor-facing half of the enrolled-factor store (the MFA ADR's D7): one hash per subject, a field per factor. `update` is one step that compares a record's version as text and keeps its fixed part byte for byte — no JSON is decoded, since `cjson` writes an empty array back as `{}`. |
| `mfaTransactionStoreClient` | `MfaTransactionStoreClient` | optional | `redis/clients.mts` | Vendor-facing half of the MFA transaction store (the MFA ADR's D8, D21, D25). Semantic operations, one script each, because every one the port calls atomic reads, decides and writes: insert-only `create`, the version compare-and-set, `reserveAttempt`, `takeChallenge`, `consume`, and D21's three subject-lock operations over the lock hash and the week's sorted set, which share the subject's tag. The email-proof requirement is one command each way, in a key with no TTL. |
| `pendingConsentStoreClient` | `PendingConsentStoreClient` | optional | `redis/clients.mts` | Vendor-facing half — what `@o3co/auth-provider-redis` needs from a driver, not what a module consumes. Semantic operations (`set` / `get` / `consume` / `discard`): `consume` reads and removes a parked request with its per-session index entry in one step, and `discard` reclaims one the adapter found corrupt only while it is still the value read (#561). |
| `rateLimiterClient` | `RateLimiterClient` | optional | `redis/clients.mts` | Vendor-facing half — what `@o3co/auth-provider-redis` needs from a driver, not what a module consumes. |
| `refreshTokenFamilyClient` | `RefreshTokenFamilyClient` | optional | `redis/clients.mts` | Vendor-facing half — what `@o3co/auth-provider-redis` needs from a driver, not what a module consumes. |
| `replaySeenSetClient` | `ReplaySeenSetClient` | optional | `redis/clients.mts` | Vendor-facing half — what `@o3co/auth-provider-redis` needs from a driver, not what a module consumes. |
| `sessionFamilyIndexClient` | `SessionSidSortedSetClient` | optional | `redis/clients.mts` | Vendor-facing half — what `@o3co/auth-provider-redis` needs from a driver, not what a module consumes. |
| `sessionFederationIndexClient` | `SessionSidSortedSetClient` | optional | `redis/clients.mts` | Vendor-facing half — what `@o3co/auth-provider-redis` needs from a driver, not what a module consumes. |
| `sessionRPRegistryClient` | `SessionRPRegistryClient` | optional | `redis/clients.mts` | Vendor-facing half — what `@o3co/auth-provider-redis` needs from a driver, not what a module consumes. |
| `subjectRevocationClient` | `SubjectRevocationClient` | optional | `redis/clients.mts` | Vendor-facing half — what `@o3co/auth-provider-redis` needs from a driver, not what a module consumes. |
| `subjectSessionIndexClient` | `SubjectSessionIndexClient` | optional | `redis/clients.mts` | Vendor-facing half — what `@o3co/auth-provider-redis` needs from a driver, not what a module consumes. |
| `userSessionStoreClient` | `UserSessionStoreClient` | optional | `redis/clients.mts` | Vendor-facing half — what `@o3co/auth-provider-redis` needs from a driver, not what a module consumes. |

## Lifecycle

**Filling a slot.** A composition root supplies it in `bootstrapComponents`, or a
module `provides` it. The boot planner resolves the graph topologically and
refuses a module whose `requires` cannot be met.

**Absence is a decision, not a default.** An `optional` slot means *optional to
wire*, never *optional to decide*. The slots below carry an `AbsencePolicy`
(#363; `packages/core/src/modules/manifest/absence-policy.mts`). Leaving one
unfilled without writing its declaration refuses boot, naming the config line to
write. This is deliberately stronger than defaulting to something harmless — a
default hands a capability to a composition that never asked for it and calls
that safety.

| Slot | Policy | Declared absent by |
| --- | --- | --- |
| `auditSink` | `AUDIT_SINK_ABSENCE_POLICY` | `audit.sink.type = "none"` |
| `accessTokenDenylist` | `ACCESS_TOKEN_DENYLIST_ABSENCE_POLICY` | `oauth.revocation.accessToken = "unsupported"` |
| `subjectRevocation` | `SUBJECT_REVOCATION_ABSENCE_POLICY` | `oauth.revocation.subject = "unsupported"` |
| `subjectSessionIndex` | `SUBJECT_REVOCATION_ABSENCE_POLICY` | `oauth.revocation.subject = "unsupported"` |
| `deviceCodeStore` | `DEVICE_CODE_STORE_ABSENCE_POLICY` | `oauth.deviceAuthorization.store = "unsupported"` |

There is no absence policy for MFA: the `mfaCoordinator` slot and
`MFA_ABSENCE_POLICY` left with the session-admission ADR (D6, D7). What a
composition expects of session admission is declared by
`sessionRequirements.expected` instead: a name there that no module registers
refuses the boot (`session-requirement-missing`), `mfa` without the MFA
package among them.

The subject-revocation pair shares one policy on purpose: two components, one
capability, so a deployment without them has one thing to declare rather than
two. `deviceCodeStore` joined with #443, which this paragraph missed while it
still said "three"; the table is now checked against the manifests that attach
each policy, the same way the slot table is (#458).

A declaration says why a slot is empty; it does not stand in for the component
where a feature needs it. `oauth.deviceAuthorization.store = "unsupported"` is
for a deployment that leaves the grant off — `deviceGrantModule` with the grant
enabled refuses to boot without a store, whatever the declaration says (#626).

**Replica safety.** In-process state stores are correct on one node and wrong on
several. `deployment.mode = "multi"` with one wired refuses boot, naming each
offender and what diverges per replica; `"single"` is silent; unset warns. The
list of unsafe modules is drift-guarded (#304), so a new in-memory adapter cannot
be silently replica-unsafe.

**Shutdown.** A component that holds a connection or a timer registers its
teardown with `lifecycleRegistrar`; `dispose()` drains in reverse-topological
order.

**Proving an implementation.** Several ports ship a conformance suite an
out-of-tree adapter can import and run:

| Port | Suite |
| --- | --- |
| `KeyStore` | `packages/core/src/keys/__tests__/keyStore.contract.mts` |
| `SubjectSessionIndex` | `packages/core/src/user-sessions/__tests__/subjectSessionIndex.contract.mts` |
| `SubjectRevocation` | `packages/core/src/user-sessions/__tests__/subjectRevocation.contract.mts` |
| `AccessTokenDenylist` | `packages/core/src/access-token-denylist/__tests__/adapters.contract.mts` |
| `ChallengeStore` | `packages/core/src/challenges/__tests__/adapters.contract.mts` |
| `ConsentStore` | `packages/core/src/consents/__tests__/adapters.contract.mts` |
| `DeviceCodeStore` | `packages/core/src/device-authorization/__tests__/adapters.contract.mts` |
| `FederationGrantStore` | `packages/core/src/federation-grants/__tests__/store.contract.mts` |
| `FederationGrantIntentStore` | `packages/core/src/federation-grants/__tests__/intentStore.contract.mts` |
| `MfaFactorStore` | `packages/core/src/mfa/__tests__/factorStore.contract.mts` |
| `MfaTransactionStore` | `packages/core/src/mfa/__tests__/transactionStore.contract.mts` |
| `PendingConsentStore` | `packages/core/src/consents/__tests__/pending.contract.mts` |
| `ReplaySeenSet` | `packages/core/src/replay-seen-set/__tests__/adapters.contract.mts` |
| `RefreshTokenFamilyStore` | `packages/core/src/refresh-token-family/__tests__/adapters.contract.mts` |
| `WebAuthnCredentialStore` | `packages/core/src/webauthn-credentials/__tests__/adapters.contract.mts` |
| `UserSessionStore` | `packages/core/src/user-sessions/__tests__/userSessionStore.contract.mts` (`runUserSessionStoreContract`) |
| `SupportsSecondFactorUpdate` (the `UserSessionStore` step-up capability; run only for a store that claims it) | `packages/core/src/user-sessions/__tests__/userSessionStore.contract.mts` (`runSecondFactorUpdateContract`) |
| `SessionRPRegistry` | `packages/core/src/user-sessions/__tests__/sessionRPRegistry.contract.mts` |
| `SessionFamilyIndex` | `packages/core/src/user-sessions/__tests__/sessionFamilyIndex.contract.mts` |
| `SessionFederationIndex` | `packages/core/src/user-sessions/__tests__/sessionFederationIndex.contract.mts` |
| `RateLimiter` (`failMode` included) | `packages/core/src/testing/slots/rateLimiter.mts` (`rateLimiterContract`) |
| `MailSender` | `packages/core/src/testing/slots/mailSender.mts` (`mailSenderContract`) |
| `MfaFactor` (a second factor contributed as `mfaFactors`; a contribution, not a slot) | `packages/core/src/testing/mfaFactor.mts` (`mfaFactorContract`, with `createTestMfaFactor` and `createTestMfaDigests`) |
| The slots of [what one module owns and others read](#what-one-module-owns-and-others-read) | `packages/core/src/testing/slots/` — one suite per slot, named in its row |

Each is run against every in-repo implementation of its port, which is what
makes it a description of the contract rather than of one adapter. There is one
exception: the Redis `AccessTokenDenylist`, whose expiry is Redis's own key TTL
and cannot follow the suite's fake clock. Its own tests cover the same cases
against a real Redis. A contract file under `__tests__/` cannot be imported
across a package boundary, so `packages/redis/__tests__/` runs copies of those
core suites. A copy may differ from its core suite only above the first
`export`, in comments and imports. The `*-parity.test.mts` tests there fail on
any other difference, and on a copy that no Redis test calls. The suites under
`packages/core/src/testing/slots/` are published on
`@o3co/auth-provider-core/testing` instead, so another package's tests import
them: the Redis rate limiter runs `rateLimiterContract` that way, and the MFA
package's TOTP factor `mfaFactorContract`. The suites a new port or
contribution gains go to the published test-kit package once it exists, and
these move there with the rest. A new port
should gain a suite: "typed and swappable" means an implementer can prove they
got it right, not only that they read the interface carefully.

What the suites hold an adapter to:

- **Records come back whole, as plain data.** A port that returns one of the
  records whose fields are all required keys (#626) has a suite that compares
  whole records with `toStrictEqual`. A field with no value must come back
  named, as `undefined`, not left out. An extra key, or a class instance in
  place of a plain object, also fails. `CodeRepository`, `FederationTokenStore`
  and `AssertionIssuerRegistry` return such records but ship no suite yet; the
  bundled adapters' own tests hold them to the same rule.
- **Only the inputs the port's types allow.** How an adapter treats a value
  outside them, such as a `null` or `""` from an untyped caller, is up to the
  adapter, and its own tests cover it. For example, the bundled device-code
  stores' tests cover a falsy `requestedScope`, which the device-code suite
  does not.
