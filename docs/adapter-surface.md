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
the mark back as `User.mfaEnrolled` on `authenticate` and on
`authenticateByToken` alike — a federated session records it from the latter —
read only through `readMfaEnrollmentWitness`: a value that is neither a
boolean nor absent is malformed, answered `503`, and never read as "not
enrolled". Why it is a Store write at all: the witness has to survive the factor store it vouches for. A factor store
that loses its records — a Redis restarted without persistence, an eviction, a
restore from an old backup — would otherwise read as "never enrolled", and every
affected account would accept a first binding from whoever holds its password.
A repository without the capability (`supportsMfaEnrollmentWitness`), and a
Store that answers no field, leave the witness absent; the factor store's
durability is then the whole defence. Foundation's `HttpUserRepository` has
the capability once `repositories.user.http.markMfaEnrolledUrl`
(`REPOSITORIES_USER_HTTP_MARK_MFA_ENROLLED_URL`) names the Store's witness
endpoint, and none without it.

`revokeAllForSubject`, the last of the three call sites above, is the pattern
for anything that looks like it needs a new slot: the library is downstream of
the action, never the one taking it. **Message
delivery is the worked example of where the line falls.** The one flow this
library drives end to end that must send is multi-factor authentication: the
one-time codes of its email factor and of the account-email proof (the MFA
ADR's D5). So there is a delivery port, `mailSender`, and it is that narrow:
what a mail means — its purpose from a closed list, the account, the address
on its user record at that moment, the code and its expiry — handed to
whatever renders and delivers it. The text, its language, delivery and any
limit on sending are the sender's; `@o3co/auth-provider-standard` holds an SMTP
sender's section and rendering and a development sender, and a deployment that
delivers through its own mail service implements `send` and nothing else.
Security notices to the account holder are not sent here at all: the
deployment builds them from the audit events. Templates, links, sign-up,
password reset and account recovery by e-mail stay the Store's and the
deployment's. Full IdPs ship more because they own the flows that send; this
library owns only these.

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
| `lifecycleRegistrar` | `LifecycleRegistrar` | required | `core/boot/types.mts` | Where a component registers its shutdown work, so `dispose()` drains in reverse-topological order, and with it a tail (`register(cleanup, { tailMs })`): the least time a host that bounds `dispose()` must allow the whole of `dispose()` for that work to settle, the cleanups around it included. `AppHandle.cleanupAllowanceMs` is the longest; tails do not add. |
| `logger` | `Logger` | optional | `core/logging/Logger.mts` | Structured logger. Optional to wire; bundled modules fall back to a console logger rather than going silent. |
| `pathResolver` | `PathResolver` | required | `core/boot/types.mts` | Resolves a package-relative path (normally `import.meta.resolve`), so `reference.conf` is found without assuming a layout. |
| `readinessRegistrar` | `ReadinessRegistrar` | required | `core/boot/types.mts` | Where a component registers a readiness probe. Distinct from liveness: this answers *can it serve*, not *is it up*. |

## Synthetic keys

Assembled by the boot planner from module contributions rather than supplied by
a composition root. Listed because a module may `require` them. `deploymentMode`
is a synthetic key too, but boot derives it from the configuration's
`core.deployment.mode`, not from contributions: it is listed with the settings slots,
under [What one module owns and others read](#what-one-module-owns-and-others-read).

| Slot | Type | Wiring | Declared in | Purpose |
| --- | --- | --- | --- | --- |
| `federationRedirectPolicyResolver` | `ReadonlyMap<string, FederationRedirectPolicy>` | optional | `session/federations/contributes.mts` | Synthetic key: the assembled per-federation `redirect_to` policies. |
| `grantHandlerResolver` | `GrantHandlerResolver` | optional | `core/modules/manifest/synthetic-keys.mts` | Synthetic key: the assembled grant registry, resolved from every module's `contributes.grants`. |
| `mfaFactorResolver` | `MfaFactorResolver` | optional | `core/modules/manifest/synthetic-keys.mts` | Synthetic key: every second factor contributed as `contributes.mfaFactors`, by kind. A factory that answered `null` (the factor switched off by its configuration) claims its kind and is absent from the resolver. In place before the `provides` factories run and filled as the contributions register, so a factory that runs earlier holds it and reads it later — the MFA package's `mfa` requirement reads it for its `reach`, which core reads once every factor has registered; a read while the provides factories run refuses the boot. A factor whose `kind` is not its key refuses boot. |
| `rateLimitBudgetResolver` | `RateLimitBudgetResolver` | optional | `core/modules/manifest/synthetic-keys.mts` | Synthetic key: every rate-limit budget contributed as `contributes.rateLimitBudgets`, by prefix (#728) — the default limit and window each module reads from its own settings for the prefixes it keys. A module claims every prefix it keys, with a budget or with `null` (no budget of its own, or one its settings switch off): a `null` prefix is absent from the resolver yet claimed, and two modules contributing one prefix refuse boot (`duplicate-contribute`), so none can claim another's. A budget that is not a positive whole limit and a window of at most a year (`isBoundedRateLimitSpec`, independent of the clock), a prefix no key can carry, and an override that loosens the budget it replaces — a higher `limit` or a shorter `windowSeconds`, a `null` side counting as the wired limiter's `defaultLimit`, and refused when none is declared — fail their contribution. Boot logs `rate_limit_budgets_registered` with each prefix, its contributed budget and the module that set it; a limiter's own `limits` entry wins over that budget and is not shown. Read at request time, like every projection: a read while the provides factories run refuses the boot. Both bundled limiter modules require it and read it through `createRateLimitBudgetLookup` (`core/ratelimit/budgetLookup.mts`), reading each budget it answers once into a frozen copy and checking it: the limiter's own `limits` entry for a prefix wins over a contributed budget, and a prefix with neither falls to its `defaultLimit`. The device grant requires it too, and refuses boot unless the contributed `device_verification` budget, after any override, is its configuration (a limiter's own entry is not compared); WebAuthn reads it for its mismatch warning. Each package's README names the prefixes it claims. |
| `sessionRequirementResolver` | `SessionRequirementResolver` | optional | `core/modules/manifest/synthetic-keys.mts` | Synthetic key: every session requirement contributed as `contributes.sessionRequirements`, by name, in registration order (the session-admission ADR's D3) — what every consumer of session admission requires, and what `admitSession` reads the requirements through — and every action contributed as `contributes.admissionActions`, by name (`action(name)`), which `admitSession` reads an action's grade from. A grade is its registering module's own statement; `grants_nothing` exempts an admission a record carries (a cookie, a code, a link) from the MFA requirement's baseline — a token is judged on its own `amr` whatever the grade — and the boot line `admission_actions_registered` names each action's grade and module. Branded by the planner: `admitSession` refuses any other object, and `resolverForTests` (`@o3co/auth-provider-core/testing`) is the one other builder. Neither overridable nor replaceable: an `overrides.sessionRequirements` entry, and a host `contributionKinds` collector for it or for `mfaFactors`, are refused at stage 1 (`session-requirement-kind-guarded`). A composition that installs a consumer declares what it expects in `core.sessionRequirements.expected`, compared as a set with what registered at the end of stage 4. An `admitted` admission carries `view`, admission's `SessionView` of the record (`null` without one), and a `step_up` admission its view: a consumer reads the session's enrollment facts there, never off the record. |
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
`core.deployment.mode`, and reserves the key.
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

`redis-rate-limiter.failMode` is the Redis limiter module's own key, the
outage policy of the limiter it builds; the guard reads the policy from the
wired limiter, never from the key.

| Slot | Type | Wiring | Declared in | Purpose |
| --- | --- | --- | --- | --- |
| `oauthTokenSettings` | `OAuthTokenSettings` | optional | `core/token-settings/types.mts` | What other modules read of the oauth module's token settings, resolved and frozen: the canonical issuer, `legacyTypAccept`, the access-token default and max, the refresh-token lifetime, whether resource indicators are enforced, and `requireEmailVerified`. Provided by the oauth module (`oauthTokenSettingsFrom`, `oauth/tokenSettings.mts`), eagerly: filled whenever the module is installed, so core's machinery reads it too. The module names it `authoritative`: while it is loaded an `overrideComponents` entry for the slot refuses boot (`authoritative-component-overridden`), and a composition without it fills the slot itself. Read, when the composition holds it, by `device-grant`, `dpop`, `federation-grants`, `mfa` (the TOTP issuer's default), `oauth-token-exchange`, `webauthn`, the subject revocation service's horizon, and core — the discovery document's issuer and the CORS table's discovery paths, a session requirement's page. Each lists it as optional and reads the configuration when no module provides it, as before: every one of them runs in a composition without the oauth module. A slot a composition holds is read whole, never a member of it beside the configuration: each reader holds it first to what readers read with core's `checkOAuthTokenSettings`, which refuses a member a hand-filled slot lacks or gets wrong, naming it (`oauthTokenSettings.<member>`), rather than letting `undefined` stand for it. A held slot, whoever provides it, names no lifetime longer than the one core resolves from the configuration: the refresh-token family modules and the subject revocation boundary size their retention from that value and cannot read the slot, so `checkOAuthTokenSettings` refuses a longer access-token maximum or refresh-token lifetime, naming the member and both values, and boot refuses a host map's at stage 1 (`token-settings-lifetime-exceeds-configuration`). The oauth module resolves its lifetimes with the same resolvers, so its value never exceeds them. Still read from the configuration: the stage-1 grant-policy issuer check, which runs before any provider, and the default refresh-token family modules' horizon. The planner's graph is module-level, so no module in the oauth module's dependency set — the providers of its `requires` and its `optional` keys, and what those depend on — can read the slot without a cycle: the revocation module is one, since the oauth module reads the `refreshTokenFamilyRevocation` it provides; the rotation module is not, and reads the configuration beside it on purpose, so that the two retain a revoked family for the same horizon. Providing the slot from a module that depends on none of them would lift the constraint, and is left for later. Not in it: the token-binding settings — the dispatch policy and `bindConfidentialClientRefreshTokens` — which apply across every mechanism at core's token-binding extension point and so are core's, the point's owner: core reads them from the configuration with its one reader of the section, `resolveTokenBindingSettings`, in every composition — boot the policy, the oauth and WebAuthn grants the binding rule; the contract refuses a value that carries either. The keys are core's own section's, `core.tokenBinding`. Nor `requireGrantTypeAllowlist`, which only the oauth module reads, nor the revocation modes, `oauth.revocation.accessToken` and `.subject` — the declarations core's declared-absence guard reads for the policies `oauth-token-exchange`, `session` and `webauthn` attach as well as oauth (the absence table below), at validation, before any provider runs, so a slot cannot serve them; where they live once `oauth {}` is the oauth module's alone is for that move. Suite `oauthTokenSettingsContract`, double `createTestOAuthTokenSettings`. |
| `loginCompletion` | `LoginCompletion` | optional | `core/session-admission/login-completion.mts` | The tail of a login (the session-admission ADR's D5): the session package's `establishSession` and `answerInterruption`, with what the provider holds — the session stores, the session's lifetime, the CSRF mechanism — out of their arguments. A requirement's completion requires it instead of importing `packages/session`: the MFA module does, finishing a login after `resumePrimary`. Provided by the session package's login-completion module (`session/modules/loginCompletionModule.mts`), over the session stores, the `csrfGuard` and the `sessionCookiePolicy` it requires (the session's lifetime is the policy's `maxAgeMs`) — its own module because it answers with the deployment's guard, whoever filled the slot, and the session module cannot require a slot it fills itself. Each login tail refuses, before the session is touched, an `Establishment` or interruption core did not build; every outage of a login tail is reported to the caller's reporter once and leaves the browser not signed in. The interruption's `403` carries a fresh token from the deployment's `csrfGuard` (the MFA ADR's D27); `establishSession` leaves the answer, and the token on it, to its caller. `renewSession` (the MFA ADR's D27) moves a signed-in browser to a regenerated express session id, keeping `isAuthenticated`, `user` and `sid`, writing a fresh renewal nonce it answers, dropping every other field and writing no session record, and saves; a session not signed in stays so. A `regenerate` or `save` failure, or a request with no express session, is answered `unavailable` (`cookie_session`), reported once, the request's cookie session dropped and nothing saved; the caller records nothing on it. express-session's save overwrites whatever its store holds, so a request in flight on the old id can put it back after the renewal: the MFA step-up's finish records the escalation with the nonce (`recordSecondFactor`), and admission refuses the old id. Records bound to the old id are orphaned: a consent `/authorize` parked, a federation-grant browser binding, the session's other open MFA transactions. A deployment's own `loginCompletion` must implement it. Suite `loginCompletionContract` (with `records`, what a call writes; with `csrfCookieName`, the `403`'s token), double `createRecordingLoginCompletion`. |
| `loginEntry` | `LoginEntry` | optional | `core/browser-session/types.mts` | The deployment's login page and how a browser that is not signed in is sent there to come back: `urlFor(returnTo)` adds `redirect_to`, the target encoded whole, to the page's own query, before any fragment; a page whose query already carries `redirect_to` is refused (the provider refuses it when built, and the session module's section schema refuses such a `session.loginPage.url` at validation). Provided by the session module from `session.loginPage.url` (`session/login-entry.mts`), which its section requires; `loginEntryFromConfig`, over a configuration without a page, builds an entry that fails where the page is read. The federation-grants connect flow requires it once grants are enabled; `/authorize` sends its login trips through it and through nothing else, so a composition that serves `/authorize` with no module providing it is refused at boot (`contribute-factory-failed`, naming the slot). Suite `loginEntryContract`, double `createTestLoginEntry`. |
| `csrfGuard` | `CsrfGuard` | optional | `core/browser-session/types.mts` | The one policy for whether a browser may change state, in its two forms. **A request** (`check`, `middleware`): a foreign `Origin` — or, without one, `Referer` — is refused whatever else the request carries, this origin or a trusted one is accepted, and with neither a signed double-submit token decides, echoed in `headerName` or in `bodyField` of a form body. **A navigation that starts a flow** (`checkNavigation`, the link start's GET): `Sec-Fetch-Site` `same-origin` or `none` accepted, `cross-site` refused, otherwise the `Origin` or `Referer` decides, and a token never counts. `issue` sets a fresh token in a cookie as the session cookie is set. Provided by the session module (`createSessionCsrfGuard`, `session/csrf.mts`): `middleware` is the guard `/session/login` runs, with its `403` and its `csrf_origin_rejected` / `csrf_token_rejected` lines; `check` is its rule as a verdict and writes nothing, so a route that asks it answers and logs a refusal itself; `checkNavigation` is the account-link start's rule, and `bodyField` is `csrf_token`. Required once their feature is enabled by device verification, which runs `middleware`, and by federation grants, whose consent answer asks `check`, answers a refusal in its own vocabulary (`403 invalid_request`) and logs it (`federation_grant_consent_csrf_refused`); required by the MFA module, whose `/session/mfa` POSTs run `middleware` and whose completed login is handed a token by `issue`. The token's signing key is derived from `session-store.secret`, which the session store's module owns: the guard signs and checks the token through `csrfTokenSigner`, and the session routes through the same signer: a token the guard issues passes the routes' check, and one the routes issue passes the guard's. Neither reads `session-store.secret`. A token is well signed only when the signer's `verify` answers `true` (a promise, another truthy value or a throw is a refusal), and one expiring more than `session.csrf.ttlSeconds` and 60 s of clock skew ahead is refused. Suite `csrfGuardContract` (a token's expiry only when the provider takes a clock, `withClock`), double `createTestCsrfGuard`. |
| `csrfTokenSigner` | `CsrfTokenSigner` | optional | `core/browser-session/types.mts` | The CSRF token's signature: `sign(payload)`, a base64url signature of `CSRF_SIGNATURE_MIN_LENGTH` (22 characters, the fewest that carry 128 bits) to `CSRF_SIGNATURE_MAX_LENGTH` (512, far inside a cookie) characters, both exported by core, the same for the same payload, and `verify(payload, signature)`, compared in constant time and never throwing. The key has one owner — the module that owns `session-store.secret`, the session store's — and is derived from the secret for this purpose alone, so a token's signature is never a session cookie's. The derivation is the owner's, not the contract's: providers that derive differently do not verify each other's tokens, so a switch between them invalidates the short-lived tokens outstanding, and a provider that must keep verifying an earlier one's pins the derivation in its own tests; neither the secret nor the key leaves the signer, a plain object (its prototype `Object.prototype` or `null`) that carries `sign` and `verify` alone, own or inherited, and is frozen. Provided by the session store's module (`createSessionCsrfTokenSigner`, `session/csrf-token-signer.mts`): HKDF-SHA256 over `session-store.secret`, no salt, info `o3co.auth.provider/session-csrf/v1`, 32 bytes, then HMAC-SHA256, base64url — pinned by literal vectors, so a token verifies for as long as the secret is kept, across a deploy in either direction: a token issued before the deploy verifies after it, and one issued after it verifies under the release it replaced. `createSessionCsrfTokenSigner` holds the secret to core's entropy floor (`assertSecretEntropy`, naming `session-store.secret`). Not named `authoritative`: an `overrideComponents` entry replaces it, and when the override derives its key differently, tokens the store's signer issued stop verifying. The session package's `createCsrfProtection` probes the signer it is built with — two payloads, their signatures and their length bounds, a changed signature and another payload's — and refuses one that breaks the contract, an asynchronous one included, so the session module refuses at boot; it reads `sign` and `verify` off the signer once, so a signer object changed afterwards changes nothing it mints or accepts. Required by the session module, whose `csrfGuard` and `/session/*` routes sign and check through it and read no `session-store.secret`; a composition that loads the session module without the session store's fills the slot itself — `createSessionCsrfTokenSigner(secret)` signs as the store does — or boot refuses it (`missing-required-component`). Suite `csrfTokenSignerContract` (with `other`, a signer built with another key; with `sessionSecret`, the check that the signature is not an HMAC under the secret itself), double `createTestCsrfTokenSigner` (a random key). |
| `sessionCookiePolicy` | `SessionCookiePolicy` | optional | `core/browser-session/types.mts` | The session cookie's attributes — name, `secure`, `sameSite`, domain and the session's lifetime — for a module that sets a cookie of its own beside the session's, or sizes what must outlive a session: the subject revocation service sizes its horizon from `maxAgeMs` and requires the slot, since core reads no `session-store` key: a composition that installs it without the slot is refused at planning (`missing-required-component`). Named for the session cookie, not the CSRF token's. Held to what browsers keep: `sameSite: none` and a `__Secure-` name only secure, a `__Host-` name only secure and host-only (either prefix in any case), a domain a cookie can carry (a host name, one leading dot allowed). The session cookie's signing secret is not in it. Provided by the session store's module, which owns the session cookie (`session/session-cookie-policy.mts`), built once per section; the store's route mounts its cookie from the same value, so a new session's cookie is the slot's. A section that would break the contract is refused at config validation (`config-validation-failed`, the issue naming `session-store.name`, `session-store.domain`, `session-store.secure` or `session-store.maxAge`), whatever the composition installs. The module names it `authoritative`: while it is loaded an `overrideComponents` entry for the slot refuses boot (`authoritative-component-overridden`), since the store would go on mounting the cookie `session-store.*` describes; a composition without it fills the slot itself. The subject revocation service requires it. Suite `sessionCookiePolicyContract`, double `createTestSessionCookiePolicy`. |
| `httpSettings` | `HttpSettings` | optional | `core/deployment/types.mts` | What every module's HTTP behaviour depends on of the `http` module's settings: `trustProxy` — which forwarding hops `req.ip` and `req.protocol` trust — and the CORS origins core's middleware lets read the token, userinfo, revocation, discovery and JWKS responses. Provided by the standalone template's `http` module (`templates/standalone/src/modules.mts`), from its `http {}` section and the list its `cors` module parses from `cors {}`, eagerly, and named `authoritative`. Core's CORS middleware reads the slot's origins when the composition holds it — read once, each held to the contract's rule, a slot that breaks it refusing the boot with a `RangeError` naming the member and the index — and `cors.allowedOrigins` from the configuration when it holds none, since core runs in compositions without the `http` module (`core/boot/http-settings.mts`); it reads nothing else of the slot. The template's host process applies `trustProxy` to Express from the slot. Suite `httpSettingsContract`, double `createTestHttpSettings`. |
| `deploymentMode` | `DeploymentMode` | optional | `core/deployment/types.mts` | How many replicas the operator says run: `single` or `multi` as `core.deployment.mode` states it, `unset` when it states nothing. Filled by core for every composition, before any provider runs, with its one reading of the key (`deploymentModeOf`, `core/deployment/mode.mts`) — the value the replica-safety guard decides by too. A synthetic key: a module that provides it, and a `bootstrapComponents` or `overrideComponents` entry for it, refuse boot (`synthetic-key-collision`). Required by every module that refuses or warns by the mode, each because it refuses under `multi` and a mode read as absent would lift that: the session module (the `/session/login` throttle's per-process fallback), the session store's module (memory storage), `webauthn` (the authentication/options throttle's fallback), the Redis federation-token and federation-grant stores (the plaintext guard), `mfa` (the development sample key, and its routes' per-process limiter). None of them reads `deployment` off the configuration, and each holds the value it is handed to `checkDeploymentMode` (`core/deployment/mode.mts`): anything but the three values, absence included, is a TypeError naming its source. A composition root that builds one by hand passes `deploymentModeOf(config)`, which core exports — the Redis grant store's `resolveRedisFederationGrantStoreOptions` takes it as its third argument, and the token store's `createRedisFederationTokenStore` and `redisFederationTokenStoreBuilder` as their required `deploymentMode` option. Suite `deploymentModeContract`, which core's tests run over what it fills; a reader's test fills the slot with the literal. |

## Component slots

| Slot | Type | Wiring | Declared in | Purpose |
| --- | --- | --- | --- | --- |
| `accessTokenDenylist` | `AccessTokenDenylist` | optional | `core/access-token-denylist/types.mts` | RFC 7009 access-token revocation by `jti`. Absence must be declared (#375). |
| `consentStore` | `ConsentStore` | optional | `core/consents/types.mts` | What an end-user agreed a client that is not first-party may obtain, read by `/authorize` and written by `POST /oauth/consent`. Absent, such clients are refused as before #527 — nothing to declare. Bundled adapters: memory (single replica) and Redis (`redisConsentStoreModule`, #561). |
| `pendingConsentStore` | `PendingConsentStore` | optional | `core/consents/types.mts` | The `/authorize` request parked under a challenge while the consent page asks; `consume` hands it to exactly one answer, so two answers in flight apply one (#552). Wired with `consentStore` — the bundled memory and Redis modules each provide both, and the OAuth router refuses a composition with one and not the other. Holds each session to `PENDING_CONSENT_PER_SESSION_LIMIT` parked requests. |
| `appleFederationConfig` | `AppleProviderConfig` | optional | `federation-apple/apple.mts` | Config slice for the bundled Sign in with Apple federation module. Carries either a `clientSecret` (string or resolver) or the `.p8` key material the module signs one from — Apple's secret is an ES256 JWT that expires. |
| `assertionVerifier` | `AssertionVerifier` | optional | `core/assertions/types.mts` | Proves possession of a presented assertion (device JWT, platform attestation) and returns the opaque handle the Store resolves. Required once the RFC 7523 jwt-bearer grant is enabled — there is no default, because the only possible one accepts things (#301). `createRegistryAssertionVerifier` over an `AssertionIssuerRegistry` is the bundled one for several issuers, each with its own keys and terms; `createJwtAssertionVerifier` is its one-entry form (#525). A verifier whose credential expires reports `expiresAt` (epoch seconds): the grant caps the issued token there, so it never outlives the assertion. The field is optional for compatibility, and omitting it asserts a credential with no expiry (auth.proxy#90). |
| `auditSink` | `AuditSink` | optional | `core/audit/types.mts` | Where security events go. Optional to wire, **not optional to decide** — an unfilled slot must be declared absent (#363). One sink fills it; more are contributed as `auditHooks`, and the slot then holds core's fan-out over its own sink and every hook, which also fills it for the absence policy. |
| `challengeCeremony` | `ChallengeCeremony` | optional | `core/challenges/types.mts` | The ceremony driver — issue and verify — kept separate from its storage. |
| `challengeStore` | `ChallengeStore` | optional | `core/challenges/types.mts` | In-flight WebAuthn ceremony challenges. |
| `clientRepository` | `ClientRepository` | required | `core/repositories/ClientRepository.mts` | Registered OAuth clients. Read-only from this library's side. |
| `codeRepository` | `CodeRepository` | optional | `core/repositories/CodeRepository.mts` | Authorization codes. Single-use, and replica-shared in any deployment that scales. Required with the `authorization_code` grant, which redeems the codes `/authorize` issues into it; a composition without that grant wires none. A record round-trips `amr`, what the session vouched for at `/authorize`, which the grant stamps on the code's tokens; one that drops it issues them without `amr`, which their refresh family carries until it ends (under `mfa.mode = "required"`, refused at its first refresh). |
| `deviceCodeStore` | `DeviceCodeStore` | optional | `core/device-authorization/types.mts` | Pending RFC 8628 device authorizations. Written as atomic operations rather than read-then-write pairs: `poll` reads the status *and* consumes an approval in one step, because two concurrent polls that both observe `approved` mint two tokens from one human approval. Absence must be declared (#298). |
| `federationProviders` | `ReadonlyMap<string, FederationProvider>` | optional | `core/modules/manifest/synthetic-keys.mts` | Upstream IdP protocol adapters, contributed per federation module. The value type is the adapter port in `core/src/federations/types.mts`; it read `unknown` until that contract moved into core (#626 P1). |
| `federationRedirectPolicies` | `{ readonly [name: string]: FederationRedire…` | optional | `session/federations/contributes.mts` | Per-federation `redirect_to` allowlist factories. Paired with the provider at boot; an unpaired one refuses. |
| `federationTokenStore` | `FederationTokenStore` | optional | `core/federation-tokens/types.mts` | Upstream tokens held on behalf of a session. Encrypted at rest by the bundled adapter. |
| `federationGrantBackground` | `FederationGrantBackground` | optional | `federation-grants/background.mts` | Not an adapter seam but lifecycle infrastructure, for work the provider itself starts and deliberately does not make a caller wait for (#593, D12): letting go of a refresh lock, telling the sink, recording a use, and a refresh that outlived the soft deadline and is still holding its lock until the rotated credential is written down. One per application. Its cleanup drains, and its dependency edges on `federationGrantStore`, `subjectRevocation` and `auditSink` are what put that drain ahead of their cleanups — an adapter that closed first would fail the write being waited for. Filled by `federationGrantBackgroundModule`; an enabled deployment registers the drain's tail with `lifecycleRegistrar`, sized by its refresh budgets and at least 45 seconds, which `AppHandle.cleanupAllowanceMs` reports — a host's default cleanup budget, ten seconds in the standalone, is shorter. |
| `federationGrantIntentStore` | `FederationGrantIntentStore` | optional | `core/federation-grants/intentStore.mts` | Acquisition's records (#593, D16, slice 6), the second port of federation grants: the intent a confidential client lodged, the consent challenge the deployment's page answers, the connect transaction the upstream callback consumes, and the bound on live first-time intents per `(client, subject)` — the only admission control in front of `createPending`, which is why it refuses at capacity instead of evicting. Its keys share a tag of their own and no operation spans this port and the grant store: supersession is settled by the grant's current-intent pointer, and core orders the two writes once. One deadline governs a whole acquisition — the intent's — and the consent and the transaction carry it rather than one of their own, because nothing extends a `pending` grant's pointer. Every operation takes the time from its caller and reclaims on the adapter's own clock; a record it cannot read is refused rather than healed. Bundled adapters: memory (`memoryFederationGrantIntentStoreModule`, single replica) and Redis (`redisFederationGrantIntentStoreModule`). Its consumer is the acquisition routes of #593 slice 6. |
| `federationGrantStore` | `FederationGrantStore` | optional | `core/federation-grants/store.mts` | Federation grants (#593): one user's consent that one client may obtain upstream access tokens through one connection, which outlives the session — the records, the upstream credentials kept beside each (sealed at rest by an adapter that persists them; the bundled one holds them in memory, unsealed), and the lock a refresh holds. Every transition is a guarded write inside the store. Every operation on a record takes the time from its caller, and what a caller is told is judged on that time alone; what an adapter reclaims is judged on its own clock. Its consumer is the federation grant routes of #593. Bundled adapters: memory (single replica) and Redis (`redisFederationGrantStoreModule`, #593 slice 4 — configured by its own section, `redis-federation-grant-store`: its layout, its retention and its key ring). |
| `githubFederationConfig` | `GithubProviderConfig` | optional | `federation-github/github.mts` | Config slice for the bundled GitHub federation module. |
| `googleFederationConfig` | `GoogleProviderConfig` | optional | `federation-google/google.mts` | Config slice for the bundled Google federation module. |
| `grantPolicy` | `GrantPolicyHook` | optional | `core/policy/types.mts` | Deployment-supplied hook consulted at grant dispatch, for policy this library does not model. |
| `keyStore` | `KeyStore` | required | `core/keys/KeyStore.mts` | Signing and verification keys. `sign()` is the seam a KMS/HSM implements without surrendering the private key (#303). |
| `mfaFactorStore` | `MfaFactorStore` | optional | `core/mfa/factorStore.mts` | Enrolled second factors (the MFA ADR's D7): one record per factor, keyed by subject and id, whose `data` the MFA package seals before it arrives and every store keeps byte for byte without reading. `update` is a compare-and-set on the record's `version`; a store that cannot answer throws, because an outage read as "no factors" would open a first binding. Bundled adapters: memory (`memoryMfaFactorStoreModule`, single replica; a restart empties it, which it warns about), Redis (`redisMfaFactorStoreModule`: one hash per subject with no TTL; it refuses a server whose `maxmemory-policy` is `allkeys-*` at boot and warns when the server keeps no AOF, D12) and the Store (`foundationMfaFactorStoreModule`, `foundation/mfa/module.mts`: `HttpMfaFactorStore` over the `foundation-mfa-factor-store` section's four URLs, on the Store transport settings — the user repository's HTTP settings — the composition root must hand it; the Store is trusted with the factors' integrity and freshness, which the provider cannot check). The Store's contract — the endpoints, what each answer means and that nothing the Store sends reaches a client when a call fails — is `@o3co/auth-provider-foundation`'s README ("The Store's MFA endpoints"), the JSON bodies and their codec `core/mfa/storeWire.mts`, and what a failure throws `foundation/mfa/storeFailure.mts`. Suite `mfaFactorStoreContract`, on `@o3co/auth-provider-test-kit`. |
| `mfaTransactionStore` | `MfaTransactionStore` | optional | `core/mfa/transactionStore.mts` | MFA transactions and the subject lock (the MFA ADR's D8, D21). A transaction is the single-use record of one second-factor ceremony, bound to what started it through a typed `binding` (`MfaTransactionBinding`, a union discriminated by `kind`: `{ kind: "session", id }`, a browser session, alone today; #742) that a store keeps whole and every use compares whole, kind included (`isMfaTransactionBoundTo`; `getBoundMfaTransaction` answers a transaction bound to anything else as an unknown id); every operation a race could split is atomic in the store — `reserveAttempt` spends an attempt before a proof is checked, `takeChallenge` answers a challenge once, `consume` gives the transaction to one verification. The subject state bounds guessable proofs across transactions on the time the caller passes: the consecutive run with its short backoff and hard limit, and the weekly budget no success refunds and no attempt bypasses; `readMfaSubjectAttemptReservation` is the one reading of what `reserveSubjectAttempt` answers — a pass with its reservation, a non-empty string, or a hold the port names with `first` and a time to come back (`null` for the hard hold, else above 0) — anything else being an outage, never a pass or a hold. It also keeps the email proof an operator reset requires at the subject's next first binding (D25), which must last as the enrolled factors do, and the account-email proof (D24) given in one session of a subject: `recordSessionEmailProof(subject, sid, provedAtMs, untilMs)` replaces an earlier one for that session, and `sessionEmailProofAt(subject, sid, nowMs)` answers when it was given, no later than `nowMs`, while `untilMs` is after both `nowMs` and the store's clock — never for another session or subject; its loss fails closed (the user proves again), and a caller reads the answer through `readSessionEmailProof`, anything else being an outage. The MFA package records it when the account-email proof its step-up opened is verified, standing `mfa.manage.maxAgeSeconds`, and its `mfa` requirement reads it at each first binding in that session. It also keeps a subject's first-binding mark (D12): `noteFirstBinding(subject, atMs, untilMs)` notes that a first counting factor was bound for the subject, or its witness marked, at `atMs` — at most `DEFAULT_CLOCK_SKEW_MS` either side of the store's clock — standing until `untilMs` on the store's clock, and of the mark held and the one noted keeps the later time and the later end (`laterFirstBindingMark`), so no note moves it back or shortens it; `firstBindingAt(subject, nowMs)` answers `atMs`, never moved earlier, while `untilMs` is after the store's clock — the caller's time never ends a mark (`firstBindingAnswer`) — and a caller reads the answer through `readFirstBindingAt`, anything but `null` or a whole instant up to `nowMs` plus `DEFAULT_CLOCK_SKEW_MS` being an outage. An applied recovery leaves the mark. The mark does not stand in for the enrollment witness: it covers only the window in which a session's recorded witness can be stale. A store that cannot read a mark it holds rejects; an absent mark trusts the session. It also keeps, per subject, the authorized recovery of the lock state (`authorizeSubjectRecovery`, `applySubjectRecovery`: the one way the lock state ends early, applied under the subject's lease, each answer saying whether the hard hold stands), the subject's generation (`subjectGeneration`), moved by each applied recovery and only under the lease, the lease a writer of the factor set holds (`acquireSubjectLease`, under the generation the writer captured, refused `stale` once it moved, and `releaseSubjectLease`), and the recovery-set floor (`raiseRecoverySetFloor`, under the lease, to a recovery-code set's generation — not the subject's — and `recoverySetFloor`), which nothing lowers. These are required methods: a store of your own adds them, and drops `clearSubjectState`. No Store variant: this is verification state. Bundled adapters: memory (`memoryMfaTransactionStoreModule`, single replica; a session's proofs and a subject's marks counted against its cap with the transactions, and swept) and Redis (`redisMfaTransactionStoreModule`: one script per atomic operation, D21's lock over a hash and a sorted set, the recovery hash and the lease under the subject's tag, a session's proof in a key family of its own with `PX` on the store's clock, a subject's mark in another judged on the server's clock alone — its end, the keep rule and its `PXAT` deadline, in one script — and the factor store's boot check). |
| `mailSender` | `MailSender` | optional | `core/mail/types.mts` | Where the one-time codes the provider issues leave it (the MFA ADR's D5; the boundary section says why it is here). `send` takes what a mail means (`MailSend`: `purpose`, one of `MAIL_PURPOSES`; the account's `subject`; `to`, the address on its user record at that moment; `code`; `expiresAtMs`) and answers `delivered` once the relay holds it or `refused_at_limit` (the provider's `429`); anything else — a rejection, or any other answer — is an outage (`503`), never "sent" (`mailSendOutcome` is the one reading), and a rejection's loggable projection carries nothing of the mail. Rendering, delivery and send limits are the sender's. A factor never calls it: a challenge or an enrollment answers the purpose and code it asks to be mailed, and the MFA package sends. `mfaModule` reads it optionally: without it a factor that asks for a mail is an outage, the account-email proof cannot be given, and `mfa.enrollment.requireEmailProof = "always"` refuses the boot (`"when-mail"` warns once). `mfaEmailFactorModule` reads it optionally too: with `mfa-email-factor.enabled` on and no sender, it refuses the boot, naming the slot. The recipient is the account's address as the login's `User` carries it (`normaliseMailAddress`) — at a login the password check's answer, in a signed-in session the `User` its cookie holds; a login code goes only when that address matches the keyed digest the email factor recorded at enrollment — the digest of the address its enrollment code went to, which the coordinator kept at the send and handed it — so the provider stores no address and a changed one redirects no code. In core because its implementer and its consumer must not depend on each other. `@o3co/auth-provider-standard` holds `standardSmtpMailSenderModule` (its section, `standard-smtp-mail-sender`, and the SMTP sender over nodemailer, built only where the slot is read: one envelope recipient, the send's `to` as written; STARTTLS required unless `secure` is `tls`, plaintext only to a loopback peer; a deadline for the whole send; a limit only from a transient reply's enhanced code, anything else a `MailTransportError` built from the reply's codes and an allowlisted transport code alone) and `standardDevelopmentMailSenderModule`, which logs each code and installs only where the name the configuration was selected by, and `CONFIG_ENV` and `NODE_ENV` where set, each read `development` or `test`. Suite `mailSenderContract` (`@o3co/auth-provider-test-kit`), double `createRecordingMailSender` (`@o3co/auth-provider-core/testing`). |
| `oidcFederationConfigs` | `Readonly<Record<string, OidcProviderConfig>>` | optional | `federation-oidc/module.mts` | Config of every generic OpenID Connect federation instance, keyed by federation name; each `oidcFederationModule(<name>)` reads its own entry. `readOidcFederationConfigs` builds it from `core.federations` (#524). |
| `rateLimiter` | `RateLimiter` | optional | `core/ratelimit/types.mts` | Shared counters for the OAuth endpoints, the login brute-force guard and the MFA routes' flood guard (the MFA module falls back to a per-process limiter without one, refused under `multi`). Its optional `failMode` is the limiter's own outage policy (#728) — `open` or `closed`, what the guard does when `check` throws — owned by the module that builds the limiter, and the only place the guard reads the policy: read once when the guard or a policy is built, absent meaning `closed`, as on the in-process limiter, which has no backend to lose, and any other value refusing the build. Its optional `defaultLimit` is the budget a key falls to when nothing covers its prefix; boot holds an override of a switched-off budget to it. The Redis limiter module answers its own `redis-rate-limiter.failMode`; any other limiter answers its own, and boot warns `rate_limit_fail_mode_not_applied` when `rateLimit.failMode`, that key's old path, says `open` and the wired limiter does not. A wrapper around a limiter forwards `failMode` and `defaultLimit`, or the guard fails closed and overrides of switched-off budgets are refused. Suite `rateLimiterContract`, double `createTestRateLimiter`. |
| `refreshTokenFamilyRevocation` | `RefreshTokenFamilyRevocation` | optional | `core/refresh-token-family/types.mts` | Family-wide revoke, used on replay detection and on the credential-change cascade. |
| `refreshTokenFamilyRotation` | `RefreshTokenFamilyRotation` | optional | `core/refresh-token-family/types.mts` | Atomic rotate-or-detect-replay. Wired separately so a deployment can have the store without the CAS path. |
| `refreshTokenFamilyStore` | `RefreshTokenFamilyStore` | optional | `core/refresh-token-family/types.mts` | Refresh-token family records — the state rotation and replay detection read. |
| `replaySeenSet` | `ReplaySeenSet` | optional | `core/replay-seen-set/types.mts` | The generic seen-set primitive the replay stores are built on: one atomic check-and-mark per single-use value, scoped per consumer. Records `private_key_jwt` `jti`s, consumed WebAuthn challenges and every accepted DPoP proof (`dpop-proof:<jkt>`); DPoP enabled with the slot empty refuses to boot. The jwt-bearer ID-JAG verifier takes its seen-set as an option from the composition, not from this slot. |
| `sessionFamilyIndex` | `SessionFamilyIndex` | optional | `core/user-sessions/types.mts` | Session → refresh-token families, so logout can revoke them. The session-end capability `SupportsSessionEnd` (`endSession`, `addFamilyIdUnlessEnded`, detected by `supportsSessionEnd`) is optional: for a logout's end and a grant's add on one session, the end lists the family or the add answers `"ended"`, while the store keeps its reads and writes linearizable and serves reads from the primary, for operations inside the session's life on every clock involved; the mark lasts the life plus `DEFAULT_CLOCK_SKEW_MS`. Both bundled indexes have it; the Redis one over a `SessionFamilyIndexClient` with `writeEndedMark` and `hasEndedMark`, and an `endedKeyPrefix`. |
| `sessionFederationIndex` | `SessionFederationIndex` | optional | `core/user-sessions/types.mts` | Session → upstream federations, so logout can propagate. |
| `sessionRPRegistry` | `SessionRPRegistry` | optional | `core/user-sessions/types.mts` | Which RPs a session has authenticated to, for back-channel logout. |
| `subjectRevocation` | `SubjectRevocation` | optional | `core/user-sessions/types.mts` | Per-subject not-before watermark: what a credential change stamps so tokens minted before it stop verifying. Absence must be declared (#406). Session admission reads it for a live record, so every module that admits a browser session reads it — the MFA module's routes among them, for an enrollment from a signed-in session and its step-up. |
| `subjectRevocationService` | `SubjectRevocationService` | optional | `core/user-sessions/subjectRevocationService.mts` | Not an adapter seam: the composed operation a Store calls to end everything one subject holds (#593, D13) — the boundary, their sessions, and their federation grants. It is a component rather than the free `revokeAllForSubject` because building it needs every session store plus the cascade, and because the one decision it carries — whether a caller MAY ask for the subject's established grants to be kept — belongs to the operator (`federation-grants.allowKeepOnSubjectRevocation`) and not to the caller. Filled by an explicitly installed module in `@o3co/auth-provider-oauth`, where `cascadeLogout` lives. |
| `mfaReset` | `MfaReset` | optional | `mfa/reset.mts` | Not an adapter seam: the operator reset a Store calls for a subject who lost their second factors (the MFA ADR's D25), `resetMfaForSubject(subject, { requireEmailProof?, federationGrants?, requestedBy? })` — every session and token ended through `subjectRevocationService`, then, under the subject's lease in the MFA transaction store, the lock state reset, every factor record removed and the enrollment witness cleared. A component because it composes those three. Filled by `mfaResetModule` in `@o3co/auth-provider-mfa`, declared by that package's `ComponentMap` augmentation; it requires `mfaSubjectLeases`, so the reset is available only where `mfaModule` is installed (not under `mfa.mode = "off"`). |
| `mfaSubjectLeases` | `MfaSubjectLeases` | optional | `mfa/factorSet.mts` | Not an adapter seam: the subject's lease owner, built by `mfaModule` from the `mfaTransactionStore` slot and `mfa.storeTimeoutMs`: every writer of a subject's factor set — the MFA routes' and the operator reset — holds a lease of the same rules (sixteen of the timeout: the most Store calls one writer makes, the acquire and one to spare; the per-call bound; the wait rules). An opaque handle; only the MFA package reads it. Filled by `mfaModule`, which declares it authoritative (no `overrideComponents` entry while `mfaModule` is loaded), declared by `@o3co/auth-provider-mfa`'s `ComponentMap` augmentation, and required by `mfaResetModule`. |
| `subjectSessionIndex` | `SubjectSessionIndex` | optional | `core/user-sessions/types.mts` | Subject → live sessions, so a credential change can enumerate what to cascade over. Absence must be declared (#406). |
| `userRepository` | `UserRepository` | required | `core/repositories/UserRepository.mts` | **The verify seam.** `authenticate` / `authenticateByToken`, plus the optional `linkFederatedIdentity` a `?link=1` flow relays to the Store, which decides, and the optional `markMfaEnrolled`, the MFA enrollment witness the provider writes and the Store answers back as `User.mfaEnrolled` — see the boundary section; over HTTP it is `markMfaEnrolledUrl` (`{ subject, enrolled }`, `204`, `404` for a subject the Store does not hold), in foundation's README, and its suite is `@o3co/auth-provider-test-kit`'s. `HttpUserRepository` has no `markMfaEnrolled`: foundation runs the suite with a stand-in for the write, reading the witness back through `authenticate`. `mfaModule` reads the slot optionally, for `markMfaEnrolled` alone: it marks the witness after a first counting factor is written and when a login's verification finds it missing, and says once at boot when the directory cannot. The optional pair `supportsFederatedIdentityLookup` / `findSubjectByFederatedIdentity` is what a federation-grant callback asks (D7 check 5, #611): whether the Store covers a registration with the claims its connection names — asked at boot — and who holds an identity from it, given the registration, the `sub` and those verified claims (Entra's `tid`/`oid` for a directory Store), as `linked` / `unlinked` / `indeterminate`. The bundled `InMemoryUserRepository` covers none. |
| `userSessionStore` | `UserSessionStore` | optional | `core/user-sessions/types.mts` | The session records themselves, keyed by `sid`. A record round-trips `authentication` (how the session was established, the MFA ADR's D9) and, when the session recorded them, `enrollmentFacts` (what the login's `User` said for a first binding: the enrollment witness and what its address is — none, one the provider reads, or one it cannot (`mailAddress`: `none`, `address`, `unreadable`), the MFA ADR's D12 and D24) — an optional key a store of your own must round-trip, recording what `recordableEnrollmentFacts` answers. A session without it recorded nothing, and a reader decides what that means: the MFA ADR's D12 has the `mfa` requirement send it to log in before a first binding. The step-up capability `SupportsSecondFactorUpdate` (`recordSecondFactor`, detected by `supportsSecondFactorUpdate`) is optional; without it a step-up asks for a re-authentication. A store that has it records the event's `renewalNonce` in the escalation's write and round-trips it as `UserSession.renewalNonce` — an optional key, and admission refuses every cookie session but the one holding it (the MFA ADR's D27) — and records only while the session's nonce is the event's `expectedRenewalNonce` (absent matching absent: core's `readRenewalNonces` reads the event's two nonces once, and `expectsRenewalNonce` compares), in the same atomic step, answering `null` otherwise; both bundled stores do. A store of your own that drops it leaves an escalated session unbound, and an old express id a request in flight saved back after the renewal gains the escalation. |
| `webauthnConfig` | `WebAuthnConfig` | optional | `webauthn/config.mts` | The WebAuthn relying party (`rpId`, `rpName`, the allowed origins) and the rest of the webauthn package's settings, as `webauthnConfigSchema` parses them — the one slot for the relying party (#728). Only the webauthn package's modules read it — the grant's (`webauthnModule`) and the WebAuthn second factor's (`webauthnMfaFactorModule`, the MFA ADR's D4) — so its contract stays there rather than in core. A composition root's bootstrap module provides it today; the webauthn package is to provide it from its own section. |
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
| `mfaTransactionStoreClient` | `MfaTransactionStoreClient` | optional | `redis/clients.mts` | Vendor-facing half of the MFA transaction store (the MFA ADR's D8, D21, D25). Semantic operations, one script each, because every one the port calls atomic reads, decides and writes: insert-only `create`, the version compare-and-set, `reserveAttempt`, `takeChallenge`, `consume`, and D21's three subject-lock operations over the lock hash and the week's sorted set, which share the subject's tag. The email-proof requirement is one command each way, in a key with no TTL; a session's account-email proof is one command each way too (`SET … PX`, `GET`). |
| `pendingConsentStoreClient` | `PendingConsentStoreClient` | optional | `redis/clients.mts` | Vendor-facing half — what `@o3co/auth-provider-redis` needs from a driver, not what a module consumes. Semantic operations (`set` / `get` / `consume` / `discard`): `consume` reads and removes a parked request with its per-session index entry in one step, and `discard` reclaims one the adapter found corrupt only while it is still the value read (#561). |
| `rateLimiterClient` | `RateLimiterClient` | optional | `redis/clients.mts` | Vendor-facing half — what `@o3co/auth-provider-redis` needs from a driver, not what a module consumes. |
| `refreshTokenFamilyClient` | `RefreshTokenFamilyClient` | optional | `redis/clients.mts` | Vendor-facing half — what `@o3co/auth-provider-redis` needs from a driver, not what a module consumes. |
| `replaySeenSetClient` | `ReplaySeenSetClient` | optional | `redis/clients.mts` | Vendor-facing half — what `@o3co/auth-provider-redis` needs from a driver, not what a module consumes. |
| `sessionFamilyIndexClient` | `SessionFamilyIndexClient` | optional | `redis/clients.mts` | Vendor-facing half — what `@o3co/auth-provider-redis` needs from a driver, not what a module consumes. |
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
| `auditSink` | `AUDIT_SINK_ABSENCE_POLICY` | `core.declaredAbsent = ["auditSink"]` |
| `accessTokenDenylist` | `ACCESS_TOKEN_DENYLIST_ABSENCE_POLICY` | `oauth.revocation.accessToken = "unsupported"` |
| `subjectRevocation` | `SUBJECT_REVOCATION_ABSENCE_POLICY` | `oauth.revocation.subject = "unsupported"` |
| `subjectSessionIndex` | `SUBJECT_REVOCATION_ABSENCE_POLICY` | `oauth.revocation.subject = "unsupported"` |
| `deviceCodeStore` | `DEVICE_CODE_STORE_ABSENCE_POLICY` | `device-grant.store = "unsupported"` |

There is no absence policy for MFA: the `mfaCoordinator` slot and
`MFA_ABSENCE_POLICY` left with the session-admission ADR (D6, D7). What a
composition expects of session admission is declared by
`core.sessionRequirements.expected` instead: a name there that no module registers
refuses the boot (`session-requirement-missing`), `mfa` without the MFA
package among them.

A declaration is either the one value a key of the feature's own holds, or,
where the slot is a composition's choice rather than a feature's, the slot's
name in core's own list, `core.declaredAbsent`, beside the other names it
holds. `isAbsenceDeclared` is the one reading of a declaration, and
`describeAbsenceDeclaration` the one way of saying how to write it.

The subject-revocation pair shares one policy on purpose: two components, one
capability, so a deployment without them has one thing to declare rather than
two. `deviceCodeStore` joined with #443, which this paragraph missed while it
still said "three"; the table is now checked against the manifests that attach
each policy, the same way the slot table is (#458).

A declaration says why a slot is empty; it does not stand in for the component
where a feature needs it. `device-grant.store = "unsupported"` is
for a deployment that leaves the grant off — `deviceGrantModule` with the grant
enabled refuses to boot without a store, whatever the declaration says (#626).

**Replica safety.** In-process state stores are correct on one node and wrong on
several. `core.deployment.mode = "multi"` with one wired refuses boot, naming each
offender and what diverges per replica; `"single"` is silent; unset warns. The
list of unsafe modules is drift-guarded (#304), so a new in-memory adapter cannot
be silently replica-unsafe.

**Shutdown.** A component that holds a connection or a timer registers its
teardown with `lifecycleRegistrar`; `dispose()` drains in reverse-topological
order and waits for every cleanup. A cleanup whose work may take long
registers a tail (`register(cleanup, { tailMs })`, a whole number of
milliseconds a timer can wait): the least time a host that bounds `dispose()`
must allow the whole of `dispose()`, the cleanups around it included.
`AppHandle.cleanupAllowanceMs` is the longest registered; tails do not add.

**Proving an implementation.** Several ports ship a conformance suite an
out-of-tree adapter can import and run:

| Port | Suite |
| --- | --- |
| `KeyStore` | `packages/core/src/keys/__tests__/keyStore.contract.mts` |
| `SubjectSessionIndex` | `packages/core/src/user-sessions/__tests__/subjectSessionIndex.contract.mts` |
| `SubjectRevocation` | `packages/core/src/user-sessions/__tests__/subjectRevocation.contract.mts` (`runSubjectRevocationContract`); its boundary on the store's clock, `packages/core/src/user-sessions/__tests__/subjectRevocation.clock.contract.mts` (`runSubjectRevocationClockContract`) |
| `SupportsSessionsOnlyRevocation` (the `SubjectRevocation` second-boundary capability; run only for a store that claims it) | `packages/core/src/user-sessions/__tests__/subjectRevocation.contract.mts` (`runSessionsOnlyRevocationContract`), and on the store's clock `packages/core/src/user-sessions/__tests__/subjectRevocation.clock.contract.mts` (`runSessionsOnlyRevocationClockContract`) |
| `AccessTokenDenylist` | `packages/core/src/access-token-denylist/__tests__/adapters.contract.mts` |
| `ChallengeStore` | `packages/core/src/challenges/__tests__/adapters.contract.mts` |
| `ConsentStore` | `packages/core/src/consents/__tests__/adapters.contract.mts` |
| `DeviceCodeStore` | `packages/core/src/device-authorization/__tests__/adapters.contract.mts` |
| `FederationGrantStore` | `packages/core/src/federation-grants/__tests__/store.contract.mts` |
| `FederationGrantIntentStore` | `packages/core/src/federation-grants/__tests__/intentStore.contract.mts` |
| `MfaFactorStore` | `packages/test-kit/src/mfa/factorStore.contract.mts` (`mfaFactorStoreContract`), published on `@o3co/auth-provider-test-kit` |
| `MfaTransactionStore` | `packages/core/src/mfa/__tests__/transactionStore.contract.mts` |
| `PendingConsentStore` | `packages/core/src/consents/__tests__/pending.contract.mts` |
| `ReplaySeenSet` | `packages/core/src/replay-seen-set/__tests__/adapters.contract.mts` |
| `RefreshTokenFamilyStore` | `packages/core/src/refresh-token-family/__tests__/adapters.contract.mts` |
| `WebAuthnCredentialStore` | `packages/test-kit/src/webauthn/credentialStore.contract.mts` (`webAuthnCredentialStoreContract`), published on `@o3co/auth-provider-test-kit` |
| `UserSessionStore` | `packages/core/src/user-sessions/__tests__/userSessionStore.contract.mts` (`runUserSessionStoreContract`) |
| `SupportsMfaEnrollmentWitness` (the `UserRepository` capability `markMfaEnrolled`, answered back as `User.mfaEnrolled` on `authenticate` and on `authenticateByToken`; run only for a repository that claims it) | `packages/test-kit/src/mfa/enrollmentWitness.contract.mts` (`mfaEnrollmentWitnessContract`), published on `@o3co/auth-provider-test-kit`; foundation runs it over `HttpUserRepository` against the kit's fake Store |
| `SupportsSecondFactorUpdate` (the `UserSessionStore` step-up capability; run only for a store that claims it) | `packages/core/src/user-sessions/__tests__/userSessionStore.contract.mts` (`runSecondFactorUpdateContract`) |
| `SessionRPRegistry` | `packages/core/src/user-sessions/__tests__/sessionRPRegistry.contract.mts` |
| `SessionFamilyIndex` | `packages/core/src/user-sessions/__tests__/sessionFamilyIndex.contract.mts` |
| `SupportsSessionEnd` (the `SessionFamilyIndex` session-end capability; run only for an index that claims it) | `packages/core/src/user-sessions/__tests__/sessionFamilyIndex.contract.mts` (`runSessionEndContract`) |
| `SessionFederationIndex` | `packages/core/src/user-sessions/__tests__/sessionFederationIndex.contract.mts` |
| `RateLimiter` (`failMode` included) | `packages/core/src/testing/slots/rateLimiter.mts` (`rateLimiterContract`) |
| `MailSender` | `packages/test-kit/src/mail/mailSender.contract.mts` (`mailSenderContract`), published on `@o3co/auth-provider-test-kit`, over core's `createRecordingMailSender`, and the standard package's SMTP sender over a scripted relay and over Mailpit |
| `MfaFactor` (a second factor contributed as `mfaFactors`; a contribution, not a slot) | `packages/test-kit/src/mfa/factor.contract.mts` (`mfaFactorContract`), over core's doubles `createTestMfaFactor` and `createTestMfaDigests` |
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
them: the Redis rate limiter runs `rateLimiterContract` that way.
`@o3co/auth-provider-test-kit` is a published package of suites of its own,
which depends on core alone: the enrollment witness's suite is there, with a
fake Store it runs against, and foundation's tests run it; so is
`MfaFactorStore`'s, `mfaFactorStoreContract`, which the kit's own tests run
over core's in-process store, the Redis package's over its store (no copy),
and foundation's over `HttpMfaFactorStore` and the fake Store; so is a
second factor's, `mfaFactorContract`, which the MFA package's TOTP factor
and the webauthn package's WebAuthn factor run, and which the kit's own tests
run over core's doubles; and so is a mail sender's, `mailSenderContract`,
which the standard package runs over its SMTP sender; and so are the generic
suites of the conditional-write convention, `conditionalRecordContract` and
`conditionalSetContract`
(`packages/test-kit/src/conditionalWrite/conditionalWrite.contract.mts`),
which a port's binding runs over its conditional members, and which the kit's
own tests run over reference stores and stores broken one rule at a time. A new port
should gain a suite: "typed and swappable" means an implementer can prove they
got it right, not only that they read the interface carefully.

What the suites hold an adapter to:

- **Records come back whole, as plain data.** A port that returns one of the
  records whose fields are all required keys (#626) has a suite that compares
  whole records with `toStrictEqual`. A field with no value must come back
  named, as `undefined`, not left out. An extra key, or a class instance in
  place of a plain object, also fails. `CodeRepository`, `FederationTokenStore`
  and `AssertionIssuerRegistry` return such records but ship no suite yet; the
  bundled adapters' own tests hold them to the same rule. The exception is
  `FederationTokens.obtainedAt`, the one optional key, which is left out when
  unset.
- **Only the inputs the port's types allow.** How an adapter treats a value
  outside them, such as a `null` or `""` from an untyped caller, is up to the
  adapter, and its own tests cover it. For example, the bundled device-code
  stores' tests cover a falsy `requestedScope`, which the device-code suite
  does not.

## Conditional writes

A port whose callers must not overwrite or restore what another writer
changed since they read it has **conditional members**: a versioned read that
answers what is stored with its **store generation**, and writes applied only
while what they guard is still at the generation the caller read. The types,
`isStoreGeneration`, `newStoreGeneration` and core's readers of every answer
are in `packages/core/src/adapters/conditionalWrite.mts`, on core's root
entry, with `BUNDLED_STORE_WRITE_LIFETIME_MS`, the bundled stores'
write-lifetime bound. `@o3co/auth-provider-test-kit`'s
`conditionalRecordContract` and `conditionalSetContract` hold a store to
the rules they can observe. A store's own tests cover the rest: minting into
state written without a generation and keeping generations from coming back
after a rollback (rule 8), and the retention's length and the write-lifetime
bound (rule 6). These are the rules every store with conditional members keeps.

**Scopes.** A generation guards one of two things:

- **A record** (record-scoped): every write of the record issues a new
  generation. `replaceIf` answers `ConditionalReplaceAnswer` (`updated` with
  the new generation, `missing` or `conflict`), `removeIf` answers
  `ConditionalRemoveAnswer` (`removed`, which carries no generation since the
  record is gone, `missing` or `conflict`), and the versioned read answers
  `Versioned<T>` or `null`.
- **A set's membership** (set-scoped): every membership write issues a new
  generation, and a member's own update, fenced by the member's own version,
  keeps it. The versioned read answers `VersionedSet<T>`, whose `generation`
  is `null` only for an absent set: never written, or its tombstone expired.
  `createIf` answers
  `ConditionalCreateAnswer` (`created` with the new generation, or
  `conflict`; never `missing`), and `removeIf` answers
  `ConditionalSetRemoveAnswer` (`removed`, always with the set's new
  generation, `missing` or `conflict`).

**The rules.**

1. **Atomic.** The check and the write are one atomic step in the store: a
   transaction, a compare-and-set or a script. An in-process lock counts only
   for an in-process store. An unconditional write (a reset, a logout-style
   delete, a create such as `attach`) is one atomic step too, serialised with
   the conditional ones, so a conditional write never interleaves with it.
2. **One snapshot, and every write moves the generation.** A versioned read
   answers the value (or the members) and the generation from one snapshot,
   which reflects every write acknowledged before the read began: never a
   cache or a lagging replica.
   Every write that changes what the generation guards issues a new one,
   legacy and unconditional writes included.
3. **Expiry is the store's retention.** A record past it reads as `null`
   and answers `missing` to a replace or a removal; a set past it (its
   tombstone expired) reads as `{ items: [], generation: null }` and answers
   as an absent set does (rule 4). The conditional check includes the expiry
   predicate. The retention is the store's own (a Redis `PX`, a SQL
   `expires_at` set from the store's TTL), never a domain field such as an
   access token's `expiresAt`.
4. **Outcomes.** An outage rejects; it is never `missing` or `null`. A
   rejection after the request was sent means "unknown", never "not
   written". `missing` and `conflict` each write nothing. A set's
   `createIf` with the set absent and an `expected` generation, with the set
   present and `expected` `null`, or with a member id already held answers
   `conflict`. A set's `removeIf` against an absent set answers `missing`;
   against a present one it checks the generation before the member, so a
   moved set answers `conflict` and an absent member at `expected` answers
   `missing`. Core's readers refuse any answer outside its type with a
   `TypeError` (a `RangeError` stays a caller's own input), which the caller
   treats as the store's outage.
5. **Unconditional writes that must win stay**: a logout, a removal of
   everything a session or subject holds, an operator reset. An
   unconditional removal removes; an unconditional write issues a new
   generation.
6. **Sets.** The generation belongs to the set's membership. Removing the
   last member keeps the set, at a new generation; the unconditional reset
   upserts the set at a new generation, creating it when absent. A set
   emptied by any membership write (its last removal or a reset, of an
   already empty set too) keeps its tombstone:
   - **A set reads absent only once the bound (`BUNDLED_STORE_WRITE_LIFETIME_MS`
     for the bundled stores) has passed since its last membership write. A
     `createIf(…, null)` commits or fails within the bound of the read that
     answered `null`.**
   - Only that write needs the bound. A stale non-null generation always
     meets `conflict` or `missing`, because a generation is never re-issued
     (rule 8); a stale `null` would otherwise find a set that had come and
     gone, its tombstone expired.
   - The bound is allocated between two parties, each keeping its own
     share without the other's deadline:
     - **The adapter declares its write lifetime W**: the longest an issued
       conditional write may take to commit or fail, under its documented
       operational assumption (for example, a Redis command timeout cannot
       withdraw a command already written to the socket). W is well under
       the bound.
     - **The port's owning module issues a conditional write only within
       (bound − W) of the read** that produced its expected generation (for
       example, under a lease far shorter than that). Callers outside that
       module never hold a generation.
     - Together, read to commit is at most (bound − W) + W = the bound. No
       deadline crosses the port: the adapter never needs the read's.
   - What remains is a named assumption: the process or the store does not
     stall for the whole bound between a `null` read and its commit.
7. **A generation fences only its own store's records.** It does not fence a
   write to another port, unless both are in the same atomic step.
8. **Never re-issued: minted, never derived.** A generation is never issued
   again for its key: not after a delete and a re-create, a byte-identical
   rewrite, a tombstone's expiry, or a failover or restore that loses
   writes. So it is random, never derived from state. A random (v4) UUID is
   one: `newStoreGeneration`, Postgres `gen_random_uuid()`, or MySQL
   `LOWER(HEX(RANDOM_BYTES(16)))`. A digest is not (it repeats with the
   content), nor a timestamp (it repeats with the clock), nor MySQL `UUID()`
   (v1, time-based), nor a counter, even one kept in the same store: a
   failover or a restore that loses the latest writes rolls it back to a
   value already issued.
   - **A rollback must not bring a generation back either.** A failover or
     restore that returns state from before a write the store acknowledged
     would serve that state's old generation again, which a caller may still
     hold. A store that can lose acknowledged writes re-mints the generation
     of everything it restores before serving it, or runs so that
     acknowledged state never rolls back (persistence, and a failover setup
     that keeps acknowledged writes), and its documentation says which: an
     assumption of the second kind is stated as one (the checklist below).
   - **State with no generation** (written before the store had conditional
     members, or by an older writer) is given a fresh one, atomically, by its
     first versioned read, which keeps its retention. A conditional write
     against it answers `conflict` and does not mint: a caller holds a
     generation only from a read that minted it, so a state without one was
     rewritten after that read.
   - **That protects only against an older writer that drops the
     generation**, by rewriting the whole value. A writer that changes what
     the generation guards but leaves the generation in place (a SQL `UPDATE`
     of the body with no trigger, a Redis `HSET` beside the generation's
     field) must not run beside conditional callers, unless the store moves
     the generation for it, as the SQL `BEFORE UPDATE` trigger below does.

**A store implementer's checklist.**

- Each conditional member is one atomic step (rule 1), the versioned read is
  one snapshot (rule 2), and the check includes the retention (rule 3).
- Every write of what a generation guards issues a new, random one, never
  re-issued, a rollback included (rules 2, 5 and 8). An older writer that
  leaves the generation in place is kept away, or covered by the store
  (rule 8).
- An outage rejects, and `missing` and `conflict` write nothing (rule 4).
- A set keeps its tombstone, and reads absent only once the bound has passed
  since its last membership write (rule 6).
- The adapter states its write lifetime W, well under the bound: an issued
  conditional write commits or fails within W. Its documentation says how,
  and states the operational assumption that rests on (rule 6).
- The port's owning module states its issue window, the longest from a
  versioned read to issuing a write conditional on it, and that the window
  is at most the bound less the adapter's W (rule 6).
- An adapter whose store can lose acknowledged writes (asynchronous
  replication on failover, say) states it: the store assumes acknowledged
  writes are not rolled back (persistence, plus a failover setup that keeps
  acknowledged writes). A deployment that accepts losing acknowledged writes
  on failover also accepts that a conditional write may then meet a restored,
  older generation (rule 8).
- The port's conformance suite passes, where it has one.

**A SQL store.** One row per record, `(key…, body, generation, expires_at)`;
`generation` is `NOT NULL`, a `uuid` (Postgres) or a `VARCHAR(64)` (MySQL),
made by the application with `randomUUID()`, and `expires_at` is the
retention.

- `replaceIf`: `UPDATE … SET body = :body, generation = :new WHERE <key> AND
  generation = :expected AND (expires_at IS NULL OR expires_at > <db now>)`.
  One row is `updated`. Zero rows: a `SELECT 1` of a live row with that key
  tells `conflict` (a row) from `missing` (none). A write that lands between
  the two can decide that label, so under a race the loser answers `missing`
  or `conflict`; either way it wrote nothing. Postgres can do both in one
  statement with a CTE, MySQL in one short `SELECT … FOR UPDATE` transaction.
  `removeIf` is the same with `DELETE`.
- **Adding the column to an existing table.** Backfill every existing row
  with its own random value, never a constant. For the whole time an older
  writer may run, keep a column default or a `BEFORE INSERT` trigger, so an
  `INSERT` that leaves the column out still gets a fresh value (Postgres
  `DEFAULT gen_random_uuid()`; MySQL 8.0.13 or later
  `DEFAULT (LOWER(HEX(RANDOM_BYTES(16))))`), and a `BEFORE UPDATE` trigger
  that renews a generation the statement left unchanged, so an older
  writer's `UPDATE` still moves it. Postgres: `IF NEW.generation IS NOT
  DISTINCT FROM OLD.generation THEN NEW.generation := gen_random_uuid(); END
  IF`. MySQL: `IF NEW.generation <=> OLD.generation THEN SET NEW.generation =
  LOWER(HEX(RANDOM_BYTES(16))); END IF`. Without that trigger, no older writer
  may run once a conditional caller does (rule 8).
- **Sets.** Every membership write is one transaction that locks the set's
  row first, then its members' rows, so there is one lock order. The reset
  upserts the set's row first, then deletes the members. The versioned read
  is one statement, or one snapshot, never a cache or a lagging replica.

**Over HTTP.** One `POST` per operation, with a JSON body each way.

- A conditional write's request carries `expectedGeneration`: a generation,
  or, for a set's `createIf` only, `null` for a set the caller read as
  absent. A request without `expectedGeneration` is `400`.
- `200` answers the operation's answer as its type states it:
  - a record's versioned read: `{ "value": <record>, "generation": "<g>" }`,
    or, for an absent record, `{ "value": null, "generation": null }`;
  - a set's versioned read: `{ "items": [<member>, …], "generation": "<g>" }`,
    or, for an absent set, `{ "items": [], "generation": null }`;
  - `replaceIf`: `{ "outcome": "updated", "generation": "<g>" }`;
  - a record's `removeIf`: `{ "outcome": "removed" }`;
  - `createIf`: `{ "outcome": "created", "generation": "<g>" }`;
  - a set's `removeIf`: `{ "outcome": "removed", "generation": "<g>" }`.
- A versioned read of something absent is a `200` stating its absence, never
  a `404`. The adapter answers a record's absence envelope, both fields
  `null`, as `null` from its versioned read; one field `null` without the
  other is malformed, and the adapter throws.

| Status | Meaning |
| --- | --- |
| `200` | Done, with the body above |
| `404` | `missing`, with the body `{ "outcome": "missing" }` (a record's write, and a set's `removeIf`) |
| `409` | `conflict`, with the body `{ "outcome": "conflict" }` |
| Anything else, `400` and `412` included, or a `404` or `409` without its body | The adapter throws: a bare status may be a misrouted request or an older Store |

A REST layer that offers ETags exposes the store's generation itself, the
never-repeating value the store issued, quoted as the strong ETag
`"<generation>"` (a generation holds no `"`), of exactly what the generation
guards — a whole record, or a set's membership — never a digest of its
content: content returns to earlier bytes, so a digest repeats. A set's
generation is not the ETag of a representation that also carries its
members' own data, which a member's update changes at the same set
generation.
