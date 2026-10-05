# @o3co/auth-provider-oauth

Last updated: 2026-10-05

The OAuth 2.0 / OpenID Connect authorization-server endpoints of [auth.provider](../../README.md): the HTTP surface under `/oauth`, the built-in grant types, client authentication, and the logout cascade.

## Responsibility

**Role.** The authorization server's HTTP face. [`@o3co/auth-provider-core`](../core/README.md) defines the ports, records, token primitives and the boot planner; this package turns them into the endpoints a client talks to — authorize, token, introspect, userinfo, revoke, consent, logout, federation token — and contributes this server's part of the discovery document. It sits beside [`@o3co/auth-provider-session`](../session/README.md) (login and the browser session) on top of core; neither imports the other.

**Owns:**

- the routes in the [Endpoints](#endpoints) table — other packages, such as the device grant and federation grants, mount routes under `/oauth` too — the order of the checks each one runs, and their wire answers;
- client authentication at every client-authenticated endpoint — `client_secret_basic`, `client_secret_post`, `private_key_jwt` and public clients where a route admits them — as one middleware, `createClientAuthMiddleware`, which [`@o3co/auth-provider-device-grant`](../device-grant/README.md) and [`@o3co/auth-provider-federation-grants`](../federation-grants/README.md) reuse;
- the built-in grants: `authorization_code`, `refresh_token`, `client_credentials`, `session` and RFC 7523 jwt-bearer;
- what each of its consumers of a session answers for each admission outcome — the redirect, the RFC 6749 error, the `401` — and the step-up trip `/authorize` sends a browser on (see [Session admission](#session-admission));
- the logout cascade (`cascadeLogout`), OIDC back- and front-channel logout, and the module that wires core's subject revocation service over that cascade;
- resolving Client ID Metadata Documents: the fetch, its SSRF guard and its cache;
- the discovery slice this server's endpoints and capabilities contribute.

**Does not own:**

- the ports and records (`ClientRepository`, `CodeRepository`, `KeyStore`, `UserSessionStore`, the `Client` record …), token minting and verification (`generateToken`, `verifyJwt`), the grant contract and the registry `/oauth/token` dispatches against, the discovery document itself and `jwks_uri` — core;
- whether a session may proceed — the live read, the subject, the subject-revocation boundary, the registered session requirements and the `acr` selection — core's session admission (`admitSession`, [`session-admission/`](../core/src/session-admission/README.md)); this package names its actions and maps the outcomes;
- login, the browser session and the federation login routes — `@o3co/auth-provider-session` (`POST /session/logout` is there too, and does not run this package's cascade: see [Logout](#logout); where core's session lifecycle is installed, it closes the session through the lifecycle, as `/oauth/logout` does, and this package's notifier tells the relying parties);
- the other grant types — token exchange, device code, WebAuthn — which their own packages contribute to the same `/oauth/token`;
- offline delegation of upstream tokens (`/oauth/federation-grants`) — `@o3co/auth-provider-federation-grants`;
- proving a DPoP key or a client certificate — `@o3co/auth-provider-dpop` / `@o3co/auth-provider-mtls`. This package reads the binding they establish and stamps it as `cnf`;
- store adapters (Redis and others) and the user Store.

**Why a separate package.** Core holds the contracts every package shares, and the adapter and grant packages — Redis, token exchange, WebAuthn — depend on core and not on this package; keeping the HTTP surface here, with Express and express-session as its peers, means none of them pulls it in. Login and the browser session are a package of their own because an API-only deployment issues tokens without them; this package is the one every token-issuing deployment installs. The two are siblings over core and neither imports the other, which is why `POST /session/logout` cannot run this package's cascade; where core's session lifecycle is installed, both close the session through it instead.

**Why four modules.** The package installs as four separate modules, each with only the requirements its own code reads, because they are needed in different compositions:

| Module | What it contributes | Why it is separate |
|---|---|---|
| [`oauthEndpointsModule`](./src/module.mts) | The `/oauth` routes and the discovery slice. It registers no grant: `/oauth/token` dispatches against core's `grantHandlerResolver`, which every installed module's `grants` contribution fills. | The token endpoint is the same whichever grants are installed, and it runs with no session store at all. |
| [`oauthAuthorizationGrantsModule`](./src/oauthAuthorization.mts) | `authorization_code`, `refresh_token`, `client_credentials` and jwt-bearer, each only when its switch in the module's section turns it on. | A deployment picks its grant set; the grants can also be installed without these routes, which is why this module declares its own `subjectRevocation` and `auditSink` absence policies. It requires `sessionRequirementResolver`, which the two session-reading grants read their sessions through, and `oauthTokenSettings` and core's `tokenBindingSettings`, which the grants read their settings from. With `refresh_token` on it refuses to boot unless both token-family slots are wired (see [`refresh_token`](#refresh_token)). |
| [`oauthSessionGrantModule`](./src/oauthSession.mts) | The `session` grant, only when its section turns it on. | It serves another topology — first-party / BFF, minting from the browser session — is enabled independently of the code grants, and declares only `keyStore`, `sessionRequirementResolver` and `oauthTokenSettings`, and optionally what admission reads beside them — `userSessionStore`, `subjectRevocation`, `auditSink` and the `logger` an outage is written to — and the `grantPolicy` it consults, with the `subjectRevocation` and `auditSink` absence policies. |
| [`subjectRevocationServiceModule`](./src/logout/subjectRevocationService.mts) | Core's `subjectRevocationService` component, built over `cascadeLogout`. | It requires the six session-cascade stores, which `oauthEndpointsModule`'s routes do not, and reads no configuration: it sizes the subject's revocation boundary from the `oauthTokenSettings` and `sessionCookiePolicy` slots, which it requires, and reads whether grants are on and may be kept from the `federationGrantPolicy` slot, which the federation-grants module provides while it is on. With grants on it also requires a `federationGrantStore` and a `subjectRevocation` that carries the grants boundary, and refuses to boot without them; it refuses a `federationGrantStore` wired with no `federationGrantPolicy` too, since reading grants as off would leave that store's grants standing. Its cascade reads no session and passes no `expiresAt`, so it lists the families and writes no ended mark. In a composition without `subjectRevocation` wired, a code exchanged at the same moment as the revocation can therefore leave its family unrevoked; with `subjectRevocation` wired, the subject watermark covers it. Core handing the cascade `expiresAt` is a follow-up, after MFA (#894). It lives here rather than in core because core cannot import `cascadeLogout` without inverting the package dependency. |

Each is installed explicitly: none of them registers another.

## Install

```sh
npm install @o3co/auth-provider-oauth @o3co/auth-provider-core express express-session
```

Peer dependencies: `@o3co/auth-provider-core`, `express@^5.0.0` and
`express-session@^1.17.0`. The package depends on `accepts`, `jose` and `zod`.

Core is a peer so that a composition holds one copy of it: the one your
composition root imports `createApp` from, which every other package's
`declare module` augmentation of core extends. express-session is a peer
because the router reads and augments the browser session (`/authorize`, the
`session` grant, logout); a composition that serves browser flows mounts it
through `@o3co/auth-provider-session`'s `sessionStoreModuleFor(config)`, as
below.

## Composing it

```ts
import express from "express";
import { createApp, jwksModule } from "@o3co/auth-provider-core";
import {
  oauthAuthorizationGrantsModule,
  oauthEndpointsModule,
  oauthSessionGrantModule,
} from "@o3co/auth-provider-oauth";
import { sessionStoreModuleFor } from "@o3co/auth-provider-session";

const handle = await createApp({
  modules: [
    // Mounts express-session. It has no ordering edge of its own, so it must be
    // listed ahead of every module that reads the browser session.
    sessionStoreModuleFor(config),
    oauthEndpointsModule,
    oauthSessionGrantModule,
    oauthAuthorizationGrantsModule,
    jwksModule, // core's: `jwks_uri` is not this package's
    // …the modules that provide clientRepository, codeRepository, keyStore and the
    // optional slots below; add subjectRevocationServiceModule when a Store calls
    // `handle.components.subjectRevocationService`.
  ],
  bootstrapComponents: { config, pathResolver: import.meta.resolve },
});

const server = express();
server.use(handle.router);
server.listen(port); // the composition's own setting; the standalone template's `http` module owns it
// on shutdown
await handle.dispose();
```

The standalone template's [`buildModules.mts`](../../templates/standalone/src/buildModules.mts) is a complete composition root.

What each module requires and reads is declared in its manifest (linked in the table above). What a composition has to decide at boot:

- `oauthEndpointsModule` requires `federationSettings`, `clientRepository` and `keyStore`. It reads nothing of the configuration but its own section: what it reads of the federations — which installed one trusts its upstream IdP's `amr` — comes from core's `federationSettings` slot, which boot fills from `core.federations` for every composition. `/authorize` sends an unauthenticated browser to the login page the `loginEntry` slot names, which `@o3co/auth-provider-session`'s session module provides from `session.loginPage.url`: a path or an absolute URL, which may carry a query of its own (`/login?tenant=x`) but not a `redirect_to`, since `/authorize` adds `redirect_to`, naming the request to come back to, and one already there would reach the page as a second (the session module refuses such a page at boot, `config-validation-failed`, naming the key). A `redirect_to` inside the fragment is not the query's, and is accepted; a fragment is kept after the query `redirect_to` joins (`/login#x` → `/login?redirect_to=…#x`). The slot is optional in the manifest and required where `/authorize` is built: with no module providing it, or one whose entry names no page, the router refuses to build (`contribute-factory-failed`, naming the slot).
- `/authorize` exists only when the grant registry holds the `authorization_code` grant as the router is built, and then needs the `codeRepository` it issues its codes into: the router refuses to build without one. The consent step and Client ID Metadata Documents exist only beside it. A composition without that grant — tokens for machines only — mounts none of them, names no authorization endpoint in discovery and needs no code repository.
- `oauthAuthorizationGrantsModule` with the `authorization_code` grant enabled requires `codeRepository`, the store the grant redeems codes from, and refuses to boot without one, naming the switch (`contribute-factory-failed`); no other grant reads it. With `subjectRevocation` wired, the grant also requires `userSessionStore`, and refuses to boot without one, naming both slots (`contribute-factory-failed`): wire a `userSessionStore` (core's `memorySessionStoresModule` for one replica, or `redisSessionStoresModule`), or remove `subjectRevocation`. The other grants are unaffected.
- `subjectRevocation`, `auditSink` and `accessTokenDenylist` are optional to wire and not optional to decide: an unfilled slot must be declared absent — `oauth.revocation.subject = "unsupported"`, `core.declaredAbsent = ["auditSink"]`, `oauth.revocation.accessToken = "unsupported"` — or boot refuses.
- `oauthEndpointsModule`, and `oauthAuthorizationGrantsModule` and `oauthSessionGrantModule` while their sections turn a grant on, require `sessionRequirementResolver` — core's synthetic key, which the boot planner fills — so a composition that installs any of them declares `core.sessionRequirements.expected`, the session requirements it installs (`[]` for none), or boot refuses (core's session-admission ADR, D7).
- An `oauth.jwt.issuer` that is not a canonical issuer URL fails router construction: `iss` is a property of the deployment, never read from a request.
- `oauthEndpointsModule` provides `oauthTokenSettings` ([#728](https://github.com/o3co/auth.provider/issues/728)): what other modules read of `oauth {}` — the canonical issuer, `legacyTypAccept`, the access- and refresh-token lifetimes, `resourceIndicator.enabled` and `requireEmailVerified` — resolved once from the module's own section and frozen ([`tokenSettings.mts`](src/tokenSettings.mts); `oauthTokenSettingsFrom(section)` is exported, for a composition that provides the slot itself: it takes `oauth {}`, never the whole configuration). Eagerly: it is filled whenever the module is installed, so core's own machinery reads it too. The module names it `authoritative`: while it is loaded, an `overrideComponents` entry for the slot refuses boot (`authoritative-component-overridden`) — the module's own code reads `oauth {}`, and a second source would split what the slot's readers see from what the module does — and a composition without the module fills the slot itself. This package's grants require it while they are on: the session grant reads the access-token lifetime and `requireEmailVerified` from it alone, and the grants of `oauthAuthorizationGrantsModule` the issuer, the lifetimes, `legacyTypAccept`, the resource-indicator switch and `requireEmailVerified`. The device, DPoP, token-exchange, WebAuthn, federation-grants and MFA packages and the subject revocation service read it when a composition holds it, and the configuration when not. The token-binding settings are not in it — the dispatch policy and `bindConfidentialClientRefreshTokens`: they apply across core's token-binding extension point, so they are core's, and core reads them from its own section, `core.tokenBinding`, through `resolveTokenBindingSettings`, and fills its own `tokenBindingSettings` slot with them, which this package's `authorization_code` and `refresh_token` grants require and read the binding rule from.
- Each module under `/oauth` parses its own body, and the order they are listed in does not matter. `oauthEndpointsModule`'s router parses JSON and form bodies (Express's default limits) for exactly the routes in the [Endpoints](#endpoints) table that this composition actually mounts, each at its own path and not at a longer one beneath it — `oauthRoutePaths` in [`routes.mts`](src/routes.mts): the authorize route only with the `authorization_code` grant, and the logout, federation-token and consent routes only when their stores are wired; a request to any other path under `/oauth` — the device grant's, federation grants', WebAuthn's, a deployment's own, including one at `/oauth/logout` or `/oauth/consent` when oauth does not mount those, and one beneath an oauth route such as `/oauth/token/custom` — reaches its route with the body unread, and the `/oauth/revoke` throttle does not count it. A module that mounts a route there and reads `req.body` mounts a parser of its own.

## Configuration

`oauthEndpointsModule` owns `oauth {}` ([#728](https://github.com/o3co/auth.provider/issues/728)): its schema, [`section.mts`](./src/section.mts), declares every key of the section, and the package's [`config/reference.conf`](./config/reference.conf) holds every default and binds every variable — the issuer (`OAUTH_JWT_ISSUER`, required, no default), the access- and refresh-token lifetimes (`OAUTH_ACCESS_TOKEN_*`, `OAUTH_REFRESH_TOKEN_*`), `oidcMode`, `requireEmailVerified`, `requireGrantTypeAllowlist`, the acr table under `authorize.acrValues`, `nonce.maxLength`, `resourceIndicator.enabled`, what revocation promises (`revocation.accessToken`, `revocation.subject`), the consent page and the Client ID Metadata Documents. Boot parses the section with the schema and hands the module what it parsed (`deps.section`); every `oauth.*` setting the module reads — the token settings it provides, its router, its discovery slice — comes from there.

- **Every level is strict.** A key the section does not declare, at any level, refuses boot (`config-validation-failed`), naming its path — `oauth.nonce.maxLenght`, say — where it used to be dropped unread.
- **Core keeps what it retired.** Core's schema still declares `oauth {}`, with the same keys, rules and messages, and core's `reference.conf` sets the same defaults with the same variables, until core stops declaring the section; boot parses with core's schema first, so a value both refuse is refused in core's words, which are the same. Core alone refuses a retired key naming what became of it (`oauth.jwt`'s flat key fields, `oauth.refreshToken.legacyTokenCompat`, `oauth.authorize.allowUnmarkedClients`), and refuses a key set under a path another section moved from (`oauth.grants`, `oauth.dpop`, `oauth.mtls`, `oauth.deviceAuthorization`, `oauth.tokenExchange`, `oauth.code`, `oauth.tokenBinding`, `oauth.jwt.signingKey`) naming its new path, while the module it moved to is loaded. Here such a path may only be an empty object or `null`, which set nothing.
- Core reads `oauth.revocation.*` from the parsed section for its declared-absence guard. The grants read their settings from the `oauthTokenSettings` slot, never from `config`, and the `refresh_token` grant its unknown-family policy from `oauthAuthorizationGrantsModule`'s own section (`oauth-authorization.grants.refreshToken.unknownFamilyPolicy`), so the module reads nothing of the configuration beyond its section. `oauth {}` declares no refresh-token family policy key: `oauth.refreshToken.unknownFamilyPolicy` refuses boot naming its new path and variable, and `oauth.refreshToken.legacyRtPolicy` refuses boot as removed.

## Endpoints

All mounted under `/oauth` by `oauthEndpointsModule`.

| Endpoint | Mounted | Described in |
|---|---|---|
| `POST /oauth/token` | always; dispatches by `grant_type` | [Grants](#grants) |
| `GET`, `POST /oauth/authorize` | when the `authorization_code` grant is registered | [The OIDC surface](#the-oidc-surface-stated-284) |
| `POST /oauth/introspect` | always | [Introspection](#introspection-which-tokens-a-caller-may-ask-about) |
| `GET`, `POST /oauth/userinfo` | always | [Userinfo](#userinfo) |
| `POST /oauth/revoke` | always; what it can revoke depends on the wiring | [Revocation](#revocation) |
| `GET`, `POST /oauth/consent` | when `consentStore` and `pendingConsentStore` are both wired, beside `/authorize` | [Consent](#consent-for-third-party-clients-527) |
| `GET`, `POST /oauth/logout` | when the six session-cascade slots are all wired | [Logout](#logout) |
| `POST /oauth/federation/:name/logout` | the same six | [Logout](#logout) |
| `POST /oauth/federation/:name/token` | the same six | [Federation token endpoint](#federation-token-endpoint) |

The six slots are `userSessionStore`, `sessionRPRegistry`, `sessionFamilyIndex`, `sessionFederationIndex`, `federationTokenStore` and `refreshTokenFamilyRevocation`. The same check decides whether discovery advertises `end_session_endpoint` and the logout capabilities, so a document never names an endpoint that is not mounted.

**Error descriptions and codes.** RFC 6749 allows error text only printable ASCII without `"` and `\` (§5.2, §4.1.2.1). This package holds to that set every `error_description` that `/oauth/token` writes, whichever grant produced it, every one that `/oauth/authorize` puts in an error redirect, and every one that client authentication writes, on `/oauth/token`, `/oauth/introspect` and `/oauth/revoke`, whose errors use the same format (RFC 7662 §2.3, RFC 7009 §2.2.1). Any other character is replaced with `?` (core's `sanitizeErrorText`, [`errors/envelope.mts`](../core/src/errors/envelope.mts)), including in a value the client sent and a description quotes, such as a grant type, scope, audience, token type or `response_type`, and in a configured value such as a client's `tokenEndpointAuthMethod` or a token-binding kind. Descriptions quote a value with `'`. The `error` code itself must be `1*NQSCHAR`, the same characters and not empty. A grant's code outside the set is answered `invalid_request` on `/oauth/token` and logged sanitised (`token_error_code_malformed`). A grant policy's deny at `/oauth/token` is answered by core's `policyDenied`: only token-endpoint codes — RFC 6749 §5.2's other than `invalid_client` (which §5.2 answers `401` with a challenge), and `invalid_target` — go out as the policy gave them, any other — `access_denied` and RFC 8628's polling codes among them — is `invalid_request` (at the device-code poll, `access_denied` and `expired_token` pass and anything else is `invalid_grant`), and its description is repaired like any other and capped at 200 characters; a rewrite is logged `grant_policy_refusal_rewritten` (warn), once per policy, code, grant type and answer on a composition's logger, and on every denial when there is no logger and the line goes to core's console logger. A policy's deny is audited as `token.issued.failure` with reason `policy_denied` and the policy's own code, sanitised, as `policy_error` (core's [README](../core/README.md#grantpolicyhook-scope--audience--token-exchange-policy)). On an `/oauth/authorize` redirect a deny's code outside the set is answered `access_denied` and logged sanitised (`authorize_policy_deny_error_malformed`). A description that is empty or not a string — a JavaScript policy can return anything — is not sent: `/oauth/token` omits it, and an `/oauth/authorize` redirect carries `policy denied`. A decision whose `outcome` is neither exactly `allow` nor exactly `deny` is not a deny and never an allow: core's `readGrantPolicyDecision` reads it as invalid, `/oauth/token` answers `500 server_error` / `policy_decision_invalid`, `/oauth/authorize` redirects with `error=server_error` and mints no code, and each logs `grant_policy_decision_invalid` (error, with the grant type, the policy's `kind` and, at `/oauth/authorize`, `site`, and none of the decision's content) and audits it as `token.issued.failure` / `authorize.rejected` with reason `policy_decision_invalid`. At `/oauth/authorize`, a deny is audited as `authorize.rejected` with reason `policy_denied` and, as `details.error`, the code the redirect carries; a decision past the client's ceiling — a `grantedScope` that is not an array or names a scope outside the client's allowance, a `grantedAudience` that is not an array or is past its ceiling — is redirected `server_error` and audited with reason `policy_out_of_bounds`; and a policy that throws is redirected with core's `policyUnavailable()`, `temporarily_unavailable` / `policy evaluation unavailable`. The client's `state` is returned exactly as sent. The other routes hold to the same set: `/oauth/federation/:name/token` and `/oauth/federation/:name/logout` quote the federation name from the path with `'` and send any other character in it as `?` (`federation '<name>' is not linked to this session`), and `/oauth/consent` answers `decision must be 'accept' or 'deny'`. Core middleware that also answers on these endpoints — the token-binding middleware, the rate limiter and the protected-resource binding — writes through core's `errorEnvelope`, which applies the rule itself (core's [README](../core/README.md#error-text-rfc-6749)).

**Space-delimited values.** A `scope`, `prompt` or `acr_values` a client sends is read by RFC 6749 §3.3's grammar, strictly (core's `readSpaceDelimitedParameter`): the space is the only delimiter, and an entry that is not a scope-token — a tab, a newline, a quote, a backslash, anything outside printable ASCII — makes the whole value malformed. A malformed `scope` is `invalid_scope` with `scope is not a space-delimited list of scope-tokens`, on `/oauth/token` for every grant here and at `/oauth/authorize` — never narrowed, and never checked against an allowlist as if it named a scope. Spaces alone are an omitted scope, as an empty value is; a tab alone is malformed. A malformed `prompt` or `acr_values` is `invalid_request`. A repeated `scope` — or any present value that is not a string — is `invalid_request`, while a JSON body's `"scope": null` is an omitted scope, as `scope=` is in a form body (RFC 6749 §3.2). The `scope` claim of this package's own access and refresh tokens (at `/oauth/userinfo`, on refresh) is read so it never widens (`readIssuedScope`): split on the space alone, and an entry that is not a scope-token is dropped — a token minted before requests were read strictly can carry `openid<TAB>email` as one entry, which named no scope and releases no claim now. A refresh carries the token's scope on in canonical form. What a third party wrote — a client metadata document's `scope`, an upstream's answer — is read tolerantly (`parseScopeTokens`): split on any whitespace, keeping the scope-tokens.

`/token`, `/introspect`, `/authorize` and `/revoke` are throttled by the composition's `rateLimiter` when one is wired, ahead of client authentication, under the limiter's own outage policy (`RateLimiter.failMode`; the Redis limiter's is `redis-rate-limiter.failMode`); without one they are not throttled. They limit under the prefixes `token`, `introspect`, `authorize` and `revoke`, which the oauth module claims with no budget of its own (`rateLimitBudgets`): the limiter's `limits` entry or its default applies, and no other module can set a budget for them.

The router refuses to be built — which through `createApp` is a boot failure — when `consentStore` is wired without `pendingConsentStore` or the reverse, and when `oauth.revocation.accessToken = "denylist"` is declared with no `accessTokenDenylist`.

**Discovery.** `oauthEndpointsModule` contributes its endpoints and metadata to core's `/.well-known/openid-configuration`, which core serves only when an issuer is configured. Each capability is advertised only where it can be honoured: `revocation_endpoint` when the endpoint can revoke something, `private_key_jwt` when a `replaySeenSet` is wired, `client_id_metadata_document_supported` when the feature is on, a consent store is wired and the `authorization_code` grant is registered, the logout fields under the six-slot check above. `grant_types_supported` is read off the resolver `/oauth/token` dispatches against, and so is the authorization endpoint's presence: with the `authorization_code` grant the document names it and advertises `response_types_supported: ["code"]`, `response_modes_supported: ["query"]`, `code_challenge_methods_supported: ["S256"]`, `request_uri_parameter_supported`, `authorization_response_iss_parameter_supported: true` and the acr table; without it, `response_types_supported: []` and none of the rest. The rules are stated where they are computed, in [`module.mts`](./src/module.mts), and pinned by [`discovery-contribution.test.mts`](./src/__tests__/discovery-contribution.test.mts).

## Public API

Everything below is exported from [`src/index.mts`](./src/index.mts); the linked file holds each definition and its doc comment.

**Modules** — see [Why four modules](#responsibility).

- `oauthEndpointsModule` (a module value, not a factory) — [`module.mts`](./src/module.mts). `oauthModule({ config })` is deprecated: it answers `oauthEndpointsModule` and never read its parameter.
- `oauthAuthorizationGrantsModule` (a module value, not a factory) — [`oauthAuthorization.mts`](./src/oauthAuthorization.mts).
- `oauthSessionGrantModule` (a module value, not a factory) — [`oauthSession.mts`](./src/oauthSession.mts). `oauthSessionModule({ config })` is deprecated: it answers `oauthSessionGrantModule` and ignores its argument.
- `subjectRevocationServiceModule` (a module value, not a factory) — [`logout/subjectRevocationService.mts`](./src/logout/subjectRevocationService.mts)

**Router.** `createOAuthRouter(express, options)` — [`routes.mts`](./src/routes.mts) — builds the `/oauth` router from explicit options; it is what `oauthEndpointsModule` calls with its resolved deps and its own section (`section`, typed `OAuthSection`), for a composition root that mounts the router itself. `section` and `federationSettings` are required, and the router takes no configuration: every `oauth.*` setting it reads comes from that one section, and which installed federation trusts its upstream IdP's `amr` from `federationSettings`, core's view of `core.federations` (a test builds one with `createTestFederationSettings` from `@o3co/auth-provider-core/testing`). Without either, the router refuses to build, naming it. It creates no grant registry: `registry` is whatever object with a `get(grantType)` the caller passes, and the same value is returned. `/oauth/token` dispatches against it, and `/authorize` is mounted only when it holds the `authorization_code` grant; `codeRepository` is then required. A caller that needs the registered grant types reads core's `grantHandlerResolver` instead. `requirements` is required: the `sessionRequirementResolver` the boot planner built, which `/authorize` and the consent step read their sessions through; the router refuses to build without one, or with one the planner did not build. The two admit `oauth.authorize` and `oauth.consent`, which `oauthEndpointsModule` registers; a root that mounts the router itself registers `OAUTH_ROUTER_ADMISSION_ACTIONS` under `contributes.admissionActions`, or the router refuses to be built, naming the handler and the action. A test builds the resolver with `resolverForTests` from `@o3co/auth-provider-core/testing`, registering them. Every registered client the router reads, it reads through core's client-record boundary (`validatedClientRepository`) over the `clientRepository` it is handed, with Client ID Metadata Documents on or off. A record the registration schema refuses is warned `client_record_refused`, and the lookup rejects with core's branded refusal (`isClientRecordRefused`): `/authorize`, `/token`, `/introspect`, `/revoke` and consent answer it as they answer a read that throws, `503 temporarily_unavailable`, logged `client_repository_unavailable` with `reason: "client_record_refused"` on the error's projection. With documents on, the same ([Client ID Metadata Documents](#client-id-metadata-documents-529)). A repository already behind the boundary is read as it is, never wrapped twice. With documents on, the router installs its own document fallback over that repository, from `oauth.clientIdMetadataDocuments` in the section it is handed; the fallback reads the registered clients through the boundary itself.

**Client authentication.**

- `createClientAuthMiddleware(clientRepository, options)` and `ClientAuthMiddlewareOptions` — [`middleware/clientAuth.mts`](./src/middleware/clientAuth.mts). Authenticates the client by `client_secret_basic`, `client_secret_post` or `private_key_jwt` (one method per request), admits public clients only when `allowPublicClients` is set, and puts the authenticated client on `req.oauthClient` (typed by a global Express augmentation). Its refusals are RFC 6749 §5.2 `{ error, error_description }`. It reads clients as the router does, through core's client-record boundary over the repository it is handed (a boundary, or the router's document fallback, is read as it is): a record the boundary refuses rejects the lookup with core's refusal, and is answered as a repository that cannot answer is, below, whether it is looked up, authenticated or asked for a `private_key_jwt` assertion's keys. A client repository that cannot answer is not a failed authentication: the request is refused `503 temporarily_unavailable` ("client repository unavailable") with no challenge, and logged at error level as `client_repository_unavailable` — except for a `private_key_jwt` assertion's key lookup, which logs `client_assertion_refused` (error) with `reason: "client_repository_unavailable"` and the error's projection as `err` (for a refused record, `err.reason: "client_record_refused"`); an unknown client or a wrong secret is still `401 invalid_client`. A `client_id` that cannot name a client — a control character, or longer than 256 characters (core's `isWellFormedClientId`, `MAX_CLIENT_ID_LENGTH`) — is refused like an unknown one before the repository is asked, so a repository that throws on such input cannot be made to answer `503`. `/authorize` screens its `client_id` the same way, and answers a repository that cannot answer `503 temporarily_unavailable` as JSON, logged the same way with `site: "authorize"`.
- `createClientAssertionVerifier`, `CLIENT_ASSERTION_ALGORITHMS`, `JWT_BEARER_CLIENT_ASSERTION_TYPE`, `MAX_CLIENT_ASSERTION_LIFETIME_SECONDS` and the types `ClientAssertionVerifier`, `ClientAssertionVerifierOptions`, `ClientAssertionOutcome` — [`middleware/clientAssertion.mts`](./src/middleware/clientAssertion.mts). The `private_key_jwt` verifier the middleware uses; see [`private_key_jwt`](#client-authentication-private_key_jwt-rfc-7523-22).

**Client ID Metadata Documents.** `isClientIdMetadataDocumentUrl` and `isClientIdMetadataDocumentClient` — [`clients/clientIdMetadataDocument.mts`](./src/clients/clientIdMetadataDocument.mts). The fallback that resolves documents is not exported: the router installs it from `oauth.clientIdMetadataDocuments`. See [Client ID Metadata Documents](#client-id-metadata-documents-529).

**Logout primitives**, for a composition that assembles its own logout:

- `cascadeLogout`, `CascadeLogoutOptions`, `CascadeLogoutResult` — [`logout/cascadeLogout.mts`](./src/logout/cascadeLogout.mts)
- `broadcastBackchannelLogout`, `BroadcastBackchannelLogoutOptions`, `BroadcastRP` — [`logout/broadcastBackchannel.mts`](./src/logout/broadcastBackchannel.mts)
- `renderFrontchannelLogoutHtml`, `RenderFrontchannelLogoutHtmlOptions`, `FrontchannelRP` — [`logout/renderFrontchannel.mts`](./src/logout/renderFrontchannel.mts)

**Testing entry**, a subpath of its own rather than `src/index.mts`: `@o3co/auth-provider-oauth/testing` — [`testing/index.mts`](./src/testing/index.mts) — `oauthConfigForTests`, the `oauth` section a test builds.

**Introspection types.** `IntrospectResponse` — [`types/introspect.mts`](./src/types/introspect.mts), the RFC 7662 response shape a resource server or proxy can type against — and `extractConfirmation` / `isCompoundConfirmation`, core's `cnf` helpers re-exported from there.

## Source layout

Each directory under `src/` has one kind of responsibility; what a single file does is in its header comment.

| Directory | Responsibility |
|---|---|
| `src/` (root) | Assembly: `oauthEndpointsModule`, `oauthAuthorizationGrantsModule` and `oauthSessionGrantModule` (the fourth, `subjectRevocationServiceModule`, is in `logout/` beside the cascade it wires), `createOAuthRouter` (`routes.mts`, which composes every route below), option resolution — the `oauth.*` options (`resolveOAuthOptions.mts`) and what the router resolves from them once, as it is built (`routerSettings.mts`: the acr table, the canonical issuer, the client repository) — a re-export of core's access-token header parser, and the one answer every route gives a token it could not verify because a dependency was down (`verificationUnavailable.mts`). |
| [`routes/`](./src/routes) | One router or handler per endpoint family (for `/authorize`, the handler and the stage files it runs) — authorize, consent, logout, federation token (the handler and the stage files it runs; the caller's standing stays in `routes/federationToken.mts`, where core's drift guard pins its session read), revoke, token (the `/oauth/token` dispatch), introspect (who may ask, and the answers when a store it needs is down; the answer on the token itself stays in `routes.mts`, where core's drift guards pin its session and `amr` reads), userinfo. Routes may use `grants/`, `logout/`, `middleware/` and `clients/`; none of those imports a route. `routes/authorizeRequest.mts` also reads one grant helper, the per-client PKCE method rules, because `/authorize` validates PKCE the way `/token` does. The RFC 8707 `resource` rules both read are core's ([`grants/resourceIndicator.mts`](../core/src/grants/resourceIndicator.mts)), shared with the WebAuthn grant. |
| [`grants/`](./src/grants) | The grant handlers: pure request-to-token decisions over core's grant contract, with no HTTP. |
| [`middleware/`](./src/middleware) | Client authentication, reused by sibling packages. |
| [`logout/`](./src/logout) | The ordered session cascade (`cascadeLogout`), the outbound back-channel POSTs to relying parties, the session-close notifier the module contributes to core's session lifecycle, the front-channel page, and the module that wires the subject revocation service. |
| [`clients/`](./src/clients) | Client ID Metadata Document resolution: fetching a client's registration from the URL it names, behind the SSRF guard, and caching it. |
| [`types/`](./src/types) | The introspection response contract. |
| [`testing/`](./src/testing) | The testing entry, `@o3co/auth-provider-oauth/testing`: what a test builds this package's configuration with. |

## Grants

### Which grants are on

Every built-in grant is off until its switch is `true` — the boolean, or a string an environment substitution produces that reads as true (`"true"`, `"1"`, in any case); `"false"`, `"0"` and `""` are off, and any other string refuses boot. Each switch sits in the section of the module that installs the grant — `oauth-session` for the session grant, `oauth-authorization` for the others — and the package's `config/reference.conf` ships each off:

| Grant | Key | Environment |
|---|---|---|
| `authorization_code` | `oauth-authorization.grants.authorizationCode.enabled` | `OAUTH_AUTHORIZATION_GRANTS_AUTHORIZATION_CODE_ENABLED` |
| `refresh_token` | `oauth-authorization.grants.refreshToken.enabled` | `OAUTH_AUTHORIZATION_GRANTS_REFRESH_TOKEN_ENABLED` |
| `client_credentials` | `oauth-authorization.grants.clientCredentials.enabled` | `OAUTH_AUTHORIZATION_GRANTS_CLIENT_CREDENTIALS_ENABLED` |
| `session` | `oauth-session.enabled` | `OAUTH_SESSION_ENABLED` |
| jwt-bearer | `oauth-authorization.grants.jwtBearer.enabled` | `OAUTH_AUTHORIZATION_GRANTS_JWT_BEARER_ENABLED` |

A grant that is off is not registered: `/oauth/token` answers `unsupported_grant_type` for it and `grant_types_supported` does not list it.

`oauthSessionGrantModule` is one module, built from nothing: it reads `oauth-session.enabled` from its section as boot parses it, and an absent section or key is off; off, it registers nothing and requires nothing. Its section is strict — a key it does not declare refuses boot, naming its path — and its schema fills no default: the package's `config/reference.conf` ships `enabled = false`.

`oauthAuthorizationGrantsModule` is one module, built from nothing, likewise: it reads each `oauth-authorization.grants.<grant>.enabled` from its section as boot parses it, and an absent section or key is off. A grant switched off registers nothing (its factory answers `null`); with every grant off the module is off, and registers and requires nothing. While any grant is on it declares the actions both session-bound grants admit (`oauth.code_exchange`, `oauth.refresh`), whichever is on: a declaration registers no grant. Its section is strict at every level — a key it does not declare, under `grants` or in a grant's block, refuses boot, naming its path — and its schema fills no default: the package's `config/reference.conf` ships every switch off, and the `refresh_token` grant's `unknownFamilyPolicy` `"reject"`.

A registered grant must also be allowed for the client, by `allowedGrantTypes` on its registration — at `/oauth/token`, where a refusal is `400 unauthorized_client`, and at `/authorize` for `authorization_code`, where the `unauthorized_client` error is redirected to the client's `redirect_uri`. A list admits exactly the grant types it names, so an empty list admits none. An absent list admits every grant except those that deny by absence — `client_credentials`, jwt-bearer, token exchange, the device grant and the WebAuthn grant — which the list must name. `oauth.requireGrantTypeAllowlist = true` (`OAUTH_REQUIRE_GRANT_TYPE_ALLOWLIST`, off by default) makes an absent list deny every grant. The base rule is core's `isGrantTypeAllowed` ([`repositories/allowedGrantTypes.mts`](../core/src/repositories/allowedGrantTypes.mts)); the grants that deny by absence declare `requiresExplicitGrantAllowlist`, which the `/oauth/token` dispatch enforces ([`routes/token.mts`](src/routes/token.mts)).

Enabling jwt-bearer without a `userRepository` or an `assertionVerifier` fails at boot — see [jwt-bearer](#jwt-bearer-which-issuers-are-trusted-525).

**Token settings are read when a grant is built.** Every grant here reads its lifetimes — and the issuer, `legacyTypAccept`, the resource-indicator switch and `requireEmailVerified`, as it uses them — from the `oauthTokenSettings` slot, once, in its factory, checked whole by core's `checkOAuthTokenSettings`; `authorization_code` and `refresh_token` read the refresh-token binding rule from core's `tokenBindingSettings` slot the same way. A slot value the check refuses — possible only for one filled by hand, since boot checks the slot before any reader — makes the factory throw a `RangeError` naming the slot or the member, and a binding rule that is not a boolean a `TypeError` naming `tokenBindingSettings`, so the grant is never registered. A request never meets it: no authorization code, ID-JAG `jti` or refresh token is spent on settings that cannot mint the answer. The other side of reading them once: a grant mints the lifetimes it was built with, so a change to `oauth.accessToken.*` or `oauth.refreshToken.expiresIn` takes effect only when the grant is built again — restart, as for any other configuration change.

### `authorization_code`: the session, `sid`, `family_id` and the id_token

The access and refresh tokens the `authorization_code` and `refresh_token` grants mint carry `family_id` — the refresh-token family, which is what [introspection](#introspection-which-tokens-a-caller-may-ask-about), [userinfo](#userinfo), [logout](#logout) and the federation token route check for revocation — and `sid`, the session id, when the code record has one. The login path writes `sid` onto the code at `/authorize` (local login or the federation callback).

**The new family is registered under the refresh token's own identity.** The refresh token's `jti` and the instant its lifetime is measured from are reserved before it is signed. With a `refreshTokenFamilyRotation` wired, the family is registered under that `jti`, expiring at that instant plus `oauth.refreshToken.expiresIn` — the token's `exp` — before any token is returned; the grant never reads them back from the signed token, so no form a `KeyStore` returns it in can leave a served refresh token without a rotation record. A family store that cannot answer is `503 temporarily_unavailable`, logged as `authorization_grant_store_unavailable` with `store: "refresh_token_family"` and `step: "register"`. With no rotation wired, no family is registered and replay detection is off — which only a composition without the `refresh_token` grant boots, so nothing redeems those refresh tokens.

**With a `userSessionStore` wired, the code must name a live session.** The session is where the tokens' subject comes from, and the grant links the new family and the client to it so that [logout](#logout) can find them. It is read through core's admission twice, as `oauth.code_exchange` ([Session admission](#session-admission)): before anything is signed, from the code's `sid` alone — a code carries no subject, so this read's record supplies it — and again before the family is linked, with that subject, which the second read must match:

- a code with no `sid` is `400 invalid_grant` — the login wiring did not record one;
- on the first read, a `sid` the store does not resolve, a session past its `expiresAt` or with no subject, or one established before the subject's sessions were revoked (with `subjectRevocation` wired) is `400 invalid_grant` / `session_invalid`;
- on the second, a session that went away, expired, was revoked or answers another subject while the tokens are being issued is `400 invalid_grant` / `session_invalidated`, logged at warn as `authorization_grant_rejected_session_invalidated_during_token_issuance` or, for another subject, `…_session_subject_changed_during_token_issuance` (which admission also audits as `session.admission.subject_mismatch`);
- a logout that ends the session after the second read, while the family is being linked, gets the same answer, `400 invalid_grant` / `session_invalidated`, logged as the same warn line, when the family index has core's session-end capability (`SupportsSessionEnd`; both bundled indexes have it). The logout marks the session ended before it lists the families, and the grant adds the family before it reads the mark, so either the logout revokes the family or the grant serves no token. The grant then revokes the family it registered — unless a `refreshTokenFamilyRotation` is wired without a `refreshTokenFamilyRevocation` (an authorization_code-only composition), where the record stays active, though no token of it was served, and boot says so once at warn as `refresh_token_family_rotation_without_revocation`; a revocation that fails is logged once at error as `authorization_grant_refused_family_revocation_failed` (`sid`, `clientId`, `familyId`, the error's projection), and the answer stands. The guarantee trusts the store, as core states (linearizable reads and writes, reads from the primary). Over an index without the capability, the family is added unguarded and a logout racing the exchange can miss it; boot says so once at warn as `session_family_index_without_session_end` (`slot`, the index's `kind`);
- a registered session requirement the session does not meet is `400 invalid_grant` naming it, with `step_up: "<requirement>"` beside it when a step-up can meet it;
- a store that cannot answer is `503 temporarily_unavailable`: the session reads logged once by admission as `session_admission_unavailable`, the linking writes as `authorization_grant_store_unavailable`.

**Where core's session lifecycle is installed** (`sessionLifecycleModule` fills the `sessionLifecycle` slot), the grant links the family and the client through it, `sessionLifecycle.join`, instead of the per-session stores above. The lifecycle writes those stores beside its own record, so a logout through them still lists the family or refuses the add, and it also refuses a session whose close it has committed, or one whose user session is gone. Its refusal is the same `400 invalid_grant` / `session_invalidated` and warn line, the family already revoked by the lifecycle, or its failure logged as `session_join_withdraw_failed`; its outage is `503 temporarily_unavailable`, logged by the lifecycle as `session_lifecycle_unavailable` and by the grant as `authorization_grant_store_unavailable` (`store: "session_lifecycle"`, `step: "join"`), and the grant revokes the family it registered. Over the per-session stores too, an outage of the linking writes now revokes that family before the `503`.

Without a `userSessionStore`, the subject is the user of the browser session that accompanies the token request, and no id_token is issued.

**The id_token** is issued when `openid` is among the granted scopes and a `userSessionStore` is wired, with `iss` the `oauthTokenSettings` slot's issuer, never the request's; otherwise it is omitted and the access and refresh tokens are returned as usual. It carries `iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `auth_time`, `sid` and `azp`; `nonce` when the authorization request had one (OIDC Core §3.1.3.7); `amr` / `acr` as described in [Step-up](#step-up-and-re-authentication-481); and the user's claims filtered by scope ([the same table userinfo uses](#userinfo)).

### `refresh_token`

- **A token whose family no record holds is refused.** `oauth-authorization.grants.refreshToken.unknownFamilyPolicy` (`OAUTH_AUTHORIZATION_GRANTS_REFRESH_TOKEN_UNKNOWN_FAMILY_POLICY`) decides it: `"reject"`, the shipped default, answers `400 invalid_grant` / `unknown_family` and logs `unknown_family_rejected`; `"accept"`, for a bounded migration window only, issues and logs `unknown_family_accepted_legacy_mode`. The grant issues only on `"accept"`: a composition whose section carries no value — one that does not layer this package's `reference.conf` — refuses. The key moved from `oauth.refreshToken.unknownFamilyPolicy`, and `OAUTH_REFRESH_TOKEN_UNKNOWN_FAMILY_POLICY` with it: either still set refuses boot, the variable unless its new name is set to the same value.
- **Both token-family slots are required.** With the grant on (`oauth-authorization.grants.refreshToken.enabled`), the module refuses to boot — `contribute-factory-failed` for the `refresh_token` grant, its `cause` naming the missing slot — unless `refreshTokenFamilyRotation` and `refreshTokenFamilyRevocation` are wired: a family store (core's `memoryRefreshTokenFamilyStoreModule` for one replica, or `redisRefreshTokenFamilyStoreModule`) with core's `defaultRefreshTokenFamilyRotationModule` and `defaultRefreshTokenFamilyRevocationModule`. Without them a refresh token was served with no family record and redeemed with no rotation and no replay check, and `/oauth/revoke` answered `200` for a family this grant never read. A deployment that wants no token families turns the grant off. Refresh tokens issued while no family store was wired have no family record, so once one is, `oauth-authorization.grants.refreshToken.unknownFamilyPolicy` decides them: the default `"reject"` refuses them (`400 invalid_grant`, `unknown_family`) and their users sign in again. `"accept"` is not a window that closes on its own: it redeems such a token with a new refresh token of the full `oauth.refreshToken.expiresIn`, in the same family, and still writes no family record, so a client that keeps refreshing keeps a chain that never expires and is never replay-checked. Waiting does not end it; setting `"reject"` again does, and at that moment every holder of such a chain is signed out.
- **The session must still exist, and the token meet the registered requirements.** The verified refresh token is admitted through core's admission ([Session admission](#session-admission)) before the rotation spends it: when a `userSessionStore` is wired and the token carries `sid`, the session is read — gone, past its `expiresAt` or answering another subject is `400 invalid_grant` / `session_invalid`, a store failure `503 temporarily_unavailable` logged once by admission as `session_admission_unavailable`. The registered session requirements are asked about the `amr` the token carries, never the session's, so a token is judged on what it was issued with: one a requirement does not accept is `400 invalid_grant` naming it, with `step_up: "<requirement>"` beside it when a step-up could meet it — the client re-authenticates the user. With no requirement registered nothing changes beyond D2's reading of the record: a record past its `expiresAt`, with an `authTime` that is not a valid date, or whose `sub` is not the token's is `session_invalid`, where the grant asked only whether one existed (the bundled stores never answer an expired one). The subject-revocation boundary for a refresh token is the watermark `verifyJwt` reads (below), not the session's.
- **The rotation is reserved before anything is signed.** The new refresh token's `jti` and the instant its lifetime is measured from are chosen first, committed to the family store by `RefreshTokenFamilyRotation.rotate`, and signed only once that commit holds. A lost race — a replay, a revoked family, an unknown family under `reject` — therefore returns having produced no signature, which matters under a KMS-backed `SigningKeyProvider` where each signature is a billable remote call. The issued token carries exactly the `jti` that was reserved and an `exp` no later than the ceiling the store committed — `RefreshTokenFamilyRotationOutcome.cappedExpiresAtMs`, less a one-second margin for the forward drift its contract documents, floored to the second — so a refresh token never outlives the family record that catches its replay. A ceiling that leaves no lifetime is `400 invalid_grant` ("refresh token family has reached its lifetime"), not a `200` carrying an already-expired refresh token.
- **What that ordering costs.** Once `rotate` commits, the presented token is spent. A signer that fails after it — a KMS outage — leaves a rotation nobody holds a token for: the grant answers `503 temporarily_unavailable` and logs `refresh_token_rotation_orphaned` with the family id, the spent `jti` and the reserved one — only when the store actually committed the rotation, so an unknown family accepted under `unknownFamilyPolicy` keeps the ordinary signer behaviour (a composition with no rotation wired does not boot with this grant). The client's retry presents the old token, which now reads as a replay, so the family is revoked and the user re-authenticates.
- **The watermark and the session are read again before signing.** After the policy, the session's admission is followed by a second verification of the presented token — the subject's revocation watermark included, so it is the last read — before the rotation; after the rotation commits, both run once more, and the family's remaining lifetime is measured again, before anything is signed. Each is refused and answered as the first check (`400 invalid_grant`, or `503 temporarily_unavailable` for an outage). The watermark is read whether or not a `userSessionStore` is wired or the token carries `sid`. A refusal after the rotation committed also revokes the family through `refreshTokenFamilyRevocation`, since its presented token is spent and its reserved one never signed; a family store that fails there is logged as `refresh_token_store_unavailable` with `step: "revoke"`.
- **A replay revokes the family** (RFC 6819 §5.2.2), which is why the module reads `refreshTokenFamilyRevocation` beside the rotation; and a refresh token whose `iat` is at or before the subject's revocation watermark is `invalid_grant`.
- **A token the grant could not verify because a dependency was down is `503 temporarily_unavailable`, not `invalid_grant`** — the keystore ("verification key unavailable") or the subject watermark ("revocation store unavailable"), logged as `token_verification_unavailable` with `site: "refresh_token"`. RFC 6749 §5.2's `invalid_grant` makes a client discard its refresh token, so answering an outage with it would log out everyone who refreshed during it. A kid the keystore does not hold is still `invalid_grant`. A family store that fails is `503` too, logged as `refresh_token_store_unavailable` with the store and the step (`rotate`, or the `revoke` a replay needs).

### `session`

Mints an access token for the user of an already-authenticated browser session (first-party / BFF topologies). The caller authenticates as a client at `/oauth/token`; the client's `allowedScopes` are the ceiling. `aud` is the client's first `allowedAudiences` entry, or its client id when it has none, and `azp` is the client id. No refresh token is issued, so the token never carries `family_id`; it carries `sid` when the browser session has one.

The browser session handed to the grant is read through core's admission as `oauth.session_grant` ([Session admission](#session-admission)) before any token is signed. A cookie that is not authenticated is `401 unauthorized`; one that names no user is `400 invalid_grant`, whether or not a store is wired. When a `userSessionStore` is wired, the cookie must carry a non-empty `sid` (`400 invalid_grant`, "session identifier (sid) is required") naming a live `UserSession` whose subject is the cookie's user: a session gone, past its `expiresAt`, answering another subject, or established before the subject's sessions were revoked (with `subjectRevocation` wired) is `400 invalid_grant` / `session_invalid`, a store failure `503 temporarily_unavailable`, logged once by admission as `session_admission_unavailable`. A registered session requirement the session does not meet is `400 invalid_grant` naming it, with `step_up: "<requirement>"` beside it when a step-up can meet it — RFC 6749's code, so an existing client keeps its mapping, and a member an updated one can act on. Without a `userSessionStore` the grant relies on the browser session alone. Validated DPoP / mTLS bindings are kept in the access token's `cnf`: DPoP answers `token_type=DPoP`, mTLS keeps `Bearer`, and the resource server must verify the corresponding proof.

A wired `grantPolicy` is consulted after admission and the scope check, before anything is signed, with `grantType: "session"`, the authenticated client, the session's subject and the requested scopes (none when `scope` is omitted). It may only narrow: a deny is `400` with the policy's own `error` when it is a token-endpoint code (RFC 6749 §5.2's other than `invalid_client`, or `invalid_target`; `invalid_request` otherwise), a policy that throws is `503 temporarily_unavailable`, and a `grantedScope` past the requested scopes or a `grantedAudience` outside the audiences the grant itself mints for — the client's `allowedAudiences`, or its client id when it lists none — is `500 server_error`. A `grantedAudience` within them is the token's `aud`. Once the policy has answered, the whole admission runs again before signing — the live-session read, the revocation boundary and every registered requirement — and a refusal or an outage there is answered as on the first admission, so a session revoked or ended while the policy evaluated mints nothing.

### `client_credentials`

RFC 6749 §4.4 machine-to-machine: public clients are refused, the token's `sub` is the client id, and no refresh token is issued. The client's `allowedGrantTypes` must name the grant — an absent list denies it rather than admitting it by omission, as it does for jwt-bearer, token exchange, the device grant and the WebAuthn grant.

A wired `grantPolicy` is consulted whether or not `oauth.resourceIndicator.enabled` is on, under the same rules as the `session` grant; the RFC 8707 `resource` reaches it only with that flag on.

## The OIDC surface, stated (#284)

This is an OAuth 2.0 authorization server with the OIDC pieces a **first-party** deployment needs. Where it stops is deliberate, and saying so is part of the contract — an RP that discovers what is here should not have to find the edges by hitting them.

**`/oauth/authorize` accepts GET and POST** (OIDC Core §3.1.2.1). Both run the identical sequence of checks: the handler reads its parameters through one accessor, so a check cannot be mounted on one method and forgotten on the other.

**`redirect_uri` is matched against `client.allowedRedirectUris` by exact string equality, with one carve-out (#483).** When **both** the registered entry and the presented value are `http:` on a loopback **IP literal** (`127.0.0.0/8`, `[::1]`), the port is dropped from both before comparing — scheme, host, path and query are still compared exactly. The equality runs on the two **original strings** with the port removed, not on normalized URLs, so dot segments (`/a/../cb`), percent-encoding variants, a `\` separator, a differing trailing slash and scheme case never widen it. A native app receiving the response on a loopback interface binds an ephemeral port the OS assigns at run time, so a registration cannot name it (RFC 8252 §7.3): `http://127.0.0.1/cb` admits `http://127.0.0.1:49152/cb`. Every registered entry is held to core's `checkRedirectUri`, the rule registration applies, its query-name rule (below) included: a registered client's entries are held to it by core's client-record boundary, which the router reads every registered client through, and a document client's entries by the document's own check. A registered record with an entry the rule refuses is refused whole: the lookup rejects with core's branded refusal, answered `503 temporarily_unavailable` as JSON with no redirect, warned `client_record_refused`. With Client ID Metadata Documents on, the same. The presented `redirect_uri` is then held to the same rule itself: it may differ from the matched entry in a loopback port, which is matched as raw text. One it refuses is answered as an unregistered URI is, `400 invalid_request` (`redirect_uri not allowed`) with no redirect, and warned `authorize_registered_redirect_uri_refused`. Like every lookup, this comes after the login step: an unauthenticated browser is sent to log in first and gets the answer after it, and `prompt=none` gets it directly. The browser is never sent to the URI.

- `http://localhost/cb` gets **no** carve-out — a loopback *name* moves the guarantee into the host's name resolution, and RFC 8252 §8.3 discourages it. Register the IP literal.
- `https://` gets no carve-out either, loopback host or not.
- The **presented** URI is where the response goes, and it is what gets bound to the authorization code. The token endpoint's `redirect_uri` check (RFC 6749 §4.1.3) compares against that record with plain equality — port included — so a listener on a different port cannot redeem another one's code.
- The comparison lives in `matchesRegisteredRedirectUri` (`@o3co/auth-provider-core`), exported so a custom authorization endpoint matches the way this one does.

**PKCE is mandatory, and `S256` is the method.** `plain` is admitted only for a client whose registration carries `allowPlainPkce: true`, which is why discovery lists `S256` alone. PKCE takes no configuration: `oauth.grants.authorization_code.pkce`, and `OAUTH_GRANTS_AUTHORIZATION_CODE_PKCE_REQUIRE_S256` set at all, refuse boot as removed.

**Every authorization response names its issuer** ([RFC 9207](https://datatracker.ietf.org/doc/html/rfc9207)). Each redirect to a client's `redirect_uri` — the code, every error redirect from `/oauth/authorize`, and the consent step's deny — carries `iss`, the issuer exactly as the discovery document's `issuer` states it (core's `advertisedIssuer`: the configured `oauth.jwt.issuer` without a trailing slash), and discovery says so with `authorization_response_iss_parameter_supported: true`. A client checks it against the issuer it sent the request to, which defeats a mix-up between authorization servers. The `400` JSON answers given before `redirect_uri` is trusted (an unknown client, an unregistered `redirect_uri`) reach no client and carry none. There is no switch: every such response is built by one function, [`routes/authorizationResponse.mts`](./src/routes/authorizationResponse.mts). It appends to the query a registered `redirect_uri` already holds and removes or replaces nothing in it: the registered parameters reach the client with their names, in order, and with their values as WHATWG URL parsing decodes them. The query is serialized again as a form, so the bytes may differ (`%20` becomes `+`, `~` becomes `%7E`), and two values change: a percent-sequence that is not UTF-8 becomes U+FFFD (`%FF` becomes `%EF%BF%BD`), and a name with no value gains `=` (`?foo` becomes `?foo=`). A query that used a response parameter's name — `code`, `state`, `iss`, `error`, `error_description`, compared ignoring case, `_` and `-` — would carry that name twice, and a client reading it with `searchParams.get` would read the registered value, so such a URI is refused: core's `checkRedirectUri` refuses it at registration (a YAML or static client at boot, a Client ID Metadata Document when it is resolved), and `/oauth/authorize` and the consent deny refuse it for a custom `ClientRepository` (above). The same rule refuses a query name outside `[A-Za-z0-9_-]`, a parameter with no name, and a `;`, which a client framework could read as another name ([core's redirect-URI rule](../core/src/net/redirect-uri.mts)).

**`prompt=none` is supported.** No session answers `login_required` at the client's `redirect_uri` — which is the point, since a hidden renewal iframe cannot act on a login page. A session proceeds silently. A `prompt` that names `none` but is malformed (`none<TAB>`) or combines it with another value still comes from a silent context, so it too is answered at the `redirect_uri` — `invalid_request` — never with the login page.

**`prompt=login` re-authenticates** — see [Step-up and re-authentication](#step-up-and-re-authentication-481) below.

**`prompt=consent` is honoured**: for a client that is not first-party it forces the consent page even when a recorded consent covers the request; for a first-party client it is a no-op — the deployment operates that client, so there is nothing to consent to. See [Consent for third-party clients](#consent-for-third-party-clients-527).

**`select_account` is refused** with `invalid_request` naming the value, not ignored: there is no account picker, and ignoring it would hand back a token the RP believes was freshly account-picked.

**`request` and `request_uri` are refused** with `request_not_supported` / `request_uri_not_supported`, not ignored: a signed request object exists to make the parameters tamper-proof, so processing the query string instead would give an attacker precisely what the object was there to prevent while the RP believes it was honoured. The discovery document says `request_uri_parameter_supported: false` for the same reason — OIDC Discovery **defaults that field to `true`**, so omitting it would be a claim.

**A `claims` parameter that names `acr` is refused** with `invalid_request` (`request acr through acr_values`) — essential or not, for the id_token or for userinfo (OIDC Core §5.5.1.1) — and so is one that is not a JSON object, or is repeated, since it cannot be told not to name it. An empty `claims=` is omitted (RFC 6749 §3.1). This server vouches for an `acr` only through `acr_values` and its table; ignoring the request would hand back a token the RP reads as having honoured it. The refusal comes before a `prompt=login` or `max_age` sends the browser to log in. Every other use of `claims` is ignored.

**A `response_mode` other than `query` is refused** with `invalid_request` on the `redirect_uri` (in the query, with `state`), not ignored: `form_post`, `fragment`, an unknown value and a repeat alike. Answering in the query anyway would deliver the response somewhere the client is not reading it. An absent or empty `response_mode`, or `query`, is served. Like the other parameter refusals, it comes after the client and `redirect_uri` are validated (until then the answer is 400 JSON) and before a `prompt=login` or `max_age` sends the browser to log in. Discovery says `response_modes_supported: ["query"]`, since RFC 8414 defaults an omitted value to `["query", "fragment"]`, which would claim a mode this server does not serve.

**Not implemented:** the `claims` parameter beyond that refusal. `claims_parameter_supported` and `request_parameter_supported` default to `false` when omitted, so the discovery document tells the truth about them by saying nothing.

**Before minting, `/authorize` reads the session through admission** — see [Session admission](#session-admission): a dead, expired, revoked or subject-less session is sent to log in, with its cookie session regenerated first, and a store that cannot answer is `temporarily_unavailable` at the `redirect_uri`, never the login page.

## Step-up and re-authentication (#481)

A native app needs two things from the OP for a sensitive action: to **force a fresh authentication** (a payment, a credential change) and to **know how the user authenticated** (passkey, password, password plus a second factor), so it — or the resource server — can require a level. Both rest on what the session records at login.

**What a session records.** `UserSession.authTime`, `UserSession.amr` — RFC 8176 values written by the login path — and `UserSession.authentication`, how the session was established (the MFA ADR's D9): `["pwd"]` for `POST /session/login`; the deployment-defined `fed` for a federation callback, with the upstream IdP's `amr` (when the provider surfaces it on the profile) beside it only for a federation configured with `core.federations.<name>.trustUpstreamAmr = true` — otherwise the IdP's values are kept in `authentication.upstreamAmr`, where nothing stamps them or matches them for `acr` (D13; the [session package README](../session/README.md#what-a-session-records-about-the-authentication) has the switch). The WebAuthn grant, which mints tokens without a session, stamps `amr: ["hwk"]` on its access token directly. RFC 8176 registers no value for "federated", and OIDC Core §2 leaves `amr` values to the deployment, so `fed` is documented here rather than borrowed.

**A session is read through core's `sessionAuthentication` / `vouchedAmr`,** never its own `amr`. A session written before `authentication` existed is split as it is read: one carrying `fed` vouches for `fed` alone — its other values were an upstream IdP's, and the session does not say which federation wrote it — and one carrying `pwd` for what it recorded.

**What the tokens carry.** The id_token has `auth_time` always, `amr` when the session vouched for one at `/authorize` (`vouchedAmr`), and `acr` when `/authorize` satisfied an `acr_values` request. Both are decided at `/authorize` and carried on the code (`CodeData.amr`, `CodeData.acr`), so a second factor the session records after the code was issued reaches none of its tokens; the exchange still reads the session, through admission, to refuse one that has ended, and for the subject, `auth_time` and the id_token's claims. A code that carries no `amr` — one an older release issued, or one a custom `CodeRepository` dropped — yields tokens without one, and the refresh grant carries none forward until the family ends or the user signs in again; under `mfa.mode = "required"` such a family is refused at its first refresh (`400 invalid_grant`). The access token mirrors `amr`, `acr` and `auth_time` when present, so `auth.policy-verifier` or a resource server can gate on them without an id_token (RFC 9470 §6.1) — and **keeps mirroring them across refreshes**: the `authorization_code` grant stamps all three on the refresh token as well, and the `refresh_token` grant carries them from the presented token onto the access and refresh tokens it mints, since a refresh does not repeat the authentication (OIDC Core §12.2; RFC 9470 §6.1: the values do not change when the access token is renewed). `auth_time` is the session's `authTime`, the primary authentication's time: a second factor verified later in the session does not move it, so `max_age` measures the login, as it does at `/authorize`. It is never later than the clock that mints the token (core's `authTimeAt`): an `authTime` ahead of that clock within the skew (`DEFAULT_CLOCK_SKEW_MS`) is stamped as the minting clock, the same on the access, refresh and id tokens, and one further ahead refuses the `authorization_code` exchange and the `session` grant with `400 invalid_grant` `session_invalid` before anything is signed (the code is spent by then, as for every refusal of the exchange's session read), warned as `auth_time_ahead_of_clock` with how far ahead it is: the remedy is that replica's clock. The `refresh_token` grant caps a carried `auth_time` at the presented token's `iat` and at its own issuance. The `session` grant mirrors what the tracked session vouches for (`vouchedAmr`) and its `authTime` (it has no `acr_values` negotiation, so no `acr`), and the passkey grant (`@o3co/auth-provider-webauthn`) stamps its `amr: ["hwk"]` and, as `auth_time`, the earliest instant the assertion could have been made — the challenge's recorded issuance; one lifetime before the redemption when none is recorded ([its README](../webauthn/README.md#security--auth_time-is-the-challenges-issuance)) — on its refresh token as well as its access token. Without a `userSessionStore` there is no session to read, and neither grant stamps `amr` or `auth_time`. Every grant reads the claims in one shape — `amr` a non-empty array of non-empty strings, `acr` a non-empty string, `auth_time` a whole, non-negative number of seconds since the epoch (core's `wellFormedAmr` / `wellFormedAcr` / `wellFormedAuthTime`) — and omits anything else, so a session that recorded `amr: []` stamps no `amr` on any token rather than one that vanishes at the first refresh. A refresh token that carries none of them yields tokens that carry none: one without `auth_time` keeps refreshing, and what it mints has no `auth_time` until the user signs in again — the grant does not read it from the session.

**`max_age`.** A non-negative integer (anything else is `invalid_request`); an empty `max_age=` is omitted, as RFC 6749 §3.1 requires of a parameter sent without a value. A session whose `auth_time` is older than `max_age` seconds — `max_age=0` is always older — is sent to the login page with the request round-tripped, exactly as an unauthenticated one is, plus one thing: the instant of the ask is recorded **on the server**. On the way back, a session authenticated strictly after that instant — compared to the millisecond — is the re-authentication that was asked for, and the request proceeds — `max_age=0` included, which is what keeps it from looping; one authenticated before it is answered `login_required` rather than sent round again. Under `prompt=none` a stale session is `login_required` straight away: silent means silent. `auth_time` in the id_token is what an RP verifies, and it is always the truth. The session's `authTime` is read against the clock through core's `authTimeAt`: for `max_age`, an instant ahead of it within the clock skew (`DEFAULT_CLOCK_SKEW_MS`) reads as now, and one further ahead cannot be read and is stale. Against an ask, an instant up to 1 s ahead of the clock (`ASK_REPLICA_SKEW_MS`, the skew tolerated between replicas: a login on one whose return reaches another a moment later) reads as now; one further ahead is never compared — a clock this one cannot check stamped it, so it does not meet a login an ask asked for, and a session back from a step-up trip with one is sent to log in once and then refused with `login_required`.

**`max_age` and the ask.** Within the ask's window, a login made after the ask counts as fresh even once `max_age` has since passed: the trip the request asked for was made, and is not asked for again. `auth_time` in the id_token is still the time of that login, so a client that needs a tighter bound compares it with its own `max_age`.

The ask is a **record in the session store**, named by an opaque id the returned URL carries as `reauth_ask`. One record per request accumulates what was asked — the login trip (`loginAskedAt`), and each step-up trip under its requirement's name (`stepUpAskedAt`, see [Session admission](#session-admission)); a record written before it did (`askedAt`) reads as a login asked then, and for one release a record carries `askedAt` beside a login ask so an older replica reads it. The record's `createdAt` is kept across the trips of one request. It is not the timestamp itself on the URL: a marker read straight off the request is the caller's to write, and a forged one would satisfy the check for any live session and skip the round trip it exists to force. A record cannot be forged (the id is 32 bytes from the CSPRNG, and naming one that does not exist is the same as naming none); it survives the session regeneration `/session/login` performs, which a field on the session would not; it is bound to the authorize request it was minted for, so an ask outstanding for one request cannot answer another's freshness requirement (presented with another, it is spent).

The ask is **read without being spent**, so every pass of the request finds it — the one after a trip, and the one after consent, whose parked request carries it back. Each trip's write spends the ask it was presented before writing the next, so a chain of trips leaves one record; a trip that finds the ask already spent by another pass of the request writes no successor carrying its instants, and the request is judged again with no ask. (A browser that is not signed in and sends `prompt=login` gets a new ask without the one it presented being read.) **The pass that mints spends it**, just before the code, so the ask cannot carry its login into a second code: replayed, a returned URL whose freshness rested on the asked-for login is asked to log in again, while one that asked for a step-up alone is decided on its merits — the stepped-up session is admitted on its own. An ask already gone at the mint — spent by another pass of the same request — is `login_required` when the session's freshness rested on the login it asked for (ignored otherwise). A refusal leaves it, so a replayed return is refused again rather than sent on a new trip. Each write opens its own ten-minute window, and a chain of trips ends **30 minutes after its first ask** however recent its last write (`REAUTH_ASK_MAX_CHAIN_MS`); past either, the ask is nothing and the request is decided on its merits again. A store that cannot answer at any of these steps is `temporarily_unavailable`, logged at error as `authorize_reauth_ask_store_unavailable`. The rationale is in [`routes/reauthAsk.mts`](./src/routes/reauthAsk.mts).

`max_age` and `prompt=login` need a `userSessionStore` (there is no `auth_time` to measure without one) and the session middleware's store (where the ask is recorded); a composition without either answers them `invalid_request` rather than accepting them silently.

The login page must return the browser to `redirect_to` **verbatim**: a page that rebuilds the authorize URL drops the ask id, and the request is asked to authenticate again.

**`prompt=login`** uses the same mechanism with the staleness test replaced by "always": to the login page, the ask recorded, then satisfied by a session authenticated after it, else `login_required`. `prompt=none login` is refused as OIDC Core §3.1.2.1 says. A browser that is not signed in gets the ask recorded before its login — with the login check, before the client is looked up, as every unauthenticated request is answered — so it logs in once, and so does one whose dead session is sent to log in. Before the client is looked up, the ask is recorded only for a request of the shape a client sends: a well-formed `client_id`, and the request within 8 KB (`ANONYMOUS_ASK_MAX_REQUEST_BYTES`) — any other gets the plain login redirect and no record; the `/authorize` rate limit and the ask's window bound what an anonymous caller can write. The ask is bound to the request less `prompt=consent`, as the consent step resumes it, so `prompt=login consent` logs in once too. A store that cannot record it sends the browser to log in without one, logged as `authorize_reauth_ask_store_unavailable`, and the user is asked to log in again on the way back.

**`acr_values`** is answered from a configured table and from nothing else:

```hocon
oauth.authorize.acrValues {
  "urn:example:pwd" = ["pwd"]
  "urn:example:mfa" = ["pwd", "mfa"]
  "urn:example:passkey" = [["hwk"], ["swk"]]
}
```

Each key is an Authentication Context Class Reference this deployment vouches for; its value is the `amr` set a session must carry to satisfy it — or a list of such sets, any one of which satisfies it (`urn:example:passkey` above: a device-bound or a synced passkey). The first requested value the session satisfies becomes the `acr` of the code and of the id_token, matched by core's requirement rule (`selectAcr`) against the `amr` the session vouches for (`vouchedAmr`). None satisfied — or a value that is not in the table at all — is `unmet_authentication_requirements` at the `redirect_uri`, naming what was unmet; there is no silent acceptance. A value one registered session requirement's step-up can meet — the MFA requirement's second factors, once it is installed — is a [step-up trip](#session-admission) to that requirement's page instead, with the values it can meet as `acr_values`; with no requirement registered there is none, and what the session does not meet is unmet. Discovery advertises the keys as `acr_values_supported` when the table is non-empty. An acr, or an alternative, that requires nothing is refused at boot: every session would satisfy it, and it would vouch for nothing. So is a key no request can name: `/authorize` reads `acr_values` as space-delimited RFC 6749 §3.3 scope-tokens, so a key is one or more printable ASCII characters other than the space, `"` and `\`; any other — one holding whitespace, a quote, a backslash or a non-ASCII letter — would be advertised and never requested. The section refuses each such key at `oauth.authorize.acrValues.<key>`, every one in a single boot, by core's `checkAcrValueName` and in its words, as core's schema does.

**An entry nothing installed can satisfy is dropped at boot**: withheld from `acr_values_supported`, answered `unmet_authentication_requirements` like a value the table does not carry — even for a session that happens to carry its values — and said once as `acr_value_unsatisfiable` with the entry (`acr`) and what nothing produces (`unproducible`). The line is `warn`, except for an entry only a second factor would meet while no registered session requirement reaches one, which is `info`: a composition that installs no MFA has chosen that, and `mfa.mode` does not enter into it. What a composition can satisfy: `pwd`, always; `fed` while a federation is installed, since only a federation callback records it; any other value while an installed federation whose section is enabled trusts its upstream IdP's `amr` (`core.federations.<name>.trustUpstreamAmr = true`, read from the `trustsUpstreamAmr` of its entry in core's `federationSettings` slot, as the federation callback reads it), because the callback then records what the IdP asserts beside `fed` — an untrusted federation's IdP meets no entry, and a disabled one signs nobody in; a second factor's values (`otp`, `hwk`, `swk`, `email`, `recovery`) and `mfa` while a registered session requirement reaches them — the union over the `sessionRequirementResolver` the module requires (the session-admission ADR's D6); the MFA module's `mfa` requirement reaches what its enabled factors add, and no release ships it yet. So without a trusted federation or a requirement reaching them, the `mfa` and `passkey` entries above are dropped, and without any federation so is an entry that needs `fed` — warned whatever is registered, since no requirement would meet it. A `trustUpstreamAmr` that is given but is not a boolean refuses the composition, before the module is built. What a session minted before the upstream split, or before trust was withdrawn, keeps carrying — a code's `acr`, a refresh token's `amr` and `acr` — is in the [operator runbook](../../docs/operator-runbook.md#trusting-an-upstream-idps-amr-and-withdrawing-that-trust). The drop is computed where the router is built and where discovery is contributed, from the same inputs (`src/acrValues.mts`).

**Both login paths must re-authenticate when asked.** The login page the deployment serves receives `redirect_to` carrying `prompt=login` / `max_age` and the marker; a page that bounces an already-authenticated browser straight back gets `login_required`, never a loop. `POST /session/login` and the federation callback always establish a *new* session with a fresh `auth_time`, which is the re-authentication.

## Session admission

Every endpoint here that lets a session do something reads it through core's one decision, `admitSession` ([the session-admission ADR](../core/docs/adr/2026-09-28-session-admission.md), [`session-admission/`](../core/src/session-admission/README.md)), with a claim core builds and the name of an action its module registers — `oauth.authorize` and `oauth.consent` by `oauthEndpointsModule`, each session-bound grant's by the module that installs the grant, all graded `use` (a grant, built before the actions register, refuses an unregistered one at the request, the router where it is built); no route or grant here reads a `UserSessionStore` for a session it admits by other means (a drift guard in core holds that). Admission reads the claim, the live record its `sid` names when a store is wired — which must have a subject, be the claim's subject, and not be past its `expiresAt` — the session lifecycle's record when `sessionLifecycleStore` is wired — a session whose close has committed is not live, its user session still there or not — the subject-revocation boundary when `subjectRevocation` is wired (not for a token, whose boundary `verifyJwt` reads), the registered session requirements, and, at `/authorize`, the `acr_values` asked for; an outage in any of them is logged once, at error, as `session_admission_unavailable` with the store and the action, never the `sid`. What each consumer answers per outcome is this package's:

| Consumer | Action, claim | Not live / revoked | A requirement not met | Step-up | Outage |
|---|---|---|---|---|---|
| `/oauth/authorize` | `oauth.authorize`, the cookie | the cookie session regenerated, then the login page (`login_required` under `prompt=none`) | `login_required`; an unmet `acr_values` is `unmet_authentication_requirements`; a new login asked for (`reauthenticate`) is one login trip, below | the trip below; `interaction_required` under `prompt=none` | `temporarily_unavailable` at the `redirect_uri` |
| `/oauth/consent` | `oauth.consent`, the cookie | `401 login_required` | `401 login_required` | `401 login_required` | `503` |
| `session` grant | `oauth.session_grant`, the cookie handed to it | `400 invalid_grant` | `400 invalid_grant` | `400 invalid_grant` with `step_up` | `503` |
| `authorization_code` grant | `oauth.code_exchange`, the code, twice | `session_invalid`, then `session_invalidated` | `400 invalid_grant` | `400 invalid_grant` with `step_up` | `503` |
| `refresh_token` grant | `oauth.refresh`, the verified token | `session_invalid` | `400 invalid_grant` | `400 invalid_grant` with `step_up` | `503` |

`/authorize` checks the cookie's flag first, before the client is looked up and with no store read, so an unauthenticated browser goes to the login page as it always did; it reads the session once, after the client lookup and the `redirect_uri` check, the request-object refusal, and the parsing of `prompt`, the single-valued parameters, `claims`, `max_age` and `acr_values`, and before the `response_type`, grant-type, first-party, email-verified, PKCE, nonce and scope checks — so a dead session sent with an unknown client is that client's `400` — and decides freshness (`max_age`, `prompt=login`) on the session the verdict carries before acting on the verdict, so `prompt=none` with a stale `max_age` is `login_required` whatever a requirement says. Before sending a browser to log in for a dead or revoked session it regenerates the cookie session, so a login page that forwards signed-in users cannot loop on the flag the refused session left; a regeneration that fails is `temporarily_unavailable`, logged as `authorize_cookie_session_unavailable`.

**A new login asked for** (`reauthenticate`) — by a requirement, or for `acr_values` a step-up through the second-factor authority cannot be recorded for on this session (a session store without `recordSecondFactor`, or a session whose primary authentication cannot be told), which admission answers `reauthenticate` (`acr`) because a new login can carry the factor — is **one login trip**: the login page with the [ask](#step-up-and-re-authentication-481) recorded, a step-up trip already asked carried in it, and the live session kept, as the `prompt=login` trip keeps it — a request a cross-site page can send does not sign the user out. A session that comes back from that trip and is still `reauthenticate` is refused rather than sent round again, whether it logged in since the ask or a login page forwarded it straight back: `unmet_authentication_requirements` for `acr` (the login carried no factor: a subject with none, a federated session), `login_required` for a requirement. `prompt=none` is `login_required` with no ask and the session kept; a composition with no session store to record the ask in answers `invalid_request`. `/oauth/token` carries a grant's `step_up` member onto the error body beside `error` and `error_description`.

**The step-up trip.** When a registered session requirement can be met by a step-up — or an `acr_values` entry by one requirement's reach — `/authorize` sends the browser to that requirement's page as registered — resolved once, at registration, on the issuer with the page's own parameters on its query (`page.href`); `/authorize` resolves nothing itself — with its own two parameters added: the reachable `acr_values` when the request asked for an acr, and `redirect_to` naming this request with the ask. The [ask](#step-up-and-re-authentication-481) records the trip under the requirement's name (`stepUpAskedAt`) beside the login it may already carry (`loginAskedAt`), so a session that comes back from the trip no later than it was sent is refused rather than sent again — `unmet_authentication_requirements` when the request's `acr_values` are what remain unmet, `login_required` when the requirement asks for a new login — while a session established after the ask may make one more trip, and a second requirement's trip is not taken for the first's. `redirect_to` names this request as a GET URL — a POST's form parameters written as its query, as every trip and login redirect here writes them — and the page must return the browser to it verbatim, as the login page must. A page URL that is not on the issuer's origin — registration refuses one when it is given the issuer — is never followed: `server_error` at the `redirect_uri`, logged at error as `authorize_step_up_page_off_origin`. No bundled requirement is released yet; the MFA module is the first.

**Coming back from the page.** The deployment's MFA page must read `redirect_to` and the `acr_values` hint from its query, post the hint to `POST /session/mfa/step-up`, and after the step-up — or a `403 mfa_no_qualifying_factor` — return the browser to `redirect_to` verbatim; on a `401` it sends the user to log in. The step-up renews the session's id, which the browser comes back with: `/authorize` admits the renewed session and mints the code with the `amr` it now vouches for (`["pwd", "otp", "mfa"]` after a TOTP step-up), the requested `acr`, and the primary's `auth_time`. The ask is a record of its own, so the renewal leaves it, and consent after the trip carries it to the pass that mints. A consent another tab parked before the step-up is bound to the old id and finds nothing: that tab starts over at `/authorize`.

## Client authentication: `private_key_jwt` (RFC 7523 §2.2)

Every client-authenticated endpoint here — `/oauth/token`, `/oauth/introspect`, `/oauth/revoke` — accepts, besides `client_secret_basic` / `client_secret_post`, a JWT the client signed with its own private key (#484). Nothing shared has to be distributed to every replica of a machine client and rotated everywhere at once: the private half stays with the client, rotation is a JWKS publish, and every assertion carries a `jti` the provider spends exactly once.

**Registration.** `tokenEndpointAuthMethod: "private_key_jwt"` with exactly one of `jwks` (the public keys, inline, RFC 7591 `jwks` — a key carrying a private member such as `d`, `p`, `q` or `k`, or a symmetric `kty: "oct"`, is refused at registration, since the projection every middleware reads is public) or `jwksUri` (`https`, or `http` on a loopback host; fetched at verification time and cached, unknown `kid`s trigger a refetch with a cooldown). No `clientSecret` — the schema refuses one next to this method, and refuses `jwks` / `jwksUri` next to any other.

**The request.** `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and `client_assertion=<JWT>` in the form body, and nothing else that authenticates: an assertion next to a Basic header or a body `client_secret` is refused before either is examined (RFC 6749 §2.3, one method per request). A body `client_id`, if present, must match the assertion.

**The assertion.** `iss` and `sub` both equal to the `client_id`; `aud` naming the issuer or the token endpoint URL (RFC 7523 §3 — either form, so a client library that uses one or the other works); `exp` required and at most one hour ahead (`MAX_CLIENT_ASSERTION_LIFETIME_SECONDS`) plus the clock tolerance (`clockToleranceSeconds`, 30 s by default, at most 300 — a verifier built with anything else is refused) — the ceiling an ID-JAG is held to, compared through core's `assertionLifetime` — and a refusal is logged as `client_assertion_refused` with `reason: "lifetime"`, `lifetimeSeconds` and `maxLifetimeSeconds`; `jti` required, at most 256 characters (core's `MAX_JTI_LENGTH`, since it is kept as a seen-set key) and single-use, recorded in the composition's `replaySeenSet` under `client-assertion:<client_id>` until the assertion expires; signed with an asymmetric algorithm (`RS*`, `PS*`, `ES*`, `EdDSA` — `token_endpoint_auth_signing_alg_values_supported` lists them; `HS*` and `none` are never accepted against a JWKS). `nbf` is validated when present, and `iat` when present must be neither ahead of the server's clock beyond the 30 s tolerance nor older than the lifetime ceiling.

**Refusals** are `401 invalid_client` — a replayed, empty or over-long `jti`, a wrong `aud`, an expired or over-long assertion, an `exp`, `iat` or `nbf` that is not a NumericDate (non-finite, such as JSON's `1e400`, or past the Date range; a fraction is fine — logged as `numeric_date`), a signature under a key the JWKS does not hold, a `kid` it does not publish, a client registered for another method, an unknown client or an `iss` that cannot name one (a control character, or past 256 characters — reason `malformed_client_id`, and the repository is not asked), or a `jwks_uri` that cannot be fetched (fail closed, logged as `client_assertion_refused` with the reason). A client repository that cannot answer is `503 temporarily_unavailable` instead (reason `client_repository_unavailable`): the client did nothing wrong. A `private_key_jwt` request in a composition that wired no `replaySeenSet` is `500 server_error`: a `jti` that cannot be recorded is one that could be replayed, so the path refuses rather than authenticating unchecked. The standalone template wires one (`ADAPTERS_REPLAY_SEEN_SET`, Redis by default; the memory adapter is refused under `CORE_DEPLOYMENT_MODE=multi` because a captured assertion would replay once per replica).

**Not shipped: `client_secret_jwt`.** It would need the repository interface to hand the middleware the raw secret as an HMAC key — `authenticate(clientId, secret)` compares, it does not reveal — and a bcrypt-hashed `clientSecret`, which is what the template recommends storing, cannot serve as one at all. The secret-based methods a deployment already has cover that case; the asymmetric one is the point of this feature.

```yaml
# config/clients.yaml
orders-service:
  tokenEndpointAuthMethod: "private_key_jwt"
  jwksUri: "https://orders.example.com/.well-known/jwks.json"
  allowedGrantTypes: ["client_credentials"]
  allowedScopes: ["orders:read"]
  defaultScopes: ["orders:read"]
  allowedAudiences: ["https://api.example.com/orders"]
```

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion=eyJhbGciOiJFUzI1NiIsImtpZCI6IjIwMjYtMDkifQ...
```

## Consent for third-party clients (#527)

`/oauth/authorize` mints a code for a client marked `firstParty: true` as soon as the session is authenticated — the deployment operates that client, and auto-consent is the honest model. Every other client goes through **consent**: the user is asked, on the deployment's own page, and the answer is recorded so they are not asked again for what they already allowed. Without a consent store, such a client is refused at `/authorize`.

Wire a `consentStore` and a `pendingConsentStore` and point `oauth.consentPage.url` (`OAUTH_CONSENT_PAGE_URL`, default `/consent`) at your page. An empty or blank url refuses boot (`config-validation-failed` at `oauth.consentPage.url`), as an empty `session.loginPage.url` does: the redirect would be `?challenge=<id>` relative to `/oauth/authorize`. An `OAUTH_CONSENT_PAGE_URL` exported empty is that mistake, not an unset variable — unset it to keep `/consent`. Each bundled module provides both: `memoryConsentStoreModule` from `@o3co/auth-provider-core` (single replica — refused under `core.deployment.mode = "multi"`) and `redisConsentStoreModule` from `@o3co/auth-provider-redis`, which shares the consent records and the parked requests across replicas. In the standalone template that is `adapters.consentStore = "memory"` or `"redis"`. Then, for a client that is not first-party:

1. `/authorize` runs every request-shape check as usual, then looks up the consent record for (`sub`, `client_id`). A live record covering the requested scopes (a subset of what was granted) mints the code with no interaction.
2. Otherwise the request is **parked under a 32-byte challenge** in the `pendingConsentStore`, bound to the session and the subject it was asked of, and the browser is redirected to `oauth.consentPage.url?challenge=<id>`. `prompt=none` gets `consent_required` at the `redirect_uri` instead (OIDC Core §3.1.2.6); `prompt=consent` parks the request even when a record covers it.
3. The page calls **`GET /oauth/consent?challenge=<id>`** (session cookie, uncacheable) and receives `client_id`, `client_id_host` (only for a client resolved from a Client ID Metadata Document — see below), `client_name`, `client_uri` (from the registration), `scopes` (what is asked), `granted_scopes` (what the user already agreed to, so the page can highlight the delta), `redirect_uri` (show its host — this is where the code goes) and `expires_in`.
4. The page **`POST`s `/oauth/consent`** with `{ "challenge": "<id>", "decision": "accept" | "deny" }` (JSON or a form). `accept` records the union of what was granted and what is asked, emits `consent.granted`, and answers `303` to the parked `/authorize` URL — which now finds the record and mints. `deny` emits `consent.denied` and answers `303` to the client's `redirect_uri` with `error=access_denied` and the `state` — unless core's `checkRedirectUri` refuses the parked `redirect_uri` (a request parked before such a URI was refused at registration), which is answered `400 invalid_request` (`redirect_uri not allowed`) with no redirect. Either way the challenge is spent.

The challenge is bound to the session that parked the request and reaches the page only through the redirect URL, which a cross-site page cannot read; a POST carrying the matching value was composed by same-origin code (the synchronizer-token pattern, with the session as the synchronizer). A foreign, replayed or expired (10 minutes) challenge is `400`. The answer **consumes** the parked record in one step (`PendingConsentStore.consume`), so two answers in flight for one challenge — a duplicated tab, a double submit — apply exactly one, and the other is told there is no pending consent. A consent-store outage at `/authorize` is `temporarily_unavailable`, never a code and never a refusal the user could act on. Both consent methods, once the parked request is found, read the session behind the cookie through core's admission as `oauth.consent` ([Session admission](#session-admission)), as `/authorize` does: a cookie that names no user, one that names no `sid` while a `userSessionStore` is wired, a session gone, past its `expiresAt`, answering another subject or established before the subject's sessions were revoked is `401 login_required`; so is a registered session requirement that is not met — a step-up included, since `/authorize` decides again after consent. A store that cannot answer is `503 temporarily_unavailable` ("session store unavailable"), logged once by admission as `session_admission_unavailable`. Nothing is shown or recorded, and the parked request stays parked, so the answer can be retried once the store is back. A live session whose subject is not the one the request was parked for is told there is no pending consent. An operator revokes a consent by removing the record (`consentStore.revoke(sub, clientId)`); the next `/authorize` for that client asks again.

Register what the page will show: `clientName` (RFC 7591 `client_name`) and `clientUri` (`client_uri`) on the client record. A native client with a loopback `redirect_uri` is the case the MCP authorization spec asks the page to warn about — `redirect_uri` is in the response for exactly that.

**A Client ID Metadata Document client names itself.** Its `client_name` and `client_uri` come from a document whoever controls its host wrote, so "Google Drive" costs nothing to type. The one verified fact is the host its `client_id` URL names, which the response carries as `client_id_host`: show it prominently, as the draft asks, and never let `client_name` stand alone. Serve the page with `Referrer-Policy: same-origin` (or `strict-origin`) so a `client_uri` link does not hand that host the page URL and its challenge. Not `no-referrer`: a page that also answers federation-grant consents would post that answer with `Origin: null`, which the federation-grants answer refuses ([its README](../federation-grants/README.md#the-answer-and-the-csrf-policy)).

## Client ID Metadata Documents (#529)

A client may identify itself with the `https` URL of its own registration — a **Client ID Metadata Document** ([draft-ietf-oauth-client-id-metadata-document](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/)), the registration model the MCP authorization spec (2026-07-28) makes the SHOULD for hosted clients now that Dynamic Client Registration is deprecated there. Off by default: `oauth.clientIdMetadataDocuments.enabled = true` (`OAUTH_CLIENT_ID_METADATA_DOCUMENTS_ENABLED`), and the discovery document then advertises `client_id_metadata_document_supported: true` beside the `none` it already lists in `token_endpoint_auth_methods_supported` — the two signals an MCP client selects on.

`GET https://client.example/oauth/client-metadata.json` is the registration:

```json
{
  "client_id": "https://client.example/oauth/client-metadata.json",
  "client_name": "Acme Chat",
  "client_uri": "https://client.example",
  "redirect_uris": ["https://client.example/cb", "http://127.0.0.1/cb"],
  "grant_types": ["authorization_code", "refresh_token"],
  "scope": "read write"
}
```

What the server does with it:

- **A pre-registered client with the same `client_id` wins**; the document is not fetched. Registered clients are read through core's client-record boundary (`validatedClientRepository`), and a document is resolved only when no client is registered under the `client_id`. A registration the boundary refuses (a malformed record) rejects the lookup with core's refusal, answered `503` like any rejected lookup (the logout routes log it and complete the logout without the post-logout redirect), and its document is never fetched in its place — whether the fallback's own boundary refuses it or one it reads through does, behind a cache or a forwarder. A repository that cannot answer is an outage (`503`), never a cached or stale document. This applies to every client lookup the router makes while documents are on — `/authorize`, `/token`, `/revoke`, introspection, consent and the federation token endpoint's `azp` lookup — whatever the `client_id` looks like, and is the same answer as with documents off, where the router reads registered clients through the boundary itself.
- **The router installs the one document fallback**, over the `clientRepository` it is handed, from `oauth.clientIdMetadataDocuments` — through `oauthEndpointsModule`'s section, or in the `section` handed to `createOAuthRouter` by a root that mounts the router itself. The package exports no fallback to build by hand, so every document client is admitted under the configured `allowedHosts`, `deniedHosts`, `allowedScopes` and `allowedAudiences`, and consent names its host (`client_id_host`) for the client object that fallback resolved.
- **A grant owns the boundary of the repository it reads.** The router reads clients through the boundary for its own lookups and for the client `/token` hands a grant (`ctx.authenticatedClient`), but it cannot wrap a grant already built. The authorization-code grant reads its client's logout metadata at the code exchange through core's boundary itself, over the repository it is handed, wherever it is built. The record is read before the code is spent: a record the boundary refuses fails the exchange `503 temporarily_unavailable`, as a read that throws does, the code stays redeemable, and nothing is signed or registered (see [Client record logout metadata](#client-record-logout-metadata)). Core installs the boundary in the `clientRepository` slot, so every module that reads the slot — this package's and other packages' — reads it through the boundary, and this package's own wrap keeps the slot's boundary as it is. A grant from another package that reads a `ClientRepository` itself, built by hand outside the slot, reads it as it was handed: a composition that builds one hands it a repository behind `validatedClientRepository`, and the grant keeps its own checks of the fields it reads.
- **The URL must be a document URL**: `https`, a path, no fragment, credentials, dot segments or query string, a host name rather than an address and not loopback. Anything else is not a client. A host name ending in the DNS root dot (`client.example.`) is refused outright: it survives URL canonicalisation and TLS accepts the undotted certificate, so it would otherwise be a spelling the host lists below do not match. The operator may narrow hosts further (`allowedHosts`, exact or `.suffix`; `deniedHosts` wins).
- **The name is resolved before the socket opens**, and every address must be public: one inside an RFC 6890 special-use range — the cloud metadata endpoint, a private network, this host — refuses the lookup. That is the SSRF guard the draft requires; a rebinding between check and connect is the residual it accepts too, and the host lists are the lever against it.
- **The fetch** follows no redirect (a 3xx is an error), times out (`timeoutMs`), caps the body on `Content-Length` and on the stream (`maxBytes`, 5 KB by default), and takes only `200` with JSON. A valid document is cached per URL for its `Cache-Control: max-age`, bounded by `cacheMaxAgeMs` and by `maxCacheEntries`, and revalidated by `ETag` when it expires. A `5xx` or a `429` from the client's server is read as *their availability*, not their registration — it takes the same path as a timeout or a DNS failure; a `4xx` or a refused redirect is the registration being absent or wrong, and takes the refusal path. A refusal is never cached *as a client*, but it is remembered as a refusal for `negativeCacheMs` (a minute by default), so an invented `client_id` does not cost a DNS resolution and a socket on every request; a registration this server already validated is still served for `staleIfErrorMs` through a revalidation that failed for a reason that is not the document's — a DNS blip, a 5xx, a timeout — because an outage at someone else's server is not a verdict on the client, while a document that was *rejected* is dropped at once. `maxConcurrentFetches` bounds how many documents are in flight across every id. Concurrent lookups share one fetch. Every refusal logs `cimd_document_rejected` / `cimd_document_fetch_failed` / `cimd_host_not_allowed` with the reason.
- **The document** must carry `client_id` equal to the URL, a non-empty `redirect_uris` this server would accept at registration (core's `checkRedirectUri`, the query-name rule included; exact match at `/authorize`, with the RFC 8252 §7.3 loopback-port carve-out), no `client_secret`, and no `token_endpoint_auth_method` but `none` — a shared-secret method is forbidden by the draft, and `private_key_jwt` is refused because the keys would come from the same attacker-authored document that names them, so it would authenticate the document rather than the client (registered clients may use it — see [`private_key_jwt`](#client-authentication-private_key_jwt-rfc-7523-22)). `grant_types` must include `authorization_code`; `response_types` must admit `code`.
- **The client it becomes is public and not first-party** (`tokenEndpointAuthMethod: none`, PKCE S256 required, `firstParty: false`), so it goes through the [consent step](#consent-for-third-party-clients-527) — **wire a consent store and register the `authorization_code` grant, or the feature stays inert**: without them `/authorize` could not finish such a flow — a document client uses no other grant — so no document is fetched and a URL-shaped `client_id` is simply an unknown client (the discovery document withholds `client_id_metadata_document_supported` for the same reason) — and the page shows the document's `client_name`, `client_uri` and the `redirect_uri`. Its scopes are the document's `scope` intersected with the operator's `allowedScopes`; its audiences are the operator's `allowedAudiences` — the resource servers this authorization server protects, which an MCP client names with `resource`. A document says who a client is, never what it may reach.

## Introspection: which tokens a caller may ask about

`POST /oauth/introspect` authenticates its caller first (RFC 7662 §2.1 — public clients are refused), then answers only about tokens that caller is entitled to see. Every answer carries `Cache-Control: no-store`; a refusal of client authentication is RFC 6749 §5.2 `{ error, error_description }`.

### The audience pin is `allowedAudiences` ∪ `{client_id}`

When client authentication identified the caller, the token's `aud` must be one of:

- an entry in that client's registered `allowedAudiences`, or
- that client's own `client_id`.

That is the same ceiling every issuing grant already derives an audience within (`client_credentials`, `refresh_token`, `/authorize`), so introspection admits exactly the audiences the registration already trusted this client to be associated with, and nothing beyond them.

The rule matters the moment RFC 8707 resource indicators are in use. Every access token then carries `aud: <resource URI>`, so a pin on `client_id` alone would mean a **resource server cannot introspect its own tokens** — it gets `active: false` unless it happens to be registered under a `client_id` that IS the resource URI. Register the resource URI as an allowed audience instead:

```jsonc
{
  "clientId": "orders-api",
  "tokenEndpointAuthMethod": "client_secret_basic",
  "allowedAudiences": ["https://api.example.com/orders"]
}
```

An audience outside that set, an unknown or expired token, one revoked through the jti denylist or the subject watermark, and one from another issuer all answer `active: false`. A token that could not be judged — the keystore, the denylist or the watermark did not answer — is `503 temporarily_unavailable` instead, on both paths: `active: false` says the token is not active, and a resource server told so refuses its client with `invalid_token`, which sends it to replace a token that may be perfectly good. The 503 vouches for nothing and is still fail-closed; it is audited as `introspect.store_unavailable` and logged as `token_verification_unavailable`. The **bearer self-introspection** path — `Authorization: Bearer <token>` where the body `token` is that same value — establishes no calling-client identity, so there is no set to pin against; the verifier records the gap as `jwt_verify_aud_skipped` rather than inventing one.

**A resource server or proxy that introspects** should read any answer other than `200` — this `503`, another 5xx, a timeout — as *unknown*, never as `active: false`:

- **Do not cache it.** A cached negative would outlast the outage, and a cached positive was never given.
- **Answer your own client with a 5xx** (`502` or `503`), not `401 invalid_token`. The token may be perfectly good, and a `401` sends the client to throw it away and start again.

[auth.proxy](https://github.com/o3co/auth.proxy) already behaves this way in validation mode. A non-2xx introspection answer is not cached, and its client gets `502 Bad Gateway`. Before v0.16.0, an outage came back as `200 active: false`, which auth.proxy cached for up to 30 seconds and answered with `401`.

### A `client_id` with reserved characters must be percent-encoded in HTTP Basic

RFC 6749 §2.3.1 requires the client id and secret to be `application/x-www-form-urlencoded`-encoded **before** the `id:secret` pair is base64-encoded into the `Authorization: Basic` header. A resource URI is the case that makes this mandatory rather than pedantic: it contains `:` and `/`, and `:` is the field separator the header is split on.

```
# WRONG — split at the first colon, so the client id parses as "https"
Authorization: Basic base64("https://api.example.com/orders:s3cret")

# RIGHT — reserved characters percent-encoded first
Authorization: Basic base64("https%3A%2F%2Fapi.example.com%2Forders:s3cret")
```

`client_secret_post` (credentials in the form body) avoids the question entirely — the body encoding already does it.

### What an active answer says about the authentication

An active token's answer carries RFC 9470 §6.2's `acr` and `auth_time`, and the token's `amr`, when the token carries them — the grant that minted it put them there, as [Step-up and re-authentication](#step-up-and-re-authentication-481) describes — read in the shape every grant reads them (`wellFormedAcr`, `wellFormedAmr`, `wellFormedAuthTime`) — `auth_time` no later than the token's own `iat` — and omitted otherwise, so a token without them answers without them. Introspection reads no session for them: it answers what the token this server signed says. `IntrospectResponse` types all three.

### Revoked families and ended sessions

- **Refresh-token family.** A token carrying `family_id` is checked with `refreshTokenFamilyRevocation.isFamilyRevoked` when that slot is wired: a revoked family answers `active: false` and emits `introspect.family_revoked`; a store that cannot answer is `503 temporarily_unavailable` ("refresh token store unavailable"), audited as `introspect.store_unavailable` and logged as `introspect_store_unavailable` — an outage, for the reason above. A token without `family_id` is verified by signature and the revocation stores alone. A revoked family is remembered until the last access token it could have minted stops being accepted, so the answer does not revert once the family's own refresh tokens expire (core's `refresh-token-family/retention.mts`).
- **Session liveness.** A token carrying a `sid` claim — or a `liveness_sid`, the liveness-only link a token-exchange result carries to its subject token's session (core's `grants/sessionClaims.mts`) — is checked against the `UserSessionStore`, the same read `/oauth/userinfo` performs. A session that has been logged out, has expired, or was deleted out of band answers `active: false` and emits `introspect.session_invalid`; a store outage is `503 temporarily_unavailable` ("session store unavailable"), audited and logged as the family store's is. A token with no `sid` (client credentials, jwt-bearer) does not pay for the read, and neither does a composition that wires no `userSessionStore`.
- **Through core's session lifecycle.** Where `sessionLifecycleModule` fills the `sessionLifecycle` slot, introspection, `/oauth/userinfo` and `POST /oauth/federation/:name/token` ask it (`sessionLifecycle.liveness`) instead of reading the `UserSessionStore`: a session whose close has committed is not live from that commit on, while its user session is still there — a close whose relying-party notice failed, for one. It answers as an ended session does (`active: false` / `introspect.session_invalid`, `401 invalid_token` `session_invalid`, `401 invalid_token` "session not found"), and so does a live session whose subject is not the token's `sub`. Its outage is the same `503` ("session store unavailable"), logged by the lifecycle as `session_lifecycle_unavailable` and by the route as `introspect_store_unavailable` / `userinfo_store_unavailable` with `store: "session_lifecycle"`, or `federation_token_store_unavailable` with `store: "session_lifecycle"`, `step: "liveness"`, none carrying an error; introspection also audits it as `introspect.store_unavailable` (`sid`, no `cause`). A lifecycle that throws (one a host fills the slot with) is the same outage, its line and event carrying the error's projection.

These bind only callers that ask: a resource server validating the JWT offline, by signature and `exp`, sees no revocation and accepts the token until it expires.

## Revocation

`POST /oauth/revoke` is RFC 7009. It authenticates the caller like `/oauth/token` — public clients included, since a public client may revoke its own tokens (§2.1) — answers `400 invalid_request` without a `token` and `400 unsupported_token_type` for a `token_type_hint` it does not recognise, and otherwise `200` whether or not the token existed or belonged to the caller (§2.2). A token is revoked only for the client it was issued to.

A revocation the server could not record is not a `200`. When the caller's own token verified and the store that records its revocation — the `accessTokenDenylist` or the refresh-token family store — fails, the answer is `503 temporarily_unavailable` (§2.2.1: the client should assume the token still exists and retry), logged at error level as `revoke_store_unavailable` with `store` naming which one and `clientId` the client whose revocation was lost. A token that does not verify, is not one this server can revoke, or belongs to another client never reaches a store, so it stays `200` during an outage too.

- **A refresh token** revokes its family through `refreshTokenFamilyRevocation`; without that slot the request is a no-op `200` — a composition without it cannot have the `refresh_token` grant on, so no refresh token it issued is redeemable.
- **An access token** is added to the `accessTokenDenylist` when `oauth.revocation.accessToken` is `"denylist"`, denied until its `exp` plus core's `REVOCATION_RETENTION_ALLOWANCE_MS` — the five-minute clock tolerance verification allows (`DEFAULT_CLOCK_SKEW_MS`), a replica allowance and a rounding second — for as long as it could still verify. A token past even that no longer verifies at this provider, so revoking it asks no store and answers `200`. A resource server of your own that calls `verifyJwt` with this denylist and a `clockSkewMs` above the default would accept a revoked token for the difference, so keep the default there. Under `"unsupported"`, `token_type_hint=access_token` is `400 unsupported_token_type` rather than a `200` that revokes nothing, and an unhinted token takes the refresh-token path only.
- **A token that cannot be verified because the keystore did not answer** is `503 temporarily_unavailable` — RFC 7009 §2.2.1's answer for a server that cannot process the request, after which the client assumes the token still exists and retries — logged as `token_verification_unavailable`. A `200` there would say a token was revoked that nothing touched. A kid the keystore does not hold is still the silent `200`.

Discovery advertises `revocation_endpoint` only when at least one of the two can revoke something. The endpoint's full behaviour is in the doc comment of [`routes/revoke.mts`](./src/routes/revoke.mts).

## Userinfo

```http
GET /oauth/userinfo
Authorization: Bearer <access_token>
```

OIDC Core §5.3, on `GET` and `POST`. Returns scope-filtered claims sourced from the durable `UserSession`.

| Condition | Response |
| --- | --- |
| Missing / invalid Bearer token | `401` with `WWW-Authenticate: Bearer realm="userinfo"` |
| Invalid JWT signature | `401 invalid_token` |
| The token's `family_id` is revoked | `401 invalid_token` |
| Session not found | `401 invalid_token` |
| The keystore, the jti denylist or the subject watermark cannot answer | `503 temporarily_unavailable` ("verification key unavailable" / "revocation store unavailable"), no challenge; logged as `token_verification_unavailable` |
| The refresh-token family store or the session store cannot answer | `503 temporarily_unavailable` ("refresh token store unavailable" / "session store unavailable"), no challenge; logged as `userinfo_store_unavailable` |
| No `userSessionStore` wired, or neither a `sid` nor a `liveness_sid` claim | `200 { sub }` (sub only, no durable claims) |
| A `liveness_sid` and no `sid` (a token-exchange result), session active | `200 { sub }` — the session is checked and none of it is released: the holder of an exchanged token is not the session's client, whatever its scope says |
| Session active | `200 { sub, ...scope-filtered claims }` |

All responses set `Cache-Control: no-store` and `Pragma: no-cache` (RFC 6750 §5.3). An outage is refused — no claims are served — but not as `invalid_token`, which RFC 6750 §3.1 defines as a statement about the token ("expired, revoked, malformed, or invalid") and which sends the client to replace it.

Scope-to-claim mapping (OIDC Core §5.4 standard scopes), shared with the id_token:

| Scope | Emitted claims |
| --- | --- |
| `openid` | *(governs id_token issuance; `sub` always included in userinfo response)* |
| `profile` | `name`, `picture` |
| `email` | `email`, `email_verified` |
| `groups` | `groups` |

## Token binding (`cnf`)

When a token-binding mechanism is installed (`@o3co/auth-provider-dpop` and/or `@o3co/auth-provider-mtls`), the grants here emit RFC 7800 `cnf` claims and the introspect handler echoes them back to resource servers. The binding contract and the `Confirmation` union are core's ([`confirmation.mts`](../core/src/grants/confirmation.mts), [`confirmationMatch.mts`](../core/src/grants/confirmationMatch.mts)); the design is in [ADR 2026-05-20-token-binding-first-class-abstraction.md](../core/docs/adr/2026-05-20-token-binding-first-class-abstraction.md).

### Issuance

- **Access-token `cnf` is the member the binding's mechanism owns.** Every grant stamps core's `ownedConfirmation` of the request's binding — DPoP's `{ jkt }`, mTLS's `{ "x5t#S256" }` — never the binding's `confirmation` as a mechanism returned it. A contributed mechanism whose kind owns neither member, or a binding carrying a member its kind does not own, gets an unbound token; a compound confirmation keeps the owned member alone. The same rule holds in the WebAuthn grant, the device grant and token exchange.
- **Refresh-token `cnf` is bound for public clients, and for confidential clients only on request.** A public client with a bound access token gets a bound refresh token, so the next refresh enforces continuity. A confidential client gets a plain refresh token — its client authentication is the refresh-time authenticator (RFC 9449 §5, RFC 8705 §7.1) — unless `core.tokenBinding.bindConfidentialClientRefreshTokens = true` (`CORE_TOKEN_BINDING_BIND_CONFIDENTIAL_CLIENT_REFRESH_TOKENS`), which binds it too. That costs key rotation: a bound refresh token pins the client to one key or certificate for its whole lifetime.
- **A required sender constraint is never downgraded.** For a client registered `senderConstrained: { required: true }`, the `/oauth/token` dispatch gate refuses, before any grant runs: no binding (`401 invalid_client`), a binding kind outside `methods` (`400 unauthorized_client`), and a binding whose confirmation carries no member its kind owns (`400 invalid_request`, "sender-constrained binding carries no confirmation its mechanism owns"; audit `token.issued.failure` with `reason: "sender_constraint_unowned_confirmation"`) — which would otherwise be minted the unbound Bearer token a client without the constraint gets.
- **Wire-level `token_type`** is read off the access token's `cnf` by core's `generateTokenResponse`: `"DPoP"` for `cnf.jkt` (RFC 9449 §5), `"Bearer"` for mTLS (RFC 8705 §3 — the certificate is the binding evidence, not the wire token type) and for an unbound token. The envelope cannot disagree with the claim.

### Refresh-time matrix

The refresh grant evaluates core's `matchConfirmation` once per mechanism (DPoP `cnf.jkt`, mTLS `cnf.x5t#S256`); each has the same five outcomes:

| Refresh token `cnf` | request binding | outcome |
| --- | --- | --- |
| plain | none | issue plain Bearer |
| plain | bound | opt-in upgrade — bind the new access token (the refresh token by the issuance rule above) |
| bound | none | reject `invalid_grant` |
| bound | bound, differs | reject `invalid_grant` (multi-key / certificate-substitution attack) |
| bound | bound, matches | rotation preserves the binding |

A `cnf` member is honoured only for its own mechanism, so a confirmation shape alone cannot satisfy a bound refresh token. A refresh token carrying **both** `cnf.jkt` and `cnf.x5t#S256` is rejected with `invalid_grant` before either matrix runs.

### Introspect

`/oauth/introspect` reads `cnf` from the access token and sets `token_type` to `"DPoP"` when `jkt` is present and `"Bearer"` otherwise (mTLS or unbound). The response carries the full `cnf`, so a resource server can require the right mechanism's proof at its boundary.

## Logout

The OIDC logout endpoints are mounted when the six session-cascade slots are all wired (see [Endpoints](#endpoints)).

> **There is a third logout endpoint, and it is not in this package.**
> `POST /session/logout` (`@o3co/auth-provider-session`) is the browser's own
> logout and the one a BFF / `auth.proxy` topology calls. It deletes the
> `UserSession` record, the subject-index entry and the federation pair — so
> the liveness checks elsewhere in this README do bite — but it revokes **no
> refresh-token families**, because `cascadeLogout` is not reachable across the
> package boundary. `POST /oauth/logout` is the only endpoint that runs the full
> cascade. If a session holds a refresh token, that is the one to call. All
> of this is without core's session lifecycle: where it is installed,
> `POST /session/logout` closes the session through it as `/oauth/logout`
> does, revoking the families and telling the relying parties. See
> [the session package README](../session/README.md#what-post-sessionlogout-invalidates).

### The session-close notifier

`oauthModule` contributes core's session-close notifier (`sessionCloseNotifiers`, under `oauth`), which core's session lifecycle calls once per relying party of a closing session, for each cause that tells them (every cause but `expiry`) — [`logout/sessionCloseNotifier.mts`](./src/logout/sessionCloseNotifier.mts). Where the lifecycle is installed, `/oauth/logout` closes the session through it (below), and this notifier is what tells its relying parties back-channel; `POST /oauth/federation/:name/logout` still runs its own steps.

- It posts one OIDC Back-Channel Logout 1.0 `logout_token` to the relying party's `backchannelLogoutUri` as its registration reads when the notice is sent, over the same sender and outbound path as the logout routes' broadcast. The token is signed by the key store, its `iss` the module's issuer (`oauth.jwt.issuer`).
- The token carries the session's `sid` unless the relying party declined one (`backchannelLogoutSessionRequired: false`), whatever closed the session.
- The notice is settled — it resolves — once delivered, when there is nowhere to send it (no URI, or the client is no longer registered), or when the relying party refuses it for good (any other 4xx, said at warn as `logout_backchannel_rejected`). It rejects only when sending again is worth it — the client registry or the key store could not answer, the request did not complete within its deadline, or the answer was 408, 429 or a 5xx — and the lifecycle then keeps that relying party's work pending for a later close or its sweep.

### `POST /oauth/logout` and `GET /oauth/logout`

OIDC RP-Initiated Logout 1.0 `end_session_endpoint`. Parameters (`application/x-www-form-urlencoded` on `POST`, the query on `GET`):

- `id_token_hint` (required) — signed id_token from this provider; its `sid` claim identifies the session
- `post_logout_redirect_uri` (optional) — must match one of `client.postLogoutRedirectUris` **exactly**, byte for byte. A reverse-domain custom scheme is a legal entry, and gets no relaxation for being one.
- `state` (optional) — round-tripped when redirecting to `post_logout_redirect_uri`

`post_logout_redirect_uri` is held to the list of the client the hint was issued to once, right after the hint is verified and found to name a session, and only the result is used from then on — by the confirmation page, the upstream end-session call and this endpoint's own redirect. One that does not match, or one for a client this deployment does not know, is treated as if none was sent: in particular, **the federation's end-session call is never handed it**. That matters because Google, GitHub and Apple publish no end-session endpoint, and without one configured their adapters redirect straight to the URI they are handed. The client is the hint's `azp` when that is one of its audiences, else its one audience (a string, or a list of one); a hint for several audiences and no `azp` names no client, and the URI is dropped. The match is exact: a trailing slash, another case in the host or the path, an added query, path segment or fragment, a prefix or another scheme is a different URI. A match must also have the shape every registration is held to at boot (core's `checkRedirectUri`). A custom `ClientRepository` bypasses `ClientEntrySchema` and so can hold an entry that is not a URL, or is in an executable scheme such as `javascript:`; such a match is dropped like an unregistered URI and the logout completes, logged once at warn as `logout_registered_redirect_uri_refused` with `site`, `clientId` and the rejection's `reason` (never the entry). A request that names no `post_logout_redirect_uri` does not consult the client repository at all. A client repository that cannot answer does not stop the logout: the URI is not used, since whether it is registered is unknown, and the logout completes as if none had been sent — logged once at error level as `client_repository_unavailable` with `site: "logout"`.

An `id_token_hint` that cannot be verified is `400 invalid_token`; one that cannot be verified because the keystore did not answer is `503 temporarily_unavailable`, on `GET` as on `POST`. One that names no session (no `sid`) is `400 invalid_request`, on `GET` as on `POST` and before the confirmation page: it can log nothing out. A `GET` whose `id_token_hint` was issued more than 24 hours ago is answered with a confirmation page instead of logging out; its form posts the hint and `state` back to this endpoint, and `post_logout_redirect_uri` only when it is on the client's allowlist.

Flow: verifies `id_token_hint` → holds `post_logout_redirect_uri` to the client's list → loads the session → begins the logout (below: the session marked ended, then its relying parties and federations read) → broadcasts an OIDC Back-Channel Logout 1.0 `logout_token` to every RP with a `backchannelLogoutUri` (best-effort; a failed POST does not stop the logout) → runs the store cascade → answers with one of:

- `text/html` page with an `<iframe>` per RP with an `http`/`https` `frontchannelLogoutUri` (see [Client record logout metadata](#client-record-logout-metadata); when `Accept: text/html` wins q-weighted negotiation), and, when `post_logout_redirect_uri` matched, a script that then sends the browser there with `state`, as the `303` below does. `renderFrontchannelLogoutHtml` takes that redirect as its parts, `postLogoutRedirect: { uri, state }`, holds `uri` to core's `checkRedirectUri` exactly as written, whoever calls it, and appends `state` itself: a `uri` the check refuses (one already carrying `state` among them), a value that is not a string, or a read that throws leaves the page without the script, logged once at warn as `logout_frontchannel_redirect_refused` with `reason` (never the URI)
- `303` to the first federation's IdP end-session URL (when that federation's provider implements `SupportsLogout`). The stored federation id_token goes with it as `id_token_hint`, and `post_logout_redirect_uri` only when it matched the client's list; when the federation token record cannot be read, the redirect goes without the hint, logged once as `logout_federation_token_read_failed` (warn)
- `303` to `post_logout_redirect_uri` (when it matches the client's allowlist)
- `200 {"logged_out": true}` (fallback)

**Where core's session lifecycle is installed** (`sessionLifecycleModule` fills the `sessionLifecycle` slot), the session is ended with `sessionLifecycle.close(sid, "rp_logout")` instead of the begin, the broadcast and the cascade above. The flow, after the session is loaded: read the federations the session joined (`sessionLifecycle.federations`) and, for the first of them when its provider implements `SupportsLogout`, its stored id_token, best effort — before the close, since the close removes the federation tokens that carry it → close → answer as above. The close's answer drives the rest:

- `done` — every item of the close work ran: the families revoked, the federation tokens and the session's index entries removed, the relying parties told, the `UserSession` deleted.
- `pending` — the close committed and some of its work is still outstanding. The session has ended — nothing joins it and no liveness read answers it live — so the logout answers as a success, audited as `logout.close_pending` (`sid`) beside `logout.success`; a later close of the session, or the lifecycle's sweep, resumes the work.
- `unavailable` — the close did not commit, or whether it did could not be read: `503 temporarily_unavailable` ("session store unavailable"), logged by the lifecycle as `session_lifecycle_unavailable` and by the route as `logout_store_unavailable` (error, `store: "session_lifecycle"`, `step: "close"`), audited as `logout.cascade_failed` (`sid`, `store: "session_lifecycle"`). On this path the event means the close could not be committed, and the session's state may be unchanged; it does not mean state was left behind. The browser session is kept for a retry, and nothing is ended upstream. One case is half-ended: the lifecycle writes the per-session stores' end mark before its closing commit, so a commit that fails after the mark was written leaves code exchanges for the session refused until a retry of the logout completes the close, or the mark lapses.

The route posts no back-channel `logout_token` itself: the lifecycle tells each relying party through the [session-close notifier](#the-session-close-notifier), once per notice. The front-channel page has an iframe for each relying party the close answers, read from its client registration (`clientRepository.findById`), only for an HTML answer; a registration that cannot be read drops that relying party's iframe alone, logged once as `client_repository_unavailable` (`site: "logout"`). The upstream end-session call goes to the first federation the close answers, with the id_token read before the close only when it was read for that same federation; a federation that joined after the read is ended upstream without a hint. A federation listing that cannot be read leaves the logout without the hint. A session already gone is the same `200` no-op as below, with nothing closed.

**A relying party that joins during the logout is in its fanout.** Where a session ends and what joins it are ordered in one place, [`logout/sessionEnd.mts`](./src/logout/sessionEnd.mts): the logout marks the session ended (when the family index has the session-end capability) before it reads the relying parties, and a code exchange registers its relying party before its family joins (`addFamilyIdUnlessEnded`). So a relying party whose family joined is in the logout's listing, and an exchange that comes after the mark is refused as ended and serves no token. This is inclusion in the back-channel and front-channel fanout, not delivery: the fanout stays best-effort. It holds under these preconditions:

- the relying-party registry is linearizable — a listing sees every registration completed before it began, read from the primary — and keeps a registration through that listing. This trusts the store: core states linearizability for the family index's session-end capability, not yet for the registry. A registration that expires during the listing is not listed though its family is (pinned in [`sessionEnd.test.mts`](./src/logout/__tests__/sessionEnd.test.mts));
- the family index's ended mark is authoritative across replicas, and no acknowledged write is lost — the conditions core states for the session-end capability;
- every way into the session passes the same fence: the code exchange does; the federation link callback does not ([#1031](https://github.com/o3co/auth.provider/issues/1031));
- the replicas' clocks agree within the session's life.

Without the session-end capability there is no mark to order by, and none of this holds.

An exchange refused as ended may already have registered its relying party, which then still gets the back-channel `logout_token` and the front-channel iframe for a `sid` it got no token for; that registration is removed with the session's other entries, or lapses with its TTL, and is never removed by the refused exchange, since the session's registrations hold earlier participants too. One lifecycle that makes joining and ending a session single, atomic steps is [#1030](https://github.com/o3co/auth.provider/issues/1030).

**The cascade** is [`cascadeLogout`](./src/logout/cascadeLogout.mts), four steps in a fixed order; its doc comment is the full contract, and [`cascadeLogout.test.mts`](./src/logout/__tests__/cascadeLogout.test.mts) pins it:

1. Read the session's refresh-token families. `/oauth/logout` hands the cascade the families its begin read when it marked the session ended (above), and nothing is read or marked again; with no session-end capability, the begin read none, and the cascade lists them (`listFamilyIds`). Called on its own, `cascadeLogout` marks the session ended and reads them (`endSession`, with the session's `expiresAt`, when the family index has the session-end capability and the caller passes `expiresAt`; `listFamilyIds` otherwise, an omitted `expiresAt` included). A code exchange that links a family after the mark is refused (see [`authorization_code`](#authorization_code-the-session-sid-family_id-and-the-id_token)). Failure stops the cascade; the mark may already be written, and a retry is safe.
2. Revoke every family and delete the session's federation tokens. Every operation is attempted; if **any** failed, the cascade stops here, before the bookkeeping a retry needs is erased.
3. Remove the session's reverse-index entries (relying parties, families, federations) — best-effort, logged, bounded by TTL.
4. Delete the `UserSession` last. Failure stops the cascade.

A cascade that stopped answers `503 {"error": "temporarily_unavailable"}`, and a retry of the same logout is safe. A cascade that stopped after step 1 marked the session leaves it half-ended: the session still exists, and its code exchanges are refused until a retry completes the logout or the mark lapses. It is logged once at error level as `logout_store_unavailable` with `store: "logout_cascade"`, the `cascadeStep` and the number of `failures`; each operation that failed also has its own `logout_cascade_operation_failed` (warn). A session store that cannot be read or marked before the cascade is the same event with `store` naming it (`user_session`, `session_family_index`, `session_rp_registry`, `session_federation_index`) and, past the session read, `left` saying what the failure left: `unchanged`; `half_ended` — the mark was written and a listing failed, so the session is half-ended as a stopped cascade leaves it; or `unknown` — the mark's call failed and the mark may have been written. A failure that left `half_ended` or `unknown` is also audited as `logout.cascade_failed` with `step: 1`, the `store` and `left`. The half-ended model itself remains unresolved ([#1030](https://github.com/o3co/auth.provider/issues/1030)).

On every success shape — and on the no-op answer for a session that is already gone — the endpoint also **ends the browser's own express-session**, but only when that session's `sid` is the one being logged out. RP-initiated logout is a request any party may make about any session, so a cookie naming a different `sid`, or naming none, is left alone rather than signing out an unrelated user. Without this the cookie would keep satisfying `req.session.isAuthenticated` at `/authorize` after the stores were emptied. A destroy the session store cannot complete is logged and does not turn a successful cascade into a `503`; `/authorize` refuses the dead `sid` on its own account either way (see [The OIDC surface](#the-oidc-surface-stated-284)). The `503` deliberately leaves the cookie in place, so a retry still names the session.

### `POST /oauth/federation/:name/logout`

Provider-scoped federation disconnect. Authorization: `Bearer <access_token>` with `typ: at+jwt`. Optional body: `post_logout_redirect_uri`, `state`.

Flow: verifies the access token → checks its family is not revoked → loads the session → verifies the federation is linked → holds `post_logout_redirect_uri` to the client's list → deletes the federation token → removes the federation from the session → if the provider implements `SupportsLogout`, redirects to the IdP end-session URL; otherwise returns `200 {"disconnected": true}`.

`post_logout_redirect_uri` is handed to the IdP end-session call only when it matches, exactly, one of the `postLogoutRedirectUris` of the client the access token was issued to (its `azp`) — the rule `/oauth/logout` applies, since this route too ends in a redirect the caller chose. Otherwise it is dropped, and the adapter answers as it does with none: Google and GitHub send the browser to their own logout pages, and Apple with no end-session endpoint configured refuses, which this route answers as any end-session call that fails — `200 {"disconnected": true}`. A token with no `azp` has no list to match, and a match is held to `checkRedirectUri` as on `/oauth/logout`. A client repository that cannot answer does not stop the disconnect: the URI is dropped and the route answers as it would without one, logged once at error level as `client_repository_unavailable` with `site: "federation_logout"`. A `POST` with no body is a disconnect that names no URI.

If the IdP end-session call throws, local state is already cleared; the response is `200 {"disconnected": true}` and an audit event `federation.logout.idp_unreachable` is emitted for operator visibility.

Returns `404 {"error": "federation_not_linked"}` when the named federation is not in the session. A keystore or a store that cannot answer — the family check included — is `503 temporarily_unavailable`, never `401 invalid_token`, logged once at error level as `federation_logout_store_unavailable` with `store` and `step` (or `token_verification_unavailable` for the keystore).

### Discovery metadata

Under the same six-slot check, `GET /.well-known/openid-configuration` advertises:

- `end_session_endpoint`
- `backchannel_logout_supported: true`
- `backchannel_logout_session_supported: true` — `logout_token` includes `sid` by default
- `frontchannel_logout_supported: true`
- `frontchannel_logout_session_supported: true` — the front-channel iframe URL includes `sid` by default

The `session_supported` defaults of `true` intentionally deviate from OIDC Back-Channel Logout 1.0 §2.2 (spec default: `false`). Clients that require the spec-default behavior must set `backchannelLogoutSessionRequired: false` or `frontchannelLogoutSessionRequired: false` on their client record.

### Client record logout metadata

The fields are defined on core's `Client` record ([`repositories/types.mts`](../core/src/repositories/types.mts)). What this package holds them to:

- `postLogoutRedirectUris` — the allowlist for `post_logout_redirect_uri`, held to the **same grammar as `allowedRedirectUris`** (#498): `https:`, `http:` for a loopback host, or an RFC 8252 §7.1 reverse-domain custom scheme (`com.example.app:/signout`), and never a fragment, userinfo or executable scheme. Its query is held to the same rule as well: names only from `[A-Za-z0-9_-]`, each parameter named, no `;`, and none of the authorization response's names (`code`, `state`, `iss`, `error`, `error_description`, ignoring case, `_` and `-`) — logout appends `state` itself. Registering the custom scheme is what lets a native app be returned to itself after logout instead of landing on a JSON body.
- `backchannelLogoutUri` — receives the `logout_token` POST. **`http`/`https` only** — this server dispatches the POST itself, and it has no way to reach a custom scheme.
- `frontchannelLogoutUri` — the iframe src. **`http`/`https` only** — the browser resolves this value in a document context, where a custom scheme is at best inert and at worst a handler invocation the RP never asked for. Its query may not use `iss` or `sid`, the names front-channel logout sets (compared ignoring case, `_` and `-`), nor a name outside `[A-Za-z0-9_-]` or a `;`: core refuses such a URI at registration, and in a custom `ClientRepository`'s record at core's client-repository boundary. **At the code exchange**, which registers the RP for logout, the client record is read through core's client-record boundary, which holds it to the registration schema, this rule included. A record the schema refuses is refused whole and warned `client_record_refused`, and the exchange answers it as it answers a read of the record that throws: `503 temporarily_unavailable`, logged `client_repository_unavailable` (for a refusal, with `reason: "client_record_refused"` on the error's projection), and no RP is registered. **At logout**, an entry a custom session RP registry answers bypasses `ClientEntrySchema`, so the same rule (the parsed protocol is `http:` or `https:`, on any host) is applied where the value is used: at the logout route and on the front-channel page. A value that fails it, is not a string or cannot be read is left out: that RP gets no iframe, and a logout with no RP left answers as without front-channel logout. Each is logged once at warn as `logout_frontchannel_uri_refused` with `site: "logout"`, `clientId` and `reason` (never the URI). The logout does not fail over it: front-channel logout is best-effort.
- `backchannelLogoutSessionRequired` / `frontchannelLogoutSessionRequired` — default `true`; `false` leaves `sid` out of the `logout_token` / the iframe URL.

## Federation token endpoint

`POST /oauth/federation/:name/token` retrieves the upstream IdP access token for the caller's session, so a consumer can make server-side API calls to Google Calendar / GitHub API / etc. on the user's behalf. It is mounted under the six-slot check (see [Endpoints](#endpoints)). Offline delegation — a token without the user's session — is a different feature, `@o3co/auth-provider-federation-grants`.

### Authentication

- A Bearer access token minted by this auth.provider instance (`typ: at+jwt`).
- The token's `azp` claim identifies the client; the client record MUST opt in via `allowedAzpForFederationToken: true` (see below).

### Flow

1. Verify the Bearer access token.
2. Deny if its family is revoked or the session no longer exists.
3. Deny unless `client.allowedAzpForFederationToken === true`.
4. Deny unless the federation is linked to the session.
5. Return the stored upstream access token if it has more than the refresh buffer (`refreshBufferMs`, 30 seconds by default) of validity remaining, or no finite expiry and no refresh token. A record with no finite expiry that holds a refresh token (a link-time record whose exchange stated no lifetime) is refreshed on first use, through the same lock and rotation path as any refresh, and its answer is stored with an end, capped as below. If that answer's lifetime is refused (`invalid_expiry`), the rotated refresh token is still kept and the stored token is answered as before. The record stays due, and the route has no refresh backoff, so each request refreshes it again. Within the buffer, a token whose record says when it was obtained (`obtainedAt`, written only when the upstream stated `expires_in`: an end stated only as an instant is on the upstream's clock and is never aged) is still returned until half its lifetime has passed, while it has at least a second left, so an upstream that issues lifetimes shorter than the buffer is not asked again, and its refresh token rotated, on every request. Core's `judgeHeldUpstreamToken` judges the age; an `obtainedAt` that is `undefined`, or that it does not believe (dated more than a second ahead of the reading replica's clock, or not before the token's end), leaves the buffer rule as it is. This damps refreshes, it does not bound them. It reads the record's instants on this replica's clock, and relies on replicas' clocks agreeing within 1 second, as [the operator runbook requires](../../docs/operator-runbook.md#replica-clocks-and-subject-revocation): for an end derived from `expires_in`, a replica δ ahead dates both instants δ late. A token is never returned this way with less than a second left on the reading replica's clock, so with δ ≤ 1 s it has at least 1 s − δ left upstream when it is judged; at the 1-second limit it can reach its upstream end as it is answered. A token handed on at or past its upstream end, at that limit or in a fleet whose clocks drift further, fails there (`401`) and widens no access.
6. Otherwise, refresh it:
   - Acquire an advisory lock (when `FederationTokenStore` implements `SupportsLock`) to prevent concurrent refresh fan-out.
   - Re-read after the lock — another waiter may have refreshed during the wait, or a logout or unlink removed the record. A record gone by then is answered `404 federation_not_linked`, as on the first read, with no upstream call and no record written back.
   - Call `provider.refreshToken(refreshToken)`; persist the result onto the record the refresh was made from, and only onto it (below). Its lifetime is read through core's `readUpstreamTokenLifetime`. An answer whose stated lifetime is malformed or contradicts the other field, or leaves less than a second, is `500 refresh_failed` (`invalid_expiry`). An answer that states no lifetime (both fields absent or `null`; RFC 6749 §5.1 only recommends `expires_in`) is given the maximum below as its end, obtained when the call began: a refreshed token is never stored with no finite expiry. Its `expires_in` announces that maximum, though the upstream may end the token sooner; such a token then fails at the resource server (`401`) and widens no access. Every end is capped at `maxTokenLifetimeMs` (24 hours by default) from when the answer is read: a longer lifetime is shortened, never refused, so such a token becomes due for refresh within that time; the refresh itself happens on the next request once it is due.
   - Release the lock.

**Every write lands only on the record it was read from.** The route reads the record with its store generation and writes only at that generation (`replaceIf` / `removeIf`, core's [conditional-write convention](../../docs/adapter-surface.md#conditional-writes)), so a logout, an unlink or a relink that lands while a refresh is in flight is never undone or overwritten:

- **Removed meanwhile** (a logout or an unlink): the refresh's tokens, the rotated refresh token included, are dropped and the answer is `404 federation_not_linked`, logged at warn as `federation_token_refresh_discarded` (`reason: "record_gone"`). The dropped refresh token is not revoked upstream.
- **Rewritten meanwhile** (a relink, or another refresh): the refresh's tokens are dropped, logged as `federation_token_refresh_discarded` (`reason: "record_replaced"`), and the record that won is read once more: answered as stored when it is not due, `503 temporarily_unavailable` ("the federation token was replaced concurrently; retry") when it is. The refresh is never repeated within one request, and nothing of the replaced connection is handed on. A refresh token the upstream rotated in the dropped refresh is lost with it: if the upstream thereby invalidated the one the winning record holds, that connection's next refresh fails (`410`) and the user reconnects.
- **A rotated refresh token on a refusal** (the `500` and `502` below) is kept the same way, on the record it was rotated from only. One removed or rewritten since is left as it is (`federation_token_keep_rotated_skipped`), and the refusal is then answered as the dropped refresh above (`404`, the record that won, or `503`), not `500` or `502`.
- **The upstream's `invalid_grant`** removes the record it refused, only as read and only while the request holds the refresh lock. A record removed or rewritten since is answered as above instead of `410`. Without the lock (a store with no `SupportsLock`) the record is kept and the answer is still `410`: a sibling refresh may have spent the refresh token this one presented, and its rotation is still to land. Under a lock whose TTL lapsed during the upstream call, the refused refresh can still remove the record a sibling is about to write; the sibling's refresh is then dropped as removed, and the user reconnects.
- **The session's federation index is never written by this route.** A link left with no record is answered `404`, holds no credential, is removed by federation logout, and ends with the session; until then RP-initiated logout may pick it for the IdP end-session call and send no `id_token_hint`.

The fence holds at the store's atomic step, not at the response: a token read, or written, just before a concurrent unlink completes can still be answered. Older replicas that still write unconditionally can restore or overwrite a record until a rolling upgrade completes.

### Response

```json
{
  "access_token": "<upstream-IdP-access-token>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "<what the connection holds>"
}
```

`token_type` is always `Bearer`, and only a bearer token is handed on. Every
other name in IANA's Access Token Types registry is either sender-constrained —
`PoP` (RFC 9200), `DPoP` (RFC 9449), where presenting the token takes proof of
possession of a key that a caller receiving it by value does not hold — or not
an access token type at all (`N_A`, RFC 8693 §2.2.1). This endpoint answers
`502 upstream_token_ineligible` for one instead of handing it out, which is the
same judgement `core` makes of the same contract on the offline-delegation
route.

The upstream's own spelling is kept in the stored record — it is what the audit
event reports, and what an operator reads — but is not echoed on the wire. Once
a non-bearer type is refused, the only values left are case-variants of one
word, and RFC 6749 §5.1 makes the comparison case-insensitive ("Value is case
insensitive"), so the spelling carries nothing a caller can act on; echoing it
would flip a `federation-oidc` connection between `Bearer` and `bearer` with the
upstream's answer, for no gain. The sibling offline-delegation route does echo
it, deliberately.

A connection whose adapter names no type **at all** is answered `Bearer`: §5.1
makes the field REQUIRED, so an absent field is an adapter that does not report
it — a third-party adapter written before the field, or a record linked before
the bundled adapters reported one — rather than an upstream meaning something
else. Every bundled adapter reports the type its upstream sent, through core's
`federationTokenSnapshot`.

Absence is the only reading treated that way. A stored value that is not a
bearer spelling is refused whatever it is — `"DPoP "`, `""`, `null`, a number —
because a store is one more thing this route does not own, and reading a
malformed record as silence would answer `Bearer` for it. At the other end, an
adapter that names something which is not a string is recorded as `""` rather
than dropped, so the refusal has something to refuse.

`scope` is what the stored connection holds, recorded when the federation is
linked. It is bounded by what the user consented to at that moment, so a
refresh can narrow it and can restore it to the grant, and can never take it
past.

One consequence worth stating: an upstream that narrows and then stays silent
on later refreshes leaves this field claiming more than the token holds. That
is deliberate — the alternative made the first narrowing permanent — and it is
bounded by consent. A client that reads `scope` to decide whether to send the
user back for consent should treat it as an upper bound rather than a
guarantee.

### What this route needs from the federation token store

The store's contract is core's `FederationTokenStore` and `FederationTokens` ([`federation-tokens/types.mts`](../core/src/federation-tokens/types.mts)); every field of a record is a required key, as [Upgrading: store records name every field](../../docs/upgrading-required-record-keys.md) describes for anyone implementing or calling a store. `obtainedAt` is a `Date` when the upstream stated `expires_in`: the instant this route's refresh call began, or, on a link-time record, the instant before session's code exchange. It is `undefined` where the token's age is unknown: an end stated only as an instant, no finite expiry, or a record written before the field. What this route depends on:

- **Every field survives `attach`, `replaceIf`, `get` and `getVersioned`.** Losing `tokenType` fails **open**: the record comes back silent, silence is read as `Bearer`, and a sender-constrained token is handed on as one. Losing `refreshToken` makes the connection unrefreshable (`410 refresh_token_absent`); losing `idToken` drops the upstream's `id_token_hint` at logout; losing `grantedScope` makes the current scope the refresh bound, which under-reports.
- **An adapter's own storage shape names every field too.** The required keys reach `FederationTokens`, not a row or document an adapter converts it to: declare the same required keys on that shape, as the bundled Redis store does for its envelope, or the conversion can forget a field and still compile. Declare `obtainedAt` there as well.
- **`obtainedAt` survives too, as a `Date`, or as `undefined` with the key named.** Dropping it fails closed: such a record loses the half-spent damping and is refreshed within the buffer, as one written before the field.
- **An unset optional string field (`refreshToken`, `idToken`, `tokenType`, `scope`, `grantedScope`) comes back as `undefined` or absent, never `null`; `obtainedAt` is always present, `undefined` when unknown.** This route refuses a stored `null`, so a serialiser that writes `undefined` as `null` — MongoDB's driver does unless `ignoreUndefined` is set — turns every connection whose adapter names no type into a `502`. The bundled Redis codec refuses a record holding `null`.

- **`getVersioned`, `replaceIf` and `removeIf` keep the [conditional-write convention](../../docs/adapter-surface.md#conditional-writes).** A store that answers a conditional write outside it (another outcome, a malformed generation) is an outage to this route: `503`, or a logged best-effort failure, never a write assumed to have landed.

Both bundled stores meet these and are pinned on them.

### Error responses

| Status | Error | Meaning |
| --- | --- | --- |
| 401 | `invalid_token` | Bearer missing, invalid, wrong type (not `at+jwt`), or family revoked |
| 403 | `forbidden` | Client not opted in via `allowedAzpForFederationToken` |
| 404 | `federation_not_linked` | The named federation isn't linked to this session, or its token record is gone — at the first read, after the refresh lock, or removed while the refresh ran — or holds no usable access token when it would be handed on (that record is then removed as it was read, and the latter is logged at warn as `federation_token_record_unusable`; a due one is refreshed). The session's index is left as it is |
| 410 | `refresh_token_absent` | Stored tokens have no refresh token (upstream didn't return one at login, or the post-lock re-read found a record without one) |
| 410 | `re_authentication_required` | The IdP rejected the refresh token: `invalid_grant` / `invalid_token` in the `error` of what its library raised, under a status that is neither a 429 nor a 5xx — the token record the refresh was made from is removed when the request holds the refresh lock, and kept otherwise; the user must re-authenticate with the IdP. A record removed or rewritten meanwhile is answered as a dropped refresh instead (`404`, or the record that won). A 429 or a 5xx is never this, whatever its body names, and neither is an error whose message merely contains the code: those keep the stored tokens (`429`, `503` and `500` below) |
| 429 | `rate_limited` | Upstream IdP rate limit exceeded (`status: 429`, whatever code its body names, or `error: "too_many_requests"`); the stored tokens are kept. `Retry-After` carries the upstream's own, when it named one in whole seconds (1 to 86400); none is invented otherwise |
| 500 | `refresh_failed` | Unclassified error from the IdP refresh path — including one whose message names `invalid_grant` without the code in its `error` — or an answer this route could not read; the stored tokens are kept. SIEM should group on the `details.reason` audit field |
| 502 | `upstream_token_ineligible` | The upstream's token is one this provider may not hand on. `error_description` names the reason — `token_type_unsupported` is the only one. Carries `Retry-After: 300` |
| 503 | `refresh_not_supported` | Provider doesn't implement `SupportsRefresh`; logged at error level as `federation_token_refresh_unsupported` — the deployment's to fix |
| 503 | `lock_timeout` | Advisory lock could not be acquired within the wait window; logged at warn as `federation_token_lock_timeout` with `federation`, `clientId` and `sid`, so contention that persists is seen |
| 503 | `temporarily_unavailable` | A refresh whose record was replaced concurrently by one that is itself due ("the federation token was replaced concurrently; retry"; see above). A token, stored or just refreshed, with less than a second left when its answer is built ("the federation token has less than a second left; retry"): a `200` never carries `expires_in: 0`, and the retry finds the token due and refreshes it. Otherwise a store outage — the refresh-token family check included, and a conditional write answered outside the store's contract — a keystore or revocation store that cannot answer while the access token is verified, or an upstream outage: an IdP that answered 5xx — whatever OAuth code its body names but `too_many_requests`, which is the `429` above, and whether the library read the body or raised over the `Response` — did not answer in time, or could not be reached (a connection or transport code, on the error or wrapped in its causes; core's `isFederationUpstreamOutage` decides, before the codes that reject the refresh token). The stored tokens are kept for the retry, though after an upstream that rotates refresh tokens the stored one may already be spent (the refresh reached the upstream but its answer did not, or the record's write failed), so the retry can end `410`. Each is logged once at error level: a store as `federation_token_store_unavailable` with `store` and `step`, the client lookup as `client_repository_unavailable` (`site: "federation_token"`), the upstream as `federation_token_upstream_unavailable`; an upstream refusal that is not a 503 is `federation_token_refresh_failed` (warn) |

All error responses set `Cache-Control: no-store` and `Pragma: no-cache`. 401 responses include `WWW-Authenticate: Bearer error="invalid_token"` per RFC 6750.

Every failure this route logs carries core's `loggableError(err)`, never the error — the `federation_token_refresh_failed` warning included. The adapter's library puts the refresh answer it refused, rotated refresh token included, on the error's cause chain, and a Redis store's error carries the refused command's arguments (the token record, under `allow-plaintext`); the projection drops those, keeps what tells the failures apart — the library's code, the HTTP status and content type, the upstream's OAuth `error`, and its `error_description` under the rule core states for it (the first line, cut at the start of the word holding a token-shaped run) — and removes the two known shapes in which a message quotes a peer (a JSON parser's input, Redis's echoed arguments). Other text a peer wrote into a message is kept; core's README says exactly what is. The rest of this package's logs follow the same rule.

### Opt-in: `allowedAzpForFederationToken`

Each `Client` carries an optional `allowedAzpForFederationToken: boolean` flag. Default is `false` — clients do NOT get federation-token access automatically. Operators explicitly opt in for clients that need it:

```yaml
clients:
  - clientId: my-backend-api
    clientSecret: ...
    allowedRedirectUris: [...]
    allowedScopes: [openid, profile, email]
    allowedAzpForFederationToken: true  # explicit opt-in
```

Rationale: federation access tokens grant access to the user's external resources (Google Drive, GitHub API, etc.). Deny-by-default prevents accidental exposure when a generic OAuth client registration only needs auth.

### Audit events

Where one of these events, or the federation logout route's (`federation.logout.success`, `federation.logout.idp_unreachable`), carries `details.federation`, it holds the name the way the log lines do: the path's name sanitised and capped at 200 characters. `federation.token.forbidden` fires before the route checks that the federation is linked to the session, so the name there is whatever the caller put in the path.

- `federation.token.success` — on token issuance (details include `refreshed: boolean` to distinguish a stored token from the refresh path)
- `federation.token.forbidden` — on 403 (client not opted in)
- `federation.token.family_revoked` — on 401 via revoked family
- `federation.token.refresh_failed` — on the 500 `refresh_failed`, which is two cases. `provider.refreshToken` threw an error the refresh-error classifier could not place: `details.reason` is `"unknown"`. Or an answer came back that this route cannot use: `"no_access_token"`, `"invalid_expiry"` or `"invalid_token_type"`. Those four are every value this event carries, and SIEM rules should group on them. With `"invalid_expiry"`, `details.verdict` says why: `"malformed"`, `"contradictory"`, `"spent"` (less than a second left), `"unreadable"` (a field whose getter threw) or `"unrecognised"` (a verdict a newer core added). The classifier's other results are **not** this event: `invalid_grant` is `federation.token.reauthentication_required` (410), and `rate_limited` (429) and `network` (503) emit no audit event.
- `federation.token.reauthentication_required` — on the IdP's structured `invalid_grant` or `invalid_token` (the 410 above)
- `federation.token.upstream_ineligible` — on 502. `details.reason` is `"token_type_unsupported"` and `details.tokenType` is what the record held, reported as it was read, sanitised and capped at 200 characters (core's `auditErrorText`) — including a value that is not a token type, which is the one worth seeing; `null` means the record held something that is not a string. The response carries `Retry-After: 300`, matching `federation-grants.ineligibleRetryAfter`'s default, because the condition ends when an operator changes the upstream's registration and not before. The caller is not told which type it was; it can do nothing with that but retry

## jwt-bearer: which issuers are trusted (#525)

The RFC 7523 grant (`urn:ietf:params:oauth:grant-type:jwt-bearer`) accepts a signed assertion from an issuer this deployment trusts and hands the verified handle to the Store (`userRepository.authenticateByToken`). It issues no refresh token.

**Through `/oauth/token` every request carries a client.** Client authentication admits a public client (`tokenEndpointAuthMethod: "none"`) by its `client_id` alone — which is what a device holding a signed assertion is — and refuses a request with no client at all (`401 invalid_client`). That client's `allowedGrantTypes` must name this grant. The grant itself also accepts a request with no client identity, since RFC 7523 §3 makes client authentication optional; that is reachable only from a composition that dispatches the grant without client-authentication middleware, and it is what the "no authenticated client" rules below refer to. Enabling it without a `userRepository` or an `assertionVerifier` fails at boot: there is no default verifier, because the only possible default would accept things.

Which issuers, on what keys, on what terms, is a **trust registry** of issuer entries — `AssertionIssuerEntryInput` as written, `AssertionIssuerEntry` as the registry answers with them — and the bundled verifier is built over it:

```ts
import {
  createMemoryAssertionIssuerRegistry,
  createRegistryAssertionVerifier,
} from "@o3co/auth-provider-core";

const registry = createMemoryAssertionIssuerRegistry([
  {
    issuer: "https://devices.example",
    keys: { type: "jwks_uri", uri: "https://devices.example/.well-known/jwks.json" },
    algorithms: ["EdDSA"],
    allowedClients: ["mobile-app"],           // who may present its assertions
    allowedScopes: ["read", "write"],         // ceiling on the issued scope
    allowedAudiences: ["https://api.example"], // ceiling on the issued aud
  },
  {
    issuer: "https://legacy.example",
    keys: { type: "key", key: legacyPublicKey },
    algorithms: ["ES256"],
    expiresAt: new Date("2026-12-31T00:00:00Z"),
  },
]);

const assertionVerifier = createRegistryAssertionVerifier({
  registry,
  audience: ["https://auth.example", "https://auth.example/oauth/token"], // what the assertion's aud must name
});
```

What an entry says, and what it means at `/oauth/token`:

- **Keys** come from one public key (`type: "key"`), a static JWK set (`type: "jwks"`), or a JWKS endpoint (`type: "jwks_uri"`, `https` required outside loopback). A remote set is fetched on first use and cached (10 minutes by default; `cacheMaxAgeMs`, `cooldownMs`, `timeoutMs` on the entry tune it); an unknown `kid` triggers a refetch, so a rotation at the issuer is picked up without a restart. The fetch is the verifier's `fetch` option when given — an egress proxy — as it is for a `private_key_jwt` client's `jwksUri`; both are core's `createRemoteKeySetCache`. An endpoint that is down is an outage: the grant answers `503`, not `invalid_grant`.
- **`exp`, `iat` and `nbf` must be NumericDates** (core's `isNumericDate`): an assertion carrying `1e400` (Infinity in JSON) or a value past the Date range is `invalid_grant`, refused before an ID-JAG's `jti` is recorded — it used to reach the replay seen-set and come back as a `503`. A fraction is fine.
- **An unregistered `iss` is refused before any signature work.** No key is fetched and no signature is checked for an issuer nobody registered; "signed by A, claiming to be B" fails on B's keys. An `iss` that cannot name an issuer (longer than 256 characters, or carrying a control character — the rule a `client_id` is held to) is refused before the registry is even asked. A registry backed by your own store is never handed one, so it cannot be made to throw, and an entry registered under such a name is refused when it is added. `findIssuer` must answer an unknown issuer `null`, never throw.
- **`allowedClients`** restricts who may present the issuer's assertions; a list refuses an unauthenticated presenter. Absent, anyone may.
- **`maxLifetimeSeconds`** caps how long a plain RFC 7523 assertion from the issuer may live, measured as `exp − iat`. An assertion that lives longer is `invalid_grant`, logged as `lifetime`. The default is an hour (core's `DEFAULT_ASSERTION_MAX_LIFETIME_SECONDS`). An entry may name any whole number of seconds up to a day (`ASSERTION_MAX_LIFETIME_LIMIT_SECONDS`), because a subject's revocation boundary is kept that long and must outlive every assertion it covers. An assertion without `iat` has no lifetime to measure. An ID-JAG keeps the profile's own hour.
- **`allowedScopes`** is intersected with the assertion's own `scope` claim (or stands alone when the assertion names none) and becomes the scope ceiling the request and the client registration are further bounded by.
- **`allowedAudiences`** bounds the issued `aud` whatever chose it — a `grantPolicy`, an RFC 8707 `resource`, the client registration (its `allowedAudiences` narrowed to the issuer's, its client id only if the issuer admits it). With no authenticated client it is also the source: the token names the issuer's first audience instead of this server. A client and an issuer that admit no audience in common is `invalid_grant` and logs `jwt_bearer_issuer_audience_mismatch`.
- **`expiresAt`** is the one field that changes in place (`registry.setExpiresAt`); everything else is immutable — remove and re-add — so the history of what was trusted is the history of adds and removes. `add`, `list`, `remove` are the rest of the admin surface. **On the memory registry that surface reaches one process:** an issuer revoked with `setExpiresAt` on one replica stays trusted on the others, a restart rebuilds the registry from the composition's entries — restoring the issuer even where it was revoked — and `core.deployment.mode = "multi"` cannot catch it, because the registry lives inside the `assertionVerifier` you hand in rather than on a module. Entries supplied when the registry is built are identical everywhere; with several replicas, change the entry list and redeploy, or implement the registry over a shared store.

`createJwtAssertionVerifier({ key, issuer, audience, algorithms })` — the static one-key shape — is a one-entry registry. A deployment that registers issuers at runtime and needs them to survive a restart implements `AssertionIssuerRegistry` (`findIssuer`) over its own store. **An entry is data** a store can hold: every field survives a JSON round trip (revive `expiresAt` as a `Date`), except `keys: { type: "key" }`, a live key object — a store-backed entry uses `jwks` (a one-key set is fine) or `jwks_uri`.

A store-backed registry must hand back **every ceiling** it was given. Each field beyond `issuer`, `keys` and `algorithms` narrows what the issuer's assertions may obtain, so a read-back that forgets one fails **open**: `allowedClients` gone admits any presenter, `expiresAt` gone trusts the issuer for ever, `profile: "id-jag"` gone drops the `jti` replay, `typ` and exact-`aud` checks. So `findIssuer` answers with `AssertionIssuerEntry`, whose fields are all **required keys** (`undefined` where the entry names no ceiling). What callers write — the composition's list and `add` — stays `AssertionIssuerEntryInput`, where absent means "no ceiling". A store-backed registry:

- **on write**, validates with `checkAssertionIssuerEntry`, normalises with `toAssertionIssuerEntry(input)`, and persists every field — declaring its own row type with every key required, or the write into it can forget one;
- **on read**, builds an `AssertionIssuerEntry` object literal naming every field. That literal is what the type checks: forgetting a key fails to compile. Mapping a row through `toAssertionIssuerEntry` does *not* — it takes the input type, where every ceiling is optional.

The type does not reach a registry in plain JavaScript, `as AssertionIssuerEntry` / `JSON.parse(row) as …` casts, or a `jwks_uri` key source's optional tuning (`cacheMaxAgeMs` lost restores the ten-minute default); those are held to the rule alone. See also [Upgrading: store records name every field](../../docs/upgrading-required-record-keys.md).

How claims are read is code, so it is the verifier's, not the entry's. With several issuers, namespace the handle unless every issuer's `sub` values are known to be disjoint — the Store receives the handle alone:

```ts
const assertionVerifier = createRegistryAssertionVerifier({
  registry,
  audience: "https://auth.example",
  readersFor: (entry) =>
    entry.profile === "id-jag"
      ? undefined // keep the ID-JAG default, <iss>#<tenant>#<sub>
      : {
          readSubjectHandle: (claims) =>
            typeof claims.sub === "string" && claims.sub.length > 0
              ? `${entry.issuer}#${claims.sub}`
              : null, // never namespace a missing or empty sub
        },
});
```

`readersFor` runs for every entry, ID-JAG ones included, so return `undefined` where the default is the right answer.

An entry that carries `readSubjectHandle` or `readScope` itself is refused when it is registered, rather than having the reader silently ignored.

### The ID-JAG profile (#526)

An entry with `profile: "id-jag"` accepts the [Identity Assertion JWT Authorization Grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/) — what an enterprise IdP mints for a client so that this server, as the resource's authorization server, can issue it an access token (the MCP "Enterprise Managed Authorization" flow, Cross-App Access). The client sends it as a plain jwt-bearer request, **with client authentication**:

```ts
const assertionVerifier = createRegistryAssertionVerifier({
  registry: createMemoryAssertionIssuerRegistry([
    {
      issuer: "https://idp.example",
      keys: { type: "jwks_uri", uri: "https://idp.example/.well-known/jwks.json" },
      algorithms: ["RS256"],
      profile: "id-jag",
      allowedClients: ["mcp-client"],
      allowedScopes: ["read", "write"],
      allowedAudiences: ["https://mcp.example"],
    },
  ]),
  audience: "https://auth.example",
  issuerIdentifier: "https://auth.example", // the only aud an ID-JAG may name
  replaySeenSet,                             // each jti is accepted once
  logger,                                    // says why an assertion was refused
});
```

On top of the registry's checks, an ID-JAG must carry `typ: oauth-id-jag+jwt`, `aud` exactly this server's issuer identifier (the token endpoint URL is not an alias), a `client_id` naming the authenticated client (an unauthenticated presenter is refused), and `jti`, `iat`, `sub` — `iat` no more than an hour old and `exp` no more than an hour ahead, as for `private_key_jwt` (core's `MAX_ASSERTION_LIFETIME_SECONDS`), each allowing the entry's clock tolerance (`clockToleranceSeconds`, default 60) for an IdP whose clock runs ahead. The tolerance must be a finite number of seconds from 0 to 300 (core's `MAX_ASSERTION_CLOCK_TOLERANCE_SECONDS`). `NaN`, `Infinity` or a string would switch the time checks off, so such an entry is refused when it is added, and again when a store-backed registry hands it to the verifier; each `jti` is accepted once for the assertion's lifetime, so a longer-lived ID-JAG is `invalid_grant`, refused before its `jti` is recorded, and so is a `jti` longer than 256 characters (`MAX_JTI_LENGTH`). The grant's answer is the same for every refusal; pass the verifier a `logger` and it says why at warn, as `jwt_bearer_assertion_refused` with the entry's `issuer` and a `reason` — `lifetime` (with `lifetimeSeconds` and `maxLifetimeSeconds`) or `numeric_date` (with the `claim`) — or, without an `issuer`, `malformed_issuer`. `scope` and `resource` travel as claims: the scope ceiling is the claim ∩ `allowedScopes`, the audience ceiling is `resource` ∩ `allowedAudiences` (a resource the entry does not admit is refused), and the grant then bounds both by the client's registration. The handle handed to the Store is `<iss>#<sub>` (or `<iss>#<tenant>#<sub>`) — `sub` is unique only within its issuer — and an identity the Store has not linked is refused there. No refresh token is issued: the assertion is the refresh mechanism, and the access token lives no longer than it (below).

### The issued token never outlives the assertion

The access token's lifetime is `min(oauth.accessToken.defaultExpiresIn, exp − now)`: `exp` is the verified assertion's, reported by the verifier as `expiresAt` (epoch seconds), and the remainder is rounded down to whole seconds at the moment the token is minted. `expires_in` in the response is that minted lifetime. This is the rule token exchange applies to its subject token ([security note 16](../oauth-token-exchange/README.md#security-notes)), and it holds for every jwt-bearer request, RFC 7523 and ID-JAG alike:

- **A short-lived assertion yields a short-lived access token.** An ID-JAG's `iat` may be at most an hour old and IdPs commonly give it minutes of lifetime; the token exchanged from it lives no longer. No refresh token is issued, so when the token expires the client **re-exchanges a fresh assertion**. It cannot present the same ID-JAG again — each `jti` is accepted once.
- **An assertion with no whole second left is refused** with `invalid_grant` / `assertion did not verify` — the answer every failed verification gets, so it tells a caller nothing about the handle behind it — and logged for the operator as `jwt_bearer_assertion_expired`. That covers an assertion past its `exp` that the entry's `clockToleranceSeconds` (default 60) still let verify: the tolerance absorbs clock skew for verification, but leaves no lifetime for a token to inherit. A steady rate of that line from one issuer is a clock out of step with this server's, or clients presenting assertions at the last moment.
- **A custom `AssertionVerifier` reports `expiresAt`** whenever its credential expires. The field is optional, but omitting it asserts a credential with **no expiry**, and the configured lifetime then stands uncapped. Present, it must be a finite number: a numeric string, `null`, `NaN` or `Infinity` is refused as `invalid_grant`, never read as an expiry or as none. `createRegistryAssertionVerifier` and `createJwtAssertionVerifier` always report it, from the `exp` they require.

### A subject revocation reaches assertions issued before it

With `subjectRevocation` wired, every assertion must carry `iat` and `exp`, whether or not a boundary is in force and whichever verifier answered. Before the Store is asked, the grant refuses an assertion in any of these cases:

- its verifier reports no usable `issuedAt` (`jwt_bearer_assertion_issued_at_unusable`);
- its `issuedAt` is ahead of this server's clock by more than core's `MAX_ASSERTION_CLOCK_TOLERANCE_SECONDS` (300 s; `jwt_bearer_assertion_issued_at_ahead`);
- it reports no usable `expiresAt` (`jwt_bearer_assertion_expiry_unusable`);
- its `expiresAt` is not after `issuedAt` (`jwt_bearer_assertion_lifetime_empty`);
- its `expiresAt − issuedAt` is over a day (core's `ASSERTION_MAX_LIFETIME_LIMIT_SECONDS`; `jwt_bearer_assertion_lifetime_exceeded`).

A subject's boundary is kept a day, so a longer-lived assertion would outlive the boundary that covers it.

The grant then reads the resolved subject's revocation boundary as its last read before signing, through core's `subjectBoundaryCovers`. It compares the assertion's `issuedAt`, taken as no later than the grant's own issuance second, using the rule and allowance `verifyJwt` applies to a token's `iat`. One at or before the boundary is refused (`jwt_bearer_assertion_revoked`). Every refusal above is the uniform `invalid_grant` / `assertion did not verify`.

A boundary that cannot be read is `503 temporarily_unavailable` (`jwt_bearer_revocation_boundary_unavailable`). After the read, an assertion that expired during it is `invalid_grant` (`jwt_bearer_assertion_expired`). A token whose own lifetime the read used up is not signed; it is `503 temporarily_unavailable` (`jwt_bearer_issuance_outlasted_token_lifetime`), and a retry succeeds.

The guarantee holds up to the issuer's clock skew, which the verifier's clock tolerance bounds: at most 300 s for the bundled verifiers. Without `subjectRevocation`, nothing changes.

- **A custom `AssertionVerifier` reports `issuedAt` and `expiresAt`, and refuses an `iat` ahead of its clock by more than its clock tolerance.** With `subjectRevocation` wired, the grant refuses every assertion its verifier reports without either, or that lives longer than a day. `createRegistryAssertionVerifier` and `createJwtAssertionVerifier` report `issuedAt` whenever the assertion carries `iat`, and refuse one ahead of their clock beyond the entry's tolerance.
- A subject revocation does not revoke the upstream issuer's credential. An assertion that issuer signs after the revocation is fresh authentication, and it is accepted.

## Tests

The invariants above are pinned where they are implemented; a starting set:

- module wiring and what each module declares — [`module.test.mts`](./src/__tests__/module.test.mts), [`oauthAuthorization.test.mts`](./src/__tests__/oauthAuthorization.test.mts), [`oauthSession.test.mts`](./src/__tests__/oauthSession.test.mts), [`subjectRevocationService.module.test.mts`](./src/logout/__tests__/subjectRevocationService.module.test.mts), and the requirements resolver every hand-built consumer requires — [`admissionWiring.test.mts`](./src/__tests__/admissionWiring.test.mts);
- each consumer's session read through admission, the changes it brought, and the step-up trip — [`authorize.admission.test.mts`](./src/__tests__/authorize.admission.test.mts), [`consent.admission.test.mts`](./src/__tests__/consent.admission.test.mts), [`sessionGrant.admission.test.mts`](./src/__tests__/sessionGrant.admission.test.mts), [`authorizationGrant.admission.test.mts`](./src/__tests__/authorizationGrant.admission.test.mts), [`refreshToken.admission.test.mts`](./src/__tests__/refreshToken.admission.test.mts), and the ask record — [`reauthAsk.test.mts`](./src/__tests__/reauthAsk.test.mts);
- the discovery gates — [`discovery-contribution.test.mts`](./src/__tests__/discovery-contribution.test.mts);
- the logout cascade order and failure handling — [`cascadeLogout.test.mts`](./src/logout/__tests__/cascadeLogout.test.mts), and the endpoints — [`logout.test.mts`](./src/__tests__/logout.test.mts);
- introspection's audience pin, session liveness and outage answers — [`introspect.audience.test.mts`](./src/__tests__/introspect.audience.test.mts), [`introspect.sessionLiveness.test.mts`](./src/__tests__/introspect.sessionLiveness.test.mts), [`introspect.revocationOutage.test.mts`](./src/__tests__/introspect.revocationOutage.test.mts), and the members it answers, `acr`, `amr` and `auth_time` among them — [`introspectCascade.test.mts`](./src/__tests__/introspectCascade.test.mts);
- the authentication claims each grant stamps and a refresh carries, `auth_time` included — [`authorization.test.mts`](./src/__tests__/authorization.test.mts), [`refreshToken.test.mts`](./src/__tests__/refreshToken.test.mts), [`sessionGrant.admission.test.mts`](./src/__tests__/sessionGrant.admission.test.mts);
- client authentication — [`clientAuth.test.mts`](./src/middleware/__tests__/clientAuth.test.mts), [`clientAssertion.test.mts`](./src/middleware/__tests__/clientAssertion.test.mts);
- the federation token route — [`federationToken.test.mts`](./src/__tests__/federationToken.test.mts).

## See also

- [`@o3co/auth-provider-core`](../core/README.md) — the ports, records and token primitives this package builds on (`Module`, `GrantHandlerResolver`, `ClientRepository`, `CodeRepository`, `KeyStore`)
- [`@o3co/auth-provider-session`](../session/README.md) — login, the browser session and the federation login routes
- [`@o3co/auth-provider-oauth-token-exchange`](../oauth-token-exchange/README.md), [`@o3co/auth-provider-device-grant`](../device-grant/README.md), [`@o3co/auth-provider-webauthn`](../webauthn/README.md) — grants contributed to `/oauth/token`
- [`@o3co/auth-provider-federation-grants`](../federation-grants/README.md) — offline delegation of upstream tokens
