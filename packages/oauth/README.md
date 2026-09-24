# @o3co/auth-provider-oauth

Last updated: 2026-09-25

The OAuth 2.0 / OpenID Connect authorization-server endpoints of [auth.provider](../../README.md): the HTTP surface under `/oauth`, the built-in grant types, client authentication, and the logout cascade.

## Responsibility

**Role.** The authorization server's HTTP face. [`@o3co/auth-provider-core`](../core/README.md) defines the ports, records, token primitives and the boot planner; this package turns them into the endpoints a client talks to — authorize, token, introspect, userinfo, revoke, consent, logout, federation token — and contributes this server's part of the discovery document. It sits beside [`@o3co/auth-provider-session`](../session/README.md) (login and the browser session) on top of core; neither imports the other.

**Owns:**

- the routes in the [Endpoints](#endpoints) table — other packages, such as the device grant and federation grants, mount routes under `/oauth` too — the order of the checks each one runs, and their wire answers;
- client authentication at every client-authenticated endpoint — `client_secret_basic`, `client_secret_post`, `private_key_jwt` and public clients where a route admits them — as one middleware, `createClientAuthMiddleware`, which [`@o3co/auth-provider-device-grant`](../device-grant/README.md) and [`@o3co/auth-provider-federation-grants`](../federation-grants/README.md) reuse;
- the built-in grants: `authorization_code`, `refresh_token`, `client_credentials`, `session` and RFC 7523 jwt-bearer;
- the logout cascade (`cascadeLogout`), OIDC back- and front-channel logout, and the module that wires core's subject revocation service over that cascade;
- resolving Client ID Metadata Documents: the fetch, its SSRF guard and its cache;
- the discovery slice this server's endpoints and capabilities contribute.

**Does not own:**

- the ports and records (`ClientRepository`, `CodeRepository`, `KeyStore`, `UserSessionStore`, the `Client` record …), token minting and verification (`generateToken`, `verifyJwt`), the grant contract and the registry `/oauth/token` dispatches against, the discovery document itself and `jwks_uri` — core;
- login, the browser session and the federation login routes — `@o3co/auth-provider-session` (`POST /session/logout` is there too, and does not run this package's cascade: see [Logout](#logout));
- the other grant types — token exchange, device code, WebAuthn — which their own packages contribute to the same `/oauth/token`;
- offline delegation of upstream tokens (`/oauth/federation-grants`) — `@o3co/auth-provider-federation-grants`;
- proving a DPoP key or a client certificate — `@o3co/auth-provider-dpop` / `@o3co/auth-provider-mtls`. This package reads the binding they establish and stamps it as `cnf`;
- store adapters (Redis and others) and the user Store.

**Why a separate package.** Core holds the contracts every package shares, and the adapter and grant packages — Redis, token exchange, WebAuthn — depend on core and not on this package; keeping the HTTP surface here, with Express and express-session as its peers, means none of them pulls it in. Login and the browser session are a package of their own because an API-only deployment issues tokens without them; this package is the one every token-issuing deployment installs. The two are siblings over core and neither imports the other, which is why `POST /session/logout` cannot run this package's cascade.

**Why four modules.** The package installs as four separate modules, each with only the requirements its own code reads, because they are needed in different compositions:

| Module | What it contributes | Why it is separate |
|---|---|---|
| [`oauthModule`](./src/module.mts) | The `/oauth` routes and the discovery slice. It registers no grant: `/oauth/token` dispatches against core's `grantHandlerResolver`, which every installed module's `grants` contribution fills. | The token endpoint is the same whichever grants are installed, and it runs with no session store at all. |
| [`oauthAuthorizationModule`](./src/oauthAuthorization.mts) | `authorization_code`, `refresh_token`, `client_credentials` and jwt-bearer, each only when enabled. | A deployment picks its grant set; the grants can also be installed without these routes, which is why this module declares its own `subjectRevocation` absence policy. |
| [`oauthSessionModule`](./src/oauthSession.mts) | The `session` grant, only when enabled. | It serves another topology — first-party / BFF, minting from the browser session — is enabled independently of the code grants, and declares only `config` and `keyStore` (and `userSessionStore`, optionally). |
| [`subjectRevocationServiceModule`](./src/logout/subjectRevocationService.mts) | Core's `subjectRevocationService` component, built over `cascadeLogout`. | It requires the six session-cascade stores, which `oauthModule`'s routes do not; with `federationGrants.enabled = true` it also requires a `federationGrantStore` and a `subjectRevocation` that carries the grants boundary, and refuses to boot without them. It lives here rather than in core because core cannot import `cascadeLogout` without inverting the package dependency. |

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
  oauthAuthorizationModule,
  oauthModule,
  oauthSessionModule,
} from "@o3co/auth-provider-oauth";
import { sessionStoreModuleFor } from "@o3co/auth-provider-session";

const handle = await createApp({
  modules: [
    // Mounts express-session. It has no ordering edge of its own, so it must be
    // listed ahead of every module that reads the browser session.
    sessionStoreModuleFor(config),
    oauthModule({ config }),
    oauthSessionModule({ config }),
    oauthAuthorizationModule({ config }),
    jwksModule, // core's: `jwks_uri` is not this package's
    // …the modules that provide clientRepository, codeRepository, keyStore and the
    // optional slots below; add subjectRevocationServiceModule when a Store calls
    // `handle.components.subjectRevocationService`.
  ],
  bootstrapComponents: { config, pathResolver: import.meta.resolve },
});

const server = express();
server.use(handle.router);
server.listen(config.http.port);
// on shutdown
await handle.dispose();
```

The standalone template's [`buildModules.mts`](../../templates/standalone/src/buildModules.mts) is a complete composition root.

What each module requires and reads is declared in its manifest (linked in the table above). What a composition has to decide at boot:

- `oauthModule` requires `config`, `clientRepository`, `codeRepository` and `keyStore`, and a non-empty `endpoints.login.url` — `/authorize` sends an unauthenticated browser there, so boot refuses without it.
- `subjectRevocation`, `auditSink` and `accessTokenDenylist` are optional to wire and not optional to decide: an unfilled slot must be declared absent — `oauth.revocation.subject = "unsupported"`, `audit.sink.type = "none"`, `oauth.revocation.accessToken = "unsupported"` — or boot refuses.
- An `oauth.jwt.issuer` that is not a canonical issuer URL fails router construction: `iss` is a property of the deployment, never read from a request.
- Each module under `/oauth` parses its own body, and the order they are listed in does not matter. `oauthModule`'s router parses JSON and form bodies (Express's default limits) for exactly the routes in the [Endpoints](#endpoints) table that this composition actually mounts, each at its own path and not at a longer one beneath it — `oauthRoutePaths` in [`routes.mts`](src/routes.mts): the logout, federation-token and consent routes only when their stores are wired; a request to any other path under `/oauth` — the device grant's, federation grants', WebAuthn's, a deployment's own, including one at `/oauth/logout` or `/oauth/consent` when oauth does not mount those, and one beneath an oauth route such as `/oauth/token/custom` — reaches its route with the body unread, and the `/oauth/revoke` throttle does not count it. A module that mounts a route there and reads `req.body` mounts a parser of its own.

## Endpoints

All mounted under `/oauth` by `oauthModule`.

| Endpoint | Mounted | Described in |
|---|---|---|
| `POST /oauth/token` | always; dispatches by `grant_type` | [Grants](#grants) |
| `GET`, `POST /oauth/authorize` | always | [The OIDC surface](#the-oidc-surface-stated-284) |
| `POST /oauth/introspect` | always | [Introspection](#introspection-which-tokens-a-caller-may-ask-about) |
| `GET`, `POST /oauth/userinfo` | always | [Userinfo](#userinfo) |
| `POST /oauth/revoke` | always; what it can revoke depends on the wiring | [Revocation](#revocation) |
| `GET`, `POST /oauth/consent` | when `consentStore` and `pendingConsentStore` are both wired | [Consent](#consent-for-third-party-clients-527) |
| `GET`, `POST /oauth/logout` | when the six session-cascade slots are all wired | [Logout](#logout) |
| `POST /oauth/federation/:name/logout` | the same six | [Logout](#logout) |
| `POST /oauth/federation/:name/token` | the same six | [Federation token endpoint](#federation-token-endpoint) |

The six slots are `userSessionStore`, `sessionRPRegistry`, `sessionFamilyIndex`, `sessionFederationIndex`, `federationTokenStore` and `refreshTokenFamilyRevocation`. The same check decides whether discovery advertises `end_session_endpoint` and the logout capabilities, so a document never names an endpoint that is not mounted.

**Error descriptions and codes.** RFC 6749 allows error text only printable ASCII without `"` and `\` (§5.2, §4.1.2.1). This package holds to that set every `error_description` that `/oauth/token` writes, whichever grant produced it, every one that `/oauth/authorize` puts in an error redirect, and every one that client authentication writes, on `/oauth/token`, `/oauth/introspect` and `/oauth/revoke`, whose errors use the same format (RFC 7662 §2.3, RFC 7009 §2.2.1). Any other character is replaced with `?` (core's `sanitizeErrorText`, [`errors/envelope.mts`](../core/src/errors/envelope.mts)), including in a value the client sent and a description quotes, such as a grant type, scope, audience, token type or `response_type`, and in a configured value such as a client's `tokenEndpointAuthMethod` or a token-binding kind. Descriptions quote a value with `'`. The `error` code itself must be `1*NQSCHAR`, the same characters and not empty. A grant policy's deny carries the policy's own code, so a code outside the set is answered `invalid_request` on `/oauth/token` and `access_denied` on an `/oauth/authorize` redirect, and logged sanitised (`token_error_code_malformed`, `authorize_policy_deny_error_malformed`). A description that is empty or not a string — a JavaScript policy can return anything — is not sent: `/oauth/token` omits it, and an `/oauth/authorize` redirect carries `policy denied`. The client's `state` is returned exactly as sent. The other routes hold to the same set: `/oauth/federation/:name/token` and `/oauth/federation/:name/logout` quote the federation name from the path with `'` and send any other character in it as `?` (`federation '<name>' is not linked to this session`), and `/oauth/consent` answers `decision must be 'accept' or 'deny'`. Core middleware that also answers on these endpoints — the token-binding middleware, the rate limiter and the protected-resource binding — writes through core's `errorEnvelope`, which applies the rule itself (core's [README](../core/README.md#error-text-rfc-6749)).

**Space-delimited values.** A `scope`, `prompt` or `acr_values` a client sends is read by RFC 6749 §3.3's grammar, strictly (core's `readSpaceDelimitedParameter`): the space is the only delimiter, and an entry that is not a scope-token — a tab, a newline, a quote, a backslash, anything outside printable ASCII — makes the whole value malformed. A malformed `scope` is `invalid_scope` with `scope is not a space-delimited list of scope-tokens`, on `/oauth/token` for every grant here and at `/oauth/authorize` — never narrowed, and never checked against an allowlist as if it named a scope. Spaces alone are an omitted scope, as an empty value is; a tab alone is malformed. A malformed `prompt` or `acr_values` is `invalid_request`. A repeated `scope` — or any present value that is not a string — is `invalid_request`, while a JSON body's `"scope": null` is an omitted scope, as `scope=` is in a form body (RFC 6749 §3.2). The `scope` claim of this package's own access and refresh tokens (at `/oauth/userinfo`, on refresh) is read so it never widens (`readIssuedScope`): split on the space alone, and an entry that is not a scope-token is dropped — a token minted before requests were read strictly can carry `openid<TAB>email` as one entry, which named no scope and releases no claim now. A refresh carries the token's scope on in canonical form. What a third party wrote — a client metadata document's `scope`, an upstream's answer — is read tolerantly (`parseScopeTokens`): split on any whitespace, keeping the scope-tokens.

`/token`, `/introspect`, `/authorize` and `/revoke` are throttled by the composition's `rateLimiter` when one is wired, ahead of client authentication, under the product's `rateLimit.failMode`; without one they are not throttled.

The router refuses to be built — which through `createApp` is a boot failure — when `consentStore` is wired without `pendingConsentStore` or the reverse, and when `oauth.revocation.accessToken = "denylist"` is declared with no `accessTokenDenylist`.

**Discovery.** `oauthModule` contributes its endpoints and metadata to core's `/.well-known/openid-configuration`, which core serves only when an issuer is configured. Each capability is advertised only where it can be honoured: `revocation_endpoint` when the endpoint can revoke something, `private_key_jwt` when a `replaySeenSet` is wired, `client_id_metadata_document_supported` when the feature is on and a consent store is wired, the logout fields under the six-slot check above. `grant_types_supported` is read off the resolver `/oauth/token` dispatches against; `code_challenge_methods_supported` is `["S256"]`. The rules are stated where they are computed, in [`module.mts`](./src/module.mts), and pinned by [`discovery-contribution.test.mts`](./src/__tests__/discovery-contribution.test.mts).

## Public API

Everything below is exported from [`src/index.mts`](./src/index.mts); the linked file holds each definition and its doc comment.

**Modules** — see [Why four modules](#responsibility).

- `oauthModule({ config })` — [`module.mts`](./src/module.mts)
- `oauthAuthorizationModule({ config })` — [`oauthAuthorization.mts`](./src/oauthAuthorization.mts)
- `oauthSessionModule({ config })` — [`oauthSession.mts`](./src/oauthSession.mts)
- `subjectRevocationServiceModule` (a module value, not a factory) — [`logout/subjectRevocationService.mts`](./src/logout/subjectRevocationService.mts)

**Router.** `createOAuthRouter(express, options)` — [`routes.mts`](./src/routes.mts) — builds the `/oauth` router from explicit options; it is what `oauthModule` calls with its resolved deps, for a composition root that mounts the router itself. It creates no grant registry: `registry` is whatever object with a `get(grantType)` the caller passes, and the same value is returned. A caller that needs the registered grant types reads core's `grantHandlerResolver` instead.

**Client authentication.**

- `createClientAuthMiddleware(clientRepository, options)` and `ClientAuthMiddlewareOptions` — [`middleware/clientAuth.mts`](./src/middleware/clientAuth.mts). Authenticates the client by `client_secret_basic`, `client_secret_post` or `private_key_jwt` (one method per request), admits public clients only when `allowPublicClients` is set, and puts the authenticated client on `req.oauthClient` (typed by a global Express augmentation). Its refusals are RFC 6749 §5.2 `{ error, error_description }`. A client repository that cannot answer is not a failed authentication: the request is refused `503 temporarily_unavailable` ("client repository unavailable") with no challenge, and logged at error level as `client_repository_unavailable`; an unknown client or a wrong secret is still `401 invalid_client`. A `client_id` that cannot name a client — a control character, or longer than 256 characters (core's `isWellFormedClientId`, `MAX_CLIENT_ID_LENGTH`) — is refused like an unknown one before the repository is asked, so a repository that throws on such input cannot be made to answer `503`. `/authorize` screens its `client_id` the same way, and answers a repository that cannot answer `503 temporarily_unavailable` as JSON, logged the same way with `site: "authorize"`.
- `createClientAssertionVerifier`, `CLIENT_ASSERTION_ALGORITHMS`, `JWT_BEARER_CLIENT_ASSERTION_TYPE`, `MAX_CLIENT_ASSERTION_LIFETIME_SECONDS` and the types `ClientAssertionVerifier`, `ClientAssertionVerifierOptions`, `ClientAssertionOutcome` — [`middleware/clientAssertion.mts`](./src/middleware/clientAssertion.mts). The `private_key_jwt` verifier the middleware uses; see [`private_key_jwt`](#client-authentication-private_key_jwt-rfc-7523-22).

**Client ID Metadata Documents.** `createClientIdMetadataDocumentResolver`, `withClientIdMetadataDocuments` (a `ClientRepository` that answers registered clients first and documents second), `isClientIdMetadataDocumentUrl`, `isClientIdMetadataDocumentClient`, and the types `ClientIdMetadataDocumentOptions`, `ClientIdMetadataDocumentResolver` — [`clients/clientIdMetadataDocument.mts`](./src/clients/clientIdMetadataDocument.mts). See [Client ID Metadata Documents](#client-id-metadata-documents-529).

**Logout primitives**, for a composition that assembles its own logout:

- `cascadeLogout`, `CascadeLogoutOptions`, `CascadeLogoutResult` — [`logout/cascadeLogout.mts`](./src/logout/cascadeLogout.mts)
- `broadcastBackchannelLogout`, `BroadcastBackchannelLogoutOptions`, `BroadcastRP` — [`logout/broadcastBackchannel.mts`](./src/logout/broadcastBackchannel.mts)
- `renderFrontchannelLogoutHtml`, `RenderFrontchannelLogoutHtmlOptions`, `FrontchannelRP` — [`logout/renderFrontchannel.mts`](./src/logout/renderFrontchannel.mts)

**Introspection types.** `IntrospectResponse` — [`types/introspect.mts`](./src/types/introspect.mts), the RFC 7662 response shape a resource server or proxy can type against — and `extractConfirmation` / `isCompoundConfirmation`, core's `cnf` helpers re-exported from there.

## Source layout

Each directory under `src/` has one kind of responsibility; what a single file does is in its header comment.

| Directory | Responsibility |
|---|---|
| `src/` (root) | Assembly: `oauthModule`, `oauthAuthorizationModule` and `oauthSessionModule` (the fourth, `subjectRevocationServiceModule`, is in `logout/` beside the cascade it wires), `createOAuthRouter` (which composes every route below), option resolution, a re-export of core's access-token header parser, and the one answer every route gives a token it could not verify because a dependency was down (`verificationUnavailable.mts`). |
| [`routes/`](./src/routes) | One router or handler per endpoint family — authorize, consent, logout, federation token, revoke, userinfo. Routes may use `grants/`, `logout/`, `middleware/` and `clients/`; none of those imports a route. `routes/authorize.mts` also reads one grant helper, the per-client PKCE method rules, because `/authorize` validates PKCE the way `/token` does. The RFC 8707 `resource` rules both read are core's ([`grants/resourceIndicator.mts`](../core/src/grants/resourceIndicator.mts)), shared with the WebAuthn grant. |
| [`grants/`](./src/grants) | The grant handlers: pure request-to-token decisions over core's grant contract, with no HTTP. |
| [`middleware/`](./src/middleware) | Client authentication, reused by sibling packages. |
| [`logout/`](./src/logout) | The ordered session cascade (`cascadeLogout`), the outbound back-channel POSTs to relying parties, the front-channel page, and the module that wires the subject revocation service. |
| [`clients/`](./src/clients) | Client ID Metadata Document resolution: fetching a client's registration from the URL it names, behind the SSRF guard, and caching it. |
| [`types/`](./src/types) | The introspection response contract. |

## Grants

### Which grants are on

Every built-in grant is off until `oauth.grants.<name>.enabled` is `true` — the boolean, or the string `"true"` an environment substitution produces; anything else is off:

| Grant | Key | Environment |
|---|---|---|
| `authorization_code` | `oauth.grants.authorization_code.enabled` | `OAUTH_GRANTS_AUTHORIZATION_CODE_ENABLED` |
| `refresh_token` | `oauth.grants.refresh_token.enabled` | `OAUTH_GRANTS_REFRESH_TOKEN_ENABLED` |
| `client_credentials` | `oauth.grants.client_credentials.enabled` | `OAUTH_GRANTS_CLIENT_CREDENTIALS_ENABLED` |
| `session` | `oauth.grants.session.enabled` | `OAUTH_GRANTS_SESSION_ENABLED` |
| jwt-bearer | `oauth.grants."urn:ietf:params:oauth:grant-type:jwt-bearer".enabled` | see core's `reference.conf` |

A grant that is off is not registered: `/oauth/token` answers `unsupported_grant_type` for it and `grant_types_supported` does not list it.

A registered grant must also be allowed for the client, by `allowedGrantTypes` on its registration — at `/oauth/token`, where a refusal is `400 unauthorized_client`, and at `/authorize` for `authorization_code`, where the `unauthorized_client` error is redirected to the client's `redirect_uri`. A list admits exactly the grant types it names, so an empty list admits none. An absent list admits every grant except those that deny by absence — `client_credentials`, jwt-bearer, token exchange, the device grant and the WebAuthn grant — which the list must name. `oauth.requireGrantTypeAllowlist = true` (`OAUTH_REQUIRE_GRANT_TYPE_ALLOWLIST`, off by default) makes an absent list deny every grant. The base rule is core's `isGrantTypeAllowed` ([`repositories/allowedGrantTypes.mts`](../core/src/repositories/allowedGrantTypes.mts)); the grants that deny by absence declare `requiresExplicitGrantAllowlist`, which the `/oauth/token` dispatch enforces ([`routes.mts`](src/routes.mts)).

Enabling jwt-bearer without a `userRepository` or an `assertionVerifier` fails at boot — see [jwt-bearer](#jwt-bearer-which-issuers-are-trusted-525).

**Token lifetimes are read when a grant is built.** Every grant here reads `oauth.accessToken` through core's `resolveAccessTokenLifetime`, and `authorization_code` and `refresh_token` read `oauth.refreshToken.expiresIn` through `resolveRefreshTokenLifetime`, once, in its factory. A configuration those resolvers refuse — possible only for one built by hand, since the schema refuses the same values at boot — makes the factory throw a `RangeError` naming the key, so the grant is never registered. A request never meets it: no authorization code, ID-JAG `jti` or refresh token is spent on a configuration that cannot mint the answer. The other side of reading them once: a grant mints the lifetimes it was built with, so changing `oauth.accessToken.*` or `oauth.refreshToken.expiresIn` on the configuration object after boot has no effect until the grant is built again — restart, as for any other configuration change.

### `authorization_code`: the session, `sid`, `family_id` and the id_token

The access and refresh tokens the `authorization_code` and `refresh_token` grants mint carry `family_id` — the refresh-token family, which is what [introspection](#introspection-which-tokens-a-caller-may-ask-about), [userinfo](#userinfo), [logout](#logout) and the federation token route check for revocation — and `sid`, the session id, when the code record has one. The login path writes `sid` onto the code at `/authorize` (local login or the federation callback).

**With a `userSessionStore` wired, the code must name a live session.** The session is where the tokens' subject comes from, and the grant links the new family and the client to it so that [logout](#logout) can find them:

- a code with no `sid` is `400 invalid_grant` — the login wiring did not record one;
- a `sid` the store does not resolve, or a session with no subject, is `400 invalid_grant` / `session_invalid`; a session that ends while the tokens are being issued is `400 invalid_grant` / `session_invalidated`;
- a store that cannot answer — the session read or the linking writes — is `503 temporarily_unavailable`.

Without a `userSessionStore`, the subject is the user of the browser session that accompanies the token request, and no id_token is issued.

**The id_token** is issued when `openid` is among the granted scopes, a `userSessionStore` is wired and `oauth.jwt.issuer` is set; otherwise it is omitted and the access and refresh tokens are returned as usual. It carries `iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `auth_time`, `sid` and `azp`; `nonce` when the authorization request had one (OIDC Core §3.1.3.7); `amr` / `acr` as described in [Step-up](#step-up-and-re-authentication-481); and the user's claims filtered by scope ([the same table userinfo uses](#userinfo)).

### `refresh_token`

- **The session must still exist.** When a `userSessionStore` is wired and the refresh token carries `sid`, the grant reads the session: gone is `400 invalid_grant`, a store failure `503 temporarily_unavailable`.
- **The rotation is reserved before anything is signed.** The new refresh token's `jti` and the instant its lifetime is measured from are chosen first, committed to the family store by `RefreshTokenFamilyRotation.rotate`, and signed only once that commit holds. A lost race — a replay, a revoked family, an unknown family under `reject` — therefore returns having produced no signature, which matters under a KMS-backed `SigningKeyProvider` where each signature is a billable remote call. The issued token carries exactly the `jti` that was reserved and an `exp` no later than the ceiling the store committed — `RefreshTokenFamilyRotationOutcome.cappedExpiresAtMs`, less a one-second margin for the forward drift its contract documents, floored to the second — so a refresh token never outlives the family record that catches its replay. A ceiling that leaves no lifetime is `400 invalid_grant` ("refresh token family has reached its lifetime"), not a `200` carrying an already-expired refresh token.
- **What that ordering costs.** Once `rotate` commits, the presented token is spent. A signer that fails after it — a KMS outage — leaves a rotation nobody holds a token for: the grant answers `503 temporarily_unavailable` and logs `refresh_token_rotation_orphaned` with the family id, the spent `jti` and the reserved one — only when the store actually committed the rotation, so a composition with no rotation wired, or an unknown family accepted under `unknownFamilyPolicy`, keeps the ordinary signer behaviour. The client's retry presents the old token, which now reads as a replay, so the family is revoked and the user re-authenticates.
- **A replay revokes the family** (RFC 6819 §5.2.2), which is why the module reads `refreshTokenFamilyRevocation` beside the rotation; and a refresh token whose `iat` is at or before the subject's revocation watermark is `invalid_grant`.
- **A token the grant could not verify because a dependency was down is `503 temporarily_unavailable`, not `invalid_grant`** — the keystore ("verification key unavailable") or the subject watermark ("revocation store unavailable"), logged as `token_verification_unavailable` with `site: "refresh_token"`. RFC 6749 §5.2's `invalid_grant` makes a client discard its refresh token, so answering an outage with it would log out everyone who refreshed during it. A kid the keystore does not hold is still `invalid_grant`. A family or session store that fails is `503` too, logged as `refresh_token_store_unavailable` with the store and the step (`rotate`, or the `revoke` a replay needs).

### `session`

Mints an access token for the user of an already-authenticated browser session (first-party / BFF topologies). The caller authenticates as a client at `/oauth/token`; the client's `allowedScopes` are the ceiling. `aud` is the client's first `allowedAudiences` entry, or its client id when it has none, and `azp` is the client id. No refresh token is issued, so the token never carries `family_id`; it carries `sid` when the browser session has one.

When a `userSessionStore` is wired, every session grant requires a non-empty `sid` and a live `UserSession` before signing a token: a missing or revoked session is `400 invalid_grant`, a store failure `503 temporarily_unavailable`, and the tracked session must have a non-empty subject matching the browser's user — a malformed or inconsistent identity is refused before any token is signed. Without a `userSessionStore` the grant relies on the browser session alone. Validated DPoP / mTLS bindings are kept in the access token's `cnf`: DPoP answers `token_type=DPoP`, mTLS keeps `Bearer`, and the resource server must verify the corresponding proof.

### `client_credentials`

RFC 6749 §4.4 machine-to-machine: public clients are refused, the token's `sub` is the client id, and no refresh token is issued. The client's `allowedGrantTypes` must name the grant — an absent list denies it rather than admitting it by omission, as it does for jwt-bearer, token exchange, the device grant and the WebAuthn grant.

## The OIDC surface, stated (#284)

This is an OAuth 2.0 authorization server with the OIDC pieces a **first-party** deployment needs. Where it stops is deliberate, and saying so is part of the contract — an RP that discovers what is here should not have to find the edges by hitting them.

**`/oauth/authorize` accepts GET and POST** (OIDC Core §3.1.2.1). Both run the identical sequence of checks: the handler reads its parameters through one accessor, so a check cannot be mounted on one method and forgotten on the other.

**`redirect_uri` is matched against `client.allowedRedirectUris` by exact string equality, with one carve-out (#483).** When **both** the registered entry and the presented value are `http:` on a loopback **IP literal** (`127.0.0.0/8`, `[::1]`), the port is dropped from both before comparing — scheme, host, path and query are still compared exactly. The equality runs on the two **original strings** with the port removed, not on normalized URLs, so dot segments (`/a/../cb`), percent-encoding variants, a `\` separator, a differing trailing slash and scheme case never widen it. A native app receiving the response on a loopback interface binds an ephemeral port the OS assigns at run time, so a registration cannot name it (RFC 8252 §7.3): `http://127.0.0.1/cb` admits `http://127.0.0.1:49152/cb`.

- `http://localhost/cb` gets **no** carve-out — a loopback *name* moves the guarantee into the host's name resolution, and RFC 8252 §8.3 discourages it. Register the IP literal.
- `https://` gets no carve-out either, loopback host or not.
- The **presented** URI is where the response goes, and it is what gets bound to the authorization code. The token endpoint's `redirect_uri` check (RFC 6749 §4.1.3) compares against that record with plain equality — port included — so a listener on a different port cannot redeem another one's code.
- The comparison lives in `matchesRegisteredRedirectUri` (`@o3co/auth-provider-core`), exported so a custom authorization endpoint matches the way this one does.

**PKCE is mandatory, and `S256` is the method.** `plain` is admitted only for a client whose registration carries `allowPlainPkce: true`, which is why discovery lists `S256` alone.

**`prompt=none` is supported.** No session answers `login_required` at the client's `redirect_uri` — which is the point, since a hidden renewal iframe cannot act on a login page. A session proceeds silently. A `prompt` that names `none` but is malformed (`none<TAB>`) or combines it with another value still comes from a silent context, so it too is answered at the `redirect_uri` — `invalid_request` — never with the login page.

**`prompt=login` re-authenticates** — see [Step-up and re-authentication](#step-up-and-re-authentication-481) below.

**`prompt=consent` is honoured**: for a client that is not first-party it forces the consent page even when a recorded consent covers the request; for a first-party client it is a no-op — the deployment operates that client, so there is nothing to consent to. See [Consent for third-party clients](#consent-for-third-party-clients-527).

**`select_account` is refused** with `invalid_request` naming the value, not ignored: there is no account picker, and ignoring it would hand back a token the RP believes was freshly account-picked.

**`request` and `request_uri` are refused** with `request_not_supported` / `request_uri_not_supported`, not ignored: a signed request object exists to make the parameters tamper-proof, so processing the query string instead would give an attacker precisely what the object was there to prevent while the RP believes it was honoured. The discovery document says `request_uri_parameter_supported: false` for the same reason — OIDC Discovery **defaults that field to `true`**, so omitting it would be a claim.

**Not implemented:** the `claims` parameter, and `response_mode` beyond the default. `claims_parameter_supported` and `request_parameter_supported` default to `false` when omitted, so the discovery document tells the truth about them by saying nothing.

**Before minting, `/authorize` re-checks the session.** An authenticated browser session whose `sid` no longer resolves in the `UserSessionStore` is sent to the login page (or answered `login_required` under `prompt=none`) rather than issued a code carrying a dead `sid`; a store that cannot answer fails closed the same way.

## Step-up and re-authentication (#481)

A native app needs two things from the OP for a sensitive action: to **force a fresh authentication** (a payment, a credential change) and to **know how the user authenticated** (passkey, password, password plus a second factor), so it — or the resource server — can require a level. Both rest on what the session records at login.

**What a session records.** `UserSession.authTime` and `UserSession.amr` — RFC 8176 values written by the login path: `["pwd"]` for `POST /session/login`; the upstream IdP's `amr` (when the provider surfaces it on the profile) plus the deployment-defined `fed` for a federation callback; the WebAuthn grant, which mints tokens without a session, stamps `amr: ["hwk"]` on its access token directly. RFC 8176 registers no value for "federated", and OIDC Core §2 leaves `amr` values to the deployment, so `fed` is documented here rather than borrowed. A composition that resumes a login after `POST /auth/mfa/verify` (the MFA route is not composed in this repository; its resume handlers are the deployment's) records `mfa` — and the factor's own value, `otp` say — in the session it creates; `CreateUserSessionInput.amr` is the seam.

**What the tokens carry.** The id_token has `auth_time` always, `amr` when the session recorded one, and `acr` when `/authorize` satisfied an `acr_values` request. The access token mirrors `amr` and `acr` when present, so `auth.policy-verifier` or a resource server can gate on them without an id_token — and **keeps mirroring them across refreshes**: the `authorization_code` grant stamps both on the refresh token as well, and the `refresh_token` grant carries them from the presented token onto the access and refresh tokens it mints, since a refresh does not repeat the authentication (OIDC Core §12.2 treats `auth_time` the same way). The `session` grant mirrors the tracked session's `amr` (it has no `acr_values` negotiation, so no `acr`), and the passkey grant (`@o3co/auth-provider-webauthn`) stamps its `amr: ["hwk"]` on its refresh token as well as its access token. Every grant reads the claims in one shape — `amr` a non-empty array of non-empty strings, `acr` a non-empty string (core's `wellFormedAmr` / `wellFormedAcr`) — and omits anything else, so a session that recorded `amr: []` stamps no `amr` on any token rather than one that vanishes at the first refresh. A refresh token that carries neither yields tokens that carry neither.

**`max_age`.** A non-negative integer (anything else is `invalid_request`). A session whose `auth_time` is older than `max_age` seconds — `max_age=0` is always older — is sent to the login page with the request round-tripped, exactly as an unauthenticated one is, plus one thing: the instant of the ask is recorded **on the server**. On the way back, a session authenticated strictly after that instant — compared to the millisecond — is the re-authentication that was asked for, and the request proceeds — `max_age=0` included, which is what keeps it from looping; one authenticated before it is answered `login_required` rather than sent round again. Under `prompt=none` a stale session is `login_required` straight away: silent means silent. `auth_time` in the id_token is what an RP verifies, and it is always the truth.

The ask is a **record in the session store**, named by an opaque id the returned URL carries as `reauth_ask`. It is not the timestamp itself on the URL: a marker read straight off the request is the caller's to write, and a forged one would satisfy the check for any live session and skip the round trip it exists to force. A record cannot be forged (the id is 32 bytes from the CSPRNG, and naming one that does not exist is the same as naming none); it survives the session regeneration `/session/login` performs, which a field on the session would not; it is bound to the authorize request it was minted for, so an ask outstanding for one request cannot answer another's freshness requirement; and it is consumed when read, so a replay of the returned URL asks again rather than minting a second code. It expires after ten minutes. The rationale is in [`routes/reauthAsk.mts`](./src/routes/reauthAsk.mts).

`max_age` and `prompt=login` need a `userSessionStore` (there is no `auth_time` to measure without one) and the session middleware's store (where the ask is recorded); a composition without either answers them `invalid_request` rather than accepting them silently.

The login page must return the browser to `redirect_to` **verbatim**: a page that rebuilds the authorize URL drops the ask id, and the request is asked to authenticate again.

**`prompt=login`** uses the same mechanism with the staleness test replaced by "always": to the login page, the ask recorded, then satisfied by a session authenticated after it, else `login_required`. `prompt=none login` is refused as OIDC Core §3.1.2.1 says.

**`acr_values`** is answered from a configured table and from nothing else:

```hocon
oauth.authorize.acrValues {
  "urn:example:pwd" = ["pwd"]
  "urn:example:mfa" = ["pwd", "mfa"]
  "urn:example:passkey" = ["hwk"]
}
```

Each key is an Authentication Context Class Reference this deployment vouches for; its value is the `amr` set a session must carry to satisfy it. The first requested value the session satisfies becomes the `acr` of the code and of the id_token. None satisfied — or a value that is not in the table at all — is `unmet_authentication_requirements` at the `redirect_uri`, naming what was unmet; there is no silent acceptance, and no step-up redirect, because the login page cannot be told which factor to add. Discovery advertises the keys as `acr_values_supported` when the table is non-empty. An acr that requires nothing is refused at boot: every session would satisfy it, and it would vouch for nothing.

**Both login paths must re-authenticate when asked.** The login page the deployment serves receives `redirect_to` carrying `prompt=login` / `max_age` and the marker; a page that bounces an already-authenticated browser straight back gets `login_required`, never a loop. `POST /session/login` and the federation callback always establish a *new* session with a fresh `auth_time`, which is the re-authentication.

## Client authentication: `private_key_jwt` (RFC 7523 §2.2)

Every client-authenticated endpoint here — `/oauth/token`, `/oauth/introspect`, `/oauth/revoke` — accepts, besides `client_secret_basic` / `client_secret_post`, a JWT the client signed with its own private key (#484). Nothing shared has to be distributed to every replica of a machine client and rotated everywhere at once: the private half stays with the client, rotation is a JWKS publish, and every assertion carries a `jti` the provider spends exactly once.

**Registration.** `tokenEndpointAuthMethod: "private_key_jwt"` with exactly one of `jwks` (the public keys, inline, RFC 7591 `jwks` — a key carrying a private member such as `d`, `p`, `q` or `k`, or a symmetric `kty: "oct"`, is refused at registration, since the projection every middleware reads is public) or `jwksUri` (`https`, or `http` on a loopback host; fetched at verification time and cached, unknown `kid`s trigger a refetch with a cooldown). No `clientSecret` — the schema refuses one next to this method, and refuses `jwks` / `jwksUri` next to any other.

**The request.** `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and `client_assertion=<JWT>` in the form body, and nothing else that authenticates: an assertion next to a Basic header or a body `client_secret` is refused before either is examined (RFC 6749 §2.3, one method per request). A body `client_id`, if present, must match the assertion.

**The assertion.** `iss` and `sub` both equal to the `client_id`; `aud` naming the issuer or the token endpoint URL (RFC 7523 §3 — either form, so a client library that uses one or the other works); `exp` required and at most one hour ahead (`MAX_CLIENT_ASSERTION_LIFETIME_SECONDS`) plus the clock tolerance (`clockToleranceSeconds`, 30 s by default, at most 300 — a verifier built with anything else is refused) — the ceiling an ID-JAG is held to, compared through core's `assertionLifetime` — and a refusal is logged as `client_assertion_refused` with `reason: "lifetime"`, `lifetimeSeconds` and `maxLifetimeSeconds`; `jti` required, at most 256 characters (core's `MAX_JTI_LENGTH`, since it is kept as a seen-set key) and single-use, recorded in the composition's `replaySeenSet` under `client-assertion:<client_id>` until the assertion expires; signed with an asymmetric algorithm (`RS*`, `PS*`, `ES*`, `EdDSA` — `token_endpoint_auth_signing_alg_values_supported` lists them; `HS*` and `none` are never accepted against a JWKS). `nbf` is validated when present, and `iat` when present must be neither ahead of the server's clock beyond the 30 s tolerance nor older than the lifetime ceiling.

**Refusals** are `401 invalid_client` — a replayed, empty or over-long `jti`, a wrong `aud`, an expired or over-long assertion, an `exp`, `iat` or `nbf` that is not a NumericDate (non-finite, such as JSON's `1e400`, or past the Date range; a fraction is fine — logged as `numeric_date`), a signature under a key the JWKS does not hold, a `kid` it does not publish, a client registered for another method, an unknown client or an `iss` that cannot name one (a control character, or past 256 characters — reason `malformed_client_id`, and the repository is not asked), or a `jwks_uri` that cannot be fetched (fail closed, logged as `client_assertion_refused` with the reason). A client repository that cannot answer is `503 temporarily_unavailable` instead (reason `client_repository_unavailable`): the client did nothing wrong. A `private_key_jwt` request in a composition that wired no `replaySeenSet` is `500 server_error`: a `jti` that cannot be recorded is one that could be replayed, so the path refuses rather than authenticating unchecked. The standalone template wires one (`REPLAY_SEEN_SET_ADAPTER`, Redis by default; the memory adapter is refused under `DEPLOYMENT_MODE=multi` because a captured assertion would replay once per replica).

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

Wire a `consentStore` and a `pendingConsentStore` and point `endpoints.consent.url` at your page. Each bundled module provides both: `memoryConsentStoreModule` from `@o3co/auth-provider-core` (single replica — refused under `deployment.mode = "multi"`) and `redisConsentStoreModule` from `@o3co/auth-provider-redis`, which shares the consent records and the parked requests across replicas. In the standalone template that is `consentStore.adapter = "memory"` or `"redis"`. Then, for a client that is not first-party:

1. `/authorize` runs every request-shape check as usual, then looks up the consent record for (`sub`, `client_id`). A live record covering the requested scopes (a subset of what was granted) mints the code with no interaction.
2. Otherwise the request is **parked under a 32-byte challenge** in the `pendingConsentStore`, bound to the session and the subject it was asked of, and the browser is redirected to `endpoints.consent.url?challenge=<id>`. `prompt=none` gets `consent_required` at the `redirect_uri` instead (OIDC Core §3.1.2.6); `prompt=consent` parks the request even when a record covers it.
3. The page calls **`GET /oauth/consent?challenge=<id>`** (session cookie, uncacheable) and receives `client_id`, `client_id_host` (only for a client resolved from a Client ID Metadata Document — see below), `client_name`, `client_uri` (from the registration), `scopes` (what is asked), `granted_scopes` (what the user already agreed to, so the page can highlight the delta), `redirect_uri` (show its host — this is where the code goes) and `expires_in`.
4. The page **`POST`s `/oauth/consent`** with `{ "challenge": "<id>", "decision": "accept" | "deny" }` (JSON or a form). `accept` records the union of what was granted and what is asked, emits `consent.granted`, and answers `303` to the parked `/authorize` URL — which now finds the record and mints. `deny` emits `consent.denied` and answers `303` to the client's `redirect_uri` with `error=access_denied` and the `state`. Either way the challenge is spent.

The challenge is bound to the session that parked the request and reaches the page only through the redirect URL, which a cross-site page cannot read; a POST carrying the matching value was composed by same-origin code (the synchronizer-token pattern, with the session as the synchronizer). A foreign, replayed or expired (10 minutes) challenge is `400`. The answer **consumes** the parked record in one step (`PendingConsentStore.consume`), so two answers in flight for one challenge — a duplicated tab, a double submit — apply exactly one, and the other is told there is no pending consent. A consent-store outage at `/authorize` is `temporarily_unavailable`, never a code and never a refusal the user could act on. An operator revokes a consent by removing the record (`consentStore.revoke(sub, clientId)`); the next `/authorize` for that client asks again.

Register what the page will show: `clientName` (RFC 7591 `client_name`) and `clientUri` (`client_uri`) on the client record. A native client with a loopback `redirect_uri` is the case the MCP authorization spec asks the page to warn about — `redirect_uri` is in the response for exactly that.

**A Client ID Metadata Document client names itself.** Its `client_name` and `client_uri` come from a document whoever controls its host wrote, so "Google Drive" costs nothing to type. The one verified fact is the host its `client_id` URL names, which the response carries as `client_id_host`: show it prominently, as the draft asks, and never let `client_name` stand alone. Serve the page with `Referrer-Policy: no-referrer` (or `strict-origin`) so a `client_uri` link does not hand that host the page URL and its challenge.

## Client ID Metadata Documents (#529)

A client may identify itself with the `https` URL of its own registration — a **Client ID Metadata Document** ([draft-ietf-oauth-client-id-metadata-document](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/)), the registration model the MCP authorization spec (2026-07-28) makes the SHOULD for hosted clients now that Dynamic Client Registration is deprecated there. Off by default: `oauth.clientIdMetadataDocuments.enabled = true` (`OAUTH_CIMD_ENABLED`), and the discovery document then advertises `client_id_metadata_document_supported: true` beside the `none` it already lists in `token_endpoint_auth_methods_supported` — the two signals an MCP client selects on.

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

- **A pre-registered client with the same `client_id` wins**; the document is not fetched.
- **The URL must be a document URL**: `https`, a path, no fragment, credentials, dot segments or query string, a host name rather than an address and not loopback. Anything else is not a client. A host name ending in the DNS root dot (`client.example.`) is refused outright: it survives URL canonicalisation and TLS accepts the undotted certificate, so it would otherwise be a spelling the host lists below do not match. The operator may narrow hosts further (`allowedHosts`, exact or `.suffix`; `deniedHosts` wins).
- **The name is resolved before the socket opens**, and every address must be public: one inside an RFC 6890 special-use range — the cloud metadata endpoint, a private network, this host — refuses the lookup. That is the SSRF guard the draft requires; a rebinding between check and connect is the residual it accepts too, and the host lists are the lever against it.
- **The fetch** follows no redirect (a 3xx is an error), times out (`timeoutMs`), caps the body on `Content-Length` and on the stream (`maxBytes`, 5 KB by default), and takes only `200` with JSON. A valid document is cached per URL for its `Cache-Control: max-age`, bounded by `cacheMaxAgeMs` and by `maxCacheEntries`, and revalidated by `ETag` when it expires. A `5xx` or a `429` from the client's server is read as *their availability*, not their registration — it takes the same path as a timeout or a DNS failure; a `4xx` or a refused redirect is the registration being absent or wrong, and takes the refusal path. A refusal is never cached *as a client*, but it is remembered as a refusal for `negativeCacheMs` (a minute by default), so an invented `client_id` does not cost a DNS resolution and a socket on every request; a registration this server already validated is still served for `staleIfErrorMs` through a revalidation that failed for a reason that is not the document's — a DNS blip, a 5xx, a timeout — because an outage at someone else's server is not a verdict on the client, while a document that was *rejected* is dropped at once. `maxConcurrentFetches` bounds how many documents are in flight across every id. Concurrent lookups share one fetch. Every refusal logs `cimd_document_rejected` / `cimd_document_fetch_failed` / `cimd_host_not_allowed` with the reason.
- **The document** must carry `client_id` equal to the URL, a non-empty `redirect_uris` this server would accept at registration (exact match at `/authorize`, with the RFC 8252 §7.3 loopback-port carve-out), no `client_secret`, and no `token_endpoint_auth_method` but `none` — a shared-secret method is forbidden by the draft, and `private_key_jwt` is refused because the keys would come from the same attacker-authored document that names them, so it would authenticate the document rather than the client (registered clients may use it — see [`private_key_jwt`](#client-authentication-private_key_jwt-rfc-7523-22)). `grant_types` must include `authorization_code`; `response_types` must admit `code`.
- **The client it becomes is public and not first-party** (`tokenEndpointAuthMethod: none`, PKCE S256 required, `firstParty: false`), so it goes through the [consent step](#consent-for-third-party-clients-527) — **wire a consent store, or the feature stays inert**: without one `/authorize` could not finish such a flow, so no document is fetched and a URL-shaped `client_id` is simply an unknown client (the discovery document withholds `client_id_metadata_document_supported` for the same reason) — and the page shows the document's `client_name`, `client_uri` and the `redirect_uri`. Its scopes are the document's `scope` intersected with the operator's `allowedScopes`; its audiences are the operator's `allowedAudiences` — the resource servers this authorization server protects, which an MCP client names with `resource`. A document says who a client is, never what it may reach.

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

[auth.proxy](https://github.com/o3co/auth.proxy) already behaves this way in validation mode. A non-2xx introspection answer is not cached, and its client gets `502 Bad Gateway`. Before this release, an outage came back as `200 active: false`, which auth.proxy cached for up to 30 seconds and answered with `401`.

### A `client_id` with reserved characters must be percent-encoded in HTTP Basic

RFC 6749 §2.3.1 requires the client id and secret to be `application/x-www-form-urlencoded`-encoded **before** the `id:secret` pair is base64-encoded into the `Authorization: Basic` header. A resource URI is the case that makes this mandatory rather than pedantic: it contains `:` and `/`, and `:` is the field separator the header is split on.

```
# WRONG — split at the first colon, so the client id parses as "https"
Authorization: Basic base64("https://api.example.com/orders:s3cret")

# RIGHT — reserved characters percent-encoded first
Authorization: Basic base64("https%3A%2F%2Fapi.example.com%2Forders:s3cret")
```

`client_secret_post` (credentials in the form body) avoids the question entirely — the body encoding already does it.

### Revoked families and ended sessions

- **Refresh-token family.** A token carrying `family_id` is checked with `refreshTokenFamilyRevocation.isFamilyRevoked` when that slot is wired: a revoked family answers `active: false` and emits `introspect.family_revoked`; a store that cannot answer is `503 temporarily_unavailable` ("refresh token store unavailable"), audited as `introspect.store_unavailable` and logged as `introspect_store_unavailable` — an outage, for the reason above. A token without `family_id` is verified by signature and the revocation stores alone. A revoked family is remembered until the last access token it could have minted stops being accepted, so the answer does not revert once the family's own refresh tokens expire (core's `refresh-token-family/retention.mts`).
- **Session liveness.** A token carrying a `sid` claim is checked against the `UserSessionStore` — the same read `/oauth/userinfo` performs. A session that has been logged out, has expired, or was deleted out of band answers `active: false` and emits `introspect.session_invalid`; a store outage is `503 temporarily_unavailable` ("session store unavailable"), audited and logged as the family store's is. A token with no `sid` (client credentials, jwt-bearer) does not pay for the read, and neither does a composition that wires no `userSessionStore`.

These bind only callers that ask: a resource server validating the JWT offline, by signature and `exp`, sees no revocation and accepts the token until it expires.

## Revocation

`POST /oauth/revoke` is RFC 7009. It authenticates the caller like `/oauth/token` — public clients included, since a public client may revoke its own tokens (§2.1) — answers `400 invalid_request` without a `token` and `400 unsupported_token_type` for a `token_type_hint` it does not recognise, and otherwise `200` whether or not the token existed or belonged to the caller (§2.2). A token is revoked only for the client it was issued to.

A revocation the server could not record is not a `200`. When the caller's own token verified and the store that records its revocation — the `accessTokenDenylist` or the refresh-token family store — fails, the answer is `503 temporarily_unavailable` (§2.2.1: the client should assume the token still exists and retry), logged at error level as `revoke_store_unavailable` with `store` naming which one and `clientId` the client whose revocation was lost. A token that does not verify, is not one this server can revoke, or belongs to another client never reaches a store, so it stays `200` during an outage too.

- **A refresh token** revokes its family through `refreshTokenFamilyRevocation`; without that slot the request is a no-op `200`.
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
| No `userSessionStore` wired or no `sid` claim | `200 { sub }` (sub only, no durable claims) |
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

- **Access-token `cnf` is mechanism-agnostic.** Any binding's `confirmation` flows through unchanged — DPoP `{ jkt }`, mTLS `{ "x5t#S256" }`.
- **Refresh-token `cnf` is bound for public clients, and for confidential clients only on request.** A public client with a bound access token gets a bound refresh token, so the next refresh enforces continuity. A confidential client gets a plain refresh token — its client authentication is the refresh-time authenticator (RFC 9449 §5, RFC 8705 §7.1) — unless `oauth.tokenBinding.bindConfidentialClientRefreshTokens = true` (`OAUTH_TOKEN_BINDING_BIND_CONFIDENTIAL_CLIENT_REFRESH_TOKENS`), which binds it too. That costs key rotation: a bound refresh token pins the client to one key or certificate for its whole lifetime.
- **Wire-level `token_type`:** `"DPoP"` only for a DPoP binding (RFC 9449 §5). mTLS keeps `"Bearer"` (RFC 8705 §3) — the certificate is the binding evidence, not the wire token type.

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
> cascade. If a session holds a refresh token, that is the one to call. See
> [the session package README](../session/README.md#what-post-sessionlogout-invalidates).

### `POST /oauth/logout` and `GET /oauth/logout`

OIDC RP-Initiated Logout 1.0 `end_session_endpoint`. Parameters (`application/x-www-form-urlencoded` on `POST`, the query on `GET`):

- `id_token_hint` (required) — signed id_token from this provider; its `sid` claim identifies the session
- `post_logout_redirect_uri` (optional) — must match one of `client.postLogoutRedirectUris` **exactly**, byte for byte. A reverse-domain custom scheme is a legal entry, and gets no relaxation for being one.
- `state` (optional) — round-tripped when redirecting to `post_logout_redirect_uri`

An `id_token_hint` that cannot be verified is `400 invalid_token`; one that cannot be verified because the keystore did not answer is `503 temporarily_unavailable`, on `GET` as on `POST`. A `GET` whose `id_token_hint` was issued more than 24 hours ago is answered with a confirmation page instead of logging out; its form posts the hint and `state` back to this endpoint, and `post_logout_redirect_uri` only when it is on the client's allowlist.

Flow: verifies `id_token_hint` → loads the session → broadcasts an OIDC Back-Channel Logout 1.0 `logout_token` to every RP with a `backchannelLogoutUri` (best-effort; a failed POST does not stop the logout) → runs the store cascade → answers with one of:

- `text/html` page with an `<iframe>` per RP with a `frontchannelLogoutUri` (when `Accept: text/html` wins q-weighted negotiation)
- `303` to the first federation's IdP end-session URL (when that federation's provider implements `SupportsLogout`)
- `303` to `post_logout_redirect_uri` (when it matches the client's allowlist)
- `200 {"logged_out": true}` (fallback)

**The cascade** is [`cascadeLogout`](./src/logout/cascadeLogout.mts), four steps in a fixed order; its doc comment is the full contract, and [`cascadeLogout.test.mts`](./src/logout/__tests__/cascadeLogout.test.mts) pins it:

1. Read the session's refresh-token families. Failure stops the cascade.
2. Revoke every family and delete the session's federation tokens. Every operation is attempted; if **any** failed, the cascade stops here, before the bookkeeping a retry needs is erased.
3. Remove the session's reverse-index entries (relying parties, families, federations) — best-effort, logged, bounded by TTL.
4. Delete the `UserSession` last. Failure stops the cascade.

A cascade that stopped answers `503 {"error": "temporarily_unavailable"}`, and a retry of the same logout is safe. It is logged once at error level as `logout_store_unavailable` with `store: "logout_cascade"`, the `cascadeStep` and the number of `failures`; each operation that failed also has its own `logout_cascade_operation_failed` (warn). A session store that cannot be read before the cascade is the same event with `store` naming it (`user_session`, `session_rp_registry`, `session_federation_index`).

On every success shape — and on the no-op answer for a session that is already gone — the endpoint also **ends the browser's own express-session**, but only when that session's `sid` is the one being logged out. RP-initiated logout is a request any party may make about any session, so a cookie naming a different `sid`, or naming none, is left alone rather than signing out an unrelated user. Without this the cookie would keep satisfying `req.session.isAuthenticated` at `/authorize` after the stores were emptied. A destroy the session store cannot complete is logged and does not turn a successful cascade into a `503`; `/authorize` refuses the dead `sid` on its own account either way (see [The OIDC surface](#the-oidc-surface-stated-284)). The `503` deliberately leaves the cookie in place, so a retry still names the session.

### `POST /oauth/federation/:name/logout`

Provider-scoped federation disconnect. Authorization: `Bearer <access_token>` with `typ: at+jwt`. Optional body: `post_logout_redirect_uri`, `state`.

Flow: verifies the access token → checks its family is not revoked → loads the session → verifies the federation is linked → deletes the federation token → removes the federation from the session → if the provider implements `SupportsLogout`, redirects to the IdP end-session URL; otherwise returns `200 {"disconnected": true}`.

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

- `postLogoutRedirectUris` — the allowlist for `post_logout_redirect_uri`, held to the **same grammar as `allowedRedirectUris`** (#498): `https:`, `http:` for a loopback host, or an RFC 8252 §7.1 reverse-domain custom scheme (`com.example.app:/signout`), and never a fragment, userinfo or executable scheme. Registering the custom scheme is what lets a native app be returned to itself after logout instead of landing on a JSON body.
- `backchannelLogoutUri` — receives the `logout_token` POST. **`http`/`https` only** — this server dispatches the POST itself, and it has no way to reach a custom scheme.
- `frontchannelLogoutUri` — the iframe src. **`http`/`https` only** — the browser resolves this value in a document context, where a custom scheme is at best inert and at worst a handler invocation the RP never asked for.
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
5. Return the stored upstream access token if it has more than 30 seconds of validity remaining.
6. Otherwise, refresh it:
   - Acquire an advisory lock (when `FederationTokenStore` implements `SupportsLock`) to prevent concurrent refresh fan-out.
   - Re-read after the lock — another waiter may have refreshed during the wait.
   - Call `provider.refreshToken(refreshToken)`; persist the result.
   - Release the lock.

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

The store's contract is core's `FederationTokenStore` and `FederationTokens` ([`federation-tokens/types.mts`](../core/src/federation-tokens/types.mts)); every field of a record is a required key, as [Upgrading: store records name every field](../../docs/upgrading-required-record-keys.md) describes for anyone implementing or calling a store. What this route depends on:

- **Every field survives `attach`, `update` and `get`.** Losing `tokenType` fails **open**: the record comes back silent, silence is read as `Bearer`, and a sender-constrained token is handed on as one. Losing `refreshToken` makes the connection unrefreshable (`410 refresh_token_absent`); losing `idToken` drops the upstream's `id_token_hint` at logout; losing `grantedScope` makes the current scope the refresh bound, which under-reports.
- **An adapter's own storage shape names every field too.** The required keys reach `FederationTokens`, not a row or document an adapter converts it to: declare the same required keys on that shape, as the bundled Redis store does for its envelope, or the conversion can forget a field and still compile.
- **An unset value comes back as `undefined` or absent, never `null`.** This route refuses a stored `null`, so a serialiser that writes `undefined` as `null` — MongoDB's driver does unless `ignoreUndefined` is set — turns every connection whose adapter names no type into a `502`. The bundled Redis codec refuses a record holding `null`.

Both bundled stores meet these and are pinned on them.

### Error responses

| Status | Error | Meaning |
| --- | --- | --- |
| 401 | `invalid_token` | Bearer missing, invalid, wrong type (not `at+jwt`), or family revoked |
| 403 | `forbidden` | Client not opted in via `allowedAzpForFederationToken` |
| 404 | `federation_not_linked` | The named federation isn't linked to this session |
| 410 | `refresh_token_absent` | Stored tokens have no refresh token (upstream didn't return one at login, or the post-lock re-read found a record without one) |
| 410 | `re_authentication_required` | IdP returned `invalid_grant` / `invalid_token` — the session's federation is cleared; the user must re-authenticate with the IdP |
| 429 | `rate_limited` | Upstream IdP rate limit exceeded (`status: 429` or `error: "too_many_requests"`); retry later |
| 500 | `refresh_failed` | Unclassified error from the IdP refresh path, or an answer this route could not read; SIEM should group on the `details.reason` audit field |
| 502 | `upstream_token_ineligible` | The upstream's token is one this provider may not hand on. `error_description` names the reason — `token_type_unsupported` is the only one. Carries `Retry-After: 300` |
| 503 | `refresh_not_supported` | Provider doesn't implement `SupportsRefresh`; logged at error level as `federation_token_refresh_unsupported` — the deployment's to fix |
| 503 | `lock_timeout` | Advisory lock could not be acquired within the wait window; logged at warn as `federation_token_lock_timeout` with `federation`, `clientId` and `sid`, so contention that persists is seen |
| 503 | `temporarily_unavailable` | Store outage — the refresh-token family check included — a keystore or revocation store that cannot answer while the access token is verified, IdP 5xx, or upstream network failure (ECONNREFUSED / ENOTFOUND / ETIMEDOUT — including codes wrapped on `error.cause.code` of a fetch TypeError). Each is logged once at error level: a store as `federation_token_store_unavailable` with `store` and `step`, the client lookup as `client_repository_unavailable` (`site: "federation_token"`), the upstream as `federation_token_upstream_unavailable`; an upstream refusal that is not a 503 is `federation_token_refresh_failed` (warn) |

All error responses set `Cache-Control: no-store` and `Pragma: no-cache`. 401 responses include `WWW-Authenticate: Bearer error="invalid_token"` per RFC 6750.

Every failure this route logs carries core's `loggableError(err)`, never the error — the `refreshToken failed (reason: …)` warning included. The adapter's library puts the refresh answer it refused, rotated refresh token included, on the error's cause chain, and a Redis store's error carries the refused command's arguments (the token record, under `allow-plaintext`); the projection drops those, keeps what tells the failures apart — the library's code, the HTTP status and content type, the upstream's OAuth `error`, and its `error_description` under the rule core states for it (the first line, cut at the start of the word holding a token-shaped run) — and removes the two known shapes in which a message quotes a peer (a JSON parser's input, Redis's echoed arguments). Other text a peer wrote into a message is kept; core's README says exactly what is. The rest of this package's logs follow the same rule.

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

- `federation.token.success` — on token issuance (details include `refreshed: boolean` to distinguish a stored token from the refresh path)
- `federation.token.forbidden` — on 403 (client not opted in)
- `federation.token.family_revoked` — on 401 via revoked family
- `federation.token.refresh_failed` — on the 500 `refresh_failed`, which is two cases. `provider.refreshToken` threw an error the refresh-error classifier could not place: `details.reason` is `"unknown"`. Or an answer came back that this route cannot use: `"no_access_token"`, `"invalid_expiry"` or `"invalid_token_type"`. Those four are every value this event carries, and SIEM rules should group on them. The classifier's other results are **not** this event: `invalid_grant` is `federation.token.reauthentication_required` (410), and `rate_limited` (429) and `network` (503) emit no audit event.
- `federation.token.reauthentication_required` — on `invalid_grant` or `invalid_token` from the IdP
- `federation.token.upstream_ineligible` — on 502. `details.reason` is `"token_type_unsupported"` and `details.tokenType` is what the record held, reported as it was read — including a value that is not a token type, which is the one worth seeing; `null` means the record held something that is not a string. The response carries `Retry-After: 300`, matching `federationGrants.ineligibleRetryAfter`'s default, because the condition ends when an operator changes the upstream's registration and not before. The caller is not told which type it was; it can do nothing with that but retry

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
- **`allowedScopes`** is intersected with the assertion's own `scope` claim (or stands alone when the assertion names none) and becomes the scope ceiling the request and the client registration are further bounded by.
- **`allowedAudiences`** bounds the issued `aud` whatever chose it — a `grantPolicy`, an RFC 8707 `resource`, the client registration (its `allowedAudiences` narrowed to the issuer's, its client id only if the issuer admits it). With no authenticated client it is also the source: the token names the issuer's first audience instead of this server. A client and an issuer that admit no audience in common is `invalid_grant` and logs `jwt_bearer_issuer_audience_mismatch`.
- **`expiresAt`** is the one field that changes in place (`registry.setExpiresAt`); everything else is immutable — remove and re-add — so the history of what was trusted is the history of adds and removes. `add`, `list`, `remove` are the rest of the admin surface. **On the memory registry that surface reaches one process:** an issuer revoked with `setExpiresAt` on one replica stays trusted on the others, a restart rebuilds the registry from the composition's entries — restoring the issuer even where it was revoked — and `deployment.mode = "multi"` cannot catch it, because the registry lives inside the `assertionVerifier` you hand in rather than on a module. Entries supplied when the registry is built are identical everywhere; with several replicas, change the entry list and redeploy, or implement the registry over a shared store.

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

## Tests

The invariants above are pinned where they are implemented; a starting set:

- module wiring and what each module declares — [`module.test.mts`](./src/__tests__/module.test.mts), [`oauthAuthorization.test.mts`](./src/__tests__/oauthAuthorization.test.mts), [`oauthSession.test.mts`](./src/__tests__/oauthSession.test.mts), [`subjectRevocationService.module.test.mts`](./src/logout/__tests__/subjectRevocationService.module.test.mts);
- the discovery gates — [`discovery-contribution.test.mts`](./src/__tests__/discovery-contribution.test.mts);
- the logout cascade order and failure handling — [`cascadeLogout.test.mts`](./src/logout/__tests__/cascadeLogout.test.mts), and the endpoints — [`logout.test.mts`](./src/__tests__/logout.test.mts);
- introspection's audience pin, session liveness and outage answers — [`introspect.audience.test.mts`](./src/__tests__/introspect.audience.test.mts), [`introspect.sessionLiveness.test.mts`](./src/__tests__/introspect.sessionLiveness.test.mts), [`introspect.revocationOutage.test.mts`](./src/__tests__/introspect.revocationOutage.test.mts);
- client authentication — [`clientAuth.test.mts`](./src/middleware/__tests__/clientAuth.test.mts), [`clientAssertion.test.mts`](./src/middleware/__tests__/clientAssertion.test.mts);
- the federation token route — [`federationToken.test.mts`](./src/__tests__/federationToken.test.mts).

## See also

- [`@o3co/auth-provider-core`](../core/README.md) — the ports, records and token primitives this package builds on (`Module`, `GrantHandlerResolver`, `ClientRepository`, `CodeRepository`, `KeyStore`)
- [`@o3co/auth-provider-session`](../session/README.md) — login, the browser session and the federation login routes
- [`@o3co/auth-provider-oauth-token-exchange`](../oauth-token-exchange/README.md), [`@o3co/auth-provider-device-grant`](../device-grant/README.md), [`@o3co/auth-provider-webauthn`](../webauthn/README.md) — grants contributed to `/oauth/token`
- [`@o3co/auth-provider-federation-grants`](../federation-grants/README.md) — offline delegation of upstream tokens
