# @o3co/auth-provider-oauth

OAuth 2.0 routes module for [auth.provider](../../README.md).

Mounts `POST /oauth/token`, `POST /oauth/introspect`, and `GET /oauth/authorize` onto an Express app. Implements a registry-based grant dispatch model so additional grant types can be plugged in without modifying this package.

## Install

This package is **private** — it is not published to npm and is only available within the `auth.provider` monorepo.

```jsonc
// packages/*/package.json
{
  "dependencies": {
    "@o3co/auth-provider-oauth": "workspace:*"
  }
}
```

Peer dependencies (install separately in the workspace root):

```
express@^5.0.0
```

## Public API

### `oauthModule`

```typescript
function oauthModule(params: {
  clientRepository: ClientRepository;
  codeRepository: CodeRepository;
  express?: ExpressLike;
}): Module;
```

Top-level module. Registers `oauthSessionModule` and `oauthAuthorizationModule` as sub-modules and mounts the OAuth router at `/oauth`. Use this as the single entry point unless you need to mount the sub-modules individually.

Routes mounted:

| Method | Path               | Description                        |
|--------|--------------------|------------------------------------|
| POST   | /oauth/token       | Token endpoint — dispatches by `grant_type` |
| POST   | /oauth/introspect  | Token introspection (RFC 7662)     |
| GET    | /oauth/authorize   | Authorization endpoint — PKCE auth code flow |

---

### `oauthSessionModule`

```typescript
function oauthSessionModule(params: {
  clientRepository: ClientRepository;
}): Module;
```

Registers the `"session"` grant type in the grant registry. Activation is gated on `config.oauth.grants.session.enabled`. Use this sub-module directly when you need to compose the grant registry manually.

---

### `oauthAuthorizationModule`

```typescript
function oauthAuthorizationModule(params: {
  codeRepository: CodeRepository;
}): Module;
```

Registers the `"authorization_code"` and `"refresh_token"` grant types in the grant registry. Use this sub-module directly when composing the grant registry manually.

---

### `createOAuthRouter`

```typescript
function createOAuthRouter(
  express: ExpressLike,
  options: {
    registry: GrantRegistry;
    config: AppConfig;
    clientRepository: ClientRepository;
    codeRepository: CodeRepository;
    keyStore: KeyStore;
  }
): Promise<{ router: Router; registry: GrantRegistry }>;
```

Low-level factory. Creates the Express router and the fully-configured grant registry. Called internally by `oauthModule`; use directly when you need access to the registry instance after construction. Client authentication at `/oauth/introspect` is handled by `createClientAuthMiddleware(clientRepository)` — no Passport dependency required.

## Usage Example

```typescript
import express from "express";
import { createApp } from "@o3co/auth-provider-core";
import { oauthModule } from "@o3co/auth-provider-oauth";

const app = createApp(express, {
  config,
  keyStore,
  modules: [
    oauthModule({
      clientRepository,
      codeRepository,
    }),
  ],
});
await app.init();
```

## TODO-F-4 changes

### `authorization_code` grant — id_token issuance

When the `openid` scope is included in the granted scopes and a `UserSessionStore` is wired, the `authorization_code` grant issues an `id_token` alongside the access token and refresh token. The `id_token` is a signed JWT built by `generateIdToken` (from `@o3co/auth-provider-core`) and appended to the token response as the `id_token` field.

Conditions for id_token issuance:

- `openid` must appear in the granted scopes (set by `GrantPolicyHook` at `/oauth/authorize` time)
- `AppOptions.userSessionStore` must be wired (session is the source of truth for user claims)
- The code record must contain `sid` (written by login/federation wiring at authorize time)
- `AppOptions.config.oauth.jwt.issuer` must be set (prevents emitting a noncompliant `iss: ""` claim)

When any condition is not met, `id_token` is omitted from the response — the token endpoint still returns `access_token` and `refresh_token` normally.

Claim composition of the issued `id_token`:

- `iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `auth_time`, `sid`, `azp` — OIDC Core §2 standard claims
- `nonce` — reflected verbatim from the code record when present (OIDC Core §3.1.3.7)
- scope-filtered user claims (see claim mapping table below)

### `/oauth/userinfo` — OIDC Core §5.3

```http
GET /oauth/userinfo
Authorization: Bearer <access_token>
```

Returns scope-filtered claims sourced from the durable `UserSession`. The endpoint is mounted by `oauthModule` alongside the existing `/oauth/token`, `/oauth/introspect`, and `/oauth/authorize` routes.

| Condition | Response |
| --- | --- |
| Missing / invalid Bearer token | `401` with `WWW-Authenticate: Bearer realm="userinfo"` |
| Invalid JWT signature | `401 invalid_token` |
| `family_id` claim revoked (F-3 cascade) | `401 invalid_token` |
| Session not found or store error | `401 invalid_token` (fail-closed) |
| No `userSessionStore` wired or no `sid` claim | `200 { sub }` (sub only, no durable claims) |
| Session active | `200 { sub, ...scope-filtered claims }` |

All responses set `Cache-Control: no-store` and `Pragma: no-cache` (RFC 6750 §5.3).

Scope-to-claim mapping (OIDC Core §5.4 standard scopes):

| Scope | Emitted claims |
| --- | --- |
| `openid` | *(governs id_token issuance; `sub` always included in userinfo response)* |
| `profile` | `name`, `picture` |
| `email` | `email`, `email_verified` |
| `groups` | `groups` |

## TODO-F-3 changes

- **`/oauth/introspect` cascading revoke.** When the access token carries a `family_id` claim and `AppOptions.refreshTokenStore` is wired, the introspect endpoint calls `RefreshTokenStore.isFamilyRevoked(familyId)` before returning an active response. If the family is revoked or the store is unreachable, the response is `{ active: false }` (fail-closed, per RFC 7009 §2.1 SHOULD). Tokens minted before F-3 that lack a `family_id` claim bypass this check and are validated by signature only.
- **`family_id` + `sid` data claims.** Both `access_token` and `refresh_token` minted by the `authorization_code` and `refresh_token` grants carry `family_id` (token family for cascading revoke) and `sid` (session ID, when the code record contains it) as JWT claims.
- **`authorization_code` grant — `sid` requirement.** The grant reads `sid` from the `CodeData` record. Deployments must have the F-2/F-3 login wiring in place (local login or federation callback writing `sid` onto the code) for the `sid` claim to be present in issued tokens.
- **`refresh_token` grant — session validation.** When `AppOptions.userSessionStore` is wired and the refresh token carries a `sid` claim, the grant calls `userSessionStore.get(sid)` to verify the session is still active. A missing session returns `400 invalid_grant`; a store error returns `503 temporarily_unavailable`.

## TODO-F-5 changes — Logout endpoints

The OAuth module exposes two logout-related routes when wired with `userSessionStore`, `federationTokenStore`, `refreshTokenStore`, and `oauth.jwt.issuer`:

### POST /oauth/logout

OIDC RP-Initiated Logout 1.0 `end_session_endpoint`. Accepts `application/x-www-form-urlencoded`:

- `id_token_hint` (required) — signed id_token from this provider; `sid` claim identifies the session
- `post_logout_redirect_uri` (optional) — must match one of `client.postLogoutRedirectUris` exactly
- `state` (optional) — round-tripped when redirecting to `post_logout_redirect_uri`

Flow: verifies `id_token_hint` → loads session → broadcasts OIDC Back-Channel Logout 1.0 `logout_token` to every RP with `backchannelLogoutUri` → executes store cascade (refresh-family revoke, federation-token delete, session delete) → responds with one of:

- `text/html` page with `<iframe>` per RP with `frontchannelLogoutUri` (when `Accept: text/html` wins q-weighted negotiation)
- `303` to first-federation IdP end-session URL (when that federation's provider implements `SupportsLogout`)
- `303` to `post_logout_redirect_uri` (when it matches the client's allowlist)
- `200 {"logged_out": true}` (fallback)

Cascade failure returns `503 {"error": "temporarily_unavailable"}`. The cascade order is fixed per the spec: step 1 (refresh-family revoke) and step 3 (session delete) fail hard; step 2 (federation-token delete) is best-effort and logs a warning on failure without aborting the cascade.

### POST /oauth/federation/:name/logout

Provider-scoped federation disconnect. Authorization: `Bearer <access_token>` with `typ: at+jwt`. Optional body: `post_logout_redirect_uri`, `state`.

Flow: verifies access_token → checks family not revoked → loads session → verifies federation is linked → deletes federation token → removes federation from session → if the provider implements `SupportsLogout`, redirects to the IdP end-session URL; otherwise returns `200 {"disconnected": true}`.

If the IdP end-session call throws, local state is already cleared; the response is `200 {"disconnected": true}` and an audit event `federation.logout.idp_unreachable` is emitted for operator visibility.

Returns `404 {"error": "federation_not_linked"}` when the named federation is not in the session.

### Discovery metadata

`GET /.well-known/openid-configuration` now advertises:

- `end_session_endpoint`
- `backchannel_logout_supported: true`
- `backchannel_logout_session_supported: true` — `logout_token` includes `sid` by default
- `frontchannel_logout_supported: true`
- `frontchannel_logout_session_supported: true` — front-channel iframe URL includes `sid` by default

The `session_supported` defaults of `true` intentionally deviate from OIDC Back-Channel Logout 1.0 §2.2 (spec default: `false`). Clients that require the spec-default behavior must set `backchannelLogoutSessionRequired: false` or `frontchannelLogoutSessionRequired: false` on their client record.

### Client record logout metadata

Each `Client` supports five optional fields for logout behavior:

- `postLogoutRedirectUris?: string[]` — allowlist for `POST /oauth/logout`'s `post_logout_redirect_uri`
- `backchannelLogoutUri?: string` — receives `logout_token` POST
- `backchannelLogoutSessionRequired?: boolean` — default `true`; set `false` to exclude `sid` from `logout_token`
- `frontchannelLogoutUri?: string` — iframe src target
- `frontchannelLogoutSessionRequired?: boolean` — default `true`; set `false` to exclude `sid` from iframe URL

## TODO-F-6 changes — Federation token endpoint

`POST /oauth/federation/:name/token` retrieves the upstream IdP access_token for the caller's session, so consumers can make server-side API calls to Google Calendar / GitHub API / etc. on the user's behalf.

### Authentication

- Bearer access_token minted by this auth.provider instance (`typ: at+jwt`).
- The token's `azp` claim identifies the client; the client record MUST opt in via `allowedAzpForFederationToken: true` (see below).

### Flow

1. Verify the Bearer access_token.
2. Deny if the family_id is revoked or the session no longer exists.
3. Deny unless `client.allowedAzpForFederationToken === true`.
4. Deny unless the federation is linked to the session.
5. Return the cached upstream access_token if it has > 30 seconds of validity remaining.
6. Otherwise, refresh it:
   - Acquire an advisory lock (when `FederationTokenStore` implements `SupportsLock`) to prevent concurrent refresh fan-out.
   - Re-read after the lock — another waiter may have refreshed during the wait.
   - Call `provider.refreshFederationToken(refreshToken)`; persist the result.
   - Release the lock.

### Response

```json
{
  "access_token": "<upstream-IdP-access-token>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "<if-available>"
}
```

### Error responses

| Status | Error | Meaning |
| --- | --- | --- |
| 401 | `invalid_token` | Bearer missing, invalid, wrong type (not `at+jwt`), or family revoked |
| 403 | `forbidden` | Client not opted in via `allowedAzpForFederationToken` |
| 404 | `federation_not_linked` | The named federation isn't linked to this session |
| 410 | `refresh_token_absent` | Stored tokens have no refresh_token (upstream didn't return one at login) |
| 410 | `re_authentication_required` | IdP returned `invalid_grant` — session federation is cleared; user must re-authenticate with the IdP |
| 500 | `refresh_failed` | Generic error from the IdP refresh |
| 503 | `refresh_not_supported` | Provider doesn't implement `SupportsRefresh` |
| 503 | `lock_timeout` | Advisory lock could not be acquired within the wait window |
| 503 | `temporarily_unavailable` | Store outage or IdP 5xx / temporarily_unavailable response |

All error responses set `Cache-Control: no-store` and `Pragma: no-cache`. 401 responses include `WWW-Authenticate: Bearer error="invalid_token"` per RFC 6750.

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

Rationale: federation access_tokens grant access to the user's external resources (Google Drive, GitHub API, etc.). Deny-by-default prevents accidental exposure when a generic OAuth client registration only needs auth.

### Audit events

The following audit events fire on this endpoint:

- `federation.token.success` — on token issuance (details include `refreshed: boolean` to distinguish cache hits from refresh path)
- `federation.token.forbidden` — on 403 (client not opted in)
- `federation.token.family_revoked` — on 401 via revoked family
- `federation.token.refresh_failed` — on provider.refreshFederationToken throwing (non-invalid_grant)
- `federation.token.reauthentication_required` — on `invalid_grant` from IdP

## Migrating from v0.3.x to v0.4.0

v0.4.0 removes passport from this package. The `/oauth/introspect` endpoint now uses `createClientAuthMiddleware(clientRepository)` — a self-hosted RFC 6749 §2.3.1 HTTP Basic + form-encoded client-auth middleware.

### Breaking changes

1. **`createOAuthRouter` signature**: the `passport` option is dropped. Pass `clientRepository: ClientRepository` directly. `oauthModule({ clientRepository, ... })` wires this automatically.
2. **`/introspect` error response**: follows RFC 6749 §5.2 shape `{ error, error_description }`.
3. **`req.oauthClient`** (typed as `PublicClient | undefined`) is attached to the express `Request` by `createClientAuthMiddleware`. Consumers composing this middleware onto their own routes can read it directly — types come via global Express namespace augmentation.

### For consumers

If you consume `@o3co/auth-provider-oauth` via its public API (`oauthModule`, `createOAuthRouter`), no code changes beyond updating your config are required — the module internally wires the new middleware.

If you extend or replace the middleware for custom client-auth schemes, import `createClientAuthMiddleware` from `@o3co/auth-provider-oauth` as a reference, or write a drop-in replacement that attaches a compatible `PublicClient` to `req.oauthClient`.

## See Also

- [`@o3co/auth-provider-session`](../session/README.md) — session login / federation routes
- [`@o3co/auth-provider-did`](../did/README.md) — DID authentication grant
- [`@o3co/auth-provider-core`](../core/README.md) — shared types (`Module`, `GrantRegistry`, `ClientRepository`, `CodeRepository`, `KeyStore`)
