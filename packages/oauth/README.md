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
passport@^0.7.0                       (optional)
passport-oauth2-client-password@^0.1.2 (optional)
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
    passport: PassportStatic;
    registry: GrantRegistry;
    config: AppConfig;
    clientRepository: ClientRepository;
    codeRepository: CodeRepository;
    keyStore: KeyStore;
  }
): Promise<{ router: Router; registry: GrantRegistry }>;
```

Low-level factory. Creates the Express router and the fully-configured grant registry. Called internally by `oauthModule`; use directly when you need access to the registry instance after construction.

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

## See Also

- [`@o3co/auth-provider-session`](../session/README.md) — session login / federation routes
- [`@o3co/auth-provider-did`](../did/README.md) — DID authentication grant
- [`@o3co/auth-provider-core`](../core/README.md) — shared types (`Module`, `GrantRegistry`, `ClientRepository`, `CodeRepository`, `KeyStore`)
