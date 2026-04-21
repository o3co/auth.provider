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

## TODO-F-3 changes

- **`/oauth/introspect` cascading revoke.** When the access token carries a `family_id` claim and `AppOptions.refreshTokenStore` is wired, the introspect endpoint calls `RefreshTokenStore.isFamilyRevoked(familyId)` before returning an active response. If the family is revoked or the store is unreachable, the response is `{ active: false }` (fail-closed, per RFC 7009 §2.1 SHOULD). Tokens minted before F-3 that lack a `family_id` claim bypass this check and are validated by signature only.
- **`family_id` + `sid` data claims.** Both `access_token` and `refresh_token` minted by the `authorization_code` and `refresh_token` grants carry `family_id` (token family for cascading revoke) and `sid` (session ID, when the code record contains it) as JWT claims.
- **`authorization_code` grant — `sid` requirement.** The grant reads `sid` from the `CodeData` record. Deployments must have the F-2/F-3 login wiring in place (local login or federation callback writing `sid` onto the code) for the `sid` claim to be present in issued tokens.
- **`refresh_token` grant — session validation.** When `AppOptions.userSessionStore` is wired and the refresh token carries a `sid` claim, the grant calls `userSessionStore.get(sid)` to verify the session is still active. A missing session returns `400 invalid_grant`; a store error returns `503 temporarily_unavailable`.

## See Also

- [`@o3co/auth-provider-session`](../session/README.md) — session login / federation routes
- [`@o3co/auth-provider-did`](../did/README.md) — DID authentication grant
- [`@o3co/auth-provider-core`](../core/README.md) — shared types (`Module`, `GrantRegistry`, `ClientRepository`, `CodeRepository`, `KeyStore`)
