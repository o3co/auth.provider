# @o3co/auth-provider-session

Session and federation routes module for [auth.provider](../../README.md).

Handles username/password login, logout, and OAuth 2.0 federation (Google, and any provider registered via `FederationRegistry`). Uses Passport.js internally for strategy management.

## Install

This package is **private** — it is not published to npm and is only available within the `auth.provider` monorepo.

```jsonc
// packages/*/package.json
{
  "dependencies": {
    "@o3co/auth-provider-session": "workspace:*"
  }
}
```

Peer dependencies (install separately in the workspace root):

```
express@^5.0.0
passport@^0.7.0               (optional)
passport-local@^1.0.0         (optional)
passport-google-oauth20@^2.0.0 (optional)
```

## Public API

### `sessionModule`

```typescript
function sessionModule(params: {
  userRepository: UserRepository;
  express?: ExpressLike;
}): Module;
```

Top-level module. Mounts session and federation routes onto the Express app.

Routes mounted:

| Method | Path                                              | Description                     |
|--------|---------------------------------------------------|---------------------------------|
| POST   | /session/login                                    | Username / password login       |
| POST   | /session/logout                                   | Session logout                  |
| GET    | /session/oauth/federation/:provider               | Initiate OAuth federation flow  |
| GET    | /session/oauth/federation/:provider/callback      | Federation callback             |

---

### `createPassport`

```typescript
function createPassport(options: {
  pathResolver: PathResolver;
  userRepository: UserRepository;
  config: AppConfig;
}): Promise<PassportStatic>;
```

Creates and configures a Passport instance.

- **LocalStrategy** — authenticates with `username` and `password` fields.
- **GoogleStrategy** — registered when `config.federations.google.enabled` is `true`.

---

### `createGoogleProvider`

```typescript
function createGoogleProvider(config: AppConfig): FederationProvider;
```

Creates a `FederationProvider` for Google OAuth 2.0. The provider reads its client ID, client secret, and callback URL from `config`.

---

### `FederationRegistry`

```typescript
class FederationRegistry {
  register(provider: FederationProvider): void;
  get(name: string): FederationProvider | undefined;
}
```

Registry for federation providers. Pass an instance to `sessionModule` (or populate it before the module initializes) to enable custom providers alongside or instead of the built-in Google provider.

---

### `FederationProvider` (interface)

```typescript
interface FederationProvider {
  name: string;
  strategyName: string;
  scope: string[];
  enabled: boolean;
  validateRedirect(url: string): FederationResult<void>;
  resolveCallbackRedirect(session: unknown): FederationResult<string>;
}
```

Implement this interface to add a custom OAuth 2.0 / OIDC federation provider.

---

### `FederationResult<T>` (type)

```typescript
type FederationResult<T> =
  | { ok: true; value: T }
  | { ok: false; status: number; error: string; errorDescription: string };
```

Discriminated union returned by `FederationProvider` methods. Check `ok` before accessing `value`.

## Usage Example

```typescript
import express from "express";
import { createApp } from "@o3co/auth-provider-core";
import { sessionModule } from "@o3co/auth-provider-session";

const app = createApp(express, {
  config,
  keyStore,
  modules: [
    sessionModule({
      userRepository,
    }),
  ],
});
await app.init();
```

### FederationRegistry

```typescript
import { FederationRegistry } from "@o3co/auth-provider-session";

const registry = new FederationRegistry();
registry.register(myCustomProvider);
```

`FederationRegistry` is used internally by `sessionModule` to manage federation providers. The built-in Google provider is registered automatically when `config.federations.google.enabled` is `true`.

## See Also

- [`@o3co/auth-provider-oauth`](../oauth/README.md) — OAuth 2.0 token and authorization routes
- [`@o3co/auth-provider-did`](../did/README.md) — DID authentication grant
- [`@o3co/auth-provider-core`](../core/README.md) — shared types (`Module`, `UserRepository`, `PathResolver`, `AppConfig`)
