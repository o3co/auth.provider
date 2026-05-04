# @o3co/auth-provider-foundation

Production HTTP user-authentication adapter for auth.provider. Registers the `"http"` adapter type into a `UserRepository` factory, which delegates `authenticate` / `authenticateByToken` to an upstream HTTP service.

This package's scope is **production non-database / external-service adapters** for the v0.5.0 module system. As of v0.5.0 it ships exactly one such adapter (`HttpUserRepository`); the previous Redis `CodeRepository` adapter was relocated to [`@o3co/auth-provider-redis`](../redis/README.md) in Phase 10.

## Install

```sh
npm install @o3co/auth-provider-foundation
# Peer dependency (required):
npm install @o3co/auth-provider-core
```

## Public API

### `registerBuiltinAdapters`

Registers the `"http"` adapter type into the provided `userFactory`.

```typescript
function registerBuiltinAdapters(factories: {
  userFactory: AdapterFactory<UserRepository>;
}): void;
```

For Redis-backed code storage, register the builder from `@o3co/auth-provider-redis` directly:

```typescript
import { redisCodeRepositoryBuilder } from "@o3co/auth-provider-redis";
codeFactory.register("redis", redisCodeRepositoryBuilder);
```

### `HttpUserRepository`

A `UserRepository` implementation that delegates authentication to an upstream HTTP service.

```typescript
class HttpUserRepository implements UserRepository {
  constructor(options: {
    authenticateUrl: string;        // POST endpoint for username/password auth
    authenticateByTokenUrl: string; // POST endpoint for token-based auth
    timeout: number;                // request timeout in milliseconds
  });

  // POST authenticateUrl with body: { email, password }
  authenticate(username: string, password: string): Promise<User | null>;

  // POST authenticateByTokenUrl with body: { token }
  authenticateByToken(token: string): Promise<User | null>;
}
```

- Returns `null` on HTTP 401 or 403.
- Throws an error on any other non-OK HTTP status.

## Usage Example

```typescript
import { createRepositoryFactories } from "@o3co/auth-provider-core";
import { registerBuiltinAdapters } from "@o3co/auth-provider-foundation";

const { userFactory } = createRepositoryFactories();

registerBuiltinAdapters({ userFactory });

// Create an HTTP user repository via the factory
const userRepo = await userFactory.create({
  type: "http",
  authenticateUrl: "https://users.example.com/authenticate",
  authenticateByTokenUrl: "https://users.example.com/authenticate-by-token",
  timeout: 5000,
});
```

## See Also

- [`@o3co/auth-provider-core`](../core/README.md) — Core interfaces (`UserRepository`, `CodeRepository`, `AdapterFactory`, `createAdapterFactory`, `BuilderContext`, `PathResolver`)
- [`@o3co/auth-provider-redis`](../redis/README.md) — Redis-backed adapters (challenges, replay-seen-set, refresh-token-family, user-sessions, federation-tokens, **code-repository**, rate-limiter)
- [auth.provider](../../README.md) — Top-level repository documentation
