# @o3co/auth-provider-foundation

Built-in repository implementations for auth.provider. Provides HTTP-based user authentication and Redis-backed authorization code storage.

## Install

```sh
npm install @o3co/auth-provider-foundation
# Peer dependency (required):
npm install @o3co/auth-provider-core
# Peer dependency (optional — required only when using RedisCodeRepository):
npm install redis
```

## Public API

### `registerBuiltinAdapters`

Registers the built-in adapter factories into the provided factory instances.

- Registers `"http"` into `userFactory` → creates `HttpUserRepository`
- Registers `"redis"` into `codeFactory` → creates `RedisCodeRepository`

```typescript
function registerBuiltinAdapters(factories: {
  userFactory: AdapterFactory<UserRepository>;
  codeFactory: AdapterFactory<CodeRepository>;
  pathResolver?: PathResolver; // optional — used to resolve the "redis" module path
}): void;
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

### `RedisCodeRepository`

A `CodeRepository` implementation that stores authorization codes in Redis. Keys are stored as `oauth:code:<base64url-code>` with a configurable TTL.

```typescript
class RedisCodeRepository implements CodeRepository {
  constructor(redis: RedisClient, defaultExpiresIn?: number); // defaultExpiresIn defaults to 600 seconds

  // Factory method — creates and connects a Redis client from config
  static create(
    config: Record<string, unknown>,
    pathResolver?: PathResolver,
  ): Promise<RedisCodeRepository>;
  // config keys:
  //   endpointUri (string, required) — Redis connection URI
  //   password    (string, optional) — Redis password
  //   defaultExpiresIn (number, optional) — TTL in seconds, default 600

  initialize(): Promise<void>;   // connects the Redis client
  createCode(params: {
    code_challenge?: string;
    code_challenge_method?: string;
    expiresIn?: number;          // overrides defaultExpiresIn for this code
  }): Promise<Code>;
  getByCode(code: string): Promise<Code | null>;
  consumeByCode(code: string): Promise<Code | null>; // atomic GET + DEL
  removeByCode(code: string): Promise<void>;
}
```

## Usage Example

```typescript
import { createDefaultFactories } from "@o3co/auth-provider-core";
import { registerBuiltinAdapters } from "@o3co/auth-provider-foundation";

const { userFactory, codeFactory } = createDefaultFactories();

registerBuiltinAdapters({ userFactory, codeFactory });

// Create an HTTP user repository via the factory
const userRepo = await userFactory.create({
  type: "http",
  authenticateUrl: "https://users.example.com/authenticate",
  authenticateByTokenUrl: "https://users.example.com/authenticate-by-token",
  timeout: 5000,
});

// Create a Redis code repository via the factory
const codeRepo = await codeFactory.create({
  type: "redis",
  endpointUri: "redis://localhost:6379",
  defaultExpiresIn: 300,
});
```

## See Also

- [`@o3co/auth-provider-core`](../core/README.md) — Core interfaces (`UserRepository`, `CodeRepository`, `AdapterFactory`, `createAdapterFactory`, `BuilderContext`, `PathResolver`)
- [auth.provider](../../README.md) — Top-level repository documentation
