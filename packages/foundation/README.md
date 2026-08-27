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
    maxResponseBytes?: number;      // response body cap, default 1 MiB
  });

  // POST authenticateUrl with body: { email, password }
  authenticate(username: string, password: string): Promise<User | null>;

  // POST authenticateByTokenUrl with body: { token }
  authenticateByToken(token: string): Promise<User | null>;
}
```

- Returns `null` on HTTP 401 or 403.
- Throws an error on any other non-OK HTTP status.
- Throws when the upstream returns 2xx with a body that is not a JSON `User`
  (`{ id: string, username: string, … }`) — an upstream failure, not a
  "user not found".

### Constructor validation

Every option is validated in the **constructor**, so a misconfigured deployment
fails at boot rather than at the first login attempt.

**Both URLs must use `https://`.** They carry plaintext user credentials — a
password on `authenticateUrl`, a token on `authenticateByTokenUrl` — so an
`http://` URL does not merely weaken the connection, it publishes the credential
to every hop on the path.

**The one carve-out is loopback:** `http://` is accepted when the host is
`localhost`, an address in `127.0.0.0/8`, or `[::1]`. That traffic never leaves
the machine, so local development and in-process test fixtures need no
certificate. Every other host must use `https://`, **including private-range
addresses and container-network service names** (`http://10.0.0.5/…`,
`http://user-service/…` are refused): those cross a network the deployment does
not control end to end, and "internal" is not a synonym for "encrypted". URLs
embedding credentials (`https://user:pass@…`) are refused as well.

This is the same rule `oauth.jwt.issuer` applies in
[`@o3co/auth-provider-core`](../core/README.md), with the carve-out widened from
the single address `127.0.0.1` to the whole `127.0.0.0/8` block, and query
strings allowed (an issuer may not carry one; a POST endpoint legitimately may).

**`timeout` must be a positive integer** no greater than `2147483647`
milliseconds. `0`, a negative number, and `NaN` all clamp to "fire immediately"
in `setTimeout` — which would abort every request — and a value above Node's
timer range clamps to 1ms, turning "be patient" into the most impatient setting
available. The deadline covers the whole exchange, **body included**: the body
read is raced against it rather than relying on the abort signal, because
aborting a request does not reliably interrupt a read already in flight. That is
the slow-loris shape — headers arrive promptly, then the body dribbles or stops
— and without the race it hangs forever. A request that outlives the deadline
rejects with a `timed out after <n>ms` error naming the endpoint.

**`maxResponseBytes` must be a positive integer**, defaulting to
`DEFAULT_MAX_RESPONSE_BYTES` (1 MiB). The cap is enforced against
`Content-Length` *and* while streaming, so a Store that omits the header — or
lies in it — is still cut off rather than allowed to exhaust memory.

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
