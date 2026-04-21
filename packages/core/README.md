# @o3co/auth-provider-core

Grant registry, token service, repository interfaces, app config, and module system for auth.provider. This package defines the core abstractions that all other packages build on.

## Install

```sh
npm install @o3co/auth-provider-core
```

Peer dependencies: `express@^5.0.0` (optional — required only when using `createApp`)

## Public API

### Configuration

`AppConfigSchema` is a [Zod](https://zod.dev/) schema that validates the full application configuration. `AppConfig` is the inferred TypeScript type.

```typescript
import { AppConfigSchema, type AppConfig } from "@o3co/auth-provider-core";

const config: AppConfig = AppConfigSchema.parse(rawConfig);
```

Top-level fields:

| Field | Description |
| --- | --- |
| `http.port` | HTTP listen port |
| `http.trustProxy` | Express trust proxy setting |
| `oauth.jwt` | JWT signing config — issuer, signingKey (provider + per-provider sub-section) |
| `oauth.accessToken.expiresIn` | Access token lifetime |
| `oauth.refreshToken.expiresIn` | Refresh token lifetime |
| `oauth.grants` | Per-grant-type config (`session`, `authorization`, `refresh_token`, and custom keys) |
| `session` | Express session — secret, maxAge, secure, sameSite, domain, storage |
| `rateLimit` | Rate limit config for `login`, `token`, and `authorize` endpoints |
| `federations` | Federation providers — `z.record(string, { enabled, type?, ...passthrough })`. Built-in types: `"google"`, `"github"`. |
| `repositories` | Repository config for clients, users, and codes |
| `endpoints` | Path overrides for `login`, `client`, and `authCallback` routes |
| `cors.allowedOrigins` | CORS allowed origins |

### Grant System

The grant system is the extension point for OAuth 2.0 grant types. Each grant type is implemented as a `GrantHandler` and registered via `GrantRegistry`.

#### Interfaces and types

```typescript
interface SessionData {
  user?: Record<string, unknown>;
  client?: Record<string, unknown>;
  code?: string;
  code_client_id?: string;
  granted_scopes?: string[];
  isAuthenticated?: boolean;
}

interface GrantContext {
  body: Record<string, unknown>;
  session: SessionData;
  issuer?: string;
  metadata: Record<string, unknown>;
}

interface GrantSuccess {
  status: number;
  tokens: TokenResponse;
}

interface GrantError {
  status: number;
  error: string;
  errorDescription?: string;
}

type GrantResult = GrantSuccess | GrantError;

interface SessionMutation {
  clear?: string[];
  set?: Record<string, unknown>;
}

interface GrantHandlerResult {
  result: GrantResult;
  sessionMutation?: SessionMutation;
}

interface GrantHandler {
  handle(ctx: GrantContext): Promise<GrantHandlerResult>;
  cleanup?(): void;
}

interface GrantDependencies {
  config: AppConfig;
  keyStore: KeyStore;
  pathResolver?: PathResolver;
}

type GrantFactory = (deps: GrantDependencies) => GrantHandler;

interface GrantModule {
  grants: Record<string, GrantFactory>;
  configSchema?: z.ZodType;
}
```

#### GrantRegistry

```typescript
class GrantRegistry {
  register(grantType: string, handler: GrantHandler): void;
  get(grantType: string): GrantHandler | undefined;
  addModule(module: GrantModule, deps: GrantDependencies): void;
  cleanup(): void;
}
```

`addModule` instantiates all `GrantFactory` entries in the module and registers them. Call `cleanup()` on shutdown to invoke each handler's optional `cleanup()` method.

### Token Utilities

```typescript
interface Token {
  token: string;
  expiresIn?: number;
  subject?: string;
  scope?: string;
  tokenType?: "at+jwt" | "rt+jwt";
  audience?: string;
  issuer?: string;
}

interface TokenResponse {
  access_token: string;
  token_type: string;
  scope?: string;
  refresh_token?: string | null;
  expires_in?: number;
}

interface GenerateTokenOptions {
  expiresIn?: number;
  keyStore: KeyStore;
  issuer?: string | null;
  audience?: string | null;
  subject?: string | null;
  authorizedParty?: string | null;
  scope?: string | null;
  tokenType?: "at+jwt" | "rt+jwt";
}

function generateToken(data: object, options: GenerateTokenOptions): Promise<Token>;
function generateTokenResponse(tokens: { accessToken: Token; refreshToken?: Token }): TokenResponse;
function formatObject<T extends object>(data: T): Partial<T>;
```

`generateToken` signs a JWT using the current signing key from `keyStore`. `generateTokenResponse` formats an access token and optional refresh token into the OAuth 2.0 token endpoint response shape. `formatObject` strips `undefined` values from an object.

### Key Store

The `KeyStore` interface abstracts over symmetric (HS256) and asymmetric (RS256, ES256, EdDSA) signing keys, including key rotation via `previousKeys`. `sign(options)` returns a compact JWT; the KeyStore self-injects the `alg` and `kid` protected header fields, so callers cannot override them. This contract lets remote-sign adapters (KMS/HSM) implement `sign()` without exposing private key material. `getSigningKidFallback()` is a cheap accessor returning the current signing kid for verifying legacy/malformed tokens that lack a `kid` header. Do not use it for rotation-safe lookup.

```typescript
type KeyLike = CryptoKey | KeyObject | Uint8Array;

interface ManagedKey {
  kid: string;
  publicKey: KeyLike;
  expiresAt?: Date;
}

interface JWTPayload {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  jti?: string;
  nbf?: number;
  exp?: number;
  iat?: number;
  [propName: string]: unknown;
}

interface SignJwtOptions {
  claims: JWTPayload;      // RFC 7519 claims
  header?: { typ?: string }; // alg / kid are KeyStore-injected; caller cannot override
}

interface KeyStore {
  readonly algorithm: "HS256" | "RS256" | "ES256" | "EdDSA";
  sign(options: SignJwtOptions): Promise<string>;
  getSigningKidFallback(): string;
  getVerificationKeys(): Promise<ManagedKey[]>;
  getVerificationKey(kid: string): Promise<KeyLike>;
}

interface AsymmetricKeyStoreOptions {
  algorithm: "RS256" | "ES256" | "EdDSA";
  kid: string;
  privateKeyPem: string;
  publicKeyPem: string;
  previousKeys?: Array<{ kid: string; publicKeyPem: string; expiresAt: Date }>;
}

type KeyStoreFactory = AdapterFactory<KeyStore>;

function createAsymmetricKeyStore(options: AsymmetricKeyStoreOptions): Promise<KeyStore>;
function createSymmetricKeyStore(secret: string, kid?: string): KeyStore;
function createKeyStoreFactory(): KeyStoreFactory;
function registerBuiltinKeyStores(factory: KeyStoreFactory): void;
```

`createKeyStoreFactory` creates a new factory with no registered types. `registerBuiltinKeyStores` registers the built-in `"local"` provider, which dispatches to `createAsymmetricKeyStore` or `createSymmetricKeyStore` based on `algorithm`. The factory pattern follows the same `AdapterFactory<T>` contract as `ClientRepository`, `UserRepository`, and `CodeRepository` factories.

### Repositories

Repository interfaces define the data access contract. Built-in in-memory implementations are provided for development and testing.

#### Interfaces and types

```typescript
interface Client {
  clientId: string;
  clientSecret: string;
  allowedRedirectUris: string[];
  allowedScopes: string[];
}

type PublicClient = Omit<Client, "clientSecret">;

interface User {
  id: string;
  username: string;
  [key: string]: unknown;
}

interface CodeData {
  code_challenge?: string;
  code_challenge_method?: string;
}

interface Code extends CodeData {
  code: string;
  expiresIn?: number;
}

interface ClientRepository {
  findById(clientId: string): Promise<PublicClient | null>;
  authenticate(clientId: string, secret: string): Promise<PublicClient | null>;
}

interface UserRepository {
  authenticate(username: string, password: string): Promise<User | null>;
  authenticateByToken(token: string): Promise<User | null>;
}

interface CodeRepository {
  createCode(params: {
    code_challenge?: string;
    code_challenge_method?: string;
    expiresIn?: number;
  }): Promise<Code>;
  getByCode(code: string): Promise<Code | null>;
  consumeByCode(code: string): Promise<Code | null>;
  removeByCode(code: string): Promise<void>;
}
```

#### Built-in implementations

```typescript
class InMemoryClientRepository implements ClientRepository {
  constructor(clients: Map<string, ClientEntry>);
}

class InMemoryUserRepository implements UserRepository {
  constructor(users: Map<string, UserEntry>);
}

class InMemoryCodeRepository implements CodeRepository {
  constructor(options?: { defaultExpiresIn?: number });
  dispose(): void; // clears internal timers
}
```

#### YAML-backed initialization

```typescript
const ClientEntrySchema: z.ZodObject<...>;
const UserEntrySchema: z.ZodObject<...>;

function loadYamlMap<T extends z.ZodTypeAny>(
  filePath: string,
  schema: T
): Map<string, z.infer<T>>;
```

`loadYamlMap` reads a YAML file whose top-level keys are record IDs and validates each entry against `schema`. Pass the result directly to `InMemoryClientRepository` or `InMemoryUserRepository`.

#### Adapter factory primitives

```typescript
interface BuilderContext {
  // Intentionally empty in v1; future additions (logger, tracer, abortSignal, ...)
  // are guaranteed to be optional field additions (additive-only evolution).
}

type AdapterBuilder<T> = (
  config: Record<string, unknown>,
  ctx: BuilderContext,
) => Promise<T> | T;

interface AdapterFactory<T> {
  register(type: string, builder: AdapterBuilder<T>): void;
  create(config: { type: string; [key: string]: unknown }): Promise<T>;
  registeredTypes(): string[];
}

function createAdapterFactory<T>(
  kind: string,
  ctx?: BuilderContext,
): AdapterFactory<T>;

class AdapterFactoryError extends Error {
  readonly kind: string;
  readonly type: string;
  readonly registered: readonly string[];
}

function createDefaultFactories(): {
  clientFactory: AdapterFactory<ClientRepository>;
  userFactory: AdapterFactory<UserRepository>;
  codeFactory: AdapterFactory<CodeRepository>;
};
```

Key contract properties:

- `create()` always returns `Promise<T>`, even for synchronous builders.
- `register()` throws if a `type` is registered twice (silent-override prevention).
- `create()` throws `AdapterFactoryError` when `type` is not registered; the error carries the `kind`, `type`, and `registered` list.
- `BuilderContext` is shared by reference across builder invocations for a given factory. Treat it as read-only from builders.

`createDefaultFactories` returns three factories pre-registered with the built-in `yaml`/`static` (client, user) and `memory` (code) types. Use `registerBuiltinAdapters` from `@o3co/auth-provider-foundation` to add `http` and `redis` adapters, or register your own types to support other backends.

### Module System

Modules extend the app with additional routes, middleware, or grant types. Each module receives a `ModuleContext` during initialization.

```typescript
type PathResolver = (specifier: string) => string;

interface ModuleContext {
  pathResolver: PathResolver;
  config: AppConfig;
  keyStore: KeyStore;
  grantRegistry: GrantRegistry;
  router: Router; // Express Router
}

interface Module {
  name: string;
  init(context: ModuleContext): Promise<void>;
}
```

### App Factory

```typescript
interface AppOptions {
  pathResolver?: PathResolver;
  config: AppConfig;
  keyStore: KeyStore;
  modules: Module[];
}

interface AppResult {
  init(): Promise<void>;
  router: Router;
  grantRegistry: GrantRegistry;
}

function createApp(express: ExpressLike, options: AppOptions): AppResult;
```

`createApp` wires together config, key store, grant registry, and modules into a single Express router. Call `init()` to run all module initializers. The router is ready to mount after `init()` resolves.

Built-in routes registered unconditionally:

- `GET /health` — returns `200 OK`
- `GET /.well-known/jwks.json` — returns the public key set from `keyStore`

`ExpressLike` is a structural type — any object with `Router()`, `json()`, and `urlencoded()` methods satisfies it. Pass the `express` default export directly.

## Usage Example

```typescript
import express from "express";
import {
  AppConfigSchema,
  createApp,
  createDefaultFactories,
  createKeyStoreFactory,
  registerBuiltinKeyStores,
} from "@o3co/auth-provider-core";

const config = AppConfigSchema.parse(rawConfig);

// Both repositories.* (uses 'type') and oauth.jwt.signingKey (uses 'provider') follow
// the same nested adapter sub-section pattern. flatten() normalises either selector
// to { type, ...subSectionFields } before forwarding to the factory:
const flatten = (
  section: ({ type: string } | { provider: string }) & Record<string, unknown>,
) => {
  const selector =
    (section as { type?: string; provider?: string }).type
    ?? (section as { provider?: string }).provider;
  if (typeof selector !== "string") {
    throw new TypeError("flatten: section requires 'type' or 'provider' string");
  }
  const sub = section[selector];
  const flattenedSub =
    typeof sub === "object" && sub !== null && !Array.isArray(sub)
      ? (sub as Record<string, unknown>)
      : {};
  return { type: selector, ...flattenedSub };
};

const keyStoreFactory = createKeyStoreFactory();
registerBuiltinKeyStores(keyStoreFactory);
const keyStore = await keyStoreFactory.create(flatten(config.oauth.jwt.signingKey));

const { clientFactory, userFactory, codeFactory } = createDefaultFactories();

const clientRepository = await clientFactory.create(flatten(config.repositories.client));
const userRepository = await userFactory.create(flatten(config.repositories.user));
const codeRepository = await codeFactory.create(flatten(config.repositories.code));

const app = createApp(express, {
  config,
  keyStore,
  modules: [
    // additional modules go here
  ],
});

await app.init();

const server = express();
server.use(app.router);
server.listen(config.http.port);
```

### Implementing a custom grant type

```typescript
import type {
  GrantFactory,
  GrantHandler,
  GrantModule,
} from "@o3co/auth-provider-core";

const myGrantFactory: GrantFactory = (deps) => ({
  async handle(ctx) {
    const token = await generateToken({}, {
      keyStore: deps.keyStore,
      subject: "user-id",
      tokenType: "at+jwt",
    });
    return {
      result: { status: 200, tokens: generateTokenResponse({ accessToken: token }) },
    };
  },
});

const myGrantModule: GrantModule = {
  grants: { my_grant: myGrantFactory },
};
```

Pass `myGrantModule` to `GrantRegistry.addModule()` or include it as a module that calls `context.grantRegistry.addModule()` in `init()`.

### Loading clients and users from YAML

```typescript
import {
  loadYamlMap,
  ClientEntrySchema,
  UserEntrySchema,
  InMemoryClientRepository,
  InMemoryUserRepository,
} from "@o3co/auth-provider-core";

const clients = loadYamlMap("./clients.yaml", ClientEntrySchema);
const users = loadYamlMap("./users.yaml", UserEntrySchema);

const clientRepo = new InMemoryClientRepository(clients);
const userRepo = new InMemoryUserRepository(users);
```

## See Also

- Root [README](../../README.md) — architecture overview, configuration reference, Docker setup
- [`@o3co/auth-provider-oauth`](../oauth/README.md) — OAuth 2.0 endpoints (authorization, token, introspection)
- [`@o3co/auth-provider-session`](../session/README.md) — session-based login flow
- [`@o3co/auth-provider-foundation`](../foundation/README.md) — shared middleware and utilities
