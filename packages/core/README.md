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
| `oauth.jwt` | JWT signing config — algorithm, kid, keys, issuer, previousKeys |
| `oauth.accessToken.expiresIn` | Access token lifetime |
| `oauth.refreshToken.expiresIn` | Refresh token lifetime |
| `oauth.grants` | Per-grant-type config (`session`, `authorization`, `refresh_token`, and custom keys) |
| `session` | Express session — secret, maxAge, secure, sameSite, domain, storage |
| `rateLimit` | Rate limit config for `login`, `token`, and `authorize` endpoints |
| `federations.google` | Google federation config |
| `clients` | Repository config for clients, users, and codes |
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

The `KeyStore` interface abstracts over symmetric (HS256) and asymmetric (RS256, ES256, EdDSA) signing keys, including key rotation via `previousKeys`.

```typescript
type KeyLike = CryptoKey | KeyObject | Uint8Array;

interface ManagedKey {
  kid: string;
  publicKey: KeyLike;
  expiresAt?: Date;
}

interface KeyStore {
  readonly algorithm: "HS256" | "RS256" | "ES256" | "EdDSA";
  readonly current: {
    readonly kid: string;
    readonly privateKey: KeyLike;
    readonly publicKey: KeyLike;
  };
  readonly previous: readonly ManagedKey[];
  getSigningKey(): { kid: string; privateKey: KeyLike };
  getVerificationKeys(): ManagedKey[];
  getVerificationKey(kid: string): KeyLike;
}

interface AsymmetricKeyStoreOptions {
  algorithm: "RS256" | "ES256" | "EdDSA";
  kid: string;
  privateKeyPem: string;
  publicKeyPem: string;
  previousKeys?: Array<{ kid: string; publicKeyPem: string; expiresAt: Date }>;
}

interface JwtConfig {
  algorithm: "HS256" | "RS256" | "ES256" | "EdDSA";
  secret?: string;
  kid: string;
  issuer?: string;
  privateKey?: string;
  privateKeyPath?: string;
  publicKey?: string;
  publicKeyPath?: string;
  previousKeys: Array<{
    kid: string;
    publicKey?: string;
    publicKeyPath?: string;
    expiresAt: string;
  }>;
}

function createAsymmetricKeyStore(options: AsymmetricKeyStoreOptions): Promise<KeyStore>;
function createSymmetricKeyStore(secret: string, kid?: string): KeyStore;
function createKeyStoreFromConfig(config: JwtConfig): Promise<KeyStore>;
```

`createKeyStoreFromConfig` is the recommended entry point — it reads `JwtConfig` (which matches `AppConfig.oauth.jwt`) and dispatches to the appropriate factory.

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

#### Repository factory

```typescript
type RepositoryBuilder<T> = (config: Record<string, unknown>) => Promise<T> | T;

class RepositoryFactory<T> {
  constructor(label: string);
  register(type: string, builder: RepositoryBuilder<T>): void;
  create(config: { type: string; [key: string]: unknown }): Promise<T>;
}

function createDefaultFactories(): {
  clientFactory: RepositoryFactory<ClientRepository>;
  userFactory: RepositoryFactory<UserRepository>;
  codeFactory: RepositoryFactory<CodeRepository>;
};
```

`createDefaultFactories` returns three factories pre-registered with the built-in `in-memory` type. Register additional types to support other backends (e.g. a database-backed implementation).

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
  createKeyStoreFromConfig,
  createDefaultFactories,
} from "@o3co/auth-provider-core";

const config = AppConfigSchema.parse(rawConfig);
const keyStore = await createKeyStoreFromConfig(config.oauth.jwt);
const { clientFactory, userFactory, codeFactory } = createDefaultFactories();

const clientRepository = await clientFactory.create(config.clients.client);
const userRepository = await userFactory.create(config.clients.user);
const codeRepository = await codeFactory.create(config.clients.code);

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
