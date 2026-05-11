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

The grant system is the extension point for OAuth 2.0 grant types. Each grant type is implemented as a `GrantHandler` and declared on a module via `contributes.grants`; the boot planner instantiates and registers handlers internally.

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

#### Grant registration

Grant handlers are wired into the boot planner via `contributes.grants` on a module's `defineModule` manifest (see A2-γ §3.3). The boot planner instantiates each `GrantFactory`, registers the resulting handler, and (after `addModule` for all modules) calls `freeze()` so post-boot mutation throws loudly.

Consumer code does NOT need to import or instantiate any registry class. Cleanup of grant handlers runs through the unified `handle.dispose()` returned by `createApp` — `AppHandle.dispose()` runs per-component `lifecycle[K].cleanup` callbacks in reverse-topological order per A2-β §8.1.

> **Removed at 1.0 GA**: the `GrantRegistry` and `GrantRegistryError` classes (deprecated as public re-exports in v0.5.1 per AS-8) are no longer exported from `@o3co/auth-provider-core`. They remain as internal implementation detail of the boot planner. Existing consumers of the v0.4.x `new GrantRegistry()` pattern should migrate to module-based `contributes.grants` declarations.

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

The `KeyStore` interface abstracts over symmetric (HS256) and asymmetric (RS256, ES256, EdDSA) signing keys, including key rotation. Rotation is shape-specific: asymmetric algorithms use `previousKeys` (kid + publicKey + expiresAt), and HS256 uses `previousSecrets` (kid + secret + expiresAt). `getVerificationKey(kid)` resolves the key by kid — the keystore returns the matching key directly, never trial-verifies across keys. `sign(options)` returns a compact JWT; the KeyStore self-injects the `alg` and `kid` protected header fields, so callers cannot override them. This contract lets remote-sign adapters (KMS/HSM) implement `sign()` without exposing private key material. `getSigningKidFallback()` is a cheap accessor returning the current signing kid for verifying legacy/malformed tokens that lack a `kid` header. Do not use it for rotation-safe lookup.

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

interface SymmetricPreviousSecret {
  kid: string;
  secret: string;
  expiresAt: Date;
}

function createAsymmetricKeyStore(options: AsymmetricKeyStoreOptions): Promise<KeyStore>;
function createSymmetricKeyStore(
  secret: string,
  kid?: string,
  previousSecrets?: ReadonlyArray<SymmetricPreviousSecret>,
): KeyStore;
function createKeyStoreFactory(): KeyStoreFactory;
function registerBuiltinKeyStores(factory: KeyStoreFactory): void;
```

`createKeyStoreFactory` creates a new factory with no registered types. `registerBuiltinKeyStores` registers the built-in `"local"` provider, which dispatches to `createAsymmetricKeyStore` or `createSymmetricKeyStore` based on `algorithm`. The factory pattern follows the same `AdapterFactory<T>` contract as `ClientRepository`, `UserRepository`, and `CodeRepository` factories.

#### HS256 key rotation (IH-9)

To rotate an HS256 signing key without a maintenance window:

1. Record the current `kid` and `secret` values.
2. Generate a new secret: `openssl rand -hex 32`.
3. Update `application.conf` to set the new `kid` + `secret` and move the old pair into `previousSecrets`:

   ```hocon
   oauth.jwt.signingKey.local {
     algorithm = "HS256"
     kid = "v1"           # new kid
     secret = "<new-secret>"
     previousSecrets = [{
       kid = "v0"          # old kid
       secret = "<old-secret>"
       expiresAt = "2026-06-05T00:00:00Z"  # access-token TTL + buffer
     }]
   }
   ```

4. Restart the server. Tokens signed by `v0` continue to verify (resolved by `kid` from the JWT header) until `expiresAt`.
5. After the overlap window passes (all `v0` tokens have expired), remove `v0` from `previousSecrets` and restart again.

The schema rejects mixing the asymmetric `previousKeys` shape with HS256 — operators on RS256/ES256/EdDSA use the existing `previousKeys` field instead.

### Repositories

Repository interfaces define the data access contract. Built-in in-memory implementations are provided for development and testing.

#### Interfaces and types

```typescript
interface Client {
  clientId: string;
  clientSecret: string;
  allowedRedirectUris: string[];
  allowedScopes: string[];
  // Logout metadata (TODO-F-5):
  postLogoutRedirectUris?: string[];
  backchannelLogoutUri?: string;
  backchannelLogoutSessionRequired?: boolean; // default: true
  frontchannelLogoutUri?: string;
  frontchannelLogoutSessionRequired?: boolean; // default: true
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
  findByCode(code: string): Promise<Code | null>;
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

function createRepositoryFactories(): {
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

`createRepositoryFactories` returns three factories pre-registered with the built-in `yaml`/`static` (client, user) and `memory` (code) types. Use `registerBuiltinAdapters` from `@o3co/auth-provider-foundation` to add the `http` user-authentication adapter, or register your own types to support other backends. For Redis-backed code/store adapters, see `@o3co/auth-provider-redis`.

### Module System

Modules extend the app with additional routes, grant handlers, or DI-graph
components. v0.5.0 modules are declarative manifests authored via
`defineModule({...})` — they declare `requires` / `optional` (typed
`ProviderDeps` keys) and contribute to `ContributesMap` slots like
`grants`, `routes`, `federations`.

```typescript
type PathResolver = (specifier: string) => string;

const myModule = defineModule({
  name: "my-module",
  requires: ["config", "clientRepository"] as const,
  contributes: {
    routes: [
      (deps) => ({ id: "my-route", mountPath: "/my", handler: makeRouter(deps) }),
    ],
  },
});
```

> Note: the v0.4.x `LegacyModule` / `ModuleContext` shape (a function
> returning `{ name, init(context) }`) was removed in Phase 9 of the
> v0.5.0 redesign. The boot planner injects typed deps directly into the
> contribution lambdas; modules no longer mutate a shared `ModuleContext`.

### App Factory

```typescript
interface CreateAppOptions {
  modules: readonly Module[];
  bootstrapComponents: { config: AppConfig; pathResolver: PathResolver };
  contributionKinds?: ContributionKindMap;
  overrideComponents?: Partial<ComponentMap>;
}

interface AppHandle {
  router: Router;
  components: Partial<ComponentMap>;
  routes: readonly OrderedRouteContribution[];
  listen(port: number): Promise<HttpServer>;
  dispose(): Promise<void>;
}

function createApp(options: CreateAppOptions): Promise<AppHandle>;
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
  createRepositoryFactories,
  createKeyStoreFactory,
  defineModule,
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

const { clientFactory, userFactory, codeFactory } = createRepositoryFactories();

const clientRepository = await clientFactory.create(flatten(config.repositories.client));
const userRepository = await userFactory.create(flatten(config.repositories.user));
const codeRepository = await codeFactory.create(flatten(config.repositories.code));

const localComponentsModule = defineModule({
  name: "local-components",
  provides: {
    keyStore: () => keyStore,
    clientRepository: () => clientRepository,
    userRepository: () => userRepository,
    codeRepository: () => codeRepository,
  },
});

const handle = await createApp({
  modules: [
    localComponentsModule,
    // additional modules go here
  ],
  bootstrapComponents: { config, pathResolver: import.meta.resolve },
});

const server = express();
server.use(handle.router);
server.listen(config.http.port);
```

### Implementing a custom grant type

```typescript
import { defineModule } from "@o3co/auth-provider-core";
import type { GrantFactory, GrantHandler } from "@o3co/auth-provider-core";

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

const myGrantModule = defineModule({
  name: "my-grant",
  requires: ["keyStore"],
  contributes: {
    grants: { my_grant: myGrantFactory },
  },
});
```

Add `myGrantModule` to the `modules` array passed to `createApp`. The boot planner registers the grant through the `contributes.grants` projection per A2-γ Amendment 3 (`grantHandlerResolver` synthetic key).

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

### Extension points (v0.4.0)

Five extension points introduced in v0.4.0 (see
`.claude/superpowers/specs/2026-04-21-extension-surface-decisions-design.md`).

#### MFA

- `MfaProvider`, optional `SupportsEnrollment` / `SupportsRevocation` capabilities
- Factory: `createMfaProviderFactory()`, type guards `supportsEnrollment()` / `supportsRevocation()`
- Flow: `/oauth/authorize` + `/auth/federation/callback` consult `MfaCoordinator.listEnrolled(userId)`; on MFA required, transaction saved via `MfaTransactionStore`, user posts to `POST /auth/mfa/verify { transaction_id, proof }`, core dispatches via `providerKind`
- No built-in providers in v0.4.0 — TOTP / WebAuthn / backup codes ship in later spec

#### Audit

- `AuditSink.record(event)` fire-and-forget
- Factory: `createAuditSinkFactory()`, built-in `"console"` via `registerBuiltinAuditSinks()`
- Errors swallowed by core — audit failure never blocks auth flow

#### Rate limiter

- `RateLimiter.check(key, ctx)` atomic check + increment
- Factory: `createRateLimiterFactory()`, built-in `"memory"` and `"redis"` via `registerBuiltinRateLimiters()`
- 429 + `Retry-After` emitted by core on denial
- The built-in `"redis"` limiter requires `config.client` matching `{ incr(key): Promise<number>; expire(key, seconds): Promise<number> }`. Core does not depend on the `redis` package and does not create its own client (`RateLimiter` has no disposal hook — lifecycle stays with the consumer). Any redis-compatible client satisfying that shape works.

#### RefreshTokenStore (RFC 6819 §5.2.2.3 replay detection)

- `RefreshTokenStoreBase.rotate(previousJti, newJti, familyId, expiresAt)` atomic primitive
- All `rt+jwt` tokens carry `family_id` claim (always emitted, backward-compatible)
- Optional: set `AppOptions.refreshTokenStore` to enable replay detection + family revocation

#### GrantPolicyHook (scope / audience / token exchange policy)

- `GrantPolicyHook.evaluate(request, ctx)` returns allow (with optional narrowing) or deny
- `/oauth/authorize` evaluates once; `/oauth/token` re-uses `grantedScope` / `grantedAudience` persisted on the Code record (no re-evaluation for `authorization_code`)
- Other grants (refresh / client_credentials / token-exchange) evaluate at the token endpoint

All five adapters are optional — absence = no-op default.

### UserSessionStore / FederationTokenStore (TODO-F)

Two new optional `AppOptions` fields introduced for federation + OIDC support:

- `userSessionStore`: sid-keyed session metadata (auth_time, active RPs, family IDs, OIDC claims). Built-in adapters: `memory`, `redis`.
- `federationTokenStore`: `(sid, federationName)`-keyed upstream IdP tokens. Built-in adapters: `memory`, `redis` (with mandatory AES-256-GCM encryption of refresh_token; `allow-plaintext` is opt-in and emits a warning).

Both stores are consumed by upcoming TODO-F-3 (cascading revocation), F-4 (id_token + /userinfo), F-5 (logout), and F-6 (/oauth/federation/:name/token). This plan (F-1) only adds the plumbing. See [the TODO-F spec](../../.claude/superpowers/specs/2026-04-21-todo-f-federation-token-lifecycle-design.md) for the full interface + encryption contract.

**F-3 consumers activated.** `CodeData` now carries two optional fields wired by the login paths:

- `nonce?` — OIDC nonce forwarded from the authorization request, persisted on the code record for later `id_token`/`userinfo` use.
- `sid?` — Session ID (`UserSession.sid`) written by the login handler and used to bind minted tokens to the session.

The `CodeRepository.createCode` params and `InMemoryCodeRepository` accept `nonce`, `sid`, and `grantedScope` in the same call. Consumers (the `authorization_code` grant) read `codeData.grantedScope` (set by `GrantPolicyHook` at `/oauth/authorize`) as the authoritative scope for token minting instead of `session.granted_scopes`.

### OIDC id_token + claim filter (TODO-F-4)

Two low-level helpers used by the `authorization_code` grant and the `/oauth/userinfo` endpoint.

#### `generateIdToken`

```typescript
interface GenerateIdTokenOptions {
  readonly sub: string;
  readonly aud: string;
  readonly azp?: string;
  readonly authTime: Date;
  readonly nonce?: string;
  readonly sid: string;
  readonly scopes: ReadonlyArray<string>;
  readonly userClaims: UserSessionClaims;
  readonly keyStore: KeyStore;
  readonly issuer: string;
  readonly expiresIn?: number; // default 3600 s
}

function generateIdToken(opts: GenerateIdTokenOptions): Promise<Token>;
```

Signs and returns an OIDC id_token JWT (OIDC Core §2). Claim composition:

- `iss`, `sub`, `aud`, `exp`, `iat`, `jti` — standard JWT claims
- `auth_time` — seconds since epoch, from `opts.authTime`
- `sid` — session identifier for back-channel logout (TODO-F-5)
- `azp` — authorized party, included when provided
- `nonce` — reflected verbatim from the authorization request when provided
- scope-filtered user claims via `filterClaimsByScope`

Header uses `typ: "id+jwt"` as an introspection convenience hint.

#### `filterClaimsByScope`

```typescript
function filterClaimsByScope(
  claims: UserSessionClaims,
  scopes: ReadonlyArray<string>,
): Record<string, unknown>;
```

Maps `UserSessionClaims` to the JWT-shaped claim subset that the granted scopes authorize. Strict whitelist — only the mappings in the table below are emitted; any other `UserSessionClaims` fields (e.g. provider-specific fields like `hd`) are never forwarded.

| Scope | Emitted claims |
| --- | --- |
| `openid` | *(no claims — governs id_token issuance; `sub` is added by `generateIdToken`)* |
| `profile` | `name`, `picture` |
| `email` | `email`, `email_verified` |
| `groups` | `groups` |

#### `/.well-known/openid-configuration`

OIDC Discovery 1.0 metadata endpoint. Registered by the OAuth module (`@o3co/auth-provider-oauth`) when `config.oauth.jwt.issuer` is configured. When registered, it returns a JSON document advertising:

- `issuer`, `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `introspection_endpoint`
- `jwks_uri` — only advertised when at least one asymmetric signing alg is configured (omitted for HS256-only deployments since the JWKS route returns 404 for symmetric keys)
- `response_types_supported: ["code"]`
- `subject_types_supported: ["public"]`
- `id_token_signing_alg_values_supported` — derived from the configured `KeyStore.algorithm`
- `scopes_supported: ["openid", "profile", "email", "groups"]`
- `token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"]`
- `code_challenge_methods_supported: ["S256"]`
- `end_session_endpoint` — added in TODO-F-5
- `backchannel_logout_supported: true` — added in TODO-F-5
- `backchannel_logout_session_supported: true` — added in TODO-F-5
- `frontchannel_logout_supported: true` — added in TODO-F-5
- `frontchannel_logout_session_supported: true` — added in TODO-F-5

### Logout helpers (TODO-F-5)

Low-level helpers used by `POST /oauth/logout` in `@o3co/auth-provider-oauth`.

#### `generateLogoutToken`

```typescript
interface GenerateLogoutTokenOptions {
  readonly issuer: string;
  readonly sub: string;
  readonly aud: string | string[];
  readonly sid?: string;
  readonly includeSid?: boolean; // default true
  readonly keyStore: KeyStore;
  readonly expiresIn?: number; // default 300 s
}

function generateLogoutToken(opts: GenerateLogoutTokenOptions): Promise<Token>;
```

Generates a signed `logout_token` JWT (OIDC Back-Channel Logout 1.0 §2.4). Header `typ: logout+jwt`. Claim composition: `iss`, `sub`, `aud`, `iat`, `exp`, `jti`, and `events` carrying `{ [BACKCHANNEL_LOGOUT_EVENT_URI]: {} }`. The `sid` claim is included by default; set `includeSid: false` for RPs registered with `backchannel_logout_session_required: false`. Default TTL is 300 s. The `nonce` claim is never included (spec §2.4 requirement).

#### `BACKCHANNEL_LOGOUT_EVENT_URI`

```typescript
const BACKCHANNEL_LOGOUT_EVENT_URI: "http://schemas.openid.net/event/backchannel-logout";
```

The canonical event URI required in every `logout_token`'s `events` claim. Exported so downstream code and tests can reference it without re-literalizing.

#### `Logger`

```typescript
interface Logger {
  warn(message: string, ...args: unknown[]): void;
}
```

Minimal structural logger interface accepted by `cascadeLogout`, `broadcastBackchannelLogout`, and other internal call sites. Structurally compatible with `console`, pino, winston, bunyan, etc. Additional methods (`info`, `error`, `debug`) are added when an internal consumer needs them.

### Federation token capabilities (TODO-F-6)

Low-level building blocks used by `POST /oauth/federation/:name/token` in `@o3co/auth-provider-oauth`.

The lock primitives below (`createInProcessLock`, `createRedisLock`) are **internal implementation details** of the built-in adapters and are not exported from `@o3co/auth-provider-core`'s public entrypoint. Custom stores that need locking should expose the public `SupportsLock` capability rather than depending on these internal helpers.

- `SupportsLock` — optional capability on `FederationTokenStore` for per-`(sid, federationName)` advisory locks. Used to prevent concurrent-refresh thundering herds. Built-in memory and redis adapters both implement this capability. Consumers detect it via the `supportsLock(store)` type guard.
- `createInProcessLock()` — internal in-memory lock implementation used by the built-in memory adapter. Not exported from `@o3co/auth-provider-core`'s public entrypoint.
- `createRedisLock({ client, keyPrefix })` — internal redis-backed lock implementation used by the built-in redis adapter. Not exported from the public entrypoint. Custom stores that need locking should expose the public `SupportsLock` capability rather than depending on this internal helper.
- `Client.allowedAzpForFederationToken` — opt-in flag on the `Client` interface; default `false`. Clients that consume `POST /oauth/federation/:name/token` must set this to `true`.

## See Also

- Root [README](../../README.md) — architecture overview, configuration reference, Docker setup
- [`@o3co/auth-provider-oauth`](../oauth/README.md) — OAuth 2.0 endpoints (authorization, token, introspection)
- [`@o3co/auth-provider-session`](../session/README.md) — session-based login flow
- [`@o3co/auth-provider-foundation`](../foundation/README.md) — shared middleware and utilities
