# @o3co/auth-provider-core

auth.provider のグラント登録、トークンサービス、リポジトリインターフェース、アプリ設定、およびモジュールシステムを提供するパッケージです。他のすべてのパッケージが依存するコア抽象を定義しています。

## インストール

```sh
npm install @o3co/auth-provider-core
```

Peer dependency: `express@^5.0.0`（任意 — `createApp` を使う場合のみ必要）

## パブリック API

### 設定

`AppConfigSchema` はアプリケーション全体の設定を検証する [Zod](https://zod.dev/) スキーマです。`AppConfig` はそこから推論される TypeScript 型です。

```typescript
import { AppConfigSchema, type AppConfig } from "@o3co/auth-provider-core";

const config: AppConfig = AppConfigSchema.parse(rawConfig);
```

トップレベルのフィールド:

| フィールド | 説明 |
| --- | --- |
| `http.port` | HTTP リッスンポート |
| `http.trustProxy` | Express の trust proxy 設定 |
| `oauth.jwt` | JWT 署名設定 — issuer、signingKey（provider + プロバイダーごとのサブセクション） |
| `oauth.accessToken.expiresIn` | アクセストークンの有効期間 |
| `oauth.refreshToken.expiresIn` | リフレッシュトークンの有効期間 |
| `oauth.grants` | グラントタイプごとの設定（`session`、`authorization`、`refresh_token`、カスタムキー） |
| `session` | Express セッション設定 — secret、maxAge、secure、sameSite、domain、storage |
| `rateLimit` | `login`、`token`、`authorize` エンドポイントのレート制限設定 |
| `federations` | フェデレーションプロバイダー — `z.record(string, { enabled, type?, ...passthrough })`。組み込みタイプ: `"google"`, `"github"`。 |
| `repositories` | client、user、code の Repository 設定 |
| `endpoints` | `login`、`client`、`authCallback` ルートのパスオーバーライド |
| `cors.allowedOrigins` | CORS 許可オリジン |

### グラントシステム

グラントシステムは OAuth 2.0 グラントタイプの拡張ポイントです。各グラントタイプは `GrantHandler` として実装し、モジュールの `contributes.grants` で宣言します。ハンドラーの実体化と登録は boot planner が内部で行います。

#### インターフェースと型

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

#### グラントハンドラーの登録

グラントハンドラーは `defineModule` マニフェストの `contributes.grants` から boot planner に渡されます（A2-γ §3.3 参照）。Boot planner が各 `GrantFactory` を実体化し、ハンドラーを登録した後、全モジュール処理を終えてから `freeze()` を呼び出すため、boot 後の変異は loud に throw します。

コンシューマコードはレジストリクラスを import / 実体化する必要はありません。グラントハンドラーのクリーンアップは `createApp` が返す `handle.dispose()` に統合されており、`AppHandle.dispose()` は A2-β §8.1 に従い、コンポーネント単位の `lifecycle[K].cleanup` コールバックを reverse-topological 順で実行します。

> **削除済み**: `GrantRegistry` / `GrantRegistryError` クラス（v0.5.1 で AS-8 に基づき public re-export として deprecated 済み）は `@o3co/auth-provider-core` から export されなくなりました。クラスは boot planner の internal 実装として残っています。v0.4.x の `new GrantRegistry()` パターンを使っていたコンシューマは、モジュールの `contributes.grants` 宣言に移行してください。削除を行ったリリースは CHANGELOG を参照。

### トークンユーティリティ

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

`generateToken` は `keyStore` の現在の署名鍵を使って JWT に署名します。`generateTokenResponse` はアクセストークンとオプションのリフレッシュトークンを OAuth 2.0 トークンエンドポイントのレスポンス形式に変換します。`formatObject` はオブジェクトから `undefined` の値を除去します。

### キーストア

`KeyStore` インターフェースは、対称鍵（HS256）と非対称鍵（RS256、ES256、EdDSA）の署名鍵を抽象化し、`previousKeys` によるキーローテーションをサポートします。`sign(options)` は compact JWT を返す。protected header の `alg` / `kid` は KeyStore 側で自動注入されるため、caller からの上書き不可。この契約により、private key を露出せずに remote-sign adapter (KMS/HSM) が `sign()` を実装できる。`getSigningKidFallback()` は `kid` header が欠落した legacy/malformed token の verify 用に、現在の signing kid を返す fallback accessor。rotation-safe lookup には使わないこと (rotation 時は token 側の `kid` をそのまま `getVerificationKey(kid)` に渡す)。

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

`createKeyStoreFactory` は登録済みタイプが空の新しいファクトリーを返します。`registerBuiltinKeyStores` は組み込みの `"local"` プロバイダーを登録します。`algorithm` に応じて `createAsymmetricKeyStore` または `createSymmetricKeyStore` に委譲します。ファクトリーパターンは `ClientRepository`、`UserRepository`、`CodeRepository` と同じ `AdapterFactory<T>` 契約に従います。

### リポジトリ

リポジトリインターフェースはデータアクセスのコントラクトを定義します。開発・テスト向けのインメモリ実装が標準で提供されています。

#### インターフェースと型

```typescript
interface Client {
  clientId: string;
  clientSecret: string;
  allowedRedirectUris: string[];
  allowedScopes: string[];
  // ログアウトメタデータ (TODO-F-5):
  postLogoutRedirectUris?: string[];
  backchannelLogoutUri?: string;
  backchannelLogoutSessionRequired?: boolean; // デフォルト: true
  frontchannelLogoutUri?: string;
  frontchannelLogoutSessionRequired?: boolean; // デフォルト: true
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

#### 組み込み実装

```typescript
class InMemoryClientRepository implements ClientRepository {
  constructor(clients: Map<string, ClientEntry>);
}

class InMemoryUserRepository implements UserRepository {
  constructor(users: Map<string, UserEntry>);
}

class InMemoryCodeRepository implements CodeRepository {
  constructor(options?: { defaultExpiresIn?: number });
  dispose(): void; // 内部タイマーをクリアする
}
```

#### YAML からの初期化

```typescript
const ClientEntrySchema: z.ZodObject<...>;
const UserEntrySchema: z.ZodObject<...>;

function loadYamlMap<T extends z.ZodTypeAny>(
  filePath: string,
  schema: T
): Map<string, z.infer<T>>;
```

`loadYamlMap` はトップレベルのキーをレコード ID とする YAML ファイルを読み込み、各エントリーを `schema` で検証します。結果を `InMemoryClientRepository` や `InMemoryUserRepository` にそのまま渡せます。

#### アダプタファクトリー

```typescript
interface BuilderContext {
  // v1 では意図的に空。将来追加される field（logger / tracer / abortSignal など）は
  // すべて optional で、破壊を起こさない追加のみ（additive-only evolution）。
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

契約の主要な性質:

- `create()` は同期ビルダーであっても必ず `Promise<T>` を返す。
- `register()` は同一 `type` の二重登録で throw する（silent override 防止）。
- `create()` は未登録 `type` で `AdapterFactoryError` を throw する。error は `kind` / `type` / `registered` を構造化フィールドとして保持する。
- `BuilderContext` は factory 単位で共有される（call ごとのコピーではない）。builder 側では read-only として扱うこと。

`createRepositoryFactories` は組み込みの `yaml` / `static`（client、user）と `memory`（code）タイプが登録済みの 3 つのファクトリーを返します。`@o3co/auth-provider-foundation` の `registerBuiltinAdapters` で `http` ユーザー認証アダプターを追加できます。独自の backend は `register` で追加してください。Redis バックエンドの code / store アダプターは `@o3co/auth-provider-redis` を参照してください。

### モジュールシステム

モジュールはルート、グラントハンドラー、DI グラフのコンポーネントをアプリに追加するための拡張ポイントです。v0.5.0 のモジュールは `defineModule({...})` で書く宣言的 manifest であり、`requires` / `optional`（型付きの `ProviderDeps` キー）を宣言し、`grants` / `routes` / `federations` などの `ContributesMap` slot に contribute します。

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

> Note: v0.4.x の `LegacyModule` / `ModuleContext` 形（`{ name, init(context) }` を返す関数）は v0.5.0 redesign の Phase 9 で削除されました。boot planner が型付きの deps を contribution lambda に直接注入するため、モジュールが共有 `ModuleContext` を mutate することはありません。

### アプリファクトリー

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

`createApp` は設定、キーストア、グラントレジストリ、モジュールを単一の Express Router にまとめます。`init()` を呼び出すとすべてのモジュール初期化処理が実行されます。Router は `init()` が解決した後にマウント可能になります。

常に登録される組み込みルート:

- `GET /health` — `200 OK` を返す
- `GET /.well-known/jwks.json` — `keyStore` の公開鍵セットを返す

`ExpressLike` は構造的型です。`Router()`、`json()`、`urlencoded()` メソッドを持つオブジェクトであれば満たします。`express` のデフォルトエクスポートをそのまま渡してください。

## 使い方

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

// repositories.* は 'type' セレクター、oauth.jwt.signingKey は 'provider' セレクターを使う。
// flatten() はどちらも { type, ...サブセクションフィールド } に正規化してから factory に渡す:
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
    // 追加モジュールをここに渡す
  ],
  bootstrapComponents: { config, pathResolver: import.meta.resolve },
});

const server = express();
server.use(handle.router);
server.listen(config.http.port);
```

### カスタムグラントタイプの実装

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

`myGrantModule` を `createApp` に渡す `modules` 配列へ追加してください。boot planner は A2-γ Amendment 3（`grantHandlerResolver` synthetic key）に従い、`contributes.grants` の projection を通じて grant を登録します。

### YAML からクライアントとユーザーを読み込む

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

### 拡張ポイント (v0.4.0)

v0.4.0 で追加された 5 つの拡張ポイント。

#### MFA

- `MfaProvider` と optional な `SupportsEnrollment` / `SupportsRevocation` capability
- Factory: `createMfaProviderFactory()`、type guard は `supportsEnrollment()` / `supportsRevocation()`
- Flow: `/oauth/authorize` と `/auth/federation/callback` が `MfaCoordinator.listEnrolled(userId)` を参照。MFA 必要時は `MfaTransactionStore` に transaction を保存、user は `POST /auth/mfa/verify { transaction_id, proof }` を submit、core は `providerKind` で provider に dispatch
- v0.4.0 では built-in provider 同梱なし — TOTP / WebAuthn / backup codes は後続 spec で提供予定

#### Audit (監査ログ)

- `AuditSink.record(event)` は fire-and-forget
- Factory: `createAuditSinkFactory()`、built-in `"console"` は `registerBuiltinAuditSinks()` で登録
- Sink のエラーは core 側で握りつぶす — audit 失敗で認証フローがブロックされることはない

#### Rate limiter

- `RateLimiter.check(key, ctx)` で atomic check + increment
- Factory: `createRateLimiterFactory()`、built-in `"memory"` と `"redis"` は `registerBuiltinRateLimiters()` で登録
- deny 時には core が 429 + `Retry-After` header で応答
- built-in `"redis"` limiter は `config.client` として `{ incr(key): Promise<number>; expire(key, seconds): Promise<number> }` の shape を満たす client の注入を必須とする。core は `redis` パッケージに依存せず自前で client を作らない (`RateLimiter` に dispose hook がないため lifecycle は consumer 側に委ねる)。この shape を満たせば redis 互換の任意 client で動作する。

#### RefreshTokenStore (RFC 6819 §5.2.2.3 replay 検出)

- `RefreshTokenStoreBase.rotate(previousJti, newJti, familyId, expiresAt)` は atomic primitive
- 全 `rt+jwt` token は `family_id` claim を常に含む (後方互換性あり)
- Optional: `AppOptions.refreshTokenStore` を設定すると replay 検出 + family revocation が有効化される

#### GrantPolicyHook (scope / audience / token exchange policy)

- `GrantPolicyHook.evaluate(request, ctx)` は allow (narrowing 可) / deny を返す
- `/oauth/authorize` で 1 回だけ評価、`/oauth/token` は Code record に persist された `grantedScope` / `grantedAudience` を再利用 (authorization_code flow では再評価しない)
- その他 grant (refresh / client_credentials / token-exchange) は token endpoint で評価

全 adapter は optional — 未設定時は no-op default。

### UserSessionStore / FederationTokenStore (TODO-F)

Federation + OIDC 対応のために `AppOptions` に追加された 2 つのオプション:

- `userSessionStore`: sid キーの session metadata (auth_time、active RP、family ID、OIDC claim)。Built-in: `memory`、`redis`。
- `federationTokenStore`: `(sid, federationName)` キーの upstream IdP token。Built-in: `memory`、`redis` (refresh_token は AES-256-GCM による暗号化必須。`allow-plaintext` は opt-in で警告を出力)。

両 store は TODO-F-3 (cascading revoke)、F-4 (id_token + /userinfo)、F-5 (logout)、F-6 (/oauth/federation/:name/token) で消費される。本 F-1 では plumbing のみを追加する。

**F-3 での consumer 有効化。** `CodeData` にログインパスが書き込む 2 つのオプションフィールドが追加された:

- `nonce?` — 認可リクエストから転送される OIDC nonce。コードレコードに保存され、後続の `id_token` / `/userinfo` 向け処理で参照できるように保持される。
- `sid?` — ログインハンドラーが書き込むセッション ID（`UserSession.sid`）。発行したトークンをセッションに紐付けるために使用される。

`CodeRepository.createCode` のパラメーターと `InMemoryCodeRepository` は同一の呼び出しで `nonce`、`sid`、`grantedScope` を受け付ける。consumer（`authorization_code` grant）は、`session.granted_scopes` の代わりに、`/oauth/authorize` 時に `GrantPolicyHook` が設定した `codeData.grantedScope` をトークン発行のスコープとして使用する。

### OIDC id_token + クレームフィルター (TODO-F-4)

`authorization_code` グラントと `/oauth/userinfo` エンドポイントが使用する低レベルヘルパー。

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
  readonly expiresIn?: number; // デフォルト 3600 秒
}

function generateIdToken(opts: GenerateIdTokenOptions): Promise<Token>;
```

OIDC id_token JWT（OIDC Core §2）に署名して返す。クレーム構成:

- `iss`、`sub`、`aud`、`exp`、`iat`、`jti` — 標準 JWT クレーム
- `auth_time` — `opts.authTime` をエポック秒に変換した値
- `sid` — バックチャネルログアウト用セッション識別子（TODO-F-5）
- `azp` — authorized party、指定された場合のみ付与
- `nonce` — 認可リクエストから転送し、そのまま反映
- `filterClaimsByScope` によるスコープフィルター済みユーザークレーム

ヘッダーは `typ: "id+jwt"` を使用する（イントロスペクション向けのヒント）。

#### `filterClaimsByScope`

```typescript
function filterClaimsByScope(
  claims: UserSessionClaims,
  scopes: ReadonlyArray<string>,
): Record<string, unknown>;
```

`UserSessionClaims` を、付与されたスコープが許可するクレームのサブセットにマッピングする。厳格なホワイトリスト制 — 下表のマッピングのみを出力し、それ以外のフィールド（例: Google の `hd` など）は一切転送しない。

| スコープ | 出力されるクレーム |
| --- | --- |
| `openid` | *(クレームなし — id_token 発行の可否を制御; `sub` は `generateIdToken` が付与)* |
| `profile` | `name`、`picture` |
| `email` | `email`、`email_verified` |
| `groups` | `groups` |

#### `/.well-known/openid-configuration`

OIDC Discovery 1.0 メタデータエンドポイント。`config.oauth.jwt.issuer` が設定され、かつ provider surface を宣言するモジュールがある（`oauthModule` が `discoveryMetadata` contribution に `providerRoot: true` を設定）場合に、core が合成して mount する。core は各モジュールの `discoveryMetadata` slice（`oauthModule` が endpoints + capabilities、`jwksModule` が `jwks_uri`）を集約して 1 つのドキュメントにする:

- `issuer`、`authorization_endpoint`、`token_endpoint`、`userinfo_endpoint`、`introspection_endpoint`
- `jwks_uri` — 常に広告する（`jwksModule` が contribute）。issuer 設定済みの構成は `jwksModule` を必ず組み込む必要があり、欠如すると boot が `DiscoveryDocumentError` で fail-fast する。HS256 のみの構成では JWKS ルートは空の鍵セット（`{ "keys": [] }`、HTTP 200）を返す（404 ではない）— 対称鍵の secret は決して公開されない。
- `response_types_supported: ["code"]`
- `subject_types_supported: ["public"]`
- `id_token_signing_alg_values_supported` — 設定された `KeyStore.algorithm` から導出
- `scopes_supported: ["openid", "profile", "email", "groups"]`
- `token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"]`
- `code_challenge_methods_supported: ["S256"]`
- `end_session_endpoint` — TODO-F-5 で追加
- `backchannel_logout_supported: true` — TODO-F-5 で追加
- `backchannel_logout_session_supported: true` — TODO-F-5 で追加
- `frontchannel_logout_supported: true` — TODO-F-5 で追加
- `frontchannel_logout_session_supported: true` — TODO-F-5 で追加

### ログアウトヘルパー (TODO-F-5)

`@o3co/auth-provider-oauth` の `POST /oauth/logout` が使用する低レベルヘルパー。

#### `generateLogoutToken`

```typescript
interface GenerateLogoutTokenOptions {
  readonly issuer: string;
  readonly sub: string;
  readonly aud: string | string[];
  readonly sid?: string;
  readonly includeSid?: boolean; // デフォルト true
  readonly keyStore: KeyStore;
  readonly expiresIn?: number; // デフォルト 300 秒
}

function generateLogoutToken(opts: GenerateLogoutTokenOptions): Promise<Token>;
```

OIDC Back-Channel Logout 1.0 §2.4 の `logout_token` JWT に署名して返す。ヘッダーは `typ: logout+jwt`。クレーム構成: `iss`、`sub`、`aud`、`iat`、`exp`、`jti`、および `{ [BACKCHANNEL_LOGOUT_EVENT_URI]: {} }` を値に持つ `events`。デフォルトで `sid` を含む。`backchannel_logout_session_required: false` で登録した RP 向けには `includeSid: false` を指定する。デフォルト TTL は 300 秒。`nonce` クレームは仕様 §2.4 の要件により常に含まれない。

#### `BACKCHANNEL_LOGOUT_EVENT_URI`

```typescript
const BACKCHANNEL_LOGOUT_EVENT_URI: "http://schemas.openid.net/event/backchannel-logout";
```

すべての `logout_token` の `events` クレームに必要な正規イベント URI。このリテラルを各所で繰り返さずに参照できるようにエクスポートされている。

#### `Logger`

```typescript
interface Logger {
  warn(message: string, ...args: unknown[]): void;
}
```

`cascadeLogout`、`broadcastBackchannelLogout` などの内部コールサイトが受け付ける最小の構造的ロガーインターフェース。`console`、pino、winston、bunyan など、互換 shape を持つオブジェクトであれば構造的に適合する。内部コールサイトが必要になった時点で追加メソッド（`info`、`error`、`debug`）を追加する。

### フェデレーショントークン capabilities (TODO-F-6)

`@o3co/auth-provider-oauth` の `POST /oauth/federation/:name/token` が使用する低レベルの構成要素。

- `SupportsLock` — `FederationTokenStore` のオプション capability。`(sid, federationName)` 単位の advisory lock を提供し、並行リフレッシュによるサンダリングハード問題を防ぐ。組み込みの memory / redis アダプター両方がこの capability を実装している。`supportsLock(store)` type guard で検出できる。
- `createInProcessLock()` — インメモリのロック実装。プロセスローカルな Map に保存し、TTL 付き expiry と Symbol ベースの所有権トークン（TTL 後の誤解放を防ぐ）を使用する。
- `createRedisLock({ client, keyPrefix })` — `SET NX PX` + compare-and-delete release による redis バックのロック実装。最小限の redis クライアント（`get` / `set` / `del`）を受け付ける。値の整合性に関する契約は `RedisLockClient` の JSDoc を参照。
- `Client.allowedAzpForFederationToken` — `Client` インターフェースの opt-in フラグ。デフォルト `false`。`POST /oauth/federation/:name/token` を利用するクライアントは `true` に設定する必要がある。

## 関連

- ルート [README](../../README.md) — アーキテクチャ概要、設定リファレンス、Docker セットアップ
- [`@o3co/auth-provider-oauth`](../oauth/README.md) — OAuth 2.0 エンドポイント（authorization、token、introspection）
- [`@o3co/auth-provider-session`](../session/README.md) — セッションベースのログインフロー
- [`@o3co/auth-provider-foundation`](../foundation/README.md) — 共通ミドルウェアとユーティリティ
