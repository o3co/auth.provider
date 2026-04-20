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

グラントシステムは OAuth 2.0 グラントタイプの拡張ポイントです。各グラントタイプは `GrantHandler` として実装し、`GrantRegistry` に登録します。

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

#### GrantRegistry

```typescript
class GrantRegistry {
  register(grantType: string, handler: GrantHandler): void;
  get(grantType: string): GrantHandler | undefined;
  addModule(module: GrantModule, deps: GrantDependencies): void;
  cleanup(): void;
}
```

`addModule` はモジュール内のすべての `GrantFactory` を実行してハンドラーを登録します。シャットダウン時に `cleanup()` を呼び出すと、各ハンドラーの `cleanup()` メソッド（存在する場合）が実行されます。

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

`KeyStore` インターフェースは、対称鍵（HS256）と非対称鍵（RS256、ES256、EdDSA）の署名鍵を抽象化し、`previousKeys` によるキーローテーションをサポートします。

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

function createDefaultFactories(): {
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

`createDefaultFactories` は組み込みの `yaml` / `static`（client、user）と `memory`（code）タイプが登録済みの 3 つのファクトリーを返します。`http` / `redis` は `@o3co/auth-provider-foundation` の `registerBuiltinAdapters` で追加できます。独自の backend は `register` で追加してください。

### モジュールシステム

モジュールはルート、ミドルウェア、グラントタイプをアプリに追加するための拡張ポイントです。各モジュールは初期化時に `ModuleContext` を受け取ります。

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

### アプリファクトリー

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
  createDefaultFactories,
  createKeyStoreFactory,
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

const { clientFactory, userFactory, codeFactory } = createDefaultFactories();

const clientRepository = await clientFactory.create(flatten(config.repositories.client));
const userRepository = await userFactory.create(flatten(config.repositories.user));
const codeRepository = await codeFactory.create(flatten(config.repositories.code));

const app = createApp(express, {
  config,
  keyStore,
  modules: [
    // 追加モジュールをここに渡す
  ],
});

await app.init();

const server = express();
server.use(app.router);
server.listen(config.http.port);
```

### カスタムグラントタイプの実装

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

`GrantRegistry.addModule()` に直接渡すか、`init()` 内で `context.grantRegistry.addModule()` を呼び出すモジュールとして組み込んでください。

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

## 関連

- ルート [README](../../README.md) — アーキテクチャ概要、設定リファレンス、Docker セットアップ
- [`@o3co/auth-provider-oauth`](../oauth/README.md) — OAuth 2.0 エンドポイント（authorization、token、introspection）
- [`@o3co/auth-provider-session`](../session/README.md) — セッションベースのログインフロー
- [`@o3co/auth-provider-foundation`](../foundation/README.md) — 共通ミドルウェアとユーティリティ
