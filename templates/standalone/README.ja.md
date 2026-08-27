# @o3co/auth-provider-standalone

auth.provider のデプロイ可能なサーバーテンプレートです。これは composition root であり、設定を読み込み、モジュールをロードし、Express サーバーを起動します。`@o3co/create-auth-provider` で生成されます。

## 使い方

```bash
# 依存関係をインストール
pnpm install

# 環境変数ファイルをコピーして必須値を記入
cp .env.example .env

# 開発モードで起動（ホットリロード）
pnpm run debug

# ビルドして本番モードで起動
pnpm run build
pnpm start
```

## 設定

設定は `config/application.conf`（HOCON 形式）から読み込まれます。各値は対応する環境変数で上書きできます。

### 環境別コンフィグ overlay

`src/app.mts` は 2 層構成でコンフィグを読み込みます:

1. **`config/application.conf`** — アプリの基本デフォルト。
2. **`config/{ENV}.conf`** — 現在の環境の overlay。
   `ENV = CONFIG_ENV || NODE_ENV || "development"` で決まります。

overlay の値は `application.conf` を上書きします。scaffold には
`development.conf` と `production.conf` が同梱されています。別の環境
（例: `staging`）を追加するときは `config/staging.conf` を作成し、
`CONFIG_ENV=staging` を設定してください。`{ENV}.conf` が存在しない場合は
起動時にエラーになります（タイポを silent に素通りさせず fail-fast します）。

### HTTP

| 変数 | デフォルト | 説明 |
|---|---|---|
| `HTTP_PORT` | `3000` | サーバーがリッスンするポート |
| `HTTP_TRUST_PROXY` | `false` | リバースプロキシの背後で動作する場合は `true` に設定。**ロードバランサ配下では必須** — 未設定だと `req.ip` が LB のアドレスになり、IP をキーとする全ての rate limit が全ユーザーで 1 バケットを共有する |

### OAuth JWT

| 変数 | デフォルト | 説明 |
|---|---|---|
| `OAUTH_JWT_ALGORITHM` | `HS256` | JWT 署名アルゴリズム（例: `RS256`、`ES256`） |
| `OAUTH_JWT_SECRET` | — | 署名シークレット（HMAC アルゴリズム用） |
| `OAUTH_JWT_ISSUER` | **（必須）** | すべてのトークンの `iss` に刻まれる canonical issuer URL。絶対 `https` URL（`http` は loopback ホストのみ）で、query / fragment を含まないこと。未設定なら起動に失敗する — `Host` ヘッダから導出されることはない。 |
| `OAUTH_JWT_KID` | `v0` | JWT ヘッダーに含まれる key ID |
| `OAUTH_JWT_PRIVATE_KEY` | — | PEM エンコードされた秘密鍵（非対称アルゴリズム用） |
| `OAUTH_JWT_PRIVATE_KEY_PATH` | — | PEM 秘密鍵ファイルのパス |
| `OAUTH_JWT_PUBLIC_KEY` | — | PEM エンコードされた公開鍵 |
| `OAUTH_JWT_PUBLIC_KEY_PATH` | — | PEM 公開鍵ファイルのパス |

### トークン有効期限

| 変数 | デフォルト | 説明 |
|---|---|---|
| `OAUTH_ACCESS_TOKEN_EXPIRES_IN` | `3600` | アクセストークンの有効期間（秒） |
| `OAUTH_REFRESH_TOKEN_EXPIRES_IN` | `86400` | リフレッシュトークンの有効期間（秒） |

### グラントタイプ

| 変数 | デフォルト | 説明 |
|---|---|---|
| `OAUTH_GRANTS_SESSION_ENABLED` | `true` | session グラントタイプを有効化 |
| `OAUTH_GRANTS_AUTHORIZATION_CODE_ENABLED` | `true` | authorization code グラントタイプを有効化 |
| `OAUTH_GRANTS_REFRESH_TOKEN_ENABLED` | `true` | refresh token グラントタイプを有効化 |

### Session

| 変数 | デフォルト | 説明 |
|---|---|---|
| `SESSION_SECRET` | — | **必須。** セッション署名シークレット |
| `SESSION_MAX_AGE` | `3600000` | セッション Cookie の最大有効期間（ミリ秒） |
| `SESSION_SECURE` | `true` | セッション Cookie に `Secure` フラグを設定 |
| `SESSION_SAME_SITE` | `lax` | `SameSite` 属性（`lax`、`strict`、`none`） |
| `SESSION_DOMAIN` | — | Cookie ドメイン（デフォルト未設定） |
| `SESSION_CSRF_TTL_SECONDS` | `7200` | 発行する CSRF トークンの有効期間（秒） |
| `SESSION_STORAGE_TYPE` | `redis` | セッションストアのバックエンド: `redis` または `memory` |
| `SESSION_STORAGE_REDIS_URL` | `redis://localhost:6379` | セッションストア用 Redis 接続 URL |
| `SESSION_STORAGE_REDIS_PASSWORD` | — | セッションストア用 Redis パスワード |

#### `/session/login` と `/session/logout` の CSRF 対策

どちらのルートも、**same-origin（もしくは信頼した）`Origin` / `Referer`**、**または** 有効な double-submit CSRF トークンのいずれかを伴うリクエストのみ受理し、どちらも無いものは拒否する（#272）。ブラウザは自動的に条件を満たす。スクリプトのクライアントはまず `GET /session/csrf` を呼び、返ってきた `csrf_token` を `<SESSION_NAME>.csrf` cookie と `x-csrf-token` ヘッダー（または `csrf_token` フォームフィールド）の両方で送り返す。

設定上の注意が 2 点:

- TLS 終端プロキシの背後では `HTTP_TRUST_PROXY=true` を設定する。設定しないと `req.protocol` は `http` のままでブラウザは `Origin: https://…` を送るため、origin 側の判定が全リクエストを拒否する。
- ログイン UI をプロバイダーと**別 origin** で配信している場合は、その origin を HOCON の `session.csrf.trustedOrigins` に列挙する。`cors.allowedOrigins` は CSRF 信頼を与えなくなった。

### Google フェデレーション

| 変数 | デフォルト | 説明 |
|---|---|---|
| `FEDERATIONS_GOOGLE_ENABLED` | `false` | Google OAuth フェデレーションを有効化 |
| `FEDERATIONS_GOOGLE_CLIENT_ID` | — | Google OAuth クライアント ID |
| `FEDERATIONS_GOOGLE_CLIENT_SECRET` | — | Google OAuth クライアントシークレット |
| `FEDERATIONS_GOOGLE_CALLBACK_URL` | `http://localhost:3000/session/oauth/federation/google/callback` | Google OAuth コールバック URL |

### クライアントリポジトリ

| 変数 | デフォルト | 説明 |
|---|---|---|
| `CLIENT_TYPE` | `yaml` | クライアントストアのバックエンド: `yaml` |
| `CLIENT_PATH` | `./config/clients.yaml` | YAML クライアントレジストリのパス |

### ユーザーリポジトリ

| 変数 | デフォルト | 説明 |
|---|---|---|
| `CLIENT_USER_TYPE` | `http` | ユーザーリポジトリのバックエンド: `http` |
| `CLIENT_USER_AUTHENTICATE_URL` | — | パスワード認証用のユーザー認証 URL |
| `CLIENT_USER_AUTHENTICATE_BY_TOKEN_URL` | — | トークン認証用のユーザー認証 URL |
| `CLIENT_USER_TIMEOUT` | `5000` | HTTP リクエストタイムアウト（ミリ秒） |

### コードリポジトリ

| 変数 | デフォルト | 説明 |
|---|---|---|
| `CLIENT_CODE_TYPE` | `redis` | 認可コードストアのバックエンド: `redis` |
| `CLIENT_CODE_ENDPOINT_URI` | — | コードストア用 Redis 接続 URI |
| `CLIENT_CODE_PASSWORD` | — | コードストア用 Redis パスワード |
| `CLIENT_CODE_DEFAULT_EXPIRES_IN` | `600` | 認可コードのデフォルト有効期間（秒） |

### エンドポイント

| 変数 | デフォルト | 説明 |
|---|---|---|
| `ENDPOINTS_LOGIN_URL` | — | ログインページの URL（リダイレクト先） |
| `ENDPOINTS_CLIENT_URL` | — | クライアントアプリケーションの URL |
| `ENDPOINTS_AUTH_CALLBACK_URL` | — | 認可コールバックの URL |

## モジュール合成順序

モジュールは以下の順序で登録されます。各モジュールは独自のルートとグラントタイプを登録します。

1. **`oauthModule`** — OAuth 2.0 コアエンドポイント: `POST /oauth/token`、`POST /oauth/introspect`、`GET /oauth/authorize`
2. **`sessionModule`** — セッションベースのログイン・ログアウトおよびフェデレーション: `POST /session/login`、`POST /session/logout`、`GET/POST /session/oauth/federation/*`
3. **`oauthSessionModule`** — session グラントタイプ（有効なセッションをトークンに交換）
4. **`oauthAuthorizationModule`** — authorization code および refresh token グラントタイプ

## 組み込みルート

以下のルートはモジュールシステムの外部で登録されます。

| メソッド | パス | 説明 |
|---|---|---|
| `GET` | `/health` | ヘルスチェックエンドポイント |
| `GET` | `/.well-known/jwks.json` | トークン検証用公開鍵セット（JWKS） |

## Docker

Dockerfile はマルチステージビルドを使用しており、以下のターゲットがあります。

| ターゲット | 用途 |
|---|---|
| `runtime` | 本番イメージ（コンパイル済み JS のみ） |
| `develop` | ホットリロード付き開発イメージ（`pnpm run debug`） |
| `test` | テストランナーイメージ |

```bash
# 本番イメージをビルド
make build IMAGE=my-auth-provider

# docker compose で起動（開発用）
make dev

# Docker でテストを実行
make test
```

`docker-compose.yml` は認証サーバーと Redis コンテナをまとめて起動します。環境変数は `.env` で設定してください。

## カスタムモジュールの追加

カスタムモジュールを追加するには、`src/buildModules.mts` でインポートし、`createApp` に渡す `modules` 配列に追加します。

```typescript
// src/buildModules.mts
import { myCustomModule } from "./modules/my-custom-module.mjs";

export function buildModules(config: AppConfig, overrides: BuildModulesOverrides = {}): Module[] {
  const googleEnabled =
    (config.federations?.google as { enabled?: boolean } | undefined)?.enabled === true;

  return [
    oauthModule({ config }),
    oauthSessionModule({ config }),
    oauthAuthorizationModule({ config }),
    sessionModule,
    ...(googleEnabled ? [googleFederationModule, googleFederationConfigModule] : []),
    myCustomModule, // ここに追加
    overrides.keyStoreModule ?? keyStoreModule,
    overrides.repositoriesModule ?? repositoriesModule,
    overrides.storesModule ?? storesModule,
  ];
}

// src/app.mts
const handle = await createApp({
  modules: buildModules(config),
  bootstrapComponents: {
    config,
    pathResolver: import.meta.resolve,
  },
});

app.use(handle.router);
const server = app.listen(config.http.port);
gracefulShutdown(server, () => handle.dispose());
```

## npm スクリプト

| スクリプト | 説明 |
|---|---|
| `pnpm run build` | TypeScript を `dist/` にコンパイル |
| `pnpm start` | コンパイル済みサーバーを起動 |
| `pnpm run debug` | `tsx watch` でホットリロード起動（開発モード） |
| `pnpm test` | Vitest でテストを実行 |

## 関連

- [`@o3co/auth-provider-core`](../../packages/core) — アプリケーションファクトリと設定スキーマ
- [`@o3co/auth-provider-oauth`](../../packages/oauth) — OAuth モジュール
- [`@o3co/auth-provider-session`](../../packages/session) — Session モジュール
- [`@o3co/auth-provider-foundation`](../../packages/foundation) — 組み込みアダプター登録
- [`@o3co/create-auth-provider`](../../create-app) — このテンプレートを生成する CLI スキャフォルダー
