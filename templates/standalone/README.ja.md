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
| `HTTP_TRUST_PROXY` | `false` | Express の `trust proxy`。`false` / アドレス・CIDR のリスト (`10.0.0.0/8,loopback`) / ホップ数 (`1`) / `true` のいずれか。**ロードバランサ配下では必須** — 未設定だと `req.ip` が LB のアドレスになり、IP をキーとする全ての rate limit が全ユーザーで 1 バケットを共有する。`true` ではなく**実際のプロキシを名指しする**こと (#292): `true` は「接続してきた相手が誰であれ、その X-Forwarded-For の先頭を信じる」という意味で、プロセスに直接到達できる相手が自分で `req.ip` を選べてしまう。詳細は [Multi-replica deployments](#multi-replica-deployments) |

### OAuth JWT

| 変数 | デフォルト | 説明 |
|---|---|---|
| `OAUTH_JWT_ALGORITHM` | `EdDSA` | JWT 署名アルゴリズム: `EdDSA` / `ES256` / `RS256` / `HS256`。デフォルトが非対称なので `/.well-known/jwks.json` が実際の検証鍵を公開する。 |
| `OAUTH_JWT_SECRET` | — | 署名シークレット（**HMAC (`HS256`) 専用**）。32 バイト（256 bit）以上のランダム値が必須 — `openssl rand -hex 32`。hex / base64 値は**デコード後**の長さで測るため、32 文字の hex 文字列は 16 バイト扱いで拒否される。 |
| `OAUTH_JWT_ISSUER` | **（必須）** | すべてのトークンの `iss` に刻まれる canonical issuer URL。絶対 `https` URL（`http` は loopback ホストのみ）で、query / fragment を含まないこと。未設定なら起動に失敗する — `Host` ヘッダから導出されることはない。 |
| `OAUTH_JWT_KID` | `v0` | JWT ヘッダーに含まれる key ID |
| `OAUTH_JWT_PRIVATE_KEY` | — | PEM エンコードされた秘密鍵（非対称アルゴリズム用） |
| `OAUTH_JWT_PRIVATE_KEY_PATH` | — | PEM 秘密鍵ファイルのパス |
| `OAUTH_JWT_PUBLIC_KEY` | — | PEM エンコードされた公開鍵 |
| `OAUTH_JWT_PUBLIC_KEY_PATH` | — | PEM 公開鍵ファイルのパス |

**署名鍵は必須。** デフォルトアルゴリズムは `EdDSA` で、鍵素材のデフォルト値は存在しない。
何も設定しないデプロイは「推測可能なシークレットで黙って署名する」のではなく、設定すべき
キー名を明示して起動に失敗する。Ed25519 鍵ペアの生成:

```bash
openssl genpkey -algorithm ed25519 -out jwt-private.pem
openssl pkey -in jwt-private.pem -pubout -out jwt-public.pem
```

生成したら `OAUTH_JWT_PRIVATE_KEY_PATH` / `OAUTH_JWT_PUBLIC_KEY_PATH` を指すか、
`OAUTH_JWT_PRIVATE_KEY` / `OAUTH_JWT_PUBLIC_KEY` に PEM をインラインで渡す。

`HS256` も引き続き選択可能（`OAUTH_JWT_ALGORITHM=HS256` + 32 バイト以上の
`OAUTH_JWT_SECRET`）だが、代償を理解した上で選ぶこと: 対称鍵には公開鍵の片割れが
存在しないため `/.well-known/jwks.json` は `404 jwks_not_published` を返し、
すべての RP に共有シークレットを渡す必要がある。それは検証だけでなく
**トークンの発行（偽造）** も可能にする鍵である。

### トークン有効期限

| 変数 | デフォルト | 説明 |
|---|---|---|
| `OAUTH_ACCESS_TOKEN_EXPIRES_IN` | `3600` | アクセストークンの有効期間（秒）。正の整数、上限は 1 年（`31536000`）。 |
| `OAUTH_REFRESH_TOKEN_EXPIRES_IN` | `86400` | リフレッシュトークンの有効期間（秒）。正の整数、上限は 1 年（`31536000`）。 |

これらを空文字で export すると fallback ではなく起動失敗になる: HOCON は `FOO=` を
`""` に解決し、それが `0` に coerce され、有効期間 0 は「発行時点で期限切れ」の
トークンを作るため。

### グラントタイプ

| 変数 | デフォルト | 説明 |
|---|---|---|
| `OAUTH_GRANTS_SESSION_ENABLED` | `true` | session グラントタイプを有効化 |
| `OAUTH_GRANTS_AUTHORIZATION_CODE_ENABLED` | `true` | authorization code グラントタイプを有効化 |
| `OAUTH_GRANTS_REFRESH_TOKEN_ENABLED` | `true` | refresh token グラントタイプを有効化 |

### Session

| 変数 | デフォルト | 説明 |
|---|---|---|
| `SESSION_SECRET` | — | **必須。** 認証済みセッションそのものである Cookie に署名する鍵。推測されればログインを偽造できる。32 バイト（256 bit）以上 — `openssl rand -hex 32`。`OAUTH_JWT_SECRET` と同じく**デコード後**の長さで測る。 |
| `SESSION_MAX_AGE` | `3600000` | セッション Cookie の最大有効期間（ミリ秒）。正の整数、上限は 1 年（`31536000000`）。 |
| `SESSION_SECURE` | `true` | セッション Cookie に `Secure` フラグを設定 |
| `SESSION_SAME_SITE` | `lax` | `SameSite` 属性（`lax`、`strict`、`none`）。`none` は `SESSION_SECURE=true` が**必須** — ブラウザは `Secure` でない `SameSite=None` Cookie を破棄するため、クライアント側で全ログインが無言で失敗するのを避けて起動時に拒否する。 |
| `SESSION_DOMAIN` | — | Cookie ドメイン（デフォルト未設定） |
| `SESSION_CSRF_TTL_SECONDS` | `7200` | 発行する CSRF トークンの有効期間（秒）。1〜86400 の整数で、外れると boot が失敗する（*空文字* は `0` に coerce され、トークン側の判定を無言で無効化してしまうため） |
| `SESSION_STORAGE_TYPE` | `redis` | セッションストアのバックエンド: `redis` または `memory` |
| `SESSION_STORAGE_REDIS_URL` | `redis://localhost:6379` | セッションストア用 Redis 接続 URL |
| `SESSION_STORAGE_REDIS_PASSWORD` | — | セッションストア用 Redis パスワード |

#### `/session/login` と `/session/logout` の CSRF 対策

どちらのルートも、**same-origin（もしくは信頼した）`Origin` / `Referer`**、**または** 有効な double-submit CSRF トークンのいずれかを伴うリクエストのみ受理し、どちらも無いものは拒否する（#272）。ブラウザは自動的に条件を満たす。スクリプトのクライアントはまず `GET /session/csrf` を呼び、返ってきた `csrf_token` を `<SESSION_NAME>.csrf` cookie と `x-csrf-token` ヘッダー（または `csrf_token` フォームフィールド）の両方で送り返す。

設定上の注意が 2 点:

- TLS 終端プロキシの背後では `HTTP_TRUST_PROXY` にそのプロキシのアドレス／CIDR を設定する (例: `HTTP_TRUST_PROXY=10.0.0.0/8`)。設定しないと `req.protocol` は `http` のままでブラウザは `Origin: https://…` を送るため、origin 側の判定が全リクエストを拒否する。`true` は「プロキシ以外が絶対にプロセスへ到達できない」と言い切れる場合にのみ正しい (#292) — 英語版 README も同じ指針。
- ログイン UI をプロバイダーと**別 origin** で配信している場合は、その origin を HOCON の `session.csrf.trustedOrigins` に列挙する。`cors.allowedOrigins` は CSRF 信頼を与えない。

### CORS（#500）

ブラウザーアプリをプロバイダーと別 origin で配信している場合、その origin を `cors.allowedOrigins`（環境変数は `CORS_ALLOWED_ORIGINS`、カンマ区切り）に列挙しないと、SPA は token エンドポイントを呼べない。有効になるのは `/oauth/token`、`/oauth/userinfo`、`/oauth/revoke`、discovery、JWKS の 5 つだけで、`/oauth/introspect`（サーバー間通信）と `/oauth/authorize`（トップレベル遷移）は意図的に対象外。

`Origin` ヘッダーとの**完全一致**なので、末尾スラッシュ・明示的な `:443`・パス・大文字ホスト・ワイルドカードはいずれも起動時に失敗する（一致しない許可リストが黙って居座るのを防ぐため）。ループバックホストを除き https が必須。

`Access-Control-Allow-Credentials` は**決して送らない** — ここでのクロスオリジン SPA は PKCE を使う public client であり cookie は不要で、cookie を渡せば `session` grant に届いてしまう。空リスト（既定）なら CORS は無効で、middleware 自体がマウントされない。詳細は英語版 README の [CORS](README.md#cors) を参照。

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
| `CLIENT_USER_AUTHENTICATE_URL` | — | パスワード認証用のユーザー認証 URL。**https 必須**（下記参照） |
| `CLIENT_USER_AUTHENTICATE_BY_TOKEN_URL` | — | トークン認証用のユーザー認証 URL。**https 必須**（下記参照） |
| `CLIENT_USER_TIMEOUT` | `5000` | HTTP リクエストタイムアウト（ミリ秒）。`2147483647` 以下の正の整数 |
| `CLIENT_USER_MAX_RESPONSE_BYTES` | `1048576` | 上流レスポンスボディの受け入れ上限（バイト） |

ユーザー認証 URL は 2 つとも上流ストアへ**平文のユーザー資格情報**を運ぶため、いずれも絶対 `https://` URL でなければならない。`http://` は loopback ホスト（`localhost`、`127.0.0.0/8` 内のアドレス、`[::1]`）に限って許可され、ローカル開発で証明書を用意せずに済むようにしている。プライベートレンジのアドレス（`http://10.0.0.5/…`）やコンテナネットワークのサービス名（`http://user-service/…`）には `https://` が必要 — これらはデプロイが端から端まで制御していないネットワークを越えるため。URL・タイムアウト・レスポンス上限のいずれかが不正なら、最初のログイン時ではなく起動時に失敗する。

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

`docker-compose.yml` は**開発用**です(`develop` target をビルドし `./src` / `./config` を bind-mount するため、そのままデプロイすると working tree を hot-reload で配信します)。デプロイ可能な形は
[`docker-compose.production.yml`](docker-compose.production.yml) — `runtime` target・source mount なし・restart policy・ネットワーク内部限定の永続 Redis・**必須**の `.env`(実際の `SESSION_SECRET` が無い boot は大声で失敗すべき)です。TLS 終端 + `HTTP_TRUST_PROXY`、`--scale` 前の multi-replica 手順など「意図的に委ねる範囲」はファイル冒頭のコメントに明記しています。

```bash
# 署名鍵は必須の入力です。デフォルトは EdDSA で鍵のデフォルト値は存在しないため、
# 鍵を生成していないデプロイは boot で失敗します。
openssl genpkey -algorithm ed25519 -out jwt-private.pem
openssl pkey -in jwt-private.pem -pubout -out jwt-public.pem
chmod 600 jwt-private.pem

docker compose -f docker-compose.production.yml up -d --build
```

**コンテナへの鍵の渡し方**。pem のペアは compose の **secret** として
`/run/secrets/` に read-only でマウントされ、compose 側が
`OAUTH_JWT_*_KEY_PATH` をそこに向けます。`config/` には置かないでください —
`Dockerfile` がこのディレクトリを `COPY` するため、置いた鍵はイメージレイヤに
焼き込まれ、push のたびに一緒に運ばれます(保管場所を誤っただけでは済まず、
ローテーションが必要になります)。`.env` も同様に git の外に置いてください。

production ファイルは `environment:` で `SESSION_SECURE=true` と `__Host-`
cookie 名も固定します(`environment` は `env_file` より優先されます)。
`.env.example` は plain-HTTP のローカル実行のために `SESSION_SECURE=false` を
出荷しており、このファイルはその同じ `.env` を要求するためです。前段で TLS を
終端する前提の構成で非 Secure な session cookie を配ることは、平文区間を読める
相手にセッションを渡すことと同じです。

イメージは `pnpm install --frozen-lockfile` でインストールするため、コミット済みの
`pnpm-lock.yaml` がビルドの必須入力です。`create-auth-provider` が scaffold 時に
生成します。手元に無い場合は一度 `pnpm install` を実行して結果をコミットしてください。
これにより同じソースからのリビルドは同じ依存ツリーになります。

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
installGracefulShutdown(server, { logger, cleanup: () => handle.dispose() });
```

### シャットダウンの保証

`src/shutdown.mts` は依存パッケージではなく scaffold 側に置いてある (#290)。全ユーザーセッションを終端するコンポーネントについて「SIGTERM は in-flight リクエストを待つのか、待つなら何秒か」は、デプロイするコード自体から答えられる必要があるため。

1. **`SIGTERM` / `SIGINT`** のどちらでも開始する。2 回目のシグナルは無視する（1 回目の dispose に重ねて 2 回目を走らせない）。
2. **新規接続は即座に停止**し、idle な keep-alive ソケットは解放する。リクエストを持たないまま server を開いたままにするソケットなので、解放しないと閑散時に deadline を丸ごと待つことになる。
3. **in-flight リクエストには `drainTimeoutMs`**(既定 **10 秒**)を与える。
4. **deadline を超えたら残接続を切り、プロセスは非ゼロ終了する。** 常に `0` しか見えない orchestrator では、正常な drain と時間切れの強制切断を区別できない。
5. **`cleanup` は drain 後・exit 前**に走る(`handle.dispose()` = 逆トポロジカルなコンポーネント cleanup + Redis/タイマーの drain)。失敗はこのサービス自身の logger(他の行と同じ NDJSON)に出し、exit code にも反映する。dispose が throw してもプロセスは終了する。

**`drainTimeoutMs` は orchestrator の kill grace period より短く設定すること** — Kubernetes の `terminationGracePeriodSeconds`、compose の `stop_grace_period` はいずれも既定 30 秒。他人の都合の `SIGKILL` が来る前に、自分の都合で閉じるのが目的。

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
