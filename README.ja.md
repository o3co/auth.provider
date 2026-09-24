# auth.provider

最終更新: 2026-09-24

[![CI](https://github.com/o3co/auth.provider/actions/workflows/ci.yml/badge.svg)](https://github.com/o3co/auth.provider/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@o3co/auth-provider-core)](https://www.npmjs.com/package/@o3co/auth-provider-core)
[![codecov](https://codecov.io/gh/o3co/auth.provider/graph/badge.svg)](https://codecov.io/gh/o3co/auth.provider)
[![API Docs](https://img.shields.io/badge/docs-API-blue)](https://o3co.github.io/auth.provider/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

> このリポジトリは、[auth](https://github.com/o3co/auth) スタックの 3 層責務分離（認証・トークン発行 / [認可判定](https://github.com/o3co/auth.policy-verifier) / [認可実施](https://github.com/o3co/protobuf.interceptors)）のうち **認証・トークン発行** を担当します。

OAuth 2.0 / OpenID Connect プロバイダー。ユーザーをサインインさせ — ユーザーサービスが検証するパスワード、上流の ID プロバイダー、またはパスキーによって — JWT のアクセストークン・リフレッシュトークン・ID トークンを発行する。下流のサービスは、公開された鍵を使ってそれらをオフラインで検証する。セッションログインと認可コードフローはどちらも同じ形式のトークンを発行し、同じイントロスペクションエンドポイントで応答し、下流では同じ方法で検証される。

## 責務と役割

**役割。** [auth](https://github.com/o3co/auth) スタックの認証・トークン発行層。
クライアントはユーザーをここに通すか、自分自身を認証して、トークンを受け取る。
トークンの宛先となるサービスは、`/.well-known/jwks.json` に対してそれを検証するか、
`/oauth/introspect` に問い合わせる。周辺のリポジトリとの関係:

- [auth.policy-verifier](https://github.com/o3co/auth.policy-verifier) は認可判定を
  行う — この主体がこのリソースに対してこの操作をしてよいか;
- [protobuf.interceptors](https://github.com/o3co/protobuf.interceptors) は
  gRPC / ConnectRPC サービスの内側でそれを実施する。イントロスペクションはこの
  プロバイダーに、判定は policy-verifier に問い合わせる;
- [auth.proxy](https://github.com/o3co/auth.proxy) は任意の境界防御: サービスに
  トラフィックが届く前にトークンを検証するリバースプロキシ。

**担うもの:**

- エンドユーザーの認証: デプロイメントのユーザーサービス（「the Store」）が検証する
  ローカルログイン、上流 ID プロバイダーを通じたフェデレーションログイン、パスキー。
  それによって作られるブラウザセッションとログアウト — サインインさせた RP への
  バックチャネル・フロントチャネルログアウトを含む;
- クライアントの認証: クライアントシークレット、`private_key_jwt`、PKCE で束縛される
  公開クライアント;
- トークンの発行: 認可コード、リフレッシュトークン（ローテーションとリプレイ検知付き）、
  クライアントクレデンシャル、JWT bearer、セッションの各グラントと、任意の
  デバイス・トークン交換・パスキーの各グラント。ID トークンと userinfo;
- トークンのライフサイクル: イントロスペクション、失効、送信者制約（DPoP、mTLS）、
  そしてファーストパーティでないクライアントに対する同意ステップ;
- 検証側が必要とするものの公開: JWKS と OpenID ディスカバリードキュメント;
- 上流 IdP トークンの保持 — セッションのために、またフェデレーショングラントでは、
  ユーザーの継続的な同意に基づいて動くバックエンドのために。

**担わないもの:**

- 認可判定: トークンが示すのは主体が誰で、どのスコープと audience に対して発行された
  かまで。リクエストを許可するかどうかは auth.policy-verifier またはサービス自身が
  判断する;
- サービス内での実施;
- ユーザーレコード: デプロイメントでは、ユーザー、パスワード、メール確認は
  デプロイメントのユーザーサービスにあり、プロバイダーはそのサービスの API を
  通じてのみ扱う（core の YAML ユーザーリポジトリは開発・テスト用のアダプター）;
- ログインページと同意ページ: デプロイメントが自前で提供し、プロバイダーはそこへ
  リダイレクトする（`endpoints.login.url`、`endpoints.consent.url`）;
- サインアップ、アカウント回復、メール。

**独立したサービスである理由。** 署名鍵とセッション状態を保持するのがここだから。
発行を判定・実施から切り離しておくことで、トークンを発行できる鍵を RP が持つ必要が
なくなり（デフォルトの署名アルゴリズムは非対称）、判定点を発行に触れずに差し替え
られ、各層を独立してスケール・デプロイ・監査できる。

## 特徴

- **モジュラー構成** — 必要なモジュールだけを選択。API のみのデプロイではセッション、フェデレーション、認可コードを丸ごとスキップ可能。
- **JWT アルゴリズム選択** — EdDSA（デフォルト）, ES256, RS256, HS256。デフォルトが非対称なので JWKS エンドポイント (`/.well-known/jwks.json`) が実際の検証鍵を公開し、RP がトークンを**発行**できる鍵を持つことがない。HS256 も選択可能だが JWKS は公開されない: ルートは `404 jwks_not_published` を返す。
- **OAuth 2.0 準拠** — PKCE 必須の認可コードフロー（RFC 7636。クライアント登録が `plain` を許可しない限り `S256`）、トークンイントロスペクション (RFC 7662)、失効 (RFC 7009)、ローテーションとリプレイ検知付きのリフレッシュトークン
- **セッション認証** — ユーザーサービスに対するローカルのユーザー名/パスワードログインと、`federation-*` パッケージによるフェデレーションログイン（[パッケージ構成](#パッケージ構成)を参照）
- **レート制限** — エンドポイント毎に設定可能
- **HOCON 設定** — Zod バリデーション + 環境変数オーバーライド

## Quick Start

```bash
npx @o3co/create-auth-provider my-auth-app
cd my-auth-app
pnpm install
```

スキャフォールドはデフォルトのままでは起動しない。`pnpm run debug` は `.env`
ファイルを読まず、シェルの環境変数から次のものを必要とする: issuer
（`OAUTH_JWT_ISSUER`）、署名鍵のペア、セッションシークレット、ユーザーサービスの
2 つの URL（`CLIENT_USER_AUTHENTICATE_URL`、`CLIENT_USER_AUTHENTICATE_BY_TOKEN_URL`）、
そして `localhost:6379` の Redis。コマンドは[テンプレートの README](templates/standalone/README.ja.md#使い方)
に、スキャフォルダーが何を生成するかは [create-app](create-app/README.ja.md) にある。

## アーキテクチャ

`packages/` 配下のすべてのパッケージは `core` に依存し、`core` はそのいずれにも
依存しない。依存の向き:

```text
core                          contracts, module system, config, tokens, keys
├── oauth                     /oauth/*
│   ├── federation-grants
│   └── device-grant          (also depends on session)
├── session                   /session/*
│   └── federation-*          one package per upstream identity provider
├── dpop · mtls · webauthn · oauth-token-exchange
├── redis                     (dpop is an optional peer)
└── foundation
templates/standalone          composes the packages above; create-app copies it
```

`oauth` と `session` は互いに依存しない。アダプター（`redis`、`foundation`、
`federation-*`）同士も依存しない。どのモジュールを組み込み、各コンポーネントスロットを
どのアダプターで埋めるかは、デプロイメントのコンポジションルート — standalone
テンプレート、または独自のアプリ — が選ぶ。

## パッケージ構成

各パッケージの README に、そのパッケージが何を担い、なぜ分かれているかが書かれている。要約:

| パッケージ | npm | 担うもの | 別パッケージである理由 |
| --- | --- | --- | --- |
| [`packages/core`](packages/core/) | `@o3co/auth-provider-core` | 他の全パッケージが埋めるポートとコンポーネントスロット、モジュールシステムとブートプランナー、設定スキーマ、トークンの署名と検証、鍵ストア、JWKS、ディスカバリー、ヘルス・レディネスのルーター、インプロセスのアダプター | 他の全パッケージが依存し、自身はそのいずれにも依存しない唯一のパッケージ: 契約がここにあるので、アダプターはポートを使う側のパッケージに依存せずにポートを実装できる。データベースドライバーは持たない |
| [`packages/oauth`](packages/oauth/) | `@o3co/auth-provider-oauth` | `/oauth/*`: トークンエンドポイントとグラントのディスパッチ、`/authorize` と同意、イントロスペクション、失効、userinfo、ログアウト。認可コード・リフレッシュトークン・クライアントクレデンシャル・JWT bearer・セッションの各グラント。クライアント認証 | OAuth の HTTP 面。デプロイメントが提供するグラントは、組み込むモジュールで選ぶ |
| [`packages/session`](packages/session/) | `@o3co/auth-provider-session` | ブラウザセッション: `/session/login`、`/session/logout`、CSRF、`express-session` のストア、そして `federation-*` アダプターが差し込まれるフェデレーションログインのルート | 任意: API のみのデプロイメントにはブラウザセッションがない |
| [`packages/device-grant`](packages/device-grant/) | `@o3co/auth-provider-device-grant` | RFC 8628 デバイス認可グラント — TV、CLI、IoT 向けのデバイスコードフロー | 独自のエンドポイントとストアを持つ任意のグラント |
| [`packages/oauth-token-exchange`](packages/oauth-token-exchange/) | `@o3co/auth-provider-oauth-token-exchange` | RFC 8693 トークン交換 — on-behalf-of、委譲 (`act`)、scope と audience の縮小 | 任意のグラント |
| [`packages/webauthn`](packages/webauthn/) | `@o3co/auth-provider-webauthn` | パスキーの登録とパスキー認証グラント | 任意。バージョンを厳密に固定した WebAuthn ライブラリを含む |
| [`packages/dpop`](packages/dpop/) | `@o3co/auth-provider-dpop` | DPoP (RFC 9449) の送信者制約付きトークン | core のトークンバインディングスロットへのプラグイン。組み込んで有効化しない限り動かない |
| [`packages/mtls`](packages/mtls/) | `@o3co/auth-provider-mtls` | mTLS (RFC 8705) の証明書に束縛されたトークン。X.509 のパス検証と失効確認を含む | dpop と同じ。加えて X.509 ライブラリと失効情報の取得処理を含む |
| [`packages/federation-google`](packages/federation-google/) | `@o3co/auth-provider-federation-google` | Google によるサインイン | 上流 ID プロバイダーごとに 1 パッケージ: 登録するものだけをインストールする |
| [`packages/federation-github`](packages/federation-github/) | `@o3co/auth-provider-federation-github` | GitHub によるサインイン | 同上 |
| [`packages/federation-apple`](packages/federation-apple/) | `@o3co/auth-provider-federation-apple` | Sign in with Apple — `form_post` コールバック、ローテーションする ES256 クライアントシークレット | 同上 |
| [`packages/federation-oidc`](packages/federation-oidc/) | `@o3co/auth-provider-federation-oidc` | issuer 指定で任意の OpenID Connect ID プロバイダー、issuer ごとに 1 インスタンス | 同上 |
| [`packages/federation-grants`](packages/federation-grants/) | `@o3co/auth-provider-federation-grants` | フェデレーショングラント（#593）: ユーザーの継続的な同意に基づき、セッションなしでクライアントが上流アクセストークンを取得する | 任意。委譲のルートとその同意フロー。`federation-oidc` が必要: 委譲ができるのは汎用 OpenID Connect アダプターだけである |
| [`packages/redis`](packages/redis/) | `@o3co/auth-provider-redis` | core のストアポートの Redis 実装。複数レプリカのデプロイメント向け | データベースドライバーを core の外に置く。standalone テンプレートはどのデプロイメントでもこれを必要とする（refresh token family が Redis にある）。これなしで済むのは、単一レプリカで動く独自のコンポジションルートだけ |
| [`packages/foundation`](packages/foundation/) | `@o3co/auth-provider-foundation` | HTTP ユーザーリポジトリ — ユーザーサービス（「the Store」）のクライアント | 外部サービス向けの本番用アダプターを core の外に置く |
| [`templates/standalone`](templates/standalone/) | — | デプロイ可能なコンポジションルート: モジュールの選択、設定、ロガー、シャットダウン、Docker | デプロイメントごとの選択。import ではなくコピーされ、公開されない |
| [`create-app`](create-app/) | `@o3co/create-auth-provider` | テンプレートを新しいプロジェクトにコピーする `npx` スキャフォルダー | `bin` 付きで単独公開される |

## エンドポイント

standalone テンプレートのような構成での主なエンドポイント。任意のパッケージは
独自のもの（デバイス認可、WebAuthn のセレモニー、フェデレーショングラント）を追加
する。各パッケージの README にそのルートの一覧がある。

| エンドポイント | パッケージ | 説明 |
| --- | --- | --- |
| `POST /oauth/token` | oauth | トークンエンドポイント: 組み込まれた全グラントを `grant_type` でディスパッチ |
| `GET`, `POST /oauth/authorize` | oauth | 認可コードフロー (PKCE) |
| `GET`, `POST /oauth/consent` | oauth | デプロイメントの同意ページが何について尋ね、答えをどこに送るか。同意ストアが配線されているときだけマウントされる（テンプレートは `CONSENT_STORE_ADAPTER=none` で出荷） |
| `POST /oauth/introspect` | oauth | トークンイントロスペクション (RFC 7662) |
| `POST /oauth/revoke` | oauth | トークン失効 (RFC 7009) |
| `GET`, `POST /oauth/userinfo` | oauth | OpenID Connect の userinfo |
| `GET`, `POST /oauth/logout` | oauth | RP 起点のログアウトと、バックチャネルログアウトのカスケード |
| `GET /.well-known/openid-configuration` | core | ディスカバリー。`oauthModule` が組み込まれているときに提供される |
| `GET /.well-known/jwks.json` | core | 検証鍵（`oauth.jwt.jwksPath` で移動できる）。HS256 では `404 jwks_not_published` を返す |
| `GET /session/csrf` | session | double-submit CSRF トークンの発行 |
| `POST /session/login` | session | ローカル認証 |
| `POST /session/logout` | session | ブラウザセッションの終了 |
| `GET /session/oauth/federation/:name` | session | フェデレーションログインの開始（コールバックは `…/:name/callback`） |
| `GET /_healthcheck`, `GET /readyz` | core | liveness と readiness のルーター。コンポジションルートがマウントする |

## 設定

HOCON 設定ファイル + 環境変数オーバーライド。設定スキーマは登録されたモジュールに依存する。`@o3co/auth-provider-core` がライブラリのデフォルトを `reference.conf` として同梱し、コンポジションルートがその上に自前のファイルを重ねる。

**Core (常に必要):**

```hocon
http { port = 3000 }
oauth {
  jwt {
    # Required. Canonical issuer stamped as `iss` on every minted token:
    # absolute https URL (http only for a loopback host), no query or fragment.
    # Boot fails when unset — it is never derived from the Host header.
    issuer = ${?OAUTH_JWT_ISSUER}
    signingKey {
      provider = "local"           # "local" is the only built-in; extend via KeyStoreFactory
      local {
        # Default. Asymmetric, so /.well-known/jwks.json publishes a real
        # verification key and no relying party ever holds a key that can
        # also MINT tokens. Required — there is no key-material default:
        #   openssl genpkey -algorithm ed25519 -out jwt-private.pem
        #   openssl pkey -in jwt-private.pem -pubout -out jwt-public.pem
        algorithm = "EdDSA"        # EdDSA | ES256 | RS256 | HS256
        privateKeyPath = ${?OAUTH_JWT_PRIVATE_KEY_PATH}
        publicKeyPath  = ${?OAUTH_JWT_PUBLIC_KEY_PATH}
        # HS256 instead: set algorithm = "HS256" and supply a secret of at
        # least 32 bytes (`openssl rand -hex 32`). No JWKS is published.
        # secret = ${?OAUTH_JWT_SECRET}
      }
    }
  }
  # Seconds, positive, <= 1 year. `defaultExpiresIn` is what every grant
  # mints; `maxExpiresIn` (unset = the default) is the most a token-exchange
  # request's `expires_in` can obtain. `expiresIn` is a deprecated alias of
  # `defaultExpiresIn`, still read while that key is unset.
  accessToken  { defaultExpiresIn = 3600, maxExpiresIn = 3600 }
  refreshToken { expiresIn = 86400 }  # seconds, positive, <= 1 year
}
```

**グラント。** 組み込みのグラントはライブラリのデフォルトではすべて無効。デプロイメントが提供するものを有効にする:

```hocon
oauth.grants {
  authorization_code { enabled = true }   # PKCE is mandatory; S256 unless a client allows plain
  refresh_token      { enabled = true }
  session            { enabled = true }
}
```

**セッション (`sessionModule` 登録時):**

```hocon
# `secret` signs the cookie that IS the authenticated session: at least
# 32 bytes (256 bits), e.g. `openssl rand -hex 32`.
session { secret = ${SESSION_SECRET} }

# One section per federation. `type` names the adapter package and defaults
# to the section's name; each adapter's README lists its settings.
federations {
  google {
    enabled = false
    # clientId, clientSecret, callbackURL — required when enabled = true
  }
  # okta { enabled = false, type = "oidc" }   # any OpenID Connect IdP, by issuer
}
```

完全な設定例: [`templates/standalone/config/application.conf`](templates/standalone/config/application.conf)

## 開発

```bash
pnpm install
pnpm run build    # build all packages
pnpm run test     # test all packages (the Redis adapters' tests start Redis in Docker)
pnpm run lint
```

## Docker

```bash
npx @o3co/create-auth-provider my-auth-app
cd my-auth-app
docker build --target runtime -t my-auth .   # or: make build IMAGE=my-auth
```

`--target runtime` が重要: Dockerfile の最後のステージは、`make dev` が実行する
ホットリロード用の `develop` イメージである。本番イメージの実行 — そのための
compose ファイル、secret としての鍵ファイル、それなしでは起動を拒否する設定 — は
テンプレートの README の [Docker](templates/standalone/README.ja.md#docker) 節と
`docker-compose.production.yml` にある。

## 運用

- [docs/operator-runbook.md](docs/operator-runbook.md) — 運用: デプロイ形態と起動拒否、liveness と readiness、各依存先で fail-closed がどう見えるか、アラート対象のログ・監査イベント、Redis のキーファミリーとサイジング、鍵のローテーション、アップグレードとロールバック。
- [docs/release-runbook.md](docs/release-runbook.md) — リリースの切り方。[docs/release-policy.md](docs/release-policy.md) — リリースと廃止された設定キーのラベル付け。
- [docs/adapter-surface.md](docs/adapter-surface.md) — コンポジションルートが埋められる全コンポーネントスロットと、何がスロットになり得るかを決める境界。

## 関連プロジェクト

- [auth.policy-verifier](https://github.com/o3co/auth.policy-verifier) — 認可判定のための ABAC ポリシーエンジン
- [auth.proxy](https://github.com/o3co/auth.proxy) — トークン検証リバースプロキシ
- [protobuf.interceptors](https://github.com/o3co/protobuf.interceptors) — gRPC / ConnectRPC 向け protobuf option ベースの認可 interceptor (auth.provider にイントロスペクション、auth.policy-verifier に認可を問い合わせ)
- [auth](https://github.com/o3co/auth) — アーキテクチャドキュメントと E2E テスト

## ライセンス

Apache License 2.0 — Copyright 2026 1o1 Co. Ltd.
