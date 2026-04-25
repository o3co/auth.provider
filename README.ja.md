# auth.provider

> このリポジトリは、[auth](https://github.com/o3co/auth) スタックの 3 層責務分離（認証・トークン発行 / [認可判定](https://github.com/o3co/auth.policy-verifier) / [認可実施](https://github.com/o3co/protobuf.interceptors)）のうち **認証・トークン発行** を担当します。

OAuth 2.0 / OIDC プロバイダー。従来のログインフローや認可コードフローで JWT を発行できる。トークン形式、イントロスペクション、下流での検証方法は同一。

## 特徴

- **モジュラー構成** — 必要なモジュールだけを選択。API のみのデプロイではセッション、フェデレーション、認可コードを丸ごとスキップ可能。
- **JWT アルゴリズム選択** — HS256, RS256, ES256, EdDSA。非対称アルゴリズムの場合は JWKS エンドポイント (`/.well-known/jwks.json`) を自動公開。
- **OAuth 2.0 準拠** — PKCE 対応認可コードフロー (RFC 7636)、トークンイントロスペクション (RFC 7662)、リフレッシュトークン
- **セッション認証** — Passport.js ローカルストラテジー + OAuth フェデレーション（Google、GitHub、`FederationProviderFactory` によるカスタムプロバイダー対応）
- **レート制限** — エンドポイント毎に設定可能
- **HOCON 設定** — Zod バリデーション + 環境変数オーバーライド

## Quick Start

```bash
npx @o3co/create-auth-provider my-auth-app
cd my-auth-app
pnpm install
pnpm build
```

## アーキテクチャ

```text
┌──────────────────────────────────────────┐
│           コンポジションルート              │
│  (standalone テンプレート or 独自アプリ)   │
├─────────┬───────────┬────────────────────┤
│  oauth  │  session  │    foundation      │
│ /oauth  │ /session  │  Redis, HTTP       │
│ routes  │  routes   │  adapters          │
├─────────┴───────────┴────────────────────┤
│                   core                    │
│  GrantRegistry · KeyStore · Repositories │
└──────────────────────────────────────────┘
```

- **core** — インターフェース、設定スキーマ、トークンサービス、アプリファクトリ。常に必要。
- **oauth** — OAuth ルート (`/oauth/token`, `/oauth/authorize`, `/oauth/introspect`)。トークン発行に必須。
- **session** — セッションログイン + OAuth フェデレーション（Google、GitHub、拡張可能）。オプション — API のみのデプロイではスキップ可能。
- **foundation** — 本番向けリポジトリアダプター (Redis コードストア, HTTP ユーザー検索)。オプション。

## パッケージ構成

| パッケージ | npm | 説明 |
| --- | --- | --- |
| [`packages/core`](packages/core/) | `@o3co/auth-provider-core` | グラントレジストリ、トークンサービス、リポジトリインターフェース、設定スキーマ |
| [`packages/oauth`](packages/oauth/) | `@o3co/auth-provider-oauth` | OAuth ルート: `/oauth/token`, `/oauth/authorize`, `/oauth/introspect` |
| [`packages/session`](packages/session/) | `@o3co/auth-provider-session` | セッションルート, Passport.js, OAuth フェデレーション（Google・GitHub・拡張可能） |
| [`packages/foundation`](packages/foundation/) | `@o3co/auth-provider-foundation` | Redis コードストア, HTTP ユーザー/クライアントリポジトリ |
| [`templates/standalone`](templates/standalone/) | — | デプロイ可能なサーバーテンプレート (コンポジションルート) |
| [`create-app`](create-app/) | `@o3co/create-auth-provider` | CLI スキャフォルダー |

## エンドポイント

| エンドポイント | モジュール | 説明 |
| --- | --- | --- |
| `POST /oauth/token` | oauth | トークン発行 (セッション, 認可コード, リフレッシュ) |
| `GET /oauth/authorize` | oauth | 認可コードフロー (PKCE) |
| `POST /oauth/introspect` | oauth | トークンイントロスペクション (RFC 7662) |
| `GET /.well-known/jwks.json` | core | JWKS エンドポイント (非対称アルゴリズムのみ) |
| `POST /session/login` | session | ローカル認証 |
| `POST /session/logout` | session | セッション破棄 |
| `GET /_healthcheck` | core | ヘルスチェック |

## 設定

HOCON 設定ファイル + 環境変数オーバーライド。設定スキーマは登録されたモジュールに依存する:

**Core (常に必要):**

```hocon
http { port = 3000 }
oauth {
  jwt {
    issuer = ${?OAUTH_JWT_ISSUER}
    signingKey {
      provider = "local"           # 組み込みは "local" のみ。KeyStoreFactory で拡張可能
      local {
        algorithm = "HS256"        # HS256 | RS256 | ES256 | EdDSA
        secret = ${?OAUTH_JWT_SECRET}
        # 非対称の場合: privateKey/privateKeyPath + publicKey/publicKeyPath
      }
    }
  }
  accessToken { expiresIn = 3600 }
  refreshToken { expiresIn = 86400 }
}
```

**セッション (`sessionModule` 登録時):**

```hocon
session { secret = ${SESSION_SECRET} }

# ショートハンド: キー名 = プロバイダータイプ (google、github、またはカスタム登録タイプ)
federations {
  google {
    enabled = false
    # clientId, clientSecret, callbackURL — enabled = true のとき必須
  }
  # github { enabled = false }
}
```

完全な設定例: [`templates/standalone/config/application.conf`](templates/standalone/config/application.conf)

## 開発

```bash
pnpm install
pnpm -r build     # 全パッケージビルド
pnpm -r test      # 全テスト実行
```

## Docker

```bash
npx @o3co/create-auth-provider my-auth-app
cd my-auth-app
docker build -t my-auth .
```

## 関連プロジェクト

- [auth.policy-verifier](https://github.com/o3co/auth.policy-verifier) — 認可判定のための ABAC ポリシーエンジン
- [auth.proxy](https://github.com/o3co/auth.proxy) — トークン検証リバースプロキシ
- [protobuf.interceptors](https://github.com/o3co/protobuf.interceptors) — gRPC / ConnectRPC 向け protobuf option ベースの認可 interceptor (auth.provider にイントロスペクション、auth.policy-verifier に認可を問い合わせ)
- [auth](https://github.com/o3co/auth) — アーキテクチャドキュメントと E2E テスト

## ライセンス

Apache License 2.0 — Copyright 2026 1o1 Co. Ltd.
