# auth.provider

> このリポジトリは、[auth](https://github.com/o3co/auth) スタックの 3 層責務分離（認証・トークン発行 / [認可判定](https://github.com/o3co/auth.policy-verifier) / [認可実施](https://github.com/o3co/protobuf.interceptors)）のうち **認証・トークン発行** を担当します。

OAuth 2.0 / OIDC プロバイダー。セッションベースのログインや認可コードフローで JWT を発行できる。トークン形式、イントロスペクション、下流での検証方法は同一。

## 特徴

- **モジュラー構成** — 必要なモジュールだけを選択。API のみのデプロイではセッション、フェデレーション、認可コードを丸ごとスキップ可能。
- **JWT アルゴリズム選択** — EdDSA（デフォルト）, ES256, RS256, HS256。デフォルトが非対称なので JWKS エンドポイント (`/.well-known/jwks.json`) が実際の検証鍵を公開し、RP がトークンを**発行**できる鍵を持つことがない。HS256 も選択可能だが JWKS は公開されない。
- **OAuth 2.0 準拠** — PKCE 対応認可コードフロー (RFC 7636)、トークンイントロスペクション (RFC 7662)、リフレッシュトークン
- **セッション認証** — ローカル ユーザー名/パスワードログイン + OAuth フェデレーション（Google、GitHub、per-federation `defineModule(...)` によるカスタムプロバイダー対応）
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
│ /oauth  │ /session  │  HTTP user         │
│ routes  │  routes   │  adapter           │
├─────────┴───────────┴────────────────────┤
│                   core                    │
│  Module system · KeyStore · Repositories │
└──────────────────────────────────────────┘
```

- **core** — インターフェース、設定スキーマ、トークンサービス、アプリファクトリ。常に必要。
- **oauth** — OAuth ルート (`/oauth/token`, `/oauth/authorize`, `/oauth/introspect`)。トークン発行に必須。
- **session** — セッションログイン + OAuth フェデレーション（Google、GitHub、Apple、拡張可能）。オプション — API のみのデプロイではスキップ可能。
- **foundation** — 本番向け HTTP ユーザー認証アダプター（「the Store」のクライアント）。オプション。
- **webauthn / dpop / mtls / oauth-token-exchange / redis** — オプションの capability / アダプターモジュール。[パッケージ構成](#パッケージ構成)を参照。

## パッケージ構成

| パッケージ | npm | 説明 |
| --- | --- | --- |
| [`packages/core`](packages/core/) | `@o3co/auth-provider-core` | 全パッケージが依存するコア抽象: モジュールシステム、トークンサービス、リポジトリインターフェース、設定スキーマ |
| [`packages/oauth`](packages/oauth/) | `@o3co/auth-provider-oauth` | OAuth 2.0 ルートモジュール: `/oauth/token`, `/oauth/authorize`, `/oauth/introspect` |
| [`packages/oauth-token-exchange`](packages/oauth-token-exchange/) | `@o3co/auth-provider-oauth-token-exchange` | RFC 8693 Token Exchange グラント — on-behalf-of、委譲 (`act`)、scope/audience 縮小 |
| [`packages/session`](packages/session/) | `@o3co/auth-provider-session` | セッション + フェデレーションルートモジュール: ログイン、ログアウト、OAuth 2.0 フェデレーション |
| [`packages/webauthn`](packages/webauthn/) | `@o3co/auth-provider-webauthn` | Passkey (WebAuthn) クレデンシャルライフサイクル + 認証グラント（AS スコープのみ） |
| [`packages/dpop`](packages/dpop/) | `@o3co/auth-provider-dpop` | DPoP (RFC 9449) sender-constrained アクセストークン |
| [`packages/mtls`](packages/mtls/) | `@o3co/auth-provider-mtls` | mTLS (RFC 8705) sender-constrained アクセストークン |
| [`packages/federation-google`](packages/federation-google/) | `@o3co/auth-provider-federation-google` | Google フェデレーションプロバイダー |
| [`packages/federation-github`](packages/federation-github/) | `@o3co/auth-provider-federation-github` | GitHub フェデレーションプロバイダー |
| [`packages/federation-apple`](packages/federation-apple/) | `@o3co/auth-provider-federation-apple` | Sign in with Apple フェデレーションプロバイダー — `form_post` コールバック、ローテーションする ES256 クライアントシークレット |
| [`packages/redis`](packages/redis/) | `@o3co/auth-provider-redis` | Redis バックエンドのアダプターと `defineModule` マニフェスト |
| [`packages/foundation`](packages/foundation/) | `@o3co/auth-provider-foundation` | 本番向け HTTP ユーザー認証アダプター（「the Store」のクライアント） |
| [`templates/standalone`](templates/standalone/) | — | デプロイ可能なサーバーテンプレート (コンポジションルート) |
| [`create-app`](create-app/) | `@o3co/create-auth-provider` | CLI スキャフォルダー |

## エンドポイント

| エンドポイント | モジュール | 説明 |
| --- | --- | --- |
| `POST /oauth/token` | oauth | トークン発行 (セッション, 認可コード, リフレッシュ) |
| `GET /oauth/authorize` | oauth | 認可コードフロー (PKCE) |
| `POST /oauth/introspect` | oauth | トークンイントロスペクション (RFC 7662) |
| `GET /.well-known/jwks.json` | core | JWKS エンドポイント (非対称アルゴリズムのみ) |
| `GET /session/csrf` | session | double-submit CSRF トークンの発行 |
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
    # 必須。すべてのトークンの `iss` に刻まれる canonical issuer。
    # 絶対 https URL（`http` は loopback ホストのみ）、query / fragment 不可。
    # 未設定なら起動に失敗する — Host ヘッダから導出されることはない。
    issuer = ${?OAUTH_JWT_ISSUER}
    signingKey {
      provider = "local"           # 組み込みは "local" のみ。KeyStoreFactory で拡張可能
      local {
        # デフォルト。非対称なので /.well-known/jwks.json が実際の検証鍵を
        # 公開でき、RP にトークンを発行できる鍵を渡さずに済む。
        # 鍵素材のデフォルトは存在しない（未設定なら起動失敗）:
        #   openssl genpkey -algorithm ed25519 -out jwt-private.pem
        #   openssl pkey -in jwt-private.pem -pubout -out jwt-public.pem
        algorithm = "EdDSA"        # EdDSA | ES256 | RS256 | HS256
        privateKeyPath = ${?OAUTH_JWT_PRIVATE_KEY_PATH}
        publicKeyPath  = ${?OAUTH_JWT_PUBLIC_KEY_PATH}
        # HS256 を使う場合: algorithm = "HS256" にして 32 バイト以上の
        # シークレット（`openssl rand -hex 32`）を設定。JWKS は公開されない。
        # secret = ${?OAUTH_JWT_SECRET}
      }
    }
  }
  accessToken  { expiresIn = 3600 }   # 秒、正の整数、上限 1 年
  refreshToken { expiresIn = 86400 }  # 秒、正の整数、上限 1 年
}
```

**セッション (`sessionModule` 登録時):**

```hocon
# `secret` は「認証済みセッションそのもの」である Cookie に署名する鍵。
# 32 バイト（256 bit）以上が必須（例: `openssl rand -hex 32`）。
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
