# auth.provider

DID (分散型識別子) 認証対応の OAuth 2.0 プロバイダー。従来のログインフローでも DID ベースの暗号証明でも JWT を発行できる。トークン形式、イントロスペクション、下流での検証方法は同一。

## DID 認証

DID 認証を使うと、クライアントは [Decentralized Identifier](https://www.w3.org/TR/did-core/) に紐づく暗号鍵ペアで身元を証明できる。パスワードも事前共有シークレットも不要。サーバーがクライアントの DID Document を resolve し、公開鍵を取り出して署名を検証する。

```text
Client                              auth.provider
  │                                      │
  │  POST /oauth/token                   │
  │  grant_type=did                      │
  │  did=did:example:org:abc123          │
  │  message={"did":"...","nonce":"..."}  │
  │  signature=<Ed25519 署名>            │
  │ ──────────────────────────────────►  │
  │                                      │  1. DID Document を resolve
  │                                      │  2. 公開鍵を取得
  │                                      │  3. 署名を検証
  │                                      │  4. JWT を発行
  │  ◄──────────────────────────────────  │
  │  { access_token: "eyJ...", ... }     │
```

`DidDocumentResolver` インターフェースはプラグイン可能。自分の DID method (`did:web`, `did:key`, `did:ion`, その他任意) 向けの resolver を実装して起動時に注入する。

### 対応署名アルゴリズム

| アルゴリズム | 形式 | ライブラリ |
| --- | --- | --- |
| `ed25519_raw` (デフォルト) | 生の Ed25519 署名 + メッセージ | `@noble/ed25519` |
| `ed25519_jws` | Compact JWS (`alg=EdDSA`) | `jose` |
| `es256_jws` | Compact JWS (`alg=ES256`) | `jose` |
| `es256k_jws` | Compact JWS (`alg=ES256K`) | `jose` |

## 特徴

- **DID 認証グラント** — プラグイン可能な `DidDocumentResolver` インターフェース、DID Document の公開鍵による署名検証
- **モジュラー構成** — 必要なモジュールだけを選択。DID のみ？ セッション、フェデレーション、認可コードは丸ごとスキップ可能。
- **JWT アルゴリズム選択** — HS256, RS256, ES256, EdDSA。非対称アルゴリズムの場合は JWKS エンドポイント (`/.well-known/jwks.json`) を自動公開。
- **OAuth 2.0 準拠** — PKCE 対応認可コードフロー (RFC 7636)、トークンイントロスペクション (RFC 7662)、リフレッシュトークン
- **セッション認証** — Passport.js ローカルストラテジー + OAuth フェデレーション（Google、GitHub、`FederationProviderFactory` によるカスタムプロバイダー対応）
- **レート制限** — エンドポイント毎に設定可能
- **HOCON 設定** — Zod バリデーション + 環境変数オーバーライド

## Quick Start

```bash
npx create-o3co-auth-provider my-auth-app
cd my-auth-app
pnpm install
pnpm build
```

DID のみのデプロイ（セッション/フェデレーション不要）:

```typescript
import express from "express";
import { parseFile, validate } from "@o3co/ts.hocon";
import {
  AppConfigSchema,
  createApp,
  createKeyStoreFactory,
  registerBuiltinKeyStores,
} from "@o3co/auth-provider-core";
import { oauthDidModule } from "@o3co/auth-provider-did";
import { oauthModule } from "@o3co/auth-provider-oauth";

// HOCON 設定を読み込んで検証する（ネストされた oauth.jwt.signingKey シェイプは
// packages/core/config/application.conf を参照）。
const config = validate(parseFile("./config/application.conf"), AppConfigSchema);

// flatten() はネストされたアダプターサブセクションを { type, ...fields } に正規化する。
// `type` (repositories.*, session.storage) と `provider` (oauth.jwt.signingKey) の
// 両方のセレクターを受け付ける。完全な定義は packages/core/README.md を参照。
const flatten = (section: { type?: string; provider?: string } & Record<string, unknown>) => {
  const selector = section.type ?? section.provider;
  if (typeof selector !== "string") throw new TypeError("missing selector");
  const sub = section[selector];
  return {
    type: selector,
    ...(typeof sub === "object" && sub !== null && !Array.isArray(sub)
      ? (sub as Record<string, unknown>)
      : {}),
  };
};

const keyStoreFactory = createKeyStoreFactory();
registerBuiltinKeyStores(keyStoreFactory);
const keyStore = await keyStoreFactory.create(flatten(config.oauth.jwt.signingKey));

// ... clientRepository / codeRepository / myDidResolver をセットアップ ...

const { init, router } = createApp({
  express,
  config,
  keyStore,
  modules: [
    oauthModule({ clientRepository, codeRepository }),
    oauthDidModule({ resolver: myDidResolver }),
  ],
});

await init();
```

## アーキテクチャ

```text
┌─────────────────────────────────────────────────┐
│              コンポジションルート                  │
│    (standalone テンプレート or 独自アプリ)         │
├─────────┬───────────┬───────────┬───────────────┤
│  oauth  │  session  │    did    │  foundation   │
│ /oauth  │ /session  │ DID grant │ Redis, HTTP   │
│ routes  │  routes   │  handler  │  adapters     │
├─────────┴───────────┴───────────┴───────────────┤
│                      core                        │
│  GrantRegistry · KeyStore · Repositories · Config│
└─────────────────────────────────────────────────┘
```

- **core** — インターフェース、設定スキーマ、トークンサービス、アプリファクトリ。常に必要。
- **oauth** — OAuth ルート (`/oauth/token`, `/oauth/authorize`, `/oauth/introspect`)。トークン発行に必須。
- **did** — DID 認証グラント。オプション — DID ベースの認証を使う場合のみ。
- **session** — セッションログイン + OAuth フェデレーション（Google、GitHub、拡張可能）。オプション — API のみのデプロイではスキップ可能。
- **foundation** — 本番向けリポジトリアダプター (Redis コードストア, HTTP ユーザー検索)。オプション。

## パッケージ構成

| パッケージ | npm | 説明 |
| --- | --- | --- |
| [`packages/core`](packages/core/) | `@o3co/auth-provider-core` | グラントレジストリ、トークンサービス、リポジトリインターフェース、設定スキーマ |
| [`packages/did`](packages/did/) | `@o3co/auth-provider-did` | プラグイン可能な resolver による DID 認証グラント |
| [`packages/oauth`](packages/oauth/) | `@o3co/auth-provider-oauth` | OAuth ルート: `/oauth/token`, `/oauth/authorize`, `/oauth/introspect` |
| [`packages/session`](packages/session/) | `@o3co/auth-provider-session` | セッションルート, Passport.js, OAuth フェデレーション（Google・GitHub・拡張可能） |
| [`packages/foundation`](packages/foundation/) | `@o3co/auth-provider-foundation` | Redis コードストア, HTTP ユーザー/クライアントリポジトリ |
| [`templates/standalone`](templates/standalone/) | — | デプロイ可能なサーバーテンプレート (コンポジションルート) |
| [`create-app`](create-app/) | `create-o3co-auth-provider` | CLI スキャフォルダー |

## エンドポイント

| エンドポイント | モジュール | 説明 |
| --- | --- | --- |
| `POST /oauth/token` | oauth | トークン発行 (セッション, 認可コード, DID, リフレッシュ) |
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

**DID グラント (`oauthDidModule` 登録時):**

```hocon
oauth.grants.did {
  enabled = true
  algorithm = "ed25519_raw"   # ed25519_raw | ed25519_jws | es256_jws | es256k_jws
  messageMaxAgeSec = 300
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
npx create-o3co-auth-provider my-auth-app
cd my-auth-app
docker build -t my-auth .
```

## 関連プロジェクト

- [auth.policy-verifier](https://github.com/o3co/auth.policy-verifier) — 認可判定のための ABAC ポリシーエンジン
- [auth.proxy](https://github.com/o3co/auth.proxy) — トークン検証リバースプロキシ
- [grpc.authz](https://github.com/o3co/grpc.authz) — gRPC 認可ミドルウェア (auth.provider にイントロスペクション、auth.policy-verifier に認可を問い合わせ)
- [auth](https://github.com/o3co/auth) — アーキテクチャドキュメントと E2E テスト

## ライセンス

Apache License 2.0 — Copyright 2026 1o1 Co. Ltd.
