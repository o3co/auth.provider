# auth.provider

OAuth 2.0 プロバイダー。ログイン、JWT アクセス/リフレッシュトークン発行、トークンイントロスペクション (RFC 7662) を担当。PKCE (RFC 7636)、DID 認証 (Ed25519)、Google OAuth フェデレーションに対応。

## パッケージ構成

| パッケージ | 説明 |
| --- | --- |
| `packages/core` (`@o3co/auth-provider-core`) | コアライブラリ: OAuth 2.0 ロジック、トークン発行、イントロスペクション、リポジトリ |
| `templates/standalone` (`@o3co/auth-provider-standalone`) | コアライブラリを使用するリファレンス実装（スタンドアロンアプリ） |
| `create-app` (`create-o3co-auth-provider`) | プロジェクトスキャフォルダー |

## エンドポイント

| エンドポイント | 説明 |
| --- | --- |
| `POST /oauth/token` | アクセストークン発行（セッション / 認可コード / DID グラント） |
| `GET /oauth/authorize` | 認可コードフロー (PKCE) |
| `POST /oauth/introspect` | トークンイントロスペクション (RFC 7662) |
| `POST /session/login` | ローカル認証 (Passport.js) |
| `POST /session/logout` | セッション破棄 |

## 機能

- JWT (HS256) アクセス/リフレッシュトークン発行
- PKCE (RFC 7636): `S256` / `plain`
- セッション固定攻撃対策: ログイン時に `session.regenerate()` を実行
- リプレイ攻撃対策: 認可コードは使用後に無効化
- DID 認証グラント (Ed25519)
- Google OAuth フェデレーション
- レート制限（ログイン、トークン、認可）
- HOCON 設定 + Zod バリデーション

## コアライブラリの使用

自分のプロジェクトに `@o3co/auth-provider-core` を依存関係として追加する:

```bash
npm install @o3co/auth-provider-core
```

OAuth 2.0 ルーターファクトリ、トークンサービス、リポジトリインターフェース、ミドルウェアを提供する。ピア依存関係 (`express`、`passport`、`passport-local`、`passport-oauth2-client-password`) は別途インストールが必要。

## 新規プロジェクトのスキャフォールド

`templates/standalone` テンプレートをベースに新しいスタンドアロンアプリを生成する:

```bash
npx create-o3co-auth-provider my-auth-app
cd my-auth-app
pnpm install
pnpm run build
```

## 開発

全パッケージのビルド:

```bash
pnpm -r run build
```

全テストの実行:

```bash
pnpm -r run test
```

スタンドアロンアプリのウォッチモード:

```bash
pnpm -r --filter @o3co/auth-provider-standalone run debug
```

## Docker

Dockerfile はスタンドアロンテンプレート (`templates/standalone/Dockerfile`) に含まれる。scaffold されたプロジェクトで直接ビルド可能:

```bash
cd my-auth-project
docker build -t my-auth .
```

## 関連プロジェクト

- [auth.proxy](https://github.com/o3co/auth.proxy) — トークン検証リバースプロキシ
- [auth.policy-verifier](https://github.com/o3co/auth.policy-verifier) — DSL 不要の ABAC ポリシー検証器
- [auth](https://github.com/o3co/auth) — アーキテクチャドキュメントとクロスコンポーネント E2E テスト
- [grpc.authz](https://github.com/o3co/grpc.authz) — gRPC 認可ミドルウェア

## ライセンス

Apache License 2.0
