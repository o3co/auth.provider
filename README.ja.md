# auth.provider

OAuth 2.0 プロバイダー。ログイン、JWT アクセス/リフレッシュトークン発行、トークンイントロスペクション (RFC 7662) を担当。PKCE (RFC 7636)、DID 認証 (Ed25519)、Google OAuth フェデレーションに対応。

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

## セットアップ

```bash
pnpm install
pnpm run build
pnpm run start
```

## 開発

```bash
pnpm run debug    # tsx watch モード
```

## Docker

```bash
make docker       # ランタイムイメージのビルド
```

## 関連プロジェクト

- [auth.proxy](https://github.com/o3co/auth.proxy) — トークン検証リバースプロキシ
- [auth.policy-verifier](https://github.com/o3co/auth.policy-verifier) — DSL 不要の ABAC ポリシー検証器
- [auth](https://github.com/o3co/auth) — アーキテクチャドキュメントとクロスコンポーネント E2E テスト
- [grpc.authz](https://github.com/o3co/grpc.authz) — gRPC 認可ミドルウェア

## ライセンス

Apache License 2.0
