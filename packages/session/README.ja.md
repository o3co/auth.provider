# @o3co/auth-provider-session

[auth.provider](../../README.md) 向けセッション・フェデレーションルートモジュール。

ユーザー名/パスワードログイン、ログアウト、OAuth 2.0 フェデレーション（Google およびカスタムプロバイダー）を担当する。内部的には Passport.js を使用してストラテジーを管理する。

## インストール

このパッケージは **private** です。npm には公開されておらず、`auth.provider` モノリポ内でのみ利用できます。

```jsonc
// packages/*/package.json
{
  "dependencies": {
    "@o3co/auth-provider-session": "workspace:*"
  }
}
```

peer dependencies（ワークスペースルートに別途インストール）:

```
express@^5.0.0
passport@^0.7.0                (optional)
passport-local@^1.0.0          (optional)
passport-google-oauth20@^2.0.0  (optional)
```

## パブリック API

### `sessionModule`

```typescript
function sessionModule(params: {
  userRepository: UserRepository;
  express?: ExpressLike;
}): Module;
```

トップレベルのモジュール。セッションおよびフェデレーションルートを Express アプリにマウントする。

マウントされるルート:

| メソッド | パス                                             | 説明                                |
|---------|--------------------------------------------------|-------------------------------------|
| POST    | /session/login                                   | ユーザー名 / パスワードログイン       |
| POST    | /session/logout                                  | セッションログアウト                  |
| GET     | /session/oauth/federation/:provider              | OAuth フェデレーションフロー開始      |
| GET     | /session/oauth/federation/:provider/callback     | フェデレーションコールバック           |

---

### `createPassport`

```typescript
function createPassport(options: {
  pathResolver: PathResolver;
  userRepository: UserRepository;
  config: AppConfig;
}): Promise<PassportStatic>;
```

Passport インスタンスを生成・設定する。

- **LocalStrategy** — `username` と `password` フィールドで認証する。
- **GoogleStrategy** — `config.federations.google.enabled` が `true` のときに登録される。

---

### `createGoogleProvider`

```typescript
function createGoogleProvider(config: AppConfig): FederationProvider;
```

Google OAuth 2.0 用の `FederationProvider` を生成する。クライアント ID、クライアントシークレット、コールバック URL は `config` から読み取る。

---

### `FederationRegistry`

```typescript
class FederationRegistry {
  register(provider: FederationProvider): void;
  get(name: string): FederationProvider | undefined;
}
```

フェデレーションプロバイダーのレジストリ。カスタムプロバイダーを登録するには、このインスタンスを `sessionModule` に渡すか、モジュールの初期化前に populate する。

---

### `FederationProvider` (interface)

```typescript
interface FederationProvider {
  name: string;
  strategyName: string;
  scope: string[];
  enabled: boolean;
  validateRedirect(url: string): FederationResult<void>;
  resolveCallbackRedirect(session: unknown): FederationResult<string>;
}
```

カスタムの OAuth 2.0 / OIDC フェデレーションプロバイダーを追加する場合はこのインターフェースを実装する。

---

### `FederationResult<T>` (type)

```typescript
type FederationResult<T> =
  | { ok: true; value: T }
  | { ok: false; status: number; error: string; errorDescription: string };
```

`FederationProvider` のメソッドが返す判別共用体。`value` にアクセスする前に `ok` を確認すること。

## 使い方

```typescript
import express from "express";
import { createApp } from "@o3co/auth-provider-core";
import { sessionModule } from "@o3co/auth-provider-session";

const app = createApp(express, {
  config,
  keyStore,
  modules: [
    sessionModule({
      userRepository,
    }),
  ],
});
await app.init();
```

### FederationRegistry

```typescript
import { FederationRegistry } from "@o3co/auth-provider-session";

const registry = new FederationRegistry();
registry.register(myCustomProvider);
```

`FederationRegistry` は `sessionModule` 内部でフェデレーションプロバイダーを管理するために使用されます。組み込みの Google プロバイダーは `config.federations.google.enabled` が `true` の場合に自動的に登録されます。

## 関連

- [`@o3co/auth-provider-oauth`](../oauth/README.ja.md) — OAuth 2.0 トークン・認可ルート
- [`@o3co/auth-provider-did`](../did/README.ja.md) — DID 認証 grant
- [`@o3co/auth-provider-core`](../core/README.ja.md) — 共有型定義 (`Module`、`UserRepository`、`PathResolver`、`AppConfig`)
