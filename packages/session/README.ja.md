# @o3co/auth-provider-session

[auth.provider](../../README.md) 向けセッション・フェデレーションルートモジュール。

ユーザー名/パスワードログイン、ログアウト、OAuth 2.0 フェデレーション（Google、GitHub、およびカスタムプロバイダー）を担当する。内部的には Passport.js を使用してストラテジーを管理する。

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
passport-github2@^0.1.12        (optional — GitHub フェデレーションのみ)
```

GitHub フェデレーションには `passport-github2` と `@types/passport-github2` が必要です。オプションの peer dependency のため、利用する場合のみ以下を実行してインストールしてください:

```bash
pnpm add passport-github2 @types/passport-github2
```

Google のみ、またはフェデレーション不要のデプロイでは、このパッケージのインストールコストは発生しません。

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

| メソッド | パス | 説明 |
| --- | --- | --- |
| POST | /session/login | ユーザー名 / パスワードログイン |
| POST | /session/logout | セッションログアウト |
| GET | /session/oauth/federation/:name | OAuth フェデレーションフロー開始 |
| GET | /session/oauth/federation/:name/callback | フェデレーションコールバック |

`:name` パスパラメーターは `config.federations` のキー（例: `google`、`github`、`google-work`）に対応する。未知の名前は `404` を返す。

---

### `createPassport`

```typescript
function createPassport(options: {
  userRepository: UserRepository;
  federationProviders: ReadonlyMap<string, FederationProvider>;
}): Promise<PassportStatic>;
```

Passport インスタンスを生成・設定する。

- **LocalStrategy** — `username` と `password` フィールドで認証する。
- **フェデレーションストラテジー** — `federationProviders` の各プロバイダーに対して `provider.setupPassportStrategy(passport, { verifyUser })` を呼び出して登録する。

---

### `createFederationProviderFactory`

```typescript
function createFederationProviderFactory(): FederationProviderFactory;
```

組み込みタイプが未登録の空の `FederationProviderFactory`（`AdapterFactory<FederationProvider>`）を返す。`registerBuiltinFederations(factory)` を呼び出して組み込みの `"google"` と `"github"` を登録し、`factory.register(type, builder)` で独自タイプを追加できる。

---

### `registerBuiltinFederations`

```typescript
function registerBuiltinFederations(factory: FederationProviderFactory): void;
```

組み込みフェデレーションアダプターを `factory` に登録する:

| タイプ | プロバイダー | 必要な peer dep |
| --- | --- | --- |
| `"google"` | `createGoogleProvider` | `passport-google-oauth20` |
| `"github"` | `createGithubProvider` | `passport-github2` (optional) |

---

### `createGoogleProvider`

```typescript
function createGoogleProvider(config: {
  name: string;
  clientId: string;
  clientSecret: string;
  callbackURL: string;
  sessionDomain?: string;
  authCallbackUrl?: string;
  clientUrl?: string;
}): FederationProvider;
```

Google OAuth 2.0 用の `FederationProvider` を生成する。ストラテジーは `config.name` の名前で Passport に登録されるため、マルチテナント構成（例: `google` と `google-work` を別インスタンスとして共存）が可能。

---

### `createGithubProvider`

```typescript
function createGithubProvider(config: {
  name: string;
  clientId: string;
  clientSecret: string;
  callbackURL: string;
  sessionDomain?: string;
  authCallbackUrl?: string;
  clientUrl?: string;
}): FederationProvider;
```

GitHub OAuth 2.0 用の `FederationProvider` を生成する。`passport-github2`（オプションの peer dep）が必要なため、別途インストールすること。デフォルトのスコープは `["read:user", "user:email"]`。`externalId` のフォーマットは `"github:" + profile.id`。

---

### `FederationProvider` (interface)

```typescript
interface FederationProvider {
  readonly name: string;
  readonly scope: readonly string[];
  validateRedirect(url: string): FederationResult<void>;
  resolveCallbackRedirect(session: { redirectTo?: string }): FederationResult<string>;
  setupPassportStrategy(passport: PassportStatic, ctx: VerifyUserContext): Promise<void>;
}

interface VerifyUserContext {
  verifyUser: (externalId: string) => Promise<User | undefined>;
}
```

カスタムの OAuth 2.0 / OIDC フェデレーションプロバイダーを追加する場合はこのインターフェースを実装する。

- `name` — Passport ストラテジーの一意な識別子。`federationProviders` の Map キーと `passport.use()` に渡すストラテジー名の両方に使用される。
- `scope` — OAuth 2.0 スコープ。
- `validateRedirect` — フェデレーションフロー開始前にリダイレクト URL を検証する。
- `resolveCallbackRedirect` — コールバック後のリダイレクト先をセッションから解決する。
- `setupPassportStrategy` — Passport ストラテジーを登録する。モジュール初期化時に一度呼ばれる。

---

### `FederationProviderFactory` (type)

```typescript
type FederationProviderFactory = AdapterFactory<FederationProvider>;
```

`AdapterFactory<FederationProvider>` の型エイリアス。`factory.register(type, builder)` でカスタムプロバイダータイプを登録できる。

---

### `FederationResult<T>` (type)

```typescript
type FederationResult<T> =
  | { ok: true; value: T }
  | { ok: false; status: number; error: string; errorDescription: string };
```

`FederationProvider` のメソッドが返す判別共用体。`value` にアクセスする前に `ok` を確認すること。

## 使い方

### 基本的な使い方

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

`sessionModule` は内部で `createFederationProviderFactory` + `registerBuiltinFederations` を使い、`config.federations` を読み込んでプロバイダーを自動的にセットアップする。

### HOCON フェデレーション設定

**ショートハンド形式（キー名 = プロバイダータイプ）:**

```hocon
federations {
  google {
    enabled = true
    clientId = ${FEDERATIONS_GOOGLE_CLIENT_ID}
    clientSecret = ${FEDERATIONS_GOOGLE_CLIENT_SECRET}
    callbackURL = "https://auth.example.com/session/oauth/federation/google/callback"
  }

  github {
    enabled = true
    clientId = ${FEDERATIONS_GITHUB_CLIENT_ID}
    clientSecret = ${FEDERATIONS_GITHUB_CLIENT_SECRET}
    callbackURL = "https://auth.example.com/session/oauth/federation/github/callback"
  }
}
```

**明示的なマルチテナント形式（Google を 2 インスタンス）:**

```hocon
federations {
  google-personal {
    enabled = true
    type = "google"
    google {
      clientId = ${FEDERATIONS_GOOGLE_PERSONAL_CLIENT_ID}
      clientSecret = ${FEDERATIONS_GOOGLE_PERSONAL_CLIENT_SECRET}
      callbackURL = "https://auth.example.com/session/oauth/federation/google-personal/callback"
    }
  }

  google-work {
    enabled = true
    type = "google"
    google {
      clientId = ${FEDERATIONS_GOOGLE_WORK_CLIENT_ID}
      clientSecret = ${FEDERATIONS_GOOGLE_WORK_CLIENT_SECRET}
      callbackURL = "https://auth.example.com/session/oauth/federation/google-work/callback"
    }
  }
}
```

トップレベルのフィールドとネストされたサブセクションを混在させた形式（mixed shape）は起動時に明確なエラーで拒否される。

### カスタムフェデレーションプロバイダー

```typescript
import {
  createFederationProviderFactory,
  registerBuiltinFederations,
  type FederationProvider,
  type FederationProviderFactory,
} from "@o3co/auth-provider-session";

// ファクトリーを生成して組み込みを登録
const factory = createFederationProviderFactory();
registerBuiltinFederations(factory);

// カスタムプロバイダータイプを登録
factory.register("microsoft", async (config) => {
  // FederationProvider を構築して返す
  return {
    name: config.name as string,
    scope: ["openid", "profile", "email"],
    validateRedirect: (url) => ({ ok: true, value: undefined }),
    resolveCallbackRedirect: (session) => ({ ok: true, value: session.redirectTo ?? "/" }),
    setupPassportStrategy: async (passport, { verifyUser }) => {
      // passport-microsoft などを登録する
    },
  };
});

// config からプロバイダー Map を構築
const federationProviders = new Map<string, FederationProvider>();
for (const [name, section] of Object.entries(config.federations)) {
  if (!section.enabled) continue;
  const type = (section.type as string | undefined) ?? name;
  const provider = await factory.create({ type, name, ...section });
  federationProviders.set(name, provider);
}
```

## 関連

- [`@o3co/auth-provider-oauth`](../oauth/README.ja.md) — OAuth 2.0 トークン・認可ルート
- [`@o3co/auth-provider-did`](../did/README.ja.md) — DID 認証 grant
- [`@o3co/auth-provider-core`](../core/README.ja.md) — 共有型定義 (`Module`、`UserRepository`、`PathResolver`、`AppConfig`)
