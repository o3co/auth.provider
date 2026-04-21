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
  federationProviders: ReadonlyMap<string, FederationProviderBase>;
  pathResolver: PathResolver;  // 必須; passport/passport-local の dynamic import に使用され、FederationProviderBase.setupPassportStrategy にも転送される
}): Promise<PassportStatic>;
```

Passport インスタンスを生成・設定する。

- **LocalStrategy** — `username` と `password` フィールドで認証する。
- **フェデレーションストラテジー** — `federationProviders` の各プロバイダーに対して `provider.setupPassportStrategy(passport, { verifyUser, pathResolver })` を呼び出して登録する。

---

### `createFederationProviderFactory`

```typescript
function createFederationProviderFactory(): FederationProviderFactory;
```

組み込みタイプが未登録の空の `FederationProviderFactory`（`AdapterFactory<FederationProviderBase>`）を返す。`registerBuiltinFederations(factory)` を呼び出して組み込みの `"google"` と `"github"` を登録し、`factory.register(type, builder)` で独自タイプを追加できる。

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
}): FederationProviderBase;
```

Google OAuth 2.0 用の `FederationProviderBase` を生成する。ストラテジーは `config.name` の名前で Passport に登録されるため、マルチテナント構成（例: `google` と `google-work` を別インスタンスとして共存）が可能。

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
}): FederationProviderBase;
```

GitHub OAuth 2.0 用の `FederationProviderBase` を生成する。`passport-github2`（オプションの peer dep）が必要なため、別途インストールすること。デフォルトのスコープは `["read:user", "user:email"]`。`externalId` のフォーマットは `${federationName}:${profile.id}`（`federationName` はプロバイダーに設定した `name`。例: デフォルトは `"github"`、カスタムテナントの場合は `"github-enterprise"` など）。

---

### `FederationProviderBase` (interface)

```typescript
interface FederationProviderBase {
  readonly name: string;
  readonly scope: readonly string[];
  validateRedirect(url: string): FederationResult<void>;
  resolveCallbackRedirect(session: { redirectTo?: string }): FederationResult<string>;
  setupPassportStrategy(passport: PassportStatic, ctx: SetupPassportContext): Promise<void>;
}

interface SetupPassportContext {
  verifyUser: (externalId: string) => Promise<User | null>;
  pathResolver?: (spec: string) => string;  // optional; Yarn PnP などの非標準モジュールレイアウト向け
}
```

カスタムの OAuth 2.0 / OIDC フェデレーションプロバイダーを追加する場合はこのインターフェースを実装する。IdP が end-session endpoint を公開している場合は `SupportsLogout` を mix-in できる。

- `name` — Passport ストラテジーの一意な識別子。`federationProviders` の Map キーと `passport.use()` に渡すストラテジー名の両方に使用される。
- `scope` — OAuth 2.0 スコープ。
- `validateRedirect` — フェデレーションフロー開始前にリダイレクト URL を検証する。
- `resolveCallbackRedirect` — コールバック後のリダイレクト先をセッションから解決する。
- `setupPassportStrategy` — Passport ストラテジーを登録する。モジュール初期化時に一度呼ばれる。

---

### `SupportsLogout` (オプショナル capability)

IdP が OIDC RP-Initiated Logout (end-session) endpoint を公開している provider 向けのオプショナル capability。

```ts
interface EndSessionRequest {
  idTokenHint?: string;
  postLogoutRedirectUri?: string;
  state?: string;
}

interface EndSessionResult {
  url: URL;
  method: "GET";
}

interface SupportsLogout {
  endSession(req: EndSessionRequest): Promise<EndSessionResult>;
}

function supportsLogout(
  provider: FederationProviderBase | undefined | null,
): provider is FederationProviderBase & SupportsLogout;
```

組み込みの `"google"` / `"github"` は `SupportsLogout` を **実装しない**。Google は OIDC end-session endpoint を公開しておらず、GitHub は OAuth2 only のため、それぞれ end_session endpoint を持たない。Microsoft Entra ID / Auth0 / Okta 等の integration ではカスタム provider 側で capability を足すことで対応する。

カスタム provider の最小実装例:

```ts
import type {
  FederationProviderBase,
  SupportsLogout,
  EndSessionRequest,
  EndSessionResult,
} from "@o3co/auth-provider-session";

function createMyIdPProvider(): FederationProviderBase & SupportsLogout {
  return {
    name: "myidp",
    scope: ["openid"],
    validateRedirect(url) { /* ... */ },
    resolveCallbackRedirect(session) { /* ... */ },
    async setupPassportStrategy(passport, ctx) { /* ... */ },
    async endSession(req: EndSessionRequest): Promise<EndSessionResult> {
      const url = new URL("https://myidp.example/oidc/logout");
      if (req.idTokenHint) url.searchParams.set("id_token_hint", req.idTokenHint);
      if (req.postLogoutRedirectUri) url.searchParams.set("post_logout_redirect_uri", req.postLogoutRedirectUri);
      if (req.state) url.searchParams.set("state", req.state);
      return { url, method: "GET" };
    },
  };
}
```

Consumer 側は capability の有無を call site で判定する:

```ts
import { supportsLogout } from "@o3co/auth-provider-session";

if (supportsLogout(provider)) {
  const { url } = await provider.endSession({ idTokenHint, postLogoutRedirectUri, state });
  res.redirect(url.toString());
} else {
  // local session destroy のみにフォールバック
}
```

---

### `SupportsClaimMapping` (オプショナル capability)

OAuth プロファイルから正規化されたクレームセットを生成できる provider 向けのオプショナル capability。

```ts
interface MappedClaims {
  readonly email?: string;
  readonly emailVerified?: boolean;
  readonly name?: string;
  readonly picture?: string;
  readonly groups?: ReadonlyArray<string>;
  readonly [key: string]: unknown;   // 非標準 IdP クレーム（例: Google の "hd"）
}

interface FederationProfile {
  readonly id: string;                 // プロバイダー内部ユーザー ID
  readonly raw: Readonly<Record<string, unknown>>;  // 生の passport プロファイルオブジェクト
  readonly accessToken?: string;
  readonly refreshToken?: string;
  readonly idToken?: string;
  readonly expiresIn?: number;
}

interface SupportsClaimMapping {
  mapClaims(profile: FederationProfile): MappedClaims;
}

function supportsClaimMapping(
  provider: FederationProviderBase | undefined | null,
): provider is FederationProviderBase & SupportsClaimMapping;
```

`SupportsClaimMapping` を実装した provider は、生の passport プロファイルデータを OIDC 標準のクレーム名に変換する。組み込みの `"google"` / `"github"` はこの capability を実装している。カスタム provider は `mapClaims` メソッドを追加することで対応できる:

```ts
import { supportsClaimMapping } from "@o3co/auth-provider-session";

if (supportsClaimMapping(provider)) {
  const claims = provider.mapClaims(profile);
  // claims.email, claims.name, claims.picture …
}
```

---

### `SupportsRefresh` (オプショナル capability)

リフレッシュトークンを使って新しいアクセストークンを取得できる provider 向けのオプショナル capability。

```ts
interface RefreshedTokens {
  readonly accessToken: string;
  readonly refreshToken?: string;
  readonly idToken?: string;
  readonly expiresAt: Date;
}

interface SupportsRefresh {
  refreshFederationToken(refreshToken: string): Promise<RefreshedTokens>;
}

function supportsRefresh(
  provider: FederationProviderBase | undefined | null,
): provider is FederationProviderBase & SupportsRefresh;
```

`SupportsRefresh` を実装した provider は、ユーザー操作なしにフェデレーショントークンを維持できる。`FederationTokenStore`（`AppOptions` で設定）が初回トークンを保存し、リフレッシュフローが自動的に取得・更新する。

```ts
import { supportsRefresh } from "@o3co/auth-provider-session";

if (supportsRefresh(provider)) {
  const refreshed = await provider.refreshFederationToken(storedRefreshToken);
  // refreshed.accessToken, refreshed.expiresAt …
}
```

---

### `onFederationCallback` フック

`SetupPassportContext` にはオプショナルな `onFederationCallback` フックがある:

```ts
readonly onFederationCallback?: (params: {
  readonly federationName: string;
  readonly profile: FederationProfile;
  readonly req: import("express").Request;
  readonly done: (err: Error | null, user: User | false) => void;
}) => Promise<void>;
```

**組み込みの動作:** `sessionModule` が passport コンテキストをセットアップする際、`AppOptions` に `UserSessionStore` と `FederationTokenStore` の**両方**が設定されている場合にのみ、組み込みの `onFederationCallback` が自動的に注入される。組み込みフックの動作:

1. `UserRepository.authenticateByToken(`${federationName}:${profile.id}`)` を使って `User` を検索する。フェデレーション初回ログイン時にユーザーを自動プロビジョニングするデプロイでは、`authenticateByToken` の実装内でその処理を行うこと。
2. IdP トークンを `FederationTokenStore` に保存する。
3. 成功時に `done(null, user)` を呼び出す。

いずれかのストアが未設定の場合、モジュールはレガシーの `verifyUser(externalId)` パスにフォールバックする。これはトークン永続化が不要なデプロイには十分。

カスタム provider はこのフックを実装する必要はない。`SetupPassportContext.onFederationCallback` 経由で受け取り、`setupPassportStrategy` 内から呼び出す。このフック抽象化により、provider コードはストア依存から解放される。

---

### 組み込みプロバイダーのメモ

**Google プロバイダー（`createGoogleProvider`）**

- デフォルトで `openid profile email` スコープをリクエストする（`openid` スコープを追加することで、Google がアクセストークンと共に ID トークンを返すようになった）。
- `passReqToCallback: true` を使用し、`onFederationCallback` フックがセッションデータを含む Express リクエストオブジェクトにアクセスできるようにする。

**GitHub プロバイダー（`createGithubProvider`）**

- デフォルトスコープは `["read:user", "user:email"]`。
- プロファイルオブジェクトに `email` フィールドが含まれない場合、GitHub `/user/emails` API を呼び出してプライマリの確認済みメールアドレスを取得することでプロファイルを補完する。
- `externalId` フォーマット: `${federationName}:${profile.id}`（`federationName` は設定した `name`。例: デフォルトは `"github"`、カスタムテナントの場合は `"github-enterprise"`）。

---

### `FederationProviderFactory` (type)

```typescript
type FederationProviderFactory = AdapterFactory<FederationProviderBase>;
```

`AdapterFactory<FederationProviderBase>` の型エイリアス。`factory.register(type, builder)` でカスタムプロバイダータイプを登録できる。

---

### `FederationResult<T>` (type)

```typescript
type FederationResult<T> =
  | { ok: true; value: T }
  | { ok: false; status: number; error: string; errorDescription: string };
```

`FederationProviderBase` のメソッドが返す判別共用体。`value` にアクセスする前に `ok` を確認すること。

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
  type FederationProviderBase,
  type FederationProviderFactory,
} from "@o3co/auth-provider-session";

// ファクトリーを生成して組み込みを登録
const factory = createFederationProviderFactory();
registerBuiltinFederations(factory);

// カスタムプロバイダータイプを登録
factory.register("microsoft", async (config) => {
  // FederationProviderBase を構築して返す
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

// config からプロバイダー Map を構築 — module.mts の正規化ロジックを反映
const federationProviders = new Map<string, FederationProviderBase>();
for (const [name, section] of Object.entries(config.federations)) {
  if (!section.enabled) continue;

  const type = (typeof section.type === "string" ? section.type : undefined) ?? name;
  const subSection = (section as Record<string, unknown>)[type];
  const isNested =
    typeof subSection === "object" && subSection !== null && !Array.isArray(subSection);

  const rawBuilderConfig = isNested
    ? (() => {
        const { enabled: _e, type: _t, [type]: _sub, ...topLevel } = section as Record<string, unknown>;
        return { type, ...topLevel, ...(subSection as Record<string, unknown>) };
      })()
    : { type, ...(section as Record<string, unknown>) };

  const { enabled: _e2, type: _t2, ...flatConfig } = rawBuilderConfig as Record<string, unknown>;
  const provider = await factory.create({ type, name, ...flatConfig });
  federationProviders.set(name, provider);
}
```

## 関連

- [`@o3co/auth-provider-oauth`](../oauth/README.ja.md) — OAuth 2.0 トークン・認可ルート
- [`@o3co/auth-provider-did`](../did/README.ja.md) — DID 認証 grant
- [`@o3co/auth-provider-core`](../core/README.ja.md) — 共有型定義 (`Module`、`UserRepository`、`PathResolver`、`AppConfig`)
