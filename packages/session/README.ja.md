# @o3co/auth-provider-session

[auth.provider](../../README.md) 向けセッション・フェデレーションルートモジュール。

ユーザー名/パスワードログイン、ログアウト、`FederationProviderFactory` に登録されたプロバイダー向けの OAuth 2.0 フェデレーションを担当する。内部的には RFC 6749 認可コードフローを使用する。Google / GitHub などの具体プロバイダーは別パッケージに分離されている。

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
```

## パブリック API

### `sessionModule`

```typescript
function sessionModule(params: {
  userRepository: UserRepository;
  express?: ExpressLike;
  federationProviderFactory?: FederationProviderFactory;
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

### `createFederationProviderFactory`

```typescript
function createFederationProviderFactory(): FederationProviderFactory;
```

プロバイダータイプが未登録の空の `FederationProviderFactory`（`AdapterFactory<FederationProvider>`）を返す。具体プロバイダーパッケージをインストールして composition root で登録し、その factory を `sessionModule` に渡す。

---

### `FederationProvider` (interface)

```typescript
interface FederationProvider {
  readonly name: string;
  readonly scope: readonly string[];

  buildAuthorizationUrl(params: {
    readonly redirectUri: string;
    readonly state: string;
    readonly codeVerifier: string;
  }): URL;

  exchangeCode(params: {
    readonly code: string;
    readonly codeVerifier: string;
    readonly redirectUri: string;
  }): Promise<FederationProfile>;

  validateRedirect(url: string): FederationResult<void>;
  resolveCallbackRedirect(session: { redirectTo?: string }): FederationResult<string>;
}
```

カスタムの OAuth 2.0 / OIDC フェデレーションプロバイダーを追加する場合はこのインターフェースを実装する。IdP が end-session endpoint を公開している場合は `SupportsLogout` を mix-in できる。

- `name` — プロバイダーの一意な識別子。`federationProviders` の Map キーとルートの `:name` パラメーターに対応する。
- `scope` — OAuth 2.0 スコープ。
- `buildAuthorizationUrl` — RFC 6749 §4.1 + RFC 7636 の認可 URL を構築する。`codeVerifier` はルート層が生成して渡す。`code_challenge` の計算には `codeChallenge(codeVerifier)` を使うこと。
- `exchangeCode` — 認可コードを `FederationProfile` に交換する。`issuer` と `sub` は必須。
- `validateRedirect` — フェデレーションフロー開始前にリダイレクト URL を検証する。
- `resolveCallbackRedirect` — コールバック後のリダイレクト先をセッションから解決する。

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
  provider: FederationProvider | undefined | null,
): provider is FederationProvider & SupportsLogout;
```

プロバイダーパッケージは、上流 IdP が end-session endpoint を提供する場合に `SupportsLogout` を実装できる。Microsoft Entra ID / Auth0 / Okta 等の integration ではカスタム provider 側で capability を足すことで対応する。

カスタム provider の最小実装例:

```ts
import type {
  FederationProvider,
  SupportsLogout,
  EndSessionRequest,
  EndSessionResult,
} from "@o3co/auth-provider-session";

function createMyIdPProvider(): FederationProvider & SupportsLogout {
  return {
    name: "myidp",
    scope: ["openid"],
    buildAuthorizationUrl({ redirectUri, state, codeVerifier }) { /* ... */ },
    async exchangeCode({ code, codeVerifier, redirectUri }) { /* ... */ },
    validateRedirect(url) { /* ... */ },
    resolveCallbackRedirect(session) { /* ... */ },
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
  readonly issuer: string;
  readonly sub: string;             // OIDC sub — この IdP での安定した識別子
  readonly email?: string;
  readonly emailVerified?: boolean;
  readonly name?: string;
  readonly picture?: string;
  readonly accessToken?: string;
  readonly refreshToken?: string;
  readonly idToken?: string;
  // accessToken の絶対有効期限。プロバイダーが有限の expires_in を返さない場合（例: GitHub OAuth Apps の classic token）は null。
  // 必須フィールド。consumer は null を「refresh せず reuse」として扱わなければならない。
  readonly expiresAt: Date | null;
  readonly [key: string]: unknown;  // プロバイダー固有の拡張クレーム
}

interface SupportsClaimMapping {
  mapClaims(profile: FederationProfile): MappedClaims;
}

function supportsClaimMapping(
  provider: FederationProvider | undefined | null,
): provider is FederationProvider & SupportsClaimMapping;
```

`SupportsClaimMapping` を実装した provider は、`FederationProfile` を OIDC 標準のクレーム名に変換する。カスタム provider は `mapClaims` メソッドを追加することで対応できる:

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
type RefreshedTokens = Omit<FederationProfile, "issuer" | "sub"> & {
  readonly issuer?: string;
  readonly sub?: string;
};

interface SupportsRefresh {
  refreshToken(refreshToken: string): Promise<RefreshedTokens>;
}

function supportsRefresh(
  provider: FederationProvider | undefined | null,
): provider is FederationProvider & SupportsRefresh;
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

### プロバイダーパッケージのメモ

**`@o3co/auth-provider-federation-google`**

- デフォルトで `openid profile email` スコープをリクエストする。
- 安定した Google OAuth/OIDC endpoint を使用する。
- `FederationProfile.sub` は Google のアカウント数値 ID。

**`@o3co/auth-provider-federation-github`**

- デフォルトスコープは `["read:user", "user:email"]`。
- プロファイルオブジェクトに `email` フィールドが含まれない場合、GitHub `/user/emails` API を呼び出してプライマリの確認済みメールアドレスを取得することでプロファイルを補完する。
- `FederationProfile.sub` は GitHub の数値ユーザー ID。
- フェデレーショントークンフォーマット: `${federationName}:${sub}`（`federationName` は設定した `name`）。

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
import {
  createFederationProviderFactory,
  sessionModule,
} from "@o3co/auth-provider-session";
import { registerGoogleFederation } from "@o3co/auth-provider-federation-google";

const federationProviderFactory = createFederationProviderFactory();
registerGoogleFederation(federationProviderFactory);

const app = createApp(express, {
  config,
  keyStore,
  modules: [
    sessionModule({
      userRepository,
      federationProviderFactory,
    }),
  ],
});
await app.init();
```

`sessionModule` は composition root から渡された factory を使って `config.federations` のプロバイダーを生成する。設定で有効なタイプが未登録の場合は起動時に fail-fast する。

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
  codeChallenge,
  createFederationProviderFactory,
  type FederationProvider,
  type FederationProviderFactory,
} from "@o3co/auth-provider-session";

const factory = createFederationProviderFactory();

// カスタムプロバイダータイプを登録
factory.register("microsoft", async (config) => {
  // FederationProvider を構築して返す
  return {
    name: config.name as string,
    scope: ["openid", "profile", "email"],
    buildAuthorizationUrl({ redirectUri, state, codeVerifier }) {
      const url = new URL("https://login.microsoftonline.com/common/oauth2/v2.0/authorize");
      url.searchParams.set("response_type", "code");
      url.searchParams.set("client_id", config.clientId as string);
      url.searchParams.set("redirect_uri", redirectUri);
      url.searchParams.set("state", state);
      url.searchParams.set("code_challenge", codeChallenge(codeVerifier));
      url.searchParams.set("code_challenge_method", "S256");
      url.searchParams.set("scope", "openid profile email");
      return url;
    },
    async exchangeCode({ code, codeVerifier, redirectUri }) {
      // トークンエンドポイントへ POST + 必要に応じて userinfo を取得し、FederationProfile に正規化する
      return { issuer: "https://login.microsoftonline.com/common/v2.0", sub: userId, email, accessToken, expiresAt };
    },
    validateRedirect: (url) => ({ ok: true, value: undefined }),
    resolveCallbackRedirect: (session) => ({ ok: true, value: session.redirectTo ?? "/" }),
  };
});

// config からプロバイダー Map を構築 — module.mts の正規化ロジックを反映
const federationProviders = new Map<string, FederationProvider>();
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

## TODO-F-3 の変更点

- **ローカルログインのセッショントラッキング。** `AppOptions.userSessionStore` が設定されている場合、`POST /session/login` は `userSessionStore.create()` で `UserSession` レコードを作成し、生成された `sid` を `req.session.sid` に書き込む。これは F-2 で確立したフェデレーションコールバックのセッション作成パスと対称であり、ローカルログイン後に発行されるトークンに有効な `sid` クレームが付与されることを保証する。

## v0.3.x → v0.4.0 マイグレーション

v0.4.0 ではこのパッケージから passport を直接依存として削除した。

### 破壊的変更

1. **`FederationProviderBase` → `FederationProvider` へリネーム。** カスタムプロバイダーを実装している場合は import のインターフェース名を変更すること。
2. **`setupPassportStrategy(passport, ctx)` を削除。** 代わりに `buildAuthorizationUrl({ redirectUri, state, codeVerifier }): URL` と `exchangeCode({ code, codeVerifier, redirectUri }): Promise<FederationProfile>` を実装する。新しいインターフェースはベンダー非依存であり、シグネチャに passport の型が漏出しない。
3. **`FederationProfile.raw` を削除。** OIDC 標準クレームがファーストクラスフィールドになった（`sub`、`email`、`emailVerified`、`name`、`picture`、`accessToken`、`refreshToken`、`idToken`、`expiresAt`）。プロバイダー固有クレーム（Google の `hd`、Microsoft の `tid` など）はインデックスシグネチャ `[key: string]: unknown` で伝達される。
4. **`FederationProfile.id` → `sub` へリネーム、`expiresIn: number` → `expiresAt: Date | null`（必須）に変更。** adapter は明示的に判断する必要がある — プロバイダーが有限の expiry を発行する場合は `Date`、発行しない場合（GitHub OAuth Apps の classic token 等）は `null` を返す。route 層は fallback expiry を勝手に発明しなくなった — `null` は「refresh せず、プロバイダーが invalidate するまで reuse」を意味する。`FederationTokenStore` 側の `FederationTokens.expiresAt` も同じ契約に従う。
5. **`createPassport()` と `SetupPassportContext` をパブリック API から削除。** 状態（CSRF）と PKCE はルート層が内部で管理する。プロバイダーは純粋関数になった。
6. **`UserSessionStore` と `FederationTokenStore` が必須になった**（以前はオプショナルでレガシーフォールバックあり）。いずれかが `ModuleContext` に存在しない場合、`sessionModule` は `init()` 時に例外をスローする。
7. **`/login` エラーレスポンス** は RFC 6749 §5.2 の形式 `{ error, error_description }` に変更。旧フォーマット `{ message: "..." }` をクライアントが解析している場合は更新が必要。
8. **`SupportsRefresh.refreshToken`** の戻り型が `RefreshedTokens`（新型）: `Omit<FederationProfile, "issuer"|"sub"> & { issuer?: string; sub?: string }` に変更。Google/GitHub のリフレッシュレスポンスは正当に `sub` を省略するため、ルート層が保存済み identity を維持する。

### カスタムプロバイダーのマイグレーション例

**変更前（v0.3.x、passport ベース）:**

```ts
class CustomProvider implements FederationProviderBase {
  name = "custom";
  scope = ["openid"];
  async setupPassportStrategy(passport, ctx) {
    passport.use(this.name, new CustomStrategy({...}, (accessToken, refreshToken, profile, done) => {
      done(null, { id: profile.id, raw: profile });
    }));
  }
  validateRedirect(url) { /* ... */ }
  resolveCallbackRedirect(session) { /* ... */ }
}
```

**変更後（v0.4.0、純粋関数インターフェース）:**

```ts
import { codeChallenge } from "@o3co/auth-provider-session";

class CustomProvider implements FederationProvider, SupportsClaimMapping {
  readonly name = "custom";
  readonly scope = ["openid"] as const;
  buildAuthorizationUrl({ redirectUri, state, codeVerifier }) {
    const url = new URL("https://idp.example.com/authorize");
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", this.clientId);
    url.searchParams.set("redirect_uri", redirectUri);
    url.searchParams.set("state", state);
    url.searchParams.set("code_challenge", codeChallenge(codeVerifier));
    url.searchParams.set("code_challenge_method", "S256");
    url.searchParams.set("scope", this.scope.join(" "));
    return url;
  }
  async exchangeCode({ code, codeVerifier, redirectUri }) {
    // トークンエンドポイントへ POST + 必要に応じて userinfo を取得し、FederationProfile に正規化する
    return {
      issuer: "https://idp.example.com",
      sub: userId,
      email,
      accessToken,
      refreshToken,
      expiresAt,
    };
  }
  mapClaims(profile) { return { email: profile.email }; }
  validateRedirect(url) { /* 変更なし */ }
  resolveCallbackRedirect(session) { /* 変更なし */ }
}
```

### モジュールの配線

`sessionModule` は `userRepository`（`/login` 用）が必要。`ModuleContext` の `userSessionStore` + `federationTokenStore` は**必須**になった。

## 関連

- [`@o3co/auth-provider-oauth`](../oauth/README.ja.md) — OAuth 2.0 トークン・認可ルート
- [`@o3co/auth-provider-core`](../core/README.ja.md) — 共有型定義 (`Module`、`UserRepository`、`PathResolver`、`AppConfig`)
