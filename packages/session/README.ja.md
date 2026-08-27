# @o3co/auth-provider-session

[auth.provider](../../README.md) 向けセッション・フェデレーションルートモジュール。

ユーザー名/パスワードログイン、ログアウト、OAuth 2.0 フェデレーションを担当する。Google / GitHub などの具体プロバイダーは別パッケージに分離されており、各プロバイダーパッケージが per-federation な `defineModule(...)` で `FederationProvider` を contribute するモデルになっている（[`@o3co/auth-provider-federation-google`](../federation-google/README.md) / [`@o3co/auth-provider-federation-github`](../federation-github/README.md) を参照）。内部的には RFC 6749 認可コードフローを使用する。

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
import { sessionModule } from "@o3co/auth-provider-session";
// → sessionModule は const Module（manifest）であり、factory 関数ではない。
// createApp / createTestApp の modules リストに直接渡す。
```

const Module。`/session` 配下に 2 つの route bundle を contribute する:

| メソッド | パス | 説明 |
| --- | --- | --- |
| GET | /session/csrf | double-submit CSRF トークンの発行 |
| POST | /session/login | ユーザー名 / パスワードログイン |
| POST | /session/logout | セッションログアウト |
| GET | /session/oauth/federation/:name | OAuth フェデレーションフロー開始 |
| GET | /session/oauth/federation/:name/callback | フェデレーションコールバック |

`:name` パスパラメーターは `config.federations` のキー（例: `google`、`github`、`google-work`）に対応する。未知の名前は `404` を返す。

#### 状態変更ルートの CSRF 対策（#272）

`POST /session/login` と `POST /session/logout` は、**same-origin（もしくは明示的に信頼した）`Origin` / `Referer`**、**または** 有効な double-submit CSRF トークンのいずれかを伴うリクエストを受理する。どちらも無いリクエストは `403 access_denied` で拒否する。以前は `Origin` ヘッダーが無いとチェック自体がスキップされていた。

- **ブラウザ** 側の変更は不要。same-origin の `fetch` / form post ではブラウザが `Origin` を付けるため、それだけで通る。
- **ヘッダーを持たないクライアント**（curl、サーバーサイドのエージェント、テストハーネス）は `GET /session/csrf` を呼ぶ。JS から読める `<session.name>.csrf` cookie がセットされ、同じ値が `csrf_token` として返る。cookie と、`x-csrf-token` ヘッダーまたは `csrf_token` フォームフィールドの両方を送り返す。
- **foreign な `Origin`** はトークンがあっても拒否する。クロスサイトリクエストであることの積極的な証拠だから。
- ログイン成功時には **新しい** CSRF cookie を返すため、後続の logout に追加のラウンドトリップは要らない。

トークンは乱数 nonce と有効期限に対する署名付きの HMAC（ステートレス）で、鍵は `session.secret` の HKDF 展開。親ドメインの cookie を書けるサブドメインでも偽造はできない。クロスオリジンのログイン UI は `session.csrf.trustedOrigins` に自身の origin を列挙する。`cors.allowedOrigins` は CSRF 信頼を与えなくなった。

`checkRequestOrigin`、`createCsrfProtection`、`createCsrfProtectionFromConfig`、`createCsrfGuard`、`createCsrfIssueHandler` を export しているので、独自のログインページや独自ルートを持つ composition でも同じ仕組みを使える。

`requires`: `userRepository`、`userSessionStore`、`federationTokenStore`、`sessionFederationIndex`（兄弟ストア）、加えて per-federation modules が contribute する内容を boot planner が集約する synthetic key `federationProviders` と `federationRedirectPolicyResolver`。フェデレーションモジュールの実装例は [`@o3co/auth-provider-federation-google`](../federation-google/README.md) を参照。

---

### `extractFederationSection`

```typescript
function extractFederationSection(
  federations: Record<string, unknown>,
  name: string,
): { type: string; [key: string]: unknown } | undefined;
```

純粋関数のユーティリティ。フェデレーション設定スライスを fla 形（`{ enabled, clientId, callbackURL }`）／nested 形（`{ enabled, type, [type]: {...} }`）／shorthand（key を type として扱う）の各形状から、フラットな credential オブジェクトに正規化する。mixed 形（top-level credential と nested sub-section の両方が存在）はエラー。エントリーが無い場合や `enabled !== true` の場合は `undefined` を返す。per-federation module が自分の config スライスを読むときに使う。

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
}
```

カスタムの OAuth 2.0 / OIDC フェデレーションプロバイダーを追加する場合はこのインターフェースを実装する。`SupportsLogout` / `SupportsClaimMapping` / `SupportsRefresh` を必要に応じて mix-in できる。

- `name` — プロバイダーの一意な識別子。`federationProviders` の Map キーとルートの `:name` パラメーターに対応する。
- `scope` — OAuth 2.0 スコープ。
- `buildAuthorizationUrl` — RFC 6749 §4.1 + RFC 7636 の認可 URL を構築する。`codeVerifier` はルート層が生成して渡す。`code_challenge` の計算には `codeChallenge(codeVerifier)` を使うこと。
- `exchangeCode` — 認可コードを `FederationProfile` に交換する。`issuer` と `sub` は必須。

> **Note (A5 split, v0.5.0):** リダイレクト URL のハンドリング（`validateRedirect` / `resolveCallbackRedirect`）は `FederationProvider` から外され、専用の `FederationRedirectPolicy` capability に分離された。per-federation module は `federationRedirectPolicies.<name>` で policy を contribute する。built-in は `createFederationRedirectPolicy(...)` を使う。カスタム provider は `FederationProvider` 上にこれらのメソッドを実装しない。

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
  const refreshed = await provider.refreshToken(storedRefreshToken);
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
import { createApp } from "@o3co/auth-provider-core";
import { sessionModule } from "@o3co/auth-provider-session";
import { googleFederationModule } from "@o3co/auth-provider-federation-google";

const handle = await createApp({
  modules: [
    sessionModule,                 // const — factory 呼び出しなし
    googleFederationModule,        // federations.google + federationRedirectPolicies.google を contribute する
    // ... composition root の userRepository や 4 ストア分割を供給するモジュール群
  ],
  bootstrapComponents: { config, pathResolver },
});
```

boot planner が per-federation modules の `federations.<name>` と `federationRedirectPolicies.<name>` の contribution を集約し、synthetic な `federationProviders` と `federationRedirectPolicyResolver` ComponentMap エントリーを構築する。`sessionModule` のフェデレーションルートはこれらを消費する。

planner が enforce する pairing 不変条件は **contribution kind 同士** に対するもの: contribute された `federations.<name>` には対になる `federationRedirectPolicies.<name>` が必須（逆も同様）であり、欠ける場合は `BootError({ reason: "federation-redirect-policy-unpaired" })` で boot 失敗する。

planner は `config.federations` と contribution の cross-check は行わない — config で有効化されている federation に対応する provider pair を contribute するモジュールが無い場合でも boot は成功し、`/session/oauth/federation/:name` がリクエスト時に `404` を返す。設定ミスを fail-fast にしたい composition root は、対応する per-federation module（あるいは federation slice が enabled だが provider package 未インストールの場合に throw する config-bootstrap module）を追加すること。なお `sessionModule` は config 由来の不変条件を boot 時に 1 つだけ enforce する: `config.federations` で enabled になっている federation はすべて `callbackURL` を宣言する必要があり、欠ける場合は boot 失敗する（v0.4.x が `init()` で enforce していた fail-fast 不変条件と同じ）。

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

カスタムフェデレーションは per-federation な `defineModule(...)` を書いて、`federations.<name>`（`FederationProvider`）と `federationRedirectPolicies.<name>`（redirect policy）の両方を contribute する。型付き ComponentMap config slot を伴う const-Module パターンが推奨形 — 実装例として [`@o3co/auth-provider-federation-google` の `google.mts`](../federation-google/src/google.mts) を参照。最小スケッチ:

```typescript
import { defineModule } from "@o3co/auth-provider-core";
import {
  codeChallenge,
  createFederationRedirectPolicy,
  type FederationProvider,
} from "@o3co/auth-provider-session";

declare module "@o3co/auth-provider-core" {
  interface ComponentMap {
    readonly microsoftFederationConfig?: { clientId: string; callbackURL: string };
  }
}

export const microsoftFederationModule = defineModule({
  name: "federation:microsoft",
  requires: ["microsoftFederationConfig"] as const,
  contributes: {
    federations: {
      microsoft: (deps) => buildMicrosoftProvider(deps.microsoftFederationConfig),
    },
    federationRedirectPolicies: {
      microsoft: (deps) => createFederationRedirectPolicy(deps.microsoftFederationConfig),
    },
  },
});
```

composition root は、`extractFederationSection(config.federations, "microsoft")` を実行して credentials を抽出し、`microsoftFederationConfig` 型 slot に流し込む小さな config-bootstrap module を用意する。`sessionModule` のフェデレーションルートは集約された `federationProviders` map を消費し、`:name` でルーティングする。

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
6. **`UserSessionStore` と `FederationTokenStore` が必須になった**（以前はオプショナルでレガシーフォールバックあり）。これらは `sessionModule.requires` に宣言され、該当 component を提供するモジュールが無い場合、boot planner が `BootError(reason: 'missing-required-component')` で拒否する。
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

`sessionModule` は `userRepository`（`/login` 用）が必要。`userSessionStore` + `federationTokenStore` は `sessionModule.requires` に含まれており、該当 component を提供するモジュールが無い場合、boot planner が `BootError` を投げる。

## 関連

- [`@o3co/auth-provider-oauth`](../oauth/README.ja.md) — OAuth 2.0 トークン・認可ルート
- [`@o3co/auth-provider-core`](../core/README.ja.md) — 共有型定義 (`Module`、`UserRepository`、`PathResolver`、`AppConfig`)
