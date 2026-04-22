# @o3co/auth-provider-oauth

[auth.provider](../../README.md) 向け OAuth 2.0 ルートモジュール。

`POST /oauth/token`、`POST /oauth/introspect`、`GET /oauth/authorize` を Express アプリにマウントする。grant type の追加はレジストリ経由で行えるため、このパッケージを変更せずに拡張できる。

## インストール

このパッケージは **private** です。npm には公開されておらず、`auth.provider` モノリポ内でのみ利用できます。

```jsonc
// packages/*/package.json
{
  "dependencies": {
    "@o3co/auth-provider-oauth": "workspace:*"
  }
}
```

peer dependencies（ワークスペースルートに別途インストール）:

```
express@^5.0.0
passport@^0.7.0                        (optional)
passport-oauth2-client-password@^0.1.2  (optional)
```

## パブリック API

### `oauthModule`

```typescript
function oauthModule(params: {
  clientRepository: ClientRepository;
  codeRepository: CodeRepository;
  express?: ExpressLike;
}): Module;
```

トップレベルのモジュール。`oauthSessionModule` と `oauthAuthorizationModule` をサブモジュールとして登録し、OAuth ルーターを `/oauth` にマウントする。サブモジュールを個別にマウントする必要がない場合はこちらを使用すること。

マウントされるルート:

| メソッド | パス               | 説明                                        |
|---------|--------------------|--------------------------------------------|
| POST    | /oauth/token       | トークンエンドポイント — `grant_type` で振り分け |
| POST    | /oauth/introspect  | トークンイントロスペクション (RFC 7662)        |
| GET     | /oauth/authorize   | 認可エンドポイント — PKCE 認可コードフロー      |

---

### `oauthSessionModule`

```typescript
function oauthSessionModule(params: {
  clientRepository: ClientRepository;
}): Module;
```

grant レジストリに `"session"` grant type を登録する。有効化は `config.oauth.grants.session.enabled` で制御される。grant レジストリを手動で構成する場合に単体で使用する。

---

### `oauthAuthorizationModule`

```typescript
function oauthAuthorizationModule(params: {
  codeRepository: CodeRepository;
}): Module;
```

grant レジストリに `"authorization_code"` および `"refresh_token"` grant type を登録する。grant レジストリを手動で構成する場合に単体で使用する。

---

### `createOAuthRouter`

```typescript
function createOAuthRouter(
  express: ExpressLike,
  options: {
    passport: PassportStatic;
    registry: GrantRegistry;
    config: AppConfig;
    clientRepository: ClientRepository;
    codeRepository: CodeRepository;
    keyStore: KeyStore;
  }
): Promise<{ router: Router; registry: GrantRegistry }>;
```

低レベルのファクトリ関数。Express ルーターと設定済み grant レジストリを生成する。通常は `oauthModule` 内部で呼び出される。構築後のレジストリインスタンスに直接アクセスしたい場合に使用する。

## 使い方

```typescript
import express from "express";
import { createApp } from "@o3co/auth-provider-core";
import { oauthModule } from "@o3co/auth-provider-oauth";

const app = createApp(express, {
  config,
  keyStore,
  modules: [
    oauthModule({
      clientRepository,
      codeRepository,
    }),
  ],
});
await app.init();
```

## TODO-F-4 の変更点

### `authorization_code` グラント — id_token 発行

付与スコープに `openid` が含まれており、かつ `UserSessionStore` が設定されている場合、`authorization_code` グラントはアクセストークン・リフレッシュトークンと合わせて `id_token` を発行する。`id_token` は `@o3co/auth-provider-core` の `generateIdToken` が生成する署名済み JWT で、トークンレスポンスの `id_token` フィールドとして付与される。

id_token が発行される条件:

- 付与スコープに `openid` が含まれること（`/oauth/authorize` 時に `GrantPolicyHook` が設定）
- `AppOptions.userSessionStore` が設定されていること（ユーザークレームのソースとして使用）
- コードレコードに `sid` が含まれること（authorize 時にログイン/federation wiring が書き込む）
- `AppOptions.config.oauth.jwt.issuer` が設定されていること（`iss: ""` の非準拠 JWT を防ぐ）

いずれかの条件が満たされない場合、`id_token` はレスポンスから省略される。その場合も `access_token` と `refresh_token` は通常どおり返される。

発行される `id_token` のクレーム構成:

- `iss`、`sub`、`aud`、`exp`、`iat`、`jti`、`auth_time`、`sid`、`azp` — OIDC Core §2 標準クレーム
- `nonce` — コードレコードに含まれる場合、そのまま反映（OIDC Core §3.1.3.7）
- スコープフィルター済みユーザークレーム（下表参照）

### `/oauth/userinfo` — OIDC Core §5.3

```http
GET /oauth/userinfo
Authorization: Bearer <access_token>
```

永続化された `UserSession` を元に、スコープフィルター済みクレームを返す。`oauthModule` が `/oauth/token`・`/oauth/introspect`・`/oauth/authorize` と同じルーターにマウントする。

| 条件 | レスポンス |
| --- | --- |
| Bearer トークン未指定または形式不正 | `401`（`WWW-Authenticate: Bearer realm="userinfo"` 付き） |
| JWT 署名検証失敗 | `401 invalid_token` |
| `family_id` クレームが失効済み（F-3 cascade） | `401 invalid_token` |
| セッション未発見またはストアエラー | `401 invalid_token`（フェイルクローズ） |
| `userSessionStore` 未設定、または `sid` クレームなし | `200 { sub }`（sub のみ、永続クレームなし） |
| セッションがアクティブ | `200 { sub, ...スコープフィルター済みクレーム }` |

すべてのレスポンスに `Cache-Control: no-store` と `Pragma: no-cache` を付与する（RFC 6750 §5.3）。

スコープ→クレームマッピング（OIDC Core §5.4 標準スコープ）:

| スコープ | 出力されるクレーム |
| --- | --- |
| `openid` | *(id_token 発行の可否を制御; `sub` は常に userinfo レスポンスに含まれる)* |
| `profile` | `name`、`picture` |
| `email` | `email`、`email_verified` |
| `groups` | `groups` |

## TODO-F-3 の変更点

- **`/oauth/introspect` によるカスケード失効。** アクセストークンに `family_id` クレームが含まれ、`AppOptions.refreshTokenStore` が設定されている場合、イントロスペクトエンドポイントはアクティブレスポンスを返す前に `RefreshTokenStore.isFamilyRevoked(familyId)` を呼び出す。ファミリーが失効済み、またはストアに到達できない場合は `{ active: false }` を返す（フェイルクローズ、RFC 7009 §2.1 SHOULD 準拠）。`family_id` クレームを持たない F-3 以前発行のトークンはこのチェックをスキップし、署名のみで検証される。
- **`family_id` + `sid` データクレーム。** `authorization_code` および `refresh_token` グラントで発行される `access_token` と `refresh_token` の両方に、`family_id`（カスケード失効用トークンファミリー）と `sid`（セッション ID、コードレコードに含まれる場合）が JWT クレームとして付与される。
- **`authorization_code` グラント — `sid` の必要条件。** グラントは `CodeData` レコードから `sid` を読み取る。発行トークンに `sid` クレームを含めるには、F-2/F-3 のログインワイアリング（ローカルログインまたはフェデレーションコールバックがコードに `sid` を書き込む処理）が必要。
- **`refresh_token` グラント — セッション検証。** `AppOptions.userSessionStore` が設定されており、かつリフレッシュトークンに `sid` クレームが含まれる場合、グラントは `userSessionStore.get(sid)` を呼び出してセッションがまだアクティブかを検証する。セッションが存在しない場合は `400 invalid_grant`、ストアエラーの場合は `503 temporarily_unavailable` を返す。

## TODO-F-5 の変更点 — ログアウトエンドポイント

OAuth モジュールは `userSessionStore`、`federationTokenStore`、`refreshTokenStore`、`oauth.jwt.issuer` が設定されている場合に 2 つのログアウトルートを公開する。

### POST /oauth/logout

OIDC RP-Initiated Logout 1.0 の `end_session_endpoint`。`application/x-www-form-urlencoded` を受け付ける:

- `id_token_hint`（必須） — このプロバイダーが発行した署名済み id_token。`sid` クレームでセッションを特定する
- `post_logout_redirect_uri`（任意） — `client.postLogoutRedirectUris` のいずれかと完全一致する必要がある
- `state`（任意） — `post_logout_redirect_uri` へのリダイレクト時にそのまま返す

フロー: `id_token_hint` を検証 → セッションを取得 → `backchannelLogoutUri` を持つすべての RP に OIDC Back-Channel Logout 1.0 の `logout_token` を POST → ストアカスケード（リフレッシュファミリー失効・フェデレーショントークン削除・セッション削除）を実行 → 以下のいずれかで応答:

- `frontchannelLogoutUri` を持つ RP ごとに `<iframe>` を含む `text/html` ページ（q 値付きネゴシエーションで `Accept: text/html` が優先された場合）
- 最初のフェデレーションの IdP end-session URL への `303` リダイレクト（そのフェデレーションプロバイダーが `SupportsLogout` を実装している場合）
- `post_logout_redirect_uri` への `303` リダイレクト（クライアントのアローリストに一致する場合）
- `200 {"logged_out": true}`（フォールバック）

カスケード失敗時は `503 {"error": "temporarily_unavailable"}` を返す。カスケードの実行順序は仕様により固定されており、ステップ 1（リフレッシュファミリー失効）とステップ 3（セッション削除）は失敗時にそのまま終了し、ステップ 2（フェデレーショントークン削除）はベストエフォートで失敗してもカスケードを継続する。

### POST /oauth/federation/:name/logout

プロバイダー単位のフェデレーション切断。Authorization ヘッダーに `Bearer <access_token>`（`typ: at+jwt`）を指定する。ボディ（任意）: `post_logout_redirect_uri`、`state`。

フロー: access_token を検証 → ファミリーが失効していないか確認 → セッションを取得 → 該当フェデレーションがセッションに紐付いていることを確認 → フェデレーショントークンを削除 → セッションからフェデレーションを削除 → プロバイダーが `SupportsLogout` を実装している場合は IdP end-session URL にリダイレクト。それ以外は `200 {"disconnected": true}` を返す。

IdP end-session 呼び出しが失敗した場合、ローカル状態はすでにクリア済みのため `200 {"disconnected": true}` を返し、オペレーター向けに `federation.logout.idp_unreachable` 監査イベントを出力する。

セッションに指定フェデレーションが存在しない場合は `404 {"error": "federation_not_linked"}` を返す。

### ディスカバリーメタデータ

`GET /.well-known/openid-configuration` に以下が追加された:

- `end_session_endpoint`
- `backchannel_logout_supported: true`
- `backchannel_logout_session_supported: true` — デフォルトで `logout_token` に `sid` を含む
- `frontchannel_logout_supported: true`
- `frontchannel_logout_session_supported: true` — デフォルトでフロントチャネルの iframe URL に `sid` を含む

`session_supported` のデフォルト `true` は OIDC Back-Channel Logout 1.0 §2.2 の仕様デフォルト（`false`）から意図的に逸脱している。仕様デフォルトの動作が必要なクライアントは、クライアントレコードで `backchannelLogoutSessionRequired: false` または `frontchannelLogoutSessionRequired: false` を設定すること。

### クライアントレコードのログアウトメタデータ

各 `Client` はログアウト動作を制御する 5 つのオプションフィールドをサポートする:

- `postLogoutRedirectUris?: string[]` — `POST /oauth/logout` の `post_logout_redirect_uri` 許可リスト
- `backchannelLogoutUri?: string` — `logout_token` の POST を受け取る URI
- `backchannelLogoutSessionRequired?: boolean` — デフォルト `true`。`false` にすると `logout_token` から `sid` を除外する
- `frontchannelLogoutUri?: string` — フロントチャネルの iframe src
- `frontchannelLogoutSessionRequired?: boolean` — デフォルト `true`。`false` にすると iframe URL から `sid` を除外する

## 関連

- [`@o3co/auth-provider-session`](../session/README.ja.md) — セッションログイン / フェデレーションルート
- [`@o3co/auth-provider-did`](../did/README.ja.md) — DID 認証 grant
- [`@o3co/auth-provider-core`](../core/README.ja.md) — 共有型定義 (`Module`、`GrantRegistry`、`ClientRepository`、`CodeRepository`、`KeyStore`)
