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
    registry: GrantHandlerResolver;
    config: AppConfig;
    clientRepository: ClientRepository;
    codeRepository: CodeRepository;
    keyStore: KeyStore;
  }
): Promise<{ router: Router; registry: GrantHandlerResolver }>;
```

低レベルのファクトリ関数。Express ルーターと設定済み grant レジストリを生成する。通常は `oauthModule` 内部で呼び出される。構築後のレジストリインスタンスに直接アクセスしたい場合に使用する。`/oauth/introspect` のクライアント認証は `createClientAuthMiddleware(clientRepository)` が担う — Passport 依存なし。

## 使い方

```typescript
import express from "express";
import { createApp } from "@o3co/auth-provider-core";
import { oauthModule } from "@o3co/auth-provider-oauth";

const handle = await createApp({
  modules: [
    // clientRepository、codeRepository、keyStore、grant handler を提供する
    // composition root 側のモジュールをここに追加する
    oauthModule({ config }),
  ],
  bootstrapComponents: { config, pathResolver: import.meta.resolve },
});

const server = express();
server.use(handle.router);
server.listen(config.http.port);

await handle.dispose();
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

## TODO-F-6 の変更点 — フェデレーショントークンエンドポイント

`POST /oauth/federation/:name/token` は、呼び出し元のセッションに紐付いた upstream IdP の access_token を返す。これにより、Google Calendar / GitHub API などに対してサーバーサイドの API 呼び出しをユーザーの代わりに行える。

### 認証

- この auth.provider インスタンスが発行した Bearer access_token（`typ: at+jwt`）を使用する。
- トークンの `azp` クレームでクライアントを特定する。クライアントレコードは `allowedAzpForFederationToken: true` で明示的に opt-in する必要がある（下記参照）。

### フロー

1. Bearer access_token を検証する。
2. `family_id` が失効済み、またはセッションが存在しない場合は拒否。
3. `client.allowedAzpForFederationToken === true` でない場合は拒否。
4. フェデレーションがセッションに紐付いていない場合は拒否。
5. キャッシュ済みの upstream access_token の有効期限が 30 秒以上残っている場合はそのまま返す。
6. それ以外はリフレッシュを行う:
   - 並行リフレッシュのファンアウトを防ぐために advisory lock を取得する（`FederationTokenStore` が `SupportsLock` を実装している場合）。
   - ロック取得後に再読み込みを行う — 待機中に別のウェイターがリフレッシュした可能性がある。
   - `provider.refreshToken(refreshToken)` を呼び出し、結果を永続化する。
   - ロックを解放する。

### レスポンス

```json
{
  "access_token": "<upstream-IdP-access-token>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "<if-available>"
}
```

### エラーレスポンス

| ステータス | エラー | 意味 |
| --- | --- | --- |
| 401 | `invalid_token` | Bearer 未指定・形式不正・型が `at+jwt` でない・family が失効済み |
| 403 | `forbidden` | クライアントが `allowedAzpForFederationToken` で opt-in していない |
| 404 | `federation_not_linked` | 指定のフェデレーションがセッションに紐付いていない |
| 410 | `refresh_token_absent` | 保存済みトークンに refresh_token がない（ログイン時に upstream が返さなかった） |
| 410 | `re_authentication_required` | IdP が `invalid_grant` を返した — セッションのフェデレーションはクリアされる。ユーザーは IdP で再認証が必要 |
| 500 | `refresh_failed` | IdP リフレッシュの汎用エラー |
| 503 | `refresh_not_supported` | プロバイダーが `SupportsRefresh` を実装していない |
| 503 | `lock_timeout` | 待機ウィンドウ内に advisory lock を取得できなかった |
| 503 | `temporarily_unavailable` | ストア障害、または IdP の 5xx / temporarily_unavailable |

すべてのエラーレスポンスには `Cache-Control: no-store` と `Pragma: no-cache` を付与する。401 レスポンスには RFC 6750 に従い `WWW-Authenticate: Bearer error="invalid_token"` を含める。

### Opt-in: `allowedAzpForFederationToken`

各 `Client` はオプションの `allowedAzpForFederationToken: boolean` フラグを持つ。デフォルトは `false` — クライアントは自動的にフェデレーショントークンアクセスを得ない。このエンドポイントを必要とするクライアントにはオペレーターが明示的に opt-in する:

```yaml
clients:
  - clientId: my-backend-api
    clientSecret: ...
    allowedRedirectUris: [...]
    allowedScopes: [openid, profile, email]
    allowedAzpForFederationToken: true  # explicit opt-in
```

設計の意図: フェデレーションの access_token はユーザーの外部リソース（Google Drive、GitHub API など）へのアクセスを許可する。deny-by-default により、認証のみを目的とする一般的な OAuth クライアント登録で誤って露出するリスクを防ぐ。

### 監査イベント

このエンドポイントでは以下の監査イベントが発火する:

- `federation.token.success` — トークン発行時（詳細に `refreshed: boolean` が含まれ、キャッシュヒットかリフレッシュパスかを区別できる）
- `federation.token.forbidden` — 403 発生時（クライアントが opt-in していない）
- `federation.token.family_revoked` — family 失効による 401 発生時
- `federation.token.refresh_failed` — `provider.refreshToken` が throw したとき（`invalid_grant` 以外）
- `federation.token.reauthentication_required` — IdP から `invalid_grant` を受け取ったとき

## v0.3.x → v0.4.0 マイグレーション

v0.4.0 ではこのパッケージから passport を削除した。`/oauth/introspect` エンドポイントは `createClientAuthMiddleware(clientRepository)` を使用するようになった。これは RFC 6749 §2.3.1 準拠の HTTP Basic + form-encoded クライアント認証ミドルウェアを自前実装したものである。

### 破壊的変更

1. **`createOAuthRouter` のシグネチャ変更**: `passport` オプションを削除。`clientRepository: ClientRepository` を直接渡す。`oauthModule({ config })` は composition root 側の provider から module `requires` 経由で repository を受け取る。
2. **`/introspect` エラーレスポンス**: RFC 6749 §5.2 の形式 `{ error, error_description }` に変更。
3. **`req.oauthClient`**（`PublicClient | undefined` 型）が `createClientAuthMiddleware` によって Express `Request` に付与される。このミドルウェアを独自ルートに組み込む場合は直接参照できる — 型はグローバルの Express 名前空間拡張で提供される。

### コンシューマー向け

`@o3co/auth-provider-oauth` のパブリック API（`oauthModule`、`createOAuthRouter`）経由で利用している場合、設定の更新以外にコード変更は不要 — モジュールが内部で新しいミドルウェアを配線する。

カスタムのクライアント認証スキーム向けにミドルウェアを拡張または置き換える場合は、`@o3co/auth-provider-oauth` から `createClientAuthMiddleware` を参照するか、`req.oauthClient` に互換性のある `PublicClient` を付与するドロップイン代替実装を作成すること。

## 関連

- [`@o3co/auth-provider-session`](../session/README.ja.md) — セッションログイン / フェデレーションルート
- [`@o3co/auth-provider-core`](../core/README.ja.md) — 共有型定義 (`Module`、`GrantHandlerResolver`、`ClientRepository`、`CodeRepository`、`KeyStore`)
