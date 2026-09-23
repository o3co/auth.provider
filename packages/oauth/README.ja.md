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
  config: AppConfig;
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
    registry: Pick<GrantHandlerResolver, "get">;
    config: AppConfig;
    clientRepository: ClientRepository;
    codeRepository: CodeRepository;
    keyStore: KeyStore;
  }
): Promise<{ router: Router; registry: Pick<GrantHandlerResolver, "get"> }>;
```

低レベルのファクトリ関数。Express ルーターと設定済み grant レジストリを生成する。通常は `oauthModule` 内部で呼び出される。構築後のレジストリインスタンスに直接アクセスしたい場合に使用する。

`registry` が `Pick<GrantHandlerResolver, "get">` なのは、router が読むのが `get` だけだからである: `/oauth/token` は `grant_type` を引くだけで、`grant_types_supported` は `oauthModule` が boot planner の resolver から導出する (#626)。`GrantHandlerResolver` をそのまま渡せるし、`get` を持つ任意のオブジェクトでもよい。戻り値の `registry` も同じ型に絞られているので、`entries()` が必要な呼び出し元は planner の `grantHandlerResolver` slot を読むこと。`/oauth/introspect` のクライアント認証は `createClientAuthMiddleware(clientRepository)` が担う — Passport 依存なし。

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
- `post_logout_redirect_uri`（任意） — `client.postLogoutRedirectUris` のいずれかと**バイト単位で完全一致**する必要がある。カスタムスキームでも一致条件は緩和されない（#498）
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

- `postLogoutRedirectUris?: string[]` — `POST /oauth/logout` の `post_logout_redirect_uri` 許可リスト。#498 以降は `allowedRedirectUris` と**同じ文法**で検証される: `https:`、ループバックホストの `http:`、または RFC 8252 §7.1 の逆ドメイン形式カスタムスキーム（`com.example.app:/signout`）。フラグメント・userinfo・実行可能スキームは拒否される。カスタムスキームを登録できることが、ネイティブアプリをログアウト後にアプリ自身へ戻せる条件になる。
- `backchannelLogoutUri?: string` — `logout_token` の POST を受け取る URI。**`http`/`https` のみ** — このサーバー自身が POST するため、カスタムスキームには到達できない。
- `backchannelLogoutSessionRequired?: boolean` — デフォルト `true`。`false` にすると `logout_token` から `sid` を除外する
- `frontchannelLogoutUri?: string` — フロントチャネルの iframe src。**`http`/`https` のみ** — ブラウザーがドキュメントコンテキストで解決する値であり、カスタムスキームは無意味かつ危険
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
  "scope": "<コネクションが現在保持しているスコープ>"
}
```

`token_type` は常に `Bearer` で、渡すのは bearer トークンだけである。IANA の
Access Token Types レジストリにある他の名前は、sender-constrained（`PoP`
(RFC 9200)、`DPoP` (RFC 9449) — 提示には鍵の所有証明が要り、値渡しで受け取った
呼び出し元はその鍵を持たない）か、そもそも access token の型ではない（`N_A`,
RFC 8693 §2.2.1）かのどちらかである。このエンドポイントはそれを渡さず
`502 upstream_token_ineligible` を返す。offline delegation 側のルートで `core`
が同じ契約に対して下している判断と同じである (#645)。以前は upstream が何と
答えても `token_type: "Bearer"` を返しており、upstream が課した制約を落として
いた。

upstream 自身の綴りは保存レコードに残る — 監査イベントが報告するのもオペレーター
が読むのもそれ — が、ワイヤー上ではそのまま返さない。非 bearer を拒否した後に
残る値は一語の大文字小文字違いだけであり、RFC 6749 §5.1 が比較を大文字小文字
非依存と定めている（"Value is case insensitive"）以上、綴りは呼び出し元が行動
できる情報を運ばない。そのまま返せば、すべての `federation-oidc` コネクションが
デプロイ後の最初の refresh で `Bearer` から `bearer` に変わるだけである。
offline delegation 側のルートは意図してそのまま返している — そちらは決定時点で
クライアントが存在しなかった。

アダプターが型を**まったく**名乗らないコネクションには `Bearer` を返す: §5.1 は
`token_type` を REQUIRED としているため、フィールドの不在は「Bearer 以外」では
なく `FederationProfile` がこのフィールドを持つ前に書かれたアダプター — 同梱
アダプターでは `federation-oidc` 以外すべて — を意味する。したがって現状この
拒否が実際に効くのは `federation-oidc` のコネクションだけである。
`federation-google` / `-github` / `-apple` は型を転送せず、3 つとも bearer
トークンを発行する。

そう扱うのは「不在」だけである。保存値が bearer の綴りでなければ、それが
`"DPoP "` でも `""` でも `null` でも数値でも拒否する — store もこのルートが
所有していないものの一つであり、壊れたレコードを沈黙と読めばそれに `Bearer` を
返してしまうため。JSON を往復してもフィールドの不在は `null` にならず落ちる
だけなので、保存された `null` は store が意図して書いたものである（同梱の Redis
codec はそれを含むレコードを拒否する）。反対側では、アダプターが文字列でない
値を名乗った場合は落とさず `""` として記録する — 拒否する対象を残すため。

サードパーティの `FederationTokenStore` アダプターは、`FederationTokens` の全
フィールドを `attach`・`update`・`get` を通して保持しなければならない。全フィールドが
**必須キー**（記録するものがなければ値は `undefined`）なので、`FederationTokens` を
組み立てるコードがどれかを書き忘れるとコンパイルエラーになる — store の `get`、`attach`/`update` の呼び出し元（store に投入するアプリ
コードやテストの fixture を含む）すべて。`FederationTokens` を組み立てる側に
とっては破壊的な型変更で、記録するものがなくても全キーを `undefined` として書く
必要がある。

型はアダプター独自の保存形式までは届かない。レコードを独自の行やドキュメントに
変換するアダプターは、その形式にも同じ必須キーを宣言すること（同梱の Redis store
は envelope でそうしている）。そうしないと変換がフィールドを落としたまま
コンパイルが通る。素の JavaScript や、型チェックを迂回するコード（不完全な
リテラルへの `as FederationTokens`、`JSON.parse(raw) as FederationTokens`、
`Object.assign`）にも届かない。

store は未設定の値を `undefined` か不在で返さなければならず、`null` で返しては
ならない。このエンドポイントは `null` を拒否するので、`undefined` を `null` として
書くシリアライザ（`ignoreUndefined` を設定しない MongoDB ドライバーなど）では、
型を名乗らないアダプターのコネクションがすべて `502` になる。

どのフィールドも失えば何かが壊れるので、すべてを文書ではなく型で強制する。
`tokenType` を失うと**開いたまま**失敗する: レコードが沈黙して返り、沈黙は #645
以前のレコードと読まれ、sender-constrained なトークンが `Bearer` として渡される。
`refreshToken` を失うと refresh できなくなり（`410 refresh_token_absent`）、
`idToken` を失うとログアウトで上流に `id_token_hint` を渡せなくなり、
`grantedScope` を失うと現在の scope が refresh の上限になる（過小に報告する）。
同梱の 2 つの store はこの要件を満たし、テストで固定されている。

### エラーレスポンス

| ステータス | エラー | 意味 |
| --- | --- | --- |
| 401 | `invalid_token` | Bearer 未指定・形式不正・型が `at+jwt` でない・family が失効済み |
| 403 | `forbidden` | クライアントが `allowedAzpForFederationToken` で opt-in していない |
| 404 | `federation_not_linked` | 指定のフェデレーションがセッションに紐付いていない |
| 410 | `refresh_token_absent` | 保存済みトークンに refresh_token がない（ログイン時に upstream が返さなかった） |
| 410 | `re_authentication_required` | IdP が `invalid_grant` を返した — セッションのフェデレーションはクリアされる。ユーザーは IdP で再認証が必要 |
| 500 | `refresh_failed` | IdP リフレッシュの汎用エラー、またはこのルートが読めない応答。SIEM は監査の `details.reason` でグルーピングすること |
| 502 | `upstream_token_ineligible` | upstream のトークンがこのプロバイダーの渡せる型ではない。理由は `error_description` が名乗る（現状は `token_type_unsupported` のみ、#645）。`Retry-After: 300` を付ける |
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
- `federation.token.refresh_failed` — 500 `refresh_failed` のとき。ケースは 2 つ: `provider.refreshToken` が SF-13 (v0.5.1) の分類器で分類できないエラーを throw した場合（`details.reason` は `"unknown"`）、または応答は返ったがこのルートが使えない場合（`"no_access_token"`・`"invalid_expiry"`・`"invalid_token_type"`）。このイベントが持つ値はこの 4 つだけで、SIEM ルールはこれでグルーピングすること。分類器の残りの結果はこのイベントに**ならない**: `invalid_grant` は `federation.token.reauthentication_required`（410）、`rate_limited`（429）と `network`（503）は監査イベントを出さない。v0.5.1 以前は `details.error: <raw message>` だった — ダッシュボードを移行すること
- `federation.token.reauthentication_required` — IdP から `invalid_grant` を受け取ったとき
- `federation.token.upstream_ineligible` — 502 発生時。`details.reason` は `"token_type_unsupported"`、`details.tokenType` はレコードが保持していた値を読んだまま（token 型として不正な値もそのまま — それこそ見る価値がある。文字列ですらない場合は `null`）。どの upstream が別の型を返し始めたかをオペレーターが追える。レスポンスには `Retry-After: 300` を付ける — `federationGrants.ineligibleRetryAfter` の既定値と同じで、この状態はオペレーターが upstream の登録を戻すまで終わらないため。呼び出し元には型を伝えない — 再試行以外にできることがないため

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
