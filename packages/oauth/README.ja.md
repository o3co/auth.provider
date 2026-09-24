# @o3co/auth-provider-oauth

最終更新: 2026-09-24

[auth.provider](../../README.md) の OAuth 2.0 / OpenID Connect 認可サーバーのエンドポイント: `/oauth` 配下の HTTP 面、組み込みのグラントタイプ、クライアント認証、ログアウトカスケード。

## 責務と役割

**役割。** 認可サーバーの HTTP 側の顔。[`@o3co/auth-provider-core`](../core/README.ja.md) がポート・レコード・トークンの基本部品・boot planner を定義し、このパッケージがそれらをクライアントが話すエンドポイント — authorize、token、introspect、userinfo、revoke、consent、logout、federation token — に仕立て、ディスカバリードキュメントのうちこのサーバーの分を提供する。core の上で [`@o3co/auth-provider-session`](../session/README.ja.md)（ログインとブラウザーセッション）と並ぶ位置にあり、どちらも相手を import しない。

**所有するもの:**

- [エンドポイント](#エンドポイント)の表にあるルート — device グラントや federation grants など、他のパッケージも `/oauth` 配下にルートをマウントする — と、各ルートが走らせるチェックの順序、ワイヤー上の応答;
- クライアント認証が要るすべてのエンドポイントでのクライアント認証 — `client_secret_basic`、`client_secret_post`、`private_key_jwt`、ルートが許す場合の public クライアント — を 1 つのミドルウェア `createClientAuthMiddleware` として。[`@o3co/auth-provider-device-grant`](../device-grant/README.md) と [`@o3co/auth-provider-federation-grants`](../federation-grants/README.md) もこれを再利用する;
- 組み込みのグラント: `authorization_code`、`refresh_token`、`client_credentials`、`session`、RFC 7523 jwt-bearer;
- ログアウトカスケード（`cascadeLogout`）、OIDC のバックチャネル / フロントチャネルログアウト、そのカスケードの上に core の subject revocation service を配線するモジュール;
- Client ID Metadata Documents の解決: 取得、その SSRF ガード、キャッシュ;
- このサーバーのエンドポイントと機能が提供するディスカバリーの一部。

**所有しないもの:**

- ポートとレコード（`ClientRepository`、`CodeRepository`、`KeyStore`、`UserSessionStore`、`Client` レコード …）、トークンの発行と検証（`generateToken`、`verifyJwt`）、グラントの契約と `/oauth/token` が振り分けに使うレジストリ、ディスカバリードキュメント本体と `jwks_uri` — core;
- ログイン、ブラウザーセッション、フェデレーションのログインルート — `@o3co/auth-provider-session`（`POST /session/logout` もそちらにあり、このパッケージのカスケードは走らせない: [ログアウト](#ログアウト)を参照）;
- その他のグラントタイプ — token exchange、device code、WebAuthn — それぞれのパッケージが同じ `/oauth/token` に提供する;
- 上流トークンのオフライン委譲（`/oauth/federation-grants`） — `@o3co/auth-provider-federation-grants`;
- DPoP 鍵やクライアント証明書の証明 — `@o3co/auth-provider-dpop` / `@o3co/auth-provider-mtls`。このパッケージはそれらが確立したバインディングを読み、`cnf` として刻む;
- ストアアダプター（Redis など）とユーザーの Store。

**なぜ別パッケージか。** core はすべてのパッケージが共有する契約を持ち、アダプターやグラントのパッケージ — Redis、token exchange、WebAuthn — は core に依存し、このパッケージには依存しない。Express と express-session を peer とする HTTP 面をここに置くことで、それらのどれもそれを引き込まない。ログインとブラウザーセッションがさらに別パッケージなのは、API 専用のデプロイはそれ無しでトークンを発行するからで、このパッケージはトークンを発行するすべてのデプロイがインストールするものである。両者は core の上の兄弟でどちらも相手を import しない。`POST /session/logout` がこのパッケージのカスケードを走らせられないのはそのためである。

**なぜ 4 つのモジュールか。** このパッケージは 4 つの別々のモジュールとしてインストールされ、それぞれ自分のコードが読むものだけを要求する。必要になる構成が異なるからである:

| モジュール | 提供するもの | 分けている理由 |
|---|---|---|
| [`oauthModule`](./src/module.mts) | `/oauth` のルートとディスカバリーの一部。グラントは 1 つも登録しない: `/oauth/token` は core の `grantHandlerResolver` を引いて振り分け、それはインストールされた各モジュールの `grants` 提供で埋まる。 | トークンエンドポイントはどのグラントがインストールされていても同じで、セッションストアが 1 つも無くても動く。 |
| [`oauthAuthorizationModule`](./src/oauthAuthorization.mts) | `authorization_code`、`refresh_token`、`client_credentials`、jwt-bearer。それぞれ有効化されたときだけ。 | デプロイがグラントの組を選ぶ。これらのルート無しでグラントだけをインストールすることもでき、そのためこのモジュールは独自に `subjectRevocation` の absence policy を宣言する。 |
| [`oauthSessionModule`](./src/oauthSession.mts) | `session` グラント。有効化されたときだけ。 | 別の構成 — ブラウザーセッションから発行するファーストパーティ / BFF — のためのもので、コード系グラントとは独立に有効化され、宣言するのは `config` と `keyStore`（任意で `userSessionStore`）だけである。 |
| [`subjectRevocationServiceModule`](./src/logout/subjectRevocationService.mts) | `cascadeLogout` の上に組んだ core の `subjectRevocationService` コンポーネント。 | セッションカスケードの 6 ストアを要求するが、`oauthModule` のルートはそれを要求しない。`federationGrants.enabled = true` のときは `federationGrantStore` と、grants 境界を持つ `subjectRevocation` も要求し、無ければ boot を拒否する。core ではなくここにあるのは、core が `cascadeLogout` を import するとパッケージの依存方向が逆転するからである。 |

どれも明示的にインストールする: どのモジュールも他のモジュールを登録しない。

## インストール

```sh
pnpm add @o3co/auth-provider-oauth
```

peer dependencies: `express@^5.0.0` と `express-session@^1.17.0`。express-session が peer なのは、ルーターがブラウザーセッションを読み、その型を拡張するから（`/authorize`、`session` グラント、ログアウト）。ブラウザーのフローを扱う構成は、下の例のとおり `@o3co/auth-provider-session` の `sessionStoreModuleFor(config)` でそれをマウントする。このパッケージは `@o3co/auth-provider-core`、`accepts`、`jose`、`zod` に依存する。

## 組み込み方

```ts
import express from "express";
import { createApp, jwksModule } from "@o3co/auth-provider-core";
import {
  oauthAuthorizationModule,
  oauthModule,
  oauthSessionModule,
} from "@o3co/auth-provider-oauth";
import { sessionStoreModuleFor } from "@o3co/auth-provider-session";

const handle = await createApp({
  modules: [
    // express-session をマウントする。自前の順序指定を持たないので、
    // ブラウザーセッションを読むすべてのモジュールより前に並べること。
    sessionStoreModuleFor(config),
    oauthModule({ config }),
    oauthSessionModule({ config }),
    oauthAuthorizationModule({ config }),
    jwksModule, // core のもの: `jwks_uri` はこのパッケージの担当ではない
    // …clientRepository、codeRepository、keyStore と下記の任意スロットを提供する
    // モジュール。Store が `handle.components.subjectRevocationService` を呼ぶなら
    // subjectRevocationServiceModule も加える。
  ],
  bootstrapComponents: { config, pathResolver: import.meta.resolve },
});

const server = express();
server.use(handle.router);
server.listen(config.http.port);
// シャットダウン時
await handle.dispose();
```

standalone テンプレートの [`buildModules.mts`](../../templates/standalone/src/buildModules.mts) が完全な composition root の例である。

各モジュールが要求するもの・読むものはそのマニフェストに宣言されている（上の表のリンク先）。構成が boot 時に決めておくべきこと:

- `oauthModule` は `config`、`clientRepository`、`codeRepository`、`keyStore` と、空でない `endpoints.login.url` を要求する — `/authorize` は未認証のブラウザーをそこへ送るので、無ければ boot が拒否する。
- `subjectRevocation`、`auditSink`、`accessTokenDenylist` は配線は任意だが決定は任意ではない: 埋めないスロットは不在を宣言すること — `oauth.revocation.subject = "unsupported"`、`audit.sink.type = "none"`、`oauth.revocation.accessToken = "unsupported"` — さもなければ boot が拒否する。
- `oauth.jwt.issuer` が正規の issuer URL でなければルーターの構築が失敗する: `iss` はデプロイの属性であり、リクエストから読むものではない。
- `/oauth` 配下の各モジュールは自分のボディを自分でパースし、モジュールを並べる順は関係しない。`oauthModule` のルーターが JSON とフォームのボディを（Express の既定の上限で）パースするのは、[エンドポイント](#エンドポイント) の表にあるルートのうち、この構成で実際にマウントしたものだけ、それもそれぞれのパスちょうどに対してだけで、その下の長いパスは含まない（[`routes.mts`](src/routes.mts) の `oauthRoutePaths`。ログアウト、federation token、同意のルートは、ストアが配線されたときだけマウントされる）。`/oauth` 配下のそれ以外のパス — device グラント、federation grants、WebAuthn、デプロイ独自のもの、oauth がマウントしないときの `/oauth/logout` や `/oauth/consent`、`/oauth/token/custom` のように oauth のルートの下にあるものを含む — へのリクエストは、ボディを読まれないままそのルートに届き、`/oauth/revoke` のスロットルにも数えられない。そこにルートをマウントして `req.body` を読むモジュールは、自分のパーサーをマウントする。

## エンドポイント

すべて `oauthModule` が `/oauth` 配下にマウントする。

| エンドポイント | マウントされる条件 | 説明 |
|---|---|---|
| `POST /oauth/token` | 常に。`grant_type` で振り分ける | [グラント](#グラント) |
| `GET`、`POST /oauth/authorize` | 常に | [OIDC の対応範囲](#oidc-の対応範囲-284) |
| `POST /oauth/introspect` | 常に | [イントロスペクション](#イントロスペクション-呼び出し元が問い合わせられるトークン) |
| `GET`、`POST /oauth/userinfo` | 常に | [Userinfo](#userinfo) |
| `POST /oauth/revoke` | 常に。何を失効できるかは配線次第 | [リボケーション](#リボケーション) |
| `GET`、`POST /oauth/consent` | `consentStore` と `pendingConsentStore` の両方が配線されたとき | [同意](#サードパーティクライアントの同意-527) |
| `GET`、`POST /oauth/logout` | セッションカスケードの 6 スロットがすべて配線されたとき | [ログアウト](#ログアウト) |
| `POST /oauth/federation/:name/logout` | 同じ 6 スロット | [ログアウト](#ログアウト) |
| `POST /oauth/federation/:name/token` | 同じ 6 スロット | [フェデレーショントークンエンドポイント](#フェデレーショントークンエンドポイント) |

6 スロットとは `userSessionStore`、`sessionRPRegistry`、`sessionFamilyIndex`、`sessionFederationIndex`、`federationTokenStore`、`refreshTokenFamilyRevocation`。ディスカバリーが `end_session_endpoint` とログアウト関連の機能を広告するかどうかも同じチェックで決まるので、ドキュメントがマウントされていないエンドポイントを名指すことはない。

**エラー説明とエラーコード。** RFC 6749 がエラーのテキストに許すのは、`"` と `\` を除く印字可能な ASCII だけである（§5.2、§4.1.2.1）。このパッケージはその範囲に次をすべて収める: `/oauth/token` が書く `error_description`（どのグラントが作ったものでも）、`/oauth/authorize` がエラーリダイレクトに載せる `error_description`、クライアント認証が `/oauth/token`、`/oauth/introspect`、`/oauth/revoke`（後の 2 つもエラーは同じ形式。RFC 7662 §2.3、RFC 7009 §2.2.1）で書く `error_description`。それ以外の文字は `?` に置き換える（core の `sanitizeErrorText`、[`errors/envelope.mts`](../core/src/errors/envelope.mts)）。説明が引用するクライアント送信の値（グラントタイプ、スコープ、audience、トークンタイプ、`response_type` など）や設定値（クライアントの `tokenEndpointAuthMethod`、トークンバインディングの kind など）に含まれる文字も同じである。説明は値を `'` で引用する。`error` コード自体は `1*NQSCHAR`（同じ文字で、空でないこと）でなければならない。グラントポリシーの deny はポリシー自身のコードを運ぶので、範囲外のコードは `/oauth/token` では `invalid_request`、`/oauth/authorize` のリダイレクトでは `access_denied` として返し、サニタイズしてログに残す（`token_error_code_malformed`、`authorize_policy_deny_error_malformed`）。空の説明や文字列でない説明（JavaScript のポリシーは何でも返せる）は送らない。`/oauth/token` は省き、`/oauth/authorize` のリダイレクトは `policy denied` を載せる。クライアントの `state` は送られたとおりに返す。これらのエンドポイントで応答する core のミドルウェア（トークンバインディングのミドルウェア、レートリミッター、保護リソースのバインディング）は core の `errorEnvelope` を通して書き、そこはまだサニタイズしない。後続の変更で同じ範囲に揃える。

`/token`、`/introspect`、`/authorize`、`/revoke` は、構成が `rateLimiter` を配線していればクライアント認証より前でスロットリングされ、プロダクトの `rateLimit.failMode` に従う。配線されていなければスロットリングされない。

`consentStore` が `pendingConsentStore` 無しで配線されたとき（またはその逆）、および `oauth.revocation.accessToken = "denylist"` を宣言して `accessTokenDenylist` が無いとき、ルーターは構築を拒否する — `createApp` 経由では boot の失敗になる。

**ディスカバリー。** `oauthModule` は自分のエンドポイントとメタデータを core の `/.well-known/openid-configuration` に提供し、core は issuer が設定されているときだけそれを提供する。各機能は守れる場合にだけ広告される: `revocation_endpoint` はエンドポイントが何かを失効できるとき、`private_key_jwt` は `replaySeenSet` が配線されているとき、`client_id_metadata_document_supported` は機能が有効で同意ストアが配線されているとき、ログアウトのフィールドは上の 6 スロットのチェックに従う。`grant_types_supported` は `/oauth/token` が振り分けに使う resolver から読み、`code_challenge_methods_supported` は `["S256"]`。規則はそれを計算している [`module.mts`](./src/module.mts) に書かれており、[`discovery-contribution.test.mts`](./src/__tests__/discovery-contribution.test.mts) で固定されている。

## パブリック API

以下はすべて [`src/index.mts`](./src/index.mts) から export される。リンク先のファイルが各定義とその doc コメントを持つ。

**モジュール** — [なぜ 4 つのモジュールか](#責務と役割)を参照。

- `oauthModule({ config })` — [`module.mts`](./src/module.mts)
- `oauthAuthorizationModule({ config })` — [`oauthAuthorization.mts`](./src/oauthAuthorization.mts)
- `oauthSessionModule({ config })` — [`oauthSession.mts`](./src/oauthSession.mts)
- `subjectRevocationServiceModule`（ファクトリではなくモジュールの値） — [`logout/subjectRevocationService.mts`](./src/logout/subjectRevocationService.mts)

**ルーター。** `createOAuthRouter(express, options)` — [`routes.mts`](./src/routes.mts) — 明示的なオプションから `/oauth` ルーターを組み立てる。`oauthModule` が解決済みの deps を渡して呼ぶものであり、ルーターを自分でマウントする composition root 向け。グラントレジストリは生成しない: `registry` は呼び出し元が渡す `get(grantType)` を持つ任意のオブジェクトで、同じ値がそのまま返る。登録済みのグラントタイプが必要な呼び出し元は core の `grantHandlerResolver` を読むこと。

**クライアント認証。**

- `createClientAuthMiddleware(clientRepository, options)` と `ClientAuthMiddlewareOptions` — [`middleware/clientAuth.mts`](./src/middleware/clientAuth.mts)。`client_secret_basic`、`client_secret_post`、`private_key_jwt`（1 リクエストに 1 方式）でクライアントを認証し、`allowPublicClients` が指定されたときだけ public クライアントを受け入れ、認証済みクライアントを `req.oauthClient` に載せる（型はグローバルな Express の拡張で提供）。拒否は RFC 6749 §5.2 の `{ error, error_description }`。
- `createClientAssertionVerifier`、`CLIENT_ASSERTION_ALGORITHMS`、`JWT_BEARER_CLIENT_ASSERTION_TYPE`、`MAX_CLIENT_ASSERTION_LIFETIME_SECONDS` と型 `ClientAssertionVerifier`、`ClientAssertionVerifierOptions`、`ClientAssertionOutcome` — [`middleware/clientAssertion.mts`](./src/middleware/clientAssertion.mts)。ミドルウェアが使う `private_key_jwt` の検証器。[`private_key_jwt`](#クライアント認証-private_key_jwt-rfc-7523-22) を参照。

**Client ID Metadata Documents。** `createClientIdMetadataDocumentResolver`、`withClientIdMetadataDocuments`（登録済みクライアントを先に、ドキュメントを後に答える `ClientRepository`）、`isClientIdMetadataDocumentUrl`、`isClientIdMetadataDocumentClient` と型 `ClientIdMetadataDocumentOptions`、`ClientIdMetadataDocumentResolver` — [`clients/clientIdMetadataDocument.mts`](./src/clients/clientIdMetadataDocument.mts)。[Client ID Metadata Documents](#client-id-metadata-documents-529) を参照。

**ログアウトの部品**（自前のログアウトを組み立てる構成向け）:

- `cascadeLogout`、`CascadeLogoutOptions`、`CascadeLogoutResult` — [`logout/cascadeLogout.mts`](./src/logout/cascadeLogout.mts)
- `broadcastBackchannelLogout`、`BroadcastBackchannelLogoutOptions`、`BroadcastRP` — [`logout/broadcastBackchannel.mts`](./src/logout/broadcastBackchannel.mts)
- `renderFrontchannelLogoutHtml`、`RenderFrontchannelLogoutHtmlOptions`、`FrontchannelRP` — [`logout/renderFrontchannel.mts`](./src/logout/renderFrontchannel.mts)

**イントロスペクションの型。** `IntrospectResponse` — [`types/introspect.mts`](./src/types/introspect.mts)。リソースサーバーやプロキシが型付けに使える RFC 7662 の応答形 — と、そこから再 export される core の `cnf` ヘルパー `extractConfirmation` / `isCompoundConfirmation`。

## ソース構成

`src/` 配下の各ディレクトリは 1 種類の責務を持つ。個々のファイルが何をするかはそのファイルのヘッダーコメントにある。

| ディレクトリ | 責務 |
|---|---|
| `src/`（ルート） | 組み立て: `oauthModule`、`oauthAuthorizationModule`、`oauthSessionModule`（4 つ目の `subjectRevocationServiceModule` は、それが配線するカスケードと並んで `logout/` にある）、`createOAuthRouter`（下のすべてのルートを組み合わせる）、オプションの解決、core のアクセストークンヘッダーパーサーの再 export。 |
| [`routes/`](./src/routes) | エンドポイント群ごとのルーターまたはハンドラー — authorize、consent、logout、federation token、revoke、userinfo。ルートは `grants/`、`logout/`、`middleware/`、`clients/` を使ってよいが、それらのどれもルートを import しない。`routes/authorize.mts` は grant のヘルパーを 1 つ（クライアントごとの PKCE 方式の規則）も読む。`/authorize` は PKCE を `/token` と同じやり方で検証するからである。両者が読む RFC 8707 `resource` の規則は core のもの（[`grants/resourceIndicator.mts`](../core/src/grants/resourceIndicator.mts)）で、WebAuthn グラントと共有している。 |
| [`grants/`](./src/grants) | グラントハンドラー: core のグラント契約の上での、リクエストからトークンへの純粋な判断。HTTP を持たない。 |
| [`middleware/`](./src/middleware) | クライアント認証。兄弟パッケージが再利用する。 |
| [`logout/`](./src/logout) | 順序の決まったセッションカスケード（`cascadeLogout`）、RP へのバックチャネル POST、フロントチャネルのページ、subject revocation service を配線するモジュール。 |
| [`clients/`](./src/clients) | Client ID Metadata Documents の解決: クライアントが名指す URL からその登録を SSRF ガード越しに取得し、キャッシュする。 |
| [`types/`](./src/types) | イントロスペクション応答の契約。 |

## グラント

### 有効にするグラント

組み込みのグラントはすべて、`oauth.grants.<name>.enabled` が `true` — 真偽値か、環境変数置換が生む文字列 `"true"`。それ以外はすべて無効 — になるまで無効:

| グラント | キー | 環境変数 |
|---|---|---|
| `authorization_code` | `oauth.grants.authorization_code.enabled` | `OAUTH_GRANTS_AUTHORIZATION_CODE_ENABLED` |
| `refresh_token` | `oauth.grants.refresh_token.enabled` | `OAUTH_GRANTS_REFRESH_TOKEN_ENABLED` |
| `client_credentials` | `oauth.grants.client_credentials.enabled` | `OAUTH_GRANTS_CLIENT_CREDENTIALS_ENABLED` |
| `session` | `oauth.grants.session.enabled` | `OAUTH_GRANTS_SESSION_ENABLED` |
| jwt-bearer | `oauth.grants."urn:ietf:params:oauth:grant-type:jwt-bearer".enabled` | core の `reference.conf` を参照 |

無効なグラントは登録されない: `/oauth/token` はそれに `unsupported_grant_type` を返し、`grant_types_supported` にも載らない。

登録済みのグラントも、クライアントの登録の `allowedGrantTypes` で許可されている必要がある — `/oauth/token` では拒否は `400 unauthorized_client` で、`authorization_code` については `/authorize` でも確認し、拒否は `unauthorized_client` エラーとしてクライアントの `redirect_uri` にリダイレクトされる。リストは名指したグラントタイプだけを許すので、空のリストは何も許さない。リストが無ければすべてのグラントを許すが、無いことを拒否として扱うもの — `client_credentials`、jwt-bearer、token exchange、device グラント、WebAuthn グラント — は例外で、リストに名指しが必要である。`oauth.requireGrantTypeAllowlist = true`（`OAUTH_REQUIRE_GRANT_TYPE_ALLOWLIST`、既定は無効）にすると、リストが無いときはすべてのグラントを拒否する。基本の規則は core の `isGrantTypeAllowed`（[`repositories/allowedGrantTypes.mts`](../core/src/repositories/allowedGrantTypes.mts)）で、無いことを拒否として扱うグラントは `requiresExplicitGrantAllowlist` を宣言し、`/oauth/token` のディスパッチ（[`routes.mts`](src/routes.mts)）がそれを強制する。

`userRepository` か `assertionVerifier` の無い状態で jwt-bearer を有効にすると boot が失敗する — [jwt-bearer](#jwt-bearer-信頼する発行者-525) を参照。

### `authorization_code`: セッション、`sid`、`family_id` と id_token

`authorization_code` と `refresh_token` グラントが発行するアクセストークンとリフレッシュトークンは `family_id` — リフレッシュトークンファミリー。[イントロスペクション](#イントロスペクション-呼び出し元が問い合わせられるトークン)、[userinfo](#userinfo)、[ログアウト](#ログアウト)、federation token ルートが失効の確認に使う — と、コードレコードにあればセッション ID の `sid` を持つ。`sid` はログイン経路（ローカルログインかフェデレーションコールバック）が `/authorize` でコードに書き込む。

**`userSessionStore` が配線されているとき、コードは生存中のセッションを名指さなければならない。** トークンのサブジェクトはそのセッションから来て、グラントは [ログアウト](#ログアウト)が見つけられるよう、新しいファミリーとクライアントをそのセッションに結び付ける:

- `sid` の無いコードは `400 invalid_grant` — ログインの配線が記録しなかった;
- ストアが解決できない `sid`、またはサブジェクトを持たないセッションは `400 invalid_grant` / `session_invalid`。トークンの発行中に終わったセッションは `400 invalid_grant` / `session_invalidated`;
- 答えられないストア — セッションの読み取りか、結び付けの書き込み — は `503 temporarily_unavailable`。

`userSessionStore` が無ければ、サブジェクトはトークンリクエストに伴うブラウザーセッションのユーザーであり、id_token は発行されない。

**id_token** は、付与スコープに `openid` が含まれ、`userSessionStore` が配線され、`oauth.jwt.issuer` が設定されているときに発行される。そうでなければ省かれ、アクセストークンとリフレッシュトークンは通常どおり返る。id_token は `iss`、`sub`、`aud`、`exp`、`iat`、`jti`、`auth_time`、`sid`、`azp` を持ち、認可リクエストに `nonce` があればそれ（OIDC Core §3.1.3.7）、[ステップアップ](#ステップアップと再認証-481)で説明する `amr` / `acr`、スコープで絞ったユーザークレーム（[userinfo と同じ表](#userinfo)）を持つ。

### `refresh_token`

- **セッションがまだ存在すること。** `userSessionStore` が配線され、リフレッシュトークンが `sid` を持つとき、グラントはセッションを読む: 無ければ `400 invalid_grant`、ストアの障害は `503 temporarily_unavailable`。
- **ローテーションは何かに署名する前に予約される。** 新しいリフレッシュトークンの `jti` と、その有効期間を測り始める時刻が先に決まり、`RefreshTokenFamilyRotation.rotate` でファミリーストアにコミットされ、そのコミットが成立してから署名される。したがって競合に負けたリクエスト — リプレイ、失効済みファミリー、`reject` 下の未知のファミリー — は署名を 1 つも生まずに返る。署名のたびに課金されるリモート呼び出しになる KMS バックエンドの `SigningKeyProvider` ではこれが効く。発行されるトークンは予約されたとおりの `jti` を持ち、`exp` はストアがコミットした上限 — `RefreshTokenFamilyRotationOutcome.cappedExpiresAtMs` から、その契約が記す前方ドリフトのための 1 秒のマージンを引き、秒に切り捨てたもの — を超えない。したがってリフレッシュトークンが、そのリプレイを捕まえるファミリーレコードより長く生きることはない。有効期間が残らない上限は、期限切れのリフレッシュトークンを載せた `200` ではなく `400 invalid_grant`（"refresh token family has reached its lifetime"）になる。
- **その順序の代償。** `rotate` がコミットした時点で、提示されたトークンは使用済みになる。その後に署名器が失敗すると — KMS の障害 — 誰もトークンを持たないローテーションが残る: グラントは `503 temporarily_unavailable` を返し、ファミリー ID・使用済みの `jti`・予約された `jti` を付けて `refresh_token_rotation_orphaned` をログに出す。これはストアが実際にローテーションをコミットしたときだけで、ローテーションを配線していない構成や、`unknownFamilyPolicy` で受け入れた未知のファミリーは通常の署名器の振る舞いのままである。クライアントの再試行は古いトークンを提示し、それは今やリプレイとして読まれるので、ファミリーは失効し、ユーザーは再認証する。
- **リプレイはファミリーを失効させる**（RFC 6819 §5.2.2）。モジュールがローテーションと並べて `refreshTokenFamilyRevocation` を読むのはそのためである。また `iat` がサブジェクトの失効ウォーターマーク以前のリフレッシュトークンは `invalid_grant` になる。

### `session`

認証済みのブラウザーセッションのユーザーにアクセストークンを発行する（ファーストパーティ / BFF 構成）。呼び出し元は `/oauth/token` でクライアントとして認証する。クライアントの `allowedScopes` が上限である。`aud` はクライアントの `allowedAudiences` の最初のエントリー、それが無ければクライアント ID で、`azp` はクライアント ID。リフレッシュトークンは発行しないので、トークンは `family_id` を持たない。`sid` はブラウザーセッションにあれば持つ。

`userSessionStore` が配線されているとき、session グラントはトークンに署名する前に必ず空でない `sid` と生存中の `UserSession` を要求する: セッションが無いか失効していれば `400 invalid_grant`、ストアの障害は `503 temporarily_unavailable`。追跡中のセッションは空でないサブジェクトを持ち、それがブラウザーのユーザーと一致しなければならない — 不正または食い違う ID はトークンに署名する前に拒否される。`userSessionStore` が無ければ、グラントはブラウザーセッションだけを頼りにする。検証済みの DPoP / mTLS バインディングはアクセストークンの `cnf` に保持される: DPoP は `token_type=DPoP`、mTLS は `Bearer` のままで、リソースサーバーは対応する証明を検証しなければならない。

### `client_credentials`

RFC 6749 §4.4 のマシン間通信: public クライアントは拒否され、トークンの `sub` はクライアント ID で、リフレッシュトークンは発行されない。クライアントの `allowedGrantTypes` がこのグラントを名指している必要がある — リストが無ければ省略による許可ではなく拒否になる。jwt-bearer、token exchange、device グラント、WebAuthn グラントも同じである。

## OIDC の対応範囲 (#284)

これは、**ファーストパーティ**のデプロイに必要な OIDC の部品を備えた OAuth 2.0 認可サーバーである。どこで止まるかは意図したもので、それを述べることも契約の一部である — ここにあるものをディスカバリーで見つけた RP が、端にぶつかって初めて境界を知るようであってはならない。

**`/oauth/authorize` は GET と POST を受け付ける**（OIDC Core §3.1.2.1）。どちらもまったく同じ順序でチェックを走らせる: ハンドラーはパラメーターを 1 つのアクセサー越しに読むので、あるチェックが片方のメソッドにだけ付いてもう片方で忘れられることはない。

**`redirect_uri` は `client.allowedRedirectUris` と文字列の完全一致で照合し、例外は 1 つだけ（#483）。** 登録値と提示値の**両方**がループバックの **IP リテラル**（`127.0.0.0/8`、`[::1]`）上の `http:` のとき、比較前に両方からポートを落とす — スキーム・ホスト・パス・クエリは引き続き完全一致で比べる。一致判定は正規化した URL ではなく、ポートを除いた**元の文字列**同士で行うので、ドットセグメント（`/a/../cb`）、パーセントエンコードの揺れ、`\` 区切り、末尾スラッシュの違い、スキームの大文字小文字によって条件が広がることはない。ループバックインターフェースで応答を受けるネイティブアプリは実行時に OS が割り当てるエフェメラルポートを使うので、登録でそれを名指せない（RFC 8252 §7.3）: `http://127.0.0.1/cb` は `http://127.0.0.1:49152/cb` を受け入れる。

- `http://localhost/cb` には例外が**無い** — ループバックの*名前*は保証をホストの名前解決に移すことになり、RFC 8252 §8.3 はそれを推奨しない。IP リテラルを登録すること。
- `https://` にも例外は無い。ホストがループバックかどうかに関係なく。
- **提示された** URI が応答の送り先であり、認可コードに結び付けられるのもそれである。トークンエンドポイントの `redirect_uri` チェック（RFC 6749 §4.1.3）はそのレコードと単純な一致で比べる — ポートも含めて — ので、別のポートのリスナーが他者のコードを引き換えることはできない。
- 比較は `matchesRegisteredRedirectUri`（`@o3co/auth-provider-core`）にあり、独自の認可エンドポイントがこれと同じやり方で照合できるよう export されている。

**PKCE は必須で、方式は `S256`。** `plain` は登録に `allowPlainPkce: true` を持つクライアントにだけ許されるので、ディスカバリーは `S256` だけを載せる。

**`prompt=none` に対応する。** セッションが無ければクライアントの `redirect_uri` で `login_required` を返す — 非表示の更新用 iframe はログインページを操作できないので、それが目的どおりである。セッションがあれば黙って進む。

**`prompt=login` は再認証させる** — 下の[ステップアップと再認証](#ステップアップと再認証-481)を参照。

**`prompt=consent` を尊重する**: ファーストパーティでないクライアントには、記録済みの同意がリクエストを覆っていても同意ページを強制する。ファーストパーティのクライアントには何もしない — デプロイ自身がそのクライアントを運用しているので、同意する対象が無い。[サードパーティクライアントの同意](#サードパーティクライアントの同意-527)を参照。

**`select_account` は無視せず拒否する**（値を名指した `invalid_request`）: アカウント選択画面は無く、無視すれば、RP はアカウントが選び直されたと信じるトークンを受け取ることになる。

**`request` と `request_uri` は無視せず拒否する**（`request_not_supported` / `request_uri_not_supported`）: 署名付きリクエストオブジェクトはパラメーターを改ざん不能にするためにあるので、代わりにクエリ文字列を処理すれば、RP がそれを尊重されたと信じている間に、オブジェクトが防ぐはずだったものを攻撃者に与えることになる。ディスカバリードキュメントが `request_uri_parameter_supported: false` と言うのも同じ理由である — OIDC Discovery はこのフィールドの省略時の既定を **`true`** としているので、省略すること自体が主張になる。

**未実装:** `claims` パラメーターと、既定以外の `response_mode`。`claims_parameter_supported` と `request_parameter_supported` は省略時の既定が `false` なので、ディスカバリードキュメントは何も言わないことでそれらについて真実を述べている。

**`/authorize` はコードを発行する前にセッションを再確認する。** 認証済みのブラウザーセッションの `sid` がもう `UserSessionStore` で解決できなければ、死んだ `sid` を載せたコードを発行する代わりにログインページへ送る（`prompt=none` なら `login_required`）。答えられないストアも同じくフェイルクローズになる。

## ステップアップと再認証 (#481)

ネイティブアプリがセンシティブな操作に OP から必要とするものは 2 つ: **新たな認証を強制すること**（支払い、資格情報の変更）と、**ユーザーがどう認証したかを知ること**（パスキー、パスワード、パスワードと第 2 要素）。後者によって、アプリ — またはリソースサーバー — はレベルを要求できる。どちらもログイン時にセッションが記録するものに依拠する。

**セッションが記録するもの。** `UserSession.authTime` と `UserSession.amr` — ログイン経路が書く RFC 8176 の値: `POST /session/login` は `["pwd"]`、フェデレーションコールバックは上流 IdP の `amr`（プロバイダーがプロファイルに載せる場合）とデプロイ定義の `fed`。セッション無しでトークンを発行する WebAuthn グラントは、アクセストークンに直接 `amr: ["hwk"]` を刻む。RFC 8176 は「フェデレーション」に当たる値を登録しておらず、OIDC Core §2 は `amr` の値をデプロイに委ねているので、`fed` は借用ではなくここで文書化している。`POST /auth/mfa/verify` の後でログインを再開する構成（MFA ルートはこのリポジトリでは組み込まれておらず、再開ハンドラーはデプロイのもの）は、作るセッションに `mfa` — と要素自身の値、たとえば `otp` — を記録する。`CreateUserSessionInput.amr` がその継ぎ目である。

**トークンが運ぶもの。** id_token は `auth_time` を常に持ち、セッションが記録していれば `amr` を、`/authorize` が `acr_values` のリクエストを満たしたときは `acr` を持つ。アクセストークンは `amr` と `acr` があればそれを写すので、`auth.policy-verifier` やリソースサーバーは id_token 無しでそれに基づいて判断できる — そして**リフレッシュを越えて写し続ける**: `authorization_code` グラントはリフレッシュトークンにも両方を刻み、`refresh_token` グラントは提示されたトークンから、自分が発行するアクセストークンとリフレッシュトークンへそれらを運ぶ。リフレッシュは認証を繰り返さないからである（OIDC Core §12.2 は `auth_time` を同じように扱う）。`session` グラントは追跡中のセッションの `amr` を写し（`acr_values` の交渉が無いので `acr` は無い）、パスキーのグラント（`@o3co/auth-provider-webauthn`）はアクセストークンと同じくリフレッシュトークンにも `amr: ["hwk"]` を刻む。どのグラントもこれらのクレームを 1 つの形で読む — `amr` は空でない文字列の空でない配列、`acr` は空でない文字列（core の `wellFormedAmr` / `wellFormedAcr`） — そしてそれ以外は省く。したがって `amr: []` を記録したセッションは、最初のリフレッシュで消える `amr` ではなく、どのトークンにも `amr` を刻まない。どちらも持たないリフレッシュトークンからは、どちらも持たないトークンが生まれる。

**`max_age`。** 負でない整数（それ以外は `invalid_request`）。`auth_time` が `max_age` 秒より古いセッション — `max_age=0` は常に古い — は、未認証のものとまったく同じくリクエストを往復させてログインページへ送られ、加えて 1 つだけ: 要求した時刻が**サーバー側に**記録される。戻ってきたとき、その時刻よりミリ秒単位で厳密に後に認証したセッションが求められた再認証であり、リクエストは進む — `max_age=0` も含めて。これがループを防ぐ。それより前に認証したセッションは、もう一度送り返されるのではなく `login_required` を返される。`prompt=none` では古いセッションは即座に `login_required`: 無言は無言である。id_token の `auth_time` が RP の検証するものであり、常に真実である。

要求は**セッションストア内のレコード**であり、戻り URL が `reauth_ask` として運ぶ不透明な ID で名指される。URL 上のタイムスタンプそのものではない: リクエストからそのまま読む目印は呼び出し元が書けるもので、偽造されれば任意の生存セッションでチェックを満たし、強制するための往復を飛ばせてしまう。レコードは偽造できない（ID は CSPRNG からの 32 バイトで、存在しないものを名指すのは何も名指さないのと同じ）。`/session/login` が行うセッション再生成を越えて残る（セッション上のフィールドでは残らない）。発行元の authorize リクエストに結び付けられるので、あるリクエストに対する未処理の要求が別のリクエストの鮮度要件を満たすことはない。読まれた時点で消費されるので、戻り URL をリプレイすると 2 つ目のコードを発行するのではなく改めて要求する。有効期限は 10 分。理由は [`routes/reauthAsk.mts`](./src/routes/reauthAsk.mts) にある。

`max_age` と `prompt=login` には `userSessionStore`（無ければ測る対象の `auth_time` が無い）と、セッションミドルウェアのストア（要求を記録する場所）が要る。どちらかが無い構成は、黙って受け入れるのではなく `invalid_request` を返す。

ログインページはブラウザーを `redirect_to` へ**そのまま**戻さなければならない: authorize URL を組み立て直すページは要求 ID を落とし、リクエストは再度の認証を求められる。

**`prompt=login`** は同じ仕組みで、古さの判定が「常に」に置き換わる: ログインページへ送り、要求を記録し、その後に認証したセッションなら満たされ、そうでなければ `login_required`。`prompt=none login` は OIDC Core §3.1.2.1 のとおり拒否する。

**`acr_values`** は設定した表からだけ答える:

```hocon
oauth.authorize.acrValues {
  "urn:example:pwd" = ["pwd"]
  "urn:example:mfa" = ["pwd", "mfa"]
  "urn:example:passkey" = ["hwk"]
}
```

各キーはこのデプロイが保証する Authentication Context Class Reference で、値はそれを満たすためにセッションが持つべき `amr` の集合。要求された値のうちセッションが最初に満たすものが、コードと id_token の `acr` になる。どれも満たされない — あるいは表にまったく無い値 — ときは、満たされなかったものを名指して `redirect_uri` で `unmet_authentication_requirements` を返す。黙って受け入れることも、ステップアップのリダイレクトも無い — ログインページにどの要素を追加すべきか伝えられないからである。表が空でなければ、ディスカバリーはキーを `acr_values_supported` として広告する。何も要求しない acr は boot で拒否される: どのセッションもそれを満たし、何も保証しないからである。

**再認証を求められたら、どちらのログイン経路も再認証しなければならない。** デプロイが提供するログインページは `prompt=login` / `max_age` と目印を載せた `redirect_to` を受け取る。既に認証済みのブラウザーをそのまま送り返すページは、ループではなく `login_required` を受け取る。`POST /session/login` とフェデレーションコールバックは常に新しい `auth_time` を持つ*新しい*セッションを確立し、それが再認証である。

## クライアント認証: `private_key_jwt` (RFC 7523 §2.2)

ここでクライアント認証を行うすべてのエンドポイント — `/oauth/token`、`/oauth/introspect`、`/oauth/revoke` — は、`client_secret_basic` / `client_secret_post` に加えて、クライアントが自分の秘密鍵で署名した JWT を受け付ける（#484）。マシンクライアントのすべてのレプリカに共有の秘密を配り、全箇所で一斉にローテーションする必要は無い: 秘密の半分はクライアントに留まり、ローテーションは JWKS の公開であり、各アサーションはプロバイダーがちょうど 1 回だけ消費する `jti` を持つ。

**登録。** `tokenEndpointAuthMethod: "private_key_jwt"` と、`jwks`（インラインの公開鍵、RFC 7591 の `jwks` — `d`、`p`、`q`、`k` のような秘密のメンバーを持つ鍵や、対称鍵 `kty: "oct"` は登録時に拒否される。どのミドルウェアも読む射影は公開のものだからである）か `jwksUri`（`https`、またはループバックホストの `http`。検証時に取得してキャッシュし、未知の `kid` はクールダウン付きで再取得を起こす）のちょうど一方。`clientSecret` は無し — スキーマはこの方式の隣の `clientSecret` を拒否し、他の方式の隣の `jwks` / `jwksUri` も拒否する。

**リクエスト。** フォームボディに `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` と `client_assertion=<JWT>`、そして認証に関わるものは他に何も付けない: Basic ヘッダーやボディの `client_secret` と並んだアサーションは、どちらも調べる前に拒否される（RFC 6749 §2.3、1 リクエストに 1 方式）。ボディの `client_id` があれば、アサーションと一致しなければならない。

**アサーション。** `iss` と `sub` はどちらも `client_id` と等しい。`aud` は issuer かトークンエンドポイントの URL を名指す（RFC 7523 §3 — どちらの形でもよいので、どちらを使うクライアントライブラリでも動く）。`exp` は必須で、最大 1 時間先まで（`MAX_CLIENT_ASSERTION_LIFETIME_SECONDS`）。`jti` は必須かつ 1 回限りで、アサーションが期限切れになるまで構成の `replaySeenSet` に `client-assertion:<client_id>` として記録される。署名は非対称アルゴリズム（`RS*`、`PS*`、`ES*`、`EdDSA` — `token_endpoint_auth_signing_alg_values_supported` が列挙する。`HS*` と `none` は JWKS に対して決して受け入れない）。`nbf` はあれば検証し、`iat` はあればサーバー時計より 30 秒の許容を超えて未来であってはならず、有効期間の上限より古くてもならない。

**拒否**は `401 invalid_client` — リプレイされた `jti`、誤った `aud`、期限切れまたは長すぎるアサーション、JWKS に無い鍵での署名、公開されていない `kid`、別の方式で登録されたクライアント、未知のクライアント、取得できない `jwks_uri`（フェイルクローズ、理由付きで `client_assertion_refused` としてログ出力）。`replaySeenSet` を配線していない構成での `private_key_jwt` リクエストは `500 server_error`: 記録できない `jti` はリプレイされ得るものなので、未検査で認証するのではなく拒否する。standalone テンプレートはそれを配線する（`REPLAY_SEEN_SET_ADAPTER`、既定は Redis。メモリーアダプターは `DEPLOYMENT_MODE=multi` では拒否される。捕獲されたアサーションがレプリカごとに 1 回ずつリプレイできてしまうからである）。

**提供しないもの: `client_secret_jwt`。** これにはリポジトリのインターフェースが生の秘密を HMAC 鍵としてミドルウェアに渡す必要がある — `authenticate(clientId, secret)` は比較するだけで明かさない — し、テンプレートが推奨する bcrypt でハッシュした `clientSecret` はそもそも鍵になり得ない。そのケースはデプロイが既に持つ秘密ベースの方式で足り、非対称の方式こそがこの機能の目的である。

```yaml
# config/clients.yaml
orders-service:
  tokenEndpointAuthMethod: "private_key_jwt"
  jwksUri: "https://orders.example.com/.well-known/jwks.json"
  allowedGrantTypes: ["client_credentials"]
  allowedScopes: ["orders:read"]
  defaultScopes: ["orders:read"]
  allowedAudiences: ["https://api.example.com/orders"]
```

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion=eyJhbGciOiJFUzI1NiIsImtpZCI6IjIwMjYtMDkifQ...
```

## サードパーティクライアントの同意 (#527)

`/oauth/authorize` は `firstParty: true` と印の付いたクライアントには、セッションが認証済みになり次第コードを発行する — デプロイ自身がそのクライアントを運用しており、自動同意が正直なモデルである。それ以外のクライアントは**同意**を通る: ユーザーはデプロイ自身のページで尋ねられ、答えは記録されるので、既に許したものについて再び尋ねられることは無い。同意ストアが無ければ、そのようなクライアントは `/authorize` で拒否される。

`consentStore` と `pendingConsentStore` を配線し、`endpoints.consent.url` を自分のページに向ける。同梱のモジュールはどれも両方を提供する: `@o3co/auth-provider-core` の `memoryConsentStoreModule`（単一レプリカ — `deployment.mode = "multi"` では拒否）と、同意レコードと保留中のリクエストをレプリカ間で共有する `@o3co/auth-provider-redis` の `redisConsentStoreModule`。standalone テンプレートでは `consentStore.adapter = "memory"` か `"redis"`。そのうえで、ファーストパーティでないクライアントについて:

1. `/authorize` は通常どおりリクエストの形のチェックをすべて走らせ、その後 (`sub`, `client_id`) の同意レコードを引く。要求スコープを覆う（付与済みの部分集合である）生存中のレコードがあれば、操作無しでコードを発行する。
2. そうでなければリクエストは `pendingConsentStore` に **32 バイトのチャレンジで保留**され、それを尋ねたセッションとサブジェクトに結び付けられ、ブラウザーは `endpoints.consent.url?challenge=<id>` へリダイレクトされる。`prompt=none` なら代わりに `redirect_uri` で `consent_required`（OIDC Core §3.1.2.6）。`prompt=consent` はレコードが覆っていてもリクエストを保留する。
3. ページは **`GET /oauth/consent?challenge=<id>`**（セッション Cookie、キャッシュ不可）を呼び、`client_id`、`client_id_host`（Client ID Metadata Document から解決したクライアントの場合のみ — 下記参照）、`client_name`、`client_uri`（登録から）、`scopes`（要求されているもの）、`granted_scopes`（ユーザーが既に同意したもの。ページが差分を強調できるように）、`redirect_uri`（ホストを表示すること — コードの送り先）、`expires_in` を受け取る。
4. ページは `{ "challenge": "<id>", "decision": "accept" | "deny" }`（JSON かフォーム）で **`/oauth/consent` に `POST`** する。`accept` は付与済みと要求中の和集合を記録し、`consent.granted` を出し、保留中の `/authorize` URL への `303` を返す — そこでレコードが見つかり、コードが発行される。`deny` は `consent.denied` を出し、`error=access_denied` と `state` を付けてクライアントの `redirect_uri` への `303` を返す。どちらの場合もチャレンジは消費される。

チャレンジはリクエストを保留したセッションに結び付けられ、ページにはクロスサイトのページが読めないリダイレクト URL 経由でのみ届く。一致する値を持つ POST は同一オリジンのコードが組み立てたものである（シンクロナイザートークンパターンで、セッションがシンクロナイザー）。他者の・リプレイされた・期限切れ（10 分）のチャレンジは `400`。回答は保留レコードを 1 ステップで**消費する**（`PendingConsentStore.consume`）ので、1 つのチャレンジに同時に 2 つの回答 — 複製したタブ、二重送信 — があっても適用されるのはちょうど 1 つで、もう一方には保留中の同意が無いと告げる。`/authorize` での同意ストアの障害は `temporarily_unavailable` であり、コードにもユーザーが対処できる拒否にもならない。オペレーターはレコードを削除して同意を取り消す（`consentStore.revoke(sub, clientId)`）。次にそのクライアントの `/authorize` が来たら改めて尋ねる。

ページが表示するものを登録すること: クライアントレコードの `clientName`（RFC 7591 `client_name`）と `clientUri`（`client_uri`）。ループバックの `redirect_uri` を持つネイティブクライアントは、MCP 認可仕様がページに警告を求めるケースである — `redirect_uri` が応答にあるのはまさにそのためである。

**Client ID Metadata Document のクライアントは自分で名乗る。** その `client_name` と `client_uri` は、ホストを支配する誰かが書いたドキュメントから来るので、"Google Drive" と名乗るのに何のコストも無い。唯一の検証済みの事実は `client_id` の URL が名指すホストで、応答はそれを `client_id_host` として運ぶ: ドラフトの求めるとおりそれを目立つように表示し、`client_name` を単独で見せないこと。`client_uri` のリンクがページ URL とそのチャレンジをそのホストに渡さないよう、ページは `Referrer-Policy: no-referrer`（または `strict-origin`）で配信すること。

## Client ID Metadata Documents (#529)

クライアントは自分の登録の `https` URL で自身を名乗れる — **Client ID Metadata Document**（[draft-ietf-oauth-client-id-metadata-document](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/)）。Dynamic Client Registration が非推奨になった MCP 認可仕様（2026-07-28）が、ホスト型クライアントの SHOULD とする登録モデルである。既定は無効: `oauth.clientIdMetadataDocuments.enabled = true`（`OAUTH_CIMD_ENABLED`）にすると、ディスカバリードキュメントは `token_endpoint_auth_methods_supported` に既に載せている `none` の隣に `client_id_metadata_document_supported: true` を広告する — MCP クライアントが選択の手掛かりにする 2 つのシグナルである。

`GET https://client.example/oauth/client-metadata.json` が登録である:

```json
{
  "client_id": "https://client.example/oauth/client-metadata.json",
  "client_name": "Acme Chat",
  "client_uri": "https://client.example",
  "redirect_uris": ["https://client.example/cb", "http://127.0.0.1/cb"],
  "grant_types": ["authorization_code", "refresh_token"],
  "scope": "read write"
}
```

サーバーがそれをどう扱うか:

- **同じ `client_id` の事前登録済みクライアントが優先される**。ドキュメントは取得しない。
- **URL はドキュメント URL でなければならない**: `https`、パスがあり、フラグメント・資格情報・ドットセグメント・クエリ文字列が無く、ホストはアドレスではなく名前で、ループバックではない。それ以外はクライアントではない。DNS ルートのドットで終わるホスト名（`client.example.`）は即座に拒否する: URL の正規化を生き延び、TLS はドット無しの証明書を受け入れるので、放置すると下記のホストリストに一致しない綴りになってしまう。オペレーターはホストをさらに絞れる（`allowedHosts`、完全一致か `.suffix`。`deniedHosts` が優先）。
- **ソケットを開く前に名前を解決し**、すべてのアドレスがパブリックでなければならない: RFC 6890 の特殊用途範囲 — クラウドのメタデータエンドポイント、プライベートネットワーク、このホスト — に入るものが 1 つでもあれば解決を拒否する。これがドラフトの要求する SSRF ガードである。チェックと接続の間のリバインディングはドラフトも受け入れる残余で、ホストリストがそれに対するレバーである。
- **取得**はリダイレクトに従わず（3xx はエラー）、タイムアウトし（`timeoutMs`）、`Content-Length` とストリームの両方でボディを上限で切り（`maxBytes`、既定 5 KB）、JSON の `200` だけを受け取る。有効なドキュメントは URL ごとに `Cache-Control: max-age` の間キャッシュし、`cacheMaxAgeMs` と `maxCacheEntries` で抑え、期限が来たら `ETag` で再検証する。クライアントのサーバーからの `5xx` や `429` は登録ではなく*相手の可用性*として読む — タイムアウトや DNS 障害と同じ経路を通る。`4xx` や拒否したリダイレクトは登録が無いか誤っているもので、拒否の経路を通る。拒否は*クライアントとして*キャッシュされることは無いが、`negativeCacheMs`（既定 1 分）の間は拒否として記憶されるので、でっち上げた `client_id` がリクエストのたびに DNS 解決とソケットを消費することは無い。このサーバーが既に検証した登録は、ドキュメント以外の理由 — DNS の揺れ、5xx、タイムアウト — で再検証に失敗しても `staleIfErrorMs` の間は提供を続ける。他者のサーバーの障害はクライアントへの判定ではないからである。一方、*拒否された*ドキュメントは即座に捨てる。`maxConcurrentFetches` はすべての ID にわたって同時に取得中のドキュメント数を抑える。同時の解決は 1 回の取得を共有する。拒否はすべて理由付きで `cimd_document_rejected` / `cimd_document_fetch_failed` / `cimd_host_not_allowed` をログに出す。
- **ドキュメント**は、URL と等しい `client_id`、このサーバーが登録時に受け入れる空でない `redirect_uris`（`/authorize` では完全一致、RFC 8252 §7.3 のループバックポートの例外付き）を持ち、`client_secret` を持たず、`token_endpoint_auth_method` は `none` 以外であってはならない — 共有秘密の方式はドラフトが禁じており、`private_key_jwt` は、鍵が攻撃者の書いた同じドキュメントから来るのでクライアントではなくドキュメントを認証することになるため拒否する（登録済みクライアントは使える — [`private_key_jwt`](#クライアント認証-private_key_jwt-rfc-7523-22) を参照）。`grant_types` は `authorization_code` を含み、`response_types` は `code` を許さなければならない。
- **それが成るクライアントは public でファーストパーティではない**（`tokenEndpointAuthMethod: none`、PKCE S256 必須、`firstParty: false`）ので、[同意のステップ](#サードパーティクライアントの同意-527)を通る — **同意ストアを配線しなければ機能は働かない**: それが無ければ `/authorize` はそのようなフローを完了できないので、ドキュメントは取得されず、URL の形をした `client_id` は単なる未知のクライアントになる（ディスカバリードキュメントが `client_id_metadata_document_supported` を出さないのも同じ理由） — そしてページはドキュメントの `client_name`、`client_uri` と `redirect_uri` を表示する。スコープはドキュメントの `scope` とオペレーターの `allowedScopes` の共通部分、audience はオペレーターの `allowedAudiences` — この認可サーバーが保護するリソースサーバーで、MCP クライアントは `resource` でそれを名指す。ドキュメントはクライアントが誰かを言うのであって、何に届いてよいかを言うのではない。

## イントロスペクション: 呼び出し元が問い合わせられるトークン

`POST /oauth/introspect` はまず呼び出し元を認証し（RFC 7662 §2.1 — public クライアントは拒否）、その呼び出し元が見てよいトークンについてだけ答える。応答はすべて `Cache-Control: no-store` を持ち、クライアント認証の拒否は RFC 6749 §5.2 の `{ error, error_description }`。

### audience の固定は `allowedAudiences` ∪ `{client_id}`

クライアント認証で呼び出し元が特定されたとき、トークンの `aud` は次のいずれかでなければならない:

- そのクライアントの登録済み `allowedAudiences` のエントリー、または
- そのクライアント自身の `client_id`。

これは発行するどのグラントも audience を導出する上限（`client_credentials`、`refresh_token`、`/authorize`）と同じなので、イントロスペクションは登録がこのクライアントとの関連を既に信頼した audience をちょうど受け入れ、それ以上は受け入れない。

この規則は RFC 8707 のリソースインジケーターを使い始めた瞬間に効いてくる。そのときすべてのアクセストークンは `aud: <resource URI>` を持つので、`client_id` だけに固定すると**リソースサーバーが自分のトークンをイントロスペクトできない** — リソース URI そのものである `client_id` で登録されていない限り `active: false` を受け取る。代わりにリソース URI を許可された audience として登録すること:

```jsonc
{
  "clientId": "orders-api",
  "tokenEndpointAuthMethod": "client_secret_basic",
  "allowedAudiences": ["https://api.example.com/orders"]
}
```

その集合の外の audience、未知または期限切れのトークン、jti の denylist かサブジェクトのウォーターマークで失効したトークン、別の issuer のトークンは、どれも `active: false` になる。**Bearer の自己イントロスペクション**経路 — ボディの `token` と同じ値を `Authorization: Bearer <token>` で送る — は呼び出し元クライアントの ID を確立しないので、固定する集合が無い。検証器は集合をでっち上げずに、その欠落を `jwt_verify_aud_skipped` として記録する。

### 予約文字を含む `client_id` は HTTP Basic でパーセントエンコードする

RFC 6749 §2.3.1 は、`id:secret` の組を `Authorization: Basic` ヘッダーへ base64 エンコードする**前に**、クライアント ID と秘密を `application/x-www-form-urlencoded` でエンコードすることを求めている。リソース URI はこれを細かい話ではなく必須にするケースである: `:` と `/` を含み、`:` はヘッダーを分割するフィールド区切りである。

```
# 誤り — 最初のコロンで分割されるので、クライアント ID は "https" と解釈される
Authorization: Basic base64("https://api.example.com/orders:s3cret")

# 正しい — 予約文字を先にパーセントエンコードする
Authorization: Basic base64("https%3A%2F%2Fapi.example.com%2Forders:s3cret")
```

`client_secret_post`（フォームボディの資格情報）ならこの問題自体が生じない — ボディのエンコードが既にそれを行う。

### 失効したファミリーと終了したセッション

- **リフレッシュトークンファミリー。** `family_id` を持つトークンは、`refreshTokenFamilyRevocation` が配線されていれば `isFamilyRevoked` で確認される: 失効済みのファミリーは `active: false` を返して `introspect.family_revoked` を出す。答えられないストアも `active: false` を返す（`introspect.store_unavailable` を出す）。RFC 7662 はこのエンドポイントに `temporarily_unavailable` を定義しておらず、inactive が唯一のフェイルクローズな答えだからである。`family_id` の無いトークンは署名と失効ストアだけで検証される。
- **セッションの生存。** `sid` クレームを持つトークンは `UserSessionStore` で確認される — `/oauth/userinfo` と同じ読み取り。ログアウトした・期限切れの・帯域外で削除されたセッションは `active: false` を返して `introspect.session_invalid` を出し、ストアの障害は `active: false` を返して `introspect.store_unavailable` を出す。`sid` の無いトークン（client credentials、jwt-bearer）はこの読み取りのコストを払わず、`userSessionStore` を配線しない構成も払わない。

これらは問い合わせる呼び出し元にしか効かない: JWT を署名と `exp` だけでオフライン検証するリソースサーバーは失効を見ず、期限まで受け入れ続ける。

## リボケーション

`POST /oauth/revoke` は RFC 7009。`/oauth/token` と同じく呼び出し元を認証し — public クライアントは自分のトークンを失効させてよいので（§2.1）それも含む — `token` が無ければ `400 invalid_request`、認識できない `token_type_hint` には `400 unsupported_token_type`、それ以外はトークンが存在したか・呼び出し元のものだったかに関係なく `200` を返す（§2.2）。トークンは発行先のクライアントに対してだけ失効される。

- **リフレッシュトークン**は `refreshTokenFamilyRevocation` でそのファミリーを失効させる。そのスロットが無ければリクエストは何もしない `200`。
- **アクセストークン**は、`oauth.revocation.accessToken` が `"denylist"` のとき `accessTokenDenylist` に追加される。`"unsupported"` のときは、`token_type_hint=access_token` に対して何も失効しない `200` ではなく `400 unsupported_token_type` を返し、ヒントの無いトークンはリフレッシュトークンの経路だけを通る。

ディスカバリーは、2 つのうち少なくとも一方が何かを失効できるときだけ `revocation_endpoint` を広告する。エンドポイントの完全な振る舞いは [`routes/revoke.mts`](./src/routes/revoke.mts) の doc コメントにある。

## Userinfo

```http
GET /oauth/userinfo
Authorization: Bearer <access_token>
```

OIDC Core §5.3。`GET` と `POST` で受け付ける。永続化された `UserSession` を元に、スコープで絞ったクレームを返す。

| 条件 | レスポンス |
| --- | --- |
| Bearer トークン未指定または形式不正 | `401`（`WWW-Authenticate: Bearer realm="userinfo"` 付き） |
| JWT 署名検証失敗 | `401 invalid_token` |
| トークンの `family_id` が失効済み | `401 invalid_token` |
| セッション未発見またはストアエラー | `401 invalid_token`（フェイルクローズ） |
| `userSessionStore` 未配線、または `sid` クレームなし | `200 { sub }`（sub のみ、永続クレームなし） |
| セッションがアクティブ | `200 { sub, ...スコープで絞ったクレーム }` |

すべてのレスポンスに `Cache-Control: no-store` と `Pragma: no-cache` を付ける（RFC 6750 §5.3）。

スコープ→クレームの対応（OIDC Core §5.4 の標準スコープ）。id_token と共通:

| スコープ | 出力されるクレーム |
| --- | --- |
| `openid` | *(id_token 発行の可否を決める。`sub` は userinfo レスポンスに常に含まれる)* |
| `profile` | `name`、`picture` |
| `email` | `email`、`email_verified` |
| `groups` | `groups` |

## トークンバインディング (`cnf`)

トークンバインディングの仕組み（`@o3co/auth-provider-dpop` と `@o3co/auth-provider-mtls` のいずれか、または両方）がインストールされていると、ここのグラントは RFC 7800 の `cnf` クレームを出し、イントロスペクトのハンドラーはそれをリソースサーバーへ返す。バインディングの契約と `Confirmation` の union は core のもの（[`confirmation.mts`](../core/src/grants/confirmation.mts)、[`confirmationMatch.mts`](../core/src/grants/confirmationMatch.mts)）。設計は [ADR 2026-05-20-token-binding-first-class-abstraction.md](../core/docs/adr/2026-05-20-token-binding-first-class-abstraction.md) にある。

### 発行

- **アクセストークンの `cnf` は仕組みに依存しない。** どのバインディングの `confirmation` もそのまま流れる — DPoP の `{ jkt }`、mTLS の `{ "x5t#S256" }`。
- **リフレッシュトークンの `cnf` は public クライアントには付け、confidential クライアントには要求があったときだけ付ける。** バインドされたアクセストークンを持つ public クライアントはバインドされたリフレッシュトークンを受け取り、次のリフレッシュが連続性を強制する。confidential クライアントはプレーンなリフレッシュトークンを受け取る — クライアント認証がリフレッシュ時の認証手段だからである（RFC 9449 §5、RFC 8705 §7.1） — ただし `oauth.tokenBinding.bindConfidentialClientRefreshTokens = true`（`OAUTH_TOKEN_BINDING_BIND_CONFIDENTIAL_CLIENT_REFRESH_TOKENS`）ならそれもバインドする。その代償は鍵のローテーションである: バインドされたリフレッシュトークンは、その有効期間全体にわたってクライアントを 1 つの鍵か証明書に固定する。
- **ワイヤー上の `token_type`:** `"DPoP"` は DPoP のバインディングのときだけ（RFC 9449 §5）。mTLS は `"Bearer"` のまま（RFC 8705 §3） — 証明書がバインディングの証拠であって、ワイヤー上のトークン型ではない。

### リフレッシュ時のマトリクス

refresh グラントは仕組みごと（DPoP の `cnf.jkt`、mTLS の `cnf.x5t#S256`）に core の `matchConfirmation` を 1 回ずつ評価する。どちらも同じ 5 つの結果を持つ:

| リフレッシュトークンの `cnf` | リクエストのバインディング | 結果 |
| --- | --- | --- |
| プレーン | なし | プレーンな Bearer を発行 |
| プレーン | あり | オプトインのアップグレード — 新しいアクセストークンをバインドする（リフレッシュトークンは上の発行規則に従う） |
| バインド済み | なし | `invalid_grant` で拒否 |
| バインド済み | あり、不一致 | `invalid_grant` で拒否（複数鍵 / 証明書差し替え攻撃） |
| バインド済み | あり、一致 | ローテーションでバインディングを保持 |

`cnf` のメンバーはそれ自身の仕組みに対してだけ尊重されるので、confirmation の形だけではバインドされたリフレッシュトークンを満たせない。`cnf.jkt` と `cnf.x5t#S256` の**両方**を持つリフレッシュトークンは、どちらのマトリクスも走らせる前に `invalid_grant` で拒否される。

### イントロスペクト

`/oauth/introspect` はアクセストークンから `cnf` を読み、`jkt` があれば `token_type` を `"DPoP"`、そうでなければ `"Bearer"`（mTLS かバインドなし）にする。応答は `cnf` をそのまま運ぶので、リソースサーバーは自分の境界で正しい仕組みの証明を要求できる。

## ログアウト

OIDC のログアウトエンドポイントは、セッションカスケードの 6 スロットがすべて配線されたときにマウントされる（[エンドポイント](#エンドポイント)を参照）。

> **3 つ目のログアウトエンドポイントがあり、それはこのパッケージには無い。**
> `POST /session/logout`（`@o3co/auth-provider-session`）はブラウザー自身の
> ログアウトで、BFF / `auth.proxy` 構成が呼ぶものである。`UserSession` レコード、
> サブジェクトのインデックスエントリー、フェデレーションの組を削除する — したがって
> この README の他の箇所にある生存確認は効く — が、`cascadeLogout` にはパッケージの
> 境界を越えて届かないので、**リフレッシュトークンファミリーは 1 つも失効させない**。
> 完全なカスケードを走らせるのは `POST /oauth/logout` だけである。セッションが
> リフレッシュトークンを持つなら、呼ぶべきはこちらである。
> [session パッケージの README](../session/README.md#what-post-sessionlogout-invalidates) を参照。

### `POST /oauth/logout` と `GET /oauth/logout`

OIDC RP-Initiated Logout 1.0 の `end_session_endpoint`。パラメーター（`POST` は `application/x-www-form-urlencoded`、`GET` はクエリ）:

- `id_token_hint`（必須） — このプロバイダーが発行した署名済み id_token。その `sid` クレームがセッションを特定する
- `post_logout_redirect_uri`（任意） — `client.postLogoutRedirectUris` のいずれかと**バイト単位で完全一致**しなければならない。逆ドメインのカスタムスキームは正当なエントリーだが、それだからといって緩和はされない。
- `state`（任意） — `post_logout_redirect_uri` へのリダイレクト時にそのまま返す

`id_token_hint` の発行から 24 時間を超えた `GET` には、ログアウトする代わりに確認ページを返す。そのフォームはヒントと `state` をこのエンドポイントへ POST で送り返し、`post_logout_redirect_uri` はクライアントのアローリストにある場合だけ送り返す。

フロー: `id_token_hint` を検証 → セッションを読む → `backchannelLogoutUri` を持つすべての RP に OIDC Back-Channel Logout 1.0 の `logout_token` を送る（ベストエフォート。POST の失敗はログアウトを止めない） → ストアカスケードを実行 → 次のいずれかで応答:

- `frontchannelLogoutUri` を持つ RP ごとの `<iframe>` を含む `text/html` ページ（q 値付きネゴシエーションで `Accept: text/html` が勝った場合）
- 最初のフェデレーションの IdP end-session URL への `303`（そのフェデレーションのプロバイダーが `SupportsLogout` を実装している場合）
- `post_logout_redirect_uri` への `303`（クライアントのアローリストに一致する場合）
- `200 {"logged_out": true}`（フォールバック）

**カスケード**は [`cascadeLogout`](./src/logout/cascadeLogout.mts) で、決まった順序の 4 ステップからなる。その doc コメントが完全な契約で、[`cascadeLogout.test.mts`](./src/logout/__tests__/cascadeLogout.test.mts) がそれを固定している:

1. セッションのリフレッシュトークンファミリーを読む。失敗したらカスケードはそこで止まる。
2. すべてのファミリーを失効させ、セッションのフェデレーショントークンを削除する。すべての操作を試み、**どれか 1 つでも**失敗すれば、再試行に必要な記録が消される前にカスケードはここで止まる。
3. セッションの逆引きインデックスのエントリー（RP、ファミリー、フェデレーション）を削除する — ベストエフォートで、ログに出し、TTL で上限がある。
4. 最後に `UserSession` を削除する。失敗したらカスケードはそこで止まる。

止まったカスケードは `503 {"error": "temporarily_unavailable"}` を返し、同じログアウトの再試行は安全である。

成功時のどの形でも — そして既に無くなっているセッションへの何もしない応答でも — エンドポイントは**ブラウザー自身の express-session も終わらせる**。ただしそのセッションの `sid` がログアウト対象のものであるときだけである。RP-Initiated Logout は誰でもどのセッションについても行えるリクエストなので、別の `sid` を名指す Cookie や何も名指さない Cookie は、無関係なユーザーをサインアウトさせないよう手を付けない。これが無いと、ストアが空になった後も Cookie が `/authorize` で `req.session.isAuthenticated` を満たし続ける。セッションストアが完了できない破棄はログに出し、成功したカスケードを `503` にはしない。`/authorize` はいずれにせよ自分の判断で死んだ `sid` を拒否する（[OIDC の対応範囲](#oidc-の対応範囲-284)を参照）。`503` は意図して Cookie を残すので、再試行は引き続きそのセッションを名指せる。

### `POST /oauth/federation/:name/logout`

プロバイダー単位のフェデレーション切断。Authorization に `typ: at+jwt` の `Bearer <access_token>`。ボディ（任意）: `post_logout_redirect_uri`、`state`。

フロー: アクセストークンを検証 → そのファミリーが失効していないか確認 → セッションを読む → フェデレーションが紐付いていることを確認 → フェデレーショントークンを削除 → セッションからフェデレーションを削除 → プロバイダーが `SupportsLogout` を実装していれば IdP の end-session URL へリダイレクト。そうでなければ `200 {"disconnected": true}` を返す。

IdP の end-session 呼び出しが例外を投げた場合、ローカルの状態は既にクリア済みなので、応答は `200 {"disconnected": true}` で、オペレーター向けに監査イベント `federation.logout.idp_unreachable` を出す。

指定のフェデレーションがセッションに無ければ `404 {"error": "federation_not_linked"}` を返す。

### ディスカバリーメタデータ

同じ 6 スロットのチェックのもとで、`GET /.well-known/openid-configuration` は次を広告する:

- `end_session_endpoint`
- `backchannel_logout_supported: true`
- `backchannel_logout_session_supported: true` — 既定で `logout_token` に `sid` を含む
- `frontchannel_logout_supported: true`
- `frontchannel_logout_session_supported: true` — 既定でフロントチャネルの iframe URL に `sid` を含む

`session_supported` の既定 `true` は OIDC Back-Channel Logout 1.0 §2.2 の仕様の既定（`false`）から意図的に外れている。仕様の既定の振る舞いが必要なクライアントは、クライアントレコードで `backchannelLogoutSessionRequired: false` または `frontchannelLogoutSessionRequired: false` を設定すること。

### クライアントレコードのログアウトメタデータ

フィールドは core の `Client` レコード（[`repositories/types.mts`](../core/src/repositories/types.mts)）に定義されている。このパッケージがそれらに課すこと:

- `postLogoutRedirectUris` — `post_logout_redirect_uri` のアローリスト。**`allowedRedirectUris` と同じ文法**で検証される（#498）: `https:`、ループバックホストの `http:`、または RFC 8252 §7.1 の逆ドメイン形式のカスタムスキーム（`com.example.app:/signout`）で、フラグメント・userinfo・実行可能スキームは決して許さない。カスタムスキームを登録できることが、ネイティブアプリをログアウト後に JSON ボディに着地させずにアプリ自身へ戻せる条件になる。
- `backchannelLogoutUri` — `logout_token` の POST を受け取る。**`http`/`https` のみ** — このサーバー自身が POST するので、カスタムスキームには届けられない。
- `frontchannelLogoutUri` — iframe の src。**`http`/`https` のみ** — ブラウザーはこの値をドキュメントのコンテキストで解決し、そこではカスタムスキームはよくて無効、悪ければ RP が頼んでもいないハンドラーの起動になる。
- `backchannelLogoutSessionRequired` / `frontchannelLogoutSessionRequired` — 既定 `true`。`false` にすると `logout_token` / iframe URL から `sid` を除く。

## フェデレーショントークンエンドポイント

`POST /oauth/federation/:name/token` は呼び出し元のセッションに紐付いた上流 IdP のアクセストークンを取り出す。これにより利用者は、ユーザーの代わりに Google Calendar / GitHub API などへサーバーサイドの API 呼び出しを行える。6 スロットのチェックのもとでマウントされる（[エンドポイント](#エンドポイント)を参照）。オフライン委譲 — ユーザーのセッション無しのトークン — は別の機能で、`@o3co/auth-provider-federation-grants` である。

### 認証

- この auth.provider インスタンスが発行した Bearer アクセストークン（`typ: at+jwt`）。
- トークンの `azp` クレームがクライアントを特定する。クライアントレコードは `allowedAzpForFederationToken: true` で明示的にオプトインしなければならない（下記参照）。

### フロー

1. Bearer アクセストークンを検証する。
2. そのファミリーが失効済みか、セッションがもう存在しなければ拒否する。
3. `client.allowedAzpForFederationToken === true` でなければ拒否する。
4. フェデレーションがセッションに紐付いていなければ拒否する。
5. 保存済みの上流アクセストークンの有効期間が 30 秒を超えて残っていれば、それを返す。
6. そうでなければリフレッシュする:
   - 同時リフレッシュのファンアウトを防ぐため advisory lock を取得する（`FederationTokenStore` が `SupportsLock` を実装している場合）。
   - ロック取得後に再読み込みする — 待機中に別のウェイターがリフレッシュしたかもしれない。
   - `provider.refreshToken(refreshToken)` を呼び、結果を永続化する。
   - ロックを解放する。

### レスポンス

```json
{
  "access_token": "<upstream-IdP-access-token>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "<コネクションが保持するもの>"
}
```

`token_type` は常に `Bearer` で、渡すのは bearer トークンだけである。IANA の
Access Token Types レジストリにある他の名前は、sender-constrained（`PoP`
(RFC 9200)、`DPoP` (RFC 9449) — 提示には鍵の所有証明が要り、値渡しで受け取った
呼び出し元はその鍵を持たない）か、そもそもアクセストークンの型ではない（`N_A`、
RFC 8693 §2.2.1）かのどちらかである。このエンドポイントはそれを渡さず
`502 upstream_token_ineligible` を返す。オフライン委譲のルートで `core` が同じ契約に
対して下している判断と同じである。

上流自身の綴りは保存レコードに残る — 監査イベントが報告するのもオペレーターが
読むのもそれ — が、ワイヤー上では返さない。非 bearer を拒否した後に残る値は
一語の大文字小文字違いだけであり、RFC 6749 §5.1 が比較を大文字小文字非依存と
定めている（"Value is case insensitive"）以上、綴りは呼び出し元が行動できる
情報を運ばない。そのまま返せば、`federation-oidc` のコネクションが上流の答え
次第で `Bearer` と `bearer` の間を行き来するだけである。兄弟のオフライン委譲の
ルートは意図してそのまま返している。

アダプターが型を**まったく**名乗らないコネクションには `Bearer` を返す: §5.1 は
このフィールドを REQUIRED としているので、フィールドの不在は上流が別の意味を
込めたのではなく、それを報告しないアダプター — このフィールド以前に書かれた
サードパーティのアダプター、または同梱アダプターが型を報告するようになる前に
リンクされたレコード — を意味する。同梱アダプターはすべて、core の
`federationTokenSnapshot` を通じて上流が送った型を報告する。

そう扱うのは「不在」だけである。保存値が bearer の綴りでなければ、それが
`"DPoP "` でも `""` でも `null` でも数値でも拒否する — ストアもこのルートが所有
していないものの一つであり、壊れたレコードを沈黙と読めばそれに `Bearer` を返して
しまうため。反対側では、アダプターが文字列でない値を名乗った場合は落とさず `""`
として記録する — 拒否する対象を残すため。

`scope` は保存されたコネクションが保持するもので、フェデレーションを紐付けたときに
記録される。その時点でユーザーが同意したものが上限なので、リフレッシュはそれを
狭めることも付与まで戻すこともできるが、それを超えることは決して無い。

述べておくべき帰結が 1 つある: 狭めた後、以降のリフレッシュで何も言わない上流は、
このフィールドがトークンの保持する以上を主張したままにする。これは意図的である —
逆にすると最初の狭まりが恒久化する — し、同意が上限になっている。`scope` を読んで
ユーザーを同意に送り返すかどうかを決めるクライアントは、それを保証ではなく上限と
して扱うこと。

### フェデレーショントークンストアに求めること

ストアの契約は core の `FederationTokenStore` と `FederationTokens`（[`federation-tokens/types.mts`](../core/src/federation-tokens/types.mts)）である。レコードのすべてのフィールドは必須キーで、ストアを実装する・呼ぶ人向けには [Upgrading: store records name every field](../../docs/upgrading-required-record-keys.md) が説明している。このルートが依存すること:

- **すべてのフィールドが `attach`、`update`、`get` を通して保たれること。** `tokenType` を失うと**開いたまま**失敗する: レコードが沈黙して返り、沈黙は `Bearer` と読まれ、sender-constrained なトークンが Bearer として渡される。`refreshToken` を失うとコネクションはリフレッシュできなくなり（`410 refresh_token_absent`）、`idToken` を失うとログアウトで上流の `id_token_hint` が落ち、`grantedScope` を失うと現在のスコープがリフレッシュの上限になる（過小に報告する）。
- **アダプター独自の保存形式もすべてのフィールドを名指すこと。** 必須キーが届くのは `FederationTokens` までで、アダプターがそれを変換する行やドキュメントには届かない: その形式にも同じ必須キーを宣言すること — 同梱の Redis ストアは envelope でそうしている — さもなければ変換がフィールドを落としたままコンパイルが通る。
- **未設定の値は `undefined` か不在で返し、決して `null` にしないこと。** このルートは保存された `null` を拒否するので、`undefined` を `null` として書くシリアライザー — MongoDB のドライバーは `ignoreUndefined` を設定しない限りそうする — では、型を名乗らないアダプターのコネクションがすべて `502` になる。同梱の Redis コーデックは `null` を含むレコードを拒否する。

同梱の 2 つのストアはこれらを満たし、テストで固定されている。

### エラーレスポンス

| ステータス | エラー | 意味 |
| --- | --- | --- |
| 401 | `invalid_token` | Bearer 未指定・不正・型が `at+jwt` でない・ファミリーが失効済み |
| 403 | `forbidden` | クライアントが `allowedAzpForFederationToken` でオプトインしていない |
| 404 | `federation_not_linked` | 指定のフェデレーションがこのセッションに紐付いていない |
| 410 | `refresh_token_absent` | 保存済みトークンにリフレッシュトークンが無い（ログイン時に上流が返さなかった、またはロック後の再読み込みでそれの無いレコードが見つかった） |
| 410 | `re_authentication_required` | IdP が `invalid_grant` / `invalid_token` を返した — セッションのフェデレーションはクリアされる。ユーザーは IdP で再認証が必要 |
| 429 | `rate_limited` | 上流 IdP のレート制限超過（`status: 429` または `error: "too_many_requests"`）。後で再試行する |
| 500 | `refresh_failed` | IdP リフレッシュ経路の分類できないエラー、またはこのルートが読めない応答。SIEM は監査の `details.reason` フィールドでグループ化すること |
| 502 | `upstream_token_ineligible` | 上流のトークンがこのプロバイダーの渡せないもの。理由は `error_description` が名乗る — `token_type_unsupported` だけである。`Retry-After: 300` を付ける |
| 503 | `refresh_not_supported` | プロバイダーが `SupportsRefresh` を実装していない |
| 503 | `lock_timeout` | 待機ウィンドウ内に advisory lock を取得できなかった |
| 503 | `temporarily_unavailable` | ストア障害、IdP の 5xx、または上流のネットワーク障害（ECONNREFUSED / ENOTFOUND / ETIMEDOUT — fetch の TypeError の `error.cause.code` に包まれたコードを含む） |

すべてのエラーレスポンスに `Cache-Control: no-store` と `Pragma: no-cache` を付ける。401 レスポンスには RFC 6750 に従い `WWW-Authenticate: Bearer error="invalid_token"` を含める。

### Opt-in: `allowedAzpForFederationToken`

各 `Client` は任意の `allowedAzpForFederationToken: boolean` フラグを持つ。既定は `false` — クライアントは自動的にはフェデレーショントークンへのアクセスを得ない。必要なクライアントにはオペレーターが明示的にオプトインする:

```yaml
clients:
  - clientId: my-backend-api
    clientSecret: ...
    allowedRedirectUris: [...]
    allowedScopes: [openid, profile, email]
    allowedAzpForFederationToken: true  # explicit opt-in
```

設計の意図: フェデレーションのアクセストークンはユーザーの外部リソース（Google Drive、GitHub API など）へのアクセスを与える。認証だけが目的の一般的な OAuth クライアント登録で誤って露出しないよう、既定で拒否する。

### 監査イベント

- `federation.token.success` — トークン発行時（詳細の `refreshed: boolean` で保存済みトークンかリフレッシュ経路かを区別する）
- `federation.token.forbidden` — 403 のとき（クライアントがオプトインしていない）
- `federation.token.family_revoked` — ファミリー失効による 401 のとき
- `federation.token.refresh_failed` — 500 `refresh_failed` のとき。ケースは 2 つ。`provider.refreshToken` がリフレッシュエラーの分類器で分類できないエラーを投げた場合: `details.reason` は `"unknown"`。または応答は返ったがこのルートが使えない場合: `"no_access_token"`・`"invalid_expiry"`・`"invalid_token_type"`。このイベントが持つ値はこの 4 つですべてで、SIEM のルールはこれでグループ化すること。分類器の残りの結果はこのイベントに**ならない**: `invalid_grant` は `federation.token.reauthentication_required`（410）、`rate_limited`（429）と `network`（503）は監査イベントを出さない。
- `federation.token.reauthentication_required` — IdP から `invalid_grant` または `invalid_token` を受け取ったとき
- `federation.token.upstream_ineligible` — 502 のとき。`details.reason` は `"token_type_unsupported"`、`details.tokenType` はレコードが保持していた値を読んだまま — トークン型として不正な値もそのまま。それこそ見る価値がある。`null` はレコードが文字列ですらないものを保持していたことを意味する。レスポンスには `Retry-After: 300` を付ける — `federationGrants.ineligibleRetryAfter` の既定値と同じで、この状態はオペレーターが上流の登録を変えるまで終わらないため。呼び出し元にはどの型だったかは伝えない — 再試行以外にできることが無いため

## jwt-bearer: 信頼する発行者 (#525)

RFC 7523 のグラント（`urn:ietf:params:oauth:grant-type:jwt-bearer`）は、このデプロイが信頼する発行者の署名付きアサーションを受け付け、検証済みのハンドルを Store に渡す（`userRepository.authenticateByToken`）。リフレッシュトークンは発行しない。

**`/oauth/token` 経由では、どのリクエストもクライアントを持つ。** クライアント認証は public クライアント（`tokenEndpointAuthMethod: "none"`）を `client_id` だけで受け入れ — 署名付きアサーションを持つデバイスはこれに当たる — クライアントがまったく無いリクエストは拒否する（`401 invalid_client`）。そのクライアントの `allowedGrantTypes` はこのグラントを名指していなければならない。グラント自体は、RFC 7523 §3 がクライアント認証を任意としているので、クライアント ID の無いリクエストも受け付ける。それはクライアント認証ミドルウェア無しでグラントを振り分ける構成からしか届かず、下の「認証済みクライアントが無い」場合の規則はそれを指す。`userRepository` か `assertionVerifier` の無い状態で有効にすると boot が失敗する: 既定の検証器は無い。あり得る唯一の既定は何でも受け入れてしまうからである。

どの発行者を、どの鍵で、どの条件で信頼するかは、発行者エントリーの**信頼レジストリ**である — 書くときは `AssertionIssuerEntryInput`、レジストリが答えるときは `AssertionIssuerEntry` — そして同梱の検証器はその上に組まれている:

```ts
import {
  createMemoryAssertionIssuerRegistry,
  createRegistryAssertionVerifier,
} from "@o3co/auth-provider-core";

const registry = createMemoryAssertionIssuerRegistry([
  {
    issuer: "https://devices.example",
    keys: { type: "jwks_uri", uri: "https://devices.example/.well-known/jwks.json" },
    algorithms: ["EdDSA"],
    allowedClients: ["mobile-app"],           // who may present its assertions
    allowedScopes: ["read", "write"],         // ceiling on the issued scope
    allowedAudiences: ["https://api.example"], // ceiling on the issued aud
  },
  {
    issuer: "https://legacy.example",
    keys: { type: "key", key: legacyPublicKey },
    algorithms: ["ES256"],
    expiresAt: new Date("2026-12-31T00:00:00Z"),
  },
]);

const assertionVerifier = createRegistryAssertionVerifier({
  registry,
  audience: ["https://auth.example", "https://auth.example/oauth/token"], // what the assertion's aud must name
});
```

エントリーが言うことと、それが `/oauth/token` で意味すること:

- **鍵**は、1 つの公開鍵（`type: "key"`）、静的な JWK セット（`type: "jwks"`）、または JWKS エンドポイント（`type: "jwks_uri"`、ループバック以外では `https` 必須）から来る。リモートのセットは初回使用時に取得してキャッシュし（既定 10 分。エントリーの `cacheMaxAgeMs`、`cooldownMs`、`timeoutMs` で調整）、未知の `kid` は再取得を起こすので、発行者側のローテーションは再起動無しで拾われる。取得には検証器の `fetch` オプションがあればそれ — エグレスプロキシ — を使い、`private_key_jwt` クライアントの `jwksUri` と同じである。どちらも core の `createRemoteKeySetCache`。エンドポイントが落ちていれば障害である: グラントは `invalid_grant` ではなく `503` を返す。
- **登録されていない `iss` は署名の処理より前に拒否される。** 誰も登録していない発行者については、鍵も取得せず署名も確認しない。「A が署名し、B を名乗る」ものは B の鍵で失敗する。
- **`allowedClients`** は発行者のアサーションを提示してよい者を制限する。リストがあれば未認証の提示者は拒否される。無ければ誰でもよい。
- **`allowedScopes`** はアサーション自身の `scope` クレームとの共通部分をとり（アサーションが何も名指さなければ単独で）、リクエストとクライアント登録がさらに絞るスコープの上限になる。
- **`allowedAudiences`** は、何が選んだかに関係なく発行される `aud` を抑える — `grantPolicy`、RFC 8707 の `resource`、クライアント登録（その `allowedAudiences` を発行者のものに絞ったもの、クライアント ID は発行者が認める場合だけ）。認証済みクライアントが無ければそれがソースにもなる: トークンはこのサーバーではなく発行者の最初の audience を名指す。共通の audience を 1 つも認めないクライアントと発行者の組は `invalid_grant` で、`jwt_bearer_issuer_audience_mismatch` をログに出す。
- **`expiresAt`** はその場で変わる唯一のフィールドで（`registry.setExpiresAt`）、それ以外は不変 — 削除して追加し直す — なので、何を信頼してきたかの履歴は追加と削除の履歴である。`add`、`list`、`remove` が管理面の残りである。**メモリーのレジストリではその管理面は 1 プロセスにしか届かない:** あるレプリカで `setExpiresAt` によって失効させた発行者は他のレプリカでは信頼されたままで、再起動は構成のエントリーからレジストリを組み直し — 失効させた場所でも発行者を復活させる — しかも `deployment.mode = "multi"` はそれを捕まえられない。レジストリはモジュール上ではなく、渡した `assertionVerifier` の内側にあるからである。レジストリ構築時に与えたエントリーはどこでも同一である。複数レプリカではエントリーのリストを変えて再デプロイするか、共有ストアの上にレジストリを実装すること。

`createJwtAssertionVerifier({ key, issuer, audience, algorithms })` — 静的な 1 鍵の形 — はエントリー 1 つのレジストリである。実行時に発行者を登録し、再起動を越えて残す必要があるデプロイは、自前のストアの上に `AssertionIssuerRegistry`（`findIssuer`）を実装する。**エントリーはストアが保持できるデータ**である: どのフィールドも JSON の往復を生き延びる（`expiresAt` は `Date` に戻す）が、`keys: { type: "key" }` は生きた鍵オブジェクトなので例外 — ストアに置くエントリーは `jwks`（1 鍵のセットでよい）か `jwks_uri` を使う。

ストアに置くレジストリは、与えられた**すべての上限**を返さなければならない。`issuer`、`keys`、`algorithms` 以外の各フィールドは発行者のアサーションが得られるものを狭めるので、どれかを忘れる読み戻しは**開いたまま**失敗する: `allowedClients` が消えれば任意の提示者を認め、`expiresAt` が消えれば発行者を永久に信頼し、`profile: "id-jag"` が消えれば `jti` のリプレイ・`typ`・`aud` の完全一致のチェックが落ちる。したがって `findIssuer` は、すべてのフィールドが**必須キー**（エントリーが上限を名指さなければ `undefined`）の `AssertionIssuerEntry` で答える。呼び出し元が書くもの — 構成のリストと `add` — は `AssertionIssuerEntryInput` のままで、不在は「上限なし」を意味する。ストアに置くレジストリは:

- **書き込み時**に `checkAssertionIssuerEntry` で検証し、`toAssertionIssuerEntry(input)` で正規化し、すべてのフィールドを永続化する — 自前の行の型もすべてのキーを必須として宣言すること。さもなければそこへの書き込みがどれかを忘れ得る;
- **読み込み時**にすべてのフィールドを名指す `AssertionIssuerEntry` のオブジェクトリテラルを組み立てる。型が検査するのはそのリテラルである: キーを忘れればコンパイルが失敗する。行を `toAssertionIssuerEntry` に通しても*そうはならない* — それは入力の型をとり、そこではどの上限も任意だからである。

型は素の JavaScript のレジストリ、`as AssertionIssuerEntry` / `JSON.parse(row) as …` のキャスト、`jwks_uri` の鍵ソースの任意の調整値（`cacheMaxAgeMs` を失うと 10 分の既定に戻る）には届かない。それらは規則だけで守る。[Upgrading: store records name every field](../../docs/upgrading-required-record-keys.md) も参照。

クレームをどう読むかはコードなので、エントリーではなく検証器のものである。複数の発行者がいるなら、どの発行者の `sub` の値も互いに素だと分かっていない限りハンドルに名前空間を付けること — Store が受け取るのはハンドルだけである:

```ts
const assertionVerifier = createRegistryAssertionVerifier({
  registry,
  audience: "https://auth.example",
  readersFor: (entry) =>
    entry.profile === "id-jag"
      ? undefined // keep the ID-JAG default, <iss>#<tenant>#<sub>
      : {
          readSubjectHandle: (claims) =>
            typeof claims.sub === "string" && claims.sub.length > 0
              ? `${entry.issuer}#${claims.sub}`
              : null, // never namespace a missing or empty sub
        },
});
```

`readersFor` は ID-JAG のものも含めてすべてのエントリーについて走るので、既定が正しい答えである場合は `undefined` を返すこと。

`readSubjectHandle` や `readScope` を自分で持つエントリーは、リーダーを黙って無視されるのではなく、登録時に拒否される。

### ID-JAG プロファイル (#526)

`profile: "id-jag"` のエントリーは [Identity Assertion JWT Authorization Grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/) を受け付ける — エンタープライズの IdP がクライアントのために発行し、リソースの認可サーバーであるこのサーバーがそのクライアントにアクセストークンを発行できるようにするもの（MCP の "Enterprise Managed Authorization" フロー、Cross-App Access）。クライアントはそれを通常の jwt-bearer リクエストとして、**クライアント認証付きで**送る:

```ts
const assertionVerifier = createRegistryAssertionVerifier({
  registry: createMemoryAssertionIssuerRegistry([
    {
      issuer: "https://idp.example",
      keys: { type: "jwks_uri", uri: "https://idp.example/.well-known/jwks.json" },
      algorithms: ["RS256"],
      profile: "id-jag",
      allowedClients: ["mcp-client"],
      allowedScopes: ["read", "write"],
      allowedAudiences: ["https://mcp.example"],
    },
  ]),
  audience: "https://auth.example",
  issuerIdentifier: "https://auth.example", // the only aud an ID-JAG may name
  replaySeenSet,                             // each jti is accepted once
});
```

レジストリのチェックに加えて、ID-JAG は `typ: oauth-id-jag+jwt`、このサーバーの issuer 識別子とちょうど等しい `aud`（トークンエンドポイントの URL は別名にならない）、認証済みクライアントを名指す `client_id`（未認証の提示者は拒否）、そして `jti`、`iat`、`sub` を持たなければならない — `iat` は `private_key_jwt` と同じく 1 時間以内。各 `jti` はアサーションの有効期間中に 1 回だけ受け付ける。`scope` と `resource` はクレームとして運ばれる: スコープの上限はクレーム ∩ `allowedScopes`、audience の上限は `resource` ∩ `allowedAudiences`（エントリーが認めないリソースは拒否）で、グラントはさらにその両方をクライアントの登録で抑える。Store に渡すハンドルは `<iss>#<sub>`（または `<iss>#<tenant>#<sub>`） — `sub` は発行者の中でしか一意でない — で、Store が紐付けていない ID はそこで拒否される。リフレッシュトークンは発行しない: アサーションがリフレッシュの仕組みであり、アクセストークンはそれより長く生きない（下記）。

### 発行するトークンはアサーションより長く生きない

アクセストークンの有効期間は `min(oauth.accessToken.defaultExpiresIn, exp − now)`: `exp` は検証済みアサーションのもので、検証器が `expiresAt`（エポック秒）として報告し、残りはトークンを発行する瞬間に秒単位へ切り捨てる。応答の `expires_in` はその発行された有効期間である。これは token exchange がサブジェクトトークンに適用する規則（[security note 16](../oauth-token-exchange/README.md#security-notes)）と同じで、RFC 7523 でも ID-JAG でも、すべての jwt-bearer リクエストに成り立つ:

- **短命なアサーションからは短命なアクセストークンが生まれる。** ID-JAG の `iat` は最大 1 時間前までで、IdP は一般に数分の有効期間しか与えない。そこから交換したトークンもそれより長くは生きない。リフレッシュトークンは発行されないので、トークンが期限切れになったらクライアントは**新しいアサーションで交換し直す**。同じ ID-JAG を再び提示することはできない — 各 `jti` は 1 回しか受け付けない。
- **1 秒も残っていないアサーションは拒否される**（`invalid_grant` / `assertion did not verify` — 検証に失敗したすべての応答と同じ答えなので、その背後のハンドルについて呼び出し元に何も伝えない）。オペレーター向けには `jwt_bearer_assertion_expired` としてログに出す。これは `exp` を過ぎていても、エントリーの `clockToleranceSeconds`（既定 60）によって検証は通ってしまうアサーションも含む: 許容は検証の際の時計のずれを吸収するが、トークンが引き継ぐ有効期間は残さない。1 つの発行者からこの行が定常的に出るなら、このサーバーと時計がずれているか、クライアントが最後の瞬間にアサーションを提示している。
- **独自の `AssertionVerifier` は**、資格情報に期限がある限り **`expiresAt` を報告する**。このフィールドは任意だが、省略すると**期限の無い**資格情報を主張することになり、設定した有効期間が上限無しで適用される。あるなら有限の数値でなければならない: 数値の文字列、`null`、`NaN`、`Infinity` は期限としても期限なしとしても読まず、`invalid_grant` で拒否する。`createRegistryAssertionVerifier` と `createJwtAssertionVerifier` は、自分が要求する `exp` から常にそれを報告する。

## テスト

上に述べた不変条件は、それを実装している場所で固定されている。出発点として:

- モジュールの配線と各モジュールの宣言 — [`module.test.mts`](./src/__tests__/module.test.mts)、[`oauthAuthorization.test.mts`](./src/__tests__/oauthAuthorization.test.mts)、[`oauthSession.test.mts`](./src/__tests__/oauthSession.test.mts)、[`subjectRevocationService.module.test.mts`](./src/logout/__tests__/subjectRevocationService.module.test.mts);
- ディスカバリーのゲート — [`discovery-contribution.test.mts`](./src/__tests__/discovery-contribution.test.mts);
- ログアウトカスケードの順序と失敗の扱い — [`cascadeLogout.test.mts`](./src/logout/__tests__/cascadeLogout.test.mts)、エンドポイント — [`logout.test.mts`](./src/__tests__/logout.test.mts);
- イントロスペクションの audience 固定、セッション生存、障害時の答え — [`introspect.audience.test.mts`](./src/__tests__/introspect.audience.test.mts)、[`introspect.sessionLiveness.test.mts`](./src/__tests__/introspect.sessionLiveness.test.mts)、[`introspect.revocationOutage.test.mts`](./src/__tests__/introspect.revocationOutage.test.mts);
- クライアント認証 — [`clientAuth.test.mts`](./src/middleware/__tests__/clientAuth.test.mts)、[`clientAssertion.test.mts`](./src/middleware/__tests__/clientAssertion.test.mts);
- federation token ルート — [`federationToken.test.mts`](./src/__tests__/federationToken.test.mts)。

## 関連

- [`@o3co/auth-provider-core`](../core/README.ja.md) — このパッケージが土台にするポート・レコード・トークンの基本部品（`Module`、`GrantHandlerResolver`、`ClientRepository`、`CodeRepository`、`KeyStore`）
- [`@o3co/auth-provider-session`](../session/README.ja.md) — ログイン、ブラウザーセッション、フェデレーションのログインルート
- [`@o3co/auth-provider-oauth-token-exchange`](../oauth-token-exchange/README.md)、[`@o3co/auth-provider-device-grant`](../device-grant/README.md)、[`@o3co/auth-provider-webauthn`](../webauthn/README.md) — `/oauth/token` に提供されるグラント
- [`@o3co/auth-provider-federation-grants`](../federation-grants/README.md) — 上流トークンのオフライン委譲
