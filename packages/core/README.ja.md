# @o3co/auth-provider-core

最終更新: 2026-09-30

## 責務と役割

`@o3co/auth-provider-core` は、auth.provider の他のすべてのパッケージが土台にするパッケージです: モジュールシステムと boot planner（`createApp`）、グラントハンドラーの契約と全グラントがトークン発行に使うヘルパー、リポジトリ・ストアのポートと単一レプリカ向けのインプロセスアダプター、キーストア、設定スキーマを持ちます。他のすべてのパッケージの下に位置し、そのどれも import しません。独立したパッケージである理由はここにあります: 複数のパッケージが共有する契約はここに置かれます。それらのパッケージがすべて互いに依存しているわけではない — `session` と `oauth` は独立しており、`oauth-token-exchange` と `webauthn` は `oauth` に依存せずにグラントを実装する — ので、全員が依存する場所は core だけだからです。

グラントタイプと `/oauth/*` エンドポイント（`@o3co/auth-provider-oauth` と各グラントパッケージ）は持ちません: core が自分でマウントするルートは discovery ドキュメントだけで、JWKS、health、readiness のルーターは composition root が組み込みます。永続アダプター（`@o3co/auth-provider-redis`）、フェデレーションアダプター（`@o3co/auth-provider-federation-*` パッケージ群）、ログインとブラウザーセッション（`@o3co/auth-provider-session`）、Store クライアント（`@o3co/auth-provider-foundation`）は持ちません。内部のどのディレクトリが何を持ち、なぜ分かれているかは [src/README.md](src/README.md) にあります。

語彙: **the Store** は auth.provider の用語で、利用者側の上流ユーザーサービス — identity・クレデンシャル・メール検証状態の system of record — を指します。定義は [`src/repositories/types.mts`](src/repositories/types.mts) の `User` doc にあり、auth.provider は Store が公開した状態を読み、Store への書き込みを引き起こすのは、自身のフローが必要とする 2 つの任意の中継（`linkFederatedIdentity` と、MFA 登録の証人 `markMfaEnrolled`）だけです。

## インストール

```sh
npm install @o3co/auth-provider-core
# createApp を使うなら、さらに:
npm install express@^5.0.0
```

optional peer dependency: `express@^5.0.0` — `createApp` を使う場合にのみ必要。
このパッケージは `bcrypt`、`jose`、`js-yaml`、`zod` に依存する。

## パブリック API

### 設定

composition root は自分の設定を解決します — 自分のファイルを、読み込むすべてのパッケージの `reference.conf` の上に、`moduleReferences(modules)` が答える順に（core のものを最後に）重ねます — そして解決したものを、パースせずに `createApp` に渡します。boot はそれを一度だけパースします（[#728](https://github.com/o3co/auth.provider/issues/728)）:

1. core の transitional base で: core 自身のセクションと、core のスキーマが他パッケージのモジュールのためにまだミラーしているすべてのセクション。ミラーはどれも省略可能で、これまでどおりの型変換と検査（環境変数の文字列を数値や真偽値として読む）を行います;
2. 書かれたものの上に重ねるので、どのスキーマも宣言していないキーは残ります — トップレベルでも、core が宣言するセクションの下でも;
3. そのうえで、読み込まれた各モジュールの `configSchema` で base の出力をパースし、各モジュール自身のセクションをそのパスでパースしてそこに書き戻します: 読み込まれたモジュールのセクションが取り除かれることはありません。

どれかが拒否する値は、オペレーターが書いた各パスを示して boot を拒否します（`config-validation-failed`）。読み込まれたどのモジュールも所有しないトップレベルのセクションは残され、設定と並べて bootstrap したロガーに一度だけ名前が出ます — `config_sections_ignored`（`warn`、名前つき）。セクション名の綴り間違いはここに現れます。何も設定しないセクション — 空のもの、または空のセクションだけを持つもの — は名前が出ません。`JWKS_PATH` と `JWKS_CACHE_MAX_AGE` が未設定のとき core 自身の `reference.conf` が残す `jwks` がそれに当たります。core のスキーマが他パッケージのセクションをまだミラーしている間（下記）、それらはどれも名前が出ません: ミラーされたセクションは、モジュールが読み込まれているかどうかにかかわらず所有されているものとして数えます。boot がパースしたものは `config` スロットにあります。ハンドルから読んでください。

```typescript
import { fileURLToPath } from "node:url";
import { type AppConfig, createApp, moduleReferences } from "@o3co/auth-provider-core";
import { parseFile } from "@o3co/ts.hocon";

// 構成自身のファイルを、読み込むすべてのパッケージの reference.conf の上に（core のものを最後に）。
const resolved = moduleReferences(modules)
  .reduce(
    (layered, reference) => layered.withFallback(parseFile(fileURLToPath(reference))),
    parseFile("config/application.conf"),
  )
  .toObject();

const handle = await createApp({
  modules,
  // パースしないまま: createApp が、読み込まれたすべてのモジュールのスキーマで一度だけパースする。
  bootstrapComponents: { config: resolved as unknown as AppConfig, pathResolver: import.meta.resolve },
});
const config = handle.components.config; // boot がパースしたもの
```

各セクションがモジュール名の下に移るまで — #728 の移動 PR — core のスキーマは他パッケージが所有するいくつかのセクション（`webauthn`、`federation-grants.enabled`）をまだミラーしており、boot は設定がそれを持つたびに、それを読むモジュールが読み込まれているかどうかにかかわらず検証します。ストアのセクション（`core-rate-limiter-memory`、`redis-*`）と、各セクションの移動元のパスは、存在だけを宣言します: 書かれたまま残し、それを解析するモジュールと移動の拒否に渡します。パッケージの `reference.conf` はそのモジュールのどれかが読み込まれれば重ねられるので、読み込まれないかもしれないモジュールのセクションも設定します。宣言されているので、それらは無視されたセクションとして名前が出ません。composition root がモジュールを知る前に読まなければならないもの — モジュールを選ぶスイッチ — は、自分のファイルを core の `reference.conf` だけの上に重ねて解決し（`coreReference()`: まだモジュールを知らないので、どのパッケージの reference も分かりません）、`readTransitionalConfig(resolved, paths)`（[`src/config/composed.mts`](src/config/composed.mts)）で読みます: 指定した各パスを core の base がそこに宣言するスキーマでパースし、それ以外は書かれたまま検査しません — 検査するのは boot です。したがってこの第一段階は、パッケージの `reference.conf` だけが設定するものを見ず、パッケージの reference が補うセクションを読んではいけません。これは過渡的なもので、それらのスイッチが composition root 自身のセクションに移った時点でなくなります。standalone テンプレートの [`app.mts`](../../templates/standalone/src/app.mts) は、ちょうどこの二段階で設定を読みます。

`AppConfigSchema` は非推奨です。`createApp` の前にこれでパースすると、宣言していないセクションがすべて取り除かれ — #472、#495、#496 はそうしてセクションを失いました — それを続ける構成は、解決したものより少ないものを boot に渡すことになります。export は残り、そこから推論される型 `AppConfig` はパース済みの設定の型です。

デフォルトはスキーマではなく `reference.conf` にあります。core 自身のセクションは [`config/reference.conf`](config/reference.conf)、モジュールのセクションはそのマニフェストが宣言する `reference.conf`（standalone テンプレートの `http`、`logging`、鍵ストアの設定はテンプレートのもの）です。core のスキーマが宣言するトップレベルのフィールド（モジュールが所有するセクションは、所有するパッケージまたはテンプレートが記述します。必須なのは行にそう書いたものだけです）:

| フィールド | 説明 |
| --- | --- |
| `http` | ホストプロセスの HTTP 設定 — `port`、`trustProxy`（Express の `trust proxy`: `false` / IP・CIDR レンジ・名前付きレンジ `loopback` / `linklocal` / `uniquelocal` のアドレスリスト / ホップ数 / `true`）、`readinessTimeoutMs`。`httpSettings` を provide するモジュール（standalone テンプレートの `http` モジュール）が所有し、デフォルトもそこにある。core はどれも読まず、デフォルトも持たない。core のスキーマはこのセクションを宣言しているので、設定が持つたびにエントリは boot 時に検証される。`true` はプロセスに到達できる誰からの forwarded アドレスも信じるため、プロキシを明示することを推奨 |
| `logging.level` | composition の logger が出力するレベル。composition root の logging モジュール（standalone テンプレートの `logging`）が所有し、デフォルトもそこにある。core はこれを読まず、スキーマが語彙を宣言している |
| `oauth.jwt` | JWT 設定 — `issuer` と `signingKey`（`provider` とそのサブセクション）: `keyStore` を provide するモジュール（standalone テンプレートの `key-store`）のセクションで、デフォルトもそこにある。core は `signingKey` を読まない |
| `oauth.accessToken.defaultExpiresIn` | リクエストが有効期間を指定しないときに全グラントが発行するアクセストークンの有効期間（秒）。指定できるのは token exchange（`expires_in` パラメータ）だけで、他のグラントはそのパラメータを無視する。有効期間は `resolveAccessTokenLifetime(config)` で読む。スキーマが拒否する値にはキーを名指しした `RangeError` を投げ（規則は `isLifetimeSeconds` で、数値として渡される有効期間のために export されている）、同梱のグラントはすべて構築時に読むので、それが拒否する手組みの config はリクエストではなく構築（と起動）で失敗する |
| `oauth.accessToken.maxExpiresIn` | token exchange の `expires_in` で得られる上限。超えるリクエストはこの値に切り詰められる。未設定ならデフォルトと同じで、明示的に設定しない限り延長されない。デフォルトがこれを超えると両キーを名指しして起動失敗 |
| `oauth.accessToken.expiresIn` | `defaultExpiresIn` の**非推奨（deprecated）**エイリアス。`defaultExpiresIn` 未設定の間だけ読まれる（`reference.conf` は出荷時の `3600` をこのキーに置いている）。パース後の config はこの名前にも解決済みのデフォルトを持つ |
| `oauth.refreshToken.expiresIn` | リフレッシュトークンの有効期間（秒）。1 から 1 年までの整数。キーの唯一の読み手である `resolveRefreshTokenLifetime(config)` で読み、それ以外の値（未設定を含む）にはキーを名指しした `RangeError` を投げる。リフレッシュトークンを発行するグラントはすべて構築時に読むので、それが拒否する手組みの config は構築で失敗し、認可コードもチャレンジも消費しない |
| `oauth.grants` | グラントタイプごとの設定。グラントタイプをキーとする。`oauth` パッケージは自分が登録するグラント — `session`、`authorization_code`、`refresh_token`、`client_credentials`、jwt-bearer の URN — の `enabled` を読み、true のものだけを登録する。他のグラントパッケージはこのキーを読まない: token exchange と WebAuthn はモジュールが組み込まれればグラントを登録し、device grant は `device-grant.enabled` が true のときだけグラントを登録する — 渡された config から `deviceGrantModule({ config })` が決める |
| `session` | ブラウザーセッションの cookie とそのストア — `secret`、`name`、`maxAge`、`secure`、`sameSite`、`domain`、`redirectAllowlist`、`storage`、`csrf` |
| `session.csrf` | 状態変更する session ルートの CSRF ポリシー — `trustedOrigins`、`ttlSeconds` |
| `rateLimit` | `login`: `/session/login` の予算（`windowMs`、`limit`）。session モジュールがこれを `login` の予算として寄与する。Redis リミッターの障害時ポリシーと OAuth エンドポイントの制限値は、リミッターモジュール自身のセクションのもの（`core-rate-limiter-memory.*` / `redis-rate-limiter.*`）。Redis リミッターの旧パス `rateLimit.failMode` は、移動の拒否と boot の `rate_limit_fail_mode_not_applied` 警告のために書かれたまま残す |
| `federations` | フェデレーションプロバイダー。名前をキーとする `{ enabled, type?, … }`。core が読むのは `enabled`（boot 時のフェデレーションストア配線チェック）だけで、`type` とエントリの残りはそれを読むアダプターパッケージのもの — アダプターパッケージは [ルート README](../../README.md) に一覧がある |
| `repositories` | client、user、code の Repository 設定 — それぞれ `type` とそのサブセクション |
| `endpoints` | `login.url`: デプロイのログインページ。`consent.url`: first-party でないクライアント向けの同意ページ（デフォルト `/consent`） |
| `core` | core 自身のセクションで、厳格: どの階層でも宣言されていないキーはブートを拒否し（`config-validation-failed`）、キーを示し、値は決して示さない |
| `core.deployment.mode` | オペレーターが述べるレプリカ数: `single`、`multi`、または未設定（`CORE_DEPLOYMENT_MODE`）。既定値は無い: 未設定はそれ自体が一つの状態である。boot はこれから `deploymentMode` スロットを埋め、`multi` のもとではレプリカごとに分岐する状態を宣言するすべてのモジュールを拒否する。`deployment.mode` はこのパスを示して拒否される。`DEPLOYMENT_MODE` は `CORE_DEPLOYMENT_MODE` へ改名されたと宣言されており、単独で、または別の値で設定されているとブートを拒否する |
| `core.sessionRequirements.expected` | この構成が期待するセッション要件 — 「ログイン済み」の意味を変える拡張で、MFA はその一つ — で、ブート時にインストールされたモジュールが登録したものと比較される（[セッション許可](#セッション許可) を参照）。書かれていれば、セッション許可に問い合わせるモジュールの有無にかかわらず両方向で比較する: インストールされたどのモジュールも登録しない名前はブートを拒否し（`session-requirement-missing`）、登録された要件を書き漏らしても拒否する（`session-requirements-undeclared`）。セッション許可に問い合わせるモジュールがインストールされているときは必須（`oauthModule` はその一つ）で、書かれていなければ拒否する（`session-requirements-undeclared`）。`[]` は「なし」。既定値は無く、構成は自らの姿勢を述べる。`sessionRequirements.expected` はこのパスを示して拒否される |
| `mfaFactorStore.adapter`、`mfaTransactionStore.adapter` | 登録済みの要素を保持するストア（`memory`、`redis`、`store`）と、MFA のトランザクションとロック状態を保持するストア（`memory`、`redis`）。どちらも既定は `memory`。MFA を組み込み、ストアを名前で選ぶ composition root が読むが、まだそうするものはない: standalone テンプレートは MFA モジュールを組み込まず、`"off"` 以外のモードではブートを拒否する（`mfa` を宣言するが、そこで登録するものは無い） |
| `cors.allowedOrigins` | token / userinfo / revocation / discovery・JWKS のレスポンスを読める browser origin — [CORS](#cors) を参照。空（既定）なら CORS は無効。`httpSettings` を provide するモジュールがないとき core が読む。standalone テンプレートの `http` モジュールはこのリストをそのスロットで渡す。CSRF の信頼は与えない（`session.csrf.trustedOrigins` を使う） |

### グラントシステム

グラントシステムは OAuth 2.0 グラントタイプの拡張ポイントです。各グラントタイプは `GrantHandler` として実装し、モジュールの `contributes.grants` で宣言します。ハンドラーの実体化と登録は boot planner が内部で行います。

#### インターフェースと型

定義は [`src/grants/types.mts`](src/grants/types.mts) にあります: `GrantHandler`、`GrantContext`、`SessionData`、`AuthenticatedClient`、`GrantHandlerResult`、`GrantDependencies`、`GrantFactory`。ハンドラーが信頼してよいもの（`authenticatedClient`。決して `body.client_id` ではない）と、してはならないことは各フィールドに記述されています。ディレクトリの責務マップは [`src/grants/README.md`](src/grants/README.md) です。

#### グラントハンドラーの登録

モジュールはグラントを `contributes.grants` にグラントタイプをキーとして宣言します。そもそもグラントを contribute するかどうかはモジュールが決めます: `oauth` パッケージのモジュールは `oauth.grants.<name>.enabled` が true のグラントだけを contribute し、token exchange と WebAuthn はモジュールが組み込まれれば自分のグラントを contribute し、`deviceGrantModule({ config })` は渡された config で `device-grant.enabled` が true のときだけ device grant を contribute します。boot は各ファクトリーを実行し、ハンドラーをそのグラントタイプで登録し — 2 つのモジュールが同じグラントタイプを contribute すると boot は拒否されます — ステージ 5 でレジストリを freeze するので、boot 後の登録は throw します。コンシューマコードがレジストリを import したり組み立てたりすることはありません: `GrantRegistry` は内部実装で、パッケージルートからは export されていません。

`GrantHandler` には後始末のフックがありません。`AppHandle.dispose()` は、提供された各コンポーネントの `lifecycle[K].cleanup` を reverse-topological 順で実行し、次に宣言を持たないモジュール提供値の `Symbol.asyncDispose` を、最後に `LifecycleRegistrar` の drain を行い — レジストリには触れません。ハンドラーのためにリソースを保持するモジュールは、自分の `lifecycle[K].cleanup` でそれを解放します。[`src/grants/README.md`](src/grants/README.md) を参照してください。

#### リソースインジケーター（RFC 8707）

`resource` を扱うグラントは、`extractResourceParam` でそれを読み、それが名指す audience を `deriveAudienceFromResources` で導き、発行する `aud` がそれを表さなければ `unrepresentedResources` で拒否します — [`src/grants/resourceIndicator.mts`](src/grants/resourceIndicator.mts)。各値は分割せずにそのまま扱い（URI はカンマを含みうる）、繰り返されたパラメーターの空のエントリーは捨て、すべて空なら要求されなかったものとして扱います。oauth のグラント、`/authorize`、WebAuthn グラントはすべてここで読むので、同じことをするカスタムグラントも同じ答えになります。

その下にあるのが `readTargetParameter` で、ターゲットパラメーター — `resource`、または RFC 8693 の `audience` — をフォームや JSON ボディから厳密に読みます。名指す値（何もなければ `[]`）を返し、文字列でも文字列の配列でもない不正な値には `null` を返します。不正な値を文字列に変換することはありません（`String([["https://x"]])` は `https://x` を名指してしまうため）。`extractResourceParam` は不正な `resource` を要求されなかったものとして読みます。トークン交換グラントは `resource` と `audience` を `readTargetParameter` で読み、不正なものを `invalid_target` で拒否します。これは RFC 8707 §2 が、サーバーが「解析できない」`resource` に与える答えで、`audience` にも対称性から同じ答えを返します。

### エラーのテキスト（RFC 6749）

RFC 6749 付録 A.7 と A.8 は `error` と `error_description` を `1*NQSCHAR`（`"` と `\` を除く印字可能な ASCII）に限ります。この規則は [`src/errors/envelope.mts`](src/errors/envelope.mts) にあります。

- `errorEnvelope(error, description?, uri?)` は RFC 6749 §5.2 のエラー本文を組み立て、規則を自身で適用します。そのため、ここを通る書き手は渡されたものが何であっても規則に従います: core のトークンバインディングのミドルウェア（機構の `retryInstruction` や `unavailable` のテキスト、ディスパッチの衝突が名指す kind）、保護リソースのバインディング、レートリミッター（リミッターアダプターの `reason`）、セッションのルート、寄与されたモジュール自身のルート。範囲外の説明の文字は `?` として送り、文字列でない説明は空の説明と同じく落とします。形式に合わない `error` コードは `server_error` として送り、`consoleLogger` で `error_envelope_code_malformed` をログに残します。コードはサーバー側のコードから来たものであり、エンベロープは呼び出し側が返すステータスを知らないからです。`error_uri` は、`http:` か `https:` の URI（§5.2 の「人が読む Web ページ」）か相対参照で、RFC 3986 の文法に照らして構成要素ごとに解析でき（userinfo なし — `https://example.com@evil.example/` の行き先は evil.example である — 、角括弧は IP リテラルのホストにだけ、相対パスの最初のセグメントにコロンなし、フラグメントは 1 つ）、WHATWG の URL パーサーが解決できるときだけ送ります。その文法が認める文字はすべて RFC 6749 の `error_uri` の文字（付録 A.9）に収まります。それ以外の `error_uri` は書き換えずに落とし、`error_envelope_uri_malformed` をログに残します。
- `sanitizeErrorText` は範囲外の文字をすべて `?` に置き換え、文字列でない値には `undefined` を返すので、呼び出し側は自分のデフォルトに戻ります。本文を自分で組み立てる書き手（リダイレクトのクエリ、リテラルの `{ error, error_description }`）は、エコーするものをこれに通します。
- `auditErrorText` は同じ処理に加えて 200 文字で切り詰めます。ログ行や監査イベント向けです。
- `auditErrorList(values, maxItems = 10)` はクライアントが選んだリスト（要求したスコープ、名指したリソース）をログ行や監査イベント向けに記録します: 配列のまま、各要素を `auditErrorText` に通し、先頭の `maxItems` 件だけを残します。小さく形の整ったリストはそのまま返ります。リストを切ったときは、呼び出し側が送られた件数を添えます（`requestedScopeCount`、`missingResourceCount`）。正の整数でない `maxItems` は `RangeError` です。
- `isWellFormedErrorCode` は `error` コードを送り出す前に検査します。自分で制御できないものからコードを組み立て、かつ自分の応答がクライアントのリクエストの拒否だとわかっている呼び出し側は、自分でクライアントエラーのコードに戻ります: トークンバインディングのミドルウェアは、`invalid_<kind>_proof` が形式に合わなくなる拒否を `invalid_request` として返し、`/oauth/token` と `/oauth/authorize` はグラントポリシーの deny に同じことをします（後述）。

このリポジトリが自分の言葉で書くテキストは、書かれた場所で [`__tests__/errorText.drift.test.mts`](src/__tests__/errorText.drift.test.mts) が範囲に収めます: 値は `'` で引用し、セクション記号は "section" と書き、em dash は使いません。

### トークンユーティリティ

`generateToken(data, options)`、`generateTokenResponse(tokens)`、`formatObject` は [`src/grants/token.mts`](src/grants/token.mts) にあり、`Token`、`TokenResponse`、`GenerateTokenOptions` がその隣にあります。

`generateToken` は `options.keyStore` の現在の署名鍵で JWT に署名します。`alg` と `kid` はキーストアのもの、`typ` は `options.tokenType`、`cnf` は `options.confirmation` が与えられたときだけ出力され、`jti` / `issuedAt` は呼び出し側が先に予約していなければここで発行されます（#449）。`exp` は `iat + options.expiresIn` なので、`expiresIn` は正の整数秒でなければなりません。小数、`NaN`、`Infinity`、0 以下は何かに署名する前に `RangeError` になり、`exp` が `Number.MAX_SAFE_INTEGER` を超える有効期間も同じです（設定スキーマは `oauth.accessToken.*` と `oauth.refreshToken.expiresIn` について同じ値を拒否します）。`generateTokenResponse` はアクセストークン、任意のリフレッシュトークン、任意の id_token を OAuth 2.0 トークンエンドポイントのレスポンス形式にまとめ、`token_type` はアクセストークン自身の confirmation（`generateToken` が `Token` に返す `confirmation`）から読みます: `cnf.jkt` なら `DPoP`（RFC 9449 §5）、`cnf.x5t#S256`（RFC 8705 §3）とバインドなしは `Bearer` — 応答の型がクレームと食い違うことはありません。グラントが刻むのは `ownedConfirmation(ctx.tokenBinding)`、つまりバインディングの仕組みが所有するメンバーであり、仕組みが返した `ctx.tokenBinding.confirmation` をそのまま刻むことはありません。`formatObject` はオブジェクトから `undefined` と `null` の値を除去します。

### キーストア

`KeyStore` インターフェースは、対称鍵（HS256）と非対称鍵（RS256、ES256、EdDSA）の署名鍵を、鍵のローテーションを含めて抽象化します。ローテーションは形が鍵種別で異なり、非対称アルゴリズムは `previousKeys`（kid + 公開鍵 + 有効期限）、HS256 は `previousSecrets`（kid + secret + 有効期限）を使います。`getVerificationKey(kid)` は kid で鍵を解決し — キーストアは一致する鍵を直接返し、複数の鍵で試し検証することはありません — 持っていない kid には `UnknownKidError`、`expiresAt` を過ぎた kid には `ExpiredKidError` を throw するので、呼び出し側は捏造された kid と退役した kid を区別できます。それ以外の throw（タイムアウトしたリモートの鍵サービスなど）はキーストアが答えられなかったということで、トークンについての判定ではありません。`verifyJwt` はそれを `kid_unknown` ではなく `verification_key_unavailable` として報告し、すべてのルートが `503 temporarily_unavailable` で答えます（[トークン検証](#トークン検証)を参照）。したがって独自のキーストアは、持っていない kid には他のエラーではなく `UnknownKidError` で答えなければなりません。`kid` は信頼できない入力です — 署名を検査する前に読むトークン自身のヘッダーで、`verifyJwt` が渡すのは整った鍵 ID（`isWellFormedKid`: 制御文字を含まない 1〜`MAX_KID_LENGTH`（256）文字の文字列）だけですが、それ以外のどんな文字でも含み得ます。リモートで鍵を引くアダプター（KMS、HSM、JWKS エンドポイント）は、それがリモートに届く前に自分の鍵の命名規則で検査し、通らないものには `UnknownKidError` で答えます。同じ規則は kid を選ぶ側でも守られます: `oauth.jwt.signingKey` と 3 つの組み込みキーストアは、整った鍵 ID でない現在の kid や以前の kid を構築時に拒否します（[`src/keys/kid.mts`](src/keys/kid.mts)）。そうでなければ、サーバーは自分の検証器が `kid_unknown` として拒否するトークンに署名してしまいます。契約は [`src/keys/KeyStore.mts`](src/keys/KeyStore.mts) の `getVerificationKey` に書かれています。`sign(options)` は compact JWT を返します。protected header の `alg` / `kid` は KeyStore が自動注入するため、呼び出し側は上書きできません。この契約により、remote-sign アダプター（KMS/HSM）は private key を露出せずに `sign()` を実装できます。`getSigningKidFallback()` は、`kid` header を欠く legacy/malformed トークンの検証用に現在の署名 kid を返す軽量なアクセサーです。rotation-safe な lookup には使わないでください。

定義 — `KeyStore`、`SignJwtOptions`、`JWTPayload`、`ManagedKey`、`KeyLike`、2 つのエラー、`AsymmetricKeyStoreOptions`、`SymmetricPreviousSecret`、`createAsymmetricKeyStore`、`createSymmetricKeyStore` — は [`src/keys/KeyStore.mts`](src/keys/KeyStore.mts) にあります。

#### 秘密鍵を持たずに署名する（KMS / HSM / Vault）

`createRemoteSigningKeyStore` は、秘密鍵がこのプロセスに入らない `KeyStore` です。継ぎ目はメソッド 1 つ、`RemoteSigner.sign(kid, data)` だけで、これはプロバイダー固有のエンコーディングではなく JWS 形式（RFC 7515 §3.3）の署名を返します。オプションが持つのは公開鍵素材だけで、`verifyOnConstruction` のデフォルトは `true` です。定義は [`src/keys/remoteSigning.mts`](src/keys/remoteSigning.mts) にあります。

`KeyStore` が負うそれ以外のすべて — protected header の組み立て、base64url エンコード、compact JWT の組み立て、ローテーションの管理、JWKS の公開 — はこちらで行うので、統合する側が書くのはプロバイダー呼び出しだけです。

**ベンダーは同梱しません。** AWS KMS、PKCS#11、Vault の transit key は `signer` を渡して配線します。`core` はそのどの SDK にも依存しません。`RemoteSigner` が関数であるのと同じ理由で、キーストアファクトリーに `remote` エントリーはありません: composition root でストアを作り、`keyStore` コンポーネントとして提供してください。

**`ES256` ではほぼすべてのプロバイダーが DER を返し、JWS はそれを受け付けません。** AWS KMS、PKCS#11、OpenSSL はいずれも ASN.1 `SEQUENCE` を返しますが、JWS が求めるのは生の `R || S` の連結です。`derToJoseEcdsaSignature(der)` が変換します。これを誤ると、署名側は成功を報告しながら RP で検証に失敗する署名ができます。そのためストアは構築時に 1 つトークンに署名して公開鍵で検証し、誤った形式を返す signer は、考えられる 2 つの原因を名指しするメッセージで起動に失敗します。`verifyOnConstruction: false` は、boot 時のプロバイダー呼び出しそのものが問題になる場合にだけ渡してください。

**`HS256` 版は意図的にありません。** 共有 secret には公開側がないので、「鍵が境界の外に出ない」は成り立ちません — すべての検証者が署名者と同じバイト列を必要とします。ここで提供すれば、デプロイは鍵素材を手の届かない場所に移したと思い込み、実際には移していない、ということになります。

```typescript
// スケッチ: AWS KMS、ES256
const store = await createRemoteSigningKeyStore({
  algorithm: "ES256",
  kid: "v1",
  publicKeyPem: await fetchPublicKeyPem(),
  signer: {
    async sign(_kid, data) {
      const { Signature } = await kms.send(new SignCommand({
        KeyId: KMS_KEY_ID,
        Message: data,
        MessageType: "RAW",
        SigningAlgorithm: "ECDSA_SHA_256",
      }));
      return derToJoseEcdsaSignature(Signature!);  // KMS は DER を返す
    },
  },
});
```

`createKeyStoreFactory()` は登録済みタイプが空の新しいファクトリーを作ります。`registerBuiltinKeyStores(factory)` は組み込みの `"local"` プロバイダーを登録し、これは `algorithm` に応じて `createAsymmetricKeyStore` か `createSymmetricKeyStore` に委譲します。どちらも [`src/keys/factory.mts`](src/keys/factory.mts) にあります。ファクトリーは `ClientRepository`、`UserRepository`、`CodeRepository` のファクトリーと同じ `AdapterFactory<T>` 契約に従います。

#### アルゴリズムのデフォルトと鍵の要件

`reference.conf` のデフォルトは `algorithm = "EdDSA"`（`DEFAULT_SIGNING_ALGORITHM`）。HS256 では RP に「検証できない（公開鍵が存在しない）」か「共有シークレットを持つ ＝ トークンを**発行**できてしまう」かの二択しか残らないため、デフォルトは非対称。

`"local"` builder に fallback は一切ない:

- `algorithm` 未設定はエラー。暗黙の `HS256` にはならない。
- 非対称アルゴリズムで `privateKey`/`privateKeyPath`（または公開鍵側）が無い場合、設定キー名・環境変数名・それらを生成する `openssl genpkey -algorithm ed25519` コマンドを明示したエラーで起動失敗する。
- `HS256` の `secret` は `MIN_SECRET_ENTROPY_BYTES`（32 バイト）以上が必須。`previousSecrets[].secret` も同じ。

エントロピーは**デコード後**の値で、かつ最も小さく読める解釈で測る（`measureSecretEntropyBytes`）: 64 文字の hex は 32 バイトで通り、32 文字の hex は 16 バイトで落ちる。`session.secret` にも同じ floor が core のスキーマで適用される。`assertSecretEntropy` / `describeWeakSecret` は export されているので、運用者のシークレットを自前で受け付ける composition root も同じ検査を適用できる。

floor が置かれているのは **builder と schema**（= config 境界）であることに注意。`createSymmetricKeyStore` は低レベルプリミティブなので強制しない — 直接呼ぶ composition root は自分で検査する責任を持つ。

#### HS256 鍵のローテーション

メンテナンス時間を取らずに HS256 の署名鍵をローテーションする手順:

1. 現在の `kid` と `secret` を控える。
2. 新しい secret を生成する: `openssl rand -hex 32`。
3. `application.conf` で新しい `kid` + `secret` を設定し、古い組を `previousSecrets` に移す:

   ```hocon
   oauth.jwt.signingKey.local {
     algorithm = "HS256"
     kid = "v1"           # 新しい kid
     secret = "<new-secret>"
     previousSecrets = [{
       kid = "v0"          # 古い kid
       secret = "<old-secret>"
       expiresAt = "2026-06-05T00:00:00Z"  # アクセストークンの TTL + 余裕
     }]
   }
   ```

4. サーバーを再起動する。`v0` で署名されたトークンは `expiresAt` まで検証が通り続ける（JWT header の `kid` で解決される）。
5. 重複期間が過ぎたら（`v0` のトークンがすべて失効したら）、`previousSecrets` から `v0` を削除して再び再起動する。

新しい `secret` もすべての `previousSecrets[].secret` も 32 バイトの floor を満たす必要がある — 退役した secret も重複期間のあいだは生きた検証鍵であり、現行の secret と同じ偽造リスクを持つ。

スキーマは非対称の `previousKeys` 形を HS256 と混ぜることを拒否し、builder は逆（RS256/ES256/EdDSA での `previousSecrets`）を拒否する — 非対称アルゴリズムの運用者は `previousKeys` フィールドを使う。

### トークン検証

`verifyJwt`（[`src/jwt/verify.mts`](src/jwt/verify.mts)）はこのプロバイダーが発行したトークンを検証し、`JwtVerificationError` を throw します。その `reason` は、トークンについての判定（署名不正、誰も持たない kid の `kid_unknown`、退役した kid の `kid_expired`、期限切れ、失効の `revoked`）か、障害（キーストアが答えられない `verification_key_unavailable`、jti の denylist か subject watermark が読めない `revocation_unavailable`）のどちらかです。`isVerificationUnavailable(err)` が両者を区別し、`VERIFICATION_UNAVAILABLE_DESCRIPTION` がワイヤーに載せる依存先の名前を与えます。このリポジトリのすべての面は障害を `503 temporarily_unavailable` で答え、判定（`401 invalid_token`、`400 invalid_grant`、`active: false`、失効の `200`）では答えません。どれもトークンを記述し、まったく問題ないかもしれない資格情報の取り替えをクライアントに促すからです。トークンはどちらの場合も拒否されます。

`REVOCATION_RETENTION_ALLOWANCE_MS` は、トークンを失効させた記録をその `exp` からどれだけ長く保持しなければならないかです。検証器のクロック許容、レプリカ間の余裕、丸めの 1 秒からなります。`/oauth/revoke` は denylist に入れた `jti` を `exp` からこの分だけ長く保持し、失効したリフレッシュトークンファミリーも同じ規則で保持されます（[リフレッシュトークンファミリー](#リフレッシュトークンファミリーrfc-6819-5223-の-replay-検出)）。

JWT の `exp`・`iat`・`nbf` は、有限で Date の範囲に収まるときだけ NumericDate（RFC 7519 §2）です。`isNumericDate` と `malformedNumericDateClaim`（[`src/jwt/numericDate.mts`](src/jwt/numericDate.mts)）がその規則を述べ、jwt-bearer のレジストリ検証器、`private_key_jwt`、DPoP はこれを破るアサーションや proof を、そこから期限を計算する前に拒否します。jose はこうしたクレームが数値であることしか確かめず、JSON の `1e400` は Infinity にパースされます。小数は許されます。単一使用のために `jti` を記録するアサーション — `private_key_jwt` のクライアントアサーション、ID-JAG — は、さらに現在から `MAX_ASSERTION_LIFETIME_SECONDS`（1 時間）先までしか有効でなく、発行もそれ以内でなければなりません（[`src/assertions/lifetime.mts`](src/assertions/lifetime.mts)）。リプレイの記録は `exp` まで残るので、上限の無い `exp` は上限の無い記録になるからです。どちらの検証器も、ほかのすべての時刻チェックと同じく時計の許容幅をその上に認め、`exp` を同じ `assertionLifetime` で比べます。時計が少し進んでいるクライアントや IdP が、一方の経路では拒否され他方では受け入れられる、ということは起きません。

### 保存時の封印（sealing）

秘密を保存するストアは、それを `v2` のキーリング封筒に封印します（[`src/sealing/envelope.mts`](src/sealing/envelope.mts)）。`sealWithKeyRing(plaintext, ring, { purpose, record })` は、リングの先頭の鍵による AES-256-GCM で `v2.<key id>.<iv>.<ciphertext>.<tag>` を返します。`openWithKeyRing(envelope, ring, { purpose, record })` は `OpenedSeal` で答えます。値と、それを開いた鍵の `keyId` とともに `ok`（先頭でなくなった鍵で開いた値を、呼び出し元が封印し直せます）、封筒が名指す鍵をリングがもう持っていないときの、その `keyId` とともに `key_unavailable`（運用者がその鍵を戻せば元に戻ります）、それ以外すべての `unreadable`（別の目的や別のレコードに結び付いた値や、16 バイト以外のタグ、12 バイト以外の IV を含みます）のいずれかです。封筒を理由に throw することはありません。目的ラベル（1〜64 文字の印字可能な ASCII、空白なし）とレコードのバイト列は認証され、保存はされません。そのため、別のレコードへコピーされた値や、同じリングで封印する別の呼び出し元が読もうとした値は開きません。

リング（`SealingKeyRing`: `{ id, key }` の `SealingKey` の並び、[`src/sealing/keyRing.mts`](src/sealing/keyRing.mts)）は先頭の鍵で封印し、どの鍵でも開けます。ID は `A-Za-z0-9_-` の 1〜64 文字（`isSealingKeyId`）、鍵は `SEALING_KEY_BYTES`（32）バイトの Buffer です。`checkSealingKeyRing(ring, setting)` は規則を破るリングを、`setting` で始まるメッセージの `RangeError` で拒否します。ストアは構築時に、リングを読んだ設定キーやオプションの名前（`redis-federation-grant-store.encryptionKeys`）でこれを呼ぶので、不正なリングは起動時に、書かれた場所を名指して拒否されます。どの拒否もエントリをインデックスで名指し、ID を引用しません。32 バイトの鍵を hex やパディングなしの base64url で書いたものは ID の規則を通るので、ID と鍵を取り違えた運用者には、引用すれば鍵が見えてしまうからです。封印と開封はリングを「sealing key ring」として改めて確かめ、規則外の目的ラベルに対して、封印は空のリングに対しても、`RangeError` を throw します。`decodeSealingKey` は設定された鍵を読みます。空白を含まない、ちょうど 32 バイトの正準な base64 なら鍵の値を、そうでなければ `undefined` を返し、呼び出し元が自分の設定キーを名指して拒否します。`@o3co/auth-provider-redis` のフェデレーショングラントストアは、この方法でクレデンシャルを封印しています。MFA パッケージも、`mfa.encryptionKeys` に設定されたリングで、要素のデータとセレモニーの状態をこの方法で封印します。

### リポジトリ

リポジトリインターフェースはデータアクセスのコントラクトを定義します。開発・テスト向けのインメモリ実装が標準で提供されています。

#### インターフェースと型

ポートは [`src/repositories/ClientRepository.mts`](src/repositories/ClientRepository.mts)（`findById`、`authenticate`。`PublicClient` は `clientSecret` を除いた `Client`。例外を投げるのはストアが答えられないときだけで、未知のクライアントや誤った secret は `null` — クライアント認証と `/authorize` は例外を `503 temporarily_unavailable` で答えるため。渡される `clientId` は [`src/repositories/clientId.mts`](src/repositories/clientId.mts) の `isWellFormedClientId`（制御文字を含まない、`MAX_CLIENT_ID_LENGTH`（256）文字以下）を通過済みだが、なおクライアントの入力なので、パラメーターとして束縛し、文字列に埋め込まない）、[`src/repositories/UserRepository.mts`](src/repositories/UserRepository.mts)（`authenticate`、`authenticateByToken`、および任意の federated-identity リンク・検索メソッド）、[`src/repositories/CodeRepository.mts`](src/repositories/CodeRepository.mts)（`createCode`、`findByCode`、アトミックな single-use ゲートである `consumeByCode`、`removeByCode`）です。レコード — `Client`、`User`、`CodeData`、`Code`、`TokenEndpointAuthMethod` — は [`src/repositories/types.mts`](src/repositories/types.mts) にあり、各フィールドの意味はそのフィールド上に一度だけ記述されています。例外はログアウト URI の 3 フィールドで、そこには記述がありません: `postLogoutRedirectUris` は `allowedRedirectUris` と同じ登録リダイレクト URI 文法（カスタムスキーム可）、`backchannelLogoutUri` と `frontchannelLogoutUri` は http/https のみです。この注記は [`src/repositories/InMemoryClientRepository.mts`](src/repositories/InMemoryClientRepository.mts) のスキーマの横にあります。

`createCode` は `client_id` と `redirect_uri` を必須とし、`Client.tokenEndpointAuthMethod` も必須です。`Code` のその他のフィールドはすべて必須キーで、記録がなければ `undefined` を保持します。`createCode` は `CreateCodeInput` を受け取り、省略できるのは `expiresIn`（省略時はリポジトリの既定値）だけです。`nonce` と `sid` は OIDC の nonce とセッション ID を `/authorize` から `/token` へ運びます。`grantedScope` / `grantedAudience` は `/authorize` でのグラントポリシーの決定で、`authorization_code` グラントはポリシーを再評価せずにこれを読みます。ディレクトリの責務マップは [`src/repositories/README.md`](src/repositories/README.md) です。

#### 組み込み実装

`InMemoryClientRepository` と `InMemoryUserRepository` は、`ClientEntrySchema` / `UserEntrySchema` で検証済みのエントリーの `Map` を受け取ります。`InMemoryCodeRepository` は任意の `defaultExpiresIn` を受け取り、`dispose()` で止める GC タイマーを持ちます。`loadYamlMap(filePath, schema)`（[`src/repositories/loadYamlMap.mts`](src/repositories/loadYamlMap.mts)）はトップレベルのキーをレコード ID とする YAML ファイルを読み込み、各エントリーを `schema` で検証します。結果を `InMemoryClientRepository` や `InMemoryUserRepository` にそのまま渡せます — [YAML からクライアントとユーザーを読み込む](#yaml-からクライアントとユーザーを読み込む) を参照。パースできないファイルは `Invalid YAML in <file> at <line>:<column>: <reason>` として拒否され、`cause` もファイルの中身も持ちません。js-yaml 自身のエラーは問題箇所の前後の行を引用し、ファイル全体を保持しており、これらのファイルはシークレットを含むからです。

#### アダプタファクトリーのプリミティブ

`createAdapterFactory<T>(kind, ctx?)`、`AdapterFactory<T>`、`AdapterBuilder<T>`（設定セクションと読み取り専用の `BuilderContext` を受け取る関数。`BuilderContext` のフィールドはすべて任意で、追加されるだけ）、`LifecycleRegistrar`（cleanup の `tailMs` を持つ `LifecycleCleanupOptions` とともに）、`AdapterFactoryError` は [`src/adapters/AdapterFactory.mts`](src/adapters/AdapterFactory.mts) に定義されています。[`src/repositories/RepositoryFactory.mts`](src/repositories/RepositoryFactory.mts) の `createRepositoryFactories(ctx?)` は client、user、code のファクトリーを返します。

契約の主要な性質:

- `create()` は同期ビルダーであっても必ず `Promise<T>` を返す。
- `register()` は同一 `type` の二重登録で throw する（silent override 防止）。`replace()` が明示的な上書きで、登録されていない `type` では throw する。
- `create()` は未登録 `type` で `AdapterFactoryError` を throw する。error は `reason`（`unknown`、`duplicate`、`unknown-replace`）、`kind`、`type`、`registered` の一覧を持つ。
- `BuilderContext` は factory 単位で共有される（call ごとのコピーではない）。builder 側では read-only として扱うこと。

`createRepositoryFactories` は組み込みの `yaml` / `static`（client、user）と `memory`（code）タイプが登録済みの 3 つのファクトリーを返します。`@o3co/auth-provider-foundation` の `registerBuiltinAdapters` で `http` ユーザー認証アダプターを追加するか、独自のタイプを登録して別の backend に対応させてください。Redis バックエンドの code / store アダプターは `@o3co/auth-provider-redis` を参照してください。

### モジュールシステム

モジュールはルート、グラントハンドラー、DI グラフのコンポーネントをアプリに追加します。モジュールは `defineModule({...})` で書く宣言的なマニフェストです: `requires` / `optional`（型付きの `ProviderDeps` キー）を宣言し、コンポーネントを `provides` し、`grants`、`routes`、`federations` などの `ContributesMap` の種別に contribute します。boot planner が型付きの deps をすべてのファクトリーに注入するので、モジュールが共有状態を書き換えることはありません。語彙は [`src/modules/manifest/`](src/modules/manifest/README.md) にあり、`@o3co/auth-provider-core/modules/manifest` サブパスとしても公開されています。

それぞれの仕組みが拡張面の 1 つの軸です: `routes`・`grants`・`federations` への contribution は振る舞いを足し（plugin）、`provides` はポートのスロットを埋め（adapter）、`supportsX` ガードで検出される任意のメソッドはアダプターの追加機能であり（capability）、core が合成する contribution の種別は core の判断の意味を変えます（extension）。新しいポリシーをどの軸に載せるかは [AGENTS.md](../../AGENTS.md#extension-surface-four-axes) の規則です。

設定を読むモジュールは、自分のセクションをマニフェストで宣言します（[#728](https://github.com/o3co/auth.provider/issues/728)）: `section.schema` はモジュールが所有する唯一のセクションの Zod スキーマで、boot はどのファクトリーよりも先にそのセクションをパースし、スキーマの出力の型を持つ `deps.section` としてすべてのファクトリーに渡します。スキーマが拒否する値は、オペレーターが書いたパスを示して boot を拒否します（`config-validation-failed`）。セクションはモジュール名の位置から読まれ、まだ古いパスにある間は `section.at` の位置から読まれます。`section.relocatedFrom` はセクションの移動元のパスを示します。そこにまだキーを設定している設定は、そのキーの新しいパスとそれを束縛する環境変数、またはキーが削除されたことを示して boot を拒否します（`config-path-relocated`）。0.x 系の間の橋渡しで、最初のメジャーリリースで削除されます（削除を忘れたリリースカットは relocated-paths のドリフトテストが失敗させます）。`section.renamedVariables` は名前が変わった環境変数を、古い名前からそれが束縛されていた古いパスへの対応で示します（新しい名前は新しいパスが束縛される変数で、削除されたキーのものにはありません）。パッケージの `reference.conf` は各名前を予約セクション `renamed-variables` に捕捉します。解決時に古い名前が設定されていたと捕捉された場合、新しい名前が同じ値で捕捉されていなければ boot を拒否します（`environment-variable-renamed`）。削除されたキーの変数が設定されている場合と、名前が捕捉されていない場合も同じく拒否します。`section.reference` はパッケージの `config/reference.conf` を指します: boot はこれを読まず、`moduleReferences(modules)`（[`src/config/references.mts`](src/config/references.mts)）が、構成が読み込むモジュールの reference を、それぞれ一度ずつ、core 自身のもの（`coreReference()`）を一番下にして答え、composition root はそれを自分のファイルの下に重ねます。パッケージは自分の reference を、自分のテストで `@o3co/auth-provider-core/testing` の `packageReferenceProblems` を使って検査します。boot はパースした各モジュールのセクションをそのパスで設定に書き戻すので、`config` を読むファクトリーは、セクションのスキーマがそれをどうしたかを見ます。別のモジュールのセクションの内側にあるセクションはその内側に書き戻され、二つのモジュールが同じパスにセクションを宣言することはできません（`module-section-path-invalid`）。boot が core のスキーマの後に設定全体をパースする `configSchema` は、各セクションがモジュール名の下に移った時点で非推奨になります。

複数のモジュールが読むキーは所有者が 1 つで、ほかのモジュールは契約が core にあるスロットを通して受け取ります（[#728](https://github.com/o3co/auth.provider/issues/728)）: 所有者が自分のセクションを解釈して値を provide し、コード上パッケージは core だけを import します。core はこれらのスロットを宣言しています。`loginCompletion`、`loginEntry`、`csrfGuard`、`sessionCookiePolicy`、`csrfTokenSigner` は session パッケージのモジュールが、`oauthTokenSettings` は oauth モジュールが provide し、`deploymentMode` は core 自身が埋め、残りは提供者より先に宣言されています:

- `oauthTokenSettings` — ほかのモジュールが読む oauth モジュールのトークン設定 — [`src/token-settings/types.mts`](src/token-settings/types.mts)。
- `loginCompletion` — 要件の完了処理が session パッケージを import する代わりに使う、ログインの末尾（`establishSession`、`answerInterruption`）— [`src/session-admission/login-completion.mts`](src/session-admission/login-completion.mts)。
- `loginEntry`、`csrfGuard`、`csrfTokenSigner`、`sessionCookiePolicy`: `redirect_to` のプロトコルを伴うログインページ、ブラウザーが状態を変えてよいかの唯一のポリシー（リクエストと、フローを始めるナビゲーションの両方）、セッションのシークレットの所有者がガードの提供者とセッションのルートに渡す CSRF トークンの署名（長さの範囲は `CSRF_SIGNATURE_MIN_LENGTH` と `CSRF_SIGNATURE_MAX_LENGTH`）、セッション Cookie の属性 — [`src/browser-session/types.mts`](src/browser-session/types.mts)。
- `httpSettings`（`trustProxy`、CORS のオリジン）と `deploymentMode`（`single`、`multi`、`unset`）— [`src/deployment/types.mts`](src/deployment/types.mts)。boot はすべての組み立てで、どの provider よりも先に、設定の `core.deployment.mode` から `deploymentMode` を埋めます。キーの読み方は一つ（[`src/deployment/mode.mts`](src/deployment/mode.mts)）で、replica-safety ガードも同じ値で判定します。synthetic key なので、それを provide するモジュールや、それを設定する `bootstrapComponents`・`overrideComponents` のエントリは boot を拒否します（`synthetic-key-collision`）。モードによって拒否や警告をするモジュールはこのスロットを requires し、`deployment` を自分では読まず、渡された値を `checkDeploymentMode` で確かめます。これは三つの値以外（無い場合も含む）に対して、値の出どころを示す TypeError を投げます。読み方そのものである `deploymentModeOf` は、そうしたモジュールを手で組み立てる composition root のために export されています。その隣に、環境名の唯一の読み方があります（[`src/deployment/environment.mts`](src/deployment/environment.mts)）: `readEnvironmentName` は名前の前後の空白を除いて小文字にし、`productionEnvironmentIn` は、いくつかの名前 — 設定が選ばれた名前、`CONFIG_ENV`、`NODE_ENV` — のどれが `production` か `staging` を示すかを答えます。そこで拒否されるモジュールのためのものです。
- `RateLimiter.failMode` — リミッター自身の障害時ポリシー。ガードはこれを適用する（宣言がなければ `closed`）— [`src/ratelimit/types.mts`](src/ratelimit/types.mts)。

それぞれ、提供者のテストが実行する契約スイートと、読む側のテストがスロットを埋めるテストダブルが `@o3co/auth-provider-core/testing` にあります。`deploymentMode` には提供者もテストダブルもありません: core 自身のテストが boot の埋めた値に対して契約スイートを実行し、読む側のテストはスロットをリテラルで埋めます。スイートとダブル: `oauthTokenSettingsContract` と `createTestOAuthTokenSettings`、`loginCompletionContract` と `createRecordingLoginCompletion`、`loginEntryContract` と `createTestLoginEntry`、`csrfGuardContract` と `createTestCsrfGuard`、`csrfTokenSignerContract` と `createTestCsrfTokenSigner`、`sessionCookiePolicyContract` と `createTestSessionCookiePolicy`、`httpSettingsContract` と `createTestHttpSettings`、`deploymentModeContract`、`rateLimiterContract` と `createTestRateLimiter`。各スロットが持つものは [docs/adapter-surface.md](../../docs/adapter-surface.md) にあります。

モジュールが provide する設定スロット — `oauthTokenSettings`、`httpSettings`、`sessionCookiePolicy`。core が自ら埋めて予約している `deploymentMode` は含まない — は、所有者がロードされている間、出どころが一つです: 所有者はそれを `authoritative` に挙げます。これは自分の `provides` のキーに型付けされたリストです（oauth モジュールは `oauthTokenSettings` を、セッションストアのモジュールは `sessionCookiePolicy` を挙げています。standalone テンプレートの `http` モジュールは `httpSettings` を挙げています）。所有者自身のコードは自分のセクションを読むので、そのスロットへの `overrideComponents` のエントリは二つ目の出どころになります — 読む側は上書きに従い、モジュールはセクションのとおりに動き続ける — ので、boot はそれを拒否します（`authoritative-component-overridden`）。モジュールが provide しないキーを authoritative に挙げることも拒否します（`authoritative-without-provides`）。所有者をロードしない組み立ては、上書きを含めて自分でスロットを埋めます。ロードされたモジュールが provide するほかのキーは上書きできます。

```typescript
const myModule = defineModule({
  name: "my-module",
  requires: ["clientRepository"] as const,
  section: { schema: z.object({ greeting: z.string() }) },
  contributes: {
    routes: [
      (deps) => ({
        id: "my-route",
        mountPath: "/my",
        handler: makeRouter(deps.clientRepository, deps.section.greeting),
      }),
    ],
  },
});
```

### アプリファクトリー

`createApp(options): Promise<AppHandle>` は [`src/boot/`](src/boot/README.md) の boot planner です。`CreateAppOptions` と `AppHandle` は [`src/boot/types.mts`](src/boot/types.mts) に定義されています。

`createApp` はマニフェストを検証し、設定を合成・パースし、コンポーネントグラフを実体化し、すべての contribution を適用し、ワールドを freeze してルートをマウントします。起動の拒否は `BootError`（[`src/boot/types.mts`](src/boot/types.mts)）です: そのメッセージは背後のエラーを `loggableError` の規則で名指し — パーサーが引用したもの、Redis の応答の引数、Error でない throw された値を引用することはありません — 出力されるとき（`util.inspect`、`console.error`、Node の unhandled rejection の出力）は、持っているすべてのエラーを射影として示します。`cause` と `details.originalError` は、それを読むコードのために throw された値のままです。返される `router` はそのままマウントでき（`app.use(handle.router)`）、`handle.listen(port)` で配信することもできます。`handle.dispose()` はすべての cleanup を reverse-topological 順で実行してそれぞれを待ち、すべての失敗を持つ `AggregateError` で reject します。`handle.cleanupAllowanceMs` は cleanup が登録された `tailMs` のうち最長のもので、`dispose()` に期限を設けるホストが `dispose()` 全体に少なくとも与える時間です。tail は周りの cleanup の分も含むので、足し合わされません。別途の `init()` ステップはありません。

core が自分でマウントするもの（この順）: レスポンスを読ませるオリジンがあれば `corsMw`（[CORS](#cors)）、contribute された機構が 1 つ以上あればそれらを合成した単一の `tokenBindingMw`、protected-resource の sender-constraint チェック（常に。トークンエンドポイントへの POST を除くすべてのリクエストで）、グラントのディスパッチ前に `grantMiddleware` の contribution、issuer が設定されかつ `providerRoot` を宣言するモジュールがあれば OIDC discovery ルート、そしてすべてのルートの後に終端のエラーハンドラー（[`src/middleware/terminalError.mts`](src/middleware/terminalError.mts)）。このハンドラーは組み立てたルートが通してしまったものに答えるので、それらのエラーがホスト自身のハンドラーへ届くことはありません（ホストが起動後に `handle.router` へ加えたルートはその後ろに付くので対象外です）: ボディパーサーの拒否は — body-parser 自身の `type` で読み — RFC 6749 のエンベロープで `400 malformed_body`、`413 body_too_large`、`415 unsupported_encoding`（Express がデコードできなかったパスは `400 malformed_path`）とし、ログには出しません。`expose` の付いたそれ以外の `http-errors` の 4xx は、自身のステータスのまま `invalid_request` / `request_refused` とし、401 の `WWW-Authenticate` や 405 の `Allow` を持っていれば（1 KiB まで）それを付けます。それ以外はすべて `500 server_error` で、`endpoint` とエラーの射影を付けて error レベルの `unhandled_request_error` として 1 回ログに出します。どの応答も `Cache-Control: no-store` と `Pragma: no-cache` です。レスポンスのヘッダーが送られた後のエラーも同じようにログに出し、レスポンスがまだ終わっていなければ接続を閉じます。どのルートも答えなかったリクエストは、これまでどおりホストへ渡ります。このハンドラーは `terminalErrorHandler(logger)` として export されており、ルーターと並べて自前のルートをマウントするホストが、その後ろで同じ答えを返すのに使えます。それ以外 — JWKS（`jwksModule`）、liveness と readiness（`createHealthcheckRouter`、`createReadinessRouter`）、OAuth と session のルート — は、composition root が組み込むモジュールかルーターです。

`express` は任意の peer dependency で、遅延ロードされます: `createApp` はルーターを作るために import し（`await import("express")`）、boot は `handle.listen()` がルーターを包む `express()` ファクトリーのためにも require します（`createRequire`）— import が失敗した場合はルーターもそこから得ます。

## CORS

`corsMw`（`src/middleware/cors.mts`）がレスポンスを読ませるオリジンは、composition が `httpSettings` スロットを持つときはその `cors.allowedOrigins`（standalone テンプレートの `http` モジュールが提供します）、持たないときは設定の `cors.allowedOrigins` です。2 つを混ぜることはありません。`assembleApp` はこのミドルウェアを**最初に** — 他のすべてのミドルウェアとルート contribution より前に — マウントします。空のリスト（既定）なら何もマウントしません: CORS ヘッダーも `Vary` も付きません。契約に反するオリジンを持つスロット（`checkSerializedOrigin` が拒否するエントリー、または文字列のリストでないもの）は、メンバーとインデックスを示す `RangeError` で boot を拒否します。

### 対象ルート

`browserFacingCorsRoutes(config, { issuer, jwksPath })` がその表で、**許可リスト**です — 隣にある sender-constraint のマウントとは逆の極性です。あちらはクレデンシャルを守るので core が知らないルートまで覆う必要がありますが、こちらはクロスオリジンの読み取りを*与える*ので、core が知らないルートこそ黙ってそれを得てはいけないルートです。

| パス | メソッド |
|---|---|
| `/oauth/token` | `POST` |
| `/oauth/userinfo` | `GET`、`POST` |
| `/oauth/revoke` | `POST` |
| `/.well-known/openid-configuration` | `GET` |
| `/.well-known/oauth-authorization-server` | `GET` |
| `jwks.path`（既定 `/.well-known/jwks.json`）。jwks モジュールのルートが提供するパスで、モジュールが無ければ無し | `GET` |

2 つの discovery の行は同じドキュメントです: OIDC Discovery 1.0 は issuer に接尾辞を付け足し、RFC 8414 は well-known 文字列をホストとパスの間に挿入します。`discoveryPathsFor`（`src/discovery/wellKnownPaths.mts`）が設定された issuer に対して両方を作ります — `https://as.example/tenant-a` なら `/tenant-a/.well-known/openid-configuration` と `/.well-known/oauth-authorization-server/tenant-a` — ので、ルート、その広告、この表がずれることはありません。

`/oauth/introspect` はサーバー間通信で、すでに public client を拒否するので対象外です。`/oauth/authorize` は `fetch` ではなくトップレベルのナビゲーションなので対象外です。`/oauth/*` のパスは同梱の `oauthModule` の mountPath に結びついています（`boot/assemble-app.mts` の `/oauth/token` へのマウントと同様）— OAuth ルーターを別の場所にマウントし直す downstream は、自分の表を作って `corsMw` に渡します。

### ヘッダー

- `Access-Control-Allow-Origin` は**一致したエントリーをそのまま**返します。任意の origin を反射することはなく、`*` も出力しません — 認証不要のドキュメントに対してもです。`*` を出せるコードパスは、トークンを運ぶレスポンスで `*` を出すまであと一歩のコードパスだからです。
- **`Access-Control-Allow-Credentials` は決して出しません。** ここでのクロスオリジン SPA は PKCE を使う public client で、こちらの cookie を持ちません。credentials を許せば cookie に依拠する `session` グラント — 認証済みのブラウザーセッションをトークンに交換する — に届き、それは「自分で認証したリクエストのレスポンスを読める」よりはるかに大きな許可ですが、CORS はこの 2 つを一緒に渡してしまいます。
- プリフライト（`Access-Control-Request-Method` を持つ `OPTIONS`）には、ルートのメソッド、`Access-Control-Allow-Headers: content-type, authorization, dpop`、`Access-Control-Max-Age: 600` を付けて `204` で応答します。
- `Access-Control-Expose-Headers: WWW-Authenticate, Retry-After` — どちらも呼び出し側がこれなしでは対処できない診断情報です（バックオフの手がかりのない不透明な `429`、どのスキームを求めたか言わない `401`）。
- これらのルートの**すべて**のレスポンスに `Vary: Origin` を付けます。CORS ヘッダーを持たないレスポンスも含むので、共有キャッシュがある origin のレスポンスを別の origin に返すことはありません。

### オリジン

エントリーは boot 時に `checkSerializedOrigin`（`src/net/origin.mts`）で検証され、インデックスを示して拒否されます。一致判定は文字列の完全一致なので、末尾のスラッシュ、明示的な `:443`、大文字のホスト、パス、ワイルドカードは、誰も通さずそのことをどこにも言わない許可リストになるからです。loopback ホストを除き `https` が必須で、判定は共有の `isLoopbackHostname` に拠ります。`corsMw` は同じ検査をもう一度適用し、落としたものを警告するので、スキーマを通っていない手組みの `AppConfig` でも、スキーマなら拒否したエントリーは入りません。

リストの書き方は 2 通りあります。環境変数が運べる唯一の形であるカンマ区切りの文字列（`CORS_ALLOWED_ORIGINS`）はカンマで分割され、各エントリーは前後の空白を除かれ、空のエントリーは捨てられるので、空の変数はリストなしになります。配列は文字列のエントリーを前後の空白を除いて保ち、空のエントリーは上の検査で拒否され、文字列でないエントリーは捨てられます。`null` はリストなしです。それ以外の形 — 数値、オブジェクト、真偽値。設定ファイルでしか書けない形です — はパース時に `cors.allowedOrigins` を示して拒否されます — `createApp` を通るなら手組みの設定も同じです。boot はこのセクションがあればいつでもパースするからです（#728）。それでもミドルウェアをマウントする箇所に届いた形は警告され（`cors_allowed_origins_unreadable`、受け取った形を `received` に持つ）、ミドルウェアはマウントされません。両方を読むのは同じファイルの `normalizeAllowedOrigins` で、export されています。WebAuthn パッケージは `WEBAUTHN_ORIGIN` / `WEBAUTHN_TOP_ORIGIN` をこれで読むので、環境変数から設定するオリジンのリストはどれも同じ書き方になります。

## 使い方

```typescript
import express from "express";
import {
  type AppConfig,
  createApp,
  createRepositoryFactories,
  createKeyStoreFactory,
  defineModule,
  readTransitionalConfig,
  registerBuiltinKeyStores,
} from "@o3co/auth-provider-core";

// boot より前にこの構成が読むもの。rawConfig は createApp 自身がパースする（#728）。
const config = readTransitionalConfig(rawConfig, ["http.port", "oauth.jwt.signingKey", "repositories"]);

// 署名鍵とポートはこの構成自身の設定: core は `oauth.jwt.signingKey` にも `http` にも
// デフォルトを持たないので、rawConfig がそれを持つ（standalone テンプレートは自分の
// `config/reference.conf` に置いている）。
const { signingKey } = config.oauth.jwt;
const port = config.http?.port;
if (signingKey === undefined || port === undefined) {
  throw new Error("oauth.jwt.signingKey and http.port are required");
}

// repositories.*（'type' セレクター）と oauth.jwt.signingKey（'provider' セレクター）は同じ入れ子の
// アダプターサブセクション形式に従う。flatten() はどちらも { type, ...サブセクションフィールド } に正規化してから factory に渡す:
const flatten = (
  section: ({ type: string } | { provider: string }) & Record<string, unknown>,
) => {
  const selector =
    (section as { type?: string; provider?: string }).type
    ?? (section as { provider?: string }).provider;
  if (typeof selector !== "string") {
    throw new TypeError("flatten: section requires 'type' or 'provider' string");
  }
  const sub = section[selector];
  const flattenedSub =
    typeof sub === "object" && sub !== null && !Array.isArray(sub)
      ? (sub as Record<string, unknown>)
      : {};
  return { type: selector, ...flattenedSub };
};

const keyStoreFactory = createKeyStoreFactory();
registerBuiltinKeyStores(keyStoreFactory);
const keyStore = await keyStoreFactory.create(flatten(signingKey));

const { clientFactory, userFactory, codeFactory } = createRepositoryFactories();

const clientRepository = await clientFactory.create(flatten(config.repositories.client));
const userRepository = await userFactory.create(flatten(config.repositories.user));
const codeRepository = await codeFactory.create(flatten(config.repositories.code));

const localComponentsModule = defineModule({
  name: "local-components",
  provides: {
    keyStore: () => keyStore,
    clientRepository: () => clientRepository,
    userRepository: () => userRepository,
    codeRepository: () => codeRepository,
  },
});

const handle = await createApp({
  modules: [
    localComponentsModule,
    // 追加モジュールをここに渡す
  ],
  bootstrapComponents: { config: rawConfig as AppConfig, pathResolver: import.meta.resolve },
});

const server = express();
server.use(handle.router);
server.listen(port);
```

### カスタムグラントタイプの実装

```typescript
import {
  defineModule,
  type GrantFactory,
  generateToken,
  generateTokenResponse,
} from "@o3co/auth-provider-core";

const myGrantFactory: GrantFactory = (deps) => ({
  async handle(ctx) {
    const token = await generateToken({}, {
      keyStore: deps.keyStore,
      subject: "user-id",
      tokenType: "at+jwt",
    });
    return {
      result: { status: 200, tokens: generateTokenResponse({ accessToken: token }) },
    };
  },
});

const myGrantModule = defineModule({
  name: "my-grant",
  requires: ["config", "keyStore"],
  contributes: {
    grants: { my_grant: myGrantFactory },
  },
});
```

`myGrantModule` を `createApp` に渡す `modules` 配列へ追加してください。`GrantFactory` は `GrantDependencies` を受け取り、その必須スロットは `config` と `keyStore` なので、モジュールはその両方を requires します。boot planner はグラントを `my_grant` で登録し、`/oauth/token` は `grantHandlerResolver` synthetic key を通じてそれにディスパッチします。

### YAML からクライアントとユーザーを読み込む

```typescript
import {
  loadYamlMap,
  ClientEntrySchema,
  UserEntrySchema,
  InMemoryClientRepository,
  InMemoryUserRepository,
} from "@o3co/auth-provider-core";

const clients = loadYamlMap("./clients.yaml", ClientEntrySchema);
const users = loadYamlMap("./users.yaml", UserEntrySchema);

const clientRepo = new InMemoryClientRepository(clients);
const userRepo = new InMemoryUserRepository(users);
```

### 拡張ポイント

任意の拡張ポイントが 5 つあります: composition root が埋める、あるいは空のままにするスロットか contribution 種別です。

#### MFA

多要素認証のポート。設計は [MFA の ADR](docs/adr/2026-09-25-multi-factor-authentication.md) にあり、MFA パッケージとそのアダプターが共有する。パッケージ `@o3co/auth-provider-mfa` は、standalone テンプレートが組み込むまで private である。セッション許可（下記）に第二要素の権限（second-factor authority）を宣言する `mfa` 要件を、そして TOTP 要素を寄与し、パスワードログインを最初の結び付けか第二要素のトランザクション（`mfa_enrollment_required`、`mfa_required`）で中断する。要素を検証してログインを完了するルートは、ステップ 8 の第 3 部（MFA の ADR のビルド順）で加わる。

- `MfaFactor` — 第二要素が実装する契約と、それが受け取るもの — [`src/mfa/factor.mts`](src/mfa/factor.mts)。要素は鍵、ストア、トランザクションのどれにも触れない: 受け取るのは開封済みのレコードのデータ、1 つのセレモニーの 2 つのリクエストの間に保持する状態、トランザクションの ID、そして鍵リングの下で代わりに作られる鍵付きダイジェスト（`MfaDigests`、照合するだけで復元しないコード用）である。検証は、要素が再利用を選ばない限り（`reusableChallenge`、メール要素）保留中のチャレンジを取り出す。鍵がリングから外れたダイジェストは `key_unavailable` を答え、障害として扱われ、誤ったコードにはならない（`MfaDigestMatch`）。要素はユーザーが登録できるかどうかを示す（`enrollable`）。チャレンジや登録の開始は、コーディネーターに送らせるコードを答えてよい（`MfaFactorMail`）: その目的（`account_email_proof` は除く）、コード（レスポンスには決して含めない）、その期限。ログインコードは、要素が登録されたアドレスの鍵付きダイジェストも持つ（`MfaLoginCodeMail`）。コーディネーターは、アカウントの現在のアドレスを正規化したものがそれと一致するときだけそこへ送り、一致しなければ再登録まで要素を拒否する。すべての呼び出しはトランザクションの下で行われる — ログインやステップアップ以外では、MFA パッケージが開く `enroll` トランザクションの下で。パッケージは要素を種別をキーに `contributes.mfaFactors` として提供する（`MfaFactorFactory`）。設定で要素が無効なら、ファクトリーは `null` を返す。boot は contribution を synthetic key `mfaFactorResolver` として射影し、`null` を返した種別はそこに現れない。その種別は占有されたままなので、同じ種別の 2 つ目の contribution は重複になる。resolver は `provides` ファクトリーの実行前から存在し、boot が contribution を登録するにつれて埋まるので、先に実行されるファクトリーがそれを保持して後で読める — MFA パッケージの要件はそれを `reach` のために読み、core はすべての要素が登録された後でその `reach` を読む。provides ファクトリーの実行中に読むと起動が拒否される。`kind` が提供時のキーと異なる要素は起動を拒否される。`@o3co/auth-provider-test-kit` の `mfaFactorContract` は要素のテストが実行するスイートで、そのテストが使うダブルは `@o3co/auth-provider-core/testing` にある: `createTestMfaFactor`（自明なプロトコルの要素。チャレンジの有無を選べ、証明は `testMfaFactorProofs`）と `createTestMfaDigests`（固定のテスト鍵による鍵付きダイジェスト）。
- `MailSender` — プロバイダーが発行したワンタイムコードが出ていくポートで、`mailSender` スロットを埋める — と `MailSend`、`MailSendResult`、閉じた一覧 `MAIL_PURPOSES`（`login_code`、`account_email_proof`、`email_factor_enrollment`） — [`src/mail/types.mts`](src/mail/types.mts)。`send` はメールの意味 — 目的、アカウントの subject、その時点のユーザーレコードのアドレス、コードとその期限 — を受け取り、リレーが保持したら `{ outcome: "delivered" }`、上限で拒まれたら `{ outcome: "refused_at_limit" }` を答え、後者をプロバイダーは `429` で答える。reject、またはそれ以外の答えは障害で、プロバイダーは `503` で答える。その答えの読み方は `mailSendOutcome` 一つで、`delivered` と `refused_at_limit` は、データプロパティが `outcome` だけのプレーンなレコードからしか読まない（[`src/mail/outcome.mts`](src/mail/outcome.mts)）。`normaliseMailAddress` は、プロバイダーがダイジェストにし比較するアドレスの唯一の綴り — 前後の空白を除き、NFC、ドメインは ASCII 形式、小文字 — で、アドレスでない値には `undefined` を答える（[`src/mail/address.mts`](src/mail/address.mts)）。レンダリング、配信、送信の上限は送信者のもの: `@o3co/auth-provider-standard` が標準のものを持つ。テストは `@o3co/auth-provider-core/testing` の `createRecordingMailSender()` を使う: 配信したものを保持し、上限に達した送信者（`refuseAtLimit`）や停止中のリレー（`failWith`、`recover`）の代わりにもなる。送信者の適合スイートは `@o3co/auth-provider-test-kit` の `mailSenderContract`。
- 登録の証人（witness）— 失われた要素ストアが「一度も登録していない」と読まれることを防ぐ（D12）: Store が `authenticate` で答える `User.mfaEnrolled`（`readMfaEnrollmentWitness()` でだけ読む: `enrolled`、`not_enrolled`（`false` か無し）、`malformed`（それ以外の値。`503` で答え、決して「登録していない」とは読まない））と、任意の `UserRepository.markMfaEnrolled(subject, enrolled)`。後者は `supportsMfaEnrollmentWitness()` で検出する — [`src/repositories/UserRepository.mts`](src/repositories/UserRepository.mts)。`InMemoryUserRepository` は `markMfaEnrolled` を持たない。
- `MfaFactorStore` — 対象ユーザーの登録済み要素を保持する場所 — と `MfaFactorRecord` — [`src/mfa/factorStore.mts`](src/mfa/factorStore.mts)。レコードの `data` はストアに届く前に封印され、ストアはそれを 1 バイトも変えずに保持する。`update` は `version` に対する compare-and-set で、`Number.MAX_SAFE_INTEGER` での更新は次のバージョンが安全な整数にならないため、何も書かずに `RangeError` になる（`checkMfaVersionAdvances`、[`src/mfa/version.mts`](src/mfa/version.mts)）。応答できないストアは「要素なし」と答えず例外を投げる。インプロセスのアダプター `createMemoryMfaFactorStore()` とそのモジュール `memoryMfaFactorStoreModule` は開発用と単一レプリカ用: 再起動で空になり、モジュールはそのことを一度だけ警告し（`mfa_factor_store_in_memory`）、`core.deployment.mode = "multi"` はこのモジュールを拒否する。`createMfaFactorStoreFactory()` / `registerBuiltinMfaFactorStores()` で名前から組み立てられる。すべてのアダプターは `@o3co/auth-provider-test-kit` のスイート `mfaFactorStoreContract` を実行し、テストキット自身のテストがそれをプロセス内のアダプターに対して走らせる。
- Store の MFA エンドポイントのワイヤ形式 — [`src/mfa/storeWire.mts`](src/mfa/storeWire.mts): list・create・update・delete・`markMfaEnrolled` の JSON ボディ（`MfaStoreFactor`、`MfaStoreFactorChanges`、`MfaStoreUpdateRequest` など）と、その変換（`toMfaStoreFactor`、`readMfaStoreFactor`、`fromMfaStoreFactor`、`readMfaStoreListAnswer`、`toMfaStoreFactorChanges`、`readMfaStoreFactorChanges`、`toMfaStoreUpdateRequest`）。Store のアダプターと、Store 自身の実装やその偽物が読む。時刻はエポックミリ秒で `…Ms` と名付け、値の無い省略可能なフィールドは省き、`null` を持つレコードは `readMfaStoreFactor` が読まない。ページが表示するフィールド — `id`・`kind`・`label` — がレコードの形から外れたものも読まない: `isMfaFactorId`（base64url の 22 文字）、`isMfaFactorKind`（ヒントのトークン）、`isMfaFactorLabel`（1〜`MFA_FACTOR_LABEL_MAX_LENGTH`、64 文字で、行を分けたり並びを変えたりする文字を含まない）。これらは [`src/mfa/factorStore.mts`](src/mfa/factorStore.mts) にある。一覧は丸ごと読まれる: 読めないレコード、別の主体を名指すレコード、同じ ID の二つのレコードのどれか一つで読めなくなる。書き手が作るものは読み手がそのまま読み戻し、読み手が拒むものは書き手が `RangeError` で拒む。更新はレコードを `subject` と `id` で名指し、期待するバージョンと、変更として `data`・`label`・`lastUsedAtMs` だけを運び、他のフィールドを持つ変更は読まれない。各応答の意味は [`@o3co/auth-provider-foundation`](../foundation/README.md#the-stores-mfa-endpoints) が定める。
- `MfaTransactionStore` — MFA のトランザクションと対象ユーザーのロック状態を保持する場所 — と `MfaTransaction`、`MfaTransactionPatch`、`MfaLockoutPolicy` — [`src/mfa/transactionStore.mts`](src/mfa/transactionStore.mts)。トランザクションは第二要素の 1 回のセレモニーの使い捨ての記録で、それを始めたものに `binding` で結び付けられる — `MfaTransactionBinding` は `kind` で区別される共用体で、現在は `{ kind: "session", id }`（`MfaSessionBinding`）だけ（#742）— ストアはそれを丸ごと保持する。どの利用も結び付けを種類も含めて丸ごと比較し（`isMfaTransactionBoundTo`）、それを通してトランザクションを読む（`getBoundMfaTransaction`。別のものに結び付いたトランザクションは未知の id として答える）。`reserveAttempt`、`takeChallenge`、`consume` はアトミックなので、同時に飛んでいる試行はそれぞれ消費され、チャレンジは一度だけ答えられ、トランザクションを消費する検証は 1 つだけである。`create` は型が認めない値のフィールド — 知らない種類の結び付けや、空の id の結び付けもそこに含まれる — と、新しい記録のカウンターで始まらないトランザクションを拒否し、トランザクションが持つフィールドだけを保持する（`newMfaTransactionRecord`）。`update` はパッチのキーだけを書き — 値は設定し、`null` は空にできるフィールドを消し、`undefined` は無いものとして扱い、それ以外は `RangeError`（`mfaTransactionPatchWrites`）— 要件を取り消す遷移を拒否する: 必須のメール証明を満たす以外の変更、満たされた証明の取り消し、`enrollment` の引き下げ（`checkMfaTransactionTransitions`）。さらに `Number.MAX_SAFE_INTEGER` での更新は、次のバージョンが安全な整数にならないため、何かを読み書きする前に `RangeError` で拒否する（`checkMfaVersionAdvances`。要素ストアも呼ぶ）。すべてのアダプターがこの 4 つを呼ぶ。どの操作も、ストア自身の時計で `expiresAtMs` 以降のトランザクションを存在しないものとして答える — `reserveAttempt` と `takeChallenge` も同じで、何も消費せず何も取り出さない — 共有バックエンドの時計が何と言おうと。対象ユーザーの状態は推測可能な証明に対するロックで、呼び出し側それぞれが渡す時刻で判断するので、呼び出し側の時計は揃っていなければならない: 連続した失敗（`threshold` 回の失敗から始まり `maxSeconds` まで倍になる短いバックオフで、最後のロックが終わってから — ロックの前なら直前の失敗から — `memorySeconds` で忘れられる。`hardLimit` に達すると免除要素での成功まで保留。成功は自分の予約までの連続を終わらせる）、そしてどの成功も払い戻さず、どの試行も迂回しない任意の連続 7 日間（`MFA_WEEKLY_WINDOW_MS`）の失敗の週次予算。拒否された予約は、試行が通された後の最初の拒否かどうかを答える（`first`）ので、ホールドの始まりをそれを繰り返す拒否と区別できる。免除要素での成功（`noteExemptSuccess`）は、その時刻までの連続を終わらせ、何も答えない。ストアは失敗を、数えなくなってから `MFA_CLOCK_SKEW_ALLOWANCE_MS`（1 日）後に、自分の時計より後にはならない時刻で判断して初めて忘れるので、それより少しだけ時計が進んでいる呼び出し側がほかの呼び出し側がまだ数える失敗を消すことはなく、大きく進んでいる呼び出し側も、どの対象ユーザーについても何も消さない。`clearSubjectState`（オペレーターのリセットとパスワード変更）は連続と週を消す。パスワード変更で週次予算が消えるのは意図したものである。ロックとは別に、ストアはオペレーターのリセットが求めたメール証明の要件を、対象ユーザーの次の最初の結び付けが消費するまで保持する（`requireEmailProofAtNextBinding`、`emailProofRequiredAtNextBinding`、`consumeEmailProofRequirement`）。`clearSubjectState` はそれを消さない。`checkMfaLockoutPolicy()` はストアが適用できないポリシーを `RangeError` で拒否する。`hardLimit` を超える `threshold` や、NIST の 100（`MFA_LOCKOUT_MAX_HARD_LIMIT`）を超える `hardLimit` もそこに含まれる。インプロセスのアダプター `createMemoryMfaTransactionStore()` と `memoryMfaTransactionStoreModule` は開発用と単一レプリカ用で、`core.deployment.mode = "multi"` では拒否される。このアダプターが保持するトランザクションは `core-mfa-transaction-store-memory.maxEntries` 件まで（`DEFAULT_MEMORY_MFA_TRANSACTION_STORE_MAX_ENTRIES`、10 万件）で、上限に達すると生きているトランザクションを追い出さず、新しいトランザクションをストア障害 `MfaTransactionStoreFullError` として拒否する。`createMfaTransactionStoreFactory()` / `registerBuiltinMfaTransactionStores()` で名前から組み立てられる。すべてのアダプターは [`src/mfa/__tests__/transactionStore.contract.mts`](src/mfa/__tests__/transactionStore.contract.mts) を実行する。
- セッションの唯一の読み方（`sessionAuthentication`、`vouchedAmr`、`SessionAuthentication`）は、`UserSession.authentication` ができる前に書かれたセッションを読むときに分割し、`requirementSession(session)` はセッション要件がそのセッションについて問われる入力を、`requirementSessionFromAmr` は生きたセッションを持たないトークンについて問われる入力を組み立てる。同じファイルに、各ログイン経路が記録するもの（`passwordSessionAuthentication`、`federatedSessionAuthentication`）、フェデレーションの上流 IdP の `amr` を数えるか（`federationTrustsUpstreamAmr`、`federations.<name>.trustUpstreamAmr`）、検証された第 2 要素がセッションをどうするか（`sessionAfterSecondFactor`、`checkSecondFactorEvent`）、ストアが `authentication` として記録してよいもの（`recordableSessionAuthentication`）がある — [`src/user-sessions/authentication.mts`](src/user-sessions/authentication.mts)。このプロバイダーが記録する `amr` の値（`PASSWORD_AMR`、`FEDERATED_AMR`、`OTP_AMR`、`HARDWARE_KEY_AMR`、`SOFTWARE_KEY_AMR`、`MFA_AMR`、`EMAIL_OTP_AMR`、`RECOVERY_CODE_AMR`）と、検証された要素がセッションの `amr` に加えるもの（`composeAmr`） — [`src/grants/authenticationClaims.mts`](src/grants/authenticationClaims.mts)。
- core は要素を同梱しない: MFA パッケージが TOTP 要素（`mfaTotpFactorModule`）を寄与し、`@o3co/auth-provider-webauthn` はパスキーを、まだ `mfaFactors` contribution ではなくグラント（`contributes.grants`）として提供する（MFA の ADR のビルド順のステップ 18）。

#### セッション許可

認証済みブラウザーセッションを使うすべての利用側が呼ぶ唯一の判断と、それを拡張する要件の契約。設計は [セッション許可の ADR](docs/adr/2026-09-28-session-admission.md) にある。判断が保証すること — 検査の順序、何が失敗側に倒れるか、何がブランド付きで何が拒否されるか — は [`src/session-admission/README.md`](src/session-admission/README.md) にある。この節は、公開された各名前が何のためにあり、どこで定義されているかを示す: 許可の関数とクレームのビルダーは [`src/session-admission/admit.mts`](src/session-admission/admit.mts)、型と要件の契約は [`src/session-admission/requirement.mts`](src/session-admission/requirement.mts)、グレードと利用側がアクションについて登録するものは [`src/session-admission/actions.mts`](src/session-admission/actions.mts)。

- **利用側**は `admitSession(deps, request)` を呼び、それが答える `Admission` を自分のプロトコルに対応付ける。`step_up` は要件のページを登録されたとおりに持つ（`RegisteredStepUpPage`）: 登録時に 1 度だけ発行者（`oauth.jwt.issuer`）で解決された `page.href` — ページの params をクエリーに載せた、戻り先のパラメーターの無い一つの絶対 URL — で、利用側はそれを返すかそこへ遷移し、自分でページを解決する利用側はない。リクエストが持つ `SessionClaim` はコアのビルダー — `cookieClaim`、`codeClaimFirstRead` と `codeClaimRevalidation`、`linkClaim`、`tokenClaim` — のどれかが作ったもので、利用側が作ったものではない。アクションは、利用側のモジュールが `contributes.admissionActions` に登録したアクションの名前で渡す。登録は `AdmissionActionDeclaration`、`{ grade }` で、グレードは `remediation` を除く `ADMISSION_GRADES` のいずれか（`ActionGrade`）。許可は要件に、そのアクションが登録したグレードを渡し、何も登録していない名前は拒否する。デプロイメント自身のルートも、同梱の利用側と同じように自分のアクションを登録する。`grants_nothing` は、レコードが運ぶ許可（Cookie、コード、リンク）を MFA 要件のベースラインの対象から外す。トークンは、グレードにかかわらずトークン自身の `amr` で判断される。ブートは登録された各アクションを、そのグレードと登録したモジュールとともに記録する（`admission_actions_registered`）。コンポジションが手でマウントしうるハンドラーを持つパッケージは、それが許可を求めるアクションを公開する（`DEVICE_GRANT_ADMISSION_ACTIONS`、`OAUTH_ROUTER_ADMISSION_ACTIONS`）。それらを登録していないリゾルバーでは、ハンドラーは組み立てを拒否する。`deps`（`AdmissionDeps`）は利用側自身のスロットと、利用側が `requires` に挙げる合成キー `sessionRequirementResolver`。手で組み立てる利用側のファクトリーはリゾルバを必須のオプションとして受け取り、組み立て時に `checkResolver(requirements, factoryName, admits)` で検査する。無いリゾルバーや偽のリゾルバー、`admits` のアクションが登録されていないリゾルバーは、ファクトリー名を添えて拒否される。テストは `@o3co/auth-provider-core/testing` の `resolverForTests` で作り、利用側が許可を求めるアクションを登録する（`{ actions }`）。`unavailable` の答えには、すべての利用側が `describeAdmissionOutage(store)` の文言をクライアントに返す。
- **ログイン**は、パスワードログインのプライマリを `passwordPrimary(facts)` で作って `admitPrimary(deps, primary)` に問う。答えは、セッションを書くための `Establishment` か、答えるべき中断である（`isEstablishment`、`isInterruptAdmission`）。フェデレーションのコールバックは問わずに `establishWithoutAsking(login)` で確立を作る。中断を完了した要件は、自分のレコードに保持した `PrimaryContinuation` を添えて `resumePrimary(deps, continuation, completed)` を呼ぶ。`checkPrimaryContinuation`（[`src/session-admission/primary.mts`](src/session-admission/primary.mts)）はそのレコードが従う形で、MFA トランザクションストアの `create` はログインの継続をそれで検査する。これは登録を知らず、各エントリをその要件の宣言に照らすのは `resumePrimary` である。`@o3co/auth-provider-session` の `establishSession` と `answerInterruption` は、これらの答えを受け取る。要件の完了処理 — MFA パッケージのもの — はそれらに `loginCompletion` スロットを通して到達し、その契約 — `LoginCompletion` と、その呼び出し・レポーター・結果の型 — は [`src/session-admission/login-completion.mts`](src/session-admission/login-completion.mts) にある（[#728](https://github.com/o3co/auth.provider/issues/728)）。
- **要件**は `SessionRequirement` で、`name` をキーに `contributes.sessionRequirements` として寄与され、コンポジションは期待するものを `core.sessionRequirements.expected` に書く。要件自身のルートは、ファクトリーが返したオブジェクトに `issuedRemediationActions(requirement)` が与える remediation アクションで許可を求める。要件はアクションのグレードで判断し、`ADMISSION_GRADES` のすべてに答え、アクションの名前では判断しない。`checkStepUpPage` はその `stepUpPage` が従う規則、`isHintToken` は中断のヒント値の文法。`secondFactorAuthority` を宣言した要件が、名前にかかわらず、第二要素（`SECOND_FACTOR_AMR`、`mfaAt`）を保証してよい唯一の要件で、ブートはそれを MFA のポートに結び付ける。宣言できるのは一つまでで、二つ目はブートを拒否する（`duplicate-second-factor-authority`）。`@o3co/auth-provider-core/testing` の `sessionRequirementContract` はすべての要件が実行するスイート。
- **`acr` の語彙** — `readAcrTable`、`stepUpReach`、`producibleAmr`、`vouchableAcrTable`、`SECOND_FACTOR_AMR`。oauth の満たせないエントリーの切り落としと discovery が読む — は [`src/session-admission/acr.mts`](src/session-admission/acr.mts)。

#### 監査（Audit）

- `AuditSink.record(event)` は fire-and-forget
- Factory: `createAuditSinkFactory()`、built-in `"console"` は `registerBuiltinAuditSinks()` で登録
- Sink のエラーは core 側で握りつぶす — audit 失敗で認証フローがブロックされることはない
- 組み込みのイベントはすべて `recordAuditEvent(sink, event)`（[`src/audit/factory.mts`](src/audit/factory.mts)）を通ってシンクに届く — `emitAuditEvent` はこれを呼んで切り離し、シンクを待つ発行者（federation grants）は直接呼んでシンクの Promise を受け取る。シンクには、`ip` を IPv4 か IPv6 のアドレス（`net.isIP`、IPv6 の `%zone` は取り除く）に限り、それ以外なら省いて — `ip` を IP 型に対応づける SIEM は `X-Forwarded-For: x` だけでイベント全体を拒否する — 、`userAgent` を `auditErrorText` と同じくサニタイズして切り詰め（RFC 6749 の NQSCHAR、それ以外は `?`、最大 200 文字）て渡す。どちらも文字列でなければ落とす。`trust proxy` の下では `req.ip` は呼び出し元が `X-Forwarded-For` に書いたものであり、User-Agent は呼び出し元自身のヘッダーだからである。通常のアドレスや User-Agent はそのまま運ばれ、イベントのキーの順序は変わらず、同期的に throw したり Promise でないものを返したりするシンクがルートに throw を返すこともない。`emitAuditEvent` のほかに直接呼ぶ発行者が二つある: federation-grants のルートのブリッジ（シンクの Promise を返し、core が待ち時間を区切り、シャットダウンが待ちきる）と、oauth の subject-revocation の監査役（シンクを待たず、拒否をログに残す: `federation_grant_audit_failed`）。[`logErrorProjection.drift.test.mts`](src/__tests__/logErrorProjection.drift.test.mts) が、ワークスペースのほかのどこもシンクに直接書かないことを確かめる
- イベントが報告するエラーは `details.cause` に `auditedError(err)`（[`src/audit/auditedError.mts`](src/audit/auditedError.mts)）として載せる: `{ name, code?, cause?: { name, code? } }`。`loggableError` が読む name と code、およびその cause を 1 段だけ、サニタイズして切り詰めたもので、メッセージは運ばない。シンクは他のシステムが読む記録であり、ストアや IdP のメッセージは相手側の文字列だからである（Redis の応答が引用する引数、JSON のパースエラーが引用する入力、上流の説明）。`rate_limit.unavailable`、`introspect.store_unavailable`、`federation.logout.idp_unreachable` がこれを運ぶ
- `details` の各キーはどのイベントでも型を 1 つに保つ。フィールドの型を最初に見たもので固定するシンク（Elasticsearch の dynamic mapping、BigQuery のスキーマ、Datadog のファセット）は食い違うイベントを落とすからである: `details.error` は現れるところではどこでも文字列（OAuth のコード、理由）で、`details.cause` の code も文字列。[`AuditEventDetails`](src/audit/types.mts) が両方のキーを型付けし、[`auditEventInventory.drift.test.mts`](src/audit/__tests__/auditEventInventory.drift.test.mts) がすべての発行箇所を読んで確かめる

##### details の契約: `AuditEventDetails` と `AuditedError`

`AuditEvent.details` は [`AuditEventDetails`](src/audit/types.mts) である。開いたレコードだが、2 つのキーはどのイベントも別の型を与えられないよう型付けされている:

| キー | 型 | 中身 |
| --- | --- | --- |
| `details.error` | `string` | OAuth のエラーコードか拒否の理由。エラーオブジェクトやエラーのメッセージは入れない |
| `details.cause` | [`AuditedError`](src/audit/auditedError.mts) | イベントが報告するエラー: `{ name: string, code?: string, cause?: { name: string, code?: string } }` |

ほかのキーは開いているが、それを運ぶイベントの間で型を 1 つに保つことが期待される。

- **独自の発行者**（`emitAuditEvent` か `recordAuditEvent` を呼ぶモジュール、イベントを組み立てるシンクのラッパー）— `sink.record` を自分で呼ぶものは `ip` と `userAgent` の上限を通らない:
  - 報告するエラーは `details.cause` に、`auditedError(err)` で作ったものだけを載せる;
  - エラーオブジェクト、そのメッセージ、スタックを `details` のどこにも書かない;
  - `details.error` には文字列だけを書く。

  オブジェクトリテラルで書いたイベントは、この 2 つのキーについてコンパイラーが検査する。先に `Record<string, unknown>` として組み立てた `details` は検査されないので、それを組み立てる発行者は自分でこの規則を守る。
- **独自のシンク**（`AuditSink` の実装、イベントを中継するラッパー）:
  - `details.error` は文字列、`details.cause` は `AuditedError` であることを前提にしてよい;
  - details を変換・秘匿するときもその型を保つ: 運ばない `cause` は `AuditedError` に置き換える（たとえば `{ name: "[redacted]" }`）。文字列やメッセージには置き換えない;
  - キーを落としてもよいが、型を変えてはいけない。

  `AuditedError` の name と code はすべて、`"` と `\` を除く印字可能な ASCII に収められ、200 文字で切り詰め済みである。

#### レートリミッター

- `RateLimiter.check(key, ctx)` で atomic check + increment
- Factory: `createRateLimiterFactory()`。`registerBuiltinRateLimiters()` が登録するのは `"memory"` だけ。`"redis"` バックエンドは `@o3co/auth-provider-redis`（`redisRateLimiterBuilder`、または宣言的な `redisRateLimiterModule`）にあり、ここで登録されないことを `ratelimit/__tests__/factory.test.mts` が検査している
- deny 時には core が 429 + `Retry-After` で応答。判定の `reason` を RFC 6749 の文字の範囲で `error_description` とし、ないとき・空のとき・文字列でないときは `Rate limit exceeded` とする
- モジュールは、自分がキーにするすべてのプレフィックスについて、自分の設定から読んだ予算か `null` を `rateLimitBudgets` の contribution として寄与する。各パッケージの README がそのプレフィックスを挙げる。core はそれらを `rateLimitBudgetResolver` のビューに合成し、2 つのモジュールが同じプレフィックスを寄与すること（よって他のモジュールのプレフィックスは主張できない）、リミッターのキーが持てないプレフィックス、ホスト独自のコレクター、そして置き換える予算を緩める上書き — `limit` が大きい、または `windowSeconds` が短い。`null` の側は配線されたリミッターの `defaultLimit`（`RateLimiter.defaultLimit`）とみなし、宣言がなければその上書きは拒否する — を拒否する。予算はパース済みの数値である（環境変数の文字列は拒否される）。`null` の予算のプレフィックスは、リミッターの `defaultLimit` に従う。core はどのパッケージの予算も名指しせず、設定から読むこともない。boot は `rate_limit_budgets_registered`（info）を出す: 配線されたリミッターの `kind` とガードが適用する障害時ポリシー、各プレフィックスの寄与された予算、それを設定したモジュールと、寄与か上書きか — リミッター自身の `limits` の項目はその予算に優先し、表示されない。寄与や上書きの予算の窓は最長 1 年（`isBoundedRateLimitSpec`）で、この上限は時刻に依存しない
- 同梱の 2 つのリミッターは、キーの予算を一つのルックアップ `createRateLimitBudgetLookup`（[`src/ratelimit/budgetLookup.mts`](src/ratelimit/budgetLookup.mts)）から得る: キーのプレフィックスに対するリミッター自身の `limits` の項目、なければ寄与された予算（ルックアップごとに一度だけ読んで凍結した複製を検査する。範囲外の予算はチェックを障害にする）、なければ `defaultLimit`。ビルダーの経路 — `registerBuiltinRateLimiters` と Redis パッケージの `redisRateLimiterBuilder` — は自分の `limits` と `defaultLimit` からリミッターを作り、寄与された予算を読まない。読むのはリミッターモジュールである
- ガードの障害時ポリシーはリミッター自身の `failMode` で、ガードまたはポリシー（`checkWithFailMode` が受け取る `createRateLimitPolicy`）を作るときに一度だけ読んで検査する: `open` ならリクエストを通し、`closed` または宣言なしは `503` を返し、それ以外の値や読めない `failMode` は作成を拒否する。プロセス内のリミッターは宣言しない。`redis-rate-limiter.failMode` が決めるのは `redisRateLimiterModule` が作るリミッターだけで、ホスト独自のリミッターやラッパーは自分のものを答える（ラッパーは `failMode` を引き継ぐ）。そのキーの旧パス `rateLimit.failMode` が `open` なのに配線されたリミッターがそうでないとき、boot は `rate_limit_fail_mode_not_applied` を警告する

#### リフレッシュトークンファミリー（RFC 6819 §5.2.2.3 の replay 検出）

- ポートは [`src/refresh-token-family/types.mts`](src/refresh-token-family/types.mts) の `RefreshTokenFamilyRotation` / `RefreshTokenFamilyRevocation`
- すべての `rt+jwt` は `family_id` claim を持つ
- `refreshTokenFamilyRotation` / `refreshTokenFamilyRevocation` スロット（ファミリーストア — `memoryRefreshTokenFamilyStoreModule` または Redis アダプター — と `defaultRefreshTokenFamilyRotationModule`、`defaultRefreshTokenFamilyRevocationModule`）を提供すると replay 検出と family revocation が働く。`refresh_token` グラントが有効なとき、両方が配線されていなければ `oauthAuthorizationModule` は起動を拒否する（[oauth パッケージ](../oauth/README.ja.md#refresh_token)）
- 失効したファミリーは、それが発行し得た最後のアクセストークンが受け入れられなくなるまで記憶される。失効させる書き込み（revocation、またはファミリーを失効させる replay）は、ファミリー自身の期限と「現在 + `oauth.accessToken.maxExpiresIn`」の遅い方に `REVOCATION_RETENTION_ALLOWANCE_MS` を足した時刻まで記録を保持する（[`src/refresh-token-family/retention.mts`](src/refresh-token-family/retention.mts)）。記録がすでに期限切れのファミリーも失効として記録される。`createRefreshTokenFamilyRevocation` と `createRefreshTokenFamilyRotation` はこの horizon を `accessTokenHorizonMs`（`resolveFamilyAccessTokenHorizonMs(config)`）として受け取り、デフォルトのモジュールは `config` から読む
- memory ストアは再起動で失効済みを含むすべてのファミリーを忘れるので、再起動前に失効したファミリーのアクセストークンは、再起動後は期限まで family チェックを通過する。単一レプリカ・開発用に限る

#### GrantPolicyHook（scope / audience / token exchange のポリシー）

- `GrantPolicyHook.evaluate(request, ctx)` は allow（narrowing 可）/ deny を返す
- deny の `error` は RFC 6749 のエラーコード `1*NQSCHAR`（空でない、`"` と `\` を除く印字可能な ASCII）でなければならない（`isWellFormedErrorCode`、[`errors/envelope.mts`](src/errors/envelope.mts)）。それ以外のコードを `/oauth/token` は `invalid_request`、`/oauth/authorize` は `access_denied` として返し、ポリシーのコードをサニタイズしてログに残す
- `/oauth/authorize` で 1 回だけ評価、`/oauth/token` は Code record に persist された `grantedScope` / `grantedAudience` を再利用（`authorization_code` では再評価しない）
- その他のグラント（refresh / client_credentials / token-exchange）はトークンエンドポイントで評価

5 つとも任意です。audit sink は absence policy（`AUDIT_SINK_ABSENCE_POLICY`）を持ちます: スロットを埋めるものがなければ、設定で不在を宣言する（`audit.sink.type = "none"`）必要があり、宣言がなければ boot は拒否されます。他の 4 つは、ないときは単に無効です。

### トークンバインディング機構

sender-constrained なトークンバインディングは第一級の拡張面です。`tokenBindingMechanisms` contribution スロットにより、モジュールは core を fork せずに独自の `TokenBindingMechanism` を提供できます。設計の根拠は [ADR 2026-05-20-token-binding-first-class-abstraction.md](docs/adr/2026-05-20-token-binding-first-class-abstraction.md) を参照してください。

#### 公開型

- `TokenBinding`（[`src/grants/tokenBinding.mts`](src/grants/tokenBinding.mts)）— 横断的なバインディングの形: `kind`、`confirmation`、そして機構がレスポンスに載せるよう求める任意の `responseHeaders`（`DPoP-Nonce`）。`kind` は開いているので、downstream の機構が追加的に拡張できる。
- `Confirmation`（[`src/grants/confirmation.mts`](src/grants/confirmation.mts)）— RFC 7800 の `cnf` claim の payload で、`jkt` と `x5t#S256` の閉じた union。variant の追加は core の semver-minor 変更。
- `TokenBindingMechanism`（[`src/middleware/tokenBinding.mts`](src/middleware/tokenBinding.mts)）— 動詞側の抽象: `kind`、`intentExplicit`（DPoP のようなヘッダー駆動の機構は `true`、mTLS のような ambient な機構は `false`）、`extract(req)`。
- `TokenBindingRefusal`（同じファイル）— `extract` が拒否するときに throw するもの。duck type で読まれ、3 種類の応答のどれにあたるかは機構自身が述べる。提示された material への判定は、トークンエンドポイントでは `400 <code>`、保護リソースではチャレンジ付きの `401 invalid_token`。`retryInstruction`（DPoP の `use_dpop_nonce`）は、トークンエンドポイントでは `400 <code>`、保護リソースではその code でチャレンジする `401`。`unavailable` の障害 — 読めない replay store のように、機構が判定に至れなかった場合 — はどちらでも `503 <code>` でチャレンジなし。クレデンシャルに非はないからである。`503` を返すディスパッチャーが、その error レベルの 1 行 — `token_binding_unavailable` または `protected_resource_binding_unavailable`、`mechanism` と `code` 付き — を持つので、機構は障害を自分でログに出す必要がなく、出すべきでもない。障害の拒否には `reason`（機構自身の呼び名。下の判定の行と同じく code の形のときだけログに出し、送信はしない）と、判定を止めた失敗を標準の `cause` として添えられ、その行は `cause` の `loggableError` 射影を持つ。判定は warn の 1 行 — `token_binding_proof_invalid` または `protected_resource_binding_proof_invalid` — で、`mechanism`、`code`、code の形をした拒否の `reason`、そして拒否の `loggableError` 射影を `err` として持ち、その `cause` が機構に拒否させたエラー（パーサーやライブラリのもの）である。したがって判定の拒否も `reason` を述べ、パーサーやライブラリのエラーはメッセージではなく `cause` として運ぶ。保護リソースでの `401 invalid_token` による拒否はすべて、warn の `sender_constraint_rejected` の 1 行にもなり（`503` の障害と、再試行の指示による `401` — DPoP の `use_dpop_nonce` — はならない）、その `rejection` が要求を拒否した sender constraint の規則 — `compound_cnf`、`scheme_mismatch`、`proof_invalid`、`no_matching_binding` — を `scheme` と `site` とともに名指す。このフィールドは以前 `reason` だったが、それは判定の行が機構自身の呼び名に使う名前である。ディスパッチャーが機構の code を知ることはない。
- `TokenBindingMechanismFactory<Deps>`（[`src/modules/manifest/contributes-map.mts`](src/modules/manifest/contributes-map.mts)）— contribution スロットのエントリー: 機構を返すか、設定でモジュールが無効なら `null` を返す（secure-default の opt-in）。

#### 組み込みの機構パッケージ

- `@o3co/auth-provider-dpop` — RFC 9449 DPoP（explicit-intent）。
- `@o3co/auth-provider-mtls` — RFC 8705 mTLS の証明書バインドトークン（ambient）。

どちらのパッケージも `tokenBindingMechanisms` で contribute します。core の `assembleApp` はすべての contribution を集め、null を除き、`/oauth/token` にマウントする単一の `tokenBindingMw` を合成します。それと `grantMiddleware` の contribution が走るのはトークンエンドポイントだけ — `/oauth/token` への POST（末尾スラッシュの有無、大文字小文字を問わない）— で、ほかのメソッドやその下の長いパスでは走りません。その中から見えるリクエストは `/oauth/token` への `use` マウントが見せるもの（`req.path` は `/`、`req.baseUrl` は `/oauth/token` で終わる）です。sender-constraint チェックが除外するのもちょうど同じリクエストです。

#### ディスパッチポリシー

複数の機構が組み込まれたとき、`oauth.tokenBinding.dispatch-policy`（core 同梱の `CoreConfigSchema` にある — single source of truth）が調停します:

- `intent-explicit`（既定）— ambient より explicit-intent の機構を優先する。
- `strict-mutual-exclusion` — 2 つ以上の機構の `extract` がバインディングを返したら `invalid_request` で拒否する。

環境変数での上書き: `OAUTH_TOKEN_BINDING_DISPATCH_POLICY`。

#### グラント側の許可リスト

`@o3co/auth-provider-oauth` のグラントが `cnf` バインドの RT を発行するのは、明示的な許可リストにある機構（`bindingIsDpop || bindingIsMtls`）の場合だけです。バインド RT の発行に新しい機構を加えるなら、リフレッシュ時の強制マトリクスを同じ PR に入れなければなりません — §9.2 のマトリクスの型は [`packages/oauth`](../oauth/) を参照。

### セッションストアとフェデレーショントークン

フェデレーションと OIDC 対応のための任意スロットの 2 つのグループで、モジュール（`memorySessionStoresModule`、`memoryFederationTokenStoreModule`）か Redis アダプターが提供します:

- `userSessionStore` と、sid / subject をキーとするその兄弟: セッションのメタデータ（auth_time、セッションがどう確立されたか — `authentication` —、アクティブな RP、family ID、OIDC claim）、ログアウトの fan-out 用インデックス、subject 単位の失効 — [`src/user-sessions/README.md`](src/user-sessions/README.md)。`SupportsSecondFactorUpdate` — `UserSessionStore` の任意の capability で、生きているセッションで検証された第 2 要素を記録する（`recordSecondFactor`）。ステップアップに必要。同梱の 2 つのストアはどちらも実装している。`supportsSecondFactorUpdate(store)` ガードで検出する。
- `federationTokenStore`: `(sid, federationName)` をキーとする上流 IdP のトークンで、ログアウトで削除される。Redis アダプターは `refresh_token` を AES-256-GCM で暗号化し、`allow-plaintext` は opt-in で警告を出力する。ストアは `FederationTokens` のすべてのフィールドを round-trip させなければならない — `expiresAt: null` を含め、記録がないフィールドは `null` ではなく `undefined` で返す。フィールドごとのポート契約は [src/README.md](src/README.md#federation-tokens) に、必須キーのためにストア実装者が変えることは [docs/upgrading-required-record-keys.md](../../docs/upgrading-required-record-keys.md) にある。

`@o3co/auth-provider-oauth` が両方を消費します: ログアウトと連鎖失効、id_token と `/userinfo`、`POST /oauth/federation/:name/token`。いずれかの `federations.<name>.enabled` が true のとき、`userSessionStore`、`sessionRPRegistry`、`sessionFamilyIndex`、`sessionFederationIndex`、`federationTokenStore`、`refreshTokenFamilyRevocation` のどれかが欠けた構成を boot は拒否します（`federation-stores-incomplete`）。

- `SupportsLock` — `FederationTokenStore` の任意の capability で、`(sid, federationName)` 単位の advisory lock を提供し、並行リフレッシュが上流に殺到するのを防ぐ。同梱の両ストアが実装しており、`supportsLock(store)` ガードで検出する。その背後のロック実装 — core の `createInProcessLock`（`src/federation-tokens/lock/memory.mts`）と `@o3co/auth-provider-redis` の `createRedisLock` — は内部実装で export されない。ロックが必要な独自ストアは代わりに `SupportsLock` を公開する。
- `Client.allowedAzpForFederationToken` — `Client` レコードの opt-in フラグ。ないときは `false`。`POST /oauth/federation/:name/token` を利用するクライアントは `true` に設定しなければならない。

### OIDC id_token とクレームフィルター

`authorization_code` グラントと `/oauth/userinfo` エンドポイントが使用する 2 つの低レベルヘルパー。

#### `generateIdToken`

`generateIdToken(opts)` は [`src/grants/idToken.mts`](src/grants/idToken.mts) にあり、そのオプション `GenerateIdTokenOptions` がその隣にあります。`expiresIn` のデフォルトは 3600 秒です。

OIDC id_token JWT（OIDC Core §2）に署名して返す。クレーム構成:

- `iss`、`sub`、`aud`、`exp`、`iat`、`jti` — 標準 JWT クレーム
- `auth_time` — `opts.authTime` をエポック秒に変換した値
- `sid` — バックチャネルログアウト用セッション識別子
- `azp` — authorized party、指定された場合のみ付与
- `nonce` — 認可リクエストから転送され、指定された場合にそのまま反映
- `amr`、`acr` — 呼び出し側が渡したとおり（`authorization_code` グラントは、セッションが保証する `amr` — `vouchedAmr` — とコードの `acr` を渡す）。空の `amr` は `[]` として出力せず省略する
- `filterClaimsByScope` によるスコープフィルター済みユーザークレーム

ヘッダーは `typ: "JWT"` を使用する — 標準綴りで、RFC 9068 の `at+jwt` と意図的に排他にしてあり、id_token が access-token 面を通ることはない。`id+jwt` を持つ id_token は通常の `typ` 不一致として拒否される。

#### `filterClaimsByScope`

`filterClaimsByScope(claims, scopes)`（[`src/grants/claimFilter.mts`](src/grants/claimFilter.mts)）は `UserSessionClaims` を、付与されたスコープが許可する JWT 形のクレームのサブセットにマッピングする。厳格なホワイトリスト制 — 下表のマッピングのみを出力し、それ以外の `UserSessionClaims` のフィールド（例: `hd` のようなプロバイダー固有のフィールド）は一切転送しない。

| スコープ | 出力されるクレーム |
| --- | --- |
| `openid` | *(クレームなし — id_token 発行の可否を制御; `sub` は `generateIdToken` が付与)* |
| `profile` | `name`、`picture` |
| `email` | `email`、`email_verified` |
| `groups` | `groups` |

#### `/.well-known/openid-configuration`

OIDC Discovery 1.0 メタデータエンドポイント。`config.oauth.jwt.issuer` が設定され、かつ provider surface を宣言するモジュールがある（`oauthModule` が `discoveryMetadata` contribution に `providerRoot: true` を設定）場合に、core が合成して mount する。core は各モジュールの `discoveryMetadata` slice を 1 つのドキュメントに集約する。`issuer` と `id_token_signing_alg_values_supported` は core 自身のもので、モジュールは設定できない。必須フィールドを欠くドキュメントは boot を拒否させる（`discovery-document-invalid`）。response type を挙げながら `authorization_endpoint` を示さないドキュメントも、それを示しながら response type を挙げないドキュメントも同じく拒否される（RFC 8414 §2: クライアントは response type をそこで求める）。`authorization_code` グラントの無い構成は OAuth の認可サーバーであって OpenID Provider ではない: そのドキュメントは RFC 8414 に従い、OpenID Connect Discovery §3 なら要求する authorization endpoint を示さない。同じドキュメントを両方のパスで配信するので、どちらからでも issuer の鍵を探すリソースサーバーはそれを見つけ、OpenID Provider を探すリライングパーティーは見つけない。同梱モジュールが contribute する slice は以下のとおり — `oauthModule` の slice は [`packages/oauth/src/module.mts`](../oauth/src/module.mts) に定義され、`jwksModule` は `jwks_uri` を contribute する:

- `issuer`、`token_endpoint`、`userinfo_endpoint`、`introspection_endpoint`
- `authorization_endpoint` — `authorization_code` グラントが登録されているときだけ。`grant_types_supported` と同じレジストリから読む。`oauthModule` は同じ条件で `/authorize` をマウントする
- `jwks_uri` — 常に広告する（`jwksModule` が contribute）。issuer 設定済みの構成は `jwksModule` を必ず組み込む必要があり、欠如すると boot が `DiscoveryDocumentError` で fail-fast する。JWKS ルートが空の鍵セットを返すことはない: HS256 構成は `404 jwks_not_published`、非対称でも公開可能な鍵が 0 件なら `503 jwks_unavailable` を返し、いずれも `Cache-Control: no-store`。まったく答えられないキーストア（タイムアウトしたリモートの鍵サービス）も、ターミナルハンドラーの `500` ではなく同じ `503` になる。リライングパーティーは `503` を再試行するからである。ルーターに logger があれば（`jwksModule` は構成の logger を渡す）、この `503` を error レベルで `jwks_unavailable` としてログに出し、キーストアが throw したときはエラーの射影を添える。対称鍵の secret はどちらの経路でも公開されない。このルートが `200` を返すときは必ず 1 件以上の鍵を含む。`jwksModule` は自身のセクション `jwks` を読む: `path` は issuer の下で鍵セットを公開するパス（既定 `/.well-known/jwks.json`、`JWKS_PATH`）、`cacheMaxAge` は成功時の `Cache-Control: public, max-age`（秒、既定 300、`JWKS_CACHE_MAX_AGE`）。両方の変数は core 自身の `reference.conf` が束縛し、`oauth.jwt.jwksPath` と `oauth.jwt.jwksCacheMaxAge` は、このモジュールがインストールされている限り、これらのパスを示してブートを拒否する。
- `revocation_endpoint` — `POST /oauth/revoke` が**何かしら revoke できる**ときに広告する。判定はルート自身の解決規則に合わせた 2 本の腕からなる: refresh 側は `refreshTokenFamilyRevocation` が wire されていること、access 側は `accessTokenDenylist` が wire され**かつ** `oauth.revocation.accessToken` が `"unsupported"` でないこと（明示的な `"unsupported"` は wiring に関わらず access 側の経路を無効化する）。どちらか一方で足りる: RFC 7009 §2.2.1 は AS が片方の token type だけを revoke できる状況のために `unsupported_token_type` を定義しているので、refresh のみのエンドポイントも revocation endpoint であり、URL を隠せば logout 時に refresh token を revoke したい client が何も revoke できなくなる。**どちらの腕も無い**場合、ルートは RFC 7009 が要求する `200` を返しつつ何も revoke しないため、広告すれば起こらない revoke を約束することになる。どの *token type* を revoke するかは依然として discovery からは導出できない（RFC 7009 / RFC 8414 に token type 別のメタデータフィールドは無い）: access token 側の答えはエンドポイント自身が `unsupported_token_type` として返す。
- `response_types_supported` — `authorization_code` グラントがあれば `["code"]`、無ければ `[]`（RFC 8414 §2 はフィールド自体を要求する）
- `request_uri_parameter_supported: false` — `authorization_code` グラントがあるとき: OIDC Discovery は省略を `true` と読み、`/authorize` は `request_uri` を拒否する
- `client_id_metadata_document_supported: true` — `oauth.clientIdMetadataDocuments.enabled` が true で、consent store が wire され、`authorization_code` グラントが登録されているときだけ。[oauth パッケージの README](../oauth/README.md) を参照
- `subject_types_supported: ["public"]`
- `id_token_signing_alg_values_supported` — 設定された `KeyStore.algorithm` から導出
- `scopes_supported: ["openid", "profile", "email", "groups"]`
- `grant_types_supported` — `/oauth/token` が dispatch する grant handler registry から読む。つまりこの構成が実際に登録した grant だけが並び、それ以外は入らない。空でも出力する: RFC 8414 §2 は**省略**を `["authorization_code", "implicit"]` と解釈するため、省略すればこの AS が実装していない `implicit` を広告することになる。
- `token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"]`、`replaySeenSet` が wire されていれば `private_key_jwt` も加わる。`jwks` / `jwksUri` を登録したクライアントは、自分が署名した JWT（RFC 7523 §2.2）を提示し、それはその鍵で検証される。`iss = sub = client_id`、`aud` は issuer かトークンエンドポイント、`exp` は最大 1 時間先、`jti` は 1 回限りで `replaySeenSet` に記録される。**そのストアが条件**: ストアがなければ検証器は検査されていない `jti` を受け入れる代わりに `500 server_error` を返すので、この方式は守れる場所でだけ広告される — 上の `revocation_endpoint` と同じ「有効かつ完遂できる」規則。[oauth パッケージの README](../oauth/README.md#client-authentication-private_key_jwt-rfc-7523-22) を参照。
- `token_endpoint_auth_signing_alg_values_supported` — アサーションのアルゴリズムで、非対称のみ（`RS*`、`PS*`、`ES*`、`EdDSA`）。同じ一覧が introspection と revocation のエンドポイント向けに `*_endpoint_auth_signing_alg_values_supported` として出力される。3 つとも方式と一緒に動く: `replaySeenSet` が wire されていなければ方式と一緒に省略される。提供されない方式のアルゴリズムは、クライアントが行動に移せる何ものも伝えないから。
- `introspection_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"]`、同じ条件で `private_key_jwt` も加わる — `none` は無い: `/oauth/introspect` は RFC 7662 §2.1 に従い public client を拒否する。メタデータが言えないが運用者に必要なことが 2 つある: (a) RFC 6749 §2.3.1 は `client_secret_basic` で `client_id` と secret を base64 の**前に** form-urlencode することを要求するので、予約文字を含む `client_id` — `:` が Basic のフィールド区切りと読まれてしまうリソース URI — はパーセントエンコードしなければならない（`https%3A%2F%2Fapi.example.com`）。(b) 認証済みの呼び出し側は、`aud` がそのクライアントの `allowedAudiences` ∪ `{client_id}` に含まれるトークンを introspect できる。これにより、リソースサーバーは RFC 8707 のもとで自分のリソース URI 向けに発行されたトークンを introspect できる。どちらも [oauth パッケージの README](../oauth/README.md#introspection-which-tokens-a-caller-may-ask-about) に詳しくある。
- `revocation_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"]`、同じ条件で `private_key_jwt` も加わる — `revocation_endpoint` と同時に出力。RFC 7009 §2.1 が public client による自身の token の revoke を認めるため `none` を含む
- `acr_values_supported` — `authorization_code` グラントがあるとき、`oauth.authorize.acrValues` のキー（表が空でないとき）: セッションが保証する `amr` から `/authorize` が満たせる Authentication Context Class Reference。ただし、インストールされたものでは満たせないエントリーは除く（boot で落とす。MFA ADR の D15、oauth パッケージの README を参照）。エントリーが残らなければ省略され、そのとき `acr_values` は `unmet_authentication_requirements` になる。
- `code_challenge_methods_supported: ["S256"]` — `authorization_code` グラントがあるとき。`S256` のみ。`oauth.grants.authorization_code.pkce.supportedMethods` から導出は**しない**。この配列は server-wide メタデータであり、読んだ client は「このいずれかを使ってよい」と解釈する。`plain` はそれを満たさない（`/authorize` は RFC 9700 §2.1.1 に従い public client には即座に拒否する）ので載せない — client 単位の例外は、どちらの向きであれ server-wide 配列には属さない。
- `dpop_signing_alg_values_supported` — `dpop.enabled = true` のとき `@o3co/auth-provider-dpop` が contribute し、そのモジュールの `algWhitelist` をそのまま載せる（RFC 9449 §5.1）
- `tls_client_certificate_bound_access_tokens: true` — `mtls.enabled = true` のとき `@o3co/auth-provider-mtls` が contribute する（RFC 8705 §3.3）。それ以外では省略し、RFC はこれを `false` と定義している。`mtls.source` には依存しない: TLS layer 経由でも trusted-proxy header 経由でも token に載る `cnf["x5t#S256"]` は同じで、このフラグは token を説明するものだから。
- `end_session_endpoint`、および `backchannel_logout_supported`、`backchannel_logout_session_supported`、`frontchannel_logout_supported`、`frontchannel_logout_session_supported`（すべて `true`）— ログアウトの連鎖に必要なすべてのストアが wire されているとき: `userSessionStore`、`sessionRPRegistry`、`sessionFamilyIndex`、`sessionFederationIndex`、`federationTokenStore`、`refreshTokenFamilyRevocation`

### ログアウトヘルパー

`@o3co/auth-provider-oauth` の `POST /oauth/logout` が使用する低レベルヘルパーで、[`src/grants/logoutToken.mts`](src/grants/logoutToken.mts) にある。

#### `generateLogoutToken`

`generateLogoutToken(opts)` は隣に定義された `GenerateLogoutTokenOptions` を受け取る。`includeSid` のデフォルトは `true`、`expiresIn` は 300 秒。OIDC Back-Channel Logout 1.0 §2.4 の `logout_token` JWT に署名して返す。ヘッダーは `typ: logout+jwt`。クレーム構成: `iss`、`sub`、`aud`、`iat`、`exp`、`jti`、および `{ [BACKCHANNEL_LOGOUT_EVENT_URI]: {} }` を値に持つ `events`。デフォルトで `sid` を含む。`backchannel_logout_session_required: false` で登録した RP 向けには `includeSid: false` を指定する。`nonce` クレームは仕様 §2.4 の要件により常に含まれない。

#### `BACKCHANNEL_LOGOUT_EVENT_URI`

すべての `logout_token` の `events` クレームが持つ正規イベント URI、`http://schemas.openid.net/event/backchannel-logout`。downstream のコードとテストがこのリテラルを繰り返し書かずに参照できるようにエクスポートされている。

### Logger

[`src/logging/Logger.mts`](src/logging/Logger.mts) にある、pino 互換の構造的ロガー: `trace` / `debug` / `info` / `warn` / `error` / `fatal`（それぞれオブジェクト先頭・文字列先頭のどちらの呼び出しも受け付ける）と `child(bindings)`。pino のインスタンスはアダプターなしでこれを満たし、デフォルトは `consoleLogger`。任意の `logger` コンポーネントスロットでもある。

[`loggableError(err)`](src/logging/loggableError.mts) は、他のシステムと話すライブラリやストアから出てきたエラーの代わりに呼び出し箇所がロガーへ渡すもの。捕捉したエラーを報告するロガー呼び出しは — ワークスペースのすべてのパッケージの `src` でも、standalone テンプレートの `src` でも — すべてこれを通り、[`src/__tests__/logErrorProjection.drift.test.mts`](src/__tests__/logErrorProjection.drift.test.mts) がそれを保つ: 読むツリーはその `SOURCE_ROOTS` に列挙してあり、ワークスペースに追加したパッケージは列挙するまでこのテストを落とす。捕捉したエラーを代わりに少なくとも同じだけ厳しい別の射影に渡すファイルは、理由とともにそこに名前を挙げてある（core のトークンバインディングのディスパッチャー。その `unavailableLogFields` は拒否の `reason` と、その cause の `loggableError` だけを出す）。

理由: 解析した上流の応答から作られたエラーは、その応答が言ったことを何でも運ぶ — OAuth ライブラリは拒否したトークン応答を cause の連鎖に載せ、JSON パーサーは解析できなかったテキストを引用し、Redis の応答は拒否したコマンドを反復し、ioredis はそのコマンドの引数（`allow-plaintext` でのストアへの書き込みならトークンレコード）をエラーに載せる。射影がすること:

- **射影はただのデータで、ログの行は射影そのもの。** `message` を持たない: シリアライザーは文字列の `message` を持つ値を Error とみなして書き換える — pino の err シリアライザーは各 `cause` を一つのメッセージとスタックに畳み込み、cause のフィールドを何も書かず、`type` の上に名前を書く。pino の `err` と `errWithCause` シリアライザーは、同じ慣習に従う他のシリアライザーと同じく、それ以外の値をそのまま通す。そのため pino のデフォルトでも、standalone テンプレートの logger でも、`consoleLogger` でも、以下のすべてのフィールドがどの段でもログの行に届き、設定すべきシリアライザーは無い。どの段にも `name` があり、pino が自前の `type` を加えることはない。
- **`detail`** はエラーのメッセージ — 上の理由から `message` ではなく `detail`（RFC 7807 が個々の事象の人が読む説明に使う名前）— で、既知の引用の形を取り除く: `SyntaxError` の message は捨てる — V8 の `JSON.parse` も body-parser も入力を引用する — ` at position N`（10 桁まで）だけを `position` として残す。`YAMLException` の message はまるごと捨てる — js-yaml は問題箇所の前後の行を引用する。Redis の `, with args beginning with: …` は、どのクライアントのクラスが運んでいてもすべてのメッセージから切り取る。相手側がメッセージに書いたそれ以外のテキストは残る — 射影はそれをこのプロセス自身のテキストと区別できない — が、1 行にする: 行を分けたり画面上の並びを変えたりする文字（C0、DEL、C1、U+2028/U+2029、方向マーク U+200E・U+200F・U+061C、双方向テキストの埋め込み・上書き・分離の制御文字 U+202A–U+202E と U+2066–U+2069）はすべて `?` に置き換え、`"`、`\`、非 ASCII の文字を含むそれ以外の文字は残す。同じフィルターを `lineSafeText(text, maxLength = 256)` として公開している。エラーのものではない相手側のテキスト（mTLS 証明書のサブジェクト、証明書が名指す URL）をログに出すパッケージ向けで、切り詰めたときは `...` で示し、サロゲートペアの途中では切らない。4 以上の整数でない `maxLength` は `RangeError` である。
- **`error_description`** は意図して残す唯一の相手側の文字列 — 失効したグラントと壊れたクライアントを見分けるため: 最初の行だけ（Azure AD の AADSTS の行で、Trace ID の行は含まない）を、その行が RFC 6749 §5.2 の文字集合に収まるとき、トークンになりうる文字（`[A-Za-z0-9._~+/=-]`）が 20 文字以上続く最初の箇所を含む語の頭で切り、前後の空白を除いて残す — トークンの一部も、その語の切れ端も残らない。古い Spring の "Invalid refresh token: <トークン>" は "Invalid refresh token:" を、Azure AD の AADSTS700016 は "AADSTS700016: Application with identifier" を残し、Azure AD や Okta が示すリダイレクト URI は `https:` ごと落ちる — 何も残らなければ省く。
- **`stack`** はフレームを残し、メッセージを運ぶヘッダーは決して残さない: フレームは 10 個、2048 文字まで、cause のそれぞれでも同じ。残すのは、スタックが名前・コード・メッセージから決まるヘッダー全体 — `name: message`、Node の `name [code]: message`、メッセージが空ならさらに `name` か `name [code]` — で始まり、そのヘッダーで行が終わるときだけ。スタックが書かれた後に書き換えられたメッセージや、文字列でないメッセージでは、スタックを残さない。
- ほかに残すもの: `name`、文字列または数値の `code`、整数の `status`、文字列の `type`（body-parser の `entity.too.large`）、§5.2 の文字集合に収まる `error`、cause または `response` にある `Response` の `response: { status, contentType }`（ゲートウェイの 503 ページ）、そして同じ形の Error である cause（3 段まで）。
- **閉じた集合のフィールド**: ストアやクライアントのエラーが記録するもので、形の上で自由なテキストを持てないため残す。コードである自身の `reason` — `_` か `-` でつないだ小文字の語で 64 文字まで（Store の通信失敗の `unreachable`、チャレンジストアの `expired-at-issue`）— と、HTTP ステータス（100〜599）を持つ自身の `<word>Status` フィールドを 4 つまで（Store の拒否の `storeStatus`）。この種のフィールドは、Express がこのサーバーの応答として読むエラー自身の `status` とは別に上流の応答を記録するものなので、どのパッケージの名前もここに挙げず、それ自身の名前のまま残す。
- **AggregateError のメンバー**（任意のエラーの `errors` 配列）を `aggregateErrors` として: 先頭 5 つ（`LOGGED_AGGREGATE_MAX_ERRORS`）のうち Error であるものを、cause と同じように同じ 3 段の中で射影する。`aggregateErrorsOmitted` はそこに入らなかったメンバーの数。`aggregateErrors` は pino が生の AggregateError のメンバーを書くときの名前なので、一つのクエリで両方が見つかる。`handle.dispose()` の失敗は、失敗したすべての cleanup の名前とコードとともにログに出る。
- **ストアのエラーが応答したコマンド**を名前だけ: ioredis の `command: { name, args }` から、名前が英数字と `_` による 32 文字までのトークンか、それを一つの `.` でつないだ二つであるときに `command: { name }` を残す — どの Redis コマンドが失敗したか（`set`、`evalsha`、`hello`、モジュールの `JSON.SET`）であって、その引数は決して残さない。ioredis 自身と同じ位置に置くので、`err.command.name` へのクエリは生の行も射影した行も同じように読める。文字列の `command`（execa のシェルコマンド行）は残さない。
- **1 行あたりの予算**: 射影は多くとも 16 個（`LOGGED_MAX_PROJECTIONS`）— エラー、その cause、そのメンバーを合わせて — で、近いものから取る。そのためエラー自身の cause とメンバーが、それらの cause やメンバーより先に入る。予算で落としたものも深さの上限で落としたものも、どの切り捨ても見える: 落としたメンバーは `aggregateErrorsOmitted` に数え、落とした cause は `causeOmitted: true` を残す。文字列はすべて切り詰められるので、1 行はおよそ 64 KB に収まる。
- 決して残さないもの: Error でない cause やメンバー（openid-client が拒否した応答を置く場所）、それ以外のフィールド（コマンドの `args`、`body`、`buffer`）、そして Error でない値を投げた場合は `typeof` 以外の何も（`thrown` として）。
- 文字列はすべて — `detail` だけでなく `name`、`code`、`type`、レスポンスの `contentType` も — 1 行にし（上のフィルター）、256 文字で切る（スタックは 2048 文字）。サロゲートペアの途中では切らない。例外は投げない。`consoleLogger` は射影したエラーを 8 段まで展開して表示する（`LOGGED_PRINT_DEPTH`）。それ以外のオブジェクトの表示は従来どおり。この深さは射影が入れ子になる最も深い段より深いので、その cause とメンバーは `[Object]` に畳まれず、すべて表示される。これを行うのは各射影が持つ列挙されない `util.inspect.custom` で、`consoleLogger` はコンソールに引数をそのまま渡す。呼び出し側がログに出すそれ以外のオブジェクト（リクエストや設定など）は、Node のデフォルトの 2 段のまま。JSON にも pino にもスパイにも、このフックは見えない。

## 関連

- ルート [README](../../README.md) — アーキテクチャ概要、設定リファレンス、Docker セットアップ
- [`@o3co/auth-provider-oauth`](../oauth/README.md) — OAuth 2.0 エンドポイント（authorization、token、introspection）
- [`@o3co/auth-provider-session`](../session/README.md) — セッションベースのログインフロー
- [`@o3co/auth-provider-foundation`](../foundation/README.md) — HTTP ユーザーリポジトリアダプター（Store クライアント）。`"http"` ユーザーアダプタータイプとして登録される
