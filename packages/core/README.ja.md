# @o3co/auth-provider-core

最終更新: 2026-09-24

## 責務と役割

`@o3co/auth-provider-core` は、auth.provider の他のすべてのパッケージが土台にするパッケージです: モジュールシステムと boot planner（`createApp`）、グラントハンドラーの契約と全グラントがトークン発行に使うヘルパー、リポジトリ・ストアのポートと単一レプリカ向けのインプロセスアダプター、キーストア、設定スキーマを持ちます。他のすべてのパッケージの下に位置し、そのどれも import しません。独立したパッケージである理由はここにあります: 複数のパッケージが共有する契約はここに置かれます。それらのパッケージがすべて互いに依存しているわけではない — `session` と `oauth` は独立しており、`oauth-token-exchange` と `webauthn` は `oauth` に依存せずにグラントを実装する — ので、全員が依存する場所は core だけだからです。

グラントタイプと `/oauth/*` エンドポイント（`@o3co/auth-provider-oauth` と各グラントパッケージ）は持ちません: core が自分でマウントするルートは discovery ドキュメントだけで、JWKS、health、readiness のルーターは composition root が組み込みます。永続アダプター（`@o3co/auth-provider-redis`）、フェデレーションアダプター（`@o3co/auth-provider-federation-*` パッケージ群）、ログインとブラウザーセッション（`@o3co/auth-provider-session`）、Store クライアント（`@o3co/auth-provider-foundation`）は持ちません。内部のどのディレクトリが何を持ち、なぜ分かれているかは [src/README.md](src/README.md) にあります。

語彙: **the Store** は auth.provider の用語で、利用者側の上流ユーザーサービス — identity・クレデンシャル・メール検証状態の system of record — を指します。定義は [`src/repositories/types.mts`](src/repositories/types.mts) の `User` doc にあり、auth.provider は Store が公開した状態を読むだけで、書き込むことはありません。このパッケージのソースが引用する design-campaign 識別子は [docs/design-campaign-index.md](../../docs/design-campaign-index.md) で解決できます。

## インストール

```sh
npm install @o3co/auth-provider-core
```

Peer dependency: `express@^5.0.0`（任意 — `createApp` を使う場合のみ必要）

## パブリック API

### 設定

`AppConfigSchema` はアプリケーション全体の設定を検証する [Zod](https://zod.dev/) スキーマです。`AppConfig` はそこから推論される TypeScript 型です。

```typescript
import { AppConfigSchema, type AppConfig } from "@o3co/auth-provider-core";

const config: AppConfig = AppConfigSchema.parse(rawConfig);
```

このスキーマは**宣言していないキーを取り除きます** — Zod のオブジェクトの既定動作であり、パースを素通しではなく検証にしているのもこの動作です。ここで問題になるのは、このパースが `createApp` の*前*に走るためです。各モジュール自身の `configSchema` が合成・適用されるのは `createApp` の中なので、このスキーマが知らないセクションは、それを読むモジュールが動く時点ではもう消えています。しかも大半のモジュールスキーマはデフォルトを持つため、結果はエラーではなく、黙って別物になったデプロイです。

そのためこのスキーマは、core 自身がどれも読まないにもかかわらず、このリポジトリのモジュールが所有するすべての設定セクション — `oauth.mtls`、`oauth.dpop`、`oauth.deviceAuthorization`、`webauthn`、`memoryRateLimiter` / `redisRateLimiter`、`redis*` のストア名前空間を含む — を宣言しています。範囲とデフォルトは所有するパッケージ側（それぞれの `reference.conf` と `configSchema`）に残り、ここでの宣言は値が途中で落ちないようにするだけです。モジュールがこのスキーマにないキーを宣言すると `module-config-key-parity.test.mts` がビルドを失敗させます。

このリポジトリの**外**のモジュールはこの検査の対象外です。そうしたモジュールが自分の設定セクションを読むなら、パース前にスキーマを拡張する（`AppConfigSchema.extend({ mySection: … })`）か、パースしていない設定を `createApp` に渡して、合成されたモジュールスキーマに検証させてください。

デフォルトはスキーマではなく [`config/reference.conf`](config/reference.conf) にあります。トップレベルのフィールド（すべてのデプロイが持つセクション。モジュールが所有するセクションは、所有するパッケージが記述します）:

| フィールド | 説明 |
| --- | --- |
| `http.port` | HTTP リッスンポート |
| `http.trustProxy` | Express の `trust proxy` 設定: `false` / アドレスリスト（IP、CIDR レンジ、名前付きレンジ `loopback` / `linklocal` / `uniquelocal`）/ ホップ数 / `true`。エントリは boot 時に検証される。`true` はプロセスに到達できる誰からの forwarded アドレスも信じるため、プロキシを明示することを推奨 |
| `oauth.jwt` | JWT 署名設定 — `issuer`、`signingKey`（`provider` とそのサブセクション）、`jwksPath`、`jwksCacheMaxAge` |
| `oauth.accessToken.defaultExpiresIn` | リクエストが有効期間を指定しないときに全グラントが発行するアクセストークンの有効期間（秒）。指定できるのは token exchange（`expires_in` パラメータ）だけで、他のグラントはそのパラメータを無視する。有効期間は `resolveAccessTokenLifetime(config)` で読む |
| `oauth.accessToken.maxExpiresIn` | token exchange の `expires_in` で得られる上限。超えるリクエストはこの値に切り詰められる。未設定ならデフォルトと同じで、明示的に設定しない限り延長されない。デフォルトがこれを超えると両キーを名指しして起動失敗 |
| `oauth.accessToken.expiresIn` | `defaultExpiresIn` の**非推奨（deprecated）**エイリアス。`defaultExpiresIn` 未設定の間だけ読まれる（`reference.conf` は出荷時の `3600` をこのキーに置いている）。パース後の config はこの名前にも解決済みのデフォルトを持つ |
| `oauth.refreshToken.expiresIn` | リフレッシュトークンの有効期間 |
| `oauth.grants` | グラントタイプごとの設定。グラントタイプをキーとする。`oauth` パッケージは自分が登録するグラント — `session`、`authorization_code`、`refresh_token`、`client_credentials`、jwt-bearer の URN — の `enabled` を読み、true のものだけを登録する。他のグラントパッケージはこのキーを読まない: token exchange と WebAuthn はモジュールが組み込まれればグラントを登録し、device grant はどちらの場合もハンドラーを登録し、`oauth.deviceAuthorization.enabled` が false の間はグラントを拒否する |
| `session` | ブラウザーセッションの cookie とそのストア — `secret`、`name`、`maxAge`、`secure`、`sameSite`、`domain`、`redirectAllowlist`、`storage`、`csrf` |
| `session.csrf` | 状態変更する session ルートの CSRF ポリシー — `trustedOrigins`、`ttlSeconds` |
| `rateLimit` | `login`: 同梱の両リミッターが初期値に使う `/session/login` の予算（`windowMs`、`limit`）。`failMode`: OAuth エンドポイントのリミッターのバックエンドが失敗したときの動作 — `closed` は `503` を返し、`open` はリクエストを通してエラーをログに出す。OAuth エンドポイントの制限値そのものはリミッターモジュールのもの（`memoryRateLimiter.*` / `redisRateLimiter.*`） |
| `federations` | フェデレーションプロバイダー。名前をキーとする `{ enabled, type?, … }`。core が読むのは `enabled`（boot 時のフェデレーションストア配線チェック）だけで、`type` とエントリの残りはそれを読むアダプターパッケージのもの — アダプターパッケージは [ルート README](../../README.md) に一覧がある |
| `repositories` | client、user、code の Repository 設定 — それぞれ `type` とそのサブセクション |
| `endpoints` | `login.url`: デプロイのログインページ。`consent.url`: first-party でないクライアント向けの同意ページ（デフォルト `/consent`） |
| `cors.allowedOrigins` | token / userinfo / revocation / discovery・JWKS のレスポンスを読める browser origin — [CORS](#cors) を参照。空（既定）なら CORS は無効。CSRF の信頼は与えない（`session.csrf.trustedOrigins` を使う） |

### グラントシステム

グラントシステムは OAuth 2.0 グラントタイプの拡張ポイントです。各グラントタイプは `GrantHandler` として実装し、モジュールの `contributes.grants` で宣言します。ハンドラーの実体化と登録は boot planner が内部で行います。

#### インターフェースと型

定義は [`src/grants/types.mts`](src/grants/types.mts) にあります: `GrantHandler`、`GrantContext`、`SessionData`、`AuthenticatedClient`、`GrantHandlerResult`、`GrantDependencies`、`GrantFactory`。ハンドラーが信頼してよいもの（`authenticatedClient`。決して `body.client_id` ではない）と、してはならないことは各フィールドに記述されています。ディレクトリの責務マップは [`src/grants/README.md`](src/grants/README.md) です。

#### グラントハンドラーの登録

モジュールはグラントを `contributes.grants` にグラントタイプをキーとして宣言します。そもそもグラントを contribute するかどうかはモジュールが決めます: `oauth` パッケージのモジュールは `oauth.grants.<name>.enabled` が true のグラントだけを contribute し、token exchange と WebAuthn はモジュールが組み込まれれば自分のグラントを contribute し、device grant はどちらの場合もハンドラーを contribute して、`oauth.deviceAuthorization.enabled` が false の間はグラントを拒否します。boot は各ファクトリーを実行し、ハンドラーをそのグラントタイプで登録し — 2 つのモジュールが同じグラントタイプを contribute すると boot は拒否されます — ステージ 5 でレジストリを freeze するので、boot 後の登録は throw します。コンシューマコードがレジストリを import したり組み立てたりすることはありません: `GrantRegistry` は内部実装で、パッケージルートからは export されていません。

`GrantHandler.cleanup?()` が呼ばれることはありません。`AppHandle.dispose()` は、提供された各コンポーネントの `lifecycle[K].cleanup` を reverse-topological 順で実行し、次に宣言を持たないモジュール提供値の `Symbol.asyncDispose` を、最後に `LifecycleRegistrar` の drain を行い — レジストリには触れません。ハンドラーのためにリソースを保持するモジュールは、自分の `lifecycle[K].cleanup` でそれを解放します。[`src/grants/README.md`](src/grants/README.md) を参照してください。

#### リソースインジケーター（RFC 8707）

`resource` を扱うグラントは、`extractResourceParam` でそれを読み、それが名指す audience を `deriveAudienceFromResources` で導き、発行する `aud` がそれを表さなければ `unrepresentedResources` で拒否します — [`src/grants/resourceIndicator.mts`](src/grants/resourceIndicator.mts)。各値は分割せずにそのまま扱い（URI はカンマを含みうる）、繰り返されたパラメーターの空のエントリーは捨て、すべて空なら要求されなかったものとして扱います。oauth のグラント、`/authorize`、WebAuthn グラントはすべてここで読むので、同じことをするカスタムグラントも同じ答えになります。

### トークンユーティリティ

`generateToken(data, options)`、`generateTokenResponse(tokens, options?)`、`formatObject` は [`src/grants/token.mts`](src/grants/token.mts) にあり、`Token`、`TokenResponse`、`GenerateTokenOptions` がその隣にあります。

`generateToken` は `options.keyStore` の現在の署名鍵で JWT に署名します。`alg` と `kid` はキーストアのもの、`typ` は `options.tokenType`、`cnf` は `options.confirmation` が与えられたときだけ出力され、`jti` / `issuedAt` は呼び出し側が先に予約していなければここで発行されます（#449）。`generateTokenResponse` はアクセストークン、任意のリフレッシュトークン、任意の id_token を OAuth 2.0 トークンエンドポイントのレスポンス形式にまとめ、`DPoP` を要求されない限り `token_type` は `Bearer` です。`formatObject` はオブジェクトから `undefined` と `null` の値を除去します。

### キーストア

`KeyStore` インターフェースは、対称鍵（HS256）と非対称鍵（RS256、ES256、EdDSA）の署名鍵を、鍵のローテーションを含めて抽象化します。ローテーションは形が鍵種別で異なり、非対称アルゴリズムは `previousKeys`（kid + 公開鍵 + 有効期限）、HS256 は `previousSecrets`（kid + secret + 有効期限）を使います。`getVerificationKey(kid)` は kid で鍵を解決し — キーストアは一致する鍵を直接返し、複数の鍵で試し検証することはありません — 持っていない kid には `UnknownKidError`、`expiresAt` を過ぎた kid には `ExpiredKidError` を throw するので、呼び出し側は捏造された kid と退役した kid を区別できます。`sign(options)` は compact JWT を返します。protected header の `alg` / `kid` は KeyStore が自動注入するため、呼び出し側は上書きできません。この契約により、remote-sign アダプター（KMS/HSM）は private key を露出せずに `sign()` を実装できます。`getSigningKidFallback()` は、`kid` header を欠く legacy/malformed トークンの検証用に現在の署名 kid を返す軽量なアクセサーです。rotation-safe な lookup には使わないでください。

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

エントロピーは**デコード後**の値で、かつ最も小さく読める解釈で測る（`measureSecretEntropyBytes`）: 64 文字の hex は 32 バイトで通り、32 文字の hex は 16 バイトで落ちる。`session.secret` にも同じ floor が `AppConfigSchema` で適用される。`assertSecretEntropy` / `describeWeakSecret` は export されているので、運用者のシークレットを自前で受け付ける composition root も同じ検査を適用できる。

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

### リポジトリ

リポジトリインターフェースはデータアクセスのコントラクトを定義します。開発・テスト向けのインメモリ実装が標準で提供されています。

#### インターフェースと型

ポートは [`src/repositories/ClientRepository.mts`](src/repositories/ClientRepository.mts)（`findById`、`authenticate`。`PublicClient` は `clientSecret` を除いた `Client`）、[`src/repositories/UserRepository.mts`](src/repositories/UserRepository.mts)（`authenticate`、`authenticateByToken`、および任意の federated-identity リンク・検索メソッド）、[`src/repositories/CodeRepository.mts`](src/repositories/CodeRepository.mts)（`createCode`、`findByCode`、アトミックな single-use ゲートである `consumeByCode`、`removeByCode`）です。レコード — `Client`、`User`、`CodeData`、`Code`、`TokenEndpointAuthMethod` — は [`src/repositories/types.mts`](src/repositories/types.mts) にあり、各フィールドの意味はそのフィールド上に一度だけ記述されています。例外はログアウト URI の 3 フィールドで、そこには記述がありません: `postLogoutRedirectUris` は `allowedRedirectUris` と同じ登録リダイレクト URI 文法（カスタムスキーム可）、`backchannelLogoutUri` と `frontchannelLogoutUri` は http/https のみです。この注記は [`src/repositories/InMemoryClientRepository.mts`](src/repositories/InMemoryClientRepository.mts) のスキーマの横にあります。

`createCode` は `client_id` と `redirect_uri` を必須とし、`Client.tokenEndpointAuthMethod` も必須です。`Code` のその他のフィールドはすべて必須キーで、記録がなければ `undefined` を保持します。`createCode` は `CreateCodeInput` を受け取り、省略できるのは `expiresIn`（省略時はリポジトリの既定値）だけです。`nonce` と `sid` は OIDC の nonce とセッション ID を `/authorize` から `/token` へ運びます。`grantedScope` / `grantedAudience` は `/authorize` でのグラントポリシーの決定で、`authorization_code` グラントはポリシーを再評価せずにこれを読みます。ディレクトリの責務マップは [`src/repositories/README.md`](src/repositories/README.md) です。

#### 組み込み実装

`InMemoryClientRepository` と `InMemoryUserRepository` は、`ClientEntrySchema` / `UserEntrySchema` で検証済みのエントリーの `Map` を受け取ります。`InMemoryCodeRepository` は任意の `defaultExpiresIn` を受け取り、`dispose()` で止める GC タイマーを持ちます。`loadYamlMap(filePath, schema)`（[`src/repositories/loadYamlMap.mts`](src/repositories/loadYamlMap.mts)）はトップレベルのキーをレコード ID とする YAML ファイルを読み込み、各エントリーを `schema` で検証します。結果を `InMemoryClientRepository` や `InMemoryUserRepository` にそのまま渡せます — [YAML からクライアントとユーザーを読み込む](#yaml-からクライアントとユーザーを読み込む) を参照。

#### アダプタファクトリーのプリミティブ

`createAdapterFactory<T>(kind, ctx?)`、`AdapterFactory<T>`、`AdapterBuilder<T>`（設定セクションと読み取り専用の `BuilderContext` を受け取る関数。`BuilderContext` のフィールドはすべて任意で、追加されるだけ）、`LifecycleRegistrar`、`AdapterFactoryError` は [`src/adapters/AdapterFactory.mts`](src/adapters/AdapterFactory.mts) に定義されています。[`src/repositories/RepositoryFactory.mts`](src/repositories/RepositoryFactory.mts) の `createRepositoryFactories(ctx?)` は client、user、code のファクトリーを返します。

契約の主要な性質:

- `create()` は同期ビルダーであっても必ず `Promise<T>` を返す。
- `register()` は同一 `type` の二重登録で throw する（silent override 防止）。`replace()` が明示的な上書きで、登録されていない `type` では throw する。
- `create()` は未登録 `type` で `AdapterFactoryError` を throw する。error は `reason`（`unknown`、`duplicate`、`unknown-replace`）、`kind`、`type`、`registered` の一覧を持つ。
- `BuilderContext` は factory 単位で共有される（call ごとのコピーではない）。builder 側では read-only として扱うこと。

`createRepositoryFactories` は組み込みの `yaml` / `static`（client、user）と `memory`（code）タイプが登録済みの 3 つのファクトリーを返します。`@o3co/auth-provider-foundation` の `registerBuiltinAdapters` で `http` ユーザー認証アダプターを追加するか、独自のタイプを登録して別の backend に対応させてください。Redis バックエンドの code / store アダプターは `@o3co/auth-provider-redis` を参照してください。

### モジュールシステム

モジュールはルート、グラントハンドラー、DI グラフのコンポーネントをアプリに追加します。モジュールは `defineModule({...})` で書く宣言的なマニフェストです: `requires` / `optional`（型付きの `ProviderDeps` キー）を宣言し、コンポーネントを `provides` し、`grants`、`routes`、`federations` などの `ContributesMap` の種別に contribute します。boot planner が型付きの deps をすべてのファクトリーに注入するので、モジュールが共有状態を書き換えることはありません。語彙は [`src/modules/manifest/`](src/modules/manifest/README.md) にあり、`@o3co/auth-provider-core/modules/manifest` サブパスとしても公開されています。

```typescript
const myModule = defineModule({
  name: "my-module",
  requires: ["config", "clientRepository"] as const,
  contributes: {
    routes: [
      (deps) => ({ id: "my-route", mountPath: "/my", handler: makeRouter(deps) }),
    ],
  },
});
```

### アプリファクトリー

`createApp(options): Promise<AppHandle>` は [`src/boot/`](src/boot/README.md) の boot planner です。`CreateAppOptions` と `AppHandle` は [`src/boot/types.mts`](src/boot/types.mts) に定義されています。

`createApp` はマニフェストを検証し、設定を合成・パースし、コンポーネントグラフを実体化し、すべての contribution を適用し、ワールドを freeze してルートをマウントします。返される `router` はそのままマウントでき（`app.use(handle.router)`）、`handle.listen(port)` で配信することもできます。`handle.dispose()` はすべての cleanup を reverse-topological 順で実行し、すべての失敗を持つ `AggregateError` で reject します。別途の `init()` ステップはありません。

core が自分でマウントするもの（この順）: `cors.allowedOrigins` が空でなければ `corsMw`、contribute された機構が 1 つ以上あればそれらを合成した単一の `tokenBindingMw`、protected-resource の sender-constraint チェック（常に）、グラントのディスパッチ前に `grantMiddleware` の contribution、そして issuer が設定されかつ `providerRoot` を宣言するモジュールがあれば OIDC discovery ルート。それ以外 — JWKS（`jwksModule`）、liveness と readiness（`createHealthcheckRouter`、`createReadinessRouter`）、OAuth と session のルート — は、composition root が組み込むモジュールかルーターです。

`express` は任意の peer dependency で、遅延ロードされます: `createApp` はルーターを作るために import し（`await import("express")`）、boot は `handle.listen()` がルーターを包む `express()` ファクトリーのためにも require します（`createRequire`）— import が失敗した場合はルーターもそこから得ます。

## CORS

`cors.allowedOrigins` を消費するのは `corsMw`（`src/middleware/cors.mts`）で、`assembleApp` はこれを**最初に** — 他のすべてのミドルウェアとルート contribution より前に — マウントします。空のリスト（既定）なら何もマウントしません: CORS ヘッダーも `Vary` も付きません。

### 対象ルート

`browserFacingCorsRoutes(config)` がその表で、**許可リスト**です — 隣にある sender-constraint のマウントとは逆の極性です。あちらはクレデンシャルを守るので core が知らないルートまで覆う必要がありますが、こちらはクロスオリジンの読み取りを*与える*ので、core が知らないルートこそ黙ってそれを得てはいけないルートです。

| パス | メソッド |
|---|---|
| `/oauth/token` | `POST` |
| `/oauth/userinfo` | `GET`、`POST` |
| `/oauth/revoke` | `POST` |
| `/.well-known/openid-configuration` | `GET` |
| `/.well-known/oauth-authorization-server` | `GET` |
| `oauth.jwt.jwksPath`（既定 `/.well-known/jwks.json`） | `GET` |

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

リストの書き方は 2 通りあります: 配列か、環境変数が運べる唯一の形であるカンマ区切りの文字列（`CORS_ALLOWED_ORIGINS`）で、各エントリーは前後の空白を除かれ、空のエントリーは捨てられます。両方を読むのは同じファイルの `normalizeAllowedOrigins` で、export されています。WebAuthn パッケージは `WEBAUTHN_ORIGIN` / `WEBAUTHN_TOP_ORIGIN` をこれで読むので、環境変数から設定するオリジンのリストはどれも同じ書き方になります。

## 使い方

```typescript
import express from "express";
import {
  AppConfigSchema,
  createApp,
  createRepositoryFactories,
  createKeyStoreFactory,
  defineModule,
  registerBuiltinKeyStores,
} from "@o3co/auth-provider-core";

const config = AppConfigSchema.parse(rawConfig);

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
const keyStore = await keyStoreFactory.create(flatten(config.oauth.jwt.signingKey));

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
  bootstrapComponents: { config, pathResolver: import.meta.resolve },
});

const server = express();
server.use(handle.router);
server.listen(config.http.port);
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

- `MfaProvider` と任意の `SupportsEnrollment` / `SupportsRevocation` capability、ガード `supportsEnrollment()` / `supportsRevocation()`、`MfaCoordinator` / `MfaTransactionStore` 型 — [`src/mfa/types.mts`](src/mfa/types.mts)。ファクトリー `createMfaProviderFactory()` — [`src/mfa/factory.mts`](src/mfa/factory.mts)。
- `createMfaRouter(express, deps)` は `POST /auth/mfa/verify { transaction_id, proof }` を作る: 保留中のトランザクションを `MfaTransactionStore` から読み、トランザクションの `providerKind` のプロバイダーで proof を検証し、再開するフローを呼び出し側が渡す `onAuthorizeResume` / `onFederationResume` / `onLoginResume` コールバックに渡す。
- core が提供するのはポートとルーターだけで、それを使うものは何もない。このリポジトリのどのルートも MFA を参照しない: `/oauth/authorize`、session のログイン、フェデレーションのコールバックは `MfaCoordinator.listEnrolled` を呼ばずトランザクションも始めない。`createMfaRouter` をマウントするものはなく、boot が集める `mfaFactors` contribution を読むプロダクトコードもない。MFA を使いたい composition root は、自分のログインフローでトランザクションを始め、ルーターをマウントし、コールバックを渡す。
- `mfaCoordinator` を提供しながら `mfaProviderFactory` と `mfaTransactionStore` の両方は提供しない構成を、boot は拒否する（`mfa-partial-wiring`）。
- factor は同梱しない。`@o3co/auth-provider-webauthn` はパスキーを `mfaFactors` contribution ではなくグラント（`contributes.grants`）として提供する。

#### 監査（Audit）

- `AuditSink.record(event)` は fire-and-forget
- Factory: `createAuditSinkFactory()`、built-in `"console"` は `registerBuiltinAuditSinks()` で登録
- Sink のエラーは core 側で握りつぶす — audit 失敗で認証フローがブロックされることはない

#### レートリミッター

- `RateLimiter.check(key, ctx)` で atomic check + increment
- Factory: `createRateLimiterFactory()`。`registerBuiltinRateLimiters()` が登録するのは `"memory"` だけ。`"redis"` バックエンドは `@o3co/auth-provider-redis`（`redisRateLimiterBuilder`、または宣言的な `redisRateLimiterModule`）にあり、ここで登録されないことを `ratelimit/__tests__/factory.test.mts` が検査している
- deny 時には core が 429 + `Retry-After` で応答

#### リフレッシュトークンファミリー（RFC 6819 §5.2.2.3 の replay 検出）

- ポートは [`src/refresh-token-family/types.mts`](src/refresh-token-family/types.mts) の `RefreshTokenFamilyRotation` / `RefreshTokenFamilyRevocation`
- すべての `rt+jwt` は `family_id` claim を持つ
- `refreshTokenFamilyRotation` / `refreshTokenFamilyRevocation` スロット（`memoryRefreshTokenFamilyStoreModule`、または Redis アダプター）を提供すると replay 検出と family revocation が有効になる

#### GrantPolicyHook（scope / audience / token exchange のポリシー）

- `GrantPolicyHook.evaluate(request, ctx)` は allow（narrowing 可）/ deny を返す
- `/oauth/authorize` で 1 回だけ評価、`/oauth/token` は Code record に persist された `grantedScope` / `grantedAudience` を再利用（`authorization_code` では再評価しない）
- その他のグラント（refresh / client_credentials / token-exchange）はトークンエンドポイントで評価

5 つとも任意です。audit sink は absence policy（`AUDIT_SINK_ABSENCE_POLICY`）を持ちます: スロットを埋めるものがなければ、設定で不在を宣言する（`audit.sink.type = "none"`）必要があり、宣言がなければ boot は拒否されます。他の 4 つは、ないときは単に無効です。

### トークンバインディング機構

sender-constrained なトークンバインディングは第一級の拡張面です。`tokenBindingMechanisms` contribution スロットにより、モジュールは core を fork せずに独自の `TokenBindingMechanism` を提供できます。設計の根拠は [ADR 2026-05-20-token-binding-first-class-abstraction.md](docs/adr/2026-05-20-token-binding-first-class-abstraction.md) を参照してください。

#### 公開型

- `TokenBinding`（[`src/grants/tokenBinding.mts`](src/grants/tokenBinding.mts)）— 横断的なバインディングの形: `kind`、`confirmation`、そして機構がレスポンスに載せるよう求める任意の `responseHeaders`（`DPoP-Nonce`）。`kind` は開いているので、downstream の機構が追加的に拡張できる。
- `Confirmation`（[`src/grants/confirmation.mts`](src/grants/confirmation.mts)）— RFC 7800 の `cnf` claim の payload で、`jkt` と `x5t#S256` の閉じた union。variant の追加は core の semver-minor 変更。
- `TokenBindingMechanism`（[`src/middleware/tokenBinding.mts`](src/middleware/tokenBinding.mts)）— 動詞側の抽象: `kind`、`intentExplicit`（DPoP のようなヘッダー駆動の機構は `true`、mTLS のような ambient な機構は `false`）、`extract(req)`。
- `TokenBindingMechanismFactory<Deps>`（[`src/modules/manifest/contributes-map.mts`](src/modules/manifest/contributes-map.mts)）— contribution スロットのエントリー: 機構を返すか、設定でモジュールが無効なら `null` を返す（secure-default の opt-in）。

#### 組み込みの機構パッケージ

- `@o3co/auth-provider-dpop` — RFC 9449 DPoP（explicit-intent）。
- `@o3co/auth-provider-mtls` — RFC 8705 mTLS の証明書バインドトークン（ambient）。

どちらのパッケージも `tokenBindingMechanisms` で contribute します。core の `assembleApp` はすべての contribution を集め、null を除き、`/oauth/token` にマウントする単一の `tokenBindingMw` を合成します。

#### ディスパッチポリシー

複数の機構が組み込まれたとき、`oauth.tokenBinding.dispatch-policy`（core 同梱の `CoreConfigSchema` にある — single source of truth）が調停します:

- `intent-explicit`（既定）— ambient より explicit-intent の機構を優先する。
- `strict-mutual-exclusion` — 2 つ以上の機構の `extract` がバインディングを返したら `invalid_request` で拒否する。

環境変数での上書き: `OAUTH_TOKEN_BINDING_DISPATCH_POLICY`。

#### グラント側の許可リスト

`@o3co/auth-provider-oauth` のグラントが `cnf` バインドの RT を発行するのは、明示的な許可リストにある機構（`bindingIsDpop || bindingIsMtls`）の場合だけです。バインド RT の発行に新しい機構を加えるなら、リフレッシュ時の強制マトリクスを同じ PR に入れなければなりません — §9.2 のマトリクスの型は [`packages/oauth`](../oauth/) を参照。

### セッションストアとフェデレーショントークン

フェデレーションと OIDC 対応のための任意スロットの 2 つのグループで、モジュール（`memorySessionStoresModule`、`memoryFederationTokenStoreModule`）か Redis アダプターが提供します:

- `userSessionStore` と、sid / subject をキーとするその兄弟: セッションのメタデータ（auth_time、アクティブな RP、family ID、OIDC claim）、ログアウトの fan-out 用インデックス、subject 単位の失効 — [`src/user-sessions/README.md`](src/user-sessions/README.md)。
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
- `amr`、`acr` — セッションが記録している場合。空の `amr` は `[]` として出力せず省略する
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

OIDC Discovery 1.0 メタデータエンドポイント。`config.oauth.jwt.issuer` が設定され、かつ provider surface を宣言するモジュールがある（`oauthModule` が `discoveryMetadata` contribution に `providerRoot: true` を設定）場合に、core が合成して mount する。core は各モジュールの `discoveryMetadata` slice を 1 つのドキュメントに集約する。`issuer` と `id_token_signing_alg_values_supported` は core 自身のもので、モジュールは設定できない。OIDC Discovery が要求するフィールドを欠くドキュメントは boot を拒否させる（`discovery-document-invalid`）。同梱モジュールが contribute する slice は以下のとおり — `oauthModule` の slice は [`packages/oauth/src/module.mts`](../oauth/src/module.mts) に定義され、`jwksModule` は `jwks_uri` を contribute する:

- `issuer`、`authorization_endpoint`、`token_endpoint`、`userinfo_endpoint`、`introspection_endpoint`
- `jwks_uri` — 常に広告する（`jwksModule` が contribute）。issuer 設定済みの構成は `jwksModule` を必ず組み込む必要があり、欠如すると boot が `DiscoveryDocumentError` で fail-fast する。JWKS ルートが空の鍵セットを返すことはない: HS256 構成は `404 jwks_not_published`、非対称でも公開可能な鍵が 0 件なら `503 jwks_unavailable` を返し、いずれも `Cache-Control: no-store`。対称鍵の secret はどちらの経路でも公開されない。このルートが `200` を返すときは必ず 1 件以上の鍵を含む。
- `revocation_endpoint` — `POST /oauth/revoke` が**何かしら revoke できる**ときに広告する。判定はルート自身の解決規則に合わせた 2 本の腕からなる: refresh 側は `refreshTokenFamilyRevocation` が wire されていること、access 側は `accessTokenDenylist` が wire され**かつ** `oauth.revocation.accessToken` が `"unsupported"` でないこと（明示的な `"unsupported"` は wiring に関わらず access 側の経路を無効化する）。どちらか一方で足りる: RFC 7009 §2.2.1 は AS が片方の token type だけを revoke できる状況のために `unsupported_token_type` を定義しているので、refresh のみのエンドポイントも revocation endpoint であり、URL を隠せば logout 時に refresh token を revoke したい client が何も revoke できなくなる。**どちらの腕も無い**場合、ルートは RFC 7009 が要求する `200` を返しつつ何も revoke しないため、広告すれば起こらない revoke を約束することになる。どの *token type* を revoke するかは依然として discovery からは導出できない（RFC 7009 / RFC 8414 に token type 別のメタデータフィールドは無い）: access token 側の答えはエンドポイント自身が `unsupported_token_type` として返す。
- `response_types_supported: ["code"]`
- `request_uri_parameter_supported: false` — OIDC Discovery は省略を `true` と読み、`/authorize` は `request_uri` を拒否する
- `client_id_metadata_document_supported: true` — `oauth.clientIdMetadataDocuments.enabled` が true で、かつ consent store が wire されているときだけ。[oauth パッケージの README](../oauth/README.md) を参照
- `subject_types_supported: ["public"]`
- `id_token_signing_alg_values_supported` — 設定された `KeyStore.algorithm` から導出
- `scopes_supported: ["openid", "profile", "email", "groups"]`
- `grant_types_supported` — `/oauth/token` が dispatch する grant handler registry から読む。つまりこの構成が実際に登録した grant だけが並び、それ以外は入らない。空でも出力する: RFC 8414 §2 は**省略**を `["authorization_code", "implicit"]` と解釈するため、省略すればこの AS が実装していない `implicit` を広告することになる。
- `token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"]`、`replaySeenSet` が wire されていれば `private_key_jwt` も加わる。`jwks` / `jwksUri` を登録したクライアントは、自分が署名した JWT（RFC 7523 §2.2）を提示し、それはその鍵で検証される。`iss = sub = client_id`、`aud` は issuer かトークンエンドポイント、`exp` は最大 1 時間先、`jti` は 1 回限りで `replaySeenSet` に記録される。**そのストアが条件**: ストアがなければ検証器は検査されていない `jti` を受け入れる代わりに `500 server_error` を返すので、この方式は守れる場所でだけ広告される — 上の `revocation_endpoint` と同じ「有効かつ完遂できる」規則。[oauth パッケージの README](../oauth/README.md#client-authentication-private_key_jwt-rfc-7523-22) を参照。
- `token_endpoint_auth_signing_alg_values_supported` — アサーションのアルゴリズムで、非対称のみ（`RS*`、`PS*`、`ES*`、`EdDSA`）。同じ一覧が introspection と revocation のエンドポイント向けに `*_endpoint_auth_signing_alg_values_supported` として出力される。3 つとも方式と一緒に動く: `replaySeenSet` が wire されていなければ方式と一緒に省略される。提供されない方式のアルゴリズムは、クライアントが行動に移せる何ものも伝えないから。
- `introspection_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"]`、同じ条件で `private_key_jwt` も加わる — `none` は無い: `/oauth/introspect` は RFC 7662 §2.1 に従い public client を拒否する。メタデータが言えないが運用者に必要なことが 2 つある: (a) RFC 6749 §2.3.1 は `client_secret_basic` で `client_id` と secret を base64 の**前に** form-urlencode することを要求するので、予約文字を含む `client_id` — `:` が Basic のフィールド区切りと読まれてしまうリソース URI — はパーセントエンコードしなければならない（`https%3A%2F%2Fapi.example.com`）。(b) 認証済みの呼び出し側は、`aud` がそのクライアントの `allowedAudiences` ∪ `{client_id}` に含まれるトークンを introspect できる。これにより、リソースサーバーは RFC 8707 のもとで自分のリソース URI 向けに発行されたトークンを introspect できる。どちらも [oauth パッケージの README](../oauth/README.md#introspection-which-tokens-a-caller-may-ask-about) に詳しくある。
- `revocation_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"]`、同じ条件で `private_key_jwt` も加わる — `revocation_endpoint` と同時に出力。RFC 7009 §2.1 が public client による自身の token の revoke を認めるため `none` を含む
- `acr_values_supported` — `oauth.authorize.acrValues` のキー（表が空でないとき）: セッションが記録した `amr` から `/authorize` が満たせる Authentication Context Class Reference。表がなければ省略され、そのとき `acr_values` は `unmet_authentication_requirements` になる。
- `code_challenge_methods_supported: ["S256"]` — `S256` のみ。`oauth.grants.authorization_code.pkce.supportedMethods` から導出は**しない**。この配列は server-wide メタデータであり、読んだ client は「このいずれかを使ってよい」と解釈する。`plain` はそれを満たさない（`/authorize` は RFC 9700 §2.1.1 に従い public client には即座に拒否する）ので載せない — client 単位の例外は、どちらの向きであれ server-wide 配列には属さない。
- `dpop_signing_alg_values_supported` — `oauth.dpop.enabled = true` のとき `@o3co/auth-provider-dpop` が contribute し、そのモジュールの `alg-whitelist` をそのまま載せる（RFC 9449 §5.1）
- `tls_client_certificate_bound_access_tokens: true` — `oauth.mtls.enabled = true` のとき `@o3co/auth-provider-mtls` が contribute する（RFC 8705 §3.3）。それ以外では省略し、RFC はこれを `false` と定義している。`oauth.mtls.source` には依存しない: TLS layer 経由でも trusted-proxy header 経由でも token に載る `cnf["x5t#S256"]` は同じで、このフラグは token を説明するものだから。
- `end_session_endpoint`、および `backchannel_logout_supported`、`backchannel_logout_session_supported`、`frontchannel_logout_supported`、`frontchannel_logout_session_supported`（すべて `true`）— ログアウトの連鎖に必要なすべてのストアが wire されているとき: `userSessionStore`、`sessionRPRegistry`、`sessionFamilyIndex`、`sessionFederationIndex`、`federationTokenStore`、`refreshTokenFamilyRevocation`

### ログアウトヘルパー

`@o3co/auth-provider-oauth` の `POST /oauth/logout` が使用する低レベルヘルパーで、[`src/grants/logoutToken.mts`](src/grants/logoutToken.mts) にある。

#### `generateLogoutToken`

`generateLogoutToken(opts)` は隣に定義された `GenerateLogoutTokenOptions` を受け取る。`includeSid` のデフォルトは `true`、`expiresIn` は 300 秒。OIDC Back-Channel Logout 1.0 §2.4 の `logout_token` JWT に署名して返す。ヘッダーは `typ: logout+jwt`。クレーム構成: `iss`、`sub`、`aud`、`iat`、`exp`、`jti`、および `{ [BACKCHANNEL_LOGOUT_EVENT_URI]: {} }` を値に持つ `events`。デフォルトで `sid` を含む。`backchannel_logout_session_required: false` で登録した RP 向けには `includeSid: false` を指定する。`nonce` クレームは仕様 §2.4 の要件により常に含まれない。

#### `BACKCHANNEL_LOGOUT_EVENT_URI`

すべての `logout_token` の `events` クレームが持つ正規イベント URI、`http://schemas.openid.net/event/backchannel-logout`。downstream のコードとテストがこのリテラルを繰り返し書かずに参照できるようにエクスポートされている。

### Logger

[`src/logging/Logger.mts`](src/logging/Logger.mts) にある、pino 互換の構造的ロガー: `trace` / `debug` / `info` / `warn` / `error` / `fatal`（それぞれオブジェクト先頭・文字列先頭のどちらの呼び出しも受け付ける）と `child(bindings)`。pino のインスタンスはアダプターなしでこれを満たし、デフォルトは `consoleLogger`。任意の `logger` コンポーネントスロットでもある。

## 関連

- ルート [README](../../README.md) — アーキテクチャ概要、設定リファレンス、Docker セットアップ
- [`@o3co/auth-provider-oauth`](../oauth/README.md) — OAuth 2.0 エンドポイント（authorization、token、introspection）
- [`@o3co/auth-provider-session`](../session/README.md) — セッションベースのログインフロー
- [`@o3co/auth-provider-foundation`](../foundation/README.md) — HTTP ユーザーリポジトリアダプター（Store クライアント）。`"http"` ユーザーアダプタータイプとして登録される
