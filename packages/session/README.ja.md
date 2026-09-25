# @o3co/auth-provider-session

最終更新: 2026-09-25

[auth.provider](../../README.ja.md) のブラウザ向けログイン・ログアウト・上流 IdP フェデレーションのルート、すべてのフェデレーションアダプターパッケージがプロバイダーと並べて contribute するリダイレクトポリシー、そしてそれらのルート（および `req.session` を読む他のすべてのルート）が乗る express-session のストア。

## 責務と役割

**役割。** 認証のブラウザ側の半分。このパッケージが使うポート（`UserRepository`、`UserSessionStore`、`FederationTokenStore`、`SessionFederationIndex`、フェデレーションアダプター契約）は core が持ち、core はルートを一つも実装しない。このパッケージはそれらのポートをブラウザ向けに駆動するドライバーである。責務は三つ:

1. **`/session` ルート** — `sessionModule`。パスワードログイン、ログアウト、CSRF トークンのルート、フェデレーションの開始ルートとコールバックルート。パスワード検証または上流 IdP の応答を `UserSession` レコードと認証済みの express session に変え、ログアウトでそれを取り消す。
2. **フェデレーションアダプターのツールキット** — アダプターパッケージが、自分が差し込まれるルーターから import するもの: `createFederationRedirectPolicy` とその元になる許可リストの規則、`extractFederationSection`。アダプターが上流への要求を組み立てるヘルパー — `codeChallenge`、`callbackUrlForExchange`、`FederationClientSecret` / `resolveClientSecret` — は core のもの。
3. **ブラウザセッションストア** — `sessionStoreModule` / `sessionStoreModuleFor` と `createSessionStoreFactory` / `registerBuiltinSessionStores`。express-session ミドルウェア、その cookie、そのストア（memory、または `connect-redis` 経由の Redis）。

**持つもの:**

- `/session` ルートとその応答。それらの CSRF ポリシー（`session.csrf.*`、および `@o3co/auth-provider-device-grant` が再利用する export 済みのガード）。ログインのレート制限ガードの配線（`rateLimit.login`）。リダイレクト許可リスト（`session.redirectAllowlist`、`federations.<name>.redirectAllowlist`）。
- フェデレーションの駆動方法: `state`・PKCE・`nonce`、`form_post` トランザクションとその cookie、クレームの優先順位、ログインが記録する `amr`、コールバックがストアに書き込む内容。
- `federationRedirectPolicies` という contribution 種別と、それが core に宣言する `federationRedirectPolicyResolver` スロット（[`src/federations/contributes.mts`](src/federations/contributes.mts)）、および [`FederationResult`](src/federations/types.mts)。
- express-session ミドルウェア、その cookie、そのストア（`session.*`、`session.storage.*`）。

**持たないもの:**

- フェデレーションアダプター契約 — `FederationProvider`、`FederationProfile`、各 capability — と、アダプターが要求を組み立てる純粋関数のヘルパー（`codeChallenge`、`callbackUrlForExchange`、`resolveClientSecret`）は core のもの（[`core/src/federations`](../core/src/federations/README.md)）。
- アダプター自体: [`federation-google`](../federation-google/README.md)、[`federation-github`](../federation-github/README.md)、[`federation-apple`](../federation-apple/README.md)、[`federation-oidc`](../federation-oidc/README.md)。
- 書き込むストア（core のポート。memory アダプターは core、Redis アダプターは [`@o3co/auth-provider-redis`](../redis/README.md)）と、ユーザーが誰か（`UserRepository` の背後の Store。例: [`@o3co/auth-provider-foundation`](../foundation/README.ja.md)）。
- トークン発行、`POST /oauth/logout` のカスケード、上流ログアウト（`SupportsLogout`）、フェデレーショントークンのリフレッシュ（`SupportsRefresh`） — [`@o3co/auth-provider-oauth`](../oauth/README.ja.md)。
- 委任認可（`SupportsDelegatedAuthorization`） — [`@o3co/auth-provider-federation-grants`](../federation-grants/README.md)。
- HTML 一切: ログインページとアカウントページはデプロイ側のもの。

**別パッケージである理由。** core から分けているのは、core がすべてのパッケージが依存する契約でありルートを実装しないこと、そしてブラウザログインを持たずにトークンを発行するデプロイ（client credentials、token exchange）が使わないルートをインストールせずに済むこと。`@o3co/auth-provider-oauth` から分けているのは、両者が core の上の兄弟でありどちらも他方を import しないため、デプロイがどちらかを他方のルートなしにインストールできること — ただし `oauth` の `/authorize` は `req.session` を読むので、それを使うデプロイは express-session のミドルウェア（通常はこのパッケージのストアモジュール）をマウントする。分けた代償は [`POST /session/logout` が無効化するもの](#post-sessionlogout-が無効化するもの) に書いてある。

**三つが同居する理由。** 他の二つはどちらもルートのために存在する。

- ツールキット: リダイレクトポリシーはこのパッケージが宣言しルーターが消費する contribution 種別であり、`extractFederationSection` はルーターがコールバック URL を読むのと同じ設定の形を読む。どちらもルーターのものであり、それがすべてのアダプターパッケージがこのパッケージを peer dependency に取る理由である。要求を組み立てる純粋関数のヘルパーはここにはない: ルーターはそのどれも使わないので、それらを使うようアダプターに指示する契約と並んで core にある。
- ストア: `req.session` そのものであり、それを書くのはここのルートである。フェデレーションルーターは `form_post` トランザクションも同じストアに置く。`sessionModule` とは別のモジュールになっているのは、他のパッケージがこれらのルートなしに `req.session` を読むから — `oauth` の `/authorize`・同意・ログアウト、`device-grant` の検証ページ、`federation-grants` のブラウザ向けルート — であり、独自のログインを持つデプロイはストアだけをインストールする。

**ソースの配置。** [`src/routes/`](src/routes/) は二つのルーター。[`src/federations/`](src/federations/) はツールキットとルーターのフェデレーション部品（クレームの優先順位、同意済みスコープ、トランザクションストア、リダイレクトポリシー）。[`src/modules/`](src/modules/) と [`src/store/`](src/store/) はブラウザセッションストア。[`src/internal/`](src/internal/) は cookie の読み取りと `User` から読むクレーム。[`src/csrf.mts`](src/csrf.mts) は CSRF の規則。[`src/redirect-allowlist.mts`](src/redirect-allowlist.mts) はログインとフェデレーションのルートが共有する許可リストの規則。各ファイルが何をするかはそのファイルのヘッダーコメントにある。

## インストール

```sh
npm install @o3co/auth-provider-session @o3co/auth-provider-core express express-session
# session.storage.type = "redis"（core の reference.conf のデフォルト）なら、さらに:
npm install redis@^6.2.1 connect-redis@^10.0.0
```

peer dependencies: `@o3co/auth-provider-core`、`express@^5.0.0`、`express-session@^1.17.0`。
optional peer dependencies: Redis セッションストアのライブラリである `redis@^6.2.1` と `connect-redis@^10.0.0`。
このパッケージ自身の dependencies は無い。

core が peer なのは、このパッケージが core を拡張する（`federationRedirectPolicies` の contribution 種別とそのスロット）からで、拡張は自分が解決した core にしか届かない。peer であれば、それは構成が持つ唯一の core になる。`session.storage.type = "memory"` のデプロイは Redis のライブラリをどちらもインストールしない。Redis ストアを組み立てるまで何もそれらを import しない。`"redis"`（デフォルト）なら両方をインストールする: どちらかが無ければ、無いパッケージとインストールコマンドを示して起動に失敗する。

## 組み立て

```ts
import { createApp } from "@o3co/auth-provider-core";
import { sessionModule, sessionStoreModuleFor } from "@o3co/auth-provider-session";
import { googleFederationModule } from "@o3co/auth-provider-federation-google";

const handle = await createApp({
  modules: [
    sessionStoreModuleFor(config), // 先頭に置く。後に続くすべてのモジュールが req.session を読めるように
    sessionModule,                 // factory ではなく const Module
    googleFederationModule,        // federations.google と federationRedirectPolicies.google を contribute
    // ... userRepository、userSessionStore、federationTokenStore、
    //     sessionFederationIndex、googleFederationConfig を提供するモジュール
  ],
  bootstrapComponents: { config, pathResolver },
});
```

完全な組み立ては standalone テンプレートの [`buildModules.mts`](../../templates/standalone/src/buildModules.mts) にある。

## ブラウザセッションストア

`sessionStoreModuleFor(config)`（または静的な `sessionStoreModule`）は `/` にマウントされる `session-middleware` というルートを一つ contribute する。中身は express-session で、cookie は `session.*` から（`HttpOnly`、`Path=/`、`session.secure`、`session.sameSite`、`session.domain`、`Max-Age` = `session.maxAge`）、ストアは `session.storage.*` から組み立てられる。デプロイ内のすべての `req.session` はこれである。デフォルト値と環境変数は [`reference.conf`](../core/config/reference.conf) にある。`session.storage.type` のデフォルトは `redis`、代替は `memory` で、それ以外の値は起動に失敗する。

成り立つこと:

- **マウント順はリスト順。ただしこのルートを名指しするルートは別。** このルートは `before` / `after` を宣言しない。デプロイが含まないかもしれないルート（`oauth` だけのデプロイには `sessionModule` が無い）を名指しすると `route-order-target-missing` で起動に失敗するからである。したがって **`req.session` を読むすべてのモジュールより前に** 並べる。これより前に並べたモジュールはセッションを読めず、起動時にそれを検査するものは無い。standalone テンプレートはこれを先頭に置いている。例外は逆向きの宣言である: federation grants が有効なとき、そのブラウザ向けルートは `after: ["session-middleware"]` を宣言するので、どちらがどこに並んでいてもこのルートの後にマウントされ、その id のルートが無い組み立ては `route-order-target-missing` で起動に失敗する。
- **`__Host-` の cookie 名には `session.secure = true` と `session.domain = null` が必要** で、満たさなければ起動に失敗する。デフォルト名は `__Host-auth.session`。
- **`memory` は `deployment.mode = "multi"` で拒否される。** express-session の `MemoryStore` はレプリカごとに分岐する: あるレプリカが処理したログインは他のレプリカに知られず、ログアウトは到達したレプリカ上しか消さず、再起動ですべてのセッションが失われる。`sessionStoreModuleFor(config)` はストレージ種別を読み、`memory` ならモジュールを replica-unsafe と宣言する。そのため core の replica-safety ガードが起動時に他の違反と並べて名指しで拒否し、`deployment.mode` が未設定なら警告し、`"single"` なら何も言わない。静的な `sessionStoreModule` は種別を知り得ないので、ガードは名指しできない。そのルートファクトリーが実行時に同じ組み合わせを拒否し（`replica-unsafe-adapter`）、警告は出さない。設定が手元にあるなら `sessionStoreModuleFor` を使う。
- **Redis ストアは自前の接続を開く。** `session.storage.redis.url`（設定されていれば `password` も）への `redis`（node-redis）クライアントを `connect-redis` の `RedisStore` の下に置く。readiness registrar が配線されていれば probe `session-store`（`PING`）を登録し、Redis を失ったレプリカはトラフィックを受けなくなる。lifecycle registrar が配線されていれば `AppHandle.dispose()` がクライアントを quit する。クライアントの `error` イベントはプロセスを落とさず `session_store_redis_error` としてログに出る。再接続は node-redis の仕事。`url` が無ければ起動に失敗し、`redis` か `connect-redis` のパッケージが無くても起動に失敗する（[インストール](#インストール) を参照）。
- **フェデレーショントランザクションは同じストアを共有する。** キーの接頭辞は `fedtx:` — [トランザクション cookie](#トランザクション-cookie) を参照。

**`@o3co/auth-provider-redis` とは別物。** あちらの `UserSessionStore` は `sid` の背後にある `UserSession` レコード — introspection・`/userinfo`・`/authorize` が解決するもの — を持ち、他のアダプターは他の core ポートを、あちらのモジュールが作るクライアント越しに持つ。このストアが持つのは express-session 自身のレコード: このパッケージのルートがセッションに置くもの（`isAuthenticated`、`user`、`sid`、ログインの `redirectTo`、`query` フェデレーションの進行中のエンベロープ）、他のパッケージがそこに置くもの（`oauth` は `client` と `code` を宣言している）、そして `fedtx:` のフェデレーショントランザクション。レコードも接続も別で、設定も別々に行う。

**別のストア。** このモジュールが登録するのは `memory` と `redis` だけ。別の express-session `Store` が必要な組み立ては、ミドルウェアを自分で組み立て — `createSessionStoreFactory(ctx)`、`registerBuiltinSessionStores(factory)`、`factory.register("<type>", builder)`（[`src/store/factory.mts`](src/store/factory.mts)） — 先頭にマウントし、このモジュールはインストールしない。federation grants を有効にするなら、そのミドルウェアを id `session-middleware` のルートとして contribute する。そうしなければ上のとおり起動に失敗する。

## ルート

`sessionModule` は二つのルーターを contribute し、どちらも `/session` にマウントされる:

| メソッド | パス | |
| --- | --- | --- |
| GET | `/session/csrf` | double-submit CSRF トークンの発行 |
| POST | `/session/login` | パスワードログイン |
| POST | `/session/logout` | ブラウザセッションの終了 — [無効化するもの](#post-sessionlogout-が無効化するもの) を参照 |
| GET | `/session/oauth/federation/:name` | フェデレーションの開始（`?redirect_to=`、`?link=1`） |
| GET | `/session/oauth/federation/:name/callback` | `query` フェデレーションのコールバック。`form_post` フェデレーションには `405`（`Allow: POST`） |
| POST | `/session/oauth/federation/:name/callback` | `form_post` フェデレーションのコールバック。`query` フェデレーションには `405`（`Allow: GET`） |

`:name` はフェデレーションの名前。どのモジュールも contribute していない名前は `404`。

マニフェスト（[`src/module.mts`](src/module.mts)）:

- `requires`: `config`、`userRepository`、`userSessionStore`、`federationTokenStore`、`sessionFederationIndex`、そして synthetic な `federationProviders` と `federationRedirectPolicyResolver`。後者二つは per-federation モジュールの `federations.<name>` と `federationRedirectPolicies.<name>` の contribution から boot planner が組み立てる。残り二つのセッションストア `sessionRPRegistry` と `sessionFamilyIndex` は `oauth` のもの。
- `optional`: `logger`、`rateLimiter`、`auditSink`、`subjectSessionIndex`。`auditSink` を配線しないなら `audit.sink.type = "none"`、`subjectSessionIndex` を配線しないなら `oauth.revocation.subject = "unsupported"` で宣言しなければ起動は拒否される。

### パスワードログイン

`POST /session/login` は `username` と `password` を受け取る（JSON またはフォーム）。

- どちらかが欠けていれば `400 invalid_request`。`UserRepository.authenticate` が `null` を返せば `401 invalid_credentials`。ログインに必要なストアが答えられなければ `503 temporarily_unavailable` — `UserRepository` が例外を投げた、`UserSession` の書き込みが例外を投げた、または express session を再生成できなかった（そのストアが古いレコードを破棄できなかった）場合。いずれも error レベルで 1 行、`login_store_unavailable` として `store`（`user_repository`、`user_session`、`cookie_session`）、`step`（`authenticate`、`create`、`regenerate`）、エラーの射影とともにログに出る。ユーザー名は出さない。再生成に失敗したときは `UserSession` とその subject index のエントリーをベストエフォートでロールバックし、失敗したロールバックの各ステップは `login_cleanup_failed` の warn 1 行になる。
- 成功すると `UserSession`（`amr: ["pwd"]`、寿命 `session.maxAge`）を作り、配線されていれば `subjectSessionIndex` に記録し、express session を再生成し、新しい CSRF cookie と共に `200` を返す。
- `redirect_to` を送るなら `session.redirectAllowlist` に載っていなければならず（[リダイレクト許可リスト](#リダイレクト許可リスト) を参照）、`req.session.redirectTo` に保存される。このパッケージの中にそこへリダイレクトするものは無い。
- ブルートフォース対策のガードは共有の `rateLimiter`（接頭辞 `login`、クライアント IP ごと）の上で `rateLimit.login` の窓と上限で動き、拒否すれば `429`、リミッター自体が失敗すれば `rateLimit.failMode` に従う。`rateLimiter` が配線されていなければルートはプロセス内のリミッターにフォールバックする: `deployment.mode = "multi"` では起動が拒否され、未設定なら `login_rate_limiter_not_shared` の警告がログに出て、`"single"` では何も言わない。

### `POST /session/logout` が無効化するもの

このプロバイダーにはログアウトのエンドポイントが **二つ** あり、無効化するものが同じではない。セッションが何を持っているかで選ぶ。

`POST /session/logout` — ブラウザ自身のログアウトであり、BFF / `auth.proxy` の injection トポロジーが呼ぶもの。`200 {"message": "Logged out successfully"}` を返し、次を無効化する:

| 対象 | 結果 |
|------|--------|
| express session | 破棄 |
| セッションの `sid` に対応する `UserSession` レコード | 削除 — これにより `/oauth/introspect` は `active: false` を返し、`/oauth/userinfo` は `session` グラントで発行されたトークンを拒否する |
| `subjectSessionIndex` のエントリー | 削除。`revokeAllForSubject` が死んだ `sid` を列挙しなくなる |
| その `sid` の `federationTokenStore` と `sessionFederationIndex` のエントリー | 削除。上流 IdP のトークンが保存されたまま残らない |
| **その `sid` に紐づくリフレッシュトークンファミリー** | **失効しない** |

最後の行は二度読むこと。ここでログインしたあと `/authorize` → `authorization_code` フローを完了したブラウザはリフレッシュトークンを持っており、このエンドポイントはそのファミリーを **失効させない**。リフレッシュトークンは期限切れまで使える。そのセッションには `id_token_hint` 付きの `POST /oauth/logout` を使う — 完全なカスケード（リフレッシュファミリーの失効、RP レジストリ、フェデレーション、セッション削除）を実行し、ブラウザセッションも終わらせる。

この境界は構造的なもの: カスケード（`packages/oauth/src/logout/cascadeLogout.mts`）は `refreshTokenFamilyRevocation`、`sessionFamilyIndex`、`sessionRPRegistry` を必要とし、このモジュールはそのどれも宣言しない。そして `@o3co/auth-provider-session` は `@o3co/auth-provider-oauth` を import しない — 両者は core の上の兄弟である。

`session` グラントはリフレッシュトークンを発行しないので、トークンがすべてそのグラント由来のデプロイには失効させるファミリーが無く、`/session/logout` だけで足りる。

**失敗時の振る舞い。** ストアの各ステップはベストエフォートでログに出し、呼び出し側には伝えない: ストアの障害でログアウトが `5xx` になり、ユーザーが生きた cookie を持ったままになってはならない。`UserSession` の削除が **最初に**、express session の破棄とベストエフォートの後片付けより前に実行されるので、フェデレーション系ストアの障害が肝心の無効化を妨げることはない。失敗は `logout_user_session_delete_failed`、`logout_subject_session_index_remove_failed`、`logout_federation_token_remove_failed`、`logout_session_federation_index_remove_failed` としてログに出る — アラートは最初のものに掛ける。express session の破棄が失敗する — そのストアの障害 — と応答は `503 temporarily_unavailable` で、error レベルで 1 行、`session_logout_store_unavailable`（`store: "cookie_session"`、`step: "destroy"`、`sid`）としてログに出て、クライアントは再試行する。その時点でレコードは既に消えているので、`/authorize` は残った cookie を自身の判断で拒否する。`sid` を持たないセッションには無効化するレコードが無く、express session だけが破棄される。

### 状態変更ルートの CSRF 対策

`POST /session/login` と `POST /session/logout` は、same-origin（または明示的に信頼した）`Origin` / `Referer` **か**、有効な double-submit CSRF トークン **の** どちらかを持つリクエストを受理する。どちらも持たないリクエストは `403 access_denied` で拒否する。

- **ブラウザ** は何も追加しなくてよい: same-origin の `fetch` / フォーム送信ではブラウザが `Origin` を付け、それだけで検査を通る。
- **ヘッダーを持たないクライアント**（curl、サーバー側のエージェント、テストハーネス）は `GET /session/csrf` を呼ぶ。JS から読める `<session.name>.csrf` cookie がセットされ、同じ値が `csrf_token` として返る。両方を送り返す: cookie と、`x-csrf-token` ヘッダーまたは `csrf_token` フォームフィールドのどちらか。
- **foreign な** `Origin` はトークンがあっても拒否する。クロスサイトリクエストであることの積極的な証拠だから。
- ログインに成功すると **新しい** CSRF cookie が返るので、続くログアウトに追加の往復は要らない。

トークンは乱数 nonce と有効期限（`session.csrf.ttlSeconds`）に対する署名付きでステートレスな HMAC で、鍵は `session.secret` の HKDF 展開 — 親ドメインの cookie を書けるサブドメインでも偽造できない。クロスオリジンのログイン UI は自身のオリジンを `session.csrf.trustedOrigins` に載せる。`cors.allowedOrigins` は CSRF の信頼を与えない。

`checkRequestOrigin`、`createCsrfProtection`、`createCsrfProtectionFromConfig`、`createCsrfGuard`、`createCsrfIssueHandler` は、独自のログインページをマウントしたり独自のルートを保護したりする組み立てのために export されている（[`src/csrf.mts`](src/csrf.mts)）。`@o3co/auth-provider-device-grant` はこれらで検証ページを守っている。

### セッションが認証について記録するもの

すべてのセッションは `authTime` と `amr` — ユーザーがどう認証したかを表す RFC 8176 の値 — を持つ。これにより `/authorize` は `max_age`・`prompt=login`・`acr_values` を扱え、id_token は `auth_time`・`amr`・`acr` を示せる（全体像は [oauth パッケージの README](../oauth/README.ja.md) にある）:

| ログイン経路 | `amr` |
| --- | --- |
| `POST /session/login` | `["pwd"]` |
| フェデレーションのコールバック | プロバイダーがプロファイルに載せた上流 IdP の `amr`（`profile.amr`、文字列の配列）に、`fed` — 「フェデレーション経由」を表すデプロイ定義のマーカーで、`FEDERATED_AMR` として export — を加えたもの。RFC 8176 にはこれを表す値が無く、OIDC Core は `amr` の値をデプロイに委ねている。 |
| 再開された MFA ログイン（`POST /auth/mfa/verify`、デプロイが組み立てる） | デプロイの再開ハンドラーが記録するもの: 最初の要素の値に `mfa`、その要素自身の値（`otp` など）を加えたもの。`CreateUserSessionInput.amr` がその継ぎ目。 |
| アカウントリンク（`?link=1`） | 変わらない — リンクはログインではない |

再認証は *新しい* セッションである: `POST /session/login` とフェデレーションのコールバックは常に新しい `authTime` でセッションを作り、`max_age` と `prompt=login` が測るのはそれである。既に認証済みのブラウザをそのまま `/authorize` に送り返すログインページは、そこで `login_required` を返され、ループしない。

### フェデレーション間のアカウントリンク（#482）

フェデレーションの ID は `<provider>:<sub>` — フェデレーションの名前と、IdP の不透明で安定した subject — であり、コールバックが `UserRepository.authenticateByToken` に渡すのはこの文字列である。**それが誰かを決めるのは Store。** このパッケージはメールアドレスでリンクしない: Web で Google、iOS で Apple でサインインする同じ人物は二つの ID であり、それが一つのアカウントかどうかは Store の記録であって、IdP が主張したアドレスからの推論ではない。

アカウントが二つ目の ID を得るのは、明示的で認証済みの操作によってだけ:

1. ブラウザが既にセッションを持っている（`isAuthenticated`、生きている `UserSession`）。
2. `?link=1` 付きでフェデレーションを開始する: `GET /session/oauth/federation/<name>?link=1` を **デプロイ自身のページ上のリンクまたはフォームから**。開始は GET でセッション cookie は `SameSite=Lax` なので、検査が無ければどのページでもサインイン中のユーザーをそこへ送れ、IdP 側のログイン CSRF と組み合わせれば攻撃者の ID が被害者のアカウントにリンクされてしまう。そのため開始には積極的な証拠が要る: `Sec-Fetch-Site: same-origin`、または `none`（入力された URL やブックマーク）。`cross-site` は拒否。`same-site` はそれだけでは足りない — 登録可能ドメイン上のすべてのホスト、ユーザーが管理する `blog.example.com` も含む — ので、それと `Sec-Fetch-Site` の無いリクエスト（古いブラウザ）は `Referer` にこのオリジンか `session.csrf.trustedOrigins` 上のオリジンを示さなければならない。`Referer` が無ければ拒否する。遷移元のページが自分でリファラーポリシーを選ぶからである。したがって兄弟ホスト上のアカウントページは `session.csrf.trustedOrigins` に載せ、`Referrer-Policy: no-referrer` を送ってはならない。拒否は `403 link_requires_trusted_origin`。認証済みセッションが無ければ `401 login_required`、Store のリポジトリが `linkFederatedIdentity` を実装していなければ `400 link_unsupported` — いずれもブラウザをどこかへ送る前に返る。
3. コールバックでは、`state`・PKCE・`nonce` をログインとまったく同じく検査したあと、ID を解決する:
   - **誰でもない** → `userRepository.linkFederatedIdentity(currentUserId, { provider, sub, token, claims })`。`ok` ならリンクされ、Store の `refused` は `403 link_refused`、`conflict` は `409 identity_conflict`。Store が `description` を返せば、RFC 6749 の文字の範囲で（範囲外の文字は `?` として）それを説明に載せる。
   - **別のアカウント** → `409 identity_conflict`。Store には問い合わせない。リンクでアカウントがマージされることはない。
   - **このアカウント** → リンクするものは無く、コールバックはそのまま進む。
4. フェデレーションは **生きている** セッション — 現在の `sid` の下の `sessionFederationIndex` と `federationTokenStore` — に紐づけられ、ブラウザはログイン後と同じようにリダイレクトされる。新しい `UserSession` は作られず、express session も再生成されない: リンクはログインではなく、セッションのクレームエンベロープは変わらない（新しいプロバイダー経由の次のログインが通常どおりに作る）。

トランザクションは要求したセッション（`link: { sid }`）を記録し、コールバックは *その* セッションのアカウントにリンクする。`form_post` フェデレーションのコールバックはアプリケーションのセッション cookie（`SameSite=Lax`）が付かないクロスサイト POST なので、それを束縛するのはこの記録である — Sign in with Apple も `query` フェデレーションとまったく同じようにリンクする — そして、コールバックで別の認証済みセッションを提示したブラウザは `401 login_required` で拒否される: ID がブラウザが今持っているセッションにリンクされることはない。Store がリンクしたあとで生きたセッションへの紐づけに失敗した場合、途中まで紐づいたフェデレーションはベストエフォートでセッションから外され（セッションが元から持っていたものはそのまま。セッションのフェデレーション一覧をそもそも読めなかったときは何も外さない）、コールバックは `503` を返す。Store のリンクは残り、そのフェデレーション経由の次のログインはそのアカウントに着地する。リンクに必要なストアが答えられない場合 — セッションの読み出し、Store の `linkFederatedIdentity`、インデックスの読み書き、トークンの紐づけ — はいずれも `503 temporarily_unavailable` で、error レベルで 1 行、`federation_link_store_unavailable` として `store`、`step`、リンク中の `sid`、エラーの射影とともにログに出る。失敗したロールバックの各ステップは `federation_cleanup_failed` の warn 1 行になる。

`link=1` が無い場合、Store が知らない ID のフェデレーションを完了した認証済みセッションは `401 unknown_user`。**暗黙のリンクは無い** — セッション cookie とはぐれた ID の組み合わせはログイン CSRF の形であり、認証済みセッションでの `link=1` がそれをユーザーの操作にする。

監査イベントは二つ: `federation.identity.linked` と `federation.identity.link_refused`（`details.reason`: `conflict` または `refused`）。どちらも `subject` はそのアカウント。

**リンクする前に Store が検査すべきこと。** この継ぎ目が受け取る `claims` はプロバイダーがマップしたもの — IdP の主張であってそれ以上ではない:

- **メールアドレスだけで結びつけない。** IdP が検証していないアドレス（`emailVerified !== true` — [欠落は `false` ではなく、文字列は欠落扱い](#emailverified-は-idp-が何を送っても-boolean)）、リレーアドレス（Apple の `@privaterelay.appleid.com`、`isPrivateEmail` として出る）、ユーザーがアドレスを変更できる IdP は、既存アカウントと照合してはならない。典型的なアカウント乗っ取りはまさにその照合である。
- リンク要求は既に認証済み — それが生きたセッション上の `link=1` の保証 — なので、リンクを認可するのは一致するアドレスではなくセッションである。それでも Store は拒否してよい: アカウントあたりプロバイダーごとに一つの ID、再認証からの最大経過時間、新しい ID に検証済みアドレスを要求する、など。
- `sub` は issuer ごとに不透明で安定している。`<provider>:<sub>` をそのまま保存し、`email` から ID を導出しない。

`@o3co/auth-provider-foundation` の `HttpUserRepository` は `linkFederatedIdentityUrl`（`CLIENT_USER_LINK_FEDERATED_IDENTITY_URL`）が設定されていればこの継ぎ目を実装する: ワイヤ契約は [その README](../foundation/README.ja.md) を参照。core のインメモリリポジトリはメモリ上でリンクするだけ — 開発用であって永続化ではない。

## フェデレーションアダプターの駆動

アダプター契約 — `FederationProvider`、`FederationProfile`、オプショナル capability とそのガード、response mode の語彙 — は core で定義・説明されている: [`core/src/federations/README.md`](../core/src/federations/README.md)、定義は [`types.mts`](../core/src/federations/types.mts) と [`response-mode.mts`](../core/src/federations/response-mode.mts)。これらの名前は `@o3co/auth-provider-core` から import する。このパッケージは再エクスポートしない。この節はセッションルーターがアダプターに対して何をするかである。

契約のうちルーターが駆動するのは `buildAuthorizationUrl`、`exchangeCode`、`responseMode`、`SupportsClaimMapping`。他の capability は別の場所で駆動される: `SupportsLogout` は `oauth` の `/oauth/logout` と `POST /oauth/federation/:name/logout`、`SupportsRefresh` は `oauth` の `POST /oauth/federation/:name/token`、`SupportsDelegatedAuthorization` は `federation-grants`。

### 開始レグ

`GET /session/oauth/federation/:name` は、IdP が nonce を使うかどうかにかかわらずすべてのフェデレーションについて、`state`（128 ビット）、PKCE の `codeVerifier`、`nonce`（128 ビット）を生成し、`redirect_to` とリンクの意図と一緒に、リダイレクト **の前に** 保存する: `query` フェデレーションなら express session に、`form_post` フェデレーションなら [フェデレーショントランザクション](#トランザクション-cookie) に。保存できないストアは `503 temporarily_unavailable` を返して誰もリダイレクトせず、error レベルで 1 行、`federation_start_store_unavailable`（`store`: `cookie_session` または `federation_transaction`）としてログに出る。リクエスト上に express-session のストアが無い、またはコールバック URL にパスが無い `form_post` フェデレーションは組み立ての誤りであり、`500 misconfiguration` を返す。これらのルートが出会う組み立ての誤り — それ、コールバック URL の無いプロバイダー、リダイレクトポリシーの無いプロバイダー — はいずれも error レベルで 1 行、`federation_misconfigured` として `reason`（`no_session_store`、`no_callback_path`、`no_callback_url`、`no_redirect_policy`）とともにログに出る。`buildAuthorizationUrl` に渡す `redirect_uri` は設定上のそのフェデレーションの `callbackURL`。`form_post` フェデレーションではアダプターが返した URL にルーターが `response_mode=form_post` を付け足し、`query` フェデレーションではアダプターが返した URL そのままになる。

### コールバックがプロファイルで行うこと

1. **アダプターは `callbackParams` を見る** — コールバックの文字列パラメーターから、ルーターが既に束縛した `code` と `state` を除いたもの。ユーザーエージェント経由で中継され署名されていない。アダプターはその中の RFC 9207 `iss` を core の `callbackUrlForExchange` 経由で渡す。
2. **`exchangeCode` が例外を投げると `502 exchange_failed`。** アダプター内のあらゆる拒否 — 誤った `iss`、不正な id_token、UserInfo の不一致 — はこの形で表に出て、Store には届かない。`sub` の無いプロファイルは `400 invalid_profile`。警告 `federation token exchange failed` が運ぶのは core の `loggableError(err)` であり、エラーそのものではない: OAuth ライブラリは拒否したトークン応答を、アクセストークンとリフレッシュトークンを含めてエラーの cause の連鎖に載せるので、エラー全体をシリアライズするロガーはそれを書き出してしまう。これらのルートがログに書く他の失敗 — ストア、リポジトリ、express-session のもの — も同じように射影する（Redis ストアのエラーは拒否されたコマンドの引数を運ぶ。`allow-plaintext` ならトークンレコードである）。
3. **ID は Store が解決する。** `<name>:<sub>` を `UserRepository.authenticateByToken` に渡し、例外なら `503 temporarily_unavailable`、`null` なら `401 unknown_user`（開始でリンクを求めていない限り）。
4. **クレーム** はローカルの `User` のものに、`mapClaims` の結果を [クレームの優先順位](#クレームの優先順位-ローカルが勝ちfederated-は名前空間に隔離される) に従って合わせたもの。`amr` は `profile.amr` に `fed` を加えたもの。
5. **セッション** は新しい `UserSession`（寿命 `session.maxAge`）、配線されていれば `subjectSessionIndex` のエントリー、`sessionFederationIndex` のエントリー、そして再生成された express session。コールバックに欠かせないストアが失敗した場合 — Store の照会、`UserSession` か `sessionFederationIndex` の書き込み、express session の再生成・保存、下のトークンの紐づけ、そしてそれらすべてに先立つ一時状態の破棄（[トランザクションが消費されるとき](#トランザクションが消費されるとき) を参照） — はいずれも `503 temporarily_unavailable` で、error レベルで 1 行、`federation_callback_store_unavailable` として `store`、`step`、エラーの射影とともにログに出る。書き込んだものはベストエフォートで逆順にロールバックされ、失敗したロールバックの各ステップは `federation_cleanup_failed` の warn 1 行になる。`subjectSessionIndex` の書き込みが失敗してもログに出る（`subject_session_index_write_failed`）だけでログインは進む。
6. **トークン** は、プロファイルが `accessToken` を持つときにだけ、新しい `sid` の下で `federationTokenStore` に紐づけられる:
   - `accessToken`、`refreshToken`、`idToken`、`expiresAt` はアダプターが返したまま — `expiresAt: null` は `null`（「リフレッシュしない」）として保存され、ルーターが有効期限をでっち上げることはない。
   - `scope` と `grantedScope`: アダプターが `profile.scope` を返していればそれ（空や使えない文字列は何も表さない）、返していなければプロバイダーが要求した `scope` — RFC 6749 §3.3 は応答の欠落を「要求どおり」と読む（[`src/federations/consented-scope.mts`](src/federations/consented-scope.mts)）。
   - `tokenType`: `profile.tokenType` をそのまま、文字列でなければ `""`、アダプターが返さなければ `undefined`（`oauth` はそれを `Bearer` と読む）。

   `profile.expiresIn` はここでは読まれない。
7. **リダイレクト** はそのフェデレーションのリダイレクトポリシーの `resolveCallbackRedirect` が決める。デフォルトのポリシーは、開始時に `redirect_to` があればその `authCallbackUrl` に `redirect_to` を付けたもの、無ければその `clientUrl` を返す。

### response mode: `query` と `form_post`

ほとんどの IdP は認可応答をクエリ文字列に載せてブラウザをリダイレクトで戻す。Sign in with Apple は違う: 要求した `scope` に `name` か `email` が含まれると、Apple は `application/x-www-form-urlencoded` のボディをコールバックへ **POST** する。プロバイダーはこれを `responseMode: "form_post"` で宣言し（無ければ `query`）、その宣言はルーターの三つの振る舞いを変え、アダプターは何も変えない:

1. **開始ルートが `response_mode=form_post` を付け足す。** このパラメーターはアダプターごとではなくルーターで一度だけ書かれる。
2. **`POST /session/oauth/federation/<name>/callback` がフォームボディを受け付ける。** パラメーターの出所が違うだけで GET コールバックと同じハンドラーである: 同じエンベロープの検索、同じ `state` の比較、同じ「非同期処理の前に破棄する」再利用防止、リクエストからではなく保存したエンベロープから読む同じ PKCE verifier と nonce、同じロールバック。**各 response mode が受け付けるメソッドはちょうど一つ**: `query` フェデレーションは POST に `405 method_not_allowed`（`Allow: GET`）を返すので POST の口を持たず、`form_post` フェデレーションは GET にトランザクション cookie を読む前に `405 method_not_allowed`（`Allow: POST`）を返すので、第三者の `<img src=".../callback">` はフローに届かない。
3. **そのフェデレーションの一時的な状態はセッションではなくフェデレーショントランザクションに置かれ**、専用の cookie を持つ。

#### トランザクション cookie

`form_post` のコールバックは IdP のオリジンからの **クロスサイト POST** として届き、`SameSite=Lax` の cookie — デプロイのデフォルトであり、正しいデフォルト — はそれには付かない。セッション cookie に頼るコールバックは比較すべき `state` も PKCE verifier も無いまま届くことになる。フローにはクロスサイト POST を越える *何らかの* cookie が要るが、それがセッション cookie であってはならない。開始ルートは認証不要で、`SameSite=Lax` の cookie はトップレベルの GET には **付く** ので、開始レグがセッション cookie について何かを変えられるなら、ブラウザにリンクを一つ踏ませられる第三者なら誰でもそれを変えられることになる — しかも恒久的に。express-session は `req.session.cookie` をストアにシリアライズし、以後のリクエストのたびにそこから組み立て直すからである。

そこでクロスサイトの部分は専用の cookie と専用のレコードを持つ:

| | 値 |
|---|---|
| cookie 名 | `__Secure-<session.name から接頭辞を除いたもの>.federation` — 例: `__Host-auth.session` も `auth.session` も `__Secure-auth.session.federation` になる |
| 属性 | `HttpOnly; Secure; SameSite=None`、`Path` はそのプロバイダーのコールバック URL に限定、`Max-Age` はトランザクションの寿命（10 分） |
| 中身 | 不透明な 256 ビットの ID だけ |
| レコード | `state`、`codeVerifier`、`nonce`、`redirectTo`、リンクの意図、プロバイダー名。express-session のストアに `fedtx:` というキー接頭辞で置かれる |

名前は CSRF cookie と同じく `session.name` から導かれる。接頭辞だけが例外で、**無条件に** 付けられる: `__Host-` ではなく `__Secure-` なのは、`__Host-` は `Path=/` を要求し、この cookie はコールバックにパスを限定しているので `__Host-` の名前ではどのブラウザにも捨てられるから。無条件なのは、この cookie が `SameSite=None` であり、したがって常に `Secure` だから（`Secure` でない `SameSite=None` の cookie はブラウザが捨てる）。したがって `form_post` フェデレーションを持つデプロイはコールバックを HTTPS で提供する — Apple はいずれにせよ戻り URL に HTTPS を要求する。

**アプリケーションのセッション cookie はデプロイが設定した属性を保つ**。`form_post` フェデレーションを開始したことがあるかどうかにかかわらず、すべてのセッションで。`session.sameSite` に触れることは無い。

トランザクションはコールバックを、それを開始したブラウザに束縛する。`state` の比較は引き続き行われ、トランザクション cookie はそれへの追加であって置き換えではない。盗んだ `state` を対応するトランザクション cookie なしで提示した呼び出しは、`state` を読む前に拒否される（`400 invalid_session`）。

リクエスト上で express-session のストアに到達できない場合 — ストアモジュールが無い、または `sessionModule` より後にマウントされている — `form_post` の開始は、完了できないフローを始める代わりに `500 misconfiguration` を返す。

放棄されたフローに残るのは短命な cookie だけで、レコードもそれと一緒に期限切れになる: 有効期限はレコードに `cookie.expires` として書かれ、`MemoryStore` は読み出し時にそれで回収し、`connect-redis` はそれをキーの `EX` にする。

#### 認証ホストの登録可能ドメイン配下のすべてのホストは信頼境界の内側

cookie を厳密に一つのホストに固定するのは `__Host-` であり、`__Secure-` は HTTPS を要求するだけである。トランザクション cookie はホスト限定（`Domain` 属性なし）で発行されるが、`__Secure-` という名前は、別のホストが認証ホストを覆う `Domain` で同名の cookie をセットすることを止めず、ブラウザはそちらもコールバックに送る。したがってトランザクション cookie は、`form_post` フローがセッション cookie — デフォルトで `__Host-`、つまりホスト限定であり、起動時にそう検査される — より弱い唯一の場所である。

- **攻撃者に必要なもの:** 認証ホストに対する cookie をセットできるホストのどれか一つの制御 — `auth.example.com` なら、その登録可能ドメイン `example.com` 配下のあらゆるホスト: `blog.example.com`、忘れられたステージングホスト、ぶら下がった DNS レコード、隣の低信頼アプリの XSS、共有ホスティングの隣人。このデプロイからは何も要らない: セッションも `state` もアカウントも。
- **それで得られるもの:** そのホストから被害者のブラウザに `Domain=example.com` で `__Secure-<name>.federation` をセットし、自分のフェデレーションフローを開始し、*自分の* トランザクション ID を仕込み、*自分の* `state` と `code` をコールバックに自動送信する。被害者のブラウザは **攻撃者の** フェデレーションアカウントにログインした状態になり、被害者のその後の操作はそのアカウントに記録される。被害者のセッションを読むことも、資格情報を晒すことも、被害者自身のアカウントに届くこともない — ID の取り違えであって、アカウント乗っ取りではない。
- **cookie に署名しても防げない理由:** 攻撃者のトランザクションは本当に攻撃者のものであり、サーバーが自分の発行物として受け入れるものは何でも攻撃者が正当に持っている。パスを限定した cookie に固有の性質である。
- **すべきこと:** 認証ホストの登録可能ドメイン配下のすべてのホスト — `auth.example.com` ならすべての `*.example.com` — をデプロイの信頼境界の内側として扱い、そのどれでも信頼できない・低信頼のコンテンツを動かさない。`session.domain = null`（`__Host-` のデフォルト）が守るのはセッション cookie であってトランザクション cookie ではなく、これに対しては何もしない。ログインルートでは署名付き CSRF トークンがこの規則を補うために存在するが、ここには束縛すべきセッションが無いので、この規則が緩和策のすべてである。

#### トランザクションが消費されるとき

レコードと cookie は、トランザクションを **判定した** コールバックの出口すべて — 成功、`invalid_state`、`exchange_failed`、`unknown_user` いずれも — で破棄され、何も判定しなかった拒否では意図的に破棄 *されない*。規則: **拒否がトランザクションを消費するのは、リクエストがそれについて主張をしたときであり、何も主張しなかったときは手を付けない。** `state` がその主張である。`state` を持たないコールバック（レコードがこのプロバイダーのものに解決した後で確認する）は何も主張せず何も失わない（`400 invalid_request`、レコードはそのまま）。GET は cookie を読む前に `405` で拒否される。*誤った* `state` はこのトランザクションへの試行であり、やはり消費されるので、推測に二度目は無い。レコードに解決しない、または別のプロバイダーのものに解決するトランザクション ID（`400 invalid_session`）も同様に消費し、ストアの読み出しが失敗した場合はベストエフォートで消費する（`503`。そこや拒否での消費が失敗すれば `federation_cleanup_failed` の warn 1 行）。この区別が重要なのは、cookie がやむを得ず `SameSite=None` で、コールバックのパスへのあらゆるクロスサイトリクエストに付くからである: どの拒否でもレコードが消費されるなら、第三者は `<img>` タグ一つで被害者の進行中のログインを壊せてしまう。

この規則は `form_post` だけのもの。`query` フェデレーションはエンベロープをセッションに置き、`state` が *一致した* 経路でだけ破棄するので、誤った `state` ではエンベロープが残る — セッション cookie は `SameSite=Lax` でトップレベルのクロスサイト GET には **付く** ため、不一致でエンベロープを消費すれば第三者に同じ可用性攻撃を与えてしまうからである。それで防げるはずの推測は現実的なものではない: `state` は CSPRNG からの 128 ビットである。両モードに共通なのは「`state` が無い」場合の規則だけ。

#### 「一度きり」が保証すること

レコードの破棄は `get` のあとに `destroy` で、往復が二回ある。express-session の `Store` API は `get` / `set` / `destroy` で、compare-and-delete は無く、この三つからアトミックな読み出しと消費は組み立てられない。

| | |
|---|---|
| **保証する** | 先行するコールバックが削除を終えた *あと* に届いたコールバックはレコードを見つけられず拒否される。これが対象とするリプレイ — プロキシのログから抜かれた `code` と `state`、戻るボタン、再試行されたリクエスト — はこれで防がれる。 |
| **保証しない** | *重なった* コールバック。どちらかが削除する前に両方がレコードを読めば、両方が `state` の比較を通り、両方が `exchangeCode` に達する。`MemoryStore` は同期的に応答するので結果的に直列化されるが、ネットワーク遅延のあるストアではそうならない。 |
| **重なりを抑えるもの** | IdP。認可コードは IdP 側で一度きりで、競合するコールバックは必ず同じコードを持つので、何本がそこまで進んでも交換に成功するのは高々一つ — 残りは `502 exchange_failed`。PKCE がその交換をレコード内の verifier に束縛する。 |

レコードがまったく削除できないなら、コールバックはコードを交換せずに `503 temporarily_unavailable` で止まる。これは `DeviceCodeStore` より弱い。あちらはアトミックな読み出しと消費である: あのストアは自前のアダプターを持ち、消費を Redis の一往復に押し込めるが、フェデレーショントランザクションはすべてのデプロイが設定しなければならないコンポーネントスロットを追加する代わりにセッションストアを共有している — IdP が既に提供している性質のために。[`Federation.transactionConcurrency.test.mts`](src/routes/__tests__/Federation.transactionConcurrency.test.mts) が表の両半分を固定している。

`query` フェデレーションはこれらのどれにも影響されない: コールバックは同一サイトのトップレベル GET で、エンベロープは `req.session.federation` に残り、認可 URL はアダプターが作ったものそのままである。

### クレームの優先順位: ローカルが勝ち、federated は名前空間に隔離される

`mapClaims` が返すのは **上流 IdP の主張** であって、このデプロイについての事実ではない。コールバックはそれをセッションのクレームエンベロープに丸ごと混ぜることはせず、一つの規則を適用する（[`src/federations/claim-precedence.mts`](src/federations/claim-precedence.mts)、`mergeFederatedClaims` として export）:

- **ローカルのレコードが正。** `User` から読んだクレーム（`email`、`emailVerified`、`name`、`picture`、`groups`）はそのまま残り、federated な値がそれを置き換えることはない。
- **隙間を埋めてよいのは三つのクレームだけ** — `email`、`name`、`picture`（`PROMOTABLE_FEDERATED_CLAIMS`）— で、ローカルのレコードがそのフィールドを欠いていて、かつ federated な値が文字列のときに限る。
- **それ以外はすべて** `claims.federated[<providerName>]` **の下に名前空間化される**。昇格した値やローカルのクレームに負けた値も含め、そのまま完全に。

したがって IdP は `groups`（アダプターが作り出した `roles` / `scope` / `permissions` も）を持ち込めない: それらは `claims.federated[<providerName>]` に届くだけである。`filterClaimsByScope` はプロバイダー固有のクレームを出力しないので、名前空間の下のものが id_token や `/userinfo` の応答に偶然現れることはない。

**`federated` クレームは任意 — 存在を確かめて読む。** プロバイダーが少なくとも一つのクレームをマップしたときにだけ書かれるので、`SupportsClaimMapping` を実装しないプロバイダーのセッションや、`mapClaims` が `{}` やオブジェクトでない値を返したセッションには無い。プロバイダーのキーも保証されない: セッションが持つのはそれを認証した一つのプロバイダーだけである。`claims.federated[name].groups` ではなく `claims.federated?.[name]?.groups` と書く。

`emailVerified` は昇格できない。これは `oauth.requireEmailVerified` がトークン発行の関門として読める Store 所有の状態であり、上流 IdP が検証するのは *その IdP が* 管理するアドレスである — `provider:sub` の結びつきは、それがローカルアカウントのアドレスであることを保証しない。この主張に基づいて動きたいデプロイは `claims.federated?.[<providerName>]?.emailVerified` を読み、その結果を `User` に反映する。

```ts
// user: { id, username, email: "alice@corp.example", groups: ["staff"] }
// mapClaims → { email: "alice@gmail.example", picture: "https://…", groups: ["admin"] }
{
  email: "alice@corp.example",          // ローカルが勝つ
  groups: ["staff"],                    // federated な groups はここに届かない
  picture: "https://…",                 // 隙間を埋めた
  federated: {
    google: { email: "alice@gmail.example", picture: "https://…", groups: ["admin"] },
  },
}
```

#### `emailVerified` は IdP が何を送っても boolean

`MappedClaims.emailVerified` は `boolean | undefined` であり、そこへ正規化するのは **アダプターの** 仕事 — マージは型変換をせず、下流も何もしない。Sign in with Apple は応答によって `email_verified` を *文字列* の `"true"` で送る。`Boolean("false")` は `true` なので、型変換するアダプターは未検証のアドレスを検証済みと報告してしまう。`"true"` / `"false"` はそれぞれの boolean として読み、それ以外の形は **欠落** として扱う — 欠落は `false` ではない。`mapClaims` の出力に boolean でない値が届いても昇格はされないが、`claims.federated[<providerName>]` の下にはそのまま *記録される*。それを関門として読むデプロイは文字列を読むことになる。

### フェデレーションの設定

`federations.<name>` がフェデレーションに名前を付け、`extractFederationSection`（[`src/federations/extract-federation-section.mts`](src/federations/extract-federation-section.mts)）がそれを読むモジュールのためにセクションを正規化する。受け付ける形は三つ:

```hocon
federations {
  # 省略形: キーが type を表す（ここでは "google"）。
  google {
    enabled = true
    clientId = ${FEDERATIONS_GOOGLE_CLIENT_ID}
    clientSecret = ${FEDERATIONS_GOOGLE_CLIENT_SECRET}
    callbackURL = "https://auth.example.com/session/oauth/federation/google/callback"
    clientUrl = "https://app.example.com/"
  }

  # type を明示したフラットな形。
  okta {
    enabled = true
    type = "oidc"
    issuer = "https://dev-123.okta.com"
    # …
  }

  # ネストした形: type の名前のサブセクションの下に資格情報を置く。
  keycloak {
    enabled = true
    type = "oidc"
    oidc {
      issuer = "https://sso.example.com/realms/staff"
      # …
    }
  }
}
```

ネストした形のセクションがトップレベルにも `clientId`・`clientSecret`・`callbackURL` を持つと起動に失敗する。それ以外のトップレベルのフィールドはサブセクションと並んで残り、サブセクションも同じフィールドを持てばサブセクションの値で上書きされる。`enabled = true` の無いセクションは無視される。Google・GitHub・Apple のモジュールはシングルテナント — それぞれ固定の名前（`google`、`github`、`apple`）でプロバイダーを登録する — なので、デプロイが持てるのはそれぞれ高々一つ。`type = "oidc"` のセクション（[`@o3co/auth-provider-federation-oidc`](../federation-oidc/README.md)）は一セクションが一フェデレーションになる。

起動時の規則:

- 有効なセクションはすべて `callbackURL` を持たなければならず、無ければ `sessionModule` が起動に失敗する。フェデレーションルーターはまさにその値を `redirect_uri` としてアダプターに渡す。
- すべての `federations.<name>` の contribution には `federationRedirectPolicies.<name>` の contribution が対になっていなければならず（逆も同じ）、そうでなければ `federation-redirect-policy-unpaired` で起動に失敗する。
- `sessionModule` は設定と contribution を突き合わせない。設定で有効だがどのモジュールも contribute していないフェデレーションは起動し、そのルートは `404` を返す。有効なセクションなしに contribute されたフェデレーションにはコールバック URL が無く、その開始は `500 misconfiguration` を返す。どちらかで起動を失敗させたい組み立ては自分で検査を加える。

### リダイレクト許可リスト

`GET /session/oauth/federation/:name?redirect_to=…` と `POST /session/login` の `redirect_to` は、その後ブラウザが行く先を示す。どちらも示せる値はすべて列挙されていなければならない: フェデレーションは `federations.<name>.redirectAllowlist`（そのリダイレクトポリシーが読む）、ログインは `session.redirectAllowlist`。

```hocon
federations {
  google {
    enabled = true
    # …資格情報…

    redirectAllowlist = [
      "https://app.example.com/welcome"
      "https://app.example.com/account/linked"
      "http://localhost:5173/welcome"      # ローカル開発のフロントエンド
    ]

    sessionDomain    = ".example.com"
    authCallbackUrl  = "https://app.example.com/auth/callback"
    clientUrl        = "https://app.example.com/"
  }
}
```

両方のリストに共通の規則（[`src/redirect-allowlist.mts`](src/redirect-allowlist.mts)）:

- **照合は完全一致。** スキーム、ホスト、ポート、パス、クエリ、フラグメントのすべてが効く。正規化で消えるのは大文字小文字、デフォルトポート、`..` セグメント、パーセントエンコーディングだけ。ワイルドカード・前方一致・サブドメイン一致は無い — エントリーは自分の兄弟を許さず、動的なクエリパラメーターを持つ行き先は一族としてまとめて列挙できない。固定のパスにし、変わる部分はセッションで運ぶ。
- **リストが無いか空なら、どの `redirect_to` も `400 invalid_redirect` で拒否する。** パラメーターを使わないデプロイにはそれが正しい設定であり、すべてを許す方法ではない。
- **ループバック以外は `https` が必須。** `localhost`、`127.0.0.0/8`、`[::1]` は `http://` を使える。これでローカル開発のフロントエンドやネイティブクライアントのループバックリスナーが証明書なしで動く。ポートは照合されるので、クライアントがバインドするポートを列挙する — RFC 8252 §7.3 のポートを問わないループバック比較はここでは実装されていない。
- **cookie ドメインが設定されていれば、リスト自体を制約する。** ループバックでないエントリーはすべて `sessionDomain`（フェデレーション）または `session.domain`（ログイン）の内側でなければならず、ポリシーを組み立てる時点で検査されるので、外側のエントリーは効いているような顔で設定に残るのではなく起動に失敗する。別ドメインへのリダイレクト先を本当に意図するなら、そのフェデレーションの `sessionDomain` を外す。

`authCallbackUrl` と `clientUrl` は許可リストではなく `resolveCallbackRedirect` が読む: 前者は `redirect_to` を受け渡すブリッジページ、後者は開始時に `redirect_to` が無かったコールバックの戻り先。どちらかが必要なのに未設定のコールバックは、セッションを保存したあとで `500 misconfiguration` を返す。したがって、すべての開始が `redirect_to` を持つのでない限りどのフェデレーションにも `clientUrl` が必要で、`redirect_to` を持つ開始には `authCallbackUrl` が必要になる。

`FederationRedirectPolicy`（[`src/federations/redirect-policy.mts`](src/federations/redirect-policy.mts)）が差し替え点である: モジュールはフェデレーションに独自のポリシーを contribute でき、そのポリシーは fail closed でなければならない。`createFederationRedirectPolicy` がデフォルトで、`checkRedirectShape`、`createRedirectAllowlistValidator`、`describeRedirectRejection`、`isLoopbackHostname` は独自のポリシーが同じ規則と拒否の語彙を再利用できるよう export されている。ポリシーのメソッドは [`FederationResult`](src/federations/types.mts) で答える: 値を持つ `ok`、または返すステータス・OAuth エラーコード・説明。ルートはステータスをそのまま返し、コードと説明は core の `errorEnvelope` を通して送る。そこが RFC 6749 の文字（`"` と `\` を除く印字可能な ASCII）に収めるので、範囲外の説明の文字は `?` として出る。形式に合わないコードは、4xx なら `invalid_request` として出し（拒否はあくまでクライアントのものであり、`400 server_error` は自己矛盾になる）、`redirect_policy_error_malformed` をログに残す。それ以外のステータスでは `server_error` として出る。`describeRedirectRejection` のテキストは最初から範囲内である。

### アダプターの書き方

OpenID Connect の discovery ドキュメントを公開する IdP なら、コードは書かない: [`@o3co/auth-provider-federation-oidc`](../federation-oidc/README.md) の `type = "oidc"` セクションがアダプターになる。そうでなければ、アダプターは `federations.<name>`（`FederationProvider`）と `federationRedirectPolicies.<name>` の両方を contribute するモジュールであり、設定は小さなブリッジモジュールが `extractFederationSection` から埋める型付きの `ComponentMap` スロットに載せる:

```ts
import { defineModule, type FederationProvider } from "@o3co/auth-provider-core";
import { createFederationRedirectPolicy } from "@o3co/auth-provider-session";

declare module "@o3co/auth-provider-core" {
  interface ComponentMap {
    readonly exampleFederationConfig?: ExampleConfig;
  }
}

export const exampleFederationModule = defineModule({
  name: "federation:example",
  requires: ["exampleFederationConfig"] as const,
  contributes: {
    federations: {
      example: (deps): FederationProvider => createExampleProvider(deps.exampleFederationConfig),
    },
    federationRedirectPolicies: {
      example: (deps) => createFederationRedirectPolicy(deps.exampleFederationConfig),
    },
  },
});
```

契約自身の規則は [core の README](../core/src/federations/README.md) と [`types.mts`](../core/src/federations/types.mts) の doc コメントにある。core がプロバイダー側に与えるもの（`@o3co/auth-provider-core` から export）:

- `codeChallenge(codeVerifier)` — ルーターが生成した verifier に対する S256 challenge（[`pkce.mts`](../core/src/federations/pkce.mts)）。
- `callbackUrlForExchange({ redirectUri, code, callbackParams })` — コード交換で OAuth ライブラリに渡す URL: `code`、コールバックが持っていれば RFC 9207 の `iss`、そしてバッグからはそれ以外何も載せない。`code` だけから URL を組み直すと `iss` が落ち、mix-up の検査が行われず、`authorization_response_iss_parameter_supported` を広告する issuer ではすべてのログインが失敗する。ライブラリには IdP が実際に公開している issuer を設定する。そうしなければ比較がすべてのログインを拒否する（[`callback-url.mts`](../core/src/federations/callback-url.mts)）。
- `FederationClientSecret` / `resolveClientSecret` — 文字列またはリゾルバー（`() => string | Promise<string>`）の `client_secret`。アダプターはトークン要求のたびに `resolveClientSecret` を呼び、それは何もキャッシュしないので、secret がローテーションするアダプター（Apple の ES256 JWT）がキャッシュを受け持つ。空や文字列でない結果は上流に送らずローカルで拒否する（[`client-secret.mts`](../core/src/federations/client-secret.mts)）。
- `federationTokenSnapshot(tokens, obtainedAt)` — プロファイルやリフレッシュのためのトークン応答の唯一の読み方: ライブラリが読んだ `expiresIn` とそこから求める `expiresAt`（有効期間が送られなければ両方 `null`）、`tokenType`、送られたときにだけ存在する `scope`（[`token-snapshot.mts`](../core/src/federations/token-snapshot.mts)）。

同梱のアダプターが実例になる — 例えば `federation-google` の [`google.mts`](../federation-google/src/google.mts)。

## これらの規則を固定するテスト

| テストファイル | 固定するもの |
| --- | --- |
| [`src/__tests__/module.test.mts`](src/__tests__/module.test.mts) | マニフェストのスロットと absence policy、`/session` の二つのルーター、`callbackURL` の起動時規則 |
| [`src/__tests__/sessionStoreModule.test.mts`](src/__tests__/sessionStoreModule.test.mts) | `/` のミドルウェアルート、cookie 名、`__Host-` の規則、replica-safety の宣言と拒否 |
| [`src/store/__tests__/factory.test.mts`](src/store/__tests__/factory.test.mts) | 二つの組み込みストア、`session-store` の readiness probe、Redis クライアントのエラーリスナー |
| [`src/__tests__/csrf.test.mts`](src/__tests__/csrf.test.mts) | 署名付きトークン、オリジン検査、ガードの受理規則 |
| [`src/routes/__tests__/Session.test.mts`](src/routes/__tests__/Session.test.mts)、[`loginRateLimit.test.mts`](src/routes/__tests__/loginRateLimit.test.mts) | ログイン、ログアウトが無効化するものとストア障害が `UserSession` の削除を止めないこと、障害時の応答とそのログ 1 行、ログインのレート制限ガード |
| [`src/routes/__tests__/Federation.test.mts`](src/routes/__tests__/Federation.test.mts) | 開始とコールバックのレグ、アカウントリンク、ストアへの書き込みとそのロールバック、障害時の応答とそのログ、`amr` |
| [`Federation.formPost.test.mts`](src/routes/__tests__/Federation.formPost.test.mts)、[`Federation.applicationCookie.test.mts`](src/routes/__tests__/Federation.applicationCookie.test.mts)、[`Federation.transactionFailures.test.mts`](src/routes/__tests__/Federation.transactionFailures.test.mts)、[`Federation.transactionConcurrency.test.mts`](src/routes/__tests__/Federation.transactionConcurrency.test.mts) | response mode、トランザクション cookie、手を付けられないセッション cookie、トランザクションの失敗経路、「一度きり」が保証すること |
| [`src/federations/__tests__/`](src/federations/__tests__/) | ツールキットとルーターのフェデレーション部品。要求を組み立てるヘルパーは core で固定される（[`core/src/federations/__tests__/`](../core/src/federations/__tests__/)） |

## 関連

- [`@o3co/auth-provider-core`](../core/README.ja.md) — このパッケージが駆動するポートと、[フェデレーションアダプター契約](../core/src/federations/README.md)
- [`@o3co/auth-provider-oauth`](../oauth/README.ja.md) — トークン発行、`/oauth/logout`、フェデレーションのトークンとログアウトのルート
- [`@o3co/auth-provider-redis`](../redis/README.md) — セッションストア（`UserSessionStore` など）の Redis アダプター。上のブラウザセッションストアとは別物
