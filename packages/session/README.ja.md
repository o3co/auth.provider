# @o3co/auth-provider-session

最終更新: 2026-10-06

[auth.provider](../../README.ja.md) のブラウザ向けログイン・ログアウト・上流 IdP フェデレーションのルート、すべてのフェデレーションアダプターパッケージの type がプロバイダーと並べて作るリダイレクトポリシー、そしてそれらのルート（および `req.session` を読む他のすべてのルート）が乗る express-session のストア。

## 責務と役割

**役割。** 認証のブラウザ側の半分。このパッケージが使うポート（`UserRepository`、`UserSessionStore`、`FederationTokenStore`、`SessionFederationIndex`、フェデレーションアダプター契約）は core が持ち、core はルートを一つも実装しない。このパッケージはそれらのポートをブラウザ向けに駆動するドライバーである。責務は三つ:

1. **`/session` ルート** — `sessionModule`。パスワードログイン、ログアウト、CSRF トークンのルート、フェデレーションの開始ルートとコールバックルート。パスワード検証または上流 IdP の応答を `UserSession` レコードと認証済みの express session に変え — どちらも一つの関数 [`establishSession`](#セッションの確立) を通して。この関数は core の [セッションアドミッション](../core/src/session-admission/README.md) が確立したものを書き、セッション requirement の完了（MFA パッケージのもの）もこれを呼ぶ — ログアウトでそれを取り消す。パスワードログインは何かを書く前に登録済みのセッション requirement に問い合わせ、requirement はそれを [中断する](#requirement-がログインを中断するとき) ことがある。
2. **フェデレーションアダプターのツールキット** — アダプターパッケージが、自分が差し込まれるルーターから import するもの: `createFederationRedirectPolicy` とその元になる許可リストの規則。アダプターが上流への要求を組み立てるヘルパー — `codeChallenge`、`callbackUrlForExchange`、`FederationClientSecret` / `resolveClientSecret` — は core のもの。
3. **ブラウザセッションストア** — `sessionStoreModule` と `createSessionStoreFactory` / `registerBuiltinSessionStores`。express-session ミドルウェア、その cookie、そのストア（memory、または `connect-redis` 経由の Redis）。

**持つもの:**

- `/session` ルートとその応答。それらの CSRF ポリシー（`session.csrf.*`）— 他のパッケージは `csrfGuard` スロットを通してこれを実行する。ログイン自身の試行上限（`session.rateLimit.login`）。core の試行ガードが `attemptCounter` スロットの上で数え、レートリミッターの予算は使わない。リダイレクト許可リスト（`session.redirectAllowlist`、`core.federations.<name>.redirectAllowlist`）。
- モジュールが、契約が core にあるスロットを通して他のパッケージに提供するもの: `csrfGuard`、`loginEntry`、`loginCompletion`、そして `sessionCookiePolicy` と `csrfTokenSigner` — [後述](#モジュールが他のパッケージに提供するもの)。
- フェデレーションの駆動方法: `state`・PKCE・`nonce`、`form_post` トランザクションとその cookie、クレームの優先順位、ログインが記録する `amr`、コールバックがストアに書き込む内容。
- core の `ContributesMap` に宣言する `federationRedirectPolicies` キー（フェデレーション type の `redirectPolicy` が返すリダイレクトポリシーの型を与える。モジュールによるその contribution や override は起動が拒否する）と、core に宣言する `federationRedirectPolicyResolver` スロット（[`src/federations/contributes.mts`](src/federations/contributes.mts)）、および [`FederationResult`](src/federations/types.mts)。
- express-session ミドルウェア、その cookie、そのストア（`session-store.*`）。
- 二つのセクション `session` と `session-store`、およびそのデフォルト値を置く [`config/reference.conf`](config/reference.conf) — [設定](#設定)。

**持たないもの:**

- フェデレーションアダプター契約 — `FederationProvider`、`FederationProfile`、各 capability — と、アダプターが要求を組み立てる純粋関数のヘルパー（`codeChallenge`、`callbackUrlForExchange`、`resolveClientSecret`）は core のもの（[`core/src/federations`](../core/src/federations/README.md)）。
- アダプター自体: [`federation-google`](../federation-google/README.md)、[`federation-github`](../federation-github/README.md)、[`federation-apple`](../federation-apple/README.md)、[`federation-oidc`](../federation-oidc/README.md)。
- 書き込むストア（core のポート。memory アダプターは core、Redis アダプターは [`@o3co/auth-provider-redis`](../redis/README.md)）と、ユーザーが誰か（`UserRepository` の背後の Store。例: [`@o3co/auth-provider-foundation`](../foundation/README.ja.md)）。
- トークン発行、`POST /oauth/logout` のカスケード、上流ログアウト（`SupportsLogout`）、フェデレーショントークンのリフレッシュ（`SupportsRefresh`） — [`@o3co/auth-provider-oauth`](../oauth/README.ja.md)。
- 委任認可（`SupportsDelegatedAuthorization`） — [`@o3co/auth-provider-federation-grants`](../federation-grants/README.md)。
- HTML 一切: ログインページとアカウントページはデプロイ側のもの。

**別パッケージである理由。** core から分けているのは、core がすべてのパッケージが依存する契約でありルートを実装しないこと、そしてブラウザログインを持たずにトークンを発行するデプロイ（client credentials、token exchange）が使わないルートをインストールせずに済むこと。`@o3co/auth-provider-oauth` から分けているのは、両者が core の上の兄弟でありどちらも他方を import しないため、デプロイがどちらかを他方のルートなしにインストールできること — ただし `oauth` の `/authorize` は `req.session` を読むので、それを使うデプロイは express-session のミドルウェア（通常はこのパッケージのストアモジュール）をマウントする。分けた代償は [`POST /session/logout` が無効化するもの](#post-sessionlogout-が無効化するもの) に書いてある。

**三つが同居する理由。** 他の二つはどちらもルートのために存在する。

- ツールキット: リダイレクトポリシーはこのパッケージが宣言しルーターが消費する契約である — その型が、フェデレーション type の `redirectPolicy` が返すものになる。これはルーターのものであり、それがすべてのアダプターパッケージがこのパッケージを peer dependency に取る理由である。フェデレーションのエントリはここでは読まない: `core.federations` は core が読み、各エントリについて読んだものを `federationSettings` スロットでモジュールに渡す。ルーターのコールバック URL もそこから取る。要求を組み立てる純粋関数のヘルパーはここにはない: ルーターはそのどれも使わないので、それらを使うようアダプターに指示する契約と並んで core にある。
- ストア: `req.session` そのものであり、それを書くのはここのルートである。フェデレーションルーターは `form_post` トランザクションも同じストアに置く。`sessionModule` とは別のモジュールになっているのは、他のパッケージがこれらのルートなしに `req.session` を読むから — `oauth` の `/authorize`・同意・ログアウト、`device-grant` の検証ページ、`federation-grants` のブラウザ向けルート — であり、独自のログインを持つデプロイはストアだけをインストールする。

**ソースの配置。** [`src/routes/`](src/routes/) は二つのルーター。[`src/establish-session.mts`](src/establish-session.mts) は二つのルーターが共有するログインの末尾。[`src/federations/`](src/federations/) はツールキットとルーターのフェデレーション部品（クレームの優先順位、同意済みスコープ、トランザクションストア、リダイレクトポリシー）。[`src/modules/`](src/modules/) と [`src/store/`](src/store/) はブラウザセッションストア。[`src/internal/`](src/internal/) は cookie の読み取り、定数時間の比較、`User` から読むクレーム。[`src/csrf.mts`](src/csrf.mts) は CSRF の規則。[`src/redirect-allowlist.mts`](src/redirect-allowlist.mts) はログインとフェデレーションのルートが共有する許可リストの規則。[`src/login-entry.mts`](src/login-entry.mts)、[`src/login-completion.mts`](src/login-completion.mts)、[`src/session-cookie-policy.mts`](src/session-cookie-policy.mts)、[`src/csrf-token-signer.mts`](src/csrf-token-signer.mts) は、CSRF ガードのほかにモジュールが他のパッケージに提供するもの。各ファイルが何をするかはそのファイルのヘッダーコメントにある。

## インストール

```sh
npm install @o3co/auth-provider-session @o3co/auth-provider-core express express-session
# session-store.storage.type = "redis"（このパッケージの reference.conf のデフォルト）なら、さらに:
npm install redis@^6.2.1 connect-redis@^10.0.0
```

peer dependencies: `@o3co/auth-provider-core`、`express@^5.0.0`、`express-session@^1.17.0`。
optional peer dependencies: Redis セッションストアのライブラリである `redis@^6.2.1` と `connect-redis@^10.0.0`。
このパッケージ自身の dependency は、セクションのスキーマを書く `zod` だけである。

core が peer なのは、このパッケージが core を拡張する（フェデレーションのリダイレクトポリシーの型を与える `federationRedirectPolicies` キーとそのスロット）からで、拡張は自分が解決した core にしか届かない。peer であれば、それは構成が持つ唯一の core になる。`session-store.storage.type = "memory"` のデプロイは Redis のライブラリをどちらもインストールしない。Redis ストアを組み立てるまで何もそれらを import しない。`"redis"`（デフォルト）なら両方をインストールする: どちらかが無ければ、無いパッケージとインストールコマンドを示して起動に失敗する。

## 組み立て

```ts
import { createApp } from "@o3co/auth-provider-core";
import { sessionModule, sessionStoreModule } from "@o3co/auth-provider-session";
import { googleFederationTypeModule } from "@o3co/auth-provider-federation-google";

const handle = await createApp({
  modules: [
    sessionStoreModule,           // 先頭に置く。後に続くすべてのモジュールが req.session を読めるように。csrfTokenSigner も提供する
    sessionModule,                // factory ではなく const Module
    googleFederationTypeModule(), // type が "google" の core.federations エントリをすべて扱う
    // ... userRepository、userSessionStore、federationTokenStore、
    //     sessionFederationIndex を提供するモジュール
  ],
  bootstrapComponents: { config, pathResolver },
});
```

完全な組み立ては standalone テンプレートの [`buildModules.mts`](../../templates/standalone/src/buildModules.mts) にある。

### モジュールが他のパッケージに提供するもの

パッケージは core だけを import するので、他のパッケージがブラウザセッションについて必要とするものは、契約が core にあるスロットを通して届く（[`core/src/browser-session/types.mts`](../core/src/browser-session/types.mts)、[`core/src/session-admission/login-completion.mts`](../core/src/session-admission/login-completion.mts)）。各提供者は、このパッケージのテストで core の契約スイートを実行する。

| スロット | 提供者 | 内容 | 読む側 |
| --- | --- | --- | --- |
| `csrfGuard` | `sessionModule` | `POST /session/login` が実行する [CSRF ポリシー](#状態変更ルートの-csrf-対策): 状態を変えるリクエストには `middleware` — 同じ `403 access_denied` と同じログ行 — と、その判定だけを返し何も書かない `check`、フローを始めるナビゲーションには `checkNavigation`（[アカウントリンクの開始](#フェデレーション間のアカウントリンク482)の規則）、そして `issue`。トークンのフォームフィールドは `csrf_token`。 | デバイス検証（グラントが有効なとき）、federation-grants の同意の回答（グラントが有効なとき） |
| `loginEntry` | `sessionModule` | ログインページ `session.loginPage.url` と、ページ自身のクエリの fragment より前に `redirect_to` を加える `urlFor(returnTo)`。クエリに既に `redirect_to` を持つページは、エントリの構築時に拒否され、`session.loginPage.url`（セクションが必須とする）としては設定の検証で拒否される。 | `/authorize`（これを必須とする）。federation-grants の connect フロー（グラントが有効なとき） |
| `loginCompletion` | `loginCompletionModule` | [`establishSession`](#セッションの確立) と [`answerInterruption`](#requirement-がログインを中断するとき)。モジュールが require するセッションストア、`csrfGuard`、`sessionCookiePolicy`（セッションの寿命はそのポリシーのもの）の上に作られる。`sessionModule` と並べて読み込む独立したモジュール: 中断の応答のトークンは、誰がスロットを埋めたかによらずデプロイメントの `csrfGuard` のものであり、`sessionModule` は自分が埋めるスロットを require できない。 | requirement の完了処理（MFA パッケージのもの） |
| `sessionCookiePolicy` | セッションストアのモジュール | セッション cookie の名前、`secure`、`sameSite`、ドメイン、寿命: ストアのルートが cookie をマウントする元の値。core の契約を破るセクションは設定の検証で拒否される（[後述](#ブラウザセッションストア)）。authoritative: ストアのモジュールがロードされている間、このスロットへの `overrideComponents` のエントリは起動を拒否する（`authoritative-component-overridden`）。ストアは `session-store.*` のとおりの cookie をマウントし続けるからである。モジュールをロードしない組み立ては自分でスロットを埋める。 | これを require する `sessionModule`（CSRF cookie、セッションの寿命、フェデレーションのトランザクション cookie の名前）と `loginCompletionModule`。subject revocation service が horizon の算出に（これを require する） |
| `csrfTokenSigner` | セッションストアのモジュール | この用途のためだけに `session-store.secret` から導出した鍵による CSRF トークンの署名: HKDF-SHA256（salt なし、info `o3co.auth.provider/session-csrf/v1`、32 バイト）、続いて HMAC-SHA256、base64url。テストの固定ベクターがこの導出を固定するので、secret を保つ限りトークンは検証を通る。secret も鍵もこの外に出ない。 | `sessionModule`: その `csrfGuard` と `/session` のルート |

CSRF トークンの鍵は `session-store.secret` から導出され、`session-store.secret` はセッションストアのモジュールが所有する。`sessionModule` は `csrfTokenSigner` を require し、`session-store.secret` を読まない: その `csrfGuard` とルートは一つの署名器で署名・検査するので、ガードが発行したトークンはルートの検査を通り、ルートが発行したトークンはガードの検査を通る。署名器の導出はテストのリテラルなベクターで固定されているので、secret を保つ限りトークンはデプロイをまたいでどちら向きにも検証を通る: デプロイ前に発行したトークンはデプロイ後に通り、デプロイ後に発行したトークンは置き換えられたリリースの下でも通る。`sessionModule` なしで `csrfGuard` を提供する組み立ては `createSessionCsrfGuard` で作り、セッションストアのモジュールなしで `sessionModule` を読み込む組み立ては `csrfTokenSigner` を `createSessionCsrfTokenSigner` で提供する（[別のストア](#ブラウザセッションストア)）。

## 設定

モジュールはそれぞれ自分のセクションを読み、設定のほかの部分は読まない: `sessionModule` が `core.federations` について必要とするものは core の `federationSettings` スロットから来る。デフォルト値と環境変数はパッケージの [`config/reference.conf`](config/reference.conf) にあり、モジュールがそれを宣言するので composition root が重ねる。

| キー | 環境変数 | デフォルト | |
| --- | --- | --- | --- |
| `session-store.secret` | `SESSION_STORE_SECRET` | なし | セッション cookie を署名する: デコード後に測って 32 バイト（256 ビット）以上の乱数。無ければセッションストアのモジュールは変数を名指しして組み立てを拒否する |
| `session-store.name` | `SESSION_STORE_NAME` | `__Host-auth.session` | セッション cookie の名前（[ブラウザが保持するもの](#ブラウザセッションストア)） |
| `session-store.maxAge` | `SESSION_STORE_MAX_AGE` | `3600000` | cookie の `Max-Age` とセッションの寿命。ミリ秒で 1 から 1 年 |
| `session-store.secure` | `SESSION_STORE_SECURE` | `true` | |
| `session-store.sameSite` | `SESSION_STORE_SAME_SITE` | `lax` | `none` は `secure = true` のときだけ |
| `session-store.domain` | `SESSION_STORE_DOMAIN` | `null` | `null` か空: ホスト限定の cookie |
| `session-store.storage.type` | `SESSION_STORE_STORAGE_TYPE` | `redis` | または `memory`（`core.deployment.mode = "multi"` では拒否される） |
| `session-store.storage.redis.url`、`.password` | `SESSION_STORE_STORAGE_REDIS_URL`、`SESSION_STORE_STORAGE_REDIS_PASSWORD` | `redis://localhost:6379`、なし | Redis ストアの接続先 |
| `session.redirectAllowlist` | | `[]` | [リダイレクト許可リスト](#リダイレクト許可リスト) |
| `session.csrf.trustedOrigins`、`.ttlSeconds` | `SESSION_CSRF_TTL_SECONDS`（`ttlSeconds`） | `[]`、`7200` | [CSRF](#状態変更ルートの-csrf-対策) |
| `session.loginPage.url` | `SESSION_LOGIN_PAGE_URL` | `/login` | 必須。`loginEntry` スロットが示すページ: パスか絶対 URL で、自身の `redirect_to` を持たない |
| `session.rateLimit.login` | | `{ windowMs = 900000, limit = 20 }` | 必須。`POST /session/login` 自身の試行上限: `windowMs` は 1 日（86400000）以下のミリ秒の整数で、秒に切り上げて読む。`limit` は正の整数 |

各セクションはどの階層でも厳格: 宣言されていないキーは、キーを名指しして起動を拒否する。`session-store.storage` が持つのは `type` と `redis` ブロックだけなので、ほかのストレージ種別のブロックも拒否される。これらのキーの移動元のパス — `session` の下の cookie とそのストアの各キー、`endpoints.login.url`、`rateLimit.login` — は、新しいパスとその環境変数を名指しして起動を拒否する（`config-path-relocated`）。一緒に改名された環境変数 — `SESSION_<KEY>` は `SESSION_STORE_<KEY>` へ、`ENDPOINTS_LOGIN_URL` は `SESSION_LOGIN_PAGE_URL` へ — は、旧名だけが設定されているか新名と違う値で設定されていると起動を拒否し（`environment-variable-renamed`）、同じ値ならどちらも起動する。

## ブラウザセッションストア

`sessionStoreModule` は `/` にマウントされる `session-middleware` というルートを一つ contribute する。中身は express-session で、cookie は `session-store.*` から（`HttpOnly`、`Path=/`、`session-store.secure`、`session-store.sameSite`、`session-store.domain`、`Max-Age` = `session-store.maxAge`）、ストアは `session-store.storage.*` から組み立てられる。デプロイ内のすべての `req.session` はこれである。デフォルト値と環境変数は [`config/reference.conf`](config/reference.conf) にある。`session-store.storage.type` のデフォルトは `redis`、代替は `memory` で、それ以外の値は起動に失敗する。

成り立つこと:

- **マウント順はリスト順。ただしこのルートを名指しするルートは別。** このルートは `before` / `after` を宣言しない。デプロイが含まないかもしれないルート（`oauth` だけのデプロイには `sessionModule` が無い）を名指しすると `route-order-target-missing` で起動に失敗するからである。したがって **`req.session` を読むすべてのモジュールより前に** 並べる。これより前に並べたモジュールはセッションを読めず、起動時にそれを検査するものは無い。standalone テンプレートはこれを先頭に置いている。例外は逆向きの宣言である: federation grants が有効なとき、そのブラウザ向けルートは `after: ["session-middleware"]` を宣言するので、どちらがどこに並んでいてもこのルートの後にマウントされ、その id のルートが無い組み立ては `route-order-target-missing` で起動に失敗する。
- **ブラウザが保持しない cookie は設定の検証で拒否される**（`config-validation-failed`、issue がキーを名指しする）: `__Host-` の名前 — デフォルトの `__Host-auth.session` — で `session-store.secure = true` かつ `session-store.domain = null` でないもの、`__Secure-` の名前で `session-store.secure = true` でないもの（どちらの接頭辞も、ブラウザと同じく大文字小文字を問わない）、RFC 6265 のトークンでない `session-store.name`、ホスト名でない `session-store.domain`（先頭のドット一つは可。スキーム、ポート、パスは不可）、`session-store.secure = true` でない `session-store.sameSite = "none"`、1 ms から 1 年の範囲外の `session-store.maxAge`。平文 HTTP で動かすときは `session-store.secure = false` と、接頭辞の無い名前（`auth.sid`）を設定する。
- **新しいセッションに渡す cookie は `sessionCookiePolicy` のもの:** ルートはスロットが持つポリシーから express-session をマウントする。保存済みのセッションは作られたときの cookie の属性を保つ（express-session はレコードから cookie を組み立て直す）ので、これらの設定を厳しくしたときはセッションストアを空にし、すべてのブラウザに新しい cookie でサインインし直させる。
- **`memory` は `core.deployment.mode = "multi"` で拒否される。** express-session の `MemoryStore` はレプリカごとに分岐する: あるレプリカが処理したログインは他のレプリカに知られず、ログアウトは到達したレプリカ上しか消さず、再起動ですべてのセッションが失われる。`sessionStoreModule` は replica safety を自分のパース済みセクションから宣言する: `session-store.storage.type` が `memory` なら replica-unsafe、それ以外の種別なら何も宣言しない。そのため core の replica-safety ガードが起動時に他の違反と並べて名指しで拒否し、`core.deployment.mode` が未設定なら警告し、`"single"` なら何も言わない。ガードはどのルートを組み立てるよりも前に、ルートがマウントするのと同じセクションで判断するので、モジュール自身はモードを読まない: `deploymentMode` を requires せず、`deployment` も読まない。
- **Redis ストアは自前の接続を開く。** `session-store.storage.redis.url`（設定されていれば `password` も）への `redis`（node-redis）クライアントを `connect-redis` の `RedisStore` の下に置く。readiness registrar が配線されていれば probe `session-store`（`PING`）を登録し、Redis を失ったレプリカはトラフィックを受けなくなる。lifecycle registrar が配線されていれば `AppHandle.dispose()` がクライアントを quit する。クライアントの `error` イベントはプロセスを落とさず `session_store_redis_error` としてログに出る。再接続は node-redis の仕事。`url` が無ければ起動に失敗し、`redis` か `connect-redis` のパッケージが無くても起動に失敗する（[インストール](#インストール) を参照）。
- **フェデレーショントランザクションは同じストアを共有する。** キーの接頭辞は `fedtx:` — [トランザクション cookie](#トランザクション-cookie) を参照。
- **答えられないストアは `500` ではなく障害である。** リクエストのセッションをストアが読み込めない（到達できない、またはタイムアウトする）とき、そのリクエストはどのルートも動く前に `503 temporarily_unavailable` で答えられる。ルートが答えたあとでセッションの保存や有効期限の更新ができないときは、その答えがそのまま残る。どちらも error レベルで 1 行、`session_middleware_store_unavailable`（`store: "cookie_session"`、`step`: `load` または `save`、エラーの射影）としてログに出て、それ以上先へは渡らない — express-session はこれを `next(err)` に渡しており、ルートの前ならターミナルハンドラーの `500`、後なら Express の最終ハンドラーに届いていた（[`src/internal/cookieSession.mts`](src/internal/cookieSession.mts)）。このパッケージのルートは、それが重要な場所 — ログイン、フェデレーションの開始とコールバック — では答える前に自分でセッションを保存するので、そこでの保存の失敗はルート自身の `503` になる。cookie ストアの障害を答えたルートはリクエストのセッションを手放すので、express-session が応答の終わりに失敗中のストアへもう一度書くことはない。
- **読めないレコードは障害ではなく「無い」ものとして扱う。** Redis ストアが返したレコードが JSON でない、またはセッションのレコード（配列ではないオブジェクトで、その `cookie` も配列ではないオブジェクトであるもの）でないときは、セッションが無いものとして読む: express-session はそのリクエストのために新しいセッションを始める。読むたびに warn 1 行、`session_cookie_record_unreadable`（`store: "cookie_session"`）としてログに出て、レコードのテキストは出さない。レコードは削除されず、ブラウザは cookie を持ったままである — 変更されていない新しいセッションは新しい cookie を設定しない — ので、そのブラウザからのリクエストは、ユーザーがサインインする（新しい cookie が設定される）かレコードの TTL が過ぎるまで、毎回同じレコードを読み直してログに出す: 一つのブラウザから続くこの warn は一つのレコードである。障害として答えれば、それらのリクエストがすべて失敗していた。同じストアにある `form_post` のトランザクション（`fedtx:`）や oauth の再認証の問い合わせ（`reauth:`）も同じように読まれる: 無いものとされ、コールバックは `400 invalid_session` を返し、`/authorize` は改めて問い合わせる（[`src/store/factory.mts`](src/store/factory.mts)）。

**`@o3co/auth-provider-redis` とは別物。** あちらの `UserSessionStore` は `sid` の背後にある `UserSession` レコード — introspection・`/userinfo`・`/authorize` が解決するもの — を持ち、他のアダプターは他の core ポートを、あちらのモジュールが作るクライアント越しに持つ。このストアが持つのは express-session 自身のレコード: このパッケージのルートがセッションに置くもの（`isAuthenticated`、`user`、`sid`、ログインの `redirectTo`、`query` フェデレーションの進行中のエンベロープ）、他のパッケージがそこに置くもの（`oauth` は `client` と `code` を宣言している）、そして `fedtx:` のフェデレーショントランザクション。レコードも接続も別で、設定も別々に行う。

**別のストア。** このモジュールが登録するのは `memory` と `redis` だけ。別の express-session `Store` が必要な組み立ては、ミドルウェアを自分で組み立て — `createSessionStoreFactory(ctx)`、`registerBuiltinSessionStores(factory)`、`factory.register("<type>", builder)`（[`src/store/factory.mts`](src/store/factory.mts)） — 先頭にマウントし、このモジュールはインストールしない。federation grants を有効にするなら、そのミドルウェアを id `session-middleware` のルートとして contribute する。そうしなければ上のとおり起動に失敗する。また `sessionModule` が require する `csrfTokenSigner` スロットを埋める。埋めなければ起動に失敗する（`missing-required-component`）: `createSessionCsrfTokenSigner(sessionSecret)` はこのモジュールと同じく署名するので、その secret の下で発行したトークンは検証を通り続ける。

## ルート

`sessionModule` は二つのルーターを contribute し、どちらも `/session` にマウントされる:

| メソッド | パス | |
| --- | --- | --- |
| GET | `/session/csrf` | double-submit CSRF トークンの発行 |
| POST | `/session/login` | パスワードログイン |
| POST | `/session/logout` | ブラウザセッションの終了 — [無効化するもの](#post-sessionlogout-が無効化するもの) を参照 |
| GET | `/session/oauth/federation/:name` | フェデレーションの開始（`?redirect_to=`、`?link=1`、鮮度のヒント `?prompt=` — `login` だけを数える — と `?max_age=`、2^53−1 以下の負でない整数。繰り返しや不正なヒントは `400 invalid_request`） |
| GET | `/session/oauth/federation/:name/callback` | `query` フェデレーションのコールバック。`form_post` フェデレーションには `405`（`Allow: POST`） |
| POST | `/session/oauth/federation/:name/callback` | `form_post` フェデレーションのコールバック。`query` フェデレーションには `405`（`Allow: GET`） |

`:name` はフェデレーションの名前。有効な `core.federations` のエントリがどれも登録しない名前は `404`。

マニフェスト（[`src/module.mts`](src/module.mts)）:

- `requires`: `userRepository`、`userSessionStore`、`federationTokenStore`、`sessionFederationIndex`、`csrfTokenSigner`（CSRF トークンを署名・検査するもの。セッションストアのモジュールが提供する）、core の `federationSettings`（core がどの構成でも埋める `core.federations` の見え方。有効な各エントリのコールバック URL と、インストールされたフェデレーションの上流 `amr` が数えられるかどうか。モジュールは自分のセクション以外の設定を読まない）、`sessionCookiePolicy`（セッション cookie の名前・属性・寿命。これもセッションストアのモジュールが提供する）、そして synthetic な `federationProviders` と `federationRedirectPolicyResolver`。後者二つは、core が type で振り分けるフェデレーションから組み立てる — 有効な `core.federations` のエントリごとに、その `type` を登録するモジュールが作るプロバイダーとリダイレクトポリシー。さらに `sessionRequirementResolver` — パスワードログインは何かを書く前に core の [セッションアドミッション](../core/src/session-admission/README.md) を通して登録済みの requirement に問い合わせ、アカウントリンクのルートはそれを通してセッションを読むので、`sessionModule` を入れる構成は `core.sessionRequirements.expected` を宣言する。手で組み立てるルーター（`routes/Session.mts`、`routes/Federation.mts`）は resolver を必須のオプション `requirements` として受け取り、無ければ例外を投げる。テストは core の `resolverForTests` で作る。そして `deploymentMode` — core が `core.deployment.mode` から埋める。ログインの試行をプロセスごとに数えることは `multi` で拒否されるので、モードは未設定として読まれるのではなく必須になっている。手で組み立てるセッションルーターは、署名器も必須のオプション `csrfTokenSigner` として受け取って無ければ例外を投げ、モードを必須のオプション `deploymentMode` として受け取って、三つの値のどれでもない値（無い場合も含む）は構築時に TypeError になる。手で組み立てるフェデレーションルーターは、core のフェデレーションの見え方を必須のオプション `federationSettings` として、トランザクション cookie の名前を必須の `federationTransactionCookieName` として（モジュールは `sessionCookiePolicy` スロットの cookie の名前から付ける）、リンクを始めてよい場所を `linkTrustedOrigins` として（モジュールは `session.csrf.trustedOrigins` を渡す。無ければこのサイト自身のページだけ）受け取り、前の二つが無ければ例外を投げる。残り二つのセッションストア `sessionRPRegistry` と `sessionFamilyIndex` は `oauth` のもの。
- `optional`: `logger`、`attemptCounter`、`auditSink`、`subjectSessionIndex`、`subjectRevocation`（リンクのルートのアドミッションが読む境界）、`sessionLifecycleStore`（core のセッションライフサイクルのポート。リンクのルートのアドミッションが生きているレコードの後に読む: 終了中・終了済みのセッションは何もリンクしない）、`sessionLifecycle`（core のセッションライフサイクル。`sessionLifecycleModule` が埋める。ログインごとにそのセッションのライフサイクルのレコードを開き、フェデレーションはそれを通してセッションに参加し、ログアウトはそれを通してセッションを終了する。`loginCompletionModule` も受け取る）。マニフェスト上は optional だが、`userSessionStore` を配線するところ — このモジュールでは常に — では必須で、ルートのファクトリーと `loginCompletionModule` のプロバイダーは、二つのスロットを名指しして起動を拒否する。セッションを持たない構成（user-session ストアなし）には要らない。`auditSink` を配線しないなら `core.declaredAbsent = ["auditSink"]`、`subjectSessionIndex` と `subjectRevocation` を配線しないなら `oauth.revocation.subject = "unsupported"` で宣言しなければ起動は拒否される。

### パスワードログイン

`POST /session/login` は `username` と `password` を受け取る（JSON またはフォーム）。

- どちらかが欠けていれば `400 invalid_request`。`UserRepository.authenticate` が `null` を返せば `401 invalid_credentials`。ログインに必要なストアが答えられなければ `503 temporarily_unavailable` — `UserRepository` が例外を投げた、`UserSession` の書き込みが例外を投げた、または express session を再生成（そのストアが古いレコードを破棄できなかった）・保存できなかった場合。いずれも error レベルで 1 行、`login_store_unavailable` として `store`（`user_repository`、`user_session`、`cookie_session`）、`step`（`authenticate`、`create`、`regenerate`、`save`）、エラーの射影とともにログに出る。ユーザー名は出さない。成功時は再生成したセッションを答える前に保存するので、保存できないストアは、次のリクエストが見つけられないセッションへの `200` ではなく `503` になる。再生成または保存に失敗したときは `UserSession` とその subject index のエントリーをベストエフォートでロールバックし、失敗したロールバックの各ステップは `login_cleanup_failed` の warn 1 行になる。この手順は [セッションの確立](#セッションの確立) にある。
- Store がユーザーを検証したら、何かを書く前に、ルートは core の [セッションアドミッション](../core/src/session-admission/README.md)（`admitPrimary`）に、core がログインから組み立てる primary（`passwordPrimary`: subject、`User` のスナップショット、レコードが持つクレーム、`authTime`、許可リストを通った `redirect_to`、クライアントのアドレスとユーザーエージェント — `amr` と `authentication` は core のもので、ルートのものではない）について問い合わせる。requirement が一つも登録されていなければ、どのログインにも `establish` が返る。requirement の障害は `503 temporarily_unavailable`（"session requirement unavailable"。core の `describeAdmissionOutage`）で何も書かれず、アドミッションが `session_admission_unavailable`（`store` は requirement の名前、`phase: "establishment"`）として一度だけログに出す。requirement による中断は [下](#requirement-がログインを中断するとき) にある。ルートは core の `readUserSnapshot` で `User` を一度だけ読み、subject とクレームをそのスナップショットから取る。スナップショットが拒否する `User`（宣言されたフィールドがプレーンなデータでない値 — `Date` の証跡や関数 — を持つもの）は、何かを書く前にルートのエラー（`500`）として拒否される。
- 成功すると — すべての requirement が `establish` と答えたとき — `UserSession`（`amr: ["pwd"]`、`authentication` の primary は `pwd`、寿命 `session-store.maxAge`）を作り、配線されていれば `subjectSessionIndex` に記録し、express session を再生成し、新しい CSRF cookie と共に `200` を返す。
- `redirect_to` を送るなら `session.redirectAllowlist` に載っていなければならず（[リダイレクト許可リスト](#リダイレクト許可リスト) を参照）、`req.session.redirectTo` に保存される。このパッケージの中にそこへリダイレクトするものは無い。
- ログインの試行上限は資格情報を読む前に効く: リクエストごとに 1 回、`login:ip:<クライアント IP>` をキーに、core の試行ガード（`createAttemptGuard`）が `attemptCounter` スロットのカウンターの上で `session.rateLimit.login` に対して数える。レートリミッターは関わらない: リミッターの `limits`・`defaultLimit`・`failMode` はこれを緩めも置き換えもせず、モジュールは core の `verifierLimitClaim({ setting: "session.rateLimit.login" })` で `login` 接頭辞を確保する: 予算は持たないので他のモジュールは設定できず、同梱のリミッターモジュールは `limits.login` の項目をこのキーを名指して拒否する。拒否した試行は `Retry-After` と `Cache-Control: no-store` を付けた `429 rate_limited` で、`RateLimit-*` ヘッダーは付けない（推測する側に残りの回数を教えることになるため）。カウンターが例外を投げる、2 秒以内に答えない、core が読めない値を返す場合は、どのリミッターの宣言にかかわらず `503 service_unavailable` で、`attempt_counter_unavailable` としてログに出し、`rate_limit.unavailable`（`tag: "login"`）として監査する。`attemptCounter` が配線されていなければガードはプロセスごとに数える: `core.deployment.mode = "multi"` では起動が拒否され、未設定なら `attempt_counter_not_shared` の警告がログに出て、`"single"` では何も言わない。モードはモジュールが requires する core の `deploymentMode` スロットであり、ルーターは `deployment` を自分では読まない。拒否した試行は監査しない。

#### requirement がログインを中断するとき

登録された requirement（パッケージが入っていれば MFA）は、ログインに中断で答えることがある: ログインはまだ完了しない。そのときルートは、express session がその間に再生成されるので二段階で、次を行う:

1. express session を再生成し、認証されていないまま残す — `isAuthenticated`、`user`、`sid`、`redirectTo` は書かない。
2. 再生成したセッションの id に束縛して requirement のセレモニーを開く。requirement は core が組み立てた continuation — ルートが組み立てたままの primary（`redirect_to` を含む）と、先の requirement が加えたもの — を自分のレコードに保存する。
3. セッションを保存し、requirement の `403` をその本文 — requirement が宣言したものに照らして core が検証した閉じた形（`error`、任意で `transaction`、`expires_in`、`hints`。`User`、subject、アドレスは決して含まない）— と新しい CSRF cookie とともに返す。

`UserSession` は書かれない。セッションは後で requirement の完了ルートが確立する: core の `resumePrimary` でログインを再開し（このログインでまだ済んでいない requirement に順に問い合わせる — 完了した requirement には二度と問い合わせない）、それが答える establishment で [`establishSession`](#セッションの確立) を呼ぶ — 別の requirement が中断すれば、それをログインとまったく同じように返す。再生成、例外を投げるか core が拒否する本文を返す `open`、失敗した保存は、いずれもリクエストの cookie セッションを手放し何も確立しない `503 temporarily_unavailable` で、`login_store_unavailable`（`store: "cookie_session"` と `step` `regenerate` か `save`、または requirement の名前と `step: "open"`）として一度だけログに出る。保存に失敗したあとは、requirement のレコードは、どのブラウザも持たないセッション id に束縛されたまま、自身の有効期限に任される。`403` がパスワードを持つ者にパスワードが正しかったことを伝えるのは受け入れている（MFA の ADR の D23）。

この手順と失敗時の応答は、パッケージが export する一つの関数 `answerInterruption(admission, { req, res, csrf, reporter })`（[`src/answer-interruption.mts`](src/answer-interruption.mts)）である。ログインのルートがこれを呼び、`resumePrimary` が別の中断を答えたときは requirement の完了ルートも呼ぶ。応答 — 渡された `CsrfProtection` による新しいトークンを伴う `403`、または `503` — を送り、失敗は呼び出し側の reporter に一度だけ（上と同じ `store` と `step` で）伝えるので、各呼び出し側は自分の語彙でログを出す。送ったもの（`answered`、またはストアとステップを伴う `unavailable`）を答える。`admitPrimary` か `resumePrimary` が答えた中断でないもの — core の `isInterruptAdmission` によるので、そのコピーやそれに似せたオブジェクトも — は、セッションに触れる前に `RangeError` になる。requirement の完了処理は `loginCompletion` スロットを通してこれに到達し、その応答はデプロイメントの `csrfGuard` のトークンを伴う。関数を直接呼ぶ側は `issue` を持つもの — ログインのルートの `CsrfProtection`、または `csrfGuard` — を渡す。トークンは保存されず署名されるので、一つの署名器の上に作ったガードは互いのトークンを受け入れる。

### セッションの確立

ログインの末尾 — ユーザーを検証してからセッションを保存するまで — は一つの関数 `establishSession`（[`src/establish-session.mts`](src/establish-session.mts)）で、`POST /session/login` とフェデレーションのコールバックの両方がこれを呼び、requirement の完了（core の `resumePrimary` のあとの MFA パッケージのもの）が同じようにログインを終えられるよう、パッケージは呼び出し側に必要な型とともにこれを export する。core のセッションアドミッションが組み立てた `Establishment` — パスワードログインでは `admitPrimary` の、フェデレーションのコールバックでは `establishWithoutAsking` の、完了では `resumePrimary` のもの — を受け取り、その primary だけから書く: subject、`User`、クレームのエンベロープ、`authTime`、core が組み立てた `amr` / `authentication`、core が `User` から導いた `enrollmentFacts`（MFA の登録の証跡と、そのアドレスが何か — 無い、プロバイダーが読めるアドレス、読めないもの。アドレスそのものではない）、そして `redirectTo`。呼び出し側がその横に渡すものは何も書かない。core が組み立てた `Establishment` でないもの — それに似せたオブジェクト、そのコピー — は何かを書く前に `RangeError` になる。どちらの経路でも、ログインのルートは core の `readUserSnapshot` で `User` を一度だけプレーンなスナップショットに読む — `User` が宣言するフィールドだけを、オブジェクトがどう保持していても名前で一度ずつ読むので、getter を持つクラスのインスタンスや ORM エンティティでもログインできる — そして `User` ではなくそのスナップショットを組み立て関数（`passwordPrimary`、`establishWithoutAsking`）に渡す。subject、クレーム、ルートのログ行もそこから読む。`req.session.user` はそのスナップショットを持つ: 宣言されたフィールドだけで、Store が答えたほかのものは持たず、Store の `toJSON` は適用されない。`id` が空でない文字列でない `User`、または宣言されたフィールドがプレーンなデータでない値を持つ `User` はスナップショットが拒否し、ログインは何も書かずに `500` を答える。次を順に行う: `UserSession` レコードの作成（新しい `sid`、有効期限は `authTime` から `session-store.maxAge` 後。先に core のセッションライフサイクルでそのレコードを開く。ライフサイクルは `UserSessionStore` と並べて必須で、ライフサイクルなしにストアを渡すと何かを書く前に `TypeError` になる。`open` の失敗・例外・拒否はレコードの `create` での障害になる。ライフサイクルが reject したときはそのエラー自身が報告され、それ以外はセッションライフサイクルを名指しするエラーが報告される。`open` の後で `create` が失敗すれば、開いたレコードを終了する）。配線されていれば `subjectSessionIndex` のエントリー（ベストエフォート: 失敗は報告され、ログインは進む）。再生成の前に呼び出し側が渡すステップ。express session の再生成（session fixation 対策）。再生成の後に呼び出し側が渡すステップ。再生成されたセッションへの `isAuthenticated`、`user`、`sid`、primary の `redirectTo`。そしてその保存。答えは `sid` を伴う `established` か、ストアとステップを名指しする `unavailable` で、後者を呼び出し側は `503 temporarily_unavailable` として答える。

成り立つこと:

- **片方の経路だけが書くものは、フラグではなく、その経路が渡すステップである。** コールバックは再生成の後に、`federationTokenStore` への紐づけ、次にセッションライフサイクルを通したフェデレーションの参加を加える（index への書き込みはしない）。紐づけは自分が宣言する undo を伴う。パスワードログインは何も加えない。ステップは、その書き込みが完了したときだけ undo される。
- **レコードができたあとの失敗はすべて逆順にロールバックされる**（ベストエフォート）: 完了した呼び出し側のステップ、次にレコード — そのライフサイクルのレコードを終了（`session_logout`）してから `UserSession` を削除する。終了の失敗はレコードの `delete` として報告される。ライフサイクルが reject したときはそのエラー自身が、`unavailable` を答えたときはセッションライフサイクルを名指しするエラーが報告される — 、最後に subject index のエントリー。再生成以降の失敗ではリクエストの cookie セッションも手放す（`abandonCookieSession`）ので、express-session が失敗したストアへ新しいセッションを保存することも、それを指す cookie を設定することもない。再生成より前では cookie セッションには触れない。失敗したロールバックのステップは報告され、残りは続けて実行される。
- **各ルートは自分の語彙でログを出す。** この関数は — 答えられないストア、失敗したロールバックのステップ、失敗した index の書き込みを — ルートが渡す reporter を通して報告する。reporter は最初の書き込みの前に `sid` と subject とともに一度だけ作られる: パスワードログインでは `login_store_unavailable` と `login_cleanup_failed`、コールバックでは `federation_callback_store_unavailable` と `federation_cleanup_failed`、両方で `subject_session_index_write_failed`。
- **`UserSessionStore` がなければ** — `POST /session/login` のルーターだけがそれを許す — レコードは作られず、ステップも走らない: express session だけが再生成され、フラグを書かれ、保存される。
- CSRF トークン、`200`、リダイレクトは呼び出し側に残る。

### `POST /session/logout` が無効化するもの

このエンドポイントと `POST /oauth/logout` は、どちらも core のセッションライフサイクルを通してセッションを終了するので、無効化するものは同じである。

`POST /session/logout` — ブラウザ自身のログアウトであり、BFF / `auth.proxy` の injection トポロジーが呼ぶもの — は、core のセッションライフサイクルを通してセッションを終了し、express session を破棄する。`UserSessionStore` を持つルーターはライフサイクルを必須とする。セッションを持たないルーター（ストアなし）には終了するレコードが無く、express session だけを破棄する。

ログアウトは `sessionLifecycle.close(sid, "session_logout")` でセッションを終了する（`sessionLifecycleModule` がスロットを埋める）。終了は `/oauth/logout` と同じ順で進む: セッションのリフレッシュトークンファミリーを失効させてフェデレーショントークンを削除し、次に relying party にバックチャネルで知らせ（`oauthEndpointsModule` が寄与する通知器を通して）、次にセッションごとのインデックスを削除し、次に `UserSession` を削除し、最後に subject インデックスのエントリーを削除する。終了が保留のあいだ、sid は subject 単位の失効が見つける場所に残る。
- コミットされた終了は、作業が `done` でも `pending` でも同じ `200` を返し、express session を破棄する。コミットの時点から、どの liveness の読み取りもそのセッションを live と答えず、残りは後の終了かライフサイクルの巡回が再開する。`pending` の終了は `/oauth/logout` と同じく `logout.close_pending`（`subject`、`sid`）として監査する。
- `UserSession` が既に失効したログアウトには終了するものが無い: `done` を返して express session を破棄し、セッションの残りは `/oauth/logout` と同じく TTL で失効する。
- コミットされなかった終了、または例外を投げたライフサイクルは `503 temporarily_unavailable` を返し、再試行のために express session を残す。コミットが live なレコードを見つけず（ストアの時計でセッションの終わりが過ぎていた）、保存するレコードなしにその場で走らせた作業が失敗した終了もこれに含まれ、再試行がそれを再び走らせる。`session_logout_store_unavailable`（error、`store: "session_lifecycle"`、`step: "close"`、`sid`）として 1 回ログに出し、エラーの射影はライフサイクルが例外を投げたときだけ持つ。ライフサイクル自身はその障害を `session_lifecycle_unavailable` としてログに出す。
- ライフサイクルが保持できない `sid` は、それ自身のどのセッションも指さない: ログアウトは express session を破棄して `200` を返し、warn で 1 回 `session_logout_sid_not_closable` と記録する。
- 終了の作業の一つが失敗すると core の `session_close_item_failed`（warn、`item` 付き）となり、終了は保留のまま残る。`item: "delete_user_session"` にアラートを掛ける。

**cookie セッションの破棄。** express session の破棄が失敗する — cookie ストアの障害 — とユーザーはログアウトできていないので、応答は `503 temporarily_unavailable` で、error レベルで 1 行、`session_logout_store_unavailable`（`store: "cookie_session"`、`step: "destroy"`、`sid`）としてログに出て、クライアントは再試行する。その時点でセッションの終了はコミット済みなので、`/authorize` は残った cookie を自身の判断で拒否する。`sid` を持たないセッションには終了するものが無く、express session だけが破棄される。

### 状態変更ルートの CSRF 対策

`POST /session/login` と `POST /session/logout` は、same-origin（または明示的に信頼した）`Origin` / `Referer` **か**、有効な double-submit CSRF トークン **の** どちらかを持つリクエストを受理する。どちらも持たないリクエストは `403 access_denied` で拒否する。

- **ブラウザ** は何も追加しなくてよい: same-origin の `fetch` / フォーム送信ではブラウザが `Origin` を付け、それだけで検査を通る。
- **ヘッダーを持たないクライアント**（curl、サーバー側のエージェント、テストハーネス）は `GET /session/csrf` を呼ぶ。JS から読める `<session-store.name>.csrf` cookie がセットされ、同じ値が `csrf_token` として返る。両方を送り返す: cookie と、`x-csrf-token` ヘッダーまたは `csrf_token` フォームフィールドのどちらか。
- **foreign な** `Origin` はトークンがあっても拒否する。クロスサイトリクエストであることの積極的な証拠だから。
- ログインに成功すると **新しい** CSRF cookie が返るので、続くログアウトに追加の往復は要らない。

トークンは乱数 nonce と有効期限（`session.csrf.ttlSeconds`）に対する署名付きでステートレスな HMAC で、鍵は `session-store.secret` の HKDF 展開 — 親ドメインの cookie を書けるサブドメインでも偽造できない。ルートはこれを `csrfTokenSigner` スロット（セッションストアのモジュールが埋める）を通して署名・検査し、`session-store.secret` を読まない。トークンが正しく署名されているとみなすのは署名器の `verify` が `true` を返したときだけで、有効期限が `session.csrf.ttlSeconds` と 60 秒の時計のずれより先にあるトークンは拒否する。ルートが発行するトークンはそれより先に期限切れにならない。クロスオリジンのログイン UI は自身のオリジンを `session.csrf.trustedOrigins` に載せる。`http.cors.allowedOrigins` は CSRF の信頼を与えない。載せたオリジンはフェデレーショングラントの同意とデバイス検証にも回答できるので、クライアントのオリジンは決して載せない（federation-grants ADR の D7）。

他のパッケージはこのポリシーを import せず、`sessionModule` が提供する `csrfGuard` スロットを通して実行する — デバイス検証はその `middleware` をマウントし、federation-grants の同意の回答はその `check` に問う。`checkRequestOrigin`、`createCsrfProtection`、`createCsrfProtectionFromConfig`、`createCsrfGuard`、`createCsrfIssueHandler`、`createSessionCsrfGuard` は、独自のログインページをマウントしたり独自のルートを保護したりする組み立てのために export されている（[`src/csrf.mts`](src/csrf.mts)）。`createCsrfProtection` と `createCsrfProtectionFromConfig` は署名器（`{ signer }`）— `csrfTokenSigner` スロットのもの、または `createSessionCsrfTokenSigner(sessionSecret)`（[`src/csrf-token-signer.mts`](src/csrf-token-signer.mts)）— を受け取る（`createSessionCsrfTokenSigner` は secret を core のエントロピーの下限に照らす）。署名器なしでは作られず、core の契約を破る署名器でも作られない: 作る前に二つのペイロードに署名させ、その署名と、変えた署名、別のペイロードの署名を検査する。`sign` と `verify` は署名器から一度だけ読むので、作った後に署名器のオブジェクトを変えても、発行するトークンにも受け入れるトークンにも影響しない。

### セッションが認証について記録するもの

すべてのセッションは `authTime`、`amr` — ユーザーがどう認証したかを表す RFC 8176 の値のうち、このプロバイダーが保証するもの — と `authentication` — セッションがどう確立されたか（MFA ADR の D9: primary、どのフェデレーションか、信頼しない上流 IdP が主張したもの、第 2 要素がいつ検証されたか、フェデレーションログインなら上流がユーザーを最後に認証した時刻 `upstreamAuthTime`） — を持つ。これにより `/authorize` は `max_age`・`prompt=login`・`acr_values` を扱え、id_token は `auth_time`・`amr`・`acr` を示せる（全体像は [oauth パッケージの README](../oauth/README.ja.md) にある）。各ログイン経路について両方を core が組み立てる（`passwordSessionAuthentication`、`federatedSessionAuthentication`）:

| ログイン経路 | `amr` | `authentication` |
| --- | --- | --- |
| `POST /session/login` | `["pwd"]`（core の `PASSWORD_AMR`） | primary は `pwd` |
| フェデレーションのコールバック | `["fed"]` — `fed` は「フェデレーション経由」を表すデプロイ定義のマーカーで、core の `FEDERATED_AMR`。このパッケージも re-export する。RFC 8176 にはこれを表す値が無く、OIDC Core は `amr` の値をデプロイに委ねている。`trustUpstreamAmr = true` のフェデレーションでは、その横に上流 IdP の `amr` | primary は `fed`、フェデレーションの名前、そして — フェデレーションが IdP を信頼しない限り — IdP の `amr` を `upstreamAmr` として。`upstreamAuthTime` はアダプターが報告する `auth_time`、報告が無くフェデレーションの `callbackMeetsFreshness` が `false`（既定）なら `null`、`true` なら何も記録しない |
| アカウントリンク（`?link=1`） | 変わらない — リンクはログインではない | 変わらない |

**上流 IdP が主張したものが数えられるのは、それを信頼するフェデレーションだけ**（`core.federations.<name>.trustUpstreamAmr`、既定 `false`、MFA ADR の D13）。上流の `amr` とは、プロバイダーがプロファイルに載せるもの（`profile.amr`、文字列の配列。同梱のアダプターはどれも載せない）である。既定では記録のために `authentication.upstreamAmr` に保持され、どのトークンにも載らず、どの `acr_values` のエントリーも満たさない — IdP が自分のログインについて言うことは、このプロバイダーの言うことではない。フェデレーションのエントリの `enabled` の横に `trustUpstreamAmr = true` と書くと `fed` の横に記録され、数えられる。このスイッチができる前は、すべてのフェデレーションがそうだった。ルートはインストールされた各フェデレーションのスイッチを、構築時に一度、core の `federationSettings` スロットから読む。その `trustsUpstreamAmr` は core の `federationTrustsUpstreamAmr` — `@o3co/auth-provider-oauth` の `acr` の除外が使うのと同じ読み方なので、セッションが記録するものと `/authorize` が広告するものは一致する。`true` でも `false` でもないスイッチは起動を拒否し、環境変数が渡す綴りはスキーマが変換する。各フェデレーションのスイッチはインストールされた名前ごとに保持され、ログインはそのコールバックが来た名前のスイッチを取る。`authentication.federation` が名指すのもその名前である。判断はセッションを作るときにセッションへ書き込まれる: スイッチを変えると、それ以後に確立されたセッションに効く。

**信頼の取り消し。** `trustUpstreamAmr` を `true` から `false` にしても、既にそのもとで記録されたセッションには届かない: その `amr` は IdP の値を持ち続ける — 書かれたときには保証されていた — ので、そこから発行されたトークンはそれを運び続け、そこから発行されたリフレッシュトークンはファミリーが終わるまで（ログインから `oauth.refreshToken.expiresIn`、既定 1 日）それを引き継ぐ。すぐに取り消すには、そのフェデレーション経由でサインインした subject について core の `revokeAllForSubject` を呼ぶ: そのセッション、そこから発行されたリフレッシュファミリーとコード、そしてこのプロバイダー自身が検証するすべてのアクセストークン（イントロスペクション、`/oauth/userinfo`、フェデレーショントークンのルート、トークン交換、リフレッシュグラント）を終わらせ、利用者は新しい設定のもとで再びログインする。リソースサーバーがオフラインで検証するアクセストークンは `exp` まで生きる。`revokeAllForSubject` には `subjectRevocation` と `subjectSessionIndex` の配線が要り、無ければ自身を `incomplete` と報告する。手順は [運用ランブック](../../docs/operator-runbook.md#trusting-an-upstream-idps-amr-and-withdrawing-that-trust) にある。

再認証は *新しい* セッションである: `POST /session/login` とフェデレーションのコールバックは常に新しい `authTime` でセッションを作る。`max_age` と `prompt=login` が測るのはセッションの鮮度（core の `sessionFreshness`）で、`authTime`、フェデレーションログインならそれと記録された上流の認証時刻の早いほうである。フェデレーションの開始（`GET /session/oauth/federation/:name`）は任意の `prompt` と `max_age` のヒントを受け取り — `login` だけを数える空白区切りの一覧と、2^53−1 以下の負でない整数。それ以外は `400 invalid_request` — アダプターに `ask` として渡す。アダプターは上流が文書化しているものだけを渡す。既にアプリケーションのセッションを持つブラウザーからの開始は、リンクでなければ再認証であり、ヒントにかかわらず新しいログイン（`login: true`）を求める。それを尊重する上流（OIDC アダプターは `prompt=login` を渡す）は、自分のシングルサインオンで答えずにユーザーにもう一度サインインを求める — その代わり、サインイン済みのユーザーがもう一度フェデレーションログインを始めると IdP のサインイン画面が出る。コールバックはアダプターが報告する上流の `auth_time` を、エポック以降で `DEFAULT_CLOCK_SKEW_MS` より先でない時刻なら記録する（`authentication.upstreamAuthTime`）。アダプターが報告するそれ以外の値は交換の失敗である（`502 exchange_failed`、`federation_callback_exchange_failed`）。報告が無いとき、`core.federations.<name>.callbackMeetsFreshness` が `false`（既定）のフェデレーションは `null`（決して新しくない）を記録し、`true` のものは何も記録しないので、そのセッションは `authTime` と同じだけ新しい。既に認証済みのブラウザをそのまま `/authorize` に送り返すログインページは、そこで `login_required` を返され、ループしない。

### フェデレーション間のアカウントリンク（#482）

フェデレーションの ID は `<provider>:<sub>` — フェデレーションの名前と、IdP の不透明で安定した subject — であり、コールバックが `UserRepository.authenticateByToken` に渡すのはこの文字列である。**それが誰かを決めるのは Store。** このパッケージはメールアドレスでリンクしない: Web で Google、iOS で Apple でサインインする同じ人物は二つの ID であり、それが一つのアカウントかどうかは Store の記録であって、IdP が主張したアドレスからの推論ではない。

アカウントが二つ目の ID を得るのは、明示的で認証済みの操作によってだけ:

1. ブラウザが既にセッションを持っている（`isAuthenticated`、生きている `UserSession`）。
2. `?link=1` 付きでフェデレーションを開始する: `GET /session/oauth/federation/<name>?link=1` を **デプロイ自身のページ上のリンクまたはフォームから**。開始は GET でセッション cookie は `SameSite=Lax` なので、検査が無ければどのページでもサインイン中のユーザーをそこへ送れ、IdP 側のログイン CSRF と組み合わせれば攻撃者の ID が被害者のアカウントにリンクされてしまう。そのため開始には積極的な証拠が要る: `Sec-Fetch-Site: same-origin`、または `none`（入力された URL やブックマーク）。`cross-site` は拒否。`same-site` はそれだけでは足りない — 登録可能ドメイン上のすべてのホスト、ユーザーが管理する `blog.example.com` も含む — ので、それと `Sec-Fetch-Site` の無いリクエスト（古いブラウザ）は `Referer` にこのオリジンか `session.csrf.trustedOrigins` 上のオリジンを示さなければならない。`Referer` が無ければ拒否する。遷移元のページが自分でリファラーポリシーを選ぶからである。したがって兄弟ホスト上のアカウントページは `session.csrf.trustedOrigins` に載せ、`Referrer-Policy: no-referrer` を送ってはならない。拒否は `403 link_requires_trusted_origin`。次に、Store のリポジトリが `linkFederatedIdentity` を実装していなければ `400 link_unsupported` — 構成の不備であり、セッションを読む前に返すので、セッションストアの状態に関わらず同じ応答になる。開始は続いて core の [セッションアドミッション](../core/src/session-admission/README.md) を通して `session.link`（グレード `credential_change`）としてセッションを読む — リンクした ID はアカウントへの新しい入口なので、登録された requirement の「最近の認証」規則は、ステップアップに戻る先のページがあるここで決まる: 認証されていない、`sid` か `user.id` の無い cookie、`UserSession` が消えた・`expiresAt` を過ぎた・別の subject のもの・（`subjectRevocation` が配線されていれば）subject 失効の境界に覆われたセッション、そして requirement の `reauthenticate` と `unmet` は `401 login_required`。requirement のステップアップは `403 step_up_required` で、`error_description`、`requirement` と `page`（requirement が登録したステップアップページを 1 つの絶対 URL 文字列で）を運ぶ — [開始がステップアップを返すとき](#開始がステップアップを返すとき) を参照。セッションストア・境界・requirement の障害は `503 temporarily_unavailable` で、何が答えられなかったかで説明し（core の `describeAdmissionOutage`: "session store unavailable"、"revocation store unavailable"、"session requirement unavailable"）、アドミッションが 1 行ログに出す（`session_admission_unavailable`、`action: "session.link"`）。いずれもブラウザをどこかへ送る前に返る。
3. コールバックでは、`state`・PKCE・`nonce` をログインとまったく同じく検査したあと、ID を解決する:
   - **誰でもない** → `userRepository.linkFederatedIdentity(currentUserId, { provider, sub, token, claims })`。`ok` ならリンクされ、Store の `refused` は `403 link_refused`、`conflict` は `409 identity_conflict`。Store が `description` を返せば、RFC 6749 の文字の範囲で（範囲外の文字は `?` として）それを説明に載せる。
   - **別のアカウント** → `409 identity_conflict`。Store には問い合わせない。リンクでアカウントがマージされることはない。
   - **このアカウント** → リンクするものは無く、コールバックはそのまま進む。
4. フェデレーションは **生きている** セッション — 現在の `sid` の下の `sessionFederationIndex` と `federationTokenStore` — に紐づけられ、ブラウザはログイン後と同じようにリダイレクトされる。新しい `UserSession` は作られず、express session も再生成されない: リンクはログインではなく、セッションのクレームエンベロープは変わらない（新しいプロバイダー経由の次のログインが通常どおりに作る）。core のセッションライフサイクルが入っていれば、先にトークンを紐づけ、それからフェデレーションがそれを通してセッションに参加する（index のエントリーは参加が書く）: アドミッションの後に終了したセッションは `401 login_required` で拒否され、ライフサイクルがそのトークンを消す。ライフサイクルを入れる前に確立したセッションも同じく拒否される: ライフサイクルのレコードがなく、フェデレーションだけの参加では引き取れないので、サインインし直す必要があり、すでに持っているフェデレーションのリンクし直しはそのフェデレーションのトークンを消す。答えられない参加は `503` で、下と同じくロールバックする。

トランザクションはアドミッションがリンクを許したセッションとその subject（`link: { sid, subject }` — cookie が示した `sid`、つまり記録を読んだキーと、記録の subject）を記録し、コールバックは *その* セッションのアカウントにリンクする: 記録された `sid` と subject（core の `linkClaim`）で `session.link_callback`（`use`）としてもう一度アドミッションを通してセッションを読む。`form_post` フェデレーションのコールバックはアプリケーションのセッション cookie（`SameSite=Lax`）が付かないクロスサイト POST なので、それを束縛するのはこの記録である — Sign in with Apple も `query` フェデレーションとまったく同じようにリンクする — そして、コールバックで別の認証済みセッションを提示したブラウザは `401 login_required` で拒否される: ID がブラウザが今持っているセッションにリンクされることはない。もう生きていない、記録が別の subject を示す、失効の境界に覆われた、または requirement が認めない — ステップアップも含む。コールバックは IdP から来るので戻る先が無い — セッションは `401 login_required`（"Linking a federated identity requires a live session"）であり、subject を記録する前の開始が書いたトランザクションも同じ: ユーザーはリンクを始め直す。Store がリンクしたあとで生きたセッションへの紐づけに失敗した場合、途中まで紐づいたフェデレーションはベストエフォートでセッションから外され（セッションが元から持っていたものはそのまま。セッションのフェデレーション一覧をそもそも読めなかったときは何も外さない）、コールバックは `503` を返す。Store のリンクは残り、そのフェデレーション経由の次のログインはそのアカウントに着地する。リンクに必要なストアが答えられない場合 — セッションの読み出し、Store の `linkFederatedIdentity`、インデックスの読み書き、トークンの紐づけ — はいずれも `503 temporarily_unavailable` で、error レベルで 1 行ログに出る: セッションの読み出し（ストア、境界、requirement。説明はリンク開始と同じ）はアドミッションが `session_admission_unavailable` として `store` と `action: "session.link_callback"` とともに（`sid` は出さない）、それ以外は `federation_link_store_unavailable` として `store`、`step`、リンク中の `sid`、エラーの射影とともに。失敗したロールバックの各ステップは `federation_cleanup_failed` の warn 1 行になる。

`link=1` が無い場合、Store が知らない ID のフェデレーションを完了した認証済みセッションは `401 unknown_user`。**暗黙のリンクは無い** — セッション cookie とはぐれた ID の組み合わせはログイン CSRF の形であり、認証済みセッションでの `link=1` がそれをユーザーの操作にする。

監査イベントは二つ: `federation.identity.linked` と `federation.identity.link_refused`（`details.reason`: `conflict` または `refused`）。どちらも `subject` はそのアカウント。

**リンクする前に Store が検査すべきこと。** この継ぎ目が受け取る `claims` はプロバイダーがマップしたもの — IdP の主張であってそれ以上ではない:

- **メールアドレスだけで結びつけない。** IdP が検証していないアドレス（`emailVerified !== true` — [欠落は `false` ではなく、文字列は欠落扱い](#emailverified-は-idp-が何を送っても-boolean)）、リレーアドレス（Apple の `@privaterelay.appleid.com`、`isPrivateEmail` として出る）、ユーザーがアドレスを変更できる IdP は、既存アカウントと照合してはならない。典型的なアカウント乗っ取りはまさにその照合である。
- リンク要求は既に認証済み — それが生きたセッション上の `link=1` の保証 — なので、リンクを認可するのは一致するアドレスではなくセッションである。それでも Store は拒否してよい: アカウントあたりプロバイダーごとに一つの ID、再認証からの最大経過時間、新しい ID に検証済みアドレスを要求する、など。
- `sub` は issuer ごとに不透明で安定している。`<provider>:<sub>` をそのまま保存し、`email` から ID を導出しない。

`@o3co/auth-provider-foundation` の `HttpUserRepository` は `linkFederatedIdentityUrl`（`REPOSITORIES_USER_HTTP_LINK_FEDERATED_IDENTITY_URL`）が設定されていればこの継ぎ目を実装する: ワイヤ契約は [その README](../foundation/README.ja.md) を参照。core のインメモリリポジトリはメモリ上でリンクするだけ — 開発用であって永続化ではない。

#### 開始がステップアップを返すとき

開始はナビゲーションである: アカウントページがそこへリンクし、ブラウザは IdP へのリダイレクトに従う。`403 step_up_required` はページではなく JSON なので、そこへ遷移したブラウザは本文を表示するだけになる。ステップアップを扱う必要のあるページは、デプロイ自身のオリジンから先に開始を探り、自分で遷移する:

```js
const res = await fetch(startUrl, { redirect: "manual", credentials: "include" });
if (res.type === "opaqueredirect") {
  location.assign(startUrl); // 開始はブラウザを IdP へ送る: そのまま進む
} else if (res.status === 403 && (await res.json()).error === "step_up_required") {
  // ユーザーを `page`（requirement のステップアップ）へ送り、そのあとリンクを始め直す
}
```

探りそのものも一つの開始であり、そのトランザクションは放棄されて失効する（`DEFAULT_FEDERATION_TRANSACTION_TTL_MS`）。`page` は、どの利用側もステップアップに返すのと同じ一つの絶対 URL である: requirement が登録したページを、登録時に **発行者（issuer）** のオリジン（`oauth.jwt.issuer`）で解決したもの — 別のホストでありうるアカウントページ自身のオリジンではない — で、params はクエリーに載り、戻り先のパラメーターは付かない。ページはそのまま遷移し、必要なら自分の戻り先のパラメーターを加える。ナビゲーションの形の応答 — 開始自身がステップアップのページへリダイレクトして戻ってくる — の設計は MFA の作業のものであり、このリリースは JSON を返す。

## フェデレーションアダプターの駆動

アダプター契約 — `FederationProvider`、`FederationProfile`、オプショナル capability とそのガード、response mode の語彙 — は core で定義・説明されている: [`core/src/federations/README.md`](../core/src/federations/README.md)、定義は [`types.mts`](../core/src/federations/types.mts) と [`response-mode.mts`](../core/src/federations/response-mode.mts)。これらの名前は `@o3co/auth-provider-core` から import する。このパッケージは再エクスポートしない。この節はセッションルーターがアダプターに対して何をするかである。

契約のうちルーターが駆動するのは `buildAuthorizationUrl`、`exchangeCode`、`responseMode`、`SupportsClaimMapping`。他の capability は別の場所で駆動される: `SupportsLogout` は `oauth` の `/oauth/logout` と `POST /oauth/federation/:name/logout`、`SupportsRefresh` は `oauth` の `POST /oauth/federation/:name/token`、`SupportsDelegatedAuthorization` は `federation-grants`。

### 開始レグ

`GET /session/oauth/federation/:name` は、IdP が nonce を使うかどうかにかかわらずすべてのフェデレーションについて、`state`（128 ビット）、PKCE の `codeVerifier`、`nonce`（128 ビット）を生成し、`redirect_to` とリンクの意図と一緒に、リダイレクト **の前に** 保存する: `query` フェデレーションなら express session に、`form_post` フェデレーションなら [フェデレーショントランザクション](#トランザクション-cookie) に。保存できないストアは `503 temporarily_unavailable` を返して誰もリダイレクトせず、error レベルで 1 行、`federation_start_store_unavailable`（`store`: `cookie_session` または `federation_transaction`）としてログに出る。リクエスト上に express-session のストアが無い、またはコールバック URL にパスが無い `form_post` フェデレーションは組み立ての誤りであり、`500 misconfiguration` を返す。これらのルートが出会う組み立ての誤り — それ、コールバック URL の無いプロバイダー、リダイレクトポリシーの無いプロバイダー — はいずれも error レベルで 1 行、`federation_misconfigured` として `reason`（`no_session_store`、`no_callback_path`、`no_callback_url`、`no_redirect_policy`）とともにログに出る。`buildAuthorizationUrl` に渡す `redirect_uri` は設定上のそのフェデレーションの `callbackURL`。`form_post` フェデレーションではアダプターが返した URL にルーターが `response_mode=form_post` を付け足し、`query` フェデレーションではアダプターが返した URL そのままになる。

### コールバックがプロファイルで行うこと

1. **アダプターは `callbackParams` を見る** — コールバックの文字列パラメーターから、ルーターが既に束縛した `code` と `state` を除いたもの。ユーザーエージェント経由で中継され署名されていない。アダプターはその中の RFC 9207 `iss` を core の `callbackUrlForExchange` 経由で渡す。
2. **`exchangeCode` が例外を投げると `502 exchange_failed`。** アダプター内のあらゆる拒否 — 誤った `iss`、不正な id_token、UserInfo の不一致 — はこの形で表に出て、Store には届かない。`expiresIn` か `expiresAt` を読むと例外を投げる応答、および `expiresAt` が無し・`null`・時刻を持つ `Date` のいずれでもない応答も同じである。`sub` の無いプロファイルは `400 invalid_profile`。警告 `federation_callback_exchange_failed`（その行にはプロバイダーが束縛される）が運ぶのは core の `loggableError(err)` であり、エラーそのものではない: OAuth ライブラリは拒否したトークン応答を、アクセストークンとリフレッシュトークンを含めてエラーの cause の連鎖に載せるので、エラー全体をシリアライズするロガーはそれを書き出してしまう。これらのルートがログに書く他の失敗 — ストア、リポジトリ、express-session のもの — も同じように射影する（Redis ストアのエラーは拒否されたコマンドの引数を運ぶ。`allow-plaintext` ならトークンレコードである）。
3. **ID は Store が解決する。** `<name>:<sub>` を `UserRepository.authenticateByToken` に渡し、例外なら `503 temporarily_unavailable`、`null` なら `401 unknown_user`（開始でリンクを求めていない限り）。
4. **クレーム** はローカルの `User` のものに、`mapClaims` の結果を [クレームの優先順位](#クレームの優先順位-ローカルが勝ちfederated-は名前空間に隔離される) に従って合わせたもの。`amr` は `fed` — 信頼するフェデレーションではその横に `profile.amr`、そうでなければ `profile.amr` は `authentication.upstreamAmr` に保持される（[上](#セッションが認証について記録するもの)）。
5. **セッション** は新しい `UserSession`（寿命 `session-store.maxAge`、ライフサイクルのレコードを開いたうえで）、配線されていれば `subjectSessionIndex` のエントリー、そして再生成された express session — [セッションの確立](#セッションの確立) に、下のトークンとフェデレーションの参加をコールバック自身のステップとして加えたもの。その establishment は core の `establishWithoutAsking` がフェデレーション自身の事実から組み立てるもので、このリリースではフェデレーションのログインでセッション requirement に問い合わせない（そこでの中断はナビゲーションでなければならない）。だからパスワードログインを中断する requirement もこれは中断しない。requirement の利用時のアドミッションは、セッションが使われるたびにそのセッションに適用される。コールバックに欠かせないストアが失敗した場合 — Store の照会、`UserSession` の書き込みかライフサイクルへの参加、express session の再生成・保存、下のトークンの紐づけ、そしてそれらすべてに先立つ一時状態の破棄（[トランザクションが消費されるとき](#トランザクションが消費されるとき) を参照） — はいずれも `503 temporarily_unavailable` で、error レベルで 1 行、`federation_callback_store_unavailable` として `store`、`step`、エラーの射影とともにログに出る。書き込んだものはベストエフォートで逆順にロールバックされ、失敗したロールバックの各ステップは `federation_cleanup_failed` の warn 1 行になる。`subjectSessionIndex` の書き込みが失敗してもログに出る（`subject_session_index_write_failed`）だけでログインは進む。フェデレーションは、下のトークンを紐づけた後で core のセッションライフサイクル（`sessionLifecycle`）を通してセッションに参加する: 参加のコミット前に終了したセッションは拒否され、ライフサイクルが渡されたトークンを消し、コールバックは書いたものをロールバックして `401 login_required` を答え、何もログに出さない（障害ではなく、セッションの終了である）。ライフサイクルが答えられない参加は `503`（store `session_lifecycle`、step `join`）。どのロールバックも、`UserSession` を削除する前にセッションのライフサイクルのレコードを終了する。
6. **トークン** は、プロファイルが `accessToken` を持つときにだけ、新しい `sid` の下で `federationTokenStore` に紐づけられる:
   - `accessToken`、`refreshToken`、`idToken` はアダプターが返したまま。
   - 有効期間は、`profile.expiresIn` と `profile.expiresAt` を core の `readUpstreamTokenLifetime` で 1 度だけ読む（下限 0、上限なし）。`expires_in` が示され読み取りが有限なら、`obtainedAt` は `exchangeCode` を呼ぶ直前の時刻、`expiresAt` は読み取りの終わり（アダプターの時刻と `obtainedAt + expiresIn` の早いほう）。それ以外（時刻だけで示された終わり — 上流の時計の上にある — 、無し、不正・矛盾・使い切りのもの）では `expiresAt` はアダプターのもので、`null` は `null`（「リフレッシュしない」）として保存され、レコードに `obtainedAt` は無い。そのため `oauth` はこのレコードにリフレッシュのバッファを保つ。ルーターが有効期限をでっち上げることはない。リンクのコールバックも同じ有効期間を書く。
   - `scope` と `grantedScope`: アダプターが `profile.scope` を返していればそれ（空や使えない文字列は何も表さない）、返していなければプロバイダーが要求した `scope` — RFC 6749 §3.3 は応答の欠落を「要求どおり」と読む（[`src/federations/consented-scope.mts`](src/federations/consented-scope.mts)）。
   - `tokenType`: `profile.tokenType` をそのまま、文字列でなければ `""`、アダプターが返さなければ `undefined`（`oauth` はそれを `Bearer` と読む）。
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
| cookie 名 | `__Secure-<session-store.name から接頭辞を除いたもの>.federation` — 例: `__Host-auth.session` も `auth.session` も `__Secure-auth.session.federation` になる |
| 属性 | `HttpOnly; Secure; SameSite=None`、`Path` はそのプロバイダーのコールバック URL に限定、`Max-Age` はトランザクションの寿命（10 分） |
| 中身 | 不透明な 256 ビットの ID だけ |
| レコード | `state`、`codeVerifier`、`nonce`、`redirectTo`、リンクの意図、プロバイダー名。express-session のストアに `fedtx:` というキー接頭辞で置かれる |

名前は CSRF cookie と同じく `session-store.name` から導かれる。接頭辞だけが例外で、**無条件に** 付けられる: `__Host-` ではなく `__Secure-` なのは、`__Host-` は `Path=/` を要求し、この cookie はコールバックにパスを限定しているので `__Host-` の名前ではどのブラウザにも捨てられるから。無条件なのは、この cookie が `SameSite=None` であり、したがって常に `Secure` だから（`Secure` でない `SameSite=None` の cookie はブラウザが捨てる）。したがって `form_post` フェデレーションを持つデプロイはコールバックを HTTPS で提供する — Apple はいずれにせよ戻り URL に HTTPS を要求する。

**アプリケーションのセッション cookie はデプロイが設定した属性を保つ**。`form_post` フェデレーションを開始したことがあるかどうかにかかわらず、すべてのセッションで。`session-store.sameSite` に触れることは無い。

トランザクションはコールバックを、それを開始したブラウザに束縛する。`state` の比較は引き続き行われ、トランザクション cookie はそれへの追加であって置き換えではない。盗んだ `state` を対応するトランザクション cookie なしで提示した呼び出しは、`state` を読む前に拒否される（`400 invalid_session`）。

リクエスト上で express-session のストアに到達できない場合 — ストアモジュールが無い、または `sessionModule` より後にマウントされている — `form_post` の開始は、完了できないフローを始める代わりに `500 misconfiguration` を返す。

放棄されたフローに残るのは短命な cookie だけで、レコードもそれと一緒に期限切れになる: 有効期限はレコードに `cookie.expires` として書かれ、`MemoryStore` は読み出し時にそれで回収し、`connect-redis` はそれをキーの `EX` にする。

#### 認証ホストの登録可能ドメイン配下のすべてのホストは信頼境界の内側

cookie を厳密に一つのホストに固定するのは `__Host-` であり、`__Secure-` は HTTPS を要求するだけである。トランザクション cookie はホスト限定（`Domain` 属性なし）で発行されるが、`__Secure-` という名前は、別のホストが認証ホストを覆う `Domain` で同名の cookie をセットすることを止めず、ブラウザはそちらもコールバックに送る。したがってトランザクション cookie は、`form_post` フローがセッション cookie — デフォルトで `__Host-`、つまりホスト限定であり、起動時にそう検査される — より弱い唯一の場所である。

- **攻撃者に必要なもの:** 認証ホストに対する cookie をセットできるホストのどれか一つの制御 — `auth.example.com` なら、その登録可能ドメイン `example.com` 配下のあらゆるホスト: `blog.example.com`、忘れられたステージングホスト、ぶら下がった DNS レコード、隣の低信頼アプリの XSS、共有ホスティングの隣人。このデプロイからは何も要らない: セッションも `state` もアカウントも。
- **それで得られるもの:** そのホストから被害者のブラウザに `Domain=example.com` で `__Secure-<name>.federation` をセットし、自分のフェデレーションフローを開始し、*自分の* トランザクション ID を仕込み、*自分の* `state` と `code` をコールバックに自動送信する。被害者のブラウザは **攻撃者の** フェデレーションアカウントにログインした状態になり、被害者のその後の操作はそのアカウントに記録される。被害者のセッションを読むことも、資格情報を晒すことも、被害者自身のアカウントに届くこともない — ID の取り違えであって、アカウント乗っ取りではない。
- **cookie に署名しても防げない理由:** 攻撃者のトランザクションは本当に攻撃者のものであり、サーバーが自分の発行物として受け入れるものは何でも攻撃者が正当に持っている。パスを限定した cookie に固有の性質である。
- **すべきこと:** 認証ホストの登録可能ドメイン配下のすべてのホスト — `auth.example.com` ならすべての `*.example.com` — をデプロイの信頼境界の内側として扱い、そのどれでも信頼できない・低信頼のコンテンツを動かさない。`session-store.domain = null`（`__Host-` のデフォルト）が守るのはセッション cookie であってトランザクション cookie ではなく、これに対しては何もしない。ログインルートでは署名付き CSRF トークンがこの規則を補うために存在するが、ここには束縛すべきセッションが無いので、この規則が緩和策のすべてである。

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
- **それ以外はすべて** `claims.federated[<providerName>]` **の下に名前空間化される**。昇格した値やローカルのクレームに負けた値も含め、JSON の形で完全に。コアは `federated` を一つの custom claim として保存する: JSON が保持できない値（bigint、循環）がマップされていると `federated` クレーム全体が落とされ、コールバックのロガーに `login_claim_dropped` として一度だけ警告され、ログインは続く。

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

`core.federations.<name>` のエントリはそれぞれ一つのフェデレーションで、`/session/oauth/federation/<name>` で到達する。エントリはフラットで、core が所有するキーとその `type` のキーが並んで置かれる。

```hocon
core.federations {
  google {
    enabled = true
    type = "google"
    clientId = ${CORE_FEDERATIONS_GOOGLE_CLIENT_ID}
    clientSecret = ${CORE_FEDERATIONS_GOOGLE_CLIENT_SECRET}
    callbackURL = "https://auth.example.com/session/oauth/federation/google/callback"
    clientUrl = "https://app.example.com/"
  }

  okta {
    enabled = true
    type = "oidc"
    issuer = "https://dev-123.okta.com"
    callbackURL = "https://auth.example.com/session/oauth/federation/okta/callback"
    # …
  }

  keycloak {
    enabled = false
    type = "oidc"
    issuer = "https://sso.example.com/realms/staff"
    # …
  }
}
```

core が所有するのは `enabled`、`type`、`trustUpstreamAmr`、`callbackURL` で、それ以外のキーはエントリの type のもの。すべてのエントリは、有効か無効かにかかわらず `type` を名指しする: 無いもの、または空のものは起動を拒否される（`core.federations.<name>.type` における `config-validation-failed`）。有効なエントリを扱うのは、その type を `federationTypes` に登録したモジュールで、そのモジュールがエントリごとにプロバイダーとリダイレクトポリシーを一つずつ、どちらもエントリの名前で作る。したがって一つの type はいくつでもエントリを持てる。Google・GitHub・Apple・OIDC の各パッケージはそのようなモジュール — `googleFederationTypeModule()`、`githubFederationTypeModule()`、`appleFederationTypeModule()`、`oidcFederationTypeModule()` — を export し、それぞれ type `"google"`、`"github"`、`"apple"`、`"oidc"` を扱う（任意の OpenID Connect IdP には [`@o3co/auth-provider-federation-oidc`](../federation-oidc/README.md)）。各パッケージの README がその type のキーを挙げる。無効なエントリは core のスキーマより先では読まれない。

起動時の規則:

- core は type に振り分けるすべてのエントリに空でない `callbackURL` を要求し、無ければ起動を拒否する（`core.federations.<name>.callbackURL` における `config-validation-failed`）。フェデレーションルーターはまさにその値を `redirect_uri` としてアダプターに渡す。
- `trustUpstreamAmr` はエントリの最上位、`enabled` の横でだけ読まれる。無ければ `false` で、（環境変数が渡す綴りを変換したあと）真偽値でないものは core のスキーマが拒否する。別のキーの下に置いた `trustUpstreamAmr`（`core.federations.okta.oidc.trustUpstreamAmr`）は読まれない。これに対応する環境変数は配線されていない。何を決めるかは [上](#セッションが認証について記録するもの) にある。
- フェデレーションのプロバイダーとリダイレクトポリシーは、その `type` を `federationTypes` に登録するモジュールから一緒に来る: 有効なエントリごとに一つずつ、エントリの名前で。モジュールは `federations` も `federationRedirectPolicies` も contribute・override できず、どちらも起動時に拒否される（`contribution-kind-guarded`）。
- `sessionModule` は設定と登録されたフェデレーションを突き合わせない。core の起動が検査する: その `type` をインストールされたどのモジュールも登録しない有効なエントリは起動を拒否される（`federation-type-unhandled`）。無効なエントリはフェデレーションを登録しないので、その開始は `404` を返す。

### リダイレクト許可リスト

`GET /session/oauth/federation/:name?redirect_to=…` と `POST /session/login` の `redirect_to` は、その後ブラウザが行く先を示す。どちらも示せる値はすべて列挙されていなければならない: フェデレーションは `core.federations.<name>.redirectAllowlist`（そのリダイレクトポリシーが読む）、ログインは `session.redirectAllowlist`。

```hocon
core.federations {
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
- **cookie ドメインが設定されていれば、リスト自体を制約する。** ループバックでないエントリーはすべて `sessionDomain`（フェデレーション）または `session-store.domain`（ログイン）の内側でなければならず、ポリシーを組み立てる時点で検査されるので、外側のエントリーは効いているような顔で設定に残るのではなく起動に失敗する。別ドメインへのリダイレクト先を本当に意図するなら、そのフェデレーションの `sessionDomain` を外す。

`authCallbackUrl` と `clientUrl` は許可リストではなく `resolveCallbackRedirect` が読む: 前者は `redirect_to` を受け渡すブリッジページ、後者は開始時に `redirect_to` が無かったコールバックの戻り先。どちらかが必要なのに未設定のコールバックは、セッションを保存したあとで `500 misconfiguration` を返し、ポリシーが答える `5xx` がすべてそうであるように error レベルで 1 行、`redirect_policy_server_fault` としてログに出る。したがって、すべての開始が `redirect_to` を持つのでない限りどのフェデレーションにも `clientUrl` が必要で、`redirect_to` を持つ開始には `authCallbackUrl` が必要になる。

`FederationRedirectPolicy`（[`src/federations/redirect-policy.mts`](src/federations/redirect-policy.mts)）が差し替え点である: フェデレーション type の `redirectPolicy` がその各エントリのポリシーを作り、デフォルト以外のポリシーは fail closed でなければならない。フェデレーションのリダイレクトポリシーを変えたいデプロイは、その type を override する（`overrides.federationTypes.<type>`）。`createFederationRedirectPolicy` がデフォルトで、`checkRedirectShape`、`createRedirectAllowlistValidator`、`describeRedirectRejection`、`isLoopbackHostname` は独自のポリシーが同じ規則と拒否の語彙を再利用できるよう export されている。ポリシーのメソッドは [`FederationResult`](src/federations/types.mts) で答える: 値を持つ `ok`、または返すステータス・OAuth エラーコード・説明。ルートはステータスをそのまま返し、コードと説明は core の `errorEnvelope` を通して送る。そこが RFC 6749 の文字（`"` と `\` を除く印字可能な ASCII）に収めるので、範囲外の説明の文字は `?` として出る。形式に合わないコードは、4xx なら `invalid_request` として出し（拒否はあくまでクライアントのものであり、`400 server_error` は自己矛盾になる）、`redirect_policy_error_malformed` をログに残す。それ以外のステータスでは `server_error` として出る。`describeRedirectRejection` のテキストは最初から範囲内である。`5xx` はクライアントへの判定ではなく、サーバーが答えられないというポリシーの表明なので、error レベルで 1 行、`redirect_policy_server_fault` としてステータスとポリシーのコード・説明（サニタイズして上限で切る。開始レグではプロバイダーも）とともにログにも出る。`4xx` はログに出ない（[`src/internal/refusalEnvelope.mts`](src/internal/refusalEnvelope.mts)）。

### アダプターの書き方

OpenID Connect の discovery ドキュメントを公開する IdP なら、コードは書かない: [`@o3co/auth-provider-federation-oidc`](../federation-oidc/README.md) の `type = "oidc"` エントリがアダプターになる。そうでなければ、アダプターは `federationTypes` に type を登録するモジュールである: エントリ自身のキーのスキーマ（フラット）と、その type の有効なエントリごとに core が呼ぶ二つのファクトリー。ファクトリーにはエントリの名前、その `callbackURL`、スキーマが返したキーが渡される。core は自分が所有するキー（`enabled`、`type`、`trustUpstreamAmr`、`callbackURL`）を取り除いてからスキーマにエントリを読ませる:

```ts
import { defineFederationType, defineModule } from "@o3co/auth-provider-core";
import { createFederationRedirectPolicy } from "@o3co/auth-provider-session";
import { z } from "zod";

const exampleEntrySchema = z.strictObject({
  clientId: z.string().min(1),
  clientSecret: z.string().min(1),
  clientUrl: z.string().optional(),
  redirectAllowlist: z.array(z.string()).optional(),
  authCallbackUrl: z.string().optional(),
  sessionDomain: z.string().optional(),
});

export const exampleFederationTypeModule = defineModule({
  name: "federation-example-type",
  contributes: {
    federationTypes: {
      example: defineFederationType()({
        entrySchema: exampleEntrySchema,
        factory: (_deps, { name, callbackURL, entry }) =>
          createExampleProvider(name, { ...entry, callbackURL }),
        redirectPolicy: (_deps, { entry }) => createFederationRedirectPolicy(entry),
      }),
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
| [`src/__tests__/sessionStoreModule.test.mts`](src/__tests__/sessionStoreModule.test.mts) | `/` のミドルウェアルート、セットする cookie とそれが provider のポリシーであること、`createApp` を通した検証時の各 cookie の拒否と、ストアを開く前のルート自身による拒否、引き続きマウントされる cookie、replica-safety の宣言と拒否 |
| [`src/store/__tests__/factory.test.mts`](src/store/__tests__/factory.test.mts) | 二つの組み込みストア、`session-store` の readiness probe、Redis クライアントのエラーリスナー |
| [`src/__tests__/cookieSessionStore.test.mts`](src/__tests__/cookieSessionStore.test.mts) | 実際の express-session と connect-redis の下で cookie セッションのストアが失敗するとき: ミドルウェアの `503` とその 1 行、そしてルートが答えた障害が一度だけ答えられ、セッションが書き直されないこと |
| [`src/__tests__/csrf.test.mts`](src/__tests__/csrf.test.mts) | 署名付きトークン、その有効期限の上限、作るときに拒否される署名器と `verify` が `true` 以外を返せば拒否として読むこと、オリジン検査、ガードの受理規則 |
| [`src/__tests__/csrfTokenSigner.test.mts`](src/__tests__/csrfTokenSigner.test.mts) | セッションストアの `csrfTokenSigner`: core の契約、固定ベクター、エントロピーの下限、`session-store.secret` の下で署名したトークンが `/session/*` と `csrfGuard` スロットを通ること、override がそれを置き換えること。`sessionModule` と手で組み立てたルーターが署名器なしでは拒否されること、スロットの署名器で署名すること、トークンがスロットと `/session/*` の間で通ること、どのルートでも `session-store.secret` を読まないこと |
| [`src/__tests__/csrfGuard.test.mts`](src/__tests__/csrfGuard.test.mts)、[`loginEntry.test.mts`](src/__tests__/loginEntry.test.mts)、[`loginCompletion.test.mts`](src/__tests__/loginCompletion.test.mts)、[`sessionCookiePolicy.test.mts`](src/__tests__/sessionCookiePolicy.test.mts) | モジュールが他のパッケージに提供するもの: それぞれ core の契約を守ること、モジュールが提供すること、ガードが `/session/login` のものと同じく応答・ログし `GET /session/csrf` が渡すトークンを受け入れること、ログインエントリがページなしで作られ読まれる場所で失敗すること、cookie ポリシーが契約を破るものを cookie の属性のすべての組み合わせにわたって拒否し、それが拒否する名前とドメインが同じメッセージで検証時に拒否されること。ストアのモジュールと並べたポリシーの override が起動を拒否し、モジュールの無い組み立てはスロットを埋めること |
| [`src/__tests__/establish-session.test.mts`](src/__tests__/establish-session.test.mts) | ログインの末尾: 書くもの（establishment の primary だけ、そして偽の establishment の拒否）、その手順、各書き込みに渡すもの、失敗しうるあらゆる点でのロールバック |
| [`src/routes/__tests__/Session.test.mts`](src/routes/__tests__/Session.test.mts)、[`loginAttempts.test.mts`](src/routes/__tests__/loginAttempts.test.mts) | ログイン、ログアウトが無効化するものとストア障害が `UserSession` の削除を止めないこと、障害時の応答とそのログ 1 行、ログインの試行上限 |
| [`src/routes/__tests__/Session.loginAdmission.test.mts`](src/routes/__tests__/Session.loginAdmission.test.mts) | セッションアドミッション上のパスワードログイン: requirement に問われること、各 outcome への応答、中断の二段階と再生成以降の各失敗への応答。単独の `answerInterruption` — その応答、各失敗での reporter と答え、拒否するもの |
| [`src/routes/__tests__/Federation.test.mts`](src/routes/__tests__/Federation.test.mts) | 開始とコールバックのレグ、アカウントリンク、ストアへの書き込みとそのロールバック、障害時の応答とそのログ、`amr` |
| [`src/routes/__tests__/Federation.linkAdmission.test.mts`](src/routes/__tests__/Federation.linkAdmission.test.mts) | セッションアドミッション上のリンクの開始とコールバック: 各 outcome への応答、`sid` と並べて記録される subject、requirement に問われること、アップグレード前のトランザクション |
| [`src/routes/__tests__/Federation.loginEstablishment.test.mts`](src/routes/__tests__/Federation.loginEstablishment.test.mts) | 問い合わせずに確立されるコールバックのログイン: パスワードログインを中断する requirement もこれは中断せず、レコードは core が組み立てたものであること、`User` は一度だけ読まれること、スナップショットが拒否するユーザーは何も書かずに拒否されること |
| [`Federation.formPost.test.mts`](src/routes/__tests__/Federation.formPost.test.mts)、[`Federation.applicationCookie.test.mts`](src/routes/__tests__/Federation.applicationCookie.test.mts)、[`Federation.transactionFailures.test.mts`](src/routes/__tests__/Federation.transactionFailures.test.mts)、[`Federation.transactionConcurrency.test.mts`](src/routes/__tests__/Federation.transactionConcurrency.test.mts) | response mode、トランザクション cookie、手を付けられないセッション cookie、トランザクションの失敗経路、「一度きり」が保証すること |
| [`src/federations/__tests__/`](src/federations/__tests__/) | ツールキットとルーターのフェデレーション部品。要求を組み立てるヘルパーは core で固定される（[`core/src/federations/__tests__/`](../core/src/federations/__tests__/)） |

## 関連

- [`@o3co/auth-provider-core`](../core/README.ja.md) — このパッケージが駆動するポートと、[フェデレーションアダプター契約](../core/src/federations/README.md)
- [`@o3co/auth-provider-oauth`](../oauth/README.ja.md) — トークン発行、`/oauth/logout`、フェデレーションのトークンとログアウトのルート
- [`@o3co/auth-provider-redis`](../redis/README.md) — セッションストア（`UserSessionStore` など）の Redis アダプター。上のブラウザセッションストアとは別物
