# @o3co/auth-provider-foundation

最終更新: 2026-10-06

auth.provider のための「the Store」 — デプロイ自身のユーザーサービス — の HTTP クライアント。`HttpUserRepository` は core の `UserRepository` ポートを HTTPS で実装する: ユーザーを認証し、フェデレーション ID をリンクし、federation grants が求める ID の照会に答え、MFA の登録の証人を書く。`registerBuiltinAdapters` はそれを `"http"` ユーザーアダプターとして登録する。このパッケージはまた、Store の MFA エンドポイント — Store が主体の第二要素と登録の証人を保持する場所 — の契約を、それを名指す設定セクションと、その失敗が投げるものとともに定める。`HttpMfaFactorStore` は要素のエンドポイントの上に core の `MfaFactorStore` を実装し、`foundationMfaFactorStoreModule` がそれを組み込む。

## 責務と役割

**役割。** core のポート二つのアダプター: [`UserRepository`](../core/src/repositories/UserRepository.mts)（[`core/src/repositories`](../core/src/repositories/README.md) を参照）と、Store がデプロイの MFA 要素を保持する場合の [`MfaFactorStore`](../core/src/mfa/factorStore.mts)。パッケージ名に反して基盤層ではない: 実行時にこれを import する他のパッケージは無い（`federation-grants` がテストで使うだけ）。これを選ぶのは組み立て側 — standalone テンプレートでは `adapters.userRepository = "http"`。

**持つもの:**

- Store が実装するワイヤ契約: `HttpUserRepository` が送るリクエストと、それぞれの応答の意味（後述）。
- Store の URL に対する通信の規則 — `https`、またはループバックホストへの `http` だけ（[`src/endpointUrl.mts`](src/endpointUrl.mts)） — と、どのリクエストもそこからリダイレクトで離れないこと。
- Store に提示する資格情報（`bearerToken`）、その資格情報に課す下限、そして Store によるその拒否の読み方。
- 通信が報告するもの — リクエストを引用しうる — を何も投げないこと。
- リクエストの期限とレスポンスサイズの上限。
- ID の照会が起動時に判定される根拠となるカバレッジ宣言。
- Store の MFA エンドポイントの契約: 各エンドポイントに何を送り、各応答が何を意味するか、そして Store が送るものが何一つクライアントに届かないこと（[後述](#store-の-mfa-エンドポイント)）。要素のエンドポイントを名指す `foundation-mfa-factor-store` セクション。その失敗が投げる `MfaStoreError`。
- Store を使う `MfaFactorStore` である `HttpMfaFactorStore` と、それを組み込む `foundation-mfa-factor-store` モジュール（[後述](#store-を使う要素ストア)）。

**持たないもの:** ポートと `User` の形（core）。MFA のポートと MFA エンドポイントの JSON ボディ（core の [`mfa/storeWire.mts`](../core/src/mfa/storeWire.mts)。Store 自身の実装とテストキットの偽の Store もこれを読む）。ユーザーをいつ認証し、ID をいつリンクし、所有者をいつ照会するか — セッションルート（[`@o3co/auth-provider-session`](../session/README.ja.md)）、`oauth` の jwt-bearer グラント（[`@o3co/auth-provider-oauth`](../oauth/README.ja.md)）、federation grants（[`@o3co/auth-provider-federation-grants`](../federation-grants/README.md)）。Store 自体。core の開発用ユーザーアダプター（`yaml` / `static`）。Redis バックエンドのストア（[`@o3co/auth-provider-redis`](../redis/README.md)。Redis の認可コードストアもこちら）。

**別パッケージである理由。** core が同梱するのはファイルから読む開発用のユーザーアダプターだけで、本番のデプロイはユーザーを自前のサービスに持ち、これはそのためのクライアントである。差し替え可能な部品 — 独自の `UserRepository` 実装を持つデプロイはこれをインストールしない — であり、パッケージとしては core だけに依存する（グローバルの `fetch` と、セクションのスキーマのための `zod`）。

## インストール

```sh
npm install @o3co/auth-provider-foundation @o3co/auth-provider-core
```

peer dependency: `@o3co/auth-provider-core`。このパッケージ自身の dependency は、設定セクションのスキーマのための `zod` だけ。

## 使い方

```typescript
import { createRepositoryFactories } from "@o3co/auth-provider-core";
import { registerBuiltinAdapters } from "@o3co/auth-provider-foundation";

const { userFactory } = createRepositoryFactories();

registerBuiltinAdapters({ userFactory });

// ファクトリー経由で HTTP ユーザーリポジトリを生成
const userRepo = await userFactory.create({
  type: "http",
  authenticateUrl: "https://users.example.com/authenticate",
  authenticateByTokenUrl: "https://users.example.com/authenticate-by-token",
  timeout: 5000,
});
```

`registerBuiltinAdapters`（[`src/index.mts`](src/index.mts)）は `UserRepository` のファクトリーに `"http"` 型を登録する。そのビルダーは下のキーを読み、`timeout` が無ければ 5000 ms、`maxResponseBytes` が無ければ `DEFAULT_MAX_RESPONSE_BYTES`（1 MiB）をデフォルトにし、文字列で与えられた数値（環境変数による上書き）も受け付ける。`HttpUserRepository`（[`src/repositories/HttpUserRepository.mts`](src/repositories/HttpUserRepository.mts)）は同じオプションで直接構築することもできる。その場合 `timeout` は必須で、5000 ms のデフォルトはビルダーのものである。

### 設定

standalone テンプレートの `repositories` セクションの `repositories.user.http` の下で、`adapters.userRepository = "http"`（`ADAPTERS_USER_REPOSITORY`）のとき読まれる。デフォルト値は[テンプレートの `reference.conf`](../../templates/standalone/config/reference.conf) にある:

| キー | 環境変数 | |
| --- | --- | --- |
| `authenticateUrl` | `REPOSITORIES_USER_HTTP_AUTHENTICATE_URL` | 必須。パスワードログイン。 |
| `authenticateByTokenUrl` | `REPOSITORIES_USER_HTTP_AUTHENTICATE_BY_TOKEN_URL` | 必須。不透明なハンドルを解決する: フェデレーションログイン、jwt-bearer グラント。 |
| `linkFederatedIdentityUrl` | `REPOSITORIES_USER_HTTP_LINK_FEDERATED_IDENTITY_URL` | 任意。アカウントリンクを有効にする。 |
| `findSubjectByFederatedIdentityUrl` | `REPOSITORIES_USER_HTTP_FIND_SUBJECT_BY_FEDERATED_IDENTITY_URL` | 任意。ID の照会。 |
| `federatedIdentityLookupCoverage` | —（リストなので HOCON のみ） | 照会がカバーする範囲。デフォルト `[]`。 |
| `markMfaEnrolledUrl` | `REPOSITORIES_USER_HTTP_MARK_MFA_ENROLLED_URL` | 任意。MFA の登録の証人を書く（[後述](#ユーザーリポジトリを通して書かれる証人)）。既定値なし。 |
| `bearerToken` | `REPOSITORIES_USER_HTTP_BEARER_TOKEN` | 任意。すべてのリクエストで `Authorization: Bearer <token>` として送る。32 バイト以上の鍵素材。未設定なら `Authorization` ヘッダーは送らない。[Store を誰が呼べるか](#store-が自分で守るべきこと) を参照。 |
| `timeout` | `REPOSITORIES_USER_HTTP_TIMEOUT` | ミリ秒。デフォルト 5000。 |
| `maxResponseBytes` | `REPOSITORIES_USER_HTTP_MAX_RESPONSE_BYTES` | デフォルト 1048576。 |

## ワイヤ契約

リクエストはすべて JSON ボディの `POST` で、`bearerToken` が設定されていれば `Authorization: Bearer <token>` ヘッダーを持つ。Store が返すユーザーは core の [`User`](../core/src/repositories/types.mts)。

**`authenticate`** は `authenticateUrl` に `{ email, password }` を送る（ユーザー名は `email` として届く）。**`authenticateByToken`** は `authenticateByTokenUrl` に `{ token }` を送る。`token` は Store がユーザーに解決する不透明なハンドル — フェデレーションのコールバックからは `<provider>:<sub>`、`oauth` の jwt-bearer グラントからは検証済みアサーションの subject ハンドル。どちらも:

- ボディが JSON の `User`（`{ id: string, username: string, … }`、どちらも空でない）である `2xx` はそのユーザー。
- `401` または `403` は `null` — ユーザーが居ない、または資格情報が誤り。
- `User` でないボディの `2xx` は例外 — 「ユーザーが見つからない」ではなく上流の障害。空の `id` や `username` は `User` ではない: 空の `id` は誰も指さず、OpenID Connect Core §2 はそれがなる `sub` にローカルに一意な識別子を求める。ユーザー名の無いユーザーには、Store は安定したラベル — たとえばメールアドレス — を `username` として送る。セッションのルートと jwt-bearer グラントはこの例外を、Store の他の障害と同じく `503 temporarily_unavailable` で返す（それぞれが出すログは [Store が自分で守るべきこと](#store-が自分で守るべきこと) の表にある）。
- それ以外のステータスは例外。

**MFA の登録の証人は両方の読み取りで。** 証人を保持する Store（MFA ADR の D12）は、`User.mfaEnrolled` を `authenticate` と `authenticateByToken` の両方で同じように返さなければならない（MUST）: 真偽値で、主体が初めて印を付けられるまでは省く。フェデレーションのログインは `authenticateByToken` の `User` から証人を記録するので、`authenticate` だけで返す Store は、フェデレーションのセッションから証人が与える防御を外す。アダプターは `mfaEnrolled` を Store が返したとおりに渡し、core がそれを読む（`readMfaEnrollmentWitness`）: `true`・`false`・省略以外の値は不正で、MFA パッケージはそれを `503` で返し、決して最初の紐付けにしない。テストキットの証人スイートが Store に両方の読み取りを課す。

`2xx` 以外の応答のボディは、これらでもリンクでも読まずに捨てる。ID の照会を含め、どのリクエストもリダイレクトを追わない: `3xx` は例外になるステータスの一つにすぎず、その `Location` には一切接続しない。

**`Bearer` チャレンジ付きの `401` または `403` は資格情報の拒否である。** `bearerToken` が設定されているとき、送り先のどのエンドポイントから `WWW-Authenticate: Bearer …`（RFC 6750 §3 — `invalid_token`、`insufficient_scope`）を持つ `401` または `403` が返ると、この節がそのステータスに与える読み — 「ユーザーが居ない」、リンクの拒否、照会の `answered HTTP <status>` — のどれでもなく、`StoreCredentialRefusedError`（`HttpUserRepository: the Store at <url> refused this deployment's credential (HTTP <status> with a Bearer challenge) — …`）が投げられる。各呼び出し元がそのとき何を返し何をログに出すかは [Store が自分で守るべきこと](#store-が自分で守るべきこと) にある。チャレンジは大文字小文字を問わず、他のチャレンジと並んでいても、独立したヘッダー行にあっても見つけ、引用符付き文字列の中にあるものは決して数えない。閉じられていない引用符付き文字列は値の末尾まで続き、その後ろにあるものを隠す — そのときはチャレンジが無いものとして読まれる。Store がスキームの後に書いたものは何も繰り返さない。`Bearer` チャレンジの無い `401` や `403`、およびトークンが設定されていないときのあらゆる `401` や `403` は、この節が与える意味を保つので、トークンを検査しない Store には影響しない。

**通信の失敗はやり取りの何も運ばない。** リクエストができない、または応答を読めないとき、エラーは `StoreTransportError` で、その `reason` とメッセージがどれかを示す:

| `reason` | いつ | メッセージ（照会では `identity lookup at <url> …`） |
| --- | --- | --- |
| `unreachable` | やり取りする接続が無い: 接続の拒否、DNS、TLS、ネットワークが届かない経路やホスト — ネットワークの経路か TLS | `HttpUserRepository: request to <url> could not be reached` |
| `connection_closed` | 完全な応答が届く前に接続が閉じられた、またはリセットされた: 1 バイト目の前、暫定の `1xx` の後、ヘッドの途中、または二つのリクエストの間に Store・プロキシ・アイドルタイムアウトが閉じたプール済みの keep-alive 接続 — 通信からはどれかを区別できない | `HttpUserRepository: the connection to <url> closed before a complete response arrived`（照会では `identity lookup at <url>: the connection closed …`） |
| `malformed_response` | Store が通信の受け取れない応答ヘッドを送った: パーサーがステータス行かヘッダーを拒否した、またはヘッドがサイズ上限を超えた — Store の、またはプロキシの応答 | `HttpUserRepository: the Store at <url> answered with a malformed HTTP response` |
| `unreadable` | HTTP の応答のボディが読み取りの途中で壊れた | `HttpUserRepository: response from <url> could not be read` |

どれも運ぶのはせいぜいオペレーターが対処できる通信のコード（メッセージの中と `code` として）だけ: `ECONNREFUSED`、`ENOTFOUND`、`ECONNRESET`、`EPROTO`、`UND_ERR_*`（`UND_ERR_HEADERS_OVERFLOW`、`UND_ERR_SOCKET` など）、ランタイムが設定する場合の `HPE_*`（Node 26 の undici はパーサーのエラーにコードを設定しない）、`ERR_SSL_*`（`ERR_SSL_WRONG_VERSION_NUMBER` は平文の HTTP を話すポートを指す https の URL、`ERR_SSL_SSL/TLS_ALERT_HANDSHAKE_FAILURE` は Store が拒否した TLS 1.2 のハンドシェイク — クライアント証明書を求める相互 TLS、または共通の暗号スイートが無い）、証明書のコード。通信自身のエラーや `cause` は決して運ばない: undici のパーサーのエラーは拒否したバイト列をそのまま引用し、リクエストを反射する相手 — 壊れたプロキシ、デバッグ用のエコー — はその中に `Authorization` ヘッダーやパスワードを置く。期限を超えたリクエストはこれではなく `TimeoutError` になる（コンストラクタでの検証を参照）。

**`linkFederatedIdentity`** は `linkFederatedIdentityUrl` に `{ userId, provider, sub, token, claims }` を送る: `2xx` の `User` は `{ ok: true, user }`、`401` / `403` は `{ ok: false, reason: "refused" }`、`409` は `{ ok: false, reason: "conflict" }`、それ以外は例外。ボディが `User` でない `2xx` も例外になるが、そのとき Store はすでにリンクを作っている: 呼び出し元は `503` を返してリンクを監査しないので、そのリンクは Store の側で整合させる。拒否のボディは読まれないので、拒否が Store からの説明を運ぶことはない。`linkFederatedIdentityUrl` が設定されていなければこのメソッドは存在せず、フェデレーションのルートはそれで `?link=1` を最初から拒否すると分かる。`2xx` を返す前に Store が検査すべきこと — 未検証やリレーのアドレスでは決してリンクしない、メールアドレスだけで決してリンクしない — は [セッションパッケージの README](../session/README.ja.md#フェデレーション間のアカウントリンク482) にある。

#### ID の照会（#613）

federation grants のデプロイ（`@o3co/auth-provider-federation-grants`、ADR の [D7](../core/docs/adr/2026-09-17-federation-grants-offline-delegation.md#d7--the-connect-flow-binds-its-callback-and-refuses-on-any-mismatch) にある接続コールバックの check 5）が Store に尋ねること: 上流の ID を誰が持っているか。アカウントが別のローカルユーザーのものなら委任を拒否するためである。Store は、その ID が通ってきた登録だけでなく、その IdP の **すべての** 登録にまたがる所有について答える — ログインはユーザーがサインインしたフェデレーションの下でリンクされ、`sub` がアプリ登録ごとのペアワイズである IdP（Entra がそう）は同じ人物に登録ごとに別の `sub` を与える。grants 用の独立した登録（ADR の [D19](../core/docs/adr/2026-09-17-federation-grants-offline-delegation.md#d19--entra-on-behalf-of-is-not-implemented-and-consent-accumulates)）にとってそれが意味するのは: `unlinked` と正直に答えるには、Store は検証済みの `(tid, oid)` を、該当テナントについて完全な権威あるディレクトリと、登録をまたがるすべてのローカル所有リンクに対して解決しなければならない。部分的なディレクトリで一致が無い場合や見知らぬ ID は `identity_not_resolvable`、異なるローカル所有者が複数居るのはサーバーエラー。カバレッジを宣言することはその戦略を表明することであり、起動時にリモートのディレクトリの完全性を調べたり証明したりはしない。

リクエストは `POST findSubjectByFederatedIdentityUrl` で、ボディは

```json
{ "provider": "entra-files", "issuer": "https://login.microsoftonline.com/<tenant>/v2.0",
  "clientId": "<the grants app registration>", "sub": "<verified sub>",
  "claims": { "tid": "<verified>", "oid": "<verified>" } }
```

— connection の設定どおりの登録、検証済みの `sub`、そして connection の `identityClaims` が名指したすべてのクレーム（id_token からの検証済みのもの。何も名指さなければ `{}`）。Store はそれらのクレームをログに出したり、保存したり、応答に含めたりしてはならない — core の [`FederatedIdentityLookup`](../core/src/repositories/UserRepository.mts) はそれらを一時的なものと定めている。照会は何も変えてはならない: ログインの記録も、リンクも、ユーザーの作成もしない。応答は `2xx` の JSON ボディで、次のいずれか

| ボディ | 意味 |
|---|---|
| `{ "kind": "linked", "subject": "<local User.id>" }` | ちょうど一人のローカルユーザーが持っている。`subject` はそのユーザーの `id` と **バイト単位で同一** — コールバックはそれをサインイン中のユーザーの `sub` と完全一致で比較するので、パディングやその他の正規化をした id は別ユーザーのものと読まれる |
| `{ "kind": "unlinked" }` | **完全な** 解決で誰も見つからなかった |
| `{ "kind": "indeterminate", "reason": "registration_not_covered" }` | この登録に戦略が無い |
| `{ "kind": "indeterminate", "reason": "identity_not_resolvable" }` | 戦略はあるが、この ID はその中に無い |

それ以外のフィールドは無視する。**それ以外はすべて障害であり、決して「誰でもない」ではない**: `2xx` 以外のあらゆるステータス — `404`、`401`、`403`、`409`、`5xx` — 、空または四つのどれでもないボディの `2xx`、リダイレクト（決して追わない: ボディは検証済みの ID を運ぶ）、タイムアウト、上限を超えるボディはすべて例外になり、コールバックは `temporarily_unavailable` を返す。異なるローカル所有者が複数居る場合は Store が `500` を返す。例外が示すのはエンドポイント — そしてステータスのある応答ならそのステータス — であり、ボディ、ID、ステータステキスト、根底の原因は決して含めない。

**カバレッジ。** grants モジュールが起動時に尋ねる probe は同期的で Store に届かないので、`federatedIdentityLookupCoverage` が Store の照会のカバー範囲を中継する: 登録ごとに一つのエントリー `{ provider, issuer, clientId, requiredClaims }` で、四つのフィールドすべてを完全一致で比較し（トリムなし、大文字小文字の畳み込みなし、末尾スラッシュの許容なし）、`requiredClaims` は戦略が必要とするクレーム名 — 登録と `sub` だけで足りる戦略なら `[]`。`supportsFederatedIdentityLookup(registration, identityClaims)` は、登録と一致するエントリーがあり、その `requiredClaims` のすべてが `identityClaims` に含まれるとき `true`。federation grants が有効で connection が一つ以上あり、`federation-grants.identityLookup` が `"required"`（デフォルト）のとき、grants モジュールはこれが `false` になる connection をすべて起動時に拒否する。`"unsupported"` のとき、または connection が無いときは何も求めない。誰も宣言していない登録はローカルで `registration_not_covered` と答え、宣言済みの登録で必要なクレームが欠けていれば `identity_not_resolvable` と答え、どちらもリクエストは送らない。宣言は構築時にスナップショットされ、重複した登録、不正なエントリー、URL の無いカバレッジは構築エラーになる。`federation-grants.connections` と同じく環境変数の形は無い（リストは HOCON のもの）。`findSubjectByFederatedIdentityUrl` が設定されていなければ `supportsFederatedIdentityLookup` と `findSubjectByFederatedIdentity` は存在せず、そのうえで `"required"` の下に connection を持つデプロイは起動時に拒否される。

## Store の MFA エンドポイント

Store は主体の第二要素（MFA ADR の D7）と登録の証人（D12）を保持できる。決めるのはプロバイダーで、Store は保存するだけ。要素の `data` はプロバイダーが先に封印し、Store はそれを復号も記録もせず、そこから何かを導きもしない。このパッケージは契約と、要素のエンドポイントを名指すセクションと、その失敗が投げるものを持つ。`HttpUserRepository` は `markMfaEnrolledUrl` が設定されていれば証人のリクエストを送り（[後述](#ユーザーリポジトリを通して書かれる証人)）、`HttpMfaFactorStore` が要素の四つのエンドポイントに送る（[後述](#store-を使う要素ストア)）。JSON ボディは core の [`mfa/storeWire.mts`](../core/src/mfa/storeWire.mts)（`MfaStoreFactor`、`MfaStoreUpdateRequest` など）で、両側が使う変換もそこにある。

**どのリクエストも** 設定された URL そのままへの JSON の `POST` で — パスもクエリも足さないので、主体や要素の ID がリクエスト行や Store のアクセスログに現れることはない — ユーザーリポジトリの規則に従う: 同じ `bearerToken`・期限・レスポンス上限、`https` かループバックの `http`、リダイレクトを追わない、`Bearer` チャレンジ付きの `401` / `403` は拒否された資格情報（[ワイヤ契約](#ワイヤ契約)）。

**要素のレコード** は `{ id, subject, kind, label?, binding?, createdAtMs, lastUsedAtMs?, version, data }`。時刻はエポックミリ秒の数値で、`…Ms` と名付ける。値の無い省略可能なフィールドは省く: `null` は決して「未設定」ではなく、どれかのフィールドに `null` を持つレコードはプロバイダーが読めないレコードである。`id` は base64url の 22 文字（16 バイトの乱数）、`kind` はヒントのトークン（`^[a-z][a-z0-9_-]{0,63}$`）、`label` は 1〜64 文字で、正しい形の文字列であり、行を分けたり並びを変えたりする文字を含まない。`binding` は `password`・`email_proof`・`federated`・`mfa`、`version` は安全な非負整数、`data` はバイト単位でそのまま保持される文字列。この形から外れたレコードはプロバイダーが読めないレコードである（core の `isMfaFactorId`・`isMfaFactorKind`・`isMfaFactorLabel`）。

| エンドポイント | リクエスト | 応答 |
| --- | --- | --- |
| list（`listUrl`） | `{ subject }` | `200 { factors: [record…], generation }`: 主体について保持するすべてのレコードと集合の世代を、一つのスナップショットから。集合が無ければ `{ factors: [], generation: null }`。他のステータスは throw。 |
| create（`createUrl`）、条件付き | `{ factor: record, expectedGeneration, deadlineMs }` | `200 { outcome: "created", generation }`: 作成し、集合は新しい世代になった。`409 { outcome: "conflict" }`: 何も書いていない。他のステータスは `404` も含めて throw。 |
| update（`updateUrl`） | `{ subject, id, expectedVersion, changes: { data, label?, lastUsedAtMs? } }` | `200 { factor: record }`、`expectedVersion + 1` で書かれたレコード。`409`: バージョンが動いた。`404`: レコードが無い — どちらもポートの `null`。他のステータスは throw。 |
| delete（`deleteUrl`）、条件付き | `{ subject, id, expectedGeneration, deadlineMs }` | `200 { outcome: "removed", generation }`: 削除し、集合は新しい世代になった。`404 { outcome: "missing" }` と `409 { outcome: "conflict" }`: 何も書いていない。他のステータスは throw。 |
| delete、集合のリセット | `{ subject, all: true }` | `2xx`（`204`）、または何も無かったときの `404`: どちらも完了。他のステータスは throw。 |
| markMfaEnrolled（`markMfaEnrolledUrl`） | `{ subject, enrolled }` | `204`（すでにその値を保持しているときも）。`404`: Store にその主体が無い — エラー（主体は認証したばかりである）。他のステータスは throw。 |

- **更新は変更だけを書く。** 更新はレコードを `subject` と `id` で名指し、期待するバージョンと、変更として `data`・`label`・`lastUsedAtMs` だけを運ぶ。省いたものは消える。`id`・`subject`・`kind`・`binding`・`createdAtMs` は変更として送られず、Store はそれらを変えてはならない。他のフィールドを持つ変更は拒否する（`400`）。Store は `expectedVersion` で原子的に比較して書き、`version` を一つ上げる: 同じバージョンへの二つの更新が両方とも成功することは無い。
- **レコードは常にすべて。** list は Store が主体について保持するすべてのレコードを、Store 自身やプロバイダーが読めないものも含めて、その主体のものだけ返す。プロバイダーは読めないレコード — フィールドの欠落、型違い、範囲外や形の外、`null` — と、別の主体を名指すレコード、一覧にすでにある ID を持つ二つ目のレコードを、存在するが使えないものとして扱う: その主体の一覧は丸ごと拒否され（core の `readMfaStoreListAnswer`）、レコードが少ないとは決して読まれない。だからそのようなレコードで主体が「要素ゼロ」と数えられることも、最初の紐付けが開くことも無い。通信の失敗は障害であり、空の一覧ではない。
- **更新の応答が `expectedVersion + 1` 以外のバージョン** なら、成功ではなく障害で、主体と要素の ID を名指すエラー行一行になる。
- **証人** は `authenticate` と `authenticateByToken` で `User.mfaEnrolled` として返される（[両方の読み取り](#ワイヤ契約)）: 真偽値で、主体が初めて印を付けられるまでは省かれ、core の `readMfaEnrollmentWitness` を通してだけ読まれる。
- **要素の完全性と鮮度は Store のもの。** レコードのバージョンは決して戻らず、Store が認めた書き込みは — 復元やフェイルオーバーを挟んでも — 決して失われない。一覧は最新の書き込みを返し、主体の持つすべてのレコードを返し、削除したレコードを返さない。プロバイダーはそのどれも検査できない（[Store が自分で守るべきこと](#store-が自分で守るべきこと)）。

**要素の集合の世代。** 主体のレコードは一つの集合で、Store はその構成に一つの世代を保つ。これは core の条件付き書き込みの規約の集合版（[`docs/adapter-surface.md` の「Conditional writes」](../../docs/adapter-surface.md#conditional-writes)）に従い、表はその HTTP ワイヤに従う。両側で core の変換がそれを運ぶ（`readMfaStoreVersionedListAnswer`、`toMfaStoreCreateIfRequest`、`readMfaStoreCreateIfAnswer`、`toMfaStoreRemoveIfRequest`、`readMfaStoreRemoveIfAnswer`）。

- **世代** は 1〜128 文字の表示可能な ASCII で `"` を含まず（core の `isStoreGeneration`）、全体としてだけ比べる。Store はそれを乱数で作り — たとえば v4 UUID — その主体について二度と発行しない: 集合が空になってから再び書かれても、バイト単位で同じ書き直しでも、墓標が期限切れになっても、書き込みを失う復元やフェイルオーバーのあとでも。ダイジェスト、タイムスタンプ、カウンターは世代にならない。
- **構成を変える書き込みのたびに新しい世代を作る**: 作成、実際に削除した削除、リセット。更新は世代を保つ。
- **条件付き書き込みは、確認と書き込みで一つの原子的な手順。** SQL なら、集合の行を先に、次にそのレコードの行をロックする一つのトランザクション。プロセス内のロックは数えない。リセットも一つの原子的な手順で、条件付きの書き込みと直列化される。
- **作成と一件の削除は、必ず `expectedGeneration` を持つ。** プロバイダーはどちらもそれ無しには送らず、Store はそれの無いものを、規約と同じく `400` で拒否してよい。`null` は作成にだけ使え、「集合が無いあいだだけ」を意味する。世代でない値と、削除での `null` は `400`。
- **`conflict` と `missing` は何も書かない。** 作成は、集合が別の世代にあるとき、`expectedGeneration` が世代を名指すのに集合が無いとき、`null` なのに集合があるとき、その `(subject, id)` をすでに持つときに `conflict` を返し、`missing` は決して返さない。削除は、集合が無ければ `missing`。集合があれば先に世代を確かめて別の世代なら `conflict`、次にレコードを確かめて無ければ `missing`。
- **空になった集合は墓標として残る。** 最後のレコードの削除やリセットは、集合を空のまま新しい世代で残し、リセットは一度も書かれていない主体にも集合を作る。墓標が無いと読まれるのは、集合の最後の構成の書き込みから `BUNDLED_STORE_WRITE_LIFETIME_MS`（24 時間）が過ぎてからだけで、集合を空にする書き込みのたびに — 空の集合のリセットも含め — 数え直す。レコードを持つ集合は期限切れにならない。アカウントの削除も同じリセットである。
- **世代を持たずに保持された集合** — Store が世代を保つ前に書かれたもの — は、最初の list でレコードを保ったまま原子的に新しい世代を与えられる。それに対する条件付き書き込みは `conflict` を返し、世代を作らない。
- **list をキャッシュから返さない。** list はレコードと世代を、list が始まる前に Store が認めたすべての書き込みを反映した一つのスナップショットから返す: Store 自身のものも、その前段の HTTP キャッシュのものも、遅れたレプリカのものも、キャッシュされた応答は決して返さない。古い list は、すでに削除した要素をあるものとして、すでに動いた世代を返す。
- **巻き戻しで世代を戻さない。** Store が認めた書き込みより前の状態に集合を戻す復元やフェイルオーバーは、その状態の世代を再び返すことになり、書き手がまだそれを持っているかもしれない。Store は、復元した集合のどれについても応答する前に新しい世代を作るか、認めた書き込みを決して巻き戻さないように運用するかのどちらかで、どちらであるかを明記する。
- **条件付き書き込みは期限を述べる。** 条件付きの作成や削除は `deadlineMs` を運ぶ: それを過ぎたら適用してはならない時刻を、プロバイダーの時計のエポックミリ秒で示す。アダプターはそれを送る瞬間にリクエストの期限を足した値にし、その瞬間に自分でも諦める。Store は `deadlineMs` を、条件付き書き込みと同じ原子的な手順の中で自分の時計と比べる。その時刻かそれより後なら、書き込みは適用せず、応答は `408` である。アダプターの書き込み寿命 W は、リクエストの期限に、プロバイダーと Store のあいだに想定する時計のずれを足したものである。プロバイダーと Store の時計は、そのずれの範囲で一致する。このアダプターはリクエストを送る直前に `deadlineMs` を取り、そのあとでタイマーを始めるので、期限はアダプターが諦める瞬間と同じかそれより前になる: 期限を過ぎた書き込みが、アダプターが待つのをやめたあとに適用されることは無い。`deadlineMs` が無いか、`Date` の範囲内の 0 より大きい整数の時刻でなければ `400`。
- **再試行しない。** アダプターは条件付き書き込みを決して再試行しない。期限で諦め、タイムアウトや想定外のステータスは結果を不明のままにする。Store も、その前段にあるものも、`421` は適用しなかったリクエストにだけ返す。HTTP クライアントがそれをもう一度送るかもしれないからである: Node の `fetch` は `421` を受けると `POST` をもう一度だけ送る。

**呼び出しが失敗したとき、Store が送ったものは何一つクライアントに届かない**: ステータスも、エラーの文面も、ヘッダーも、レコードも、レコードが読めなかったかどうかも。これらのエンドポイントの失敗はすべて、プロバイダーの障害の応答 `503 temporarily_unavailable` になる。何が起きたかは運用者のログ行と監査イベントにだけ届き、アダプターが投げる `MfaStoreError`（[`src/mfa/storeFailure.mts`](src/mfa/storeFailure.mts)）を通る。それは操作、エンドポイントのオリジンとパス、数値としてのステータス、そしてバージョンが飛んだときは主体と要素の ID — ログ行が切り詰めても両方が残るようにメッセージの先頭に置き、それぞれ core の `auditErrorText` を通して最大 64 文字 — から作られ、ボディやステータス文言やヘッダーからは決して作られない。ボディは読まずに解放され、HTTP 層が応答に使ったり表示したりする `status`・`statusCode`・`cause` を持たない。通信の失敗・期限・拒否された資格情報は、ユーザーリポジトリのエラーを投げる。`reason` は `unexpected_status`（表に無いステータス。`storeStatus` に入る）、`unknown_subject`（`markMfaEnrolledUrl` の `404`）、`malformed_answer`（表と違うボディの `2xx`、または結果のボディを持たない条件付き書き込みの `404` や `409`。`listVersioned` では、読めないレコードを含む一覧も）、`unreadable_record`（`list` での、読めないレコードを含む一覧。一つの欠陥に二つの理由がある: 同じ一覧で `listVersioned` は、core の変換が契約の外の応答として読むので `malformed_answer` を投げる）、`version_skipped`（`expectedVersion + 1` 以外のバージョン）。

読めるレコードの `id`・`kind`・`label` は、設計としてクライアントに届く: MFA ADR のページがそれを表示する（アカウントページの要素一覧 F4、最初の紐付けで登録できる種類 F3）。届くのは読み手が保つ形のものだけなので、Store がそこに書いたそれ以外のものは届かない。

**要素のエンドポイントの設定。** 四つのエンドポイントは、主体の要素を Store に保持するモジュールのセクション `foundation-mfa-factor-store`（モジュール名と同じ。[`src/mfa/section.mts`](src/mfa/section.mts)）にある。パッケージの [`config/reference.conf`](config/reference.conf)（`@o3co/auth-provider-foundation/reference.conf` として export）が、各キーをそのパスから名付けた変数に既定値なしで結ぶ: `listUrl` は `FOUNDATION_MFA_FACTOR_STORE_LIST_URL`、`createUrl` は `FOUNDATION_MFA_FACTOR_STORE_CREATE_URL`、`updateUrl` は `FOUNDATION_MFA_FACTOR_STORE_UPDATE_URL`、`deleteUrl` は `FOUNDATION_MFA_FACTOR_STORE_DELETE_URL`。セクションの知らないキーと、`https` でもループバックの `http` でもない URL は、設定の検証で起動を拒否し、キーを表示可能な文字だけで名指して値は引用しない。各 URL は必須である: セクションを読むモジュール `foundationMfaFactorStoreModule` はストアを eager に提供し（`foundationMfaFactorStoreLifecycle`）、先に `readFoundationMfaFactorStoreUrls` を呼ぶので、四つのどれかが未設定のままそれを入れた構成は、ストアを必要とするものがあってもなくても、欠けたキーとその変数をすべて名指して起動を拒否する。

`markMfaEnrolledUrl` はこのセクションに無い。証人は要素を何が保持していてもユーザーリポジトリを通して書かれる — Redis の要素と Store の証人の組み合わせもそこに含まれる — ので、その URL はユーザーリポジトリの設定のキー `repositories.user.http.markMfaEnrolledUrl`（`REPOSITORIES_USER_HTTP_MARK_MFA_ENROLLED_URL`、既定値なし）である。URL があれば、ユーザーリポジトリは証人を書く（`markMfaEnrolled`）。無ければ、リポジトリは `markMfaEnrolled` を持たない — その能力が無いだけで、起動の拒否にはならない。証人は省略可能だからである（MFA ADR の D12）。そして MFA が有効でユーザーリポジトリが証人を書けない構成には、要素を何が保持していても、起動時に警告が出る（`mfa_enrollment_witness_unwritable`）。失われた要素ストアが最初の紐付けを開かないようにするのが証人だからである。文字列でない値、`https` でもループバックの `http` でもない URL、`user:password@` を含む URL は、リポジトリを作るときに `markMfaEnrolledUrl` を名指し、値を引用せずに起動を拒否する。

### Store を使う要素ストア

[`HttpMfaFactorStore`](src/mfa/HttpMfaFactorStore.mts) は要素の四つのエンドポイントの上の `MfaFactorStore`（`kind` は `"store"`）で、[`foundationMfaFactorStoreModule`](src/mfa/module.mts) がそれを組み込む:

```typescript
import { foundationMfaFactorStoreModule } from "@o3co/auth-provider-foundation";

const modules = [
  // Store の通信設定: ユーザーリポジトリの HTTP 設定を、組み立て側がユーザーリポジトリのビルダーに渡すのと同じように渡す。
  foundationMfaFactorStoreModule({ storeTransport: config.repositories.user.http }),
  // ...MFA パッケージのモジュール、トランザクションストア
];
```

- モジュールは `mfaFactorStore` を、それを必要とするものがあってもなくても起動時に、先に読むセクションの四つの URL から作って提供する。
- 必須とするスロットは無く、自分のセクション以外の設定は読まない。
- `storeTransport` は必須である: Store の資格情報・期限・レスポンス上限はユーザーリポジトリのものなので、組み立て側がユーザーリポジトリの HTTP 設定（`repositories.user.http`）を渡す。その `bearerToken`・`timeout`・`maxResponseBytes` を `"http"` ビルダーと同じように（文字列は数値として）読むので、一つのトークンが Store のすべてのエンドポイントに送られる。`{}` は設定が無いことを示す: 資格情報は送らず、期限と上限は 5000 ms と 1 MiB。設定が渡されないとき、またはキーのセクションでないときは、資格情報を送らずに済ませるのではなく起動を拒否する。通信が拒否する設定 — [コンストラクタでの検証](#コンストラクタでの検証)の規則 — も、`HttpMfaFactorStore` を名指して起動を拒否する（`provides-factory-failed`）。
- レプリカで分岐する状態は宣言しない: 要素は Store のものである。

要素の集合の構成は `createIf`、`removeIf` とリセットで書く。ポートには[契約](#store-の-mfa-エンドポイント)が各応答に与える意味で答え、それ以外はすべて throw する:

| 操作 | Store の応答 | ポートが受け取るもの |
| --- | --- | --- |
| `list` | `200 { factors }` | すべてのレコードを丸ごと読んだもの。読めないレコード、別の主体のレコード、同じ ID の二つ目のレコードは `unreadable_record` を throw。 |
| `list` | 他のすべてのステータス（リダイレクトも） | `unexpected_status` を throw。決して「要素なし」ではない。 |
| `update` | `200 { factor }` | 名指したレコードで、送った変更を持ち、`expectedVersion + 1` であればそのレコード。そうでなければ `malformed_answer` か `version_skipped` を throw。その `kind`・`binding`・`createdAtMs` は Store の言うとおりである: ポートは比べる元のレコードをアダプターに渡さない。`kind` は封印に結び付いているので、別の種類として返されたデータは開かない。 |
| `update` | `409` または `404` / その他 | `null` / `unexpected_status` を throw。 |
| `removeAllForSubject` | `2xx` または `404` / その他 | 完了 / `unexpected_status` を throw。 |
| `listVersioned` | `200 { factors, generation }` | レコードと集合の世代を `readMfaStoreVersionedListAnswer` で丸ごと読んだもの。集合が無ければ `{ items: [], generation: null }`。変換が拒否する応答 — 世代を持つ前の Store が返すような `generation` の無いもの、形の外の世代、読めないレコード、別の主体のレコード、同じ ID の二つ目 — は `malformed_answer` を throw。 |
| `listVersioned` | 他のすべてのステータス | `unexpected_status` を throw。 |
| `createIf` | 結果のボディ付きの `200` / `409` | 集合の新しい世代付きの `created` / `conflict`。ボディが無いか、別のステータスの結果なら `malformed_answer` を throw。 |
| `createIf` | 他のすべてのステータス（`404`、遅れた書き込みの `408`、`expectedGeneration` を無視する Store の `204` も） | `unexpected_status` を throw。 |
| `removeIf` | 結果のボディ付きの `200` / `404` / `409` | 集合の新しい世代付きの `removed` / `missing` / `conflict`。ボディが無いか、別のステータスの結果なら `malformed_answer` を throw。 |
| `removeIf` | 他のすべてのステータス（遅れた書き込みの `408` も） | `unexpected_status` を throw。 |

集合のメンバーは先にステータスを読む: 操作に与えられていないステータスは `unexpected_status` を throw し、ボディは読まずに解放する。与えられたステータスのボディは一度だけ解析して core の変換だけで読み、変換が拒否したものは、変換の言葉を何も持たない `malformed_answer` を throw する。送ったあとで失敗した条件付き書き込み — 期限、切れた接続、`408`、拒否した応答 — は不明であり、決して `missing` や `conflict` ではない: コミットしたかもしれない。`expectedGeneration` を無視する Store は、その応答が拒否される前に囲いなしで書いたかもしれない。そうしないことを示せるのは、Store 自身の CI で走らせる契約スイートだけである。

リクエストの前に、ワイヤの変換が読み戻せないレコードや更新 — base64url の 22 文字でない ID、形の外のラベル、`Number.MAX_SAFE_INTEGER` での更新、世代でない期待する世代 — は `RangeError` になり、何も送らない。渡された `data` はそのまま送る: 封印したのは MFA パッケージで、ここでは開かない。

**要素は Store に任される。** アダプターは各応答を厳密に読むが、古いレコードと現在のもの、レコードの抜けた一覧と完全な一覧、削除されてから再び返された要素と一度も削除されていない要素を見分けられない: 要素の完全性と鮮度は Store の責任である（[Store が自分で守るべきこと](#store-が自分で守るべきこと)）。

### ユーザーリポジトリを通して書かれる証人

`markMfaEnrolledUrl` があれば、`HttpUserRepository.markMfaEnrolled(subject, enrolled)` はそこに `{ subject, enrolled }` を送る（[`src/mfa/markEnrolled.mts`](src/mfa/markEnrolled.mts)）。資格情報と期限はユーザーリポジトリのもの。ボディを読まないので、レスポンス上限は掛からない。`204` は完了。`404` は `MfaStoreError` の `unknown_subject` を、他のすべてのステータス — `200` やリダイレクトも — は `unexpected_status` を投げ、ボディは読まずに解放する。通信の失敗・期限・拒否された資格情報は、ユーザーリポジトリのエラーを投げる。空でない文字列でない主体や真偽値でない値は `RangeError` で、何も送らない。

MFA パッケージは、最初の数える要素を書いたあと — ログインでも、サインイン済みのセッションでも、最初の紐付けのあと — に主体を `true` と印付けし、ログインの `User` が登録済みと言わないところで数える要素が検証されるたびに — ステップアップも含め — もう一度印付けするので、失敗した印付けはその主体の次のそのような検証で書かれる。失敗した印付けは警告一行（`mfa_enrollment_witness_unwritten`）で、ログインは完了する。したがって、印付けを受け取るが `mfaEnrolled` を返さない Store は、数える要素の検証のたびに一度印付けされる。そのうえで証人は、失われた要素ストアが最初の紐付けを開くのを止める: `User` が登録済みと言い、数える要素が無いログインは `503`（`mfa.enrollment_state_inconsistent`）で、パスワードだけのログインにも最初の紐付けにもならない。

URL が無ければ何も書かれず、プロバイダーは Store が返す `mfaEnrolled` をそのまま読む。そのとき主体の要素一覧を欠けなく保つのは Store だけである: 主体のレコードを落とした Store は、`mfa.mode = "optional"` ではパスワードだけのログインを通し、`required` ではパスワードを持つ誰にでも最初の紐付けを開く。

**有効にするとき。** `REPOSITORIES_USER_HTTP_MARK_MFA_ENROLLED_URL` を設定する前に登録した主体は、次に数える要素を検証するまで証人を持たず、それまで失われた要素ストアはその主体を一度も登録していないものとして読む。URL を設定するときは、数える要素を持つすべての主体について、Store に `mfaEnrolled = true` を書き込んでおく（バックフィル）。

### 契約に対するテスト



[`@o3co/auth-provider-test-kit`](../test-kit/README.md) が、登録の証人の契約スイート、`MfaFactorStore` のスイート（`mfaFactorStoreContract`）、要素の集合のスイート（`mfaFactorStoreConditionalContract`）、そしてこれらのエンドポイントに表のとおり — 集合の世代と墓標も含め、指示すれば壊れた Store のように — 応答する偽の Store を持つ。このパッケージのテストは、要素ストアの二つのスイートを、同じ Store の上の二つ目のアダプターと競わせながら偽の Store の上の `HttpMfaFactorStore` に対して、証人のスイートを `markMfaEnrolledUrl` を持つ `HttpUserRepository` に対して、`authenticate` と `authenticateByToken` で証人を読み戻しながら走らせる。セクションのテスト用ビルダー `foundationMfaFactorStoreConfig` は `@o3co/auth-provider-foundation/testing` にある。

## Store が自分で守るべきこと

- **誰が呼べるか。** `authenticateByToken` と紐付けが運ぶものは秘密ではない — フェデレーションのコールバックの `<provider>:<sub>` は識別子である — ので、誰にでも応答する Store では、`authenticateByTokenUrl` に届く者は誰でも既知の ID をそのユーザーに解決でき、開いた `linkFederatedIdentityUrl` に届く者は誰でも任意の ID を任意の `userId` に結びつけられる。MFA のエンドポイントも同じである: 開いた `deleteUrl` や `markMfaEnrolledUrl` に届く者は誰でも主体の要素を消し、証人を外せ、その主体の次のパスワードログインは、パスワードを持つ誰にでも最初の紐付けを開く。`bearerToken`（`REPOSITORIES_USER_HTTP_BEARER_TOKEN`、`openssl rand -hex 32` で生成）を設定し、Store は auth.provider に提供するすべてのエンドポイント — ユーザーリポジトリの四つも MFA のエンドポイントも — で、`Authorization` が `Bearer <そのトークン>` と正確に一致しない（定数時間で比較する）リクエストを拒否し、そのヘッダーをログに出さない。一つのトークンがそれらの URL すべてに送られるので、それらは一つの信頼境界でなければならない: どれか一つのエンドポイントを運用する者は、他のエンドポイントも受け付ける資格情報を持つことになる。拒否は `401` と `WWW-Authenticate: Bearer error="invalid_token"`（RFC 6750 §3）で返す — 有効だが足りないトークンなら `403` と `error="insufficient_scope"` で。このチャレンジがあれば、Store が受け付けないトークン — 打ち間違い、途中で止まったローテーション — はすべての呼び出しで障害になり、各呼び出し元はそれを下の表のとおり報告する。チャレンジが無ければ `401` や `403` はワイヤ上の意味 — 「ユーザーが居ない」またはリンクの拒否 — を保ち、不一致はすべてのログインの失敗としてしか現れない。同じ理由で、ユーザーのパスワード誤り、未知の ID、ポリシーが拒否するリンクに `Bearer` チャレンジを付けてはならない: その応答は Store が auth.provider を拒否したと読まれ、そのユーザーのログインやリンクの失敗が障害になる。ローテーションは、Store に古いトークンと新しいトークンの両方を受け付けさせ、auth.provider を新しいものに移し、それから古いものを廃止する。`bearerToken` が無ければどのリクエストも `Authorization` ヘッダーを持たないので、Store は別の方法で auth.provider だけを受け入れる: ネットワークポリシーやプライベートネットワーク、または Store の前段でプラットフォームが提供する相互 TLS（ループバックアドレス上のサイドカー。`http` の例外が受け付ける）で。このアダプター自身はクライアント証明書を提供しない: Node の `fetch` がそれを受け取るのは `undici` のディスパッチャー経由だけで、このパッケージはその依存を持たない。`user:password@` を含む URL は拒否される。
- **URL に秘密を入れない。** クエリ文字列のトークンは秘密のままではいられない: すべてのリクエスト行に載り、Store 自身のアクセスログにも途中のプロキシにも届く。このアダプターが投げるエラー（セッションルートがログに出す）はエンドポイントをオリジンとパスだけで示し、クエリやフラグメントは決して示さないので、少なくともこのデプロイのログにはクエリは届かない。呼び出し元の資格情報は `bearerToken` に置く。このアダプターが投げるものはどれもそれを含まない。
- **リダイレクトせずに応答する。** どのリクエストもリダイレクトを追わないので、パスワード、トークン、リンクのリクエスト、ID は設定された URL — 下の `https` の規則が検査する URL — にだけ届き、それ以外のどこからの応答もユーザー、リンク、照会の答えとして受け取られない。どのエンドポイントからの `3xx` も、他の想定外のステータスと同じく例外になる（セッションルートと jwt-bearer グラントは `503 temporarily_unavailable`、grants のコールバックは `temporarily_unavailable` を返す）ので、リダイレクトする URL — 正規のホストへリダイレクトするホストの別名、末尾スラッシュの付加、パスの移動 — の背後にある Store はすべての呼び出しで失敗する。各 URL には、リダイレクトするエンドポイントではなく応答するエンドポイントを設定する。
- **MFA の要素を欠けなく新しく保つ。** MFA の要素を保持する Store は、その完全性と鮮度に責任を持つ: 要素を巻き戻さず、一覧から隠さず、削除を認めたものを返さず、同じバージョンへの二つの更新を両方とも成功させない。バージョンは決して戻らず、認めた書き込みは復元やフェイルオーバーを挟んでも失われず、一覧はキャッシュや遅れたレプリカのものでなく最新の書き込みを返す。それが破られてもプロバイダーには分からない: 古いレコードの封印されたデータは当時のとおりに開く — 封印が結び付けるのは主体・要素 ID・種類で、バージョンではない — ので、使用済みの TOTP のステップが窓の中で再び受け付けられ、使用済みのリカバリーコードが再び使え、削除した要素が戻る。主体のレコードを落とした Store は、`mfa.mode = "optional"` ではパスワードだけのログインを通し、`required` ではパスワードを持つ誰にでも最初の紐付けを開く。それを止めるのは要素ストアの外に保つ登録の証人である（MFA ADR の D12）。MFA ADR の O6 は、要素を Redis に、証人を Store に置くことを勧める。両方を一つの Store に置くとこの守りは失われる: 一方を落としたり巻き戻したりするものは、もう一方にも同じことができるからである。フェイルオーバーと復元の手順は運用ランブックの「Keeping MFA factors in the Store」にある。

**拒否されたトークンが呼び出し元ごとにどう見えるか。** どの呼び出し元も `StoreCredentialRefusedError` を他の Store の障害 — `StoreTransportError` や `TimeoutError` も — と同じく扱い、違うのはログに出すものである:

| 呼び出し元 | 返すもの | ログ |
| --- | --- | --- |
| パスワードログイン、`POST /session/login`（[`@o3co/auth-provider-session`](../session/README.ja.md)） | `503 temporarily_unavailable` | `login_store_unavailable`（error、`store: "user_repository"`、`err` 付き） |
| フェデレーションのログインと `?link=1` のコールバック（session） | `503 temporarily_unavailable` | `federation_callback_store_unavailable` または `federation_link_store_unavailable`（error、`store: "user_repository"`、`err` 付き） |
| jwt-bearer グラント（[`@o3co/auth-provider-oauth`](../oauth/README.ja.md)） | `503 temporarily_unavailable` | `jwt_bearer_user_repository_unavailable`（error、`err` 付き） |
| federation-grants の接続コールバック — ID の照会（[`@o3co/auth-provider-federation-grants`](../federation-grants/README.md)） | `error=temporarily_unavailable` 付きのリダイレクト | `federation_grant_callback_unavailable`（error、`store: "user_directory"`、`err` 付き） |

`err` がログに出る場合、`StoreCredentialRefusedError` のメッセージは Store のエンドポイント（オリジンとパス）、ステータス、`REPOSITORIES_USER_HTTP_BEARER_TOKEN` を示し、トークンは決して示さない。`StoreTransportError` のメッセージは同じくエンドポイント、何が失敗したか、せいぜい通信のコードを示す。このアダプターが投げるどのメッセージも URL のクエリ文字列やフラグメントを引用しない。

## コンストラクタでの検証

すべてのオプションは **コンストラクタ** で検証されるので、設定を誤ったデプロイは最初のログイン試行ではなく起動時に失敗する。`HttpMfaFactorStore` も四つの URL・`timeout`・`maxResponseBytes`・`bearerToken` を以下の同じ規則で検証し、拒否は `HttpMfaFactorStore` を名指す。

**すべての URL は `https://` でなければならない**（リンク・照会・証人のエンドポイントも含む）。これらは平文のユーザー資格情報 — `authenticateUrl` にはパスワード、`authenticateByTokenUrl` にはトークン、`findSubjectByFederatedIdentityUrl` には検証済みの上流 ID — を運ぶので、`http://` の URL は接続を弱めるだけでなく、経路上のすべてのホップに資格情報を公開する。ここで検査される URL がリクエストの唯一の行き先であり、応答を受け取る唯一の相手である: どのリクエストもリダイレクトを追わないので、`307` や `308` がこの規則の見ていない `Location` へボディを送り直すことも、`301`・`302`・`303` がそこから応答を取ってくることもない。

**唯一の例外はループバック:** ホストが `localhost`、`127.0.0.0/8` 内のアドレス、`[::1]` のいずれかなら `http://` を受け付ける。その通信はマシンの外に出ないので、ローカル開発とプロセス内のテストフィクスチャに証明書は要らない。それ以外のホストは **プライベートレンジのアドレスやコンテナネットワークのサービス名も含めて** `https://` が必須（`http://10.0.0.5/…`、`http://user-service/…` は拒否される）: それらはデプロイが端から端まで制御していないネットワークを越えるものであり、「内部」は「暗号化済み」の同義語ではない。資格情報を埋め込んだ URL（`https://user:pass@…`）も拒否する。

これは [`@o3co/auth-provider-core`](../core/README.ja.md) の `oauth.jwt.issuer` が適用するのと同じ規則で、例外を単一アドレス `127.0.0.1` から `127.0.0.0/8` ブロック全体に広げ、クエリ文字列を許している（issuer は持てないが、POST のエンドポイントは正当に持ちうる）。クエリは送られるが引用はされない: どのエラーもエンドポイントをオリジンとパスで示す。

**`timeout` は `2147483647` ミリ秒以下の正の整数でなければならない。** `0`・負数・`NaN` は `setTimeout` ではいずれも「即時発火」に丸められ — すべてのリクエストが中断される — 、Node のタイマー範囲を超える値は 1ms に丸められるので、「気長に待つ」つもりの設定が最もせっかちな設定になる。空の環境変数による上書きはデフォルトにはならず起動失敗になる。期限は **ボディの読み取りを含む** やり取り全体に掛かる: ボディの読み取りは abort signal に頼らず期限と競わせる。リクエストの中断は進行中の読み取りを確実には止めないからである。これは slow-loris の形 — ヘッダーはすぐ届き、ボディが少しずつ届くか止まる — で、競わせなければ永久にハングする。期限を超えたリクエストは、エンドポイントを示す `timed out after <n>ms` のエラーで reject される。そのエラーの名前はどのリクエストでも `TimeoutError` なので、名前で分類するレポーターはそれをタイムアウトと読む。

**`maxResponseBytes` は正の整数でなければならず**、デフォルトは `DEFAULT_MAX_RESPONSE_BYTES`（1 MiB）。上限は `Content-Length` に対しても、ストリーム読み取り中にも適用されるので、ヘッダーを省く — あるいは偽る — Store も、メモリを使い果たす前に打ち切られる。

**`bearerToken` は、設定するなら 32 バイト以上の鍵素材を持つ素の RFC 6750 トークンでなければならない。** 未設定（キーが無い）なら `Authorization` ヘッダーは送らない。設定した場合は、文字列であること、空でないこと（空の環境変数による上書きは「トークン無し」ではなく起動失敗）、英字・数字・`-._~+/` と末尾の `=` パディングだけから成ること — 空白も改行も、アダプターが付ける `Bearer ` の接頭辞も含まない — 、そして core の共有シークレットの下限（`MIN_SECRET_ENTROPY_BYTES`。`SESSION_STORE_SECRET` と `KEY_STORE_LOCAL_SECRET` が満たすのと同じもの）を満たすことが求められ、どれかを欠けば拒否される。hex や base64 の値はデコード後の長さで測るので、`openssl rand -hex 16` は見た目の長さに関わらず 16 バイトである。このトークンを持つ者は auth.provider として Store と話せる。形をここで検査するのは、`fetch` が拒否するヘッダー値は、`fetch` が投げるエラーの中にそのまま引用されるからである。どの拒否も値を引用せず、リクエストのどのエラーも値を含まず — 通信の失敗は通信自身のエラーを付けずに投げられる（ワイヤ契約を参照） — 、値は ECMAScript の private フィールドに保持されるので、リポジトリの `inspect()` や `JSON.stringify` にも現れない。これらの検査はリポジトリが組み立てられるときに行われ、デプロイがそうするのは `adapters.userRepository = "http"`（standalone テンプレートのデフォルト）のときである。core の `reference.conf` のデフォルトである `yaml` では、`http` ブロック — とその中のトークン — はまったく読まれない。

## パブリック API

[`src/index.mts`](src/index.mts) から export される:

- `registerBuiltinAdapters({ userFactory })` — `"http"` 型を登録する。
- `HttpUserRepository` — リポジトリ（[`src/repositories/HttpUserRepository.mts`](src/repositories/HttpUserRepository.mts)）。
- `StoreCredentialRefusedError` — 資格情報が拒否されたときに投げられるもの。`name` と `storeStatus`（`401` または `403`）は契約の一部。`status` ではない: Express、http-errors、standalone の終端ハンドラーはそれを応答するステータスとして読む。
- `StoreTransportError`、`StoreTransportFailure` — 通信の失敗で投げられるもの。`name`、`reason`、`code` は契約の一部で、こちらも `status` を持たない（[`src/repositories/storeErrors.mts`](src/repositories/storeErrors.mts)）。
- `DEFAULT_MAX_RESPONSE_BYTES` — レスポンス上限のデフォルト。
- `FederatedIdentityLookupCoverage` — カバレッジのエントリー一つの型。
- `HttpMfaFactorStore`・`HttpMfaFactorStoreOptions` — Store を使う `MfaFactorStore`（[`src/mfa/HttpMfaFactorStore.mts`](src/mfa/HttpMfaFactorStore.mts)）。
- `foundationMfaFactorStoreModule`・`FoundationMfaFactorStoreModuleOptions` — そのモジュール（[`src/mfa/module.mts`](src/mfa/module.mts)）。
- `MfaStoreError`・`MfaStoreFailure`・`MfaStoreOperation` — MFA エンドポイントの失敗が投げるもの。`name`・`reason`・`operation`・`storeStatus` は契約の一部で、`status` は持たない（[`src/mfa/storeFailure.mts`](src/mfa/storeFailure.mts)）。アダプターが投げるときに通す関数と、`foundation-mfa-factor-store` セクションのスキーマと読み取り（[`src/mfa/section.mts`](src/mfa/section.mts)）はパッケージ内部のもの。

[`src/testing/index.mts`](src/testing/index.mts) から `@o3co/auth-provider-foundation/testing` として、テストコードのためだけに export される: `foundationMfaFactorStoreConfig(urls, extra?)` — テストの設定に重ねる設定の断片としての `foundation-mfa-factor-store` セクション。`urls` が持つ四つの URL（偽の Store の `urls` も。その他のエンドポイントは残す）と、`extra` をそのまま持つ。そして `foundationUserRepositoryHttpConfig(urls, extra?)` — ユーザーリポジトリの `http` ブロック。`urls` が持つもののうち `"http"` ビルダーが読む Store の URL（MFA 要素のエンドポイントは残す）と、`extra` をそのまま持ち、テストが `"http"` ビルダーに、または `foundationMfaFactorStoreModule` に `storeTransport` として渡す。

## テスト

| テストファイル | 固定するもの |
| --- | --- |
| [`HttpUserRepository.test.mts`](src/repositories/__tests__/HttpUserRepository.test.mts) | 認証とその応答、Store が返したとおりに渡される `mfaEnrolled`、`User` の形の検査、https の規則、タイムアウトとレスポンス上限、リンク、ID の照会の有無・probe・ワイヤ |
| [`HttpUserRepository.transport.test.mts`](src/repositories/__tests__/HttpUserRepository.transport.test.mts) | 実際の HTTP サーバーに対して: ID の照会が拒否した応答の接続を解放すること、四つのリクエストそれぞれでリダイレクト — 別のオリジンへ、同じオリジンへ、`Location` 無し — が拒否され、リダイレクト先に何も送られないこと |
| [`HttpUserRepository.credential.test.mts`](src/repositories/__tests__/HttpUserRepository.credential.test.mts) | 実際の HTTP サーバーに対して: `bearerToken` があれば四つのリクエストそれぞれに `Authorization: Bearer <token>` が付き、無ければ `Authorization` ヘッダーが付かないこと（直接構築でも `"http"` ビルダー経由でも）、弱い・形の誤った・空の・文字列でないトークンが構築時に拒否されること、どの失敗にもリポジトリのどの検査にもトークンが現れないこと、通信の失敗が何が失敗したかを示す `StoreTransportError` になること — 接続の拒否と平文の HTTP のポートを指す https の URL（届かない）、トークンを反射したステータス行やヘッダー、サイズ上限を超えるヘッド（壊れた応答）、`1xx` の後・ヘッドの途中・1 バイト目の前の切断や、二つのリクエストの間に閉じられたプール済みの keep-alive 接続（接続が閉じられた）、chunked ボディ（読めない）、クライアントのハンドシェイクを拒否する TLS 1.2 サーバー（届かない、`ERR_SSL_SSL/TLS_ALERT_HANDSHAKE_FAILURE`） — コード付き、cause 無しで、タイムアウトはヘッダーとボディのどちらが止まっても `TimeoutError` になること、トークンを送ったときの `Bearer` チャレンジ付き `401` または `403` が四つそれぞれで `StoreCredentialRefusedError`（`storeStatus`、`status` 無し）になり、チャレンジの無いもの — またはトークンを送っていないとき — は従来どおり読まれること |
| [`storeErrors.test.mts`](src/repositories/__tests__/storeErrors.test.mts) | どの通信のコードが残るか、二つの名前付きエラーの形 — `status` も cause も無い |
| [`wwwAuthenticate.test.mts`](src/repositories/__tests__/wwwAuthenticate.test.mts) | どの `WWW-Authenticate` の値が `Bearer` チャレンジを持つか、敵対的な 64 KiB の値を一度の走査で読むこと |
| [`registerBuiltinAdapters.test.mts`](src/repositories/__tests__/registerBuiltinAdapters.test.mts) | `"http"` のビルダー、そのデフォルトと文字列の変換、渡す任意の URL、組み立て時に拒否される設定 |
| [`endpointUrl.test.mts`](src/__tests__/endpointUrl.test.mts) | https またはループバックの規則 |
| [`storeFailure.test.mts`](src/mfa/__tests__/storeFailure.test.mts) | MFA エンドポイントの失敗が投げるもの: Store の書いたものがエラーのどの形にも届かないこと、ボディを読まずに解放すること、応答に使うステータスを持たないこと。飛んだバージョンのログ行が、どれほど長くても主体と要素 ID を無害化し上限をつけて名指すこと |
| [`section.test.mts`](src/mfa/__tests__/section.test.mts) | `foundation-mfa-factor-store` セクション: スキーマ、読み取り、パッケージのモジュールで `createApp` を通した欠落・不正・未知のキーでの起動拒否（モジュールだけを入れた構成も） |
| [`module.test.mts`](src/mfa/__tests__/module.test.mts) | `createApp` を通した `foundationMfaFactorStoreModule`: 他に何も入れずにセクションの URL の上に Store を使うストアを提供すること。Store の通信設定が必須であること、そこから読むユーザーリポジトリのベアラートークン・期限・上限（文字列は数値として読む）、設定が無いかキーのセクションでないとき、およびユーザーリポジトリも拒否する値のときの起動拒否 |
| [`HttpMfaFactorStore.contract.test.mts`](src/mfa/__tests__/HttpMfaFactorStore.contract.test.mts) | テストキットの `MfaFactorStore` スイートと要素の集合の条件付き書き込みのスイートを、偽の Store の上の `HttpMfaFactorStore` に対して、同じ Store の上の二つ目のアダプター、Store が閉じたアダプター、書き込み寿命の上限を越えて進めた Store の墓標の時計とともに走らせる |
| [`HttpMfaFactorStore.test.mts`](src/mfa/__tests__/HttpMfaFactorStore.test.mts) | 送るもの — 設定どおりの各 URL、ベアラートークン、バイト単位でそのままの封印されたデータと、その封印元を何も送らないこと、変換が拒否するものを送らないこと。各操作の応答と、契約を破る Store: `404`、`5xx`、リダイレクト、壊れた応答、読めないレコード、別の主体、重複した ID、飛んだバージョン、変更を書かなかった応答。集合のメンバー: 送るもの、結果のボディ付きの各ステータス、ボディの無い `404` や `409` は壊れた応答、他のステータスは想定外、世代の無い一覧は壊れた応答、期限で諦める条件付き書き込み、送った時刻に期限を足した `deadlineMs`、`408` で拒否され適用されない遅れた書き込み、期限内に適用される書き込み。Store が送ったものが投げるものに何も現れないこと。拒否された資格情報（このストアを名指す）、ヘッドまたはボディでの期限切れ、上限、届かない Store。構築、無条件の `create` も `remove` も持たないこと、ストアを検査したときにトークンもエンドポイントも見えないこと |
| [`foundationMfaFactorStoreConfig.test.mts`](src/testing/__tests__/foundationMfaFactorStoreConfig.test.mts) | testing 入口のセクションのビルダー |
| [`foundationUserRepositoryHttpConfig.test.mts`](src/testing/__tests__/foundationUserRepositoryHttpConfig.test.mts) | testing 入口のユーザーリポジトリの `http` ブロックのビルダーと、`"http"` ビルダーがそれを受け取ること |
| [`storeRequestMessages.test.mts`](src/mfa/__tests__/storeRequestMessages.test.mts) | MFA エンドポイントでの通信の失敗が、どのクライアントから送っても同じ文言になること |
| [`referenceConf.test.mts`](src/mfa/__tests__/referenceConf.test.mts) | パッケージの `reference.conf`: そのセクションだけを持ち、各 URL がそのパスから名付けた変数に既定値なしで結ばれること |
| [`enrollmentWitness.contract.test.mts`](src/mfa/__tests__/enrollmentWitness.contract.test.mts) | テストキットの証人スイートを偽の Store の上の `HttpUserRepository` に対して走らせ、`markMfaEnrolled` で書き、`authenticate` と `authenticateByToken` で読み戻す。能力は `markMfaEnrolledUrl` があるときだけ |
| [`markEnrolled.test.mts`](src/mfa/__tests__/markEnrolled.test.mts) | `markMfaEnrolled`: 送るもの — 設定どおりの URL、`{ subject, enrolled }`、bearer トークン、形の外の主体や値には何も送らない。`204` は完了、`404` は `unknown_subject`、他のステータスは `unexpected_status` で `Location` には接続しない。拒否された資格情報、期限、届かない Store。投げるものに Store が送ったもの・クエリ・主体が現れないこと。URL に課す https の規則 |

## 関連

- [`@o3co/auth-provider-core`](../core/README.ja.md) — `UserRepository` ポート、`createRepositoryFactories`、開発用ユーザーアダプター、MFA のポートと MFA エンドポイントのワイヤ形式
- [`@o3co/auth-provider-test-kit`](../test-kit/README.md) — 登録の証人と要素ストアの契約スイート、偽の Store
- [`@o3co/auth-provider-session`](../session/README.ja.md) — `authenticate`・`authenticateByToken`・`linkFederatedIdentity` を呼ぶルート
- [`@o3co/auth-provider-federation-grants`](../federation-grants/README.md) — ID の照会の呼び出し元
- [auth.provider](../../README.ja.md) — リポジトリ全体のドキュメント
