# @o3co/auth-provider-foundation

最終更新: 2026-09-25

auth.provider のための「the Store」 — デプロイ自身のユーザーサービス — の HTTP クライアント。`HttpUserRepository` は core の `UserRepository` ポートを HTTPS で実装する: ユーザーを認証し、フェデレーション ID をリンクし、federation grants が求める ID の照会に答える。`registerBuiltinAdapters` はそれを `"http"` ユーザーアダプターとして登録する。

## 責務と役割

**役割。** core のポート一つ、[`UserRepository`](../core/src/repositories/UserRepository.mts)（[`core/src/repositories`](../core/src/repositories/README.md) を参照）のアダプター。パッケージ名に反して基盤層ではない: 実行時にこれを import する他のパッケージは無い（`federation-grants` がテストで使うだけ）。これを選ぶのは組み立て側 — standalone テンプレートでは `repositories.user.type = "http"`。

**持つもの:**

- Store が実装するワイヤ契約: `HttpUserRepository` が送るリクエストと、それぞれの応答の意味（後述）。
- Store の URL に対する通信の規則 — `https`、またはループバックホストへの `http` だけ（[`src/endpointUrl.mts`](src/endpointUrl.mts)） — と、どのリクエストもそこからリダイレクトで離れないこと。
- Store に提示する資格情報（`bearerToken`）、その資格情報に課す下限、そして Store によるその拒否の読み方。
- 通信が報告するもの — リクエストを引用しうる — を何も投げないこと。
- リクエストの期限とレスポンスサイズの上限。
- ID の照会が起動時に判定される根拠となるカバレッジ宣言。

**持たないもの:** ポートと `User` の形（core）。ユーザーをいつ認証し、ID をいつリンクし、所有者をいつ照会するか — セッションルート（[`@o3co/auth-provider-session`](../session/README.ja.md)）、`oauth` の jwt-bearer グラント（[`@o3co/auth-provider-oauth`](../oauth/README.ja.md)）、federation grants（[`@o3co/auth-provider-federation-grants`](../federation-grants/README.md)）。Store 自体。core の開発用ユーザーアダプター（`yaml` / `static`）。Redis バックエンドのストア（[`@o3co/auth-provider-redis`](../redis/README.md)。Redis の認可コードストアもこちら）。

**別パッケージである理由。** core が同梱するのはファイルから読む開発用のユーザーアダプターだけで、本番のデプロイはユーザーを自前のサービスに持ち、これはそのためのクライアントである。差し替え可能な部品 — 独自の `UserRepository` 実装を持つデプロイはこれをインストールしない — であり、core 以外の何にも依存しない（グローバルの `fetch` のみで、他の依存は無い）。

## インストール

```sh
npm install @o3co/auth-provider-foundation @o3co/auth-provider-core
```

peer dependency: `@o3co/auth-provider-core`。このパッケージ自身の dependencies は無い。

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

`repositories.user`（`type = "http"`、`CLIENT_USER_TYPE`）の `http` ブロックの下。デフォルト値は [`reference.conf`](../core/config/reference.conf) にある:

| キー | 環境変数 | |
| --- | --- | --- |
| `authenticateUrl` | `CLIENT_USER_AUTHENTICATE_URL` | 必須。パスワードログイン。 |
| `authenticateByTokenUrl` | `CLIENT_USER_AUTHENTICATE_BY_TOKEN_URL` | 必須。不透明なハンドルを解決する: フェデレーションログイン、jwt-bearer グラント。 |
| `linkFederatedIdentityUrl` | `CLIENT_USER_LINK_FEDERATED_IDENTITY_URL` | 任意。アカウントリンクを有効にする。 |
| `findSubjectByFederatedIdentityUrl` | `CLIENT_USER_FIND_SUBJECT_BY_FEDERATED_IDENTITY_URL` | 任意。ID の照会。 |
| `federatedIdentityLookupCoverage` | —（リストなので HOCON のみ） | 照会がカバーする範囲。デフォルト `[]`。 |
| `bearerToken` | `CLIENT_USER_BEARER_TOKEN` | 任意。すべてのリクエストで `Authorization: Bearer <token>` として送る。32 バイト以上の鍵素材。未設定なら `Authorization` ヘッダーは送らない。[Store を誰が呼べるか](#store-が自分で守るべきこと) を参照。 |
| `timeout` | `CLIENT_USER_TIMEOUT` | ミリ秒。デフォルト 5000。 |
| `maxResponseBytes` | `CLIENT_USER_MAX_RESPONSE_BYTES` | デフォルト 1048576。 |

## ワイヤ契約

リクエストはすべて JSON ボディの `POST` で、`bearerToken` が設定されていれば `Authorization: Bearer <token>` ヘッダーを持つ。Store が返すユーザーは core の [`User`](../core/src/repositories/types.mts)。

**`authenticate`** は `authenticateUrl` に `{ email, password }` を送る（ユーザー名は `email` として届く）。**`authenticateByToken`** は `authenticateByTokenUrl` に `{ token }` を送る。`token` は Store がユーザーに解決する不透明なハンドル — フェデレーションのコールバックからは `<provider>:<sub>`、`oauth` の jwt-bearer グラントからは検証済みアサーションの subject ハンドル。どちらも:

- ボディが JSON の `User`（`{ id: string, username: string, … }`）である `2xx` はそのユーザー。
- `401` または `403` は `null` — ユーザーが居ない、または資格情報が誤り。
- `User` でないボディの `2xx` は例外 — 「ユーザーが見つからない」ではなく上流の障害。
- それ以外のステータスは例外。

`2xx` 以外の応答のボディは、これらでもリンクでも読まずに捨てる。ID の照会を含め、どのリクエストもリダイレクトを追わない: `3xx` は例外になるステータスの一つにすぎず、その `Location` には一切接続しない。

**`Bearer` チャレンジ付きの `401` または `403` は資格情報の拒否である。** `bearerToken` が設定されているとき、四つのエンドポイントのどれかから `WWW-Authenticate: Bearer …`（RFC 6750 §3 — `invalid_token`、`insufficient_scope`）を持つ `401` または `403` が返ると、この節がそのステータスに与える読み — 「ユーザーが居ない」、リンクの拒否、照会の `answered HTTP <status>` — のどれでもなく、`StoreCredentialRefusedError`（`HttpUserRepository: the Store at <url> refused this deployment's credential (HTTP <status> with a Bearer challenge) — …`）が投げられる。各呼び出し元がそのとき何を返し何をログに出すかは [Store が自分で守るべきこと](#store-が自分で守るべきこと) にある。チャレンジは大文字小文字を問わず、他のチャレンジと並んでいても、独立したヘッダー行にあっても見つけ、引用符付き文字列の中にあるものは決して数えない。閉じられていない引用符付き文字列は値の末尾まで続き、その後ろにあるものを隠す — そのときはチャレンジが無いものとして読まれる。Store がスキームの後に書いたものは何も繰り返さない。`Bearer` チャレンジの無い `401` や `403`、およびトークンが設定されていないときのあらゆる `401` や `403` は、この節が与える意味を保つので、トークンを検査しない Store には影響しない。

**通信の失敗はやり取りの何も運ばない。** リクエストができない、または応答を読めないとき、エラーは `StoreTransportError` で、その `reason` とメッセージがどれかを示す:

| `reason` | いつ | メッセージ（照会では `identity lookup at <url> …`） |
| --- | --- | --- |
| `unreachable` | やり取りする接続が無い: 接続の拒否、DNS、TLS、ネットワークが届かない経路やホスト — ネットワークの経路か TLS | `HttpUserRepository: request to <url> could not be reached` |
| `connection_closed` | 完全な応答が届く前に接続が閉じられた、またはリセットされた: 1 バイト目の前、暫定の `1xx` の後、ヘッドの途中、または二つのリクエストの間に Store・プロキシ・アイドルタイムアウトが閉じたプール済みの keep-alive 接続 — 通信からはどれかを区別できない | `HttpUserRepository: the connection to <url> closed before a complete response arrived`（照会では `identity lookup at <url>: the connection closed …`） |
| `malformed_response` | Store が通信の受け取れない応答ヘッドを送った: パーサーがステータス行かヘッダーを拒否した、またはヘッドがサイズ上限を超えた — Store の、またはプロキシの応答 | `HttpUserRepository: the Store at <url> answered with a malformed HTTP response` |
| `unreadable` | HTTP の応答のボディが読み取りの途中で壊れた | `HttpUserRepository: response from <url> could not be read` |

どれも運ぶのはせいぜいオペレーターが対処できる通信のコード（メッセージの中と `code` として）だけ: `ECONNREFUSED`、`ENOTFOUND`、`ECONNRESET`、`EPROTO`、`UND_ERR_*`（`UND_ERR_HEADERS_OVERFLOW`、`UND_ERR_SOCKET` など）、ランタイムが設定する場合の `HPE_*`（Node 26 の undici はパーサーのエラーにコードを設定しない）、`ERR_SSL_*`（`ERR_SSL_WRONG_VERSION_NUMBER` は平文の HTTP を話すポートを指す https の URL、`ERR_SSL_SSL/TLS_ALERT_HANDSHAKE_FAILURE` は Store が拒否した TLS 1.2 のハンドシェイク — クライアント証明書を求める相互 TLS、または共通の暗号スイートが無い）、証明書のコード。通信自身のエラーや `cause` は決して運ばない: undici のパーサーのエラーは拒否したバイト列をそのまま引用し、リクエストを反射する相手 — 壊れたプロキシ、デバッグ用のエコー — はその中に `Authorization` ヘッダーやパスワードを置く。期限を超えたリクエストはこれではなく `TimeoutError` になる（コンストラクタでの検証を参照）。

**`linkFederatedIdentity`** は `linkFederatedIdentityUrl` に `{ userId, provider, sub, token, claims }` を送る: `2xx` の `User` は `{ ok: true, user }`、`401` / `403` は `{ ok: false, reason: "refused" }`、`409` は `{ ok: false, reason: "conflict" }`、それ以外は例外。拒否のボディは読まれないので、拒否が Store からの説明を運ぶことはない。`linkFederatedIdentityUrl` が設定されていなければこのメソッドは存在せず、フェデレーションのルートはそれで `?link=1` を最初から拒否すると分かる。`2xx` を返す前に Store が検査すべきこと — 未検証やリレーのアドレスでは決してリンクしない、メールアドレスだけで決してリンクしない — は [セッションパッケージの README](../session/README.ja.md#フェデレーション間のアカウントリンク482) にある。

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

**カバレッジ。** grants モジュールが起動時に尋ねる probe は同期的で Store に届かないので、`federatedIdentityLookupCoverage` が Store の照会のカバー範囲を中継する: 登録ごとに一つのエントリー `{ provider, issuer, clientId, requiredClaims }` で、四つのフィールドすべてを完全一致で比較し（トリムなし、大文字小文字の畳み込みなし、末尾スラッシュの許容なし）、`requiredClaims` は戦略が必要とするクレーム名 — 登録と `sub` だけで足りる戦略なら `[]`。`supportsFederatedIdentityLookup(registration, identityClaims)` は、登録と一致するエントリーがあり、その `requiredClaims` のすべてが `identityClaims` に含まれるとき `true`。federation grants が有効で connection が一つ以上あり、`federationGrants.identityLookup` が `"required"`（デフォルト）のとき、grants モジュールはこれが `false` になる connection をすべて起動時に拒否する。`"unsupported"` のとき、または connection が無いときは何も求めない。誰も宣言していない登録はローカルで `registration_not_covered` と答え、宣言済みの登録で必要なクレームが欠けていれば `identity_not_resolvable` と答え、どちらもリクエストは送らない。宣言は構築時にスナップショットされ、重複した登録、不正なエントリー、URL の無いカバレッジは構築エラーになる。`federationGrants.connections` と同じく環境変数の形は無い（リストは HOCON のもの）。`findSubjectByFederatedIdentityUrl` が設定されていなければ `supportsFederatedIdentityLookup` と `findSubjectByFederatedIdentity` は存在せず、そのうえで `"required"` の下に connection を持つデプロイは起動時に拒否される。

## Store が自分で守るべきこと

- **誰が呼べるか。** `authenticateByToken` と紐付けが運ぶものは秘密ではない — フェデレーションのコールバックの `<provider>:<sub>` は識別子である — ので、誰にでも応答する Store では、`authenticateByTokenUrl` に届く者は誰でも既知の ID をそのユーザーに解決でき、開いた `linkFederatedIdentityUrl` に届く者は誰でも任意の ID を任意の `userId` に結びつけられる。`bearerToken`（`CLIENT_USER_BEARER_TOKEN`、`openssl rand -hex 32` で生成）を設定し、Store は四つのエンドポイントすべてで、`Authorization` が `Bearer <そのトークン>` と正確に一致しない（定数時間で比較する）リクエストを拒否し、そのヘッダーをログに出さない。一つのトークンが四つの URL すべてに送られるので、それらは一つの信頼境界でなければならない: どれか一つのエンドポイントを運用する者は、他のエンドポイントも受け付ける資格情報を持つことになる。拒否は `401` と `WWW-Authenticate: Bearer error="invalid_token"`（RFC 6750 §3）で返す — 有効だが足りないトークンなら `403` と `error="insufficient_scope"` で。このチャレンジがあれば、Store が受け付けないトークン — 打ち間違い、途中で止まったローテーション — はすべての呼び出しで障害になり、各呼び出し元はそれを下の表のとおり報告する。チャレンジが無ければ `401` や `403` はワイヤ上の意味 — 「ユーザーが居ない」またはリンクの拒否 — を保ち、不一致はすべてのログインの失敗としてしか現れない。同じ理由で、ユーザーのパスワード誤り、未知の ID、ポリシーが拒否するリンクに `Bearer` チャレンジを付けてはならない: その応答は Store が auth.provider を拒否したと読まれ、そのユーザーのログインやリンクの失敗が障害になる。ローテーションは、Store に古いトークンと新しいトークンの両方を受け付けさせ、auth.provider を新しいものに移し、それから古いものを廃止する。`bearerToken` が無ければどのリクエストも `Authorization` ヘッダーを持たないので、Store は別の方法で auth.provider だけを受け入れる: ネットワークポリシーやプライベートネットワーク、または Store の前段でプラットフォームが提供する相互 TLS（ループバックアドレス上のサイドカー。`http` の例外が受け付ける）で。このアダプター自身はクライアント証明書を提供しない: Node の `fetch` がそれを受け取るのは `undici` のディスパッチャー経由だけで、このパッケージはその依存を持たない。`user:password@` を含む URL は拒否される。
- **URL に秘密を入れない。** クエリ文字列のトークンは秘密のままではいられない: このアダプターが投げるエラーは URL 全体を示し、セッションルートはそれをログに出す。呼び出し元の資格情報は `bearerToken` に置く。このアダプターが投げるものはどれもそれを含まない。
- **リダイレクトせずに応答する。** どのリクエストもリダイレクトを追わないので、パスワード、トークン、リンクのリクエスト、ID は設定された URL — 下の `https` の規則が検査する URL — にだけ届き、それ以外のどこからの応答もユーザー、リンク、照会の答えとして受け取られない。四つのエンドポイントのどれからの `3xx` も、他の想定外のステータスと同じく例外になる（セッションルートと jwt-bearer グラントは `503 temporarily_unavailable`、grants のコールバックは `temporarily_unavailable` を返す）ので、リダイレクトする URL — 正規のホストへリダイレクトするホストの別名、末尾スラッシュの付加、パスの移動 — の背後にある Store はすべての呼び出しで失敗する。各 URL には、リダイレクトするエンドポイントではなく応答するエンドポイントを設定する。

**拒否されたトークンが呼び出し元ごとにどう見えるか。** どの呼び出し元も `StoreCredentialRefusedError` を他の Store の障害 — `StoreTransportError` や `TimeoutError` も — と同じく扱い、違うのはログに出すものである:

| 呼び出し元 | 返すもの | ログ |
| --- | --- | --- |
| パスワードログイン、`POST /session/login`（[`@o3co/auth-provider-session`](../session/README.ja.md)） | `503 temporarily_unavailable` | `local login authenticate failed`（warn、`err` 付き） |
| フェデレーションのログインと `?link=1` のコールバック（session） | `503 temporarily_unavailable` | `user repository lookup failed` または `federation link: user repository failed`（warn、`err` 付き） |
| jwt-bearer グラント（[`@o3co/auth-provider-oauth`](../oauth/README.ja.md)） | `503 temporarily_unavailable` | `jwt_bearer_user_repository_unavailable`（error、`err` 付き） |
| federation-grants の接続コールバック — ID の照会（[`@o3co/auth-provider-federation-grants`](../federation-grants/README.md)） | `error=temporarily_unavailable` 付きのリダイレクト | `federation_grant.failure`（warn）に `during: "callback_identity_lookup"` と `classification: "store_credential_refused"`（`StoreTransportError` なら `store_transport_failed`、`TimeoutError` なら `timeout`） — このレポーターは分類を出し、エラーのメッセージは決して出さない |

`err` がログに出る場合、`StoreCredentialRefusedError` のメッセージは Store の URL、ステータス、`CLIENT_USER_BEARER_TOKEN` を示し、トークンは決して示さない。`StoreTransportError` のメッセージは URL、何が失敗したか、せいぜい通信のコードを示す。

## コンストラクタでの検証

すべてのオプションは **コンストラクタ** で検証されるので、設定を誤ったデプロイは最初のログイン試行ではなく起動時に失敗する。

**すべての URL は `https://` でなければならない**（リンクと照会のエンドポイントも含む）。これらは平文のユーザー資格情報 — `authenticateUrl` にはパスワード、`authenticateByTokenUrl` にはトークン、`findSubjectByFederatedIdentityUrl` には検証済みの上流 ID — を運ぶので、`http://` の URL は接続を弱めるだけでなく、経路上のすべてのホップに資格情報を公開する。ここで検査される URL がリクエストの唯一の行き先であり、応答を受け取る唯一の相手である: どのリクエストもリダイレクトを追わないので、`307` や `308` がこの規則の見ていない `Location` へボディを送り直すことも、`301`・`302`・`303` がそこから応答を取ってくることもない。

**唯一の例外はループバック:** ホストが `localhost`、`127.0.0.0/8` 内のアドレス、`[::1]` のいずれかなら `http://` を受け付ける。その通信はマシンの外に出ないので、ローカル開発とプロセス内のテストフィクスチャに証明書は要らない。それ以外のホストは **プライベートレンジのアドレスやコンテナネットワークのサービス名も含めて** `https://` が必須（`http://10.0.0.5/…`、`http://user-service/…` は拒否される）: それらはデプロイが端から端まで制御していないネットワークを越えるものであり、「内部」は「暗号化済み」の同義語ではない。資格情報を埋め込んだ URL（`https://user:pass@…`）も拒否する。

これは [`@o3co/auth-provider-core`](../core/README.ja.md) の `oauth.jwt.issuer` が適用するのと同じ規則で、例外を単一アドレス `127.0.0.1` から `127.0.0.0/8` ブロック全体に広げ、クエリ文字列を許している（issuer は持てないが、POST のエンドポイントは正当に持ちうる）。

**`timeout` は `2147483647` ミリ秒以下の正の整数でなければならない。** `0`・負数・`NaN` は `setTimeout` ではいずれも「即時発火」に丸められ — すべてのリクエストが中断される — 、Node のタイマー範囲を超える値は 1ms に丸められるので、「気長に待つ」つもりの設定が最もせっかちな設定になる。空の環境変数による上書きはデフォルトにはならず起動失敗になる。期限は **ボディの読み取りを含む** やり取り全体に掛かる: ボディの読み取りは abort signal に頼らず期限と競わせる。リクエストの中断は進行中の読み取りを確実には止めないからである。これは slow-loris の形 — ヘッダーはすぐ届き、ボディが少しずつ届くか止まる — で、競わせなければ永久にハングする。期限を超えたリクエストは、エンドポイントを示す `timed out after <n>ms` のエラーで reject される。そのエラーの名前は四つのリクエストすべてで `TimeoutError` なので、名前で分類するレポーターはそれをタイムアウトと読む。

**`maxResponseBytes` は正の整数でなければならず**、デフォルトは `DEFAULT_MAX_RESPONSE_BYTES`（1 MiB）。上限は `Content-Length` に対しても、ストリーム読み取り中にも適用されるので、ヘッダーを省く — あるいは偽る — Store も、メモリを使い果たす前に打ち切られる。

**`bearerToken` は、設定するなら 32 バイト以上の鍵素材を持つ素の RFC 6750 トークンでなければならない。** 未設定（キーが無い）なら `Authorization` ヘッダーは送らない。設定した場合は、文字列であること、空でないこと（空の環境変数による上書きは「トークン無し」ではなく起動失敗）、英字・数字・`-._~+/` と末尾の `=` パディングだけから成ること — 空白も改行も、アダプターが付ける `Bearer ` の接頭辞も含まない — 、そして core の共有シークレットの下限（`MIN_SECRET_ENTROPY_BYTES`。`SESSION_SECRET` と `OAUTH_JWT_SECRET` が満たすのと同じもの）を満たすことが求められ、どれかを欠けば拒否される。hex や base64 の値はデコード後の長さで測るので、`openssl rand -hex 16` は見た目の長さに関わらず 16 バイトである。このトークンを持つ者は auth.provider として Store と話せる。形をここで検査するのは、`fetch` が拒否するヘッダー値は、`fetch` が投げるエラーの中にそのまま引用されるからである。どの拒否も値を引用せず、リクエストのどのエラーも値を含まず — 通信の失敗は通信自身のエラーを付けずに投げられる（ワイヤ契約を参照） — 、値は ECMAScript の private フィールドに保持されるので、リポジトリの `inspect()` や `JSON.stringify` にも現れない。これらの検査はリポジトリが組み立てられるときに行われ、デプロイがそうするのは `repositories.user.type = "http"`（standalone テンプレートのデフォルト）のときである。core の `reference.conf` のデフォルトである `yaml` では、`http` ブロック — とその中のトークン — はまったく読まれない。

## パブリック API

[`src/index.mts`](src/index.mts) から export される:

- `registerBuiltinAdapters({ userFactory })` — `"http"` 型を登録する。
- `HttpUserRepository` — リポジトリ（[`src/repositories/HttpUserRepository.mts`](src/repositories/HttpUserRepository.mts)）。
- `StoreCredentialRefusedError` — 資格情報が拒否されたときに投げられるもの。`name` と `storeStatus`（`401` または `403`）は契約の一部。`status` ではない: Express、http-errors、standalone の終端ハンドラーはそれを応答するステータスとして読む。
- `StoreTransportError`、`StoreTransportFailure` — 通信の失敗で投げられるもの。`name`、`reason`、`code` は契約の一部で、こちらも `status` を持たない（[`src/repositories/storeErrors.mts`](src/repositories/storeErrors.mts)）。
- `DEFAULT_MAX_RESPONSE_BYTES` — レスポンス上限のデフォルト。
- `FederatedIdentityLookupCoverage` — カバレッジのエントリー一つの型。

## テスト

| テストファイル | 固定するもの |
| --- | --- |
| [`HttpUserRepository.test.mts`](src/repositories/__tests__/HttpUserRepository.test.mts) | 認証とその応答、`User` の形の検査、https の規則、タイムアウトとレスポンス上限、リンク、ID の照会の有無・probe・ワイヤ |
| [`HttpUserRepository.transport.test.mts`](src/repositories/__tests__/HttpUserRepository.transport.test.mts) | 実際の HTTP サーバーに対して: ID の照会が拒否した応答の接続を解放すること、四つのリクエストそれぞれでリダイレクト — 別のオリジンへ、同じオリジンへ、`Location` 無し — が拒否され、リダイレクト先に何も送られないこと |
| [`HttpUserRepository.credential.test.mts`](src/repositories/__tests__/HttpUserRepository.credential.test.mts) | 実際の HTTP サーバーに対して: `bearerToken` があれば四つのリクエストそれぞれに `Authorization: Bearer <token>` が付き、無ければ `Authorization` ヘッダーが付かないこと（直接構築でも `"http"` ビルダー経由でも）、弱い・形の誤った・空の・文字列でないトークンが構築時に拒否されること、どの失敗にもリポジトリのどの検査にもトークンが現れないこと、通信の失敗が何が失敗したかを示す `StoreTransportError` になること — 接続の拒否と平文の HTTP のポートを指す https の URL（届かない）、トークンを反射したステータス行やヘッダー、サイズ上限を超えるヘッド（壊れた応答）、`1xx` の後・ヘッドの途中・1 バイト目の前の切断や、二つのリクエストの間に閉じられたプール済みの keep-alive 接続（接続が閉じられた）、chunked ボディ（読めない）、クライアントのハンドシェイクを拒否する TLS 1.2 サーバー（届かない、`ERR_SSL_SSL/TLS_ALERT_HANDSHAKE_FAILURE`） — コード付き、cause 無しで、タイムアウトはヘッダーとボディのどちらが止まっても `TimeoutError` になること、トークンを送ったときの `Bearer` チャレンジ付き `401` または `403` が四つそれぞれで `StoreCredentialRefusedError`（`storeStatus`、`status` 無し）になり、チャレンジの無いもの — またはトークンを送っていないとき — は従来どおり読まれること |
| [`storeErrors.test.mts`](src/repositories/__tests__/storeErrors.test.mts) | どの通信のコードが残るか、二つの名前付きエラーの形 — `status` も cause も無い |
| [`wwwAuthenticate.test.mts`](src/repositories/__tests__/wwwAuthenticate.test.mts) | どの `WWW-Authenticate` の値が `Bearer` チャレンジを持つか、敵対的な 64 KiB の値を一度の走査で読むこと |
| [`registerBuiltinAdapters.test.mts`](src/repositories/__tests__/registerBuiltinAdapters.test.mts) | `"http"` のビルダー、そのデフォルトと文字列の変換、組み立て時に拒否される設定 |
| [`endpointUrl.test.mts`](src/__tests__/endpointUrl.test.mts) | https またはループバックの規則 |

## 関連

- [`@o3co/auth-provider-core`](../core/README.ja.md) — `UserRepository` ポート、`createRepositoryFactories`、開発用ユーザーアダプター
- [`@o3co/auth-provider-session`](../session/README.ja.md) — `authenticate`・`authenticateByToken`・`linkFederatedIdentity` を呼ぶルート
- [`@o3co/auth-provider-federation-grants`](../federation-grants/README.md) — ID の照会の呼び出し元
- [auth.provider](../../README.ja.md) — リポジトリ全体のドキュメント
