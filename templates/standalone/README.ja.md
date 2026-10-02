# @o3co/auth-provider-standalone

最終更新: 2026-10-03

auth.provider のデプロイ可能なサーバーテンプレート。これは composition root であり、設定を読み込み、モジュールをロードし、Express サーバーを起動する。`@o3co/create-auth-provider` で生成される。

## 責務と役割

**役割。** composition root であり、デプロイの出発点である。ライブラリではない: これを import するものは何も無い。`@o3co/create-auth-provider` がこれを新しいプロジェクトにコピーし、以後はオペレーターがそのコピーを所有・編集する。パッケージ群の上に位置し、`@o3co/auth-provider-core` の上に `@o3co/auth-provider-oauth`、`-session`、Google と汎用 OpenID Connect のフェデレーションアダプター、`-federation-grants`、`-redis`、`-foundation`、`-standard` のメール送信者を合成する。

**所有する**のは、1 つのデプロイに固有の選択である:

- どのモジュールをどの順序で合成し、各ストアスロットをどのアダプターで埋めるか — [`src/buildModules.mts`](src/buildModules.mts)（[モジュール合成順序](#モジュール合成順序) を参照）。その選択は自身のセクション `adapters` から読む（[`src/adapters.mts`](src/adapters.mts)）
- この scaffold だけが持つモジュール — `logging` と `http`（ホストプロセス自身の設定とその CORS のリスト、および core の `httpSettings` スロット）、署名鍵ストア、クライアントリポジトリとユーザーリポジトリ、監査 sink、共有される唯一の Redis 接続、in-memory のユーザーセッションストア・コードリポジトリ・フェデレーショントークンストア、そしてフェデレーションの config bridge — [`src/modules.mts`](src/modules.mts)。それらが所有するセクションのデフォルトは [`config/reference.conf`](config/reference.conf) にある。これらがパッケージではなく scaffold 側にあるのは、どれもこのテンプレートの設定セクションから自分のコンポーネントを組み立てるためである。別のソースを使いたいデプロイは、同じ形のモジュールを自前で配線する
- 設定をどこから読み、そのレイヤーをどう重ねるか — [`src/configPath.mts`](src/configPath.mts) と [`config/`](config/)
- ホストプロセス: Express アプリ、そのセキュリティヘッダー、起動処理 — [`src/app.mts`](src/app.mts)。health / readiness / metrics の各ルート、合成されたルーター、その後ろの core の終端のエラーハンドラーを、マウントする順に — [`src/routes.mts`](src/routes.mts)。リスナーはソケットが bind されたときに `server_listening`（info、`port`）を 1 行ログに出し、bind できなければその bind のエラーで起動を失敗させ、その後のサーバーのエラーは `server_error`（error）としてログに出す — [`src/listen.mts`](src/listen.mts)。このコードがログに出すエラー — 処理されなかったリクエストのエラー、共有 Redis 接続の `error` イベント、失敗したシャットダウン — はすべて core の [`loggableError`](../../packages/core/README.ja.md#logger) による射影としてログに出し、エラーそのものは出さない。エラーは上流や Redis が言ったことを運びうるためである（サーバーが接続を拒否したとき、接続のエラーは `AUTH` のハンドシェイクをパスワードごと運ぶ）
- 具体的な logger と監査ストリーム（pino） — [`src/logger.mts`](src/logger.mts) — およびメトリクス（[`src/metrics.mts`](src/metrics.mts)）
- プロセスのライフサイクル: drain の deadline 付きのシグナル処理 — [`src/shutdown.mts`](src/shutdown.mts)
- パッケージング: `Dockerfile`、compose ファイル群、`Makefile`
- 自身のテスト: `pnpm run test` と `make test` がこの合成に対して実行する `src/__tests__/` と、独自の `package.json` を持つ別個のブラックボックス API スイートで、既に起動しているサーバー（`API_BASE_URL`）に対して実行する `tests/`。`src/__tests__/` が保つものの 1 つは、このテンプレートが有効にできるすべてのモジュールが一緒に起動し、モジュールが出会って初めて成り立つ契約 — 1 つのディスカバリー文書、どちらのマウント順でも保たれる各モジュールのボディ規則、503 で答えて 1 行だけログに出るストアまたはリポジトリの障害 — を守ることであり、`all-modules-composition.test.mts` がそれを固定する。

**所有しない**のは HTTP API、グラント、トークン形式、各ストアの振る舞い、config スキーマで、これらはパッケージ側が所有する。変更は上流で行い、ここでは行わない。

**分離している理由。** 上記はすべてデプロイごとの判断であるため、公開ライブラリの外に置き、オペレーターが変更する前提のツリーに入れている。これ自体は `"private": true` で、公開されることはなく、ユーザーに届くのは scaffolder 経由だけである。scaffold されたコピーにはこの README も含まれるが、その中の `../../docs` と `../../packages` への相対リンクはこのリポジトリ内でしか解決しない。

## 動作要件

- **Node.js** `>=22.0.0`
- **`bcrypt` のネイティブバイナリ**: このテンプレートは推移的に `bcrypt@6.x` に依存しており、これは `darwin-arm64`、`darwin-x64`、`linux-x64`（glibc と musl）、`linux-arm64`（glibc と musl）、`linux-arm`、`win32-x64`、`win32-arm64` 向けの **prebuild 済み N-API バイナリ**を同梱している。これらのプラットフォームでは `pnpm install` はソースからコンパイルせずに成功し、追加のツールチェーンは不要である（`darwin-*`、`node:*-alpine`、`node:*-bookworm` の各イメージはいずれも同梱の prebuild に一致する）。一致する prebuild の無いプラットフォームや libc/arch の組み合わせでは `pnpm install` がコンパイルにフォールバックし、その場合は C++ コンパイラと Python（Node.js ネイティブアドオンの標準ツールチェーン）が必要になる: Debian/Ubuntu は `apt-get install build-essential python3`、Alpine は `apk add make g++ python3`、macOS は `xcode-select --install`。`bcrypt` 向けの pnpm 10 の `onlyBuiltDependencies` allowlist は `pnpm-workspace.yaml` にある — pnpm ≥10.29 は単一パッケージのプロジェクトでもそこからしか読まない。`create-auth-provider` は scaffold するプロジェクトにこのファイルを書き出す（このモノレポ内では、allowlist はワークスペースルートの `pnpm-workspace.yaml` にある）。これが無いと、新規の `pnpm install` はそれらのプラットフォームで install hook を黙ってスキップする。
- **Redis 7.2 LTS 以降** — Redis をバックエンドとするアダプター（refresh token family ストア、コードリポジトリ、フェデレーショントークンストア、セッションストア）すべてに必要。複数のアダプターが依存する `pExpireGT` フラグの組は Redis 7.0+ で導入された。7.2 LTS がテスト済みの下限である。AWS ElastiCache for Redis 7.2、Upstash Redis、Redis Cloud 7.2、セルフマネージドの `redis:7.2-alpine` でテストしている。
- **ioredis** `^6.0.0`（ランタイムの直接依存）。このテンプレートが配線する `@o3co/auth-provider-redis` のアダプター — refresh token family、認可コード、rate limit カウンター、アクセストークン denylist、replay seen-set、ユーザーセッションストア、フェデレーショントークンストア、同意ストア、フェデレーショングラントのストア — はすべて、`standaloneRedisClientsModule` がレプリカごとに開く 1 本の ioredis 接続の上で動く。同じモジュールは Redis パッケージが提供するほかのストア — デバイスコードストアと WebAuthn の challenge ストア — のクライアントも提供するため、デバイスグラントや WebAuthn を Redis のストアとともに `buildModules.mts` に加えるデプロイは、そのクライアントをここで得る。`redis` npm パッケージ（`^6.2.1`）が依存に残っている理由は 1 つだけである: `connect-redis` は node-redis クライアントを受け取るため、`SESSION_STORE_STORAGE_TYPE=redis` の背後にある `express-session` ストアは 2 本目の別接続になる（`/readyz` の `session-store` probe）。

## ファーストパーティクライアント

`firstParty: true` が付いたクライアントに対しては、`GET /authorize` はユーザーのセッションが認証済みになった時点で認可コードを発行する。**同意ステップは無い**: このクライアントに自分の identity を渡してよいかを、ユーザーが問われることは一切ない。

これは**ファーストパーティ**の OP — 登録されたクライアントがすべて自分で運用するものである OP — にとっては筋の通ったモデルだが、それ以外では成り立たない。自分が制御していないページが `/authorize?client_id=X&redirect_uri=...&code_challenge=<theirs>` へのトップレベル遷移を強制できる。ログイン中のユーザーのブラウザは*そのユーザーの*セッションに紐づいたコードを発行し、それは X の登録済み `redirect_uri` に届けられ、`code_challenge` を選んだ者がそれを、そのユーザーの identity を載せたトークンと引き換える。

そのため、この前提は仮定されるのではなく強制される。それ以外のクライアント — `firstParty` フィールドを持たないものも、`false` を持つものも同様に — は同意ステップを通る: コードが発行される前に、デプロイ側の同意ページでユーザーに確認する。このステップには同意ストアが必要だが、テンプレートは何も同梱していない（`ADAPTERS_CONSENT_STORE=none`）ため、デフォルトのままではそのようなクライアントは `/authorize` で `unauthorized_client` として拒否される。それを受け付けるには [同意ストア](#同意ストア) を参照。クライアントをファーストパーティとしてマークするのは、そのクライアントが**ユーザーに確認することなく**ユーザーの identity を受け取っても構わないと言える場合だけにすること。

```yaml
# config/clients.yaml
my-app:
  tokenEndpointAuthMethod: "client_secret_basic"
  firstParty: true
  allowedRedirectUris: ["https://app.example/callback"]
```

マシンクライアントは共有シークレットの代わりに鍵で認証できる（#484）: `tokenEndpointAuthMethod: "private_key_jwt"` に `jwks`（インラインの公開鍵）または `jwksUri` を加え、`/oauth/token` で署名済みアサーションを提示する — [oauth パッケージの README](../../packages/oauth/README.md#client-authentication-private_key_jwt-rfc-7523-22) を参照。そのようなクライアントについては、`clients.yaml` に秘密情報は何も置かれない。

**これがしないこと。** ファーストパーティで*ある*クライアントについて、`/authorize` を強制遷移に対して安全にするわけではない — それはここで受け入れているモデルのままである。これが防ぐのは、確認なしのコード発行を任せるべきではなかったクライアントが、誤ってその立場に登録されることである。

**マークの無い登録。** このフィールドの無い登録はファーストパーティではない: デフォルトのままでは、マークするまで `/authorize` で拒否され、警告付きで受け入れる猶予期間も無い。自分で運用するクライアントは、`/authorize` に向ける前にすべてマークすること。`oauth.authorize.allowUnmarkedClients` は設定項目ではない: これを設定した config や環境（`OAUTH_AUTHORIZE_ALLOW_UNMARKED_CLIENTS`、値は問わない）は、黙って無視されるのではなく、移行手順を示して起動時に失敗する。

## マルチレプリカ構成

運用面は [オペレーター runbook](../../docs/operator-runbook.md) が端から端まで扱っている — 起動拒否、probe、依存先の障害、アラート、Redis のサイジング、鍵ローテーション。このセクションはマルチレプリカのチェックリストである。

ロードバランサ配下で standalone サーバーを複数インスタンス動かすときは、`REDIS_CLIENTS_URL` を**共有**の Redis 7.2+ インスタンスに向けること。共有の Redis URL が無いと、各レプリカは refresh token family を自分の接続（と、ローカル専用の Redis）に保持するため、トークンを発行していないレプリカに届いた refresh リクエストは `invalid_grant` を返し、ラウンドロビンの LB では 1 回おきにそうなる。

**ロードバランサ配下では `HTTP_TRUST_PROXY` をプロキシのアドレスに設定すること。** デフォルトは `false` で、この場合 `req.ip` はクライアントではなく*ロードバランサの*アドレスになる。すると IP をキーとするすべての rate limit — OAuth エンドポイントの limiter と `POST /session/login` の総当たり対策ガード — が**全ユーザーで 1 つのバケットを共有する**: 誰からであれ最初の 20 回のログイン試行でウィンドウを使い切り、以降のユーザーは全員 `429` を受け取る。この障害は設定ミスではなく攻撃のように見えるため、深夜 3 時の診断が高くつく。このサービスの前段で何かが TLS を終端したりプロキシしたりしているなら必ず設定し、`X-Forwarded-For` を設定しているのがそのホップであることを確認すること。`ip` のない監査イベントは、リクエストのアドレスがアドレスでなかった — `req.ip` がアドレス以外を入れた `X-Forwarded-For` から来た — ことを意味するので、`HTTP_TRUST_PROXY` がそのヘッダーを設定するホップだけを信頼しているか確認すること。

取りうる形は 4 つで、いずれも Express 自身のものである:

| 値 | 意味 |
|---|---|
| `false`（デフォルト） | 何も信頼しない。`req.ip` はソケットのピアになる |
| `10.0.0.0/8,192.168.0.0/16` | 正確にこれらのホップを信頼する。IP リテラル、CIDR レンジ、または名前付きレンジ `loopback` / `linklocal` / `uniquelocal`。環境変数ではカンマ区切りにする |
| `1` | ソケットのピアから数えてその数だけのホップを信頼する |
| `true` | すべてのホップを信頼する — 接続を開いた相手が誰であれ、その `X-Forwarded-For` の左端のエントリ |

**アドレスリストを優先すること。** `true` は、このプロセスに到達できる相手なら誰からの転送クライアントアドレスでも信じる。直接、あるいは想定より 1 ホップ多く経由して到達したクライアントは、自分の `req.ip` を、ひいてはそれをキーとする rate limit 上の identity を自分で選べてしまう。エントリは起動時に検証されるため、ホスト名や打ち間違えたレンジは、決して一致しないルールになるのではなく、はっきりと失敗する。

allowlist はネットワーク上の制御であって、暗号学的な制御ではない。エッジは受信した `X-Forwarded-*` ヘッダーに追記するのではなく**除去**しなければならず、エッジとこのプロセスの間のホップは、送信元アドレスを偽装できる者から到達できてはならない。

**`adapters.rateLimiter` を Redis に向けること。** デフォルトは `"memory"` でプロセスごとである: N レプリカでは設定したすべての limit が実質 N 倍になり、デプロイのたびにリセットされる。memory アダプターは**バケット枯渇によって回避可能**でもある: バケット数の上限を 10,000 とし、上限に達すると、新しいキーを受け入れる際にリセットが最も近いバケットを追い出す — そのため多数の送信元 IP を提示できる攻撃者（`HTTP_TRUST_PROXY` が実際のホップより広ければ、`req.ip` はクライアントの影響を受ける）は、標的のカウンターが追い出されてやり直しになるまでテーブルをかき回せる。これは開発用の 1 プロセスなら許容できるが、本番の rate limit ではない。ログインガードも同じ共有コンポーネントの上で動くため、1 つの設定で OAuth エンドポイントと `/session/login` の両方がカバーされる。ログインのウィンドウと上限は引き続き `session.rateLimit.login` で設定する。session モジュールがそれを両アダプターが読む `login` の予算として寄与するため、改めて書き直すものは無い。

**BFF の背後では、必要になる前に `limits.token` を上げておくこと。** OAuth エンドポイントの rate limit は `req.ip` をキーにする（`packages/core/src/ratelimit/guard.mts` はバケットキーを `<endpoint>:ip:<req.ip>` として組み立てる）。クライアントがブラウザやネイティブアプリで、このプロバイダーと直接通信しているなら、これは正しい identity である。しかし backend-for-frontend 構成 — サーバー側アプリがセッションを保持し、ユーザーに代わってコード交換と refresh を行う構成 — では誤った identity になる: すべての `/oauth/token` と `/oauth/introspect` の呼び出しが BFF の単一アドレスから届き、デプロイ全体で 1 つのバケットを共有する。デフォルトの 60 秒あたり 60 リクエストでは、**全ユーザー合計で毎分およそ 60 回の session グラント交換**が上限になる — しかもそれは rate limit として表に出てこない。BFF は想定していない `429` を受け取り、それを自分の呼び出し元への `502` に変え、ユーザーが報告する症状は「サインインがときどき壊れる」になる。それは起き始めるトラフィック量に達した時点で現れ、それより前には現れない。

`HTTP_TRUST_PROXY` はこれを解決しないし、そのためのものでもない。これは `req.ip` に*プロキシ* — 他者のリクエストを転送し、そのことを `X-Forwarded-For` で申告するホップ — の向こうを見通させるものである。BFF は誰のリクエストも転送していない。BFF 自身がクライアントであり、そのアドレスは「誰が呼んだか」への正直な答えである。これらのリクエストには、キーにできるユーザーごとの identity が存在しない。

調整すべきはエンドポイントごとの予算である。どちらの limiter アダプターも、自身のセクションで、エンドポイントの prefix をキーとする `limits { <prefix> { limit, windowSeconds } }` を受け取る:

```hocon
redis-rate-limiter {
  limits {
    token     { limit = 600, windowSeconds = 60 }
    introspect { limit = 600, windowSeconds = 60 }
  }
}
```

（memory アダプターでは `core-rate-limiter-memory.limits` で、形は同じ。）BFF の毎分のサインインと refresh のピークから、余裕を持たせてサイズを決めること。また `adapters.rateLimiter = "redis"` のもとでは予算がレプリカ間で共有されることを覚えておくこと — ここではそれが望ましい挙動であり、それによってこの数値が意味を持つ。

デフォルトは意図的に変えていない: 送信元 IP ごとに 60 秒あたり 60 回というのは、クライアントが本当に別々の IP であるデプロイにとって妥当な総当たり対策の上限であり、一方の構成に合わせて全体的に引き上げれば、もう一方の構成での防御が弱まる。BFF *自身の*ユーザーを守るスロットリングは、ユーザーごとの identity がまだ存在する BFF の前段に置くこと。

**2 つ以上のレプリカを動かすようになったら `CORE_DEPLOYMENT_MODE=multi` を設定すること。** すると、共有が必要な in-memory ストアがまだ配線されていれば起動が*失敗*し、該当するものすべてと、それぞれの代償が名指しされる — ユーザーセッションの分岐（back-channel logout が 1 つのレプリカにしか届かず、ログアウトしたセッションが他のレプリカでは有効なまま）、rate limit カウンターの倍増、アクセストークン失効の未伝播、一度きりのクライアントアサーションや WebAuthn チャレンジがレプリカごとに 1 回ずつ再利用できてしまうこと。このチェックはライブラリのモジュール名のリストではなく、インストールされた各モジュールが自身の manifest に持つ宣言を読むため、このテンプレート独自の in-memory モジュール — ユーザーセッションストア（`ADAPTERS_USER_SESSION_STORES=memory`）、認可コードリポジトリ（`ADAPTERS_CODE_REPOSITORY=memory`）、フェデレーショントークンストア（`ADAPTERS_FEDERATION_TOKEN_STORE=memory`、デフォルト） — も名指しで拒否される。`SESSION_STORE_STORAGE_TYPE=memory` のときの express-session 自身のストア（#474）と、デフォルトの memory の rate limiter（`core-rate-limiter-memory`、`ADAPTERS_RATE_LIMITER=memory`）も同様である。モードが未設定なら何も拒否されない: これらはすべて、起動時の 1 件の `replica_unsafe_adapters` 警告に列挙される。（login と WebAuthn-options のルートは、それぞれ個別に警告するプロセス単位のフォールバック limiter を持つが、それが働くのは `rateLimiter` をまったく配線しない構成だけで、このテンプレートは常に配線する。オペレーター runbook を参照。）`CORE_DEPLOYMENT_MODE=single` ではチェックは何も言わない。レプリカは 1 つだと宣言したからである。このテンプレートは DPoP をインストールしない。DPoP を加えた構成では、受け入れた DPoP proof はすべて `private_key_jwt` と同じ replay seen-set（`ADAPTERS_REPLAY_SEEN_SET`）に記録されるため、同じ扱いを受ける — `memory` は `CORE_DEPLOYMENT_MODE=multi` のもとで拒否され、モード未設定なら警告に列挙される。同梱の `redis` なら DPoP の記録もレプリカ間で共有される。dpop パッケージの [operator requirements](../../packages/dpop/README.md#operator-requirements) を参照。

この変数は `core.deployment.mode` を設定する。旧名の `DEPLOYMENT_MODE` は、単独で、または `CORE_DEPLOYMENT_MODE` と異なる値で設定されているとブートを拒否し、同じ値で並べて設定されていればブートする。

このチェックに*できない*ことも把握しておくこと: `CORE_DEPLOYMENT_MODE` を一度も設定しないまま N レプリカにスケールしても、何も失敗しない。すべての状態を自分のメモリに持つプロセスには、他のピアに気づくための共有媒体が無い — その状態は、まさにそれが真であるときに内側からは検出できない。この変数はスケールの一環として設定し、何かが壊れてからにしないこと。

**アクセストークンの失効には denylist が必要で、テンプレートはそれを同梱している。** `POST /oauth/revoke` はアクセストークンの `jti` を `accessTokenDenylist` に書き込むことで失効させ、トークン検証と introspection はそれを参照する。背後に denylist の無い状態でエンドポイントがマウントされていると、起動が*失敗*する: RFC 7009 はエンドポイントに `200` を返すことを義務づけているため、denylist が配線されていないと、トークンは失効したと告げながら、そのトークンは期限切れまで使え続けてしまう。ここでは `adapters.accessTokenDenylist` のデフォルトは `"redis"` で（単一インスタンスのローカル作業では `ADAPTERS_ACCESS_TOKEN_DENYLIST=memory`）、`REDIS_CLIENTS_URL` で設定した ioredis ソケットを共有するため、追加の接続は発生しない。本当にアクセストークンを失効させないデプロイは、代わりに `OAUTH_REVOCATION_ACCESS_TOKEN=unsupported` を設定する。するとエンドポイントは `token_type_hint=access_token` に対して `unsupported_token_type` を返す。**リフレッシュトークンの失効はどちらの場合でも機能し、denylist を必要としたことは一度もない。**

デフォルトのモジュールがカバーする、その他のマルチレプリカ上の考慮点:

- `express-session` のストア（`sessionStoreModule`）は独自の接続である: `SESSION_STORE_STORAGE_TYPE=redis` とし、`SESSION_STORE_STORAGE_REDIS_URL`（`session-store.storage.redis.url`）を共有インスタンスに向ける。
- ユーザーセッションストアは `adapters.userSessionStores = "redis"`（`ADAPTERS_USER_SESSION_STORES`）で切り替わり、共有の ioredis 接続 — `REDIS_CLIENTS_URL` で設定するもの — の上に `redisSessionStoresModule` を配線する。
- 認可コードリポジトリは `adapters.codeRepository`（`ADAPTERS_CODE_REPOSITORY`）で切り替わる。テンプレートは同じ接続上の `"redis"` を同梱しているので、すべてのアダプターで Redis URL は 1 つである。Redis のリポジトリ自身の設定はそのセクション `redis-code-repository`、in-process のものは `standalone-in-memory-code-repository` にある（[コードリポジトリ](#コードリポジトリ) を参照）。
- replay seen-set — `private_key_jwt` クライアント認証（#484）の背後にある、`jti` の一回限り使用の記録 — は `adapters.replaySeenSet`（`ADAPTERS_REPLAY_SEEN_SET`）で切り替わる。テンプレートは共有接続上の `"redis"` を同梱しており、`memory` は `CORE_DEPLOYMENT_MODE=multi` のもとでは拒否される。捕獲されたクライアントアサーションが、レプリカごとに 1 回ずつリプレイできてしまうためである。
- ファーストパーティでないクライアントのための同意ステップ（#527）は `adapters.consentStore`（`ADAPTERS_CONSENT_STORE`）で切り替わる。デフォルトはオフ（`none`）である。`memory` は `CORE_DEPLOYMENT_MODE=multi` のもとでは拒否される。あるレプリカで与えた同意が他のすべてのレプリカで再度求められ、同意ページが保留したリクエストを、回答を受け取ったレプリカが知らないという事態になるためである。`redis`（#561）は両方を共有接続上に保持する。[同意ストア](#同意ストア) を参照。
- フェデレーショントークンストアのデフォルトは memory である。`ADAPTERS_FEDERATION_TOKEN_STORE=redis`（`adapters.federationTokenStore = "redis"`）を設定し、`REDIS_FEDERATION_TOKEN_STORE_ENCRYPTION_KEY` — 32 バイト、base64 エンコード（`openssl rand -base64 32`） — を与えること。ストアは保持する上流のリフレッシュトークンを暗号化する。`REDIS_CLIENTS_URL` で設定した ioredis ソケットを共有する。[フェデレーショントークンストア](#フェデレーショントークンストア) を参照。
- フェデレーショングラント（#593）は、有効にするとさらに 2 つのストアを持つ: グラントそのもの（`ADAPTERS_FEDERATION_GRANT_STORE`）と、取得フローの記録（`ADAPTERS_FEDERATION_GRANT_INTENT_STORE`）。どちらも `none` を同梱しており、機能を有効にするとそのストアを名指しして起動が拒否される。それぞれ `redis`（共有ソケット）か `memory` を選ぶ。いずれかを `memory` にすると `CORE_DEPLOYMENT_MODE=multi` のもとでは拒否され、Redis のグラントと memory のユーザーセッションストアの組み合わせはレプリカ数にかかわらず拒否される。グラントが、それを終わらせる境界より長生きしてしまうためである。[フェデレーショングラント](#フェデレーショングラント) を参照。

## 使い方

`pnpm run debug` はこのマシン上で `src/app.mts` を `tsx watch` で実行する。
`.env` ファイルは読まない — 設定は `config/` と、起動したシェルの環境変数だけで
ある — そして、その環境が次のものを与えるまで起動しない:

- `OAUTH_JWT_ISSUER` — このサーバーのオリジン（loopback ホストなら `http` も可）;
- 署名鍵のペア、`KEY_STORE_LOCAL_PRIVATE_KEY_PATH` / `KEY_STORE_LOCAL_PUBLIC_KEY_PATH`
  （[OAuth JWT](#oauth-jwt) を参照）;
- `SESSION_STORE_SECRET`、32 バイト以上;
- `REPOSITORIES_USER_HTTP_AUTHENTICATE_URL` と `REPOSITORIES_USER_HTTP_AUTHENTICATE_BY_TOKEN_URL` —
  ユーザーサービス（「the Store」）。`https`、または loopback ホストなら `http`。
  起動時に検査されるのは形式だけで、応答があるかどうかではない。何かが応答する
  までログインは失敗する（[ユーザーリポジトリ](#ユーザーリポジトリ) を参照）;
- `redis://localhost:6379` で到達できる Redis。同梱の設定は、ブラウザセッションの
  ストアをそこに置き（`SESSION_STORE_STORAGE_REDIS_URL`）、共有の接続を 1 本
  （`REDIS_CLIENTS_URL`）開いて、refresh token family、
  認可コード、アクセストークン denylist、replay seen-set に使う — 下の設定を
  加えれば、ユーザーセッションストアにも。

平文の HTTP では、さらに `SESSION_STORE_SECURE=false` と、`__Host-` プレフィックスを
持たないセッション Cookie 名が必要になる（[Session](#session) を参照）。また
`ADAPTERS_USER_SESSION_STORES=redis` を設定すること: ブラウザセッションのストアは
Redis にあり、ユーザーセッションストアのデフォルトは memory で、`tsx watch` は
保存のたびにプロセスを再起動する — 両者が分かれていると、再起動のあとブラウザの
セッションは既に存在しない `UserSession` を指し、`/authorize` がループする
（[Docker](#docker) を参照）。

クライアントレジストリ `config/clients.yaml`（`REPOSITORIES_CLIENT_YAML_PATH`）も読む。このファイルは
デプロイごとのもの: scaffold は空のものを作るが、`.gitignore` がそれをプロジェクトの
リポジトリから外すため、新しい clone には無く、作るまで起動はそのパスを挙げて失敗する
— `config/clients.yaml.example` から作るか、クライアントの無いレジストリなら空で作る。

下の鍵ペアは Node で生成する。これを動かすマシンには必ず Node がある。
`openssl genpkey -algorithm ed25519` でもよいが、OpenSSL 1.1.1 以降が必要で、
macOS が `/usr/bin/openssl` として同梱する LibreSSL では動かない。

```bash
pnpm install

# 署名鍵のペア（Ed25519）とローカルの Redis
node -e '
const { generateKeyPairSync } = require("node:crypto");
const fs = require("node:fs");
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
fs.writeFileSync("jwt-private.pem", privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
fs.writeFileSync("jwt-public.pem", publicKey.export({ type: "spki", format: "pem" }));
'
docker run -d --name auth-redis -p 127.0.0.1:6379:6379 redis:7.2-alpine

# 起動に必要なもの（ユーザーサービスの URL は自分の Store のものに置き換える）
export OAUTH_JWT_ISSUER=http://localhost:3000 \
  KEY_STORE_LOCAL_PRIVATE_KEY_PATH=./jwt-private.pem \
  KEY_STORE_LOCAL_PUBLIC_KEY_PATH=./jwt-public.pem \
  SESSION_STORE_SECRET="$(openssl rand -hex 32)" \
  SESSION_STORE_SECURE=false SESSION_STORE_NAME=auth.sid \
  ADAPTERS_USER_SESSION_STORES=redis \
  REPOSITORIES_USER_HTTP_AUTHENTICATE_URL=http://localhost:8080/authenticate \
  REPOSITORIES_USER_HTTP_AUTHENTICATE_BY_TOKEN_URL=http://localhost:8080/authenticate-by-token

# 開発モードで起動（ホットリロード）
pnpm run debug

# ビルドしてから、コンパイル済みサーバーを実行（CONFIG_ENV または NODE_ENV が config/<env>.conf を選ぶ）
pnpm run build
pnpm run start
```

`.env` を読むのは compose ファイル（`env_file`）だけである。`make dev`
（`docker compose up --build`）は同じ debug サーバーを Redis サービスと並べて
コンテナで実行し、環境変数を `.env` から取る — `.env` は `.env.example` から
コピーするもので、その Redis の URL はそのサービスを指している。そこでの値は
コンテナの中で解決され、コンテナには鍵ファイルが無い: あるのは `src/`、
`config/`、パッケージのマニフェストと、そのインストールとビルドの成果物だけで
ある。ホストで有効な鍵のパスや `localhost` の URL は、そこでは有効ではない。
デプロイ用のイメージとその compose ファイルは [Docker](#docker) にある。

## 設定

設定は `config/application.conf`（HOCON 形式）から、パッケージ群の `reference.conf` とテンプレート自身の `config/reference.conf` のデフォルトの上に読み込まれる。各値は対応する環境変数で上書きできる。

### 環境別コンフィグ overlay

`src/app.mts` は複数の層でコンフィグを読み込む（優先度の高い順）:

1. **`config/{ENV}.conf`** — 現在の環境の overlay。`ENV = CONFIG_ENV || NODE_ENV || "development"` で決まる。
2. **`config/application.conf`** — このデプロイの設定。
3. **読み込むモジュールの各パッケージの `reference.conf`**、その次に **`@o3co/auth-provider-core` のもの** — デフォルト。インストール済みパッケージから解決される: 各モジュールが自分のパッケージのファイルを宣言し、core の `moduleReferences(modules)` がそれを core のものを最後にして列挙する。テンプレート自身のモジュールは `config/reference.conf` を宣言し、そこには自身が所有するセクション — `logging`、`http`（その CORS のリスト `http.cors` を含む）、`key-store`、共有 Redis 接続の `redis-clients`、`repositories`、in-process のコードリポジトリの `standalone-in-memory-code-repository`、`audit-sink` — と、composition root 自身の `adapters`（下記）のデフォルトがある。デプロイ固有の値はそこではなく上の 2 ファイルに書く。`config/reference.conf` はこれらのキーの変数をデフォルトの横で束縛するので、上の 2 ファイルのどちらかが設定する値は変数に勝つ。ただし `HTTP_PORT`、`HTTP_TRUST_PROXY`、`HTTP_CORS_ALLOWED_ORIGINS`、`REDIS_CLIENTS_URL` / `REDIS_CLIENTS_PASSWORD` は `application.conf` が末尾の行でもう一度束縛するので、それぞれ、そのファイルがそれより上で設定する値に勝つ。上の 2 ファイルのどちらも設定していないキーは、ここから値を得る。

上の 2 ファイルは、環境変数の一つのスナップショットのもとで一度だけ読み（`readOwnLayers`）、その一度の読み込みから二つの段階を組み立てる — 起動中にファイルが置き換えられても、変数が変わっても、boot がモジュールを選んだものと違うものをパースすることはない。読み込みは二段階で行う（[#728](https://github.com/o3co/auth.provider/issues/728)、[`src/configPath.mts`](src/configPath.mts)）。まず、モジュールを知る前に、`buildModules` がモジュールを選ぶスイッチ — フェデレーション、機能 — と、期待するセッション要件を導く元の `sessionRequirements` を、上の 2 ファイルを core の `reference.conf` だけの上に重ねて読む（`readSwitches`、core の transitional reader で読む）。パースするのはそれらのパス（`SWITCHES`）だけである。`adapters` — 各スロットをどのアダプターで埋めるか、composition root 自身のセクション — は、上の 2 ファイルをテンプレートの `config/reference.conf` の上に重ね、テンプレート自身のスキーマで読む（`readAdapters`）: 移動する前のパスにまだ書かれた選択や、それとともに改名された変数は、どのモジュールを選ぶよりも前にここで拒否され、新しいパスと変数を名指しする。boot には `adapters` を渡さない。それと並んで `mfa.mode` をテンプレート自身が読む（`readMfaMode`）: composition root が読まない MFA モジュールのキーを、テンプレート自身のレイヤーから生のまま — `application.conf` が既定値なしで `MFA_MODE` を束縛する — 読み、`off`・`optional`・`required` に限り、無いときは `off` とする。このキーを読むのは MFA モジュールを組み込むまでで、MFA ADR のビルド順のステップ 20 がこの読み込みを取り除く。パッケージの `reference.conf` だけが設定するものはこの段階では見えない — まだどれも重ねていない — ので、組み立て時に設定を読むモジュールを `buildModules` に加えるなら、そのモジュールが読むパスを `SWITCHES` に加える。ログレベルも boot の前に読むが、それは `logging` モジュールのセクションとして、そのモジュールのスキーマで、テンプレートの `reference.conf` の上に読む（`readLogging`）: テンプレートは設定を読みモジュールを選ぶ間もログを出すので、logger は boot の前に存在する。次に、読み込むすべてのモジュールの `reference.conf` の上に解決した設定を、第一段階で導いたセッション要件を書き込み、読み込むモジュールが読まない限り `mfa` セクションを除いて、パースせずに `createApp` に渡す（`resolveForBoot`）: boot はそれを、読み込まれたすべてのモジュールのスキーマで一度だけパースし、どのモジュールのセクションも取り除かない。boot の後にテンプレートが読むもの — 信頼するホップ、ポート、readiness の期限 — は、`http` モジュールから読む: core の `httpSettings` スロットと、テンプレートの `httpHostSettings` である。読み込まれたどのモジュールも所有しないトップレベルのセクションは残され、boot 時に `config_sections_ignored` として一度だけログに出る: セクション名の綴り間違いはここに現れる。

overlay の値は `application.conf` より優先される。scaffold には `development.conf` と `production.conf` が同梱されている。別の環境（例: `staging`）を追加するときは `config/staging.conf` を作成し、`CONFIG_ENV=staging` を設定する。`{ENV}.conf` が存在しない場合は起動時エラーになる — タイポは黙ってデフォルトにフォールバックせず、fail-fast する。

### アダプター

各スロットをどのアダプターで埋めるかは composition root 自身の選択で、自身のセクション `adapters` にあり、どのモジュールを選ぶよりも前に読む（上記）。各キーに変数がある。テンプレートが知らない値や、宣言していないキーは、それを名指しして boot の前に失敗する。

| 変数 | デフォルト | 説明 |
|---|---|---|
| `ADAPTERS_RATE_LIMITER` | `memory` | `adapters.rateLimiter`: `memory` または `redis`。[マルチレプリカ構成](#マルチレプリカ構成) を参照 |
| `ADAPTERS_USER_SESSION_STORES` | `memory` | `adapters.userSessionStores`: ユーザーセッションストア、`memory` または `redis`。`SESSION_STORE_STORAGE_TYPE` と揃える（[Docker](#docker) を参照） |
| `ADAPTERS_ACCESS_TOKEN_DENYLIST` | `redis` | `adapters.accessTokenDenylist`: `memory` または `redis` |
| `ADAPTERS_REPLAY_SEEN_SET` | `redis` | `adapters.replaySeenSet`: `private_key_jwt` の背後の replay seen-set、`memory` または `redis` |
| `ADAPTERS_CONSENT_STORE` | `none` | `adapters.consentStore`: `none`、`memory` または `redis`。[同意ストア](#同意ストア) を参照 |
| `ADAPTERS_FEDERATION_TOKEN_STORE` | `memory` | `adapters.federationTokenStore`: `memory` または `redis`。[フェデレーショントークンストア](#フェデレーショントークンストア) を参照 |
| `ADAPTERS_FEDERATION_GRANT_STORE` | `none` | `adapters.federationGrantStore`: `none`、`memory` または `redis`。[フェデレーショングラント](#フェデレーショングラント) を参照 |
| `ADAPTERS_FEDERATION_GRANT_INTENT_STORE` | `none` | `adapters.federationGrantIntentStore`: `none`、`memory` または `redis`。[フェデレーショングラント](#フェデレーショングラント) を参照 |
| `ADAPTERS_MFA_FACTOR_STORE` | `memory` | `adapters.mfaFactorStore`: `memory`、`redis` または `store`。MFA を組み込む合成のためのもので、テンプレートは組み込まない |
| `ADAPTERS_MFA_TRANSACTION_STORE` | `memory` | `adapters.mfaTransactionStore`: `memory` または `redis`。MFA を組み込む合成のためのもの |
| `ADAPTERS_CODE_REPOSITORY` | `redis` | `adapters.codeRepository`: 認可コードリポジトリ、`memory` または `redis`。[コードリポジトリ](#コードリポジトリ) を参照 |
| `ADAPTERS_CLIENT_REPOSITORY` | `yaml` | `adapters.clientRepository`: `yaml`、または `static`（core の `yaml` の別名）。[クライアントリポジトリ](#クライアントリポジトリ) を参照 |
| `ADAPTERS_USER_REPOSITORY` | `http` | `adapters.userRepository`: `http`、`yaml` または `static`（core の `yaml` の別名）。[ユーザーリポジトリ](#ユーザーリポジトリ) を参照 |
| `ADAPTERS_AUDIT_SINK` | `logger` | `adapters.auditSink`: セキュリティイベントの送り先、`logger`（stdout への pino エンベロープ付き NDJSON）または `console`（イベントの JSON そのまま）。`none` は存在しない。[監査ログ](#監査ログ) を参照 |

移動する前の場所 — `rateLimiter.adapter`、`oauth.code.adapter`、`audit.sink.type`、`repositories.user.type` など — にまだ書かれた選択や、それとともに改名された変数（`RATE_LIMITER_ADAPTER`、`CLIENT_TYPE` など）が単独で、または別の値で設定されていると、新しいパスと変数を名指しして boot の前に失敗する。古い変数が新しい変数と同じ値で並んでいるなら受け入れる。

### HTTP

| 変数 | デフォルト | 説明 |
|---|---|---|
| `HTTP_PORT` | `3000` | サーバーがリッスンするポート。`0` から `65535` の 10 進数字で書く。`0` は空いているポートを OS に選ばせる。空のまま設定すると起動に失敗する |
| `HTTP_TRUST_PROXY` | `false` | Express の `trust proxy`: `false`、アドレス／CIDR のリスト（`10.0.0.0/8,loopback`）、ホップ数（`1`）、または `true`。**ロードバランサ配下では必須** — 設定しないと、IP をキーとするすべての rate limit が全ユーザーで 1 つのバケットを共有する。`true` よりもプロキシを名指しすることを優先する。[マルチレプリカ構成](#マルチレプリカ構成) を参照 |
| `HTTP_READINESS_TIMEOUT_MS` | `1000` | `/readyz` の probe ごとの deadline（[ヘルスエンドポイント](#ヘルスエンドポイント) を参照） |
| `LOGGING_LEVEL` | `info` | 出力する最小レベル: `trace`\|`debug`\|`info`\|`warn`\|`error`\|`fatal`\|`silent`。監査ログの出力は左右**しない** — [監査ログ](#監査ログ) を参照 |

### OAuth JWT

署名鍵は `key-store` モジュールのセクションである: `key-store.provider`（`KEY_STORE_PROVIDER`、`local`）と、ローカル鍵ストアの `key-store.local`（`KEY_STORE_LOCAL_*`）。issuer とトークンの形式は `oauth.jwt` に残る。

| 変数 | デフォルト | 説明 |
|---|---|---|
| `KEY_STORE_LOCAL_ALGORITHM` | `EdDSA` | JWT 署名アルゴリズム: `EdDSA` / `ES256` / `RS256` / `HS256`。デフォルトが非対称なので `/.well-known/jwks.json` が実際の検証鍵を公開する。 |
| `KEY_STORE_LOCAL_SECRET` | — | 署名シークレット（**HMAC (`HS256`) 専用**）。32 バイト（256 bit）以上のランダム値 — `openssl rand -hex 32`。hex / base64 値は**デコード後**の長さで測るため、32 文字の hex 文字列は 16 バイト扱いで拒否される。 |
| `OAUTH_JWT_ISSUER` | **（必須）** | すべてのトークンの `iss` に刻まれる canonical issuer URL。絶対 `https` URL（`http` は loopback ホストのみ）で、query / fragment を含まないこと。未設定なら起動に失敗する — `Host` ヘッダーから導出されることはない。 |
| `OAUTH_REQUIRE_EMAIL_VERIFIED` | `false` | Store が `emailVerified: true` を公開するまで、そのユーザーへのトークン発行を拒否する。`/authorize` と `session` グラントで強制される。検証そのものは Store の仕事で、これは結果を読むだけである。 |
| `OAUTH_CLIENT_ID_METADATA_DOCUMENTS_ENABLED` | `false` | Client ID Metadata Document を受け付ける（#529）: `client_id` が自身の登録情報の `https` URL であるクライアントで、MCP ホストが使うモデルである。このようなクライアントは public で、決してファーストパーティにはならない — 同意ステップを通るため、`ADAPTERS_CONSENT_STORE` を配線すること。 |
| `OAUTH_CLIENT_ID_METADATA_DOCUMENTS_ALLOWED_SCOPES` | — | カンマ区切り: そのようなクライアントが取得してよいもの（ドキュメントの `scope` はこれとの積集合を取る）。空なら何も許可しない。 |
| `OAUTH_CLIENT_ID_METADATA_DOCUMENTS_ALLOWED_AUDIENCES` | — | カンマ区切り: そのクライアント向けにトークンを発行してよいリソースサーバー（RFC 8707 の `resource`）。空なら自身の `client_id` だけを許可する。 |
| `OAUTH_CLIENT_ID_METADATA_DOCUMENTS_ALLOWED_HOSTS` | — | ドキュメントを置いてよいホスト（カンマ区切り）: 完全一致、またはドメインとそのサブドメインを表す `.suffix`。空なら任意の公開ホストを許可する。 |
| `OAUTH_CLIENT_ID_METADATA_DOCUMENTS_DENIED_HOSTS` | — | 上で許可されていても拒否するホスト（カンマ区切り）。 |
| `OAUTH_CLIENT_ID_METADATA_DOCUMENTS_MAX_BYTES` | `5120` | ドキュメントのバイト数上限（draft は 5 KB を推奨）。 |
| `OAUTH_CLIENT_ID_METADATA_DOCUMENTS_TIMEOUT_MS` | `5000` | 取得のタイムアウト。 |
| `OAUTH_CLIENT_ID_METADATA_DOCUMENTS_CACHE_MAX_AGE_MS` | `600000` | 有効なドキュメントをキャッシュから返す期間の上限。`Cache-Control: max-age` によって短くなることがある。 |
| `OAUTH_CLIENT_ID_METADATA_DOCUMENTS_MAX_CACHE_ENTRIES` | `256` | 同時に記憶しておくドキュメントの数。キーは未認証の呼び出し元が選ぶため、マップには上限を設けている。 |
| `OAUTH_CLIENT_ID_METADATA_DOCUMENTS_STALE_IF_ERROR_MS` | `300000` | 検証済みの登録情報を、ドキュメント側に原因の無い理由（DNS の一時的な不調、5xx、タイムアウト）で再検証が失敗した後も返し続ける期間 — 障害で、動いているクライアントを壊すべきではないため。*拒否*されたドキュメントは即座に破棄される。`0` で無効化する。 |
| `OAUTH_CLIENT_ID_METADATA_DOCUMENTS_NEGATIVE_CACHE_MS` | `60000` | 拒否を記憶しておく期間。同じ `client_id` をリクエストのたびに解決・取得し直さないためである。ドキュメントを修正したクライアントが締め出されないよう、短くしてある。 |
| `OAUTH_CLIENT_ID_METADATA_DOCUMENTS_MAX_CONCURRENT_FETCHES` | `8` | すべての `client_id` を通じて、同時に取得中にできるドキュメントの数。未認証の呼び出し元がこのサーバーに接続させられる量を制限する。 |
| `KEY_STORE_LOCAL_KID` | `v0` | JWT ヘッダーに含まれる key ID。制御文字を含まない 1〜256 文字。それ以外は起動時に拒否される — export されているが空の変数も含む（以前は kid `""` で署名されていた。そうして発行されたトークンは修正後に拒否されるため、そのユーザーは再ログインになる） |
| `KEY_STORE_LOCAL_PRIVATE_KEY` | — | PEM エンコードされた秘密鍵（非対称アルゴリズム用） |
| `KEY_STORE_LOCAL_PRIVATE_KEY_PATH` | — | PEM 秘密鍵ファイルのパス |
| `KEY_STORE_LOCAL_PUBLIC_KEY` | — | PEM エンコードされた公開鍵 |
| `KEY_STORE_LOCAL_PUBLIC_KEY_PATH` | — | PEM 公開鍵ファイルのパス |
| `OAUTH_JWT_LEGACY_TYP_ACCEPT` | `false` | `typ` ヘッダーの無いトークンを受け付ける。`false` ではそれらを拒否し、typ の無いトークンを、たいていそうであるように設定ミスかダウングレードの試みとして扱う。`true` にするのは、v0.4.x のトークンがまだ流通している間の、期限を区切った移行期間に限ること。 |
| `JWKS_PATH` | `/.well-known/jwks.json` | issuer の下で検証鍵を公開するパスで、discovery が `jwks_uri` として広告するもの（`jwks.path`）。`//`、ドットセグメント、クエリ、フラグメント、バックスラッシュ、パーセントエンコーディング、制御文字を含まない絶対パス。 |
| `JWKS_CACHE_MAX_AGE` | `300` | JWKS レスポンスの `Cache-Control: public, max-age`（秒、`jwks.cacheMaxAge`）。ローテーションした鍵がキャッシュする検証者に間に合って届くよう、鍵の重複期間より十分短く保つこと。 |

**署名鍵は必須。** デフォルトアルゴリズムは `EdDSA` で、鍵素材のデフォルト値は存在しない。何も設定しないデプロイは、推測可能なもので黙って署名するのではなく、設定すべき鍵を名指しして起動に失敗する。Ed25519 鍵ペアの生成:

```bash
openssl genpkey -algorithm ed25519 -out jwt-private.pem
openssl pkey -in jwt-private.pem -pubout -out jwt-public.pem
```

生成したら `KEY_STORE_LOCAL_PRIVATE_KEY_PATH` / `KEY_STORE_LOCAL_PUBLIC_KEY_PATH` をそれらに向ける（または `KEY_STORE_LOCAL_PRIVATE_KEY` / `KEY_STORE_LOCAL_PUBLIC_KEY` で PEM をインラインで渡す）。

`HS256` も引き続き選択可能（`KEY_STORE_LOCAL_ALGORITHM=HS256` と 32 バイト以上の `KEY_STORE_LOCAL_SECRET`）だが、代償を理解した上で選ぶこと: 対称鍵には公開鍵の片割れが存在しないため `/.well-known/jwks.json` は `404 jwks_not_published` を返し、すべての RP に共有シークレットを渡す必要がある — そしてその共有シークレットは、RP にトークンの検証だけでなく**発行**も可能にしてしまう。

### トークン有効期限

| 変数 | デフォルト | 説明 |
|---|---|---|
| `OAUTH_ACCESS_TOKEN_DEFAULT_EXPIRES_IN` | `3600` | リクエストが有効期間を指定しないときに全グラントが発行するアクセストークンの有効期間（秒）。正の整数、上限は 1 年（`31536000`）。 |
| `OAUTH_ACCESS_TOKEN_MAX_EXPIRES_IN` | デフォルトと同じ | token exchange リクエストの `expires_in` パラメータで得られる上限。超えるリクエストはこの値に切り詰められる。未設定ならデフォルトと同じで、これを設定しない限りどのトークンも延長されない。デフォルトがこれを超えると、両キーを名指しして起動に失敗する。オフラインで検証するリソースサーバーに対し、交換で発行されたトークンが失効後も通用し得る期間の上限でもある。 |
| `OAUTH_ACCESS_TOKEN_EXPIRES_IN` | — | `OAUTH_ACCESS_TOKEN_DEFAULT_EXPIRES_IN` の**非推奨（deprecated）**エイリアス（config キーでは `oauth.accessToken.expiresIn` が `oauth.accessToken.defaultExpiresIn` のエイリアス）。新しい変数が未設定の間だけ読まれる。これがまだデフォルトを決めている間は、起動時に `config_key_deprecated`（warn）がログに出る。値は新しい変数へ移すこと。 |
| `OAUTH_REFRESH_TOKEN_EXPIRES_IN` | `86400` | リフレッシュトークンの有効期間（秒）。正の整数、上限は 1 年（`31536000`）。 |

どれも 10 進数字だけを読む。空文字で export すると、フォールバックではなく起動失敗になる（HOCON は `FOO=` を `""` に解決する）。16 進（`0x10`）、指数（`1e3`）、符号（`+5`）、小数（`5.0`）も同じく起動失敗になる。

`expires_in` リクエストパラメータを読むのは token exchange（RFC 8693）だけで、他のグラントはそれを無視してデフォルトを発行する。

### グラントタイプ

| 変数 | デフォルト | 説明 |
|---|---|---|
| `OAUTH_SESSION_ENABLED` | `true` | session グラントタイプを有効化 |
| `OAUTH_AUTHORIZATION_GRANTS_AUTHORIZATION_CODE_ENABLED` | `true` | authorization code グラントタイプを有効化 |
| `OAUTH_AUTHORIZATION_GRANTS_REFRESH_TOKEN_ENABLED` | `true` | refresh token グラントタイプを有効化 |
| `OAUTH_AUTHORIZATION_GRANTS_CLIENT_CREDENTIALS_ENABLED` | `false` | client credentials グラントタイプを有効化 |
| `OAUTH_AUTHORIZATION_GRANTS_JWT_BEARER_ENABLED` | `false` | jwt-bearer グラントタイプ（RFC 7523）を有効化 |

スイッチはそれぞれモジュールのキー — `oauth-session.enabled`、ほかは `oauth-authorization.grants.<grant>.enabled` — で、テンプレートはモジュールを選ぶために boot の前に自分のファイルと環境変数からこれを読む。旧名の `OAUTH_GRANTS_<GRANT>_ENABLED` は、単独で、または新名と違う値で設定されていると boot を拒否し、同じ値なら boot する。

### Session

| 変数 | デフォルト | 説明 |
|---|---|---|
| `SESSION_STORE_SECRET` | — | **必須。** 認証済みセッション*そのもの*である Cookie に署名する鍵で、推測されればログインを偽造できる。32 バイト（256 bit）以上 — `openssl rand -hex 32`。`KEY_STORE_LOCAL_SECRET` と同じく**デコード後**の長さで測る。 |
| `SESSION_STORE_NAME` | `__Host-auth.session` | セッション Cookie 名。デフォルトは `__Host-` prefix を使うため、`SESSION_STORE_SECURE=true` と、`SESSION_STORE_DOMAIN` の未設定が必要になる。 |
| `SESSION_STORE_MAX_AGE` | `3600000` | セッション Cookie の最大有効期間（ミリ秒）。正の整数、上限は 1 年（`31536000000`）。 |
| `SESSION_STORE_SECURE` | `true` | セッション Cookie に `Secure` フラグを設定 |
| `SESSION_STORE_SAME_SITE` | `lax` | `SameSite` 属性（`lax`、`strict`、`none`）。`none` は `SESSION_STORE_SECURE=true` が**必須** — ブラウザは `Secure` でない `SameSite=None` Cookie を破棄するため、クライアント側で全ログインが黙って失敗するのを放置せず、起動時にこの組み合わせを拒否する。 |
| `SESSION_STORE_DOMAIN` | — | Cookie ドメイン（デフォルト未設定） |
| `SESSION_CSRF_TTL_SECONDS` | `7200` | 発行する CSRF トークンの有効期間（秒）。10 進数字で書いた 1〜86400 の整数で、それ以外なら起動に失敗する（*空文字*や空白だけの値も含む）。 |
| `SESSION_STORE_STORAGE_TYPE` | `redis` | セッションストアのバックエンド: `redis` または `memory`。`memory` はプロセスごとで、他の in-memory ストアと同様に `CORE_DEPLOYMENT_MODE=multi` のもとでは拒否される（#474） |
| `SESSION_STORE_STORAGE_REDIS_URL` | `redis://localhost:6379` | セッションストア用 Redis 接続 URL |
| `SESSION_STORE_STORAGE_REDIS_PASSWORD` | — | セッションストア用 Redis パスワード |

cookie とそのストアはセッションストアのセクション `session-store` のもので、CSRF トークンの寿命、ログインページ、ログインの予算は session モジュールのセクション `session` のもの。`SESSION_STORE_*` の旧名 `SESSION_<KEY>` は、単独で、または新名と違う値で設定されていると boot を拒否し、同じ値なら boot する。

ローカルの HTTP 開発のために `SESSION_STORE_SECURE=false` を設定する場合や、ドメインを共有する Cookie のために `SESSION_STORE_DOMAIN` を設定する場合は、`SESSION_STORE_NAME` も `auth.sid` のような `__Host-` でない値にすること — `SESSION_STORE_SECURE=false` なら接頭辞の無い値にする: `__Secure-` の名前も `SESSION_STORE_SECURE=true` を要する。`__Host-` や `__Secure-`（大文字小文字は問わない）の Cookie 名が、ブラウザがその prefix に対して拒否する属性と組み合わされると、`SESSION_STORE_NAME` が Cookie の名前（RFC 6265 のトークン: 空白、`;` などの区切り文字を含まない）でないと、また `SESSION_STORE_DOMAIN` がホスト名でない（スキーム、ポート、パスを含む）と、サーバーは fail-fast する。

#### `/session/login` と `/session/logout` の CSRF 対策

どちらのルートも、same-origin（もしくは信頼した）`Origin` / `Referer`、**または**有効な double-submit CSRF トークンの**いずれか**を伴うリクエストを受理し、どちらも伴わないものは拒否する（#272）。ブラウザは自動的にこの条件を満たす。スクリプトのクライアントはまず `GET /session/csrf` を呼び、返ってきた `csrf_token` を `<SESSION_STORE_NAME>.csrf` Cookie と `x-csrf-token` ヘッダー（または `csrf_token` フォームフィールド）の両方で送り返す。

設定上の注意が 2 点ある:

- TLS 終端プロキシの背後では `HTTP_TRUST_PROXY` を設定する（`true` ではなく、プロキシのアドレスまたは CIDR レンジに）。設定しないと `req.protocol` は `http` と読まれる一方でブラウザは `Origin: https://…` を送るため、origin 側の判定がすべてのリクエストを拒否する。
- ログイン UI をプロバイダーと**別 origin** で配信している場合は、その origin を HOCON 設定の `session.csrf.trustedOrigins` に列挙する。列挙した origin はフェデレーショングラントの同意とデバイス検証にも回答できるので、クライアントの origin は決して載せない（federation-grants ADR の D7）。`http.cors.allowedOrigins` は CSRF 上の信頼を与えない — それが何を与えるかは [CORS](#cors) を参照。

### CORS

| 変数 | デフォルト | 説明 |
|---|---|---|
| `HTTP_CORS_ALLOWED_ORIGINS` | *（空 — CORS 無効）* | token、userinfo、revocation、discovery/JWKS の各レスポンスの読み取りを許可するブラウザ origin のカンマ区切りリスト |

このプロバイダーと別の origin から配信されるブラウザアプリ — `https://auth.example.com` のプロバイダーに対する `https://app.example.com` の SPA — は、その origin が `http.cors.allowedOrigins` に無い限り、token エンドポイントをまったく呼べない。設定すると、プロバイダーは、ブラウザがクロスオリジンで呼ぶ正当な理由のある 5 つのエンドポイントで preflight に応答し、`Access-Control-Allow-Origin` を付与する:

| エンドポイント | メソッド | 理由 |
|---|---|---|
| `/oauth/token` | `POST` | PKCE のコード交換と refresh — SPA が避けられない呼び出し |
| `/oauth/userinfo` | `GET`, `POST` | OIDC Core §5.3 が両方を定義している |
| `/oauth/revoke` | `POST` | RFC 7009 §2.1 — public client がサインアウト時に自分のトークンを失効させる |
| `/.well-known/openid-configuration` | `GET` | Discovery。ブラウザのクライアントライブラリが取得する |
| `/.well-known/jwks.json` | `GET` | 同上。`jwks.path` を上書きした場合はそれに従う |

`/oauth/introspect` と `/oauth/authorize` は意図的に**含めていない**。introspection はサーバー間通信で、既に public client を拒否しているため、ブラウザが使うことはあり得ない。`/authorize` は `fetch` ではなくトップレベル遷移であり、ブラウザがどこへ遷移してよいかについて CORS は関与しない。

```hocon
http.cors {
  allowedOrigins = ["https://app.example.com", "http://localhost:5173"]
}
```

または `HTTP_CORS_ALLOWED_ORIGINS=https://app.example.com,http://localhost:5173`。書き方はこの 2 通りで、どちらでもない値 — 数値、オブジェクト、真偽値。設定ファイルでしか書けない形 — は、origin なしとして読まれるのではなく、`http.cors.allowedOrigins` を示して起動時に失敗する。

このリストは `http` モジュールのセクションの一部で、デフォルトは `config/reference.conf` にある。`http` モジュールがそれを、信頼するホップとともに `httpSettings` スロットで core の CORS middleware に渡し、core は設定ではなくスロットを読む: `httpSettings` の provider が無い合成は CORS を組み込まない。

**照合は `Origin` ヘッダーとの文字列の完全一致である**。一致し得ない形はすべて、誰も許可しないまま設定に居座るのではなく、そのインデックスを名指しして起動時に失敗する。つまり: 末尾スラッシュ（`https://app.example.com/`）、明示的なデフォルトポート（`:443`）、パス、大文字のホストはいずれも不可で、**ワイルドカードも不可** — サブドメインの照合は無く、今後も提供しない。loopback ホスト（`localhost`、`127.0.0.0/8`、`[::1]`）を除き `https` が必須で、この例外は、フロントエンドの開発サーバーを証明書なしで動かせるようにするためのものである。

**credentials は決して許可しない。** プロバイダーは `Access-Control-Allow-Credentials` を送らないため、allowlist にある origin はこれらのレスポンスを読めるが、ブラウザのセッション Cookie は使えない。これは意図的である: ここでのクロスオリジン SPA は PKCE を使う public client で Cookie を必要とせず、一方でそうでなければ得られてしまう Cookie は `session` グラント — 認証済みのブラウザセッションをトークンと交換するもの — に届く。アプリがそのグラントを必要とするなら、same-origin で配信するか、前段に BFF を置くこと。

これら 5 つのルートのレスポンスは、CORS ヘッダーを持たないものも含めてすべて `Vary: Origin` を持つため、共有キャッシュがある origin のレスポンスを別の origin に渡すことはない。空リスト（デフォルト）では middleware 自体がマウントされない — ヘッダーも `Vary` も付かず、何も変わらない。

### Google フェデレーション

フェデレーションは core のものである: `core.federations`、各フェデレーションに到達する名前（`/session/oauth/federation/<name>`）をキーとする 1 つのマップ。各キーは、そのパスから名付けた変数 `CORE_FEDERATIONS_<NAME>_<KEY>` に束縛される。トップレベルに書いたマップ（`federations { ... }`）は、各キーの `core.federations` の下のパスを名指しして起動を拒否する。`FEDERATIONS_GOOGLE_*` や `FEDERATIONS_OIDC_*` の変数が単独で、または新しい名前と異なる値で設定されていると、どのモジュールを選ぶよりも前に拒否される。

| 変数 | デフォルト | 説明 |
|---|---|---|
| `CORE_FEDERATIONS_GOOGLE_ENABLED` | `false` | Google OAuth フェデレーションを有効化 |
| `CORE_FEDERATIONS_GOOGLE_CLIENT_ID` | — | Google OAuth クライアント ID |
| `CORE_FEDERATIONS_GOOGLE_CLIENT_SECRET` | — | Google OAuth クライアントシークレット |
| `CORE_FEDERATIONS_GOOGLE_CALLBACK_URL` | `http://localhost:3000/session/oauth/federation/google/callback` | Google OAuth コールバック URL |
| `CORE_FEDERATIONS_GOOGLE_ACCESS_TYPE` | 未設定（`offline`） | `offline`: サインインのたびに Google の同意画面を表示し、すべてのセッションがリフレッシュトークンを得る。`online`: 同意画面は初回のサインインだけで、リフレッシュトークンはまったく得ない。[federation-google](../../packages/federation-google/README.md#refresh-tokens-and-the-consent-screen) を参照 |

### OIDC フェデレーション（任意の OpenID Connect プロバイダー）

`config/application.conf` の `core.federations.oidc` に 1 つのインスタンスが同梱されている（`@o3co/auth-provider-federation-oidc`、#524）: Okta、Entra ID、Auth0、Keycloak、または自前のテナントを issuer で選ぶ。Discovery は起動時に実行され、失敗すれば起動を拒否する。Store に渡される identity は `oidc:<sub>` で、Store が知らない identity は 401 で拒否される — 何もプロビジョニングされない。

| 変数 | デフォルト | 説明 |
|---|---|---|
| `CORE_FEDERATIONS_OIDC_ENABLED` | `false` | OIDC フェデレーションを有効化 |
| `CORE_FEDERATIONS_OIDC_ISSUER` | — | issuer 識別子（https）。IdP が `iss` に書くものと完全に同じにする |
| `CORE_FEDERATIONS_OIDC_CLIENT_ID` | — | IdP に登録したクライアント ID |
| `CORE_FEDERATIONS_OIDC_CLIENT_SECRET` | — | クライアントシークレット（`client_secret_basic`）。`private_key_jwt` を使う場合は、代わりに設定ファイルで `privateKey` を設定する |
| `CORE_FEDERATIONS_OIDC_CALLBACK_URL` | `http://localhost:3000/session/oauth/federation/oidc/callback` | IdP がブラウザを戻す先 |

2 つ目の IdP は、`type = "oidc"` と独自のコールバックを持つ別のセクションにする:

```hocon
core.federations {
  okta {
    enabled = true
    type = "oidc"
    issuer = "https://dev-123.okta.com"
    clientId = ${OKTA_CLIENT_ID}
    clientSecret = ${OKTA_CLIENT_SECRET}
    callbackURL = "https://auth.example.com/session/oauth/federation/okta/callback"
    redirectAllowlist = ["https://app.example.com/welcome"]
  }
}
```

エントリの `type` が実装を指定する。`type` の無い `core.federations.google` は組み込みの Google フェデレーションである。`type = "oidc"` を付けると `google` という名前の汎用 OIDC インスタンスになり、組み込みモジュールは合成されない。

パッケージが受け付けるすべてのフィールド — `scopes`、`discovery` / `endpoints`、`privateKey`、`userInfo`、`idTokenSignedResponseAlg`、`clockToleranceSeconds` — は [パッケージの README](../../packages/federation-oidc/README.md) に記載されている。

### クライアントリポジトリ

| 変数 | デフォルト | 説明 |
|---|---|---|
| `ADAPTERS_CLIENT_REPOSITORY` | `yaml` | クライアントストアのバックエンド: `yaml`、または core の `yaml` の別名で `repositories.client.static.path`（デフォルトなし）を読む `static` |
| `REPOSITORIES_CLIENT_YAML_PATH` | `./config/clients.yaml` | YAML クライアントレジストリのパス |

レジストリはデプロイごとの設定である: `.gitignore` は `config/clients.yaml` を git から、`.dockerignore` はイメージから外し、本番の compose ファイルがそれをマウントする（[Docker](#docker) を参照）。

### ユーザーリポジトリ

| 変数 | デフォルト | 説明 |
|---|---|---|
| `ADAPTERS_USER_REPOSITORY` | `http` | ユーザーリポジトリのバックエンド: `http`、またはローカル作業用の `yaml`（core の `yaml` の別名 `static` は `repositories.user.static.path` を読み、デフォルトはない） |
| `REPOSITORIES_USER_YAML_PATH` | `./config/users.yaml` | `yaml` バックエンドが読む YAML のユーザーファイル |
| `REPOSITORIES_USER_HTTP_AUTHENTICATE_URL` | — | パスワード認証用のユーザー認証 URL。**https 必須**（下記参照） |
| `REPOSITORIES_USER_HTTP_AUTHENTICATE_BY_TOKEN_URL` | — | トークン認証用のユーザー認証 URL。**https 必須**（下記参照） |
| `REPOSITORIES_USER_HTTP_LINK_FEDERATED_IDENTITY_URL` | — | 任意。Store がフェデレーション identity を紐づける URL（#482）。フェデレーション開始ルートで `?link=1` を有効にする。**https 必須** |
| `REPOSITORIES_USER_HTTP_FIND_SUBJECT_BY_FEDERATED_IDENTITY_URL` | — | 任意。上流 identity の持ち主を Store が答える URL（#613、フェデレーショングラントの check 5）。設定した場合は、Store が cover する範囲を `repositories.user.http.federatedIdentityLookupCoverage`（HOCON）に宣言する。**https 必須** |
| `REPOSITORIES_USER_HTTP_MARK_MFA_ENROLLED_URL` | — | 任意。Store が MFA の登録の証人を保持する URL（MFA ADR の D12）。設定すれば、失われた要素ストアが最初の紐付けを開けない。そのとき Store は二つの認証 URL の両方で `mfaEnrolled` を返す。未設定なら、MFA が有効な起動で警告が出る（`mfa_enrollment_witness_unwritable`）。**https 必須** |
| `REPOSITORIES_USER_HTTP_BEARER_TOKEN` | — | 任意。このサーバーが Store に提示する資格情報: Store へのすべてのリクエストが `Authorization: Bearer <token>` を持つ。32 バイト以上の素のトークン（`Bearer ` の接頭辞なし）— `openssl rand -hex 32`。未設定なら `Authorization` ヘッダーは送らない（下記参照） |
| `REPOSITORIES_USER_HTTP_TIMEOUT` | `5000` | HTTP リクエストタイムアウト（ミリ秒）。`2147483647` 以下の正の整数 |
| `REPOSITORIES_USER_HTTP_MAX_RESPONSE_BYTES` | `1048576` | 上流レスポンスボディの受け入れ上限（バイト） |

ユーザー認証 URL は 2 つとも上流ストアへ**平文のユーザー資格情報**を運ぶため、いずれも絶対 `https://` URL でなければならない。`http://` は loopback ホスト（`localhost`、`127.0.0.0/8` 内のアドレス、`[::1]`）に限って許可され、ローカル開発で証明書を用意せずに済むようにしている。プライベートレンジのアドレス（`http://10.0.0.5/…`）やコンテナネットワークのサービス名（`http://user-service/…`）には依然として `https://` が必要 — これらはデプロイが端から端まで制御していないネットワークを越えるため。URL のどちらか、タイムアウト、レスポンス上限のいずれかが使えない値なら、最初のログイン時ではなく起動時に失敗する。

各 URL には、リダイレクトするエンドポイントではなく応答するエンドポイントを設定する: どのリクエストも `3xx` を追わないので、リダイレクトする URL ではすべての呼び出しが失敗する — [Store が自分で守るべきこと](../../packages/foundation/README.ja.md#store-が自分で守るべきこと) を参照。

**Store を誰が呼べるか。** トークンによるログインとアカウントリンクが送るものは秘密ではなく識別子なので、誰にでも応答する Store は、そこに届く者なら誰にでも、既知の ID をそのユーザーに解決し — あるいは任意のアカウントにリンクし — てしまう。`REPOSITORIES_USER_HTTP_BEARER_TOKEN` を設定し、Store は `Authorization` が `Bearer <そのトークン>` と正確に一致しないすべてのリクエストに、`401` と `WWW-Authenticate: Bearer error="invalid_token"`（または `403` と `error="insufficient_scope"`）を返す。一つのトークンが上のすべての Store の URL に送られるので、それらのエンドポイントは一つの信頼境界でなければならない。`ADAPTERS_USER_REPOSITORY=http` — このテンプレートのデフォルト — のもとでは、トークンが 32 バイトより弱い（`SESSION_STORE_SECRET` と同じ測り方）、形が誤っている、または空で export されている場合は起動に失敗する。トークンはこのサーバーが投げるどのエラーにも現れない。そのチャレンジがあれば、Store が受け付けないトークンはすべての Store 呼び出しで障害になる: ログインは `503 temporarily_unavailable` を返し、拒否された資格情報を示すエラーをログに出す（トークンは示さない）。federation-grants の接続も同じエラーを `federation_grant_callback_unavailable` としてログに出す。チャレンジの無い `401` や `403` は従来の意味を保つ — ログインでは「ユーザーが居ない」、`?link=1` のリンクでは拒否、federation-grants の ID の照会では他の `2xx` 以外と同じく障害 — ので、不一致はすべてのログインの失敗とすべてのリンクの拒否としてしか現れない。そして、ユーザーのパスワード誤りや拒否するリンクに `Bearer` チャレンジを付けてはならない。Store に届かない、完全な応答の前に接続を閉じる、または壊れた HTTP の応答を返す場合はそのようにログに出され、運ぶのはせいぜい通信のコード（`ECONNREFUSED`、`UND_ERR_SOCKET`、`ERR_SSL_WRONG_VERSION_NUMBER` など）だけで、通信が引用したものは決して含まない。トークンを使わない場合は、ネットワークポリシーかプラットフォームの相互 TLS で、このサーバーだけが Store に届くようにする。ローテーション、各呼び出し元がログに出すもの、Store が検査することは、同じ foundation README の節にある。

### コードリポジトリ

`adapters.codeRepository`（`ADAPTERS_CODE_REPOSITORY`）がリポジトリを選び、それぞれが自身のセクションを読む。Redis のものは `REDIS_CLIENTS_URL` が設定する共有接続の上で動くので、自身の URL やパスワードは持たない。

| 変数 | デフォルト | 説明 |
|---|---|---|
| `REDIS_CODE_REPOSITORY_DEFAULT_EXPIRES_IN` | `600` | `redis-code-repository.defaultExpiresIn`: Redis のリポジトリの認可コードのデフォルト有効期間（秒） |
| `REDIS_CODE_REPOSITORY_KEY_PREFIX` | `oauth:code:` | `redis-code-repository.keyPrefix`: Redis のリポジトリのキー名前空間（[Redis の名前空間](#redis-の名前空間) を参照） |
| `STANDALONE_IN_MEMORY_CODE_REPOSITORY_DEFAULT_EXPIRES_IN` | `600` | `standalone-in-memory-code-repository.defaultExpiresIn`: in-process のリポジトリのもの。正の整数（秒） |

`CLIENT_CODE_DEFAULT_EXPIRES_IN` と `CLIENT_CODE_KEY_PREFIX` はこれらとともに改名され、`CLIENT_CODE_ENDPOINT_URI` と `CLIENT_CODE_PASSWORD` は削除された。改名されたものが単独で、または新しい名前と異なる値で設定されていると、そして削除されたものが設定されていると、代わりに設定すべきものを名指しして起動に失敗する。

### フェデレーショントークンストア

セッションに代わって保持する上流 IdP のトークン（たとえば Google のリフレッシュトークン）。デフォルトは memory で、レプリカごとに分岐し、`CORE_DEPLOYMENT_MODE=multi` のもとでは拒否される。Redis ストアは `REDIS_CLIENTS_URL` で設定したソケットを共有し、保存時にレコードを暗号化するため、鍵が必要になる。

| 変数 | デフォルト | 説明 |
|---|---|---|
| `ADAPTERS_FEDERATION_TOKEN_STORE` | `memory` | フェデレーショントークンストアのバックエンド: `memory` または `redis` |
| `REDIS_FEDERATION_TOKEN_STORE_ENCRYPTION_KEY` | — | 保存時のレコード暗号化に使う AES-256-GCM 鍵: 32 バイト、base64 エンコード（`openssl rand -base64 32`）。下のモードが `allow-plaintext` でない限り、`redis` では**必須** |
| `REDIS_FEDERATION_TOKEN_STORE_ENCRYPTION_MODE` | `required` | `required` または `allow-plaintext`。平文は、config が production/staging 環境（`CONFIG_ENV` または `NODE_ENV`）によって選択された場合と、任意の環境での `CORE_DEPLOYMENT_MODE=multi` のもとでは拒否される。ただし `FEDERATION_TOKENS_ALLOW_INSECURE=1` も設定されている場合を除く — 開発専用 |

`ttl`（秒。上流のリフレッシュトークンの有効期間より大きくしておくこと）と #291 の `scanFallback` 移行フラグは、環境変数ではなく config レイヤーの `redis-federation-token-store` の下に置く。

### 同意ストア

ファーストパーティでないクライアントに対するエンドユーザーの同意と、同意ページが確認している間保留される `/authorize` リクエストを記録する場所（#527、#552）。1 つのスイッチで両方を配線する。デフォルトは `none` で、そのようなクライアントは拒否され、ファーストパーティのクライアントだけが受け付けられる。`memory` はレプリカごとに分岐し、`CORE_DEPLOYMENT_MODE=multi` のもとでは拒否される。`redis`（#561）は `REDIS_CLIENTS_URL` で設定したソケット上で両方を共有する。

| 変数 | デフォルト | 説明 |
|---|---|---|
| `ADAPTERS_CONSENT_STORE` | `none` | ファーストパーティでないクライアントのための同意ストア（#527）: `none`（そのようなクライアントは拒否される）、`memory`（単一レプリカ）、または `redis`（共有、#561） |

### フェデレーショングラント

上流 IdP のトークンのオフライン委譲（#593）: ユーザーは、あるクライアント — バックエンドやエージェント — が 1 つの上流 connection についてユーザーに代わってアクセストークンを取得してよいことに一度だけ同意し、クライアントは後から、ユーザー不在のまま HTTP でそれを取得する。グラントは**ログアウトを越えて残り**、資格情報の変更が subject-revocation service を通じてそれを終わらせる。デフォルトはオフで、オフなら何もインストールされない。ルートと各応答の意味は [パッケージの README](../../packages/federation-grants/README.md) に、各 IdP がリフレッシュトークンを発行する前に必要とするものは [`docs/offline-access.md`](../../packages/federation-grants/docs/offline-access.md) にある。

| 変数 | デフォルト | 説明 |
|---|---|---|
| `FEDERATION_GRANTS_ENABLED` | `false` | ルート、下記で選んだ 2 つのストア（選ぶまではなし）、subject-revocation service をインストールする |
| `FEDERATION_GRANTS_CONSENT_URL` | — | グラント用の、デプロイ側の同意ページ: パス、またはプロバイダーの origin 上の絶対 URL。デフォルトは無い — グラントの有効化はページが存在するという表明であり、無ければ起動を拒否する |
| `FEDERATION_GRANTS_IDENTITY_LOOKUP` | `required` | connect callback が、既に別のローカルユーザーに紐づいた上流アカウントを拒否するかどうか。`required` には、すべての connection の registration を cover するユーザーリポジトリが必要（下記）。`unsupported` はこの検査を行わないことを記録する |
| `ADAPTERS_FEDERATION_GRANT_STORE` | `none` | グラントの保存先: `none`（ストアなし。機能を有効にするとそれを名指しして起動が拒否される）、`memory`（1 レプリカ。再起動で失われ、全ユーザーが再接続する）または `redis`（共有ソケット） |
| `ADAPTERS_FEDERATION_GRANT_INTENT_STORE` | `none` | 取得フローの記録 — バックエンドが登録した intent、同意チャレンジ、connect トランザクション — の保存先: `none`（ストアなし。機能を有効にするとそれを名指しして起動が拒否される）、`memory`（1 レプリカ。再起動で失うのは進行中のフローだけ）または `redis` |
| `REDIS_FEDERATION_GRANT_STORE_ENCRYPTION_MODE` | `required` | `required` または `allow-plaintext`。`FEDERATION_TOKENS_ALLOW_INSECURE=1` でない限り、平文は production/staging と `CORE_DEPLOYMENT_MODE=multi` のもとでは拒否される |
| `FEDERATION_GRANTS_ALLOW_KEEP_ON_SUBJECT_REVOCATION` | `false` | subject 全体の失効に、確立済みのグラントを残すよう*求めて*よいかどうか。許可であって指示ではない |
| `REDIS_FEDERATION_GRANT_STORE_KEY_PREFIX` | `fg:` | Redis グラントストアのキー名前空間 |
| `REDIS_FEDERATION_GRANT_INTENT_STORE_KEY_PREFIX` | `fg:` | Redis インテントストアのキー名前空間。グラントストアのものと一緒に設定する。グラントストアのものを設定してこちらを既定値のままにすると、テンプレートは起動を拒否する |

機能自身の設定は `federation-grants {}` セクション、Redis グラントストアの設定 — 鍵リング、暗号化モード、prefix — は `redis-federation-grant-store {}` にある。**環境変数の形を持たないものが 2 つある** — リストは HOCON のものだからである: connection と、暗号鍵リング。デプロイ側が所有するレイヤー — たとえば `config/production.conf` — に書く:

```hocon
redis-federation-grant-store {
  encryptionKeys = [
    # The first key seals; every listed key opens. GRANT_KEY_2026_09 is a name
    # you choose (openssl rand -base64 32), not a template override.
    { id = "2026-09", key = ${GRANT_KEY_2026_09} }
  ]
}

federation-grants {
  connections {
    files {
      federation = "entra-files"   # an enabled core.federations.<name> of type "oidc", with an app registration of its own
      scopes = ["openid", "profile", "offline_access", "Files.Read"]
      boundary = "production"
      maxAccessTokenLifetime = 3600
      # The grant flow's own callback on this provider's origin — not the
      # federation's login callback.
      callbackURL = "https://auth.example/session/federation-grants/callback/files"
      allowScopeSubsets = false
      identityClaims = ["oid", "tid"]
    }
  }
}
```

**起動時に拒否されるもの**（ユーザーがフローの途中で出くわすのではなく、それぞれ名指しで）: 同意ページが無い；`callbackURL` の無い connection、有効になっていない federation 上の connection、または委譲 capability を持たないアダプターの federation 上の connection — それを持つのは汎用 OIDC アダプターだけなので、Google の connection は `type = "oidc"` の federation にする；`required` なのに connection の registration を cover しないユーザーリポジトリ；memory のユーザーセッションストアと並ぶ Redis のグラント（`ADAPTERS_USER_SESSION_STORES=memory` — グラントが、それを終わらせる境界より長生きしてしまう。compose ファイルは 2 つとも `redis` を設定している）；`encryptionMode = "required"` なのにリングに鍵が無い Redis グラントストア（memory ストアは何も封じないので鍵を必要としない）；`CORE_DEPLOYMENT_MODE=multi` のもとで、いずれかのストアが `memory`。

**ユーザーリポジトリ。** `required` のもとでは、起動時に各 connection の registration を cover するかをリポジトリに問い、connect callback は上流アカウントの持ち主をリポジトリに問う。テンプレートの `http` リポジトリはそれを Store に問う（#613）: `REPOSITORIES_USER_HTTP_FIND_SUBJECT_BY_FEDERATED_IDENTITY_URL` にエンドポイントを設定し、そのエンドポイントが cover するもの — registration ごとに 1 エントリ、Store の戦略が必要とする claim 付き — を HOCON レイヤーに宣言する:

```hocon
repositories.user.http.federatedIdentityLookupCoverage = [
  { provider = "entra-files", issuer = "https://login.microsoftonline.com/<tenant>/v2.0",
    clientId = "<the grants app registration>", requiredClaims = ["tid", "oid"] }
]
```

起動時にはすべての connection がこれと突き合わされる: registration が宣言されていない connection、または `identityClaims` に必須の claim が欠けている connection は名指しで拒否される。Store が実装する wire 契約 — そして「unlinked」と答えるために何を確認済みでなければならないか — は [foundation README](../../packages/foundation/README.md#the-identity-lookup-613) にある。起動時に Store は問われない。同梱の in-memory リポジトリはどの registration も cover しない。cover する Store が無い場合は `FEDERATION_GRANTS_IDENTITY_LOOKUP=unsupported` を設定する — 別のローカルユーザーが既に持つ上流アカウントを拒否しない、という記録された決定である。connection を 1 つも設定していなければ、何も要求されない。

**クライアントの登録。** `config/clients.yaml` で、グラントを保持してよい confidential クライアントには、要求してよい connection と、ブラウザを戻してよい先を列挙する。`allowedRedirectUris` も `firstParty` も、そのどちらも与えない:

```yaml
worker:
  tokenEndpointAuthMethod: "client_secret_basic"
  clientSecret: "$2b$10$…"
  allowedFederationGrantConnections: ["files"]
  federationGrantRedirectUris: ["https://worker.example/connected"]
```

**クライアント側から見たフロー。** `POST /oauth/federation-grants`（クライアント認証付き）は `sub` に対する intent を登録し、`grant_id` と `connect_uri` を返す。クライアントはユーザーのブラウザをそこへ送る。プロバイダーは必要ならユーザーをサインインさせ、デプロイ側の同意ページを見せ、上流へ送り、`grant_id` と `state` を付けてブラウザをクライアントの `redirect_uri` に戻す — トークンは決して載せない。その後クライアントは、自身の資格情報とユーザーの `sub` を使い、ユーザー不在のまま `/oauth/federation-grants/:grantId/token`、`/status`、`/revoke` を呼ぶ。

**同意ページ**はデプロイ側のもので、プロバイダーと same-origin であり、その契約は `/oauth/consent` のものと同じなので、1 つのページで両方を担える。`GET /session/federation-grants/consent?challenge=…` は JSON を返す: `client_id`、`client_name`、`connection`、`scopes`、`resource`、`grant_expires_in`（承認後の期間であって日付ではない）、`continues_after_logout`（ページが必ず表示すること）、`expires_in`（フローの残り時間）。`challenge` と `decision`（`accept` | `deny`）を付けた `POST` は `303` を返す — 上流へ、またはクライアントへ戻す。取得も更新もすべてここを通る。回答は session モジュールの CSRF ポリシーに照らされる: ページからフォームで POST し、ページは `Referrer-Policy: same-origin` で配信する — `no-referrer` ではない（ヘッダー、`<meta name="referrer">`、フォームの `rel="noreferrer"` のいずれによるものも）。その下ではブラウザが `Origin: null` を送り、回答は拒否される。このアプリの `helmet()` はすべての応答に `no-referrer` を付けるので、このアプリが配信するページは自身のルートで `Referrer-Policy: same-origin` を付ける。プロキシの背後では `HTTP_TRUST_PROXY` がそのプロキシを指し、プロキシは `X-Forwarded-Proto` と `X-Forwarded-Host` を転送する（またはブラウザの `Host` を保つ）。`Origin` も `Referer` も送らないユーザーエージェントは、`POST /session/login` と同じく `GET /session/csrf` が渡すトークンを送り返す。トークンはどちらも送られないときにだけ効くので、ページはいつでもトークンを含めてよい。規則はパッケージの README にある。

**ログインページ**は `SESSION_LOGIN_PAGE_URL` が指すもので、`redirect_to=<the connect link>` 付きで到達する。ユーザーをサインインさせ、`/oauth/authorize` の場合と同様に、そのリンクへそのまま戻る。そのリンクを `POST /session/login` の `redirect_to` として送信してはならない: そのルートの完全一致 allowlist はランディングページ用で、フローごとの handle は拒否する。

**運用。** 鍵リングは [オペレーター runbook](../../docs/operator-runbook.md) の手順でローテーションする — 新しい鍵をまず末尾に、次に先頭に置き、古い鍵は 365 日残す。この機能が有効な間、シャットダウンは cleanup に 45 秒を与え（`upstreamHardTimeoutMs`、`persistRetryBudgetMs`、`lockWaitMs` を上げればそれより長くなる。allowance はそれらの合計に余裕を加えたものだからである）、compose ファイルは 2 つともプロセスに 60 秒を与える。[シャットダウンの保証](#シャットダウンの保証) を参照。機能の無効化は失効ではない: グラントは失効させるまで Redis に残るので、先に終わらせること。また一時的な停止の間も、鍵と失効境界は保持しておくこと。

### Redis の名前空間

マルチテナントの Redis クラスターでは、2 つの auth.provider インスタンスが同じデータベース内で衝突しないよう、デプロイ固有のキー prefix を設定する:

| 変数 | デフォルト | 説明 |
|---|---|---|
| `REDIS_SESSION_STORES_KEY_PREFIX` | `ss:` | ユーザーセッション、RP レジストリ、session-family インデックス、session-federation インデックスの外側の prefix。 |
| `REDIS_REFRESH_TOKEN_FAMILY_STORE_KEY_PREFIX` | `rtfam:` | refresh token family レコードの prefix。 |
| `REDIS_CODE_REPOSITORY_KEY_PREFIX` | `oauth:code:` | OAuth 認可コードの prefix。 |
| `REDIS_FEDERATION_TOKEN_STORE_KEY_PREFIX` | `ft:` | フェデレーショントークンのレコード、そのセッションごとのインデックス、およびそのロックキーの prefix。 |
| `REDIS_CONSENT_STORE_KEY_PREFIX` | `consent:` | 同意レコードと、保留中の同意リクエストおよびそのセッションごとのインデックスの prefix（`ADAPTERS_CONSENT_STORE=redis`、#561）。 |

デプロイ名を含む値を使う。たとえば `tenant-a:ss:`、`tenant-a:rtfam:`、`tenant-a:code:`、`tenant-a:ft:`、`tenant-a:consent:`。

### エンドポイント

| 変数 | デフォルト | 説明 |
|---|---|---|
| `SESSION_LOGIN_PAGE_URL` | `/login` | ログインページの URL（リダイレクト用） |
| `OAUTH_CONSENT_PAGE_URL` | `/consent` | ファーストパーティでないクライアントが経由させられる同意ページの URL。`?challenge=<id>` 付きで遷移する（#527） |

デプロイ全体で共通のクライアント URL やコールバック URL は無い: フェデレーションのコールバック URL はフェデレーションごとに設定する（`CORE_FEDERATIONS_GOOGLE_CALLBACK_URL`、`CORE_FEDERATIONS_OIDC_CALLBACK_URL`）。

## モジュール合成順序

どのモジュールをどの順序で合成するかについては、[`src/buildModules.mts`](src/buildModules.mts) が唯一の信頼できる情報源である — そのコピーではなく、それ自体を読むこと。boot planner は `requires` / `provides` をトポロジカルに解決するが、ルートとミドルウェアは、モジュールが `before` / `after` を宣言しない限りリストの順にマウントする — したがって、何かをマウントするモジュールでは位置が意味を持つ。リストを編集するときに守るべきルールは次のとおり:

1. **`sessionStoreModuleFor(config)` は先頭のままにする。** これは `express-session` の middleware をマウントし、`before` / `after` を宣言しないため、`req.session` を読むすべてのルートより前に来るのは、リスト内の位置のおかげである。`config` から組み立てるのは、`session-store.storage.type = "memory"` が自らを replica-unsafe と宣言するようにするためである。
2. **`/oauth` の下では順序は関係しない。** `federationGrantsModules`（フェデレーショングラントが有効な間）、`oauthModule`、独自のモジュールは、いずれも `/oauth` の下にルートをマウントしうる。`oauthModule` のルーターが body をパースするのは自身のルートだけなので、各モジュールへのリクエストは、リストの順に関係なくそのモジュール自身の parser に届く — ただし、`/oauth` 配下のどのモジュールも自分の body を自分でパースし、その parser を自分のパスちょうどに限定している場合に限る（同梱のモジュールはそうしている）。限定はルートとして行う（`router.all(path, parser)` か、ルート自身のハンドラ列）。`router.use(path, parser)` は `path` の下のすべてのパスにもマッチする。フェデレーショングラントのブラウザ側の半分は、自身の `after` によってセッション middleware の後ろに自らを並べる。
3. **ストアスロット 1 つにつきモジュール 1 つ。** 各アダプタースイッチ — `adapters.federationTokenStore`、`adapters.userSessionStores`、`adapters.rateLimiter`、`adapters.codeRepository`、`adapters.accessTokenDenylist`、`adapters.replaySeenSet`、`adapters.consentStore`、およびフェデレーショングラントの 2 つのストアスイッチ — は、memory / Redis の組から 1 つを選ぶ。両者は同じスロットを提供するため、両方を配線すると起動時のスロット衝突になる。`adapters.consentStore = "none"` はどちらも配線せず、フェデレーショングラントのストアは機能が有効な間だけ配線される。
4. **共有 Redis 接続は、最初の Redis バックエンドのモジュールとともに加わる。** `standaloneRedisClientsModule` は、ここにあるすべての Redis アダプターが使う 1 本の ioredis 接続を自身のセクション（`redis-clients`）から開き、合成されたモジュールがそれを必要とするときには必ず追加される。同梱の合成では refresh token family ストアが Redis 上にあるため、デプロイには常にこれがある。in-memory の family ストアはテスト用の override（`overrides.refreshTokenFamilyModules`）である。
5. **テンプレート自身の設定モジュールは常に合成される。** `loggingModule` と `httpModule` は `logging {}` と `http {}` を所有し、CORS のリストは `http` のキーの一つ（`http.cors.allowedOrigins`）である。`httpModule` は core の `httpSettings` を提供する。これは authoritative なので、モジュールが読み込まれている間は `overrideComponents` のエントリで置き換えられない。`httpModule` はさらに、`app.mts` が boot の後にポートと readiness の期限を読むテンプレートの `httpHostSettings` を提供する。logger はモジュールではなく、boot の前に `logging` セクションから作られ（`readLogging`）、`logger` コンポーネントとして boot に渡される。
6. **フェデレーションアダプターは、その config bridge とともに加わる。** `googleFederationModule` には `googleFederationConfigModule` が伴い — これは有効化され、かつ `type` が `google` である `core.federations.google` エントリに対してのみで、そのため `google` という名前の `type = "oidc"` セクションが二重に合成されることはない — 有効化された `type = "oidc"` のセクションごとに 1 つずつの `oidcFederationModule(name)` には、それらが共有する 1 つの `oidcFederationConfigModule` が伴う。bridge の provider は対応するセクションが無いと throw するため、この組は内部でゲートされるのではなく、合成時に含めるかどうかが決まる。
7. **メール送信者は環境に従う。** 設定が `development` として選ばれたところでは `@o3co/auth-provider-standard` の開発用送信者で、これは各コードをログに書く。そのモジュールは、その名前と、設定されていれば `CONFIG_ENV` と `NODE_ENV` のそれぞれが `development` か `test` であるところでだけ入り、それ以外のところ、または `core.deployment.mode` が `multi` のところでは起動を拒否する。それ以外の名前では SMTP 送信者のモジュールで、そのセクションは `standard-smtp-mail-sender`（[パッケージの README](../../packages/standard/README.md)）。その送信者は `mailSender` スロットを何かが読むところでだけ作られ、そこでは起動に `STANDARD_SMTP_MAIL_SENDER_HOST` と `STANDARD_SMTP_MAIL_SENDER_FROM` が要る。このテンプレートが合成するものでメールを送るものは無い: `mailSender` スロットを読むのは MFA パッケージで、テンプレートはそれを入れていないので、それらが無くても起動する。独自の送信者はこの選択を置き換える: [`src/app.mts`](src/app.mts) が `buildModules` を呼ぶところで、そのモジュールを `buildModules(switches, { environment: env, logger, mailSenderModules: [mySenderModule] })` のように渡す。`mailSenderModules` を渡すと、どの環境名でもそれが入り、同梱の送信者は入らないので、両方がスロットを提供することは無い。空のリストを渡すと送信者は入らず、送信者を必要とするモジュール（MFA のメール要素、または `requireEmailProof = "always"` の MFA モジュール）は起動を拒否する。

`jwksModule`（core 由来）は常に合成される: トークンに署名するプロバイダーは、issuer が設定されているかどうかにかかわらず検証鍵を公開する。各ルートモジュールが何をマウントするかは、それぞれのパッケージの README にある。合成時に知っておくべき振る舞いが 1 つある: `sessionModule` の `POST /session/logout` は `UserSession` レコード（これにより `/oauth/introspect` と `/oauth/userinfo` はそのセッションから発行されたトークンを受け付けなくなる）、subject インデックス、フェデレーションのエントリを削除する — しかし refresh token family は失効させ**ない**。完全なカスケードを実行するエンドポイントは `POST /oauth/logout` である。[どのログアウトエンドポイントが何を無効化するか](../../docs/operator-runbook.md#which-logout-endpoint-invalidates-what) を参照。

## 組み込みルート

`src/routes.mts` はこれらを、合成された auth ルーターより前にホストアプリへマウントする。そのため auth パイプラインが劣化している間も応答し続ける — オペレーターがこれらを必要とするのはまさにそのときである。そしてそれらすべての後ろに core の終端のエラーハンドラーをマウントするので、これらのルートが通してしまったエラーは auth のルートと同じく答えられる（`500 server_error`、`unhandled_request_error` として 1 回ログに出す）。JWKS ルートはこれらに含まれない: それは `jwksModule` が提供する（上記参照）。

| メソッド | パス | 説明 |
|---|---|---|
| `GET` | `/_healthcheck` | liveness — Redis の状態にかかわらず、プロセスが起動していれば常に `200 {"status":"ok"}`。[ヘルスエンドポイント](#ヘルスエンドポイント) を参照 |
| `GET` | `/readyz` | readiness — 登録されたすべての依存先 probe（`redis`、`session-store`、…）を `HTTP_READINESS_TIMEOUT_MS` のもとで実行する。`200 {"status":"ready"}` または `503 {"status":"unready"}` で、キャッシュされることはない |
| `GET` | `/metrics` | Prometheus のテキスト exposition。依存先の gauge はスクレイプのたびに probe し直される。公開 listener には置かないこと — [メトリクス](#メトリクス) を参照 |

## Docker

Dockerfile はマルチステージビルドを使い、以下のターゲットを持つ:

| ターゲット | 用途 |
|---|---|
| `runtime` | 本番イメージ（コンパイル済み JS のみ） |
| `develop` | ホットリロード付き開発イメージ（`pnpm run debug`） |
| `test` | テストランナーイメージ |

```bash
# 本番イメージをビルド
make build IMAGE=my-auth-provider

# docker compose で起動（開発用）
make dev

# Docker でテストを実行
make test
```

`docker-compose.yml` は認証サーバーと Redis コンテナをまとめて起動する。環境変数は `.env` で設定する。

`docker-compose.yml` は**開発用**のファイルである: `develop` ターゲットをビルドし、`./src` と `./config` を bind-mount するため、そのままデプロイすると working tree を動かす hot-reload サーバーを配信することになる。デプロイ可能な形は [`docker-compose.production.yml`](docker-compose.production.yml) である — `runtime` ターゲット、ソースのマウントなし、restart policy、ネットワーク内部限定の永続 Redis、そして**必須**の `.env`（実際の `SESSION_STORE_SECRET` の無い起動ははっきりと失敗しなければならない）。意図的に利用者に委ねている範囲 — 前段での TLS 終端と、`--scale` の前の [マルチレプリカ](#マルチレプリカ構成) 手順 — は、ファイル冒頭のコメントに記載している。

そこでは `HTTP_TRUST_PROXY` は明示的な `${HTTP_TRUST_PROXY:?…}` エントリになっているため、`.env` でホップを指定するまで `docker compose up` は**起動を拒否する**。これは意図的である: ファイルがデフォルトにできるアドレスで、自分が選んでいないホップを黙って信頼しないものは存在しない。そしてこの変数が無いと、ファイルが固定している Secure Cookie は一度もセットされず、CSRF の origin チェックはブラウザからのすべての POST を 403 にし、IP をキーとするすべての rate limit が 1 つのバケットを共有する。

レコードが 1 プロセスより長く生き残らなければならないストアは、継承に任せるのではなく、すべてそのファイルの `environment:` ブロックで名指しされている — `SESSION_STORE_STORAGE_TYPE=redis` と必ずセットで設定しなければならない `ADAPTERS_USER_SESSION_STORES=redis` も含めて。両者が揃っていないとき、`CORE_DEPLOYMENT_MODE=single` はそれを教えてくれない: レプリカガードが答えるのは「これらのストアは共有できるか」であって、「この 2 つのストアは同じ寿命を持つか」ではない。両者を分けると、再起動後にすべてのブラウザが、生き残った express-session — 背後に `UserSession` が無いのにまだ `isAuthenticated` と読めるもの — を保持したままになる。`/authorize` はログインへ飛ばし、Cookie がそれを送り返し、このループはユーザーが Cookie を削除するまで解消しない。

```bash
# 署名鍵は必須の入力である。デフォルトは EdDSA で鍵素材のデフォルト値は存在しないため、
# 鍵を生成していないデプロイは起動時に失敗する。
openssl genpkey -algorithm ed25519 -out jwt-private.pem
openssl pkey -in jwt-private.pem -pubout -out jwt-public.pem
chmod 600 jwt-private.pem

# クライアントレジストリも必須の入力: scaffold の config/clients.yaml か、
# config/clients.yaml.example から作ったもの。

docker compose -f docker-compose.production.yml up -d --build
```

**コンテナ内の鍵。** pem のペアは compose の **secret** としてコンテナに届き、`/run/secrets/` に read-only でマウントされ、compose ファイルが `KEY_STORE_LOCAL_*_KEY_PATH` をそこに向ける。`config/` に置いてはならない: `Dockerfile` はこのディレクトリを `COPY` する。`.dockerignore` は、`.gitignore` が git から外すのと同じく、すべての `*.pem` と `*.key` をビルドコンテキストから外すが、それ以外の名前でそこに置いた鍵はイメージレイヤーに焼き込まれ、push のたびに一緒に運ばれる — 保管場所を誤っただけの鍵ではなく、ローテーションしなければならない鍵になる。`.env` も同様である。どちらも git の外に置くこと。

**コンテナ内のクライアントレジストリ。** `config/clients.yaml` も同じ経路で、compose の secret `client_registry` として届き、`REPOSITORIES_CLIENT_YAML_PATH` がそこを指す。これはデプロイごとのもので、クライアントのシークレットを含みうるため、`.dockerignore` がビルドコンテキストから外す: どのイメージもレジストリを持たず、作業コピーからビルドしたイメージと clean checkout からビルドしたイメージは同じになる。ファイルが存在するまで compose は起動を拒否する。別の方法でイメージを動かすなら、自分でマウントして `REPOSITORIES_CLIENT_YAML_PATH` を設定する。

production ファイルは `environment:` ブロックで `SESSION_STORE_SECURE=true` と `__Host-` の Cookie 名も固定しており、これは `env_file` より優先される。`.env.example` は plain-HTTP の compose 実行（`make dev`）が `__Host-` Cookie の検査に引っかからないよう `SESSION_STORE_SECURE=false` を同梱しており、このファイルはその同じ `.env` を要求する — このファイルが前提とする TLS の背後では、非 Secure のセッション Cookie は、平文区間を 1 つでも読める相手にセッションを渡すことに等しい。

イメージは `pnpm install --frozen-lockfile` でインストールするため、コミット済みの `pnpm-lock.yaml` がビルドの必須入力である — `create-auth-provider` が scaffold 時に生成する。手元に無い場合は一度 `pnpm install` を実行して結果をコミットすること。これにより、同じソースからのリビルドは同じ依存ツリーを生む。

本番イメージは `ENV HTTP_PORT=3000` を設定し、それを `EXPOSE` と、`/_healthcheck` に対する Docker ネイティブの healthcheck の両方に使う。HOCON 設定も `http.port` に `${?HTTP_PORT}` を読むため、リスナーと healthcheck がずれることはない。別のポートで動かすには:

```bash
docker run -e HTTP_PORT=8080 -p 8080:8080 my-auth-provider
```

`EXPOSE` はイメージのメタデータであり、それだけではポートを公開しないため、明示的な `-p` マッピングが引き続き必要である。

### ヘルスエンドポイント

2 つのルートが、それぞれ異なる問いに答える。どちらも auth ルーターより前にホストアプリへマウントされるため、auth パイプラインが劣化している間も応答し続ける。

| ルート | 問い | 答え |
|---|---|---|
| `GET /_healthcheck` | プロセスは起動しているか？ | 常に `200 {"status":"ok"}` |
| `GET /readyz` | このレプリカは今リクエストを処理できるか？ | `200 {"status":"ready", …}` または `503 {"status":"unready", …}` |

それぞれ別の probe に使う:

```yaml
livenessProbe:
  httpGet: { path: /_healthcheck, port: 3000 }
readinessProbe:
  httpGet: { path: /readyz, port: 3000 }
```

liveness を `/readyz` に向けるのは避けるべき誤りである: そうすると Redis のネットワーク分断が壊れたコンテナのように見え、Kubernetes はすべてのレプリカをループで再起動する。それで再接続されるものは何も無く、インシデントにコールドスタートが加わるだけである。Redis を失うことは、レプリカへの*ルーティング*を止める理由であって、レプリカを kill する理由ではない。

イメージの `HEALTHCHECK` が `/_healthcheck` を probe するのも同じ理由による。Docker が持つ health シグナルはちょうど 1 つで、Swarm や ECS では unhealthy なコンテナは停止されて置き換えられる — そのためこれを `/readyz` につなぐと、Kubernetes 以外のすべての orchestrator で再起動ループが再び生じる。`depends_on: condition: service_healthy` に「alive」ではなく「ready」を意味させたいなら、イメージを変更するのではなく、compose ファイルでその 1 つのサービスの `healthcheck:` を上書きすること。

`/readyz` はバックエンド接続ごとに 1 つの probe を実行し、それぞれを名前付きで報告する:

```json
{
  "status": "unready",
  "checks": [
    { "name": "redis", "ok": true, "durationMs": 2 },
    { "name": "session-store", "ok": false, "durationMs": 1001 }
  ]
}
```

失敗の*理由*は意図的にボディから除いてあり、代わりにログに出る（`readiness_probe_failed`、チェックごとの完全な詳細付き）。ドライバーのエラーは `connect ECONNREFUSED 10.0.3.14:6379` — 内部のホストとポート — のように読め、しかもこのエンドポイントは、orchestrator が提示できる資格情報を持たないため未認証である。`createReadinessRouter` に `includeErrorDetail: true` を設定するのは、エンドポイントがデプロイの内側からしか到達できない場合に限ること。

同じ理由で、`/readyz` は公開 listener に置かないこと。auth ルーターより前にあるためそのルーターの rate limiter の外にあり、各リクエストは、まさに報告対象の依存先に対して probe ごとに 1 コマンドを発行する — 匿名のリクエストループがインシデント中に負荷を上乗せするには十分である。内部ネットワーク、管理用 listener、または ingress の内部専用パスルールにバインドすること。

probe は接続を開いた builder が登録するため、リストはこのデプロイが実際に配線したものを反映する: Redis アダプターが選択されていれば共有 ioredis クライアント（`redis`）と connect-redis のセッションクライアント（`session-store`）、Redis をバックエンドとするモジュールを持たない構成では**何も無い** — その構成は unready になる原因となる依存先が無いので、常に ready になる。同梱の構成はそうはならない: refresh token family は常に Redis にあるので、`redis` は常に probe される。

`http.readinessTimeoutMs`（環境変数 `HTTP_READINESS_TIMEOUT_MS`、デフォルト `1000`）は probe ごとの deadline である。orchestrator 自身の probe タイムアウトより小さくしておくこと。さもないと、到達できない依存先が、unready なレプリカではなく遅いレプリカとして読まれてしまう。

## カスタムモジュールの追加

カスタムモジュールを追加するには、`src/buildModules.mts` でインポートし、`buildModules` が返す配列に追加する。boot planner は依存関係をモジュールが `require` / `provide` するものによって解決するが、ルートとミドルウェアは、`before` / `after` の指定が無い限りリストの順にマウントする。したがって、他のルートが依存する middleware では位置が意味を持つ — セッションストアモジュール、[モジュール合成順序](#モジュール合成順序) のルール 1 である。`/oauth` のように別のモジュールも使うプレフィックスの下のルートは、自分の body を自分でパースし、その parser を自分のパスちょうどに限定する限り、特定の位置を必要としない（ルール 2）: `oauthModule` のルーターがパースするのは自身のルートの body だけで、プレフィックス配下のすべてのリクエストに走る parser は、他のモジュールの body を代わりに読んでしまう。前者のようなものをマウントしないモジュールは末尾に置けばよい:

```diff
 // src/buildModules.mts
+import { myCustomModule } from "./my-custom-module.mjs";
 …
 	return [
 		sessionStoreModuleFor(config),
 		…
 		...(federationGrantsEnabled ? [subjectRevocationServiceModule] : []),
+		myCustomModule,
 	];
```

そこにある他のルールも守ること: セッションストアモジュールは先頭のままにし、ストアスロットを埋めるモジュールは、そのスロットのアダプタースイッチの横に追加するのではなく、スイッチを置き換える。[`src/app.mts`](src/app.mts) は変更不要である: `buildModules(config, …)` を `createApp` に渡し、`createApp` が返すルーターをマウントし、サーバーのライフタイムを配線している — `installGracefulShutdown`（下記）がサーバーを drain し、`handle.dispose()` を呼ぶ。例外は独自のメール送信者で、これはリストに足すのではなく、その呼び出しの `mailSenderModules` override から入れる（ルール 7）。リストに足すと、同梱の送信者と `mailSender` スロットで衝突する。

セッション要件を寄与するモジュール — MFA パッケージの `mfa`、あるいは自前のもの — は「ログイン済み」の意味を変えるので、その名前を `core.sessionRequirements.expected` に書く。`config/application.conf` はこれを `[]` として出荷する: テンプレートは何も組み込まない。boot はこのリストをモジュールが登録したものと比較する。リストにあって何も登録しない名前はブートを拒否し（`session-requirement-missing`）、登録された要件をリストが書き漏らしても拒否する（`session-requirements-undeclared`）。`mfa.mode`（`MFA_MODE`）が `off` でないとき、テンプレートはリストに `mfa` を加える（`expectedSessionRequirements`、[`src/configPath.mts`](src/configPath.mts)）。書いた名前はそのまま残る。テンプレートは MFA モジュールを組み込まないので、そのようなモードはパスワードだけでログインを通すのではなく、ブートを拒否する（`session-requirement-missing`）。3 つのどれでもないモードは、ブートの前に `mfa.mode` を名指して拒否する。テンプレートは MFA モジュールを組み込むまで（MFA ADR のビルド順のステップ 20）、モジュールを選ぶ前にこのモードを自ら読む。追加したモジュールが `mfa` を登録しても、その要件が MFA パッケージのもののように第二要素の権限（second-factor authority）を宣言していなければ宣言を満たさず、テンプレートは listen の前にブートを拒否する（`MfaRequirementNotAuthorityError`、[`src/secondFactorAuthority.mts`](src/secondFactorAuthority.mts)）。

### シャットダウンの保証

`src/shutdown.mts` は意図的に、依存パッケージではなく scaffold の一部にしてある（#290）: すべてのユーザーセッションを終端するコンポーネントについて、*「SIGTERM は in-flight リクエストを待つのか、待つならどれだけの時間か？」*という問いには、デプロイするコード自体から答えられなければならないためである。

1. **`SIGTERM` と `SIGINT`** のどちらでも開始する。2 回目のシグナルは、1 回目の dispose が扱っているストアに重ねて 2 回目の dispose を始めるのではなく、無視される。
2. **新規接続は即座に停止**し、idle な keep-alive ソケットは解放される — これらは背後にリクエストの無いままサーバーを開いたままにするため、解放しなければ、閑散としたサーバーが deadline 全体を無駄に待つことになる。
3. **in-flight リクエストには `drainTimeoutMs`**（デフォルト **10 秒**）が与えられ、その間に完了する。
4. **deadline を過ぎると残りの接続は切断され、プロセスは非ゼロで終了する。** 常に `0` しか見ない orchestrator には、正常な drain と時間切れになった drain を区別できない。
5. **`cleanup` は drain の後、終了の前に実行される** — `handle.dispose()`、すなわち逆トポロジカル順のコンポーネント cleanup と Redis／タイマーの drain である。そこでの失敗はこのサービス自身の logger（他のすべての行と同じ NDJSON）で `shutdown_cleanup_failed`（または `shutdown_cleanup_timed_out`）としてログに出力され、終了コードにも反映される。各段階はそれぞれ 1 つのイベントである（下の表を参照）。throw した dispose でもプロセスは終了し、プロセスが固まることはない。その行が運ぶのは失敗の core の [`loggableError`](../../packages/core/README.ja.md#logger) による射影であり、エラーそのものではない: `dispose()` はすべての cleanup 自身のエラーをまとめた AggregateError で reject し、その行はそれぞれをコードとともに名前で示し（`aggregateErrors`、先頭 5 つ）、それが持つものは何も出さない — その中には失敗したストアへの書き込みが、書き込もうとしていた内容ごと含まれうる。

6. **`cleanup` には少なくとも、モジュールが登録した allowance が与えられる**: `handle.cleanupAllowanceMs` — モジュールが cleanup とともに登録した tail のうち最長のもの — を、`src/app.mts` が `installGracefulShutdown` に `cleanupAllowanceMs: () => handle.cleanupAllowanceMs` として渡し、シグナルが届いた時点で読む。cleanup の予算は、それと drain の 10 秒のうち長いほうであり、`shutdown_draining` がそれを `cleanupTimeoutMs` として記録する。1 から 2147483647 までの整数ミリ秒でない allowance は無視される。テンプレートはこれを決めるためにモジュールの設定を読まない。フェデレーショングラントが有効なら、パッケージは自分の drain の tail を `federation-grants.upstreamHardTimeoutMs` + `persistRetryBudgetMs` + `lockWaitMs` + 12 秒として登録し、45 秒を下回ることはない — 同梱の予算（25 + 3 + 5 + 12）ではちょうど 45 秒 — dispose が、ローテーションされた上流資格情報の書き込みを待つためである。予算を上げれば allowance もそれに応じて増えるので、orchestrator の grace もそれに合わせて上げること。無効なら、allowance を登録するものはなく、cleanup の予算は drain のものと同じままである。

各段階はそれぞれ 1 行をログに出す:

| イベント | レベル | フィールド |
|---|---|---|
| `shutdown_draining` | info | `drainTimeoutMs`, `cleanupTimeoutMs` |
| `shutdown_drain_deadline_exceeded` | error | `drainTimeoutMs` |
| `shutdown_server_close_failed` | error | `err` |
| `shutdown_cleanup_timed_out` | error | `cleanupTimeoutMs` |
| `shutdown_cleanup_failed` | error | `err` |
| `shutdown_complete` | info | `reason`、`drain`、`exitCode` |

`err` は `loggableError` による射影である。`drain` は drain がどう終わったか — `drained`、`drain-timeout`、`close-failed` のいずれか（閉じられなかったリスナーは正常な drain とはみなされず、非ゼロで終了する）。`reason` は `exitCode` を決めたもの — drain の結果、またはその後の cleanup が時間切れになったか throw したときの `cleanup-timeout` / `cleanup-failed` — なので、`reason: "drained"` が非ゼロのコードと並ぶことはない。

**`drainTimeoutMs` と `cleanupTimeoutMs` の合計が orchestrator の kill grace period を下回るようにすること。** Kubernetes の `terminationGracePeriodSeconds` はデフォルトで 30 秒、compose の `stop_grace_period` は 10 秒である。フェデレーショングラントが有効な場合の最悪値は drain（10 秒）+ cleanup（45 秒）= 55 秒なので、**grace は 60 秒以上に設定すること** — 同梱の compose ファイルはそうしてあり、Kubernetes のデプロイは自分で `terminationGracePeriodSeconds: 60` を設定しなければならない。さもないと、ローリング再起動のたびに、cleanup が完了させるためにある書き込みの途中でプロセスが SIGKILL される。目的は、他人の都合で `SIGKILL` が届く前に、自分の都合で閉じることである。

## npm スクリプト

| スクリプト | 説明 |
|---|---|
| `pnpm run build` | TypeScript を `dist/` にコンパイル |
| `pnpm run start` | コンパイル済みサーバーを起動 |
| `pnpm run debug` | `tsx watch` でホットリロード起動（開発モード） |
| `pnpm run test` | 型検査（`tsc --noEmit`）のあと、Vitest でテストを実行 |

## 関連

- [オペレーター runbook](../../docs/operator-runbook.md) — デプロイ形態と起動拒否、probe、各依存先の障害がどう見えるか、アラート対象のイベント、Redis のキーファミリーと障害のタイミング、鍵ローテーション、アップグレードとロールバック
- [`@o3co/auth-provider-core`](../../packages/core) — アプリケーションファクトリと設定スキーマ
- [`@o3co/auth-provider-oauth`](../../packages/oauth) — OAuth モジュール
- [`@o3co/auth-provider-session`](../../packages/session) — Session モジュール
- [`@o3co/auth-provider-foundation`](../../packages/foundation) — 組み込みアダプター登録
- [`@o3co/create-auth-provider`](../../create-app) — このテンプレートを生成する CLI スキャフォルダー

## 可観測性

### ログ

プロバイダーは [pino](https://getpino.io) を通じて stdout に改行区切りの JSON をログ出力する。これはログアグリゲーターがパーサーなしで取り込める形式である。`LOGGING_LEVEL`（HOCON では `logging.level`。`logging` モジュールのセクションで、boot の前にそのモジュールのスキーマで読む）が閾値を設定する。`trace` と `debug` はリクエスト単位の詳細を含み、デフォルトではオフである。pino は閾値未満の呼び出しをフォーマット前に捨てるため、出力されてから下流でフィルタされるのではなく、本番環境ではコストがかからない。

logger は boot planner の `logger` コンポーネントスロットに配線されるため、`optional: ["logger"]` を宣言するすべてのモジュール — oauth、session、dpop、mtls、token-exchange — はこの 1 つのインスタンスを通じてログを出す。`LOGGING_LEVEL` がそれらに届くのは、このスロットを埋めているからである。スロットを空のままにした composition root では、代わりに各モジュール自身のデフォルトの `consoleLogger` が使われ、レベルを設定しても何も変わらない。

イベントは構造化され、名前が付いている: `logger.error({ err }, "session_store_redis_error")`。アラートはメッセージ本文ではなく名前に対して設定すること。

バックエンドを差し替えるには、`src/logger.mts` の `createAppLogger` を置き換える。core の `Logger` を満たすものなら何でも動く — このインターフェースは pino の 2 つのオーバーロードを持つ呼び出し形なので、pino 互換の logger ならアダプターは不要である。

### 監査ログ

セキュリティに関わるイベント — 誰が認証したか、何が発行されたか、何が拒否されたか、rate limiter がいつ応答できなかったか — は、`adapters.auditSink`（環境変数 `ADAPTERS_AUDIT_SINK`）が指す sink に送られる。テンプレートは `"logger"` を同梱しており、これは他のすべてと同じ pino ストリームを通じて 1 行に 1 イベントを書き出す:

```json
{"level":30,"time":1787841564013,"name":"audit","audit":{"timestamp":"2026-08-27T14:39:24.013Z","type":"token.issued.failure","ip":"203.0.113.7","details":{"reason":"unsupported_grant_type"}},"msg":"token.issued.failure"}
```

出力形式は 1 つなので、アグリゲーターはアプリケーションログと監査イベントを 1 つのパーサーで取り込み、`name`（`"provider"` か `"audit"` か）で分けられる。イベント種別はメッセージでもあるため、`session_store_redis_error` の場合と同じように、名前 — `authorize.rejected`、`token.issued.failure`、`rate_limit.unavailable` — に対してアラートを設定すること。

`ADAPTERS_AUDIT_SINK=console` を指定すると、代わりに core の組み込み sink が選ばれる: ログのエンベロープ無しで、イベントそのものを 1 行に 1 つの JSON オブジェクトとして出す。イベントだけを必要とし、それ以外は要らないパイプライン向けである。

**`LOGGING_LEVEL` は監査ログの出力を左右しない。** 監査ストリームのレベルは `info` に固定されている。`warn` は本番では普通の設定であり、`silent` も正当な設定である。そのどちらかがこれを黙らせれば、ログの好みの設定のように見えながら、すべての認証と発行の記録を消してしまう。監査イベントの送り先は `adapters.auditSink` で選ぶ — そしてこのセレクターには **`"none"` が無い**。未知の sink は、監査ログの無いデプロイを生むのではなく、登録されている sink を名指しして起動を失敗させる。sink を意図して組み込まない合成は、core 自身のセクションで `core.declaredAbsent = ["auditSink"]` とそれを宣言する。このテンプレートは常に 1 つ組み込む。

実際の sink — SIEM、ログパイプライン、メッセージバス — に向けるには、`auditSinkModuleFor`（`src/modules.mts`）に builder を登録し、それを選択する。オプションは `audit-sink` モジュールのセクションに、sink の名前の下に書く:

```ts
factory.register("splunk-hec", (cfg) => createSplunkSink(cfg));
```

```hocon
adapters.auditSink = "splunk-hec"
audit-sink {
  splunk-hec { endpoint = ${?SPLUNK_HEC_URL}, token = ${?SPLUNK_HEC_TOKEN} }
}
```

設定した送り先と並べて監査の送り先を加えるには、自分のモジュールから `auditHooks` を寄与する。core は `auditSink` と `auditHooks` をまとめてファンアウトする。

sink は契約上 fire-and-forget である: core は await せずにディスパッチし、reject を握りつぶすため、遅い sink や失敗する sink が認証フローにレイテンシを加えたり、フローを失敗させたりすることはない。その裏返しとして、配信できない sink はイベントを落とす。sink が 1 つだけなら、その失敗は黙って握りつぶされる。モジュールが `auditHooks` を寄与していれば、ファンアウトが失敗した呼び出しをそれぞれ、sink の位置とイベントの `type` を添えて `audit_sink_failed` としてエラーレベルでログに出す。取りこぼしはまだカウントされていない — 下記「メトリクス」の **まだ公開していないもの** を参照。

### メトリクス

`GET /metrics` は Prometheus のテキスト exposition 形式を返す。

| メトリクス | 種類 | 何に答えるか |
|---|---|---|
| `http_request_duration_seconds` | histogram | リクエストレート、エラーレート、レイテンシ（`method` / `route` / `status` 別） |
| `auth_dependency_up` | gauge | バックエンドの各依存先が readiness probe に応答したかどうか（`dependency="redis"`、`"session-store"`） |
| `auth_provider_*` | 各種 | Node プロセスのデフォルト — イベントループの遅延、ヒープ、GC、ハンドル |

`auth_dependency_up` は「Redis が落ちた」と「アプリが遅い」を区別する系列であり、これが無ければコンテナログを grep しない限り区別できない。アダプターの builder が既に登録した probe を再利用するため、ずれていく第二のリストではなく、このデプロイが実際に配線したものを反映する。依存先はスクレイプのたびにサンプリングし直され — キャッシュされた判定は、インシデントが続いている間ずっと healthy と報告してしまう — 実行中の probe は再発行されずに合流されるため、スクレイプのループが、既に問題を抱えている依存先にコマンドを積み重ねることはない。

ルートのラベルには URL ではなく Express のルート**パターン**（`/oauth/token`、`/api/widgets/:id`）を使い、一致しないリクエストは `route="unmatched"` にまとめられる。パスでラベル付けすると異なる URL ごとに系列が生まれ、しかもこのサーバーのパスは不透明な値を含む — メトリクスエンドポイントが、自分を監視するはずの監視基盤を落としてしまうのは、このようにしてである。

スクレイプ設定の例:

```yaml
scrape_configs:
  - job_name: auth-provider
    static_configs:
      - targets: ["auth-provider:3000"]
```

`/readyz` と同じ理由で、`/metrics` は公開 listener に置かないこと: 未認証であり、auth ルーターより前にあるためその rate limiter の外にあり、スクレイプのたびに readiness probe をサンプリングする。

**まだ公開していないもの:** rate limiter の fail-closed の回数と、監査 sink の取りこぼし。どちらも `@o3co/auth-provider-core` の内部で起きるため、composition root からは観測できない。これらを数えるには、このテンプレートから手の届くものではなく、core 側のメトリクスフックが必要である。それまでは、`rate_limiter_failed_closed` と `rate_limit.unavailable` のログイベントに対してアラートを設定すること。
