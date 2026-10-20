# auth-provider

[![CI](https://github.com/o3co/auth.provider/actions/workflows/ci.yml/badge.svg?branch=develop)](https://github.com/o3co/auth.provider/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@o3co/create-auth-provider/next)](https://www.npmjs.com/package/@o3co/create-auth-provider)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

[English](README.md) | 日本語

auth-provider は、TypeScript で書かれた Node.js 向けのセルフホスト型 OAuth 2.0 認可サーバー兼 OpenID Connect（OIDC）プロバイダーです。必要な機能を選んでアプリを生成し、Node.js で実行するか、Docker イメージをビルドして利用します。

選んだ機能が依存するモジュールは、ジェネレーターが追加します。アプリは起動時に設定を検証し、見つかった問題を、設定名またはモジュール名とともにすべて表示します。

0.18 は、パッケージ名を変更して 0.17 を書き直したバージョンで、まだプレリリース段階です。0.18.0 の正式リリースまでは、npm の `next` タグを指定してインストールしてください。タグを省略すると 0.17 がインストールされます。既存の 0.17 環境を移行する場合は、まず[移行ガイド](docs/migration.md)を読んでください。既存環境をそのままアップグレードすることはできません。設定の書き直しが必要で、保存済みの状態も移行されません。

## 主な機能

ユーザーのログインとセッションを管理し、アプリケーションにトークンを発行します。署名鍵を管理し、トークンの検証と失効のためのエンドポイントも提供します。

| 機能 | 仕様 | モジュール |
|---|---|---|
| 認可コードフロー（すべてのクライアントで PKCE（S256）が必須） | RFC 6749, RFC 7636 | [authorize](modules/oauth/authorize/README.md), [code-grant](modules/oauth/code-grant/README.md) |
| リフレッシュトークン（使用するたびにローテーションし、再利用を検知） | RFC 6749 | [refresh](modules/oauth/refresh/README.md) |
| クライアントクレデンシャルグラント | RFC 6749 | [token-endpoint](modules/oauth/token-endpoint/README.md) |
| ID トークンと UserInfo | OpenID Connect Core 1.0 | [oidc](modules/oauth/oidc/README.md), [userinfo](modules/oauth/userinfo/README.md) |
| ディスカバリードキュメントと署名検証用の公開鍵（JWKS） | OpenID Connect Discovery 1.0, RFC 8414 | [discovery](modules/oauth/discovery/README.md), [keys](modules/foundation/keys/README.md) |
| RP 起点（クライアント起点）、フロントチャネル、バックチャネルのログアウト | OpenID Connect のログアウト関連仕様 | [rp-logout](modules/oauth/rp-logout/README.md) |
| トークンイントロスペクションと失効 | RFC 7662, RFC 7009 | [token-control](modules/oauth/token-control/README.md) |
| クライアントシークレットと `private_key_jwt` によるクライアント認証、クライアント認証なしのパブリッククライアント | RFC 6749, RFC 7523 | [clients](modules/identity/clients/README.md), [client-assertion](modules/oauth/client-assertion/README.md) |
| Client ID Metadata Documents（URL をクライアント ID として使用） | | [clients-cimd](modules/oauth/clients-cimd/README.md) |
| JWT ベアラーグラント | RFC 7523 | [jwt-bearer](modules/oauth/jwt-bearer/README.md) |
| Device Authorization Grant | RFC 8628 | [device-grant](modules/oauth/device-grant/README.md) |
| Token Exchange | RFC 8693 | [token-exchange](modules/oauth/token-exchange/README.md) |
| クライアントが保持する鍵にバインドしたトークン（DPoP） | RFC 9449 | [dpop](modules/oauth/dpop/README.md) |
| 証明書にバインドしたトークン（mTLS） | RFC 8705 | [mtls](modules/cert-binding/mtls/README.md) |
| リソースインジケーター | RFC 8707 | [resource-indicators](modules/oauth/resource-indicators/README.md) |
| パスキーによるログインと登録 | WebAuthn | [webauthn-login](modules/passkey/webauthn-login/README.md), [passkey-registration](modules/passkey/passkey-registration/README.md) |
| 第2の認証要素：認証アプリ（TOTP）、メールコード、リカバリーコード、セキュリティキー | RFC 6238, WebAuthn | [mfa](modules/second-factor/mfa/README.md) と `mfa-*` モジュール |
| 上流の OpenID Connect プロバイダー、Google、GitHub、Apple を通じたログイン | OpenID Connect、GitHub OAuth | [federation](modules/upstream-login/federation/README.md) と `idp-*` モジュール |

パスキーログインはトークンエンドポイントのカスタムグラントで、ブラウザーのセッションは開始しません。mTLS モジュールはトークンを証明書にバインドします。クライアント認証には別の方式を使います。

このほか、同意、ステップアップ認証、クライアント向けに上流のトークンを保持する機能に対応するモジュールがあります。ユーザーストアで失効させたユーザーのセッションを終了するモジュールもあります。[担当モジュール一覧](modules/README.md)には、すべてのモジュールとその責務をまとめています。

### 自分で用意するもの

- ログインページと、同意が必要なクライアントがある場合は同意ページ。プロバイダーは `redirect_to` パラメーターを付けて、ブラウザーをログインページにリダイレクトします。ログインページでは `GET /session/csrf` で CSRF トークンを取得し、ユーザー名、パスワード、トークン、`redirect_to` を `POST /session/login` に送信します。その後、応答で受け取った `redirect_to` にブラウザーを移動します。ページはプロバイダーの公開オリジンから配信してください。たとえば、同じリバースプロキシの背後に配置します。別のオリジンから送信されたログイン要求は拒否されます。要るリクエストと答えは[ログインページの手引き](docs/login-page.md)に、契約は [login-password](modules/identity/login-password/README.md) と [csrf](modules/identity/csrf/README.md) にあります。
- ユーザーアカウント。設定に列挙するか、プロバイダーが呼び出す独自の HTTP サービスで管理します。この HTTP サービスをドキュメントではユーザー台帳（user ledger）と呼びます（[users-http](modules/user-ledger-http/users-http/README.md)）。ユーザー登録とパスワード復旧の機能は含まれません。
- TLS を終端するリバースプロキシ。アプリ自体は平文の HTTP で待ち受けます。
- 各サービス内での認可。トークンで何を許可するかは、各サービスまたは別のポリシーエンジンが判断します。[関連プロジェクト](#関連プロジェクト)を参照してください。

## 動作要件

- Node.js 24 以降。
- 生成したプロジェクトの `packageManager` フィールドに指定されたバージョンの pnpm。`corepack enable` でそのバージョンをインストールできます。Node.js 25 以降には Corepack が同梱されていないため、先に `npm install -g corepack` を実行してください。
- 状態の永続化や複数インスタンスでの運用に Redis アダプターを使う場合は、Redis 7.0 以降。[本番運用の前に](#本番運用の前に)を参照してください。サーバーに必要な設定 (append-only ファイル、eviction しないことなど) は、runbook の [Redis の節](docs/runbook.md#redis)にあります。アプリは起動時にそれを確かめます。
- 生成したイメージをビルドして実行する場合は、Docker。

パターンによっては、HTTP ユーザー台帳、監査ログの収集先、SMTP リレー、上流の ID プロバイダーも必要です。`simple-web` では、これらは不要です。

## クイックスタート

まずは `simple-web` から始めてください。ユーザーは設定で管理し、状態はメモリーに保持します。Web アプリ向けのパスワードログイン（認可コードフロー、OIDC、リフレッシュトークン）と、サービス向けのクライアントクレデンシャルを利用できます。

```sh
npx @o3co/create-auth-provider@next my-provider --pattern simple-web
cd my-provider
pnpm install
cp .env.example .env
cp config/local.conf.example config/local.conf
```

生成された `README.md` に、パターンと設定の説明があります。2 つのサンプルファイルは、どちらも全行がコメントアウトされているため、コピーしただけでは何も設定されません。必要な設定のコメントを外し、サンプル値を置き換えてください。

`.env` には次を設定します。

- `ISSUER_URL` と `HTTP_PUBLIC_ORIGIN`：クライアントから見える URL（末尾のスラッシュなし）と、そのスキーム・ホスト・ポートです。両者のオリジンは一致させてください。
  - デフォルトでは、公開オリジンは https でなければなりません。手元のマシンで平文の http を使って試すには、両方を `http://127.0.0.1:8080` に設定し、`.env` に `HTTP_INSECURE_ORIGIN=true` を設定してください。
- `KEYS_SIGNING_KID` と `KEYS_SIGNING_ALG`。サンプルでは Ed25519 鍵用に EdDSA を指定しています。
- `AUTHORIZE_LOGIN_PAGE`：ログインページの URL です。プロバイダーと同じオリジンに置きます。たとえば `http://127.0.0.1:8080/login` とし、ページを配信して残りをアプリに渡すプロキシの背後に置きます。アプリはこのページを配信しません。別のオリジンのページでもアプリは起動しますが、そこからのログインは必ず `403 csrf` で拒否されます。`CONSENT_PAGE` は同意ページの URL です。すべてのクライアントがファーストパーティの場合は、未設定のままにしてください。
- サンプルに従い、`KERNEL_DEPLOYMENT=single`、`STORE_ACCEPT_VOLATILE=true`、`MAIL_ACCEPT_UNSENT=true`、`TOKENS_REVOCATION=denylist` を設定します。これらは、単一インスタンスで動作し、状態をメモリーに保持し（再起動で失われます）、メールを送信しない構成であることを明示します。`TOKENS_REVOCATION=denylist` は失効したアクセストークンを denylist に置いて拒否し、`unsupported` は失効の要求に unsupported と答えます。

署名鍵を生成します。

```sh
node -e 'const {generateKeyPairSync}=require("node:crypto");process.stdout.write(generateKeyPairSync("ed25519").privateKey.export({type:"pkcs8",format:"pem"}))' > signing.pem
```

テスト用ユーザーのパスワードハッシュを作成します。プロバイダーが受け付けるのは bcrypt または scrypt のハッシュで、平文のパスワードは受け付けません。次のコマンドは scrypt ハッシュを出力します。

```sh
node -e 'const c=require("node:crypto");const s=c.randomBytes(16);const k=c.scryptSync(process.argv[1],s,32,{N:2**15,r:8,p:1,maxmem:64*1024*1024});const b=x=>x.toString("base64").replace(/=+$/,"");console.log(`$scrypt$ln=15,r=8,p=1$${b(s)}$${b(k)}`)' 'your-password'
```

次に `config/local.conf` を記述します。ここには署名鍵、監査ログの送信先、ユーザー、クライアントを設定します。`.env` の `KEYS_SIGNING_PRIVATE_KEY` は未設定のままにしてください。`users.registered` はサンプルファイルにないため、自分で追加してください。

```hocon
keys.signing.private-key = """
<signing.pem の内容を貼り付けてください>
"""

audit.receivers = [log]

users.registered = [
  { identifier = "alice", password-hash = "<上のコマンドで出力されたハッシュ>" }
]

clients.registered = [
  {
    id = "my-web-app"
    kind = "public"
    method = "none"
    sections {
      authorize { redirect-uris = ["http://127.0.0.1:3000/callback"] }
      client-allowance {
        grants = ["authorization_code", "refresh_token"]
        scopes = ["openid", "profile"]
        default-scopes = ["openid"]
      }
      consent { first-party = true }
    }
  }
]
```

`client-allowance` に列挙するまで、クライアントにはグラントもスコープも許可されません。認可コードフローを使うクライアントには `redirect-uris` も必要です。`first-party = true` を設定すると、同意ページを省略します。コンフィデンシャルクライアントでは、`kind = "confidential"`、`client_secret_basic` などの `method`、`sections.client-secret.hash` にシークレットのハッシュを設定します。クライアントの全セクションは[設定リファレンス](docs/configuration.md#client-metadata-sections)にあります。

アプリを起動します。

```sh
APP_CONFIG=config/local.conf,config/application.conf pnpm start
```

設定に不足や誤りがあると、アプリは問題 1 件ごとに `refused <setting or module>: <reason>` という行を標準エラー出力に書き出し、終了ステータス 78 で終了します。設定を修正して、再度起動してください。修正すると、次の段階の拒否が表示されることがあります。

デフォルトのポートと上記のローカル用 issuer を使う場合は、次のコマンドで起動を確認します。

```sh
curl http://127.0.0.1:8080/readyz
curl http://127.0.0.1:8080/.well-known/openid-configuration
```

issuer の URL にパスが含まれる場合、ディスカバリードキュメントはそのパスの下に配置されます。

ブラウザーでログインするには、ログインページも必要です。ブラウザーなしでログインを確かめるには、ログインページとクライアントが行う手順を順に実行します。CSRF トークン、ログイン、PKCE 付きの認可リクエスト、トークンエンドポイントでのコードの引き換えです。上記のユーザーとクライアントでは次のとおりです。

```sh
V=$(node -e 'console.log(require("crypto").randomBytes(32).toString("base64url"))')
C=$(node -e 'console.log(require("crypto").createHash("sha256").update(process.argv[1]).digest("base64url"))' "$V")
AUTH="http://127.0.0.1:8080/oauth/authorize?response_type=code&client_id=my-web-app&redirect_uri=http%3A%2F%2F127.0.0.1%3A3000%2Fcallback&scope=openid&state=xyz&code_challenge=$C&code_challenge_method=S256"
TOKEN=$(curl -s -c jar -b jar http://127.0.0.1:8080/session/csrf | node -pe 'JSON.parse(require("fs").readFileSync(0)).csrf_token')
curl -s -c jar -b jar -H "X-CSRF-Token: $TOKEN" --data-urlencode username=alice --data-urlencode password=your-password --data-urlencode "redirect_to=$AUTH" http://127.0.0.1:8080/session/login
curl -s -o /dev/null -w '%{redirect_url}\n' -b jar "$AUTH"
curl -s http://127.0.0.1:8080/oauth/token -d grant_type=authorization_code -d client_id=my-web-app --data-urlencode redirect_uri=http://127.0.0.1:3000/callback -d code=<code> -d code_verifier="$V"
```

3 つ目のリクエストは、コード付きの `http://127.0.0.1:3000/callback` へのリダイレクトを出力します。そのコードを最後のリクエストの `<code>` に入れると、トークンが返ります。各リクエストと答えは[ログインページの手引き](docs/login-page.md)にあります。第 2 要素 (TOTP) までの続きは[レシピ](docs/recipe-mfa-page.md)にあり、各リクエストと答えは動いているアプリから記録しています。

## パターンの選択と機能の追加

パターンは、デプロイの用途に合わせてモジュールをあらかじめ組み合わせたものです。`--pattern` で選択します。必要なものは生成された README に記載されます。各パターンの短い説明は [modules/scaffold/create-app/src/patterns](modules/scaffold/create-app/src/patterns/README.md) にあります。

| パターン | 用途 | ストレージと外部サービス |
|---|---|---|
| `simple-web` | Web アプリ向けのパスワードログイン（リフレッシュトークン付きの認可コードフロー）と、サービス向けのクライアントクレデンシャル | インメモリーストア、単一インスタンス。ユーザーは設定で管理し、監査ログはログに出力 |
| `mfa-web` | `simple-web` に TOTP、メールコード、リカバリーコードを追加 | Redis と SMTP |
| `device` | `simple-web` に Device Authorization Grant を追加。ユーザーが別の画面でコードを承認 | インメモリーストア、単一インスタンス |
| `native-app` | パブリッククライアントとして動作するネイティブアプリとシングルページアプリ。PKCE、リフレッシュトークン、DPoP を使用 | インメモリーストア、単一インスタンス |
| `a2a` | ユーザーを介さないサービス間のトークン発行。クライアントクレデンシャルまたは JWT ベアラー、`private_key_jwt`、mTLS、DPoP を使用 | インメモリーストア、単一インスタンス。mTLS 用にクライアント証明書を転送するプロキシ |
| `sso-federated` | ローカルのパスワードを使わず、上流プロバイダーを通じてログイン | インメモリーストア、単一インスタンス。HTTP ユーザー台帳と上流プロバイダー |
| `full` | 明示的な有効化が必要なものを除く全機能（0.17 でデフォルトで含まれていた機能） | Redis、HTTP ユーザー台帳、HTTP 監査ログ受信先、SMTP |

`--pattern` を省略すると `full` になります。外部サービスなしで始めるには `simple-web` を使ってください。

機能の追加には `--add` を使い、`@mod/<name>` 形式のモジュール名を指定します。`<name>` は `modules/` 配下にあるモジュールのディレクトリ名です。

```sh
npx @o3co/create-auth-provider@next my-provider-dpop --pattern simple-web --add @mod/dpop
```

機能ごとに `--add` を繰り返し指定してください。`simple-web` のストアを Redis にするには、`--axis @mod/store=@mod/redis` を追加します。パターンのログイン方式、グラント、その他の機能グループも置き換えられます。axis とグループのオプションは、`full` 以外のパターンで使えます。すべてのオプションは `npx @o3co/create-auth-provider@next --help` で確認できます。

パターンを選ばず、モジュールを自分で列挙する方法もあります。その場合、モジュール同士の接続に必要なものはジェネレーターが追加し、設定は自分で記述します。各種プロジェクトに含まれるものは [app-output](modules/scaffold/app-output/README.md) を参照してください。

既存アプリのモジュール構成を変更するには、空のディレクトリに新しいプロジェクトを生成し、設定をコピーしてください。ジェネレーターは、ファイルがあるディレクトリを上書きしません。

## 設定

設定には HOCON を使います。モジュールごとに、モジュール名のセクションがあります。たとえば `issuer.url`、`keys.signing.alg`、`tokens.access-token-lifetime` です。未知のキー、読み込んでいないモジュールのセクション、不正な値があると、アプリは起動しません。エラーメッセージには設定名を表示し、値は表示しません。時間やサイズには、`30s` や `5KiB` のように単位が必要です。

パターンから生成したプロジェクトは、2 つのローカルファイルを読み込みます。どちらも git と Docker のビルドコンテキストから除外されるため、シークレットはこれらのファイルに保存してください。

- `.env` には、`config/application.conf` が読み取る環境変数を設定します。
- `config/local.conf` には、リスト、複数行の値、その他 HOCON で直接記述する設定を保存します。

環境変数名は、設定のパスを大文字にし、`.` と `-` を `_` に置き換えたものです。`keys.signing.private-key` は `KEYS_SIGNING_PRIVATE_KEY` になります。環境変数が反映されるのは、`config/application.conf` がその変数から読み取る設定だけです。任意の設定を上書きする仕組みではありません。

`APP_CONFIG` には、設定ファイルをカンマ区切りで列挙します。前に指定したファイルが、後のファイルより優先されます。未指定の場合は `config/application.conf` を読み込みます。

起動前に、すべてのサンプル値を置き換えてください。シークレットのプレースホルダーは `REPLACE-` で始まり、そのまま残っていると拒否されます。

[設定リファレンス](docs/configuration.md)に、すべての設定の型、デフォルト値、環境変数を記載しています。このリポジトリの各モジュールディレクトリにも、デフォルト値を記載した生成済みの `reference.conf` があります。参照専用です。

## Docker での実行

まず `pnpm install` を実行して `pnpm-lock.yaml` を作成し、次を実行します。

```sh
docker build -t auth-provider .
docker run --env-file .env \
  -e HTTP_HOST=0.0.0.0 \
  -e HTTP_PORT=8080 \
  -e APP_CONFIG=config/local.conf,config/application.conf \
  -v "$PWD/config/local.conf:/app/config/local.conf:ro" \
  -p 8080:8080 \
  auth-provider
```

Docker の env ファイルでは、変数ごとに 1 行で記述する必要があります。PEM 鍵などの複数行の値は `config/local.conf` に保存してください。

イメージは Node 24 を使い、本番用の依存パッケージだけをインストールして、非 root ユーザーで実行します。ヘルスチェックでは `/_healthcheck` を呼び出します。

## 本番運用の前に

インメモリーストアを Redis、またはストアの契約を満たす独自のアダプターに置き換えてください。Redis アダプターには、単一プライマリー構成の Redis 7.0 以降が必要です。クラスターモードは拒否されます。アプリは起動時にサーバーの設定を検証します。永続化、レプリケーション、マネージドサービスについては、[Redis の要件](docs/runbook.md#redis)を読んでください。

`kernel.deployment` を `single` または `multi` に設定してください。`multi` の場合、インメモリーストアやログ出力専用のメーラーなど、複数インスタンスで動作できないモジュールがあると、アプリは起動しません。

アプリを TLS 終端プロキシの背後に配置し、`http.trusted-proxies` を設定してください。プロキシは、自身のヘッダーを設定する前に、クライアントが送った転送ヘッダーやクライアント証明書ヘッダーをすべて削除する必要があります。サービスを公開する前に、[デプロイの要件](docs/runbook.md#before-you-deploy)と[セキュリティモデル](docs/security-model.md)を読んでください。

## エンドポイント

[ルートリファレンス](docs/routes.md)には、すべてのオプション機能を含む full テンプレートの全ルートについて、メソッド、リクエストボディ、ポリシーを記載しています。アプリが提供するのは、読み込んだモジュールのルートだけです。

主なエンドポイントは次のとおりです。

- `/.well-known/openid-configuration` と `/.well-known/oauth-authorization-server`：issuer にパスがない場合のディスカバリー。
- `/.well-known/jwks.json`：署名検証用の公開鍵。
- `/oauth/authorize` と `/oauth/token`。

実際に提供されるエンドポイントは、デプロイした環境のディスカバリードキュメントに記載されます。

## 運用

死活監視には `GET /_healthcheck`、リクエストを受け付けられるかの確認には `GET /readyz` を使います。Redis などの依存先が停止している間、`GET /readyz` は 503 を返します。依存先が復旧するまで、そのインスタンスへのトラフィックを停止してください。インスタンスを再起動しても解決しません。

Prometheus パブリッシャーを読み込むと、`/metrics` でメトリクスを公開します。パスは `metrics-prometheus.path` で変更できます。プロキシでアクセスを制限してください。ログは標準出力に 1 行 1 件の JSON 形式で出力します。ログレベルは `kernel.logging.level` で設定します。

監査ログの送信先は `audit.receivers` で選びます。`log` は組み込みです。`stdout` と `http` を使うには、それぞれの受信モジュール（`audit-stdout`、`audit-http`）が必要です。配送はベストエフォートのため、`auth_audit_events_lost_total` を監視してください。[監査イベントリファレンス](docs/audit-events.md)に、すべてのイベントとその属性を記載しています。

SIGTERM と SIGINT を受け取ると、アプリは `kernel.stop-deadline`（デフォルトは `30s`）以内に処理を終えて正常に停止します。オーケストレーターには、それより長い終了猶予時間を設定してください。

[運用手順書](docs/runbook.md)では、デプロイ、署名鍵と封印鍵のローテーション、アップグレード、ユーザーの失効、アラートについて説明しています。

## 独自モジュールの作成

[担当モジュール一覧](modules/README.md)から必要な契約を探し、そのモジュールの README を読んでください。

`@o3co/auth-provider-foundation/kernel` の `defineModule` でモジュールを定義し、生成された `src/main.ts` が `assemble` に渡すモジュール一覧に追加します。独自のパッケージとして公開パッケージに対して作る例は、[独自のグラントのレシピ](docs/recipe-external-grant.md)にあります。モジュール API は [kernel の README](modules/foundation/kernel/README.md) で説明しています。

ストアやユーザー台帳などの実装を置き換えるには、その契約を実装し、`testing` サブパスで公開されている契約テストを実行してください。たとえば `@o3co/auth-provider-foundation/store/testing` です。

このリポジトリ内のモジュールについては、[combinations の README](modules/scaffold/combinations/README.md) で、アダプターや他のモジュールとの接続に必要なモジュールをマニフェストで宣言する方法を説明しています。

**ジェネレーターを使わずに組み立てる。** 生成したプロジェクトの代わりに自分のコンポジションルートを持つ場合:

1. `@o3co/auth-provider-scaffold` をインストールし、`@o3co/auth-provider-scaffold/combinations` からモジュール名を得ます。選択には `composed`、自分で並べたモジュールには `needed` を使います。どちらも知らない名前を拒否します。
2. その名前を `published` に渡します。それぞれについて、依存するパッケージと、モジュールを import するパス (`<entry>/module`) が返ります。
3. それらのパッケージを、scaffold のバンドルと同じバージョン (1 つのリリースのバンドルはすべて同じバージョン) で `package.json` に追加します。`assemble` のために、`@mod/kernel` を含むパッケージ (`published(["@mod/kernel"])`) も追加します。
4. 名前にログの出力先が含まれていなければ、`@mod/log-stdout` などを追加します。ないとログはどこにも出ません。
5. 起動します。あなたにしか決められない設定で起動が拒否されたら (たとえば、subject を確かめるモジュールがないときの `tokens.subject-check = none`)、その設定を書きます。

## バージョンとサポート

アプリに必要なパッケージはジェネレーターが選びます。公開パッケージの名前は `@o3co/auth-provider-<concern>` で、すべて同じバージョンを使い、各モジュールをサブパスとして公開しています。[移行ガイド](docs/migration.md#packages)に、0.17 のパッケージと 0.18 での置き換え先を記載しています。

1.0 より前は、マイナーリリースでも互換性が失われる場合があります。新しいリリース候補でも同様です。アップグレード前に、移行ガイドと[変更履歴](CHANGELOG.md)を読んでください。

セキュリティ修正は、最新の 0.18.x にのみ提供します。リリース候補で見つかった問題の修正は、次のリリース候補に含めます。脆弱性は、[SECURITY.md](SECURITY.md) の説明に従い、このリポジトリの Security タブにある **Report a vulnerability** から非公開で報告してください。公開 issue は作成しないでください。

## 開発への参加

Node.js 24 以降と、リポジトリの `package.json` に指定されたバージョンの pnpm を使ってください（`corepack enable` でインストールできます）。

```sh
pnpm install
pnpm check
```

`pnpm check` は、型チェック、lint、ユニットテスト、guard、配布物のチェックを実行します。`pnpm test:integration` は、Docker が必要なテストを実行します。

モジュールは `modules/<group>/<name>` にあり、各モジュールの README がその契約です。[担当モジュール一覧](modules/README.md)から、変更を担当するモジュールを探してください。[guard](modules/tooling/guard/README.md) は、依存関係の方向、各パッケージの公開範囲、モジュールのサイズを検査します。

プルリクエストを作成する前に [CONTRIBUTING.md](CONTRIBUTING.md) を読み、マージ先を `develop` にしてください。メンテナーは [docs/releasing.md](docs/releasing.md) に従ってリリースします。

## 関連プロジェクト

- [auth](https://github.com/o3co/auth)：全体をまとめるリポジトリです。アーキテクチャと、コンポーネントをまたぐ E2E テストがあります。
- [auth.policy-verifier](https://github.com/o3co/auth.policy-verifier)：認可判断を行うポリシーエンジンです。
- [auth.proxy](https://github.com/o3co/auth.proxy)：サービスの前段でトークンを検証する、任意で利用できるリバースプロキシです。
- [protobuf.interceptors](https://github.com/o3co/protobuf.interceptors)：このプロバイダーのイントロスペクションとポリシー検証器の判断を使い、gRPC と ConnectRPC のサービス内で認可を行います。

## ライセンス

[Apache License 2.0](LICENSE)。

Copyright 2026 1o1 Co. Ltd. Licensed under the Apache License, Version 2.0.