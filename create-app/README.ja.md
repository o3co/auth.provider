# @o3co/create-auth-provider

最終更新: 2026-09-24

auth.provider 用の CLI スキャフォルダーです。内包する standalone テンプレートから新しいサーバープロジェクトを生成します。

## 責務と役割

**役割。** リポジトリ内のテンプレート
[`templates/standalone`](../templates/standalone) を、独立した新しいプロジェクトに
変換する `npx` の入口です。運用者のマシン上で一度だけ実行されます。生成された
プロジェクトはこのパッケージを import せず、このパッケージも `packages/*` の
ライブラリを一切 import しません。

**担うもの。** プロジェクト名とディレクトリ名の検証、テンプレートのコピー、生成された
`package.json` の書き換え（名前、`workspace:*` → 公開バージョン）、プロジェクトの
`pnpm-workspace.yaml` の書き出し、そして一度きりの `pnpm-lock.yaml` の解決。

**担わないもの。** 生成されるプロジェクトの中身 — ソース、設定、Dockerfile、
テスト — はテンプレートのものです（このパッケージではなく `templates/standalone` を
編集してください）。実行時の振る舞いは `@o3co/auth-provider-core` と、テンプレートが
依存するライブラリのものです。

**別パッケージである理由。** `bin` 付きで単独公開されるため、provider をインストール
せずに `npx` で実行できます。公開 tarball にはモノレポが含まれないので、このパッケージは
テンプレートのコピーと、固定するライブラリのバージョンを自前で持ちます
（[テンプレートの同梱方法](#テンプレートの同梱方法)）。

## 使い方

```bash
npx @o3co/create-auth-provider <project-name> [--dir <dir-name>] [--no-lockfile]
```

`<project-name>` はスコープ付き npm 名 (`@scope/pkg`) とスコープなしの名前 (`pkg`) のどちらでも指定できます。

スコープなしの例:

```bash
npx @o3co/create-auth-provider my-auth-server
cd my-auth-server
pnpm install
```

スコープ付きの例（ディレクトリ名はパッケージ部分 `auth.provider` がデフォルト）:

```bash
npx @o3co/create-auth-provider @my-org/auth.provider
cd auth.provider
pnpm install
```

`--dir` でディレクトリ名を明示指定:

```bash
npx @o3co/create-auth-provider @my-org/auth.provider --dir provider
cd provider
```

`--no-lockfile` を付けると lockfile の生成（下記の手順 7）を省略します。

生成されるプロジェクトは pnpm のプロジェクトです。`Dockerfile` は
`pnpm install --frozen-lockfile` でインストールし、ビルドの許可リストは
`pnpm-workspace.yaml` にあります。

CLI は最後のメッセージで次に `pnpm run debug` を実行するよう案内します。
スキャフォールドのデフォルトのままでは、これは起動しません: `.env` ファイルは
読まず（読むのは compose ファイルだけ）、シェルの環境変数から issuer
（`OAUTH_JWT_ISSUER`）、署名鍵のペア、セッションシークレット、ユーザーサービスの
2 つの URL（`CLIENT_USER_AUTHENTICATE_URL`、`CLIENT_USER_AUTHENTICATE_BY_TOKEN_URL`）、
そして `localhost:6379` の Redis を必要とします。コマンドは、プロジェクトに含まれる
テンプレートの README の[使い方](../templates/standalone/README.ja.md#使い方)にあります。

## 動作内容

1. `<project-name>` を検証する（[バリデーションルール](#バリデーションルール) 参照）。
2. 生成先ディレクトリ名を決定する: `--dir <value>` が指定されていればその値、そうでなければスコープ付き名のパッケージ部分、最終的には入力値そのもの。
3. 生成先ディレクトリを `<cwd>/<dir-name>` として解決し、すでに存在する場合はエラーで終了する。
4. 内包するテンプレートを生成先ディレクトリにコピーし（`node_modules/` と `dist/` は除外）、`.gitignore` を復元する（npm は公開パッケージから `.gitignore` という名前のファイルを落とすため、tarball には `gitignore` として入っている）。
5. 生成されたディレクトリの `package.json` を書き換える:
   - `name` を `<project-name>` そのままに設定する（スコープを保持）。
   - `"private": true` は意図的に残す: スキャフォールドされた ID プロバイダーが誤って公開できてはならないため。本当に公開するつもりなら自分でこのフィールドを削除する。
   - `dependencies`・`devDependencies`・`peerDependencies` の各 `workspace:*` を、内包する `versions.json` の `^<version>` に置き換える。
6. `bcrypt` 用の `onlyBuiltDependencies` 許可リストを書いた `pnpm-workspace.yaml` を生成する — pnpm 10.29 以降はこの許可リストを、単一パッケージのプロジェクトであってもこのファイルからしか読まない。
7. `--no-lockfile` が指定されていなければ、依存関係を `pnpm-lock.yaml` に解決する（`pnpm install --lockfile-only --ignore-workspace`。`pnpm` が `PATH` にない場合は `corepack pnpm` 経由）。到達可能なレジストリが必要で、失敗しても警告を出すだけでスキャフォールドは完了する。
8. 次のステップを出力する。

### 生成される `pnpm-lock.yaml`

テンプレートの `Dockerfile` は `pnpm install --frozen-lockfile` でインストール
するため、生成されたプロジェクトは lockfile がなければそもそもビルドできません。
lockfile をテンプレートに同梱することはできません: 手順 5 がすべての
`workspace:*` を公開バージョンに置き換えるまで、lockfile が固定すべき依存関係の
集合が存在しないからです。そこで、書き換え後の `package.json` に対してここで
一度だけ解決します。**コミットしてください** — `docker build` を再現可能にするのは
この lockfile です。手順 7 が失敗した、または省略した場合は、プロジェクト内で一度
`pnpm install` を実行して結果をコミットしてください。

## テンプレートの同梱方法

パッケージの `prebuild` と `prepack` スクリプトが
[`scripts/copy-templates.mjs`](scripts/copy-templates.mjs) を実行し、
`templates/standalone` を `create-app/templates/standalone` にコピーし（git 管理外。
`node_modules/` と `dist/` は除外）、`create-app/templates/versions.json` —
公開される `@o3co/auth-provider-*` 全パッケージの現在のバージョン — を書き出します。
tarball には両方が入り（`files: ["dist", "templates"]`）、`scaffold()` はそこから
読みます。したがってスキャフォールドされるのは、このパッケージをビルドした時点の
テンプレートで、同じビルド時点のライブラリバージョンに固定されます。

CI は [`scripts/check-versions-json.mjs`](scripts/check-versions-json.mjs) を
実行します。`packages/` 配下の公開パッケージが `copy-templates.mjs` のバージョン
一覧に欠けているとき、または一覧がもう存在しないパッケージを挙げているときに
失敗します — そうでなければスキャフォールドがそのパッケージの `workspace:*` の
バージョンを解決できずに失敗するためです。

## バリデーションルール

`<project-name>` は以下のいずれかに一致する必要があります:

- スコープなし: `^[a-z0-9][a-z0-9-._~]*$`
- スコープ付き: `^@[a-z0-9][a-z0-9-._~]*/[a-z0-9][a-z0-9-._~]*$`

いずれも空文字・`.`・`..` は不可、最大 214 文字。

`--dir <value>` はスコープなしのパターンと同じ制約です。

## 既知の制約

- 内包されているテンプレートの `README.md` / `README.ja.md` の見出しは上流の `@o3co/auth-provider-standalone` のままです。スコープ付きでプロジェクトを生成した場合、この見出しは `package.json` の名前と一致しません。必要に応じて手動で修正してください。
- テンプレートの README は、このリポジトリ内を相対パス（`../../docs/…`、`../../packages/…`）でリンクしています。これはモノレポ内では解決しますが、横に `docs/` も `packages/` もないスキャフォールド先のプロジェクトでは解決しません。GitHub 上で参照してください。

## 生成される構造

生成されるプロジェクトは [`templates/standalone`](../templates/standalone) の
完全なコピー（`node_modules/` と `dist/` を除く）に、`pnpm-workspace.yaml`（手順 6）と、
`--no-lockfile` を指定せず lockfile の手順が失敗しなかった場合は `pnpm-lock.yaml`（手順 7）を加えたものです。どの
ファイルがモジュール構成で、どれがホストプロセスで、スキャフォールドが何を
持つかは、テンプレートの README に記述されています。

## プログラマティック API

モジュールは CLI を構成する関数を export しています。シグネチャは
[`src/index.mts`](src/index.mts) にあります。

- `scaffold(targetDir, projectName)` — 手順 4〜6。内包するテンプレートがない場合、または `workspace:*` 依存が `versions.json` に見つからない場合は例外を投げる。
- `generateLockfile(targetDir)` — 手順 7。例外を投げず、`{ ok: true, command }` か `{ ok: false, reason }` を返す。
- `main()` — CLI 本体。`process.argv` を読み、不正な引数や既存のディレクトリに対しては非ゼロで終了する。
- `isValidProjectName(name)` / `isValidDirName(name)` — [バリデーションルール](#バリデーションルール)。

## 関連

- [`@o3co/auth-provider-standalone`](../templates/standalone) — このツールが生成元とするテンプレート
- [`@o3co/auth-provider-core`](../packages/core) — コアアプリケーションファクトリ
