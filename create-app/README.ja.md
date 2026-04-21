# create-o3co-auth-provider

auth.provider 用の CLI スキャフォルダーです。standalone テンプレートから新しいプロジェクトを生成します。

## 使い方

```bash
npx create-o3co-auth-provider <project-name> [--dir <dir-name>]
```

`<project-name>` はスコープ付き npm 名 (`@scope/pkg`) とスコープなしの名前 (`pkg`) のどちらでも指定できます。

スコープなしの例:

```bash
npx create-o3co-auth-provider my-auth-server
cd my-auth-server
npm install
npm run debug
```

スコープ付きの例（ディレクトリ名はパッケージ部分 `auth.provider` がデフォルト）:

```bash
npx create-o3co-auth-provider @my-org/auth.provider
cd auth.provider
npm install
npm run debug
```

`--dir` でディレクトリ名を明示指定:

```bash
npx create-o3co-auth-provider @my-org/auth.provider --dir provider
cd provider
```

## 動作内容

1. `<project-name>` を検証する（バリデーションルール参照）。
2. 生成先ディレクトリ名を決定する: `--dir <value>` が指定されていればその値、そうでなければスコープ付き名のパッケージ部分、最終的には入力値そのもの。
3. 生成先ディレクトリを `<cwd>/<dir-name>` として解決する。
4. ディレクトリがすでに存在する場合はエラーを出力して終了する。
5. `templates/standalone/` を生成先ディレクトリにコピーする（`node_modules/` と `dist/` は除外）。
6. 生成されたディレクトリの `package.json` を書き換える:
   - `name` を `<project-name>` をそのまま設定する（スコープを保持）。
   - `private` フィールドを削除する。
   - すべての `workspace:*` バージョン参照を `versions.json` の公開 semver バージョンに置き換える。
7. 次のステップを出力する。

## バリデーションルール

`<project-name>` は以下のいずれかに一致する必要があります:

- スコープなし: `^[a-z0-9][a-z0-9-._~]*$`
- スコープ付き: `^@[a-z0-9][a-z0-9-._~]*/[a-z0-9][a-z0-9-._~]*$`

いずれも空文字・`.`・`..` は不可、最大 214 文字。

`--dir <value>` はスコープなしのパターンと同じ制約です。

## 既知の制約

内包されているテンプレートの `README.md` / `README.ja.md` の見出しは `@o3co/auth-provider-standalone` のままです。スコープ付きでプロジェクトを生成した場合、この見出しは生成された `package.json` の `name` と一致しません。必要に応じて手動で修正してください。

## 生成される構造

```
<プロジェクト名>/
├── config/
│   ├── application.conf   # HOCON 設定（環境変数で上書き可能）
│   ├── clients.yaml       # OAuth クライアントレジストリ
│   └── clients.yaml.example
├── src/
│   └── app.mts            # Composition root
├── tests/
├── .dockerignore
├── .env.example
├── Dockerfile
├── docker-compose.yml
├── docker-compose.test.yml
├── Makefile
├── package.json
├── tsconfig.json
└── vitest.config.mts
```

生成後、`.env.example` をコピーして `.env` を作成し、必須の環境変数を設定してください。

## プログラマティック API

```typescript
import { scaffold, main } from "create-o3co-auth-provider";

// 絶対パスにプロジェクトを生成する
scaffold(targetDir: string, projectName: string): void;

// CLI エントリーポイント — process.argv を読み取り、エラー時は終了する
main(): void;
```

テンプレートディレクトリが見つからない場合、または `workspace:*` 依存関係が `versions.json` で解決できない場合、`scaffold` はエラーをスローします。

## 関連

- [`@o3co/auth-provider-standalone`](../templates/standalone) — このツールが生成元とするテンプレート
- [`@o3co/auth-provider-core`](../packages/core) — コアアプリケーションファクトリ
