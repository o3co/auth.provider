# create-o3co-auth-provider

auth.provider 用の CLI スキャフォルダーです。standalone テンプレートから新しいプロジェクトを生成します。

## 使い方

```bash
npx create-o3co-auth-provider <プロジェクト名>
```

例:

```bash
npx create-o3co-auth-provider my-auth-server
cd my-auth-server
npm install
npm run debug
```

## 動作内容

1. プロジェクト名を検証する。
2. ターゲットディレクトリを `<cwd>/<プロジェクト名>` として解決する。
3. ディレクトリがすでに存在する場合はエラーを出力して終了する。
4. `templates/standalone/` をターゲットディレクトリにコピーする（`node_modules/` と `dist/` は除外）。
5. 生成されたディレクトリの `package.json` を書き換える:
   - `name` を指定したプロジェクト名に設定する。
   - `private` フィールドを削除する。
   - すべての `workspace:*` バージョン参照を `versions.json` の公開 semver バージョンに置き換える。
6. 次のステップを出力する。

## バリデーションルール

プロジェクト名は以下の条件をすべて満たす必要があります。

- `.` または `..` でないこと
- パス区切り文字（`/` または `\`）を含まないこと

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
