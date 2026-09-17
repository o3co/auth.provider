# ts.hocon — TypeScript 向け HOCON パーサー

[![npm](https://img.shields.io/npm/v/@o3co/ts.hocon.svg)](https://www.npmjs.com/package/@o3co/ts.hocon)
[![CI](https://github.com/o3co/ts.hocon/actions/workflows/test.yml/badge.svg)](https://github.com/o3co/ts.hocon/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/o3co/ts.hocon/branch/develop/graph/badge.svg)](https://codecov.io/gh/o3co/ts.hocon)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

[Lightbend HOCON](https://github.com/lightbend/config/blob/main/HOCON.md) 仕様の TypeScript パーサー。現在の準拠率は [仕様準拠](#仕様準拠) を参照。

> **[Claude](https://claude.ai/)（Anthropic）による実装** — Claude Code を用いて設計・実装されました。
> [GitHub Copilot](https://github.com/features/copilot) および [OpenAI Codex](https://openai.com/index/openai-codex/) によるレビュー。

[English](README.md)

---

## クイックスタート

### 1. インストール

```bash
npm install @o3co/ts.hocon
```

Node.js 22 以上が必要です。

ESM / CJS の両方に対応しています。`import` でも `require` でも同じエントリポイント
（`adapters/*` のサブパスを含む）に到達します:

```ts
import { parse } from '@o3co/ts.hocon'          // ESM
const { parse } = require('@o3co/ts.hocon')     // CJS
```

CI では PR ごと・リリースごとに、ビルド成果物に対して 7 つの export すべてを両形式で
ロードし、実際に呼び出し（バンドル形式で挙動が変わる package include を含む）、各条件が
自前の型定義を宣言しているかまで検証します。1.10.0 で CJS の 7 エントリポイントすべてが
ロード時に例外を投げた実績があるためのゲートであり、この種の欠陥を検出するものです
（あらゆる欠陥が起こり得ないという保証ではありません）。

### 2. 使い方

```ts
import { parse } from '@o3co/ts.hocon'

const cfg = parse(`
  server {
    host = "localhost"
    port = 8080
  }
`)

cfg.getString('server.host')   // "localhost"
cfg.getNumber('server.port')   // 8080
cfg.has('server.host')         // true
```

## なぜ HOCON？

| | `.env` | JSON | YAML | HOCON |
|---|---|---|---|---|
| Comments | No | No | Yes | Yes |
| Nesting | No | Yes | Yes | Yes |
| References / Substitution | No | No | No | Yes (`${var}`) |
| File inclusion | No | No | No | Yes (`include`) |
| Object merging | No | No | Anchors (fragile) | Yes (deep merge) |
| Optional values | No | No | No | Yes (`${?var}`) |
| Trailing commas | N/A | No | N/A | Yes |
| Unquoted strings | Yes | No | Yes | Yes |

HOCON は単なるシリアライズ形式ではなく、**プログラムに注入するための設定言語** です。JSON / YAML / TOML はデータ構造の表現に徹しており、ファイルの重ね合わせ・環境変数・参照解決はアプリ側（Pydantic、Serde、Zod 等）の責務になります。HOCON はそれらを仕様そのものに内包しているため、プログラムが設定を受け取る時点で、フォールバックは合成済み・`${VAR}` 参照は解決済みの「1 枚の設定」になっています。「このレイヤーに値があるか？」に由来する条件分岐は、コードではなくフォーマット境界で消えます。

加えて HOCON は YAML の可読性と JSON の構造性を兼ね備えるため、フラットなキーバリュー設定を超えるユースケースには強い選択肢になります。

## 特徴

- 完全な HOCON パース：オブジェクト、配列、スカラー値、代入（`${path}`、`${?path}`）
- 自己参照代入（`path = ${path}:/extra`）
- 重複キーのディープマージ（後勝ち）
- `+=` 追加演算子
- `include "file.conf"` および `include file("file.conf")` ディレクティブ
- トリプルクォート文字列（`"""..."""`）
- HOCON エミッタ（`renderHocon()`）— 解決済み `Config` を HOCON テキストとして出力。再パースすると同一の値ツリーになる（E18 ラウンドトリップ契約）
- 同期・非同期 API（`parse` / `parseAsync` / `parseFile` / `parseFileAsync`）
- ESM + CJS デュアルパッケージ（全エントリポイントを CI で両形式ロード検証）
- [Zod](https://zod.dev/) スキーマバリデーション統合（オプション）
- ブラウザ対応（`parse`/`parseAsync` — Node.js 不要）

## API

### パース関数

```ts
import { parse, parseAsync, parseFile, parseFileAsync } from '@o3co/ts.hocon'
import type { ParseOptions } from '@o3co/ts.hocon'

parse(input: string, opts?: ParseOptions): Config
parseAsync(input: string, opts?: ParseOptions): Promise<Config>
parseFile(path: string, opts?: ParseOptions): Config
parseFileAsync(path: string, opts?: ParseOptions): Promise<Config>
```

`ParseOptions`:
| オプション | 型 | 説明 |
|----------|-----|------|
| `baseDir` | `string` | `include` 解決のベースディレクトリ |
| `env` | `Record<string, string>` | 代入で使用する環境変数（デフォルト: `process.env`） |
| `readFileSync` | `(path: string) => string` | カスタムファイルリーダー（同期） |
| `readFile` | `(path: string) => Promise<string>` | カスタムファイルリーダー（非同期） |

### Config メソッド

| メソッド | 戻り値 | スローする条件 |
|---------|--------|--------------|
| `get(path)` | `unknown \| undefined` | — |
| `getString(path)` | `string` | 存在しない、型が違う |
| `getNumber(path)` | `number` | 存在しない、型が違う |
| `getBoolean(path)` | `boolean` | 存在しない、型が違う |
| `getConfig(path)` | `Config` | 存在しない、オブジェクトでない |
| `getList(path)` | `unknown[]` | 存在しない、配列でない |
| `has(path)` | `boolean` | — |
| `keys()` | `string[]` | — |
| `withFallback(fallback)` | `Config` | — |
| `toObject()` | `unknown` | — |
| `renderHocon()` | `string` | 未解決の場合 |

### Zod 統合

```ts
import { validate, getValidated } from '@o3co/ts.hocon/zod'
import { z } from 'zod'

const Schema = z.object({
  server: z.object({
    host: z.string(),
    port: z.number().int(),
  }),
})

// 設定全体をバリデート
const app = validate(cfg, Schema)

// 特定パスをバリデート
const port = getValidated(cfg, 'server.port', z.number().int())
```

Zod をピア依存としてインストール:
```bash
npm install zod
```

### エラー型

```ts
import { ParseError, ResolveError, ConfigError } from '@o3co/ts.hocon'

// ParseError   — 字句解析・構文解析エラー: .line, .col, .file?
// ResolveError — 代入・include 解決エラー: .path, .line, .col, .file?
// ConfigError  — 型不一致・パス不存在エラー: .path
```

## HOCON の例

```hocon
# # または // でコメント
database {
  host = "db.example.com"
  port = 5432
  url  = "jdbc:"${database.host}":"${database.port}
}

# 重複キーはディープマージ（スカラーは後勝ち）
server { host = localhost }
server { port = 8080 }      // 結果: { host: "localhost", port: 8080 }

# 自己参照による追記
path = "/usr/bin"
path = ${path}":/usr/local/bin"

# += 短縮構文
items = [1]
items += 2
items += 3   // [1, 2, 3]

# Include
include "defaults.conf"
include file("overrides.conf")

# トリプルクォート複数行文字列
description = """
  これは
  複数行の文字列です。
"""
```

## 仕様準拠

[Lightbend HOCON 仕様](https://github.com/lightbend/config/blob/main/HOCON.md) への準拠状況は [`docs/spec-compliance.md`](docs/spec-compliance.md) に項目単位で記載しており、以下の表はそこから計算されます — `tests/docs.test.ts` が再計算し、表がずれるとビルドが fail します。実装横断のロールアップは [`xx.hocon/docs/compliance-matrix.md`](https://github.com/o3co/xx.hocon/blob/main/docs/compliance-matrix.md) を参照してください。

| 指標                                   | 状況          |
| -------------------------------------- | ------------- |
| 仕様全体（out-of-scope を含む）        | **90.0%**     |
| In-scope のみ                          | **100.0%**    |
| Lightbend `test01`–`test13` テスト群   | 13/13 合格    |

未対応の機能:
- `include url(...)`
- `include classpath(...)`

## パフォーマンス

### ts.hocon のパースコスト

[Vitest bench](https://vitest.dev/guide/features.html#benchmarking)（tinybench）で計測。`pnpm bench` で再現できます。

| シナリオ | ops/sec | 1回あたりの時間 |
|---|---|---|
| 小規模設定（10キー） | ~200,000 | ~5 µs |
| 中規模設定（100キー） | ~23,000 | ~43 µs |
| 大規模設定（1,000キー） | ~2,100 | ~476 µs |
| substitution 10個 | ~74,000 | ~14 µs |
| substitution 50個 | ~14,000 | ~71 µs |
| substitution 100個 | ~6,900 | ~145 µs |
| ネスト深度 5 | ~210,000 | ~5 µs |
| ネスト深度 10 | ~147,000 | ~7 µs |
| ネスト深度 20 | ~80,000 | ~13 µs |

### JSON.parse との比較

JSON.parse は V8 のネイティブ C++ 実装であり、最速の基準線です。この比較は HOCON の豊富な機能によるオーバーヘッドを示します。

| 設定サイズ | ts.hocon | JSON.parse | 倍率 |
|---|---|---|---|
| 小規模（10キー） | ~198K ops/s | ~1,967K ops/s | ~10x |
| 中規模（100キー） | ~23K ops/s | ~280K ops/s | ~12x |
| 大規模（1,000キー） | ~2.2K ops/s | ~12K ops/s | ~5.4x |

一般的なアプリケーション設定（起動時に1回読み込み）であれば、パースコストは無視できるレベルです。1,000キーの設定でも 0.5 ms 未満でパースできます。

### node-config との機能比較

ts.hocon は [node-config](https://github.com/node-config/node-config)（JSON）と比較して、大幅に豊富な設定機能を提供します：

| 機能 | ts.hocon | node-config (JSON) |
|---|---|---|
| コメント | `//` `#` | 非対応 |
| 複数行文字列 | `"""..."""` | 非対応 |
| substitution（`${path}`） | 対応 | 非対応 |
| optional substitution（`${?path}`） | 対応 | 非対応 |
| 環境変数参照 | 対応（substitution経由） | 部分対応（`custom-environment-variables` ファイル） |
| include | 対応 | 非対応 |
| ディープマージ | 対応（配列も対応） | 部分対応（配列は置換） |
| 追加演算子（`+=`） | 対応 | 非対応 |
| 環境別設定 | HOCON仕様で自由に構成可 | 対応（ファイル名規約） |
| スキーマ検証 | Zod 統合 | 非対応 |
| プログラマティック API | `parse(string)` | ファイルベース初期化後に `get()` |
| 型付きゲッター | `getString`, `getNumber` 等 | `get()`（any） |

## ブラウザ対応

`parse()` と `parseAsync()` はブラウザで動作します。`parseFile()` と `parseFileAsync()` は Node.js（またはカスタムの `readFileSync`/`readFile` オプション）が必要です。

```ts
// カスタムファイルローダーを使ったブラウザ利用
const cfg = await parseAsync(hoconString, {
  readFile: async (path) => {
    const res = await fetch(`/config/${path}`)
    return res.text()
  },
})
```

## ベストプラクティス

### 設定構成

- **ドメインごとに分割**: 設定を論理的な単位に分けましょう（`database.conf`、`server.conf`、`logging.conf`）
- **`include` で合成**: ドメイン別ファイルからフル設定を組み立てましょう
- **設定にロジックを入れない**: HOCON は宣言的なデータのためのもので、条件分岐や計算には向きません

### 環境変数

- **`${ENV}` の使用を最小限に**: 設定ファイル自体にデフォルト値を定義し、`${?ENV}`（オプショナル）を使いましょう
- **ローカル開発で環境変数を必須にしない**: デフォルトだけで動くようにしましょう
- **必須の環境変数を文書化**: プロジェクトの README や `.env.example` にリストしましょう
- **変数名の階層は `.` ではなく `__` で**: `loadEnv`（および `parseDotEnv`）で一括マウント
  するとき、階層を作るのは `__` **だけ** です。`.` は通常のキー文字なので、次の 2 つは
  別々のキーであり、どちらも失われません:

  ```text
  APP_FOO__BAR=nested   # -> foo.bar      : cfg.getString('foo.bar')
  APP_FOO.BAR=dotted    # -> "foo.bar"    : cfg.getString('"foo.bar"')
  ```

  単独の `_` もセグメントの一部のままです（`APP_DB__MAX_CONN` → `db.max_conn`）。

### 開発 / 本番の分離

```text
config/
├── application.conf    # 共有デフォルト
├── dev.conf            # include "application.conf" + 開発用オーバーライド
└── prod.conf           # include "application.conf" + 本番用オーバーライド
```

### バリデーション

- 設定のバリデーションは常にアプリケーション起動時に行い、使用時ではなく早期に検出しましょう
- スキーマバリデーション（TypeScript は Zod、Go は struct Unmarshal、Rust は Serde）を使って早期にエラーをキャッチしましょう

```typescript
import { parseWithSchema } from '@o3co/ts.hocon/zod'
import { z } from 'zod'

const schema = z.object({
  server: z.object({ host: z.string(), port: z.number() }),
  debug: z.boolean(),
})
const config = parseWithSchema(hoconInput, schema) // 起動時に即座に失敗
```

## 関連プロジェクト

| プロジェクト | 言語 | レジストリ | 説明 |
|---------|----------|----------|-------------|
| [go.hocon](https://github.com/o3co/go.hocon) | Go | [pkg.go.dev](https://pkg.go.dev/github.com/o3co/go.hocon) | Go 向け HOCON パーサー |
| [rs.hocon](https://github.com/o3co/rs.hocon) | Rust | [crates.io](https://crates.io/crates/o3co-hocon) | Rust 向け HOCON パーサー |
| [hocon2](https://github.com/o3co/hocon2) | Go | [pkg.go.dev](https://pkg.go.dev/github.com/o3co/hocon2) | HOCON → JSON/YAML/TOML/Properties 変換 CLI |

3 つのパーサー実装（[ts.hocon](https://github.com/o3co/ts.hocon)、[rs.hocon](https://github.com/o3co/rs.hocon)、[go.hocon](https://github.com/o3co/go.hocon)）はすべて同じ Lightbend HOCON 仕様で追跡されています — 実装ごとの準拠率は [横断ロールアップ](https://github.com/o3co/xx.hocon/blob/main/docs/compliance-matrix.md) を参照してください。

## フォーマットアダプタ

*他のプログラム* が所有する設定ファイルを HOCON としてマウントできます。自分の
ドキュメント内の `${...}` からその内容を参照できるようになります:

```ts
import { parseStringWithOptions } from '@o3co/ts.hocon'
import { loadEnv } from '@o3co/ts.hocon/adapters/env'

const base = loadEnv({ prefix: 'APP_' })            // APP_DB__HOST -> db.host
const cfg = parseStringWithOptions(src, { resolveSubstitutions: false })
const merged = cfg.withFallback(base).resolve()
```

解決を遅延させることが重要です。素の `parse` はパースしながら解決するため、
フォールバックを付ける前に `${...}` の解決が失敗してしまいます。

| サブパス | 必要な依存 | 備考 |
| --- | --- | --- |
| `@o3co/ts.hocon/adapters/properties` | — | `java.util.Properties`。`include` と構文レイヤーを共有 |
| `@o3co/ts.hocon/adapters/env` | — | プレフィックス付き名前空間の一括マウント。`.env` の読み込みも可能 |
| `@o3co/ts.hocon/adapters/jsonc` | — | コメントと末尾カンマを許す JSON |
| `@o3co/ts.hocon/adapters/json5` | — | JSON5 1.0.0。手書き scanner で依存ゼロ |
| `@o3co/ts.hocon/adapters/toml` | `smol-toml` | オプショナルなピア依存 |
| `@o3co/ts.hocon/adapters/yaml` | `yaml` 2.9.x | オプショナルなピア依存。スカラー解決はそのライブラリの答えで、`version: '1.2'` を明示してドリフトを防止 |

TOML と YAML のライブラリは **オプショナルなピア依存** なので、本パッケージを入れても
何も追加でインストールされません — 実際に使うものだけを足してください。プレーンな JSON に
アダプタは不要です（HOCON は JSON のスーパーセットです）。

外部のデータはあくまでデータです。マウントされた値の中の `${a.b}` は参照ではなく
リテラルなテキストとして扱われます。そのファイルは HOCON の構文に同意していない
プログラムのものだからです。

### 環境変数名の付け方

パス区切りは `__` だけです。変数名の中の `.` は境界ではなくキー文字なので、
`APP_FOO.BAR` と `APP_FOO__BAR` は別のキーであり、同時に設定できます:

```ts
const cfg = loadEnv({ prefix: 'APP_', env: { 'APP_FOO.BAR': 'dotted', APP_FOO__BAR: 'nested' } })
cfg.getString('"foo.bar"')   // "dotted"  — 名前にドットを含む 1 つのキー
cfg.getString('foo.bar')     // "nested"  — foo -> bar
```

### JSONC / YAML の数値

整数は精度を落とさずに取り込まれます。JS の `number` で表せない幅の整数リテラルも
桁がそのまま保持され、int64 の範囲を超える値は黙って壊れる代わりにエラーになります。
取得結果はゲッターによって変わります:

```ts
const cfg = parseJsonc('{"id": 9007199254740993}')
cfg.getString('id')   // "9007199254740993"  — ソースそのままの正確な値
cfg.getNumber('id')   // 9007199254740992    — JS の数値モデルで丸められる
cfg.toObject()        // { id: 9007199254740992 }
```

したがって大きな識別子（snowflake ID、台帳の連番など）は `getString` で読んでください。
`getNumber` と `toObject` は JavaScript の数値セマンティクスをそのまま適用します
（HOCON テキストに同じリテラルを書いた場合と同じ挙動です）。保証されるのは
**取り込み時に情報が失われない** ことです。

YAML のスカラー解決はそれ以外の点では `yaml` ライブラリのものです。アダプタは
デフォルト任せにせず `version: '1.2'` を明示し、`fromYamlValue` はデコード済みの
ツリーを受け取るため、別のライブラリやスキーマを使うこともできます。

## 既知の制限

- **`include url(...)`** は未対応です。リモート設定の取得はこのパーサーの範囲外です。アプリの HTTP クライアントで取得してから `parse()` に渡してください。
- **`include classpath(...)`** は未対応です。JVM 固有の include 形式で、Java ランタイム以外に対応物がありません。
- **watch / reload なし** — ライブラリはロード時にパースするだけです。ライブリロードが必要なら変更時に `parse()` / `parseFile()` を呼び直してください。
- **ストリーミングパーサーなし** — 入力全体をメモリに載せます。非常に大きな設定はパース前にサイズを検証してください（セキュリティ上の考慮事項を参照）。

## セキュリティ上の考慮事項

信頼できない HOCON 入力をパースする際は次に注意してください:

- **include のパストラバーサル:** 相対 `include` パスは `baseDir` から解決され、`..` セグメントで外に出て `/etc/passwd` のような機密ファイルに到達し得ます。信頼できない入力をパースするなら、パスを検証するカスタム `readFileSync`/`readFile` を渡してください。
- **入力サイズ:** パーサーに入力サイズ上限はありません。信頼できない入力は `parse()` の前にサイズを検証してください。
- **include の深さ:** 深い include 連鎖によるスタックオーバーフローを防ぐため 50 段に制限されています。
- **プロトタイプ汚染:** `__proto__` / `constructor` / `prototype` という名前のキーは
  **通常のキーとして保持されます**。`.properties` ファイルや環境変数がそれらを正当に
  使っていることがあり、落とせば黙ったデータ欠落になるからです。ライブラリ内部の安全性は
  拒否リストではなく構造で担保しています。ネスト構築には `__proto__` セッターを継承しない
  null プロトタイプのオブジェクトを使い、各アダプタと `toObject()` はキーを own データ
  プロパティとして定義します。パース自体は何も汚染せず、返るオブジェクトのプロトタイプは
  常に `Object.prototype` です。

  **重要なのは結果をどう扱うか** です。設定データが own な `__proto__` キーを持ち得ます:

  ```ts
  const data = cfg.toObject()
  { ...data }             // 安全
  structuredClone(data)   // 安全
  Object.assign({}, data) // 危険 — キーが消え、設定データがコピー先のプロトタイプになる
  deepMerge({}, data)     // 危険 — 素朴な再帰マージはグローバルな Object.prototype に書き込み得る
  ```

  いずれも **コピー先** オブジェクトのプロトタイプに起因するため、避けるのは利用側の責務です。
  コピーはスプレッドか `structuredClone`、走査は `Object.entries()` / `Object.keys()` を使い、
  `__proto__` を通常のキー名として扱ってください。制御下にない場所へ渡す場合は
  `cfg.toObject({ nullPrototype: true })` が何も継承しないツリーを返します（ただし利用側が
  素の `{}` にコピーする場合の問題までは解消できません）。

## ライセンス

Apache License 2.0 — [LICENSE](LICENSE) を参照。

Copyright 2026 1o1 Co. Ltd.
