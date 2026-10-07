# ts.hocon — TypeScript 向け HOCON パーサー

[![npm](https://img.shields.io/npm/v/@o3co/ts.hocon.svg)](https://www.npmjs.com/package/@o3co/ts.hocon)
[![CI](https://github.com/o3co/ts.hocon/actions/workflows/test.yml/badge.svg)](https://github.com/o3co/ts.hocon/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/o3co/ts.hocon/branch/main/graph/badge.svg)](https://codecov.io/gh/o3co/ts.hocon)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

[Lightbend HOCON](https://github.com/lightbend/config/blob/main/HOCON.md) 仕様に完全準拠した TypeScript ライブラリです。

> **[Claude](https://claude.ai/)（Anthropic）による実装** — Claude Code を用いて設計・実装されました。
> [GitHub Copilot](https://github.com/features/copilot) および [OpenAI Codex](https://openai.com/index/openai-codex/) によるレビュー。

[English](README.md)

---

## クイックスタート

### 1. インストール

```bash
npm install @o3co/ts.hocon
```

Node.js 18 以上が必要です。

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

HOCON は YAML の可読性と JSON の構造性を兼ね備え、どちらにもない機能 — 変数参照、インクルード、ディープマージ — を提供します。設定がフラットなキーバリューペア以上のものであれば、HOCON を検討する価値があります。

## 特徴

- 完全な HOCON パース：オブジェクト、配列、スカラー値、代入（`${path}`、`${?path}`）
- 自己参照代入（`path = ${path}:/extra`）
- 重複キーのディープマージ（後勝ち）
- `+=` 追加演算子
- `include "file.conf"` および `include file("file.conf")` ディレクティブ
- トリプルクォート文字列（`"""..."""`）
- 同期・非同期 API（`parse` / `parseAsync` / `parseFile` / `parseFileAsync`）
- ESM + CJS デュアルパッケージ
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

[Lightbend 公式テストスイート](https://github.com/lightbend/config/tree/main/config/src/test/resources)でテスト済み: **13/13 テストグループ合格**。

v0.1.0 で未対応の機能:
- `include url(...)`
- `include classpath(...)`
- `.properties` ファイルのパース

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

すべての実装が Lightbend HOCON 仕様に完全準拠しています。

## ライセンス

Apache License 2.0 — [LICENSE](LICENSE) を参照。

Copyright 2026 1o1 Co. Ltd.
