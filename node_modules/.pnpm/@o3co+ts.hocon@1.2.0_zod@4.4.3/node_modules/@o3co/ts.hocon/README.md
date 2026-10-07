# ts.hocon — HOCON Parser for TypeScript

[![npm](https://img.shields.io/npm/v/@o3co/ts.hocon.svg)](https://www.npmjs.com/package/@o3co/ts.hocon)
[![CI](https://github.com/o3co/ts.hocon/actions/workflows/test.yml/badge.svg)](https://github.com/o3co/ts.hocon/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/o3co/ts.hocon/branch/main/graph/badge.svg)](https://codecov.io/gh/o3co/ts.hocon)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

A [Lightbend HOCON](https://github.com/lightbend/config/blob/main/HOCON.md) parser for TypeScript. See [Spec Compliance](#spec-compliance) for the current conformance rate.

> **Implemented by [Claude](https://claude.ai/) (Anthropic)** — designed and built end-to-end with Claude Code.
> Reviewed by [GitHub Copilot](https://github.com/features/copilot) and [OpenAI Codex](https://openai.com/index/openai-codex/).

[日本語](README.ja.md)

> **Library stance:** ts.hocon is a HOCON config loader — its purpose is reading `.hocon` config files and providing typed access via the Config API (`getString`, `getNumber`, `getBoolean`, `getDuration`, `getBytes`, `toObject`). It is not a low-level parser API. Internal types like `HoconValue` may change between minor versions.
>
> **Cross-language conformance:** This implementation is tested against shared expected-JSON fixtures from [o3co/xx.hocon](https://github.com/o3co/xx.hocon) alongside [go.hocon](https://github.com/o3co/go.hocon) and [rs.hocon](https://github.com/o3co/rs.hocon) to ensure all three implementations meet the same Lightbend HOCON specification.

---

## Quick Start

### 1. Install

```bash
npm install @o3co/ts.hocon
```

Requires Node.js 22+.

### 2. Use

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

## Why HOCON?

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

HOCON gives you the readability of YAML, the structure of JSON, and features that neither has — substitutions, includes, and deep merge. If your config is more than a few flat key-value pairs, HOCON is worth considering.

## Features

- Full HOCON parsing: objects, arrays, scalars, substitutions (`${path}`, `${?path}`)
- Self-referential substitutions (`path = ${path}:/extra`)
- Deep-merge for duplicate keys (last definition wins)
- `+=` append operator
- `include "file.conf"` and `include file("file.conf")` directives
- Triple-quoted strings (`"""..."""`)
- Duration and byte size parsing (`getDuration()`, `getBytes()`)
- Sync and async API (`parse` / `parseAsync` / `parseFile` / `parseFileAsync`)
- ESM + CJS dual package
- Optional [Zod](https://zod.dev/) integration for schema validation
- Browser compatible (`parse`/`parseAsync` — no Node.js required)

## API

For full API documentation, see [o3co.github.io/ts.hocon](https://o3co.github.io/ts.hocon/) (generated with TypeDoc, updated on each minor/major release).

### Parse functions

```ts
import { parse, parseAsync, parseFile, parseFileAsync } from '@o3co/ts.hocon'
import type { ParseOptions } from '@o3co/ts.hocon'

parse(input: string, opts?: ParseOptions): Config
parseAsync(input: string, opts?: ParseOptions): Promise<Config>
parseFile(path: string, opts?: ParseOptions): Config
parseFileAsync(path: string, opts?: ParseOptions): Promise<Config>
```

`ParseOptions`:
| Option | Type | Description |
|--------|------|-------------|
| `baseDir` | `string` | Base directory for `include` resolution |
| `env` | `Record<string, string>` | Environment variables for substitution (default: `process.env`) |
| `readFileSync` | `(path: string) => string` | Custom file reader (sync) |
| `readFile` | `(path: string) => Promise<string>` | Custom file reader (async) |

### Config methods

| Method | Returns | Throws if |
|--------|---------|-----------|
| `get(path)` | `unknown \| undefined` | — |
| `getString(path)` | `string` | missing, wrong type |
| `getNumber(path)` | `number` | missing, wrong type |
| `getBoolean(path)` | `boolean` | missing, wrong type |
| `getConfig(path)` | `Config` | missing, not an object |
| `getList(path)` | `unknown[]` | missing, not an array |
| `getDuration(path, unit?)` | `number` | missing, not a string, or invalid duration format |
| `getBytes(path, unit?)` | `number` | missing, not a string, or invalid byte size format |
| `has(path)` | `boolean` | — |
| `keys()` | `string[]` | — |
| `withFallback(fallback)` | `Config` | — |
| `toObject()` | `unknown` | — |

### Zod integration

```ts
import { validate, getValidated } from '@o3co/ts.hocon/zod'
import { z } from 'zod'

const Schema = z.object({
  server: z.object({
    host: z.string(),
    port: z.number().int(),
  }),
})

// Validate entire config
const app = validate(cfg, Schema)

// Validate a single path
const port = getValidated(cfg, 'server.port', z.number().int())
```

Install Zod as a peer dependency:
```bash
npm install zod
```

### Error types

```ts
import { ParseError, ResolveError, ConfigError } from '@o3co/ts.hocon'

// ParseError   — lexing/parsing failure: .line, .col, .file?
// ResolveError — substitution/include failure: .path, .line, .col, .file?
// ConfigError  — wrong type or missing path: .path
```

## HOCON Examples

```hocon
# Comments with # or //
database {
  host = "db.example.com"
  port = 5432
  url  = "jdbc:"${database.host}":"${database.port}
}

# Duplicate keys deep-merge (last wins for scalars)
server { host = localhost }
server { port = 8080 }      // result: { host: "localhost", port: 8080 }

# Self-referential append
path = "/usr/bin"
path = ${path}":/usr/local/bin"

# += shorthand
items = [1]
items += 2
items += 3   // [1, 2, 3]

# Include
include "defaults.conf"
include file("overrides.conf")

# Triple-quoted multiline strings
description = """
  This is a
  multiline string.
"""
```

### Duration and Byte Sizes

```ts
const c = parse(`
  timeout   = "30s"
  cache-ttl = "5m"
  max-size  = "512MiB"
`)

c.getDuration('timeout')        // 30000 (ms)
c.getDuration('timeout', 's')   // 30
c.getDuration('cache-ttl', 'm') // 5

c.getBytes('max-size')          // 536870912 (bytes)
c.getBytes('max-size', 'MiB')  // 512
```

Supported duration units: `ns`, `us`, `ms`, `s`, `m`, `h`, `d` (and long forms like `seconds`, `minutes`).
Supported byte units: `B`, `KB`/`KiB`, `MB`/`MiB`, `GB`/`GiB`, `TB`/`TiB` (and long forms like `megabytes`, `mebibytes`).

## Spec Compliance

Conformance against the [Lightbend HOCON specification](https://github.com/lightbend/config/blob/main/HOCON.md) is tracked at item granularity in [`docs/spec-compliance.md`](docs/spec-compliance.md). The table below is a snapshot as of 2026-05-13; see [`xx.hocon/docs/compliance-matrix.md`](https://github.com/o3co/xx.hocon/blob/main/docs/compliance-matrix.md) for live cross-impl values.

| Metric                                | Status        |
| ------------------------------------- | ------------- |
| Spec total (incl. out-of-scope)       | **74.2%**     |
| In-scope only                         | **83.3%**     |
| Lightbend `test01`–`test13` suite     | 13/13 passing |

Not supported in v0.1.0:

- `include url(...)`
- `include classpath(...)`

Supported since v0.2.0 (P1):

- `.properties` file parsing

### Stricter than Lightbend

- **S8.6 leading-hyphen rejection** (Unreleased): `a = -foo`, `a = -bar`, `a = -` etc. now raise a lex error per HOCON.md L270–276, where Lightbend silently falls back to unquoted strings. Mitigation: quote the value (`a = "-foo"`). See [CHANGELOG](CHANGELOG.md#unreleased) and [`docs/spec-compliance.md`](docs/spec-compliance.md) §S8.6.

## Performance

### ts.hocon Parsing Cost

Measured with [Vitest bench](https://vitest.dev/guide/features.html#benchmarking) (tinybench). Run `pnpm bench` to reproduce.

| Scenario | ops/sec | Time per op |
|---|---|---|
| Small config (10 keys) | ~200,000 | ~5 µs |
| Medium config (100 keys) | ~23,000 | ~43 µs |
| Large config (1,000 keys) | ~2,100 | ~476 µs |
| 10 substitutions | ~74,000 | ~14 µs |
| 50 substitutions | ~14,000 | ~71 µs |
| 100 substitutions | ~6,900 | ~145 µs |
| Depth 5 nesting | ~210,000 | ~5 µs |
| Depth 10 nesting | ~147,000 | ~7 µs |
| Depth 20 nesting | ~80,000 | ~13 µs |

### Comparison with JSON.parse

JSON.parse is V8's native C++ implementation — the fastest possible baseline. This comparison shows the overhead of HOCON's rich feature set.

| Config Size | ts.hocon | JSON.parse | Ratio |
|---|---|---|---|
| Small (10 keys) | ~198K ops/s | ~1,967K ops/s | ~10x |
| Medium (100 keys) | ~23K ops/s | ~280K ops/s | ~12x |
| Large (1,000 keys) | ~2.2K ops/s | ~12K ops/s | ~5.4x |

For typical application configs (loaded once at startup), the parsing cost is negligible — even a 1,000-key config parses in under 0.5 ms.

### Feature Comparison with node-config

ts.hocon provides significantly richer configuration capabilities compared to [node-config](https://github.com/node-config/node-config) (JSON):

| Feature | ts.hocon | node-config (JSON) |
|---|---|---|
| Comments | `//` `#` | No |
| Multi-line strings | `"""..."""` | No |
| Substitution (`${path}`) | Yes | No |
| Optional substitution (`${?path}`) | Yes | No |
| Environment variable reference | Yes (via substitution) | Partial (`custom-environment-variables` file) |
| Include | Yes | No |
| Deep merge | Yes (arrays too) | Partial (arrays replaced) |
| Append operator (`+=`) | Yes | No |
| Environment-based config | Configurable via HOCON | Yes (filename convention) |
| Schema validation | Zod integration | No |
| Programmatic API | `parse(string)` | File-based initialization, then `get()` |
| Typed getters | `getString`, `getNumber`, etc. | `get()` (any) |

## Browser Compatibility

`parse()` and `parseAsync()` work in browsers. `parseFile()` and `parseFileAsync()` require Node.js (or a custom `readFileSync`/`readFile` option).

```ts
// Browser usage with custom file loader
const cfg = await parseAsync(hoconString, {
  readFile: async (path) => {
    const res = await fetch(`/config/${path}`)
    return res.text()
  },
})
```

## Best Practices

### Config Structure

- **Split by domain**: Separate configuration into logical units (`database.conf`, `server.conf`, `logging.conf`)
- **Use `include` for composition**: Compose a full config from domain-specific files
- **Avoid logic in config**: HOCON is for declarative data, not conditionals or computation

### Environment Variables

- **Minimize `${ENV}` usage**: Prefer `${?ENV}` (optional) with sensible defaults defined in the config itself
- **Never require env vars for local development**: Defaults should work out of the box
- **Document required env vars**: List them in your project's README or a `.env.example`

### Dev / Prod Separation

```text
config/
├── application.conf    # shared defaults
├── dev.conf            # include "application.conf" + dev overrides
└── prod.conf           # include "application.conf" + prod overrides
```

### Validation

- Always validate config at application startup, not at point-of-use
- Use schema validation (Zod for TypeScript, struct unmarshaling for Go, Serde for Rust) to catch errors early

```typescript
import { parseWithSchema } from '@o3co/ts.hocon/zod'
import { z } from 'zod'

const schema = z.object({
  server: z.object({ host: z.string(), port: z.number() }),
  debug: z.boolean(),
})
const config = parseWithSchema(hoconInput, schema) // fails fast on startup
```

## Related Projects

| Project | Language | Registry | Description |
|---------|----------|----------|-------------|
| [go.hocon](https://github.com/o3co/go.hocon) | Go | [pkg.go.dev](https://pkg.go.dev/github.com/o3co/go.hocon) | HOCON parser for Go |
| [rs.hocon](https://github.com/o3co/rs.hocon) | Rust | [crates.io](https://crates.io/crates/o3co-hocon) | HOCON parser for Rust |
| [hocon2](https://github.com/o3co/hocon2) | Go | [pkg.go.dev](https://pkg.go.dev/github.com/o3co/hocon2) | HOCON → JSON/YAML/TOML/Properties CLI |

The three parser implementations ([ts.hocon](https://github.com/o3co/ts.hocon), [rs.hocon](https://github.com/o3co/rs.hocon), [go.hocon](https://github.com/o3co/go.hocon)) are all tracked against the same Lightbend HOCON spec — see the [cross-impl roll-up](https://github.com/o3co/xx.hocon/blob/main/docs/compliance-matrix.md) for per-impl conformance rates.

## Known Limitations

- **`include url(...)`** is not supported. Fetching remote configuration is outside the scope of this parser. Use your application's HTTP client to fetch the content, then pass it to `parse()`.
- **`include classpath(...)`** is not supported. This is a JVM-specific include form with no equivalent outside Java runtimes.
- **No watch/reload** — the library parses config at load time. For live-reloading, re-call `parse()` or `parseFile()` on change.
- **No streaming parser** — the entire input is loaded into memory. For very large configs, validate input size before parsing (see Security Considerations).
- **`.properties` include** — supports basic `key=value` / `key:value` syntax. Does not support multiline values (backslash continuation), Unicode escapes, or key escaping from the full Java .properties specification.

## Security Considerations

When parsing untrusted HOCON input, be aware of:

- **Path traversal in includes:** `include "../../../etc/passwd"` will resolve relative to `baseDir`. Use a custom `readFileSync`/`readFile` that validates paths if parsing untrusted input.
- **Input size:** The parser has no built-in input size limit. For untrusted input, validate size before calling `parse()`.
- **Include depth:** Limited to 50 levels to prevent stack overflow from deep include chains.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

Copyright 2026 1o1 Co. Ltd.
