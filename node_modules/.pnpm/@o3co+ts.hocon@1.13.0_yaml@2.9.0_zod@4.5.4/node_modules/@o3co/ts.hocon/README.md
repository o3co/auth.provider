# ts.hocon — HOCON Parser for TypeScript

[![npm](https://img.shields.io/npm/v/@o3co/ts.hocon.svg)](https://www.npmjs.com/package/@o3co/ts.hocon)
[![CI](https://github.com/o3co/ts.hocon/actions/workflows/test.yml/badge.svg)](https://github.com/o3co/ts.hocon/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/o3co/ts.hocon/branch/develop/graph/badge.svg)](https://codecov.io/gh/o3co/ts.hocon)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

A [Lightbend HOCON](https://github.com/lightbend/config/blob/main/HOCON.md) parser for TypeScript. See [Spec Compliance](#spec-compliance) for the current conformance rate.

> **Implemented by [Claude](https://claude.ai/) (Anthropic)** — designed and built end-to-end with Claude Code.
> Reviewed by [GitHub Copilot](https://github.com/features/copilot) and [OpenAI Codex](https://openai.com/index/openai-codex/).

[日本語](README.ja.md)

> **Library stance:** ts.hocon is a HOCON config loader — its purpose is reading `.hocon` config files and providing typed access via the Config API (`getString`, `getNumber`, `getBoolean`, `getDuration`, `getBytes`, `toObject`). It is not a low-level parser API. Internal types like `HoconValue` may change between minor versions.
>
> **Cross-language conformance:** This implementation is tested against shared expected-JSON fixtures from [o3co/xx.hocon](https://github.com/o3co/xx.hocon) alongside [go.hocon](https://github.com/o3co/go.hocon), [rs.hocon](https://github.com/o3co/rs.hocon), and [py.hocon](https://github.com/o3co/py.hocon) to ensure all four implementations meet the same Lightbend HOCON specification.

---

## Quick Start

### 1. Install

```bash
npm install @o3co/ts.hocon
```

Requires Node.js 22+.

Both module systems are supported — `import` and `require` reach the same
entrypoints, including every `adapters/*` subpath:

```ts
import { parse } from '@o3co/ts.hocon'          // ESM
const { parse } = require('@o3co/ts.hocon')     // CJS
```

On every PR and every release, CI loads all seven exports both ways against the
built artifact, calls each one (including a package-scoped `include`, which
behaves differently per bundle format), and checks that each condition declares
its own type declarations. That gate exists because 1.10.0 shipped with all
seven CJS entrypoints throwing at load; it catches that class of defect rather
than promising none can exist.

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

HOCON isn't just a serialization format — it's a **config-injection language**. JSON, YAML, and TOML describe data structures and leave file layering, environment variables, and reference resolution to your code (Pydantic, Serde, Zod, etc.). HOCON bakes those into the spec itself: by the time your program reads the config, fallback files are merged and `${VAR}` references resolved into a single composed object. Conditional branching from "is this value present in this layer?" disappears at the format boundary.

On top of that, HOCON combines the readability of YAML with the structure of JSON — making it a strong fit for anything beyond flat key-value config.

## Features

- Full HOCON parsing: objects, arrays, scalars, substitutions (`${path}`, `${?path}`)
- Self-referential substitutions (`path = ${path}:/extra`)
- Deep-merge for duplicate keys (last definition wins)
- `+=` append operator
- `include "file.conf"` and `include file("file.conf")` directives
- Triple-quoted strings (`"""..."""`)
- Duration and byte size parsing (`getDuration()`, `getBytes()`)
- HOCON emitter (`renderHocon()`) — renders a resolved `Config` back to HOCON text; re-parsing yields the same value tree (E18 round-trip contract)
- Sync and async API (`parse` / `parseAsync` / `parseFile` / `parseFileAsync`)
- ESM + CJS dual package (every entrypoint smoke-tested in both formats on each CI run)
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
| `getString(path)` | `string` | missing, wrong type, or unresolved |
| `getNumber(path)` | `number` | missing, wrong type, or unresolved |
| `getBoolean(path)` | `boolean` | missing, wrong type, or unresolved |
| `getConfig(path)` | `Config` | missing, not an object, or unresolved |
| `getList(path)` | `unknown[]` | missing, not an array, or unresolved |
| `getDuration(path, unit?)` | `number` | missing, not a string, or invalid duration format |
| `getBytes(path, unit?)` | `number` | missing, not a string, or invalid byte size format |
| `has(path)` | `boolean` | — |
| `keys()` | `string[]` | — |
| `withFallback(fallback)` | `Config` | — |
| `resolve(opts?)` | `Config` | unresolvable substitution (unless `allowUnresolved: true`) |
| `resolveWith(source, opts?)` | `Config` | source unresolved, or unresolvable substitution |
| `isResolved()` | `boolean` | — |
| `toObject()` | `unknown` | — |
| `renderHocon()` | `string` | unresolved |

### Deferred resolution API (E12)

Separate the parse, fallback-layering, and resolve steps for runtime config injection.

```ts
import { parseStringWithOptions, fromMap, empty } from '@o3co/ts.hocon'
import type { ResolveOptions } from '@o3co/ts.hocon'

// 1. Parse without resolving — substitutions deferred
const cfg = parseStringWithOptions(
  'version = ${shortversion}-${CI_RUN_NUMBER}\nvariables { shortversion = "1.2.3" }',
  { resolveSubstitutions: false }
)
cfg.isResolved() // false — ${CI_RUN_NUMBER} still pending

// 2. Layer runtime fallbacks
const runtime = fromMap({ CI_RUN_NUMBER: '42' })
const vars = cfg.getConfig('variables')   // already available (not a substitution)
const merged = cfg.withFallback(runtime).withFallback(vars)

// 3. Resolve the full fallback stack
const resolved = merged.resolve({ useSystemEnvironment: false })
resolved.getString('version') // "1.2.3-42"

// resolveWith: resolve receiver using source for lookup, source keys NOT in result
const receiver = parseStringWithOptions('r = ${key}', { resolveSubstitutions: false })
const source = fromMap({ key: 'val' })
const result = receiver.resolveWith(source)
result.has('key')    // false — source keys excluded
result.getString('r') // "val"
```

`ResolveOptions`:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `useSystemEnvironment` | `boolean` | `true` | Consult `process.env` for substitution fallback |
| `allowUnresolved` | `boolean` | `false` | Leave unresolvable substitutions in place (no error) |

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

Supported duration units: `ns`, `us`, `ms`, `s`, `m`, `h`, `d` (and long forms like `seconds`, `minutes`). Duration unit names are case-sensitive and must be lowercase (HOCON spec). Byte units are more case-tolerant: the canonical forms below plus lowercase aliases (`kb`, `kib`, …), any-case long forms (`megabytes`), and single-letter powers-of-two in both cases (`K`/`k`, per Lightbend).
Supported byte units: `B`, `KB`/`KiB`, `MB`/`MiB`, `GB`/`GiB`, `TB`/`TiB` (and long forms like `megabytes`, `mebibytes`).

## Spec Compliance

Conformance against the [Lightbend HOCON specification](https://github.com/lightbend/config/blob/main/HOCON.md) is tracked at item granularity in [`docs/spec-compliance.md`](docs/spec-compliance.md), which is the source these rates are computed from — `tests/docs.test.ts` recomputes them and fails the build if this table drifts. See [`xx.hocon/docs/compliance-matrix.md`](https://github.com/o3co/xx.hocon/blob/main/docs/compliance-matrix.md) for the cross-implementation roll-up.

| Metric                                | Status        |
| ------------------------------------- | ------------- |
| Spec total (incl. out-of-scope)       | **90.0%**     |
| In-scope only                         | **100.0%**    |
| Lightbend `test01`–`test13` suite     | 13/13 passing |

**Extra-spec conventions (E-series) — implementation status:**

| Item | Description | Status |
|------|-------------|--------|
| E11  | `include package(...)` service-locator includes | ✅ v1.3.0 |
| E12  | Deferred substitution resolution (`parse → withFallback → resolve()` lifecycle) | ✅ v1.4.0 |

Not supported:

- `include url(...)`
- `include classpath(...)`

Supported since v0.2.0 (P1):

- `.properties` file parsing

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

Feature-level comparison with [node-config](https://github.com/node-config/node-config) **v4.4.2** reading JSON config files, as of 2026-07-26:

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
- **Name variables with `__`, never `.`**: when bulk-mounting with `loadEnv` (or
  `parseDotEnv`), `__` is the *only* thing that creates hierarchy. A dot is
  ordinary key text, so the two spellings below are different keys and both
  survive:

  ```text
  APP_FOO__BAR=nested   # -> foo.bar      : cfg.getString('foo.bar')
  APP_FOO.BAR=dotted    # -> "foo.bar"    : cfg.getString('"foo.bar"')
  ```

  A single `_` also stays part of its segment (`APP_DB__MAX_CONN` → `db.max_conn`).

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
| [py.hocon](https://github.com/o3co/py.hocon) | Python | [PyPI](https://pypi.org/project/hocon-parser/) | HOCON parser for Python |
| [hocon2](https://github.com/o3co/hocon2) | Go | [pkg.go.dev](https://pkg.go.dev/github.com/o3co/hocon2) | HOCON → JSON/YAML/TOML/Properties CLI |

The four parser implementations ([ts.hocon](https://github.com/o3co/ts.hocon), [rs.hocon](https://github.com/o3co/rs.hocon), [go.hocon](https://github.com/o3co/go.hocon), [py.hocon](https://github.com/o3co/py.hocon)) are all tracked against the same Lightbend HOCON spec — see the [cross-impl roll-up](https://github.com/o3co/xx.hocon/blob/main/docs/compliance-matrix.md) for per-impl conformance rates.

## Format adapters

Config files that belong to *other* programs can be mounted as HOCON, so a
`${...}` in your document can reach into them:

```ts
import { parseStringWithOptions } from '@o3co/ts.hocon'
import { loadEnv } from '@o3co/ts.hocon/adapters/env'

const base = loadEnv({ prefix: 'APP_' })            // APP_DB__HOST -> db.host
const cfg = parseStringWithOptions(src, { resolveSubstitutions: false })
const merged = cfg.withFallback(base).resolve()
```

Deferring resolution matters: the plain `parse` resolves as it goes, so a
`${...}` aimed at the fallback would fail before the fallback is attached.

| Subpath | Needs | Notes |
| --- | --- | --- |
| `@o3co/ts.hocon/adapters/properties` | — | `java.util.Properties`, sharing the `include` syntax layer |
| `@o3co/ts.hocon/adapters/env` | — | Bulk-mounts a prefixed namespace; also reads `.env` |
| `@o3co/ts.hocon/adapters/jsonc` | — | JSON with comments and trailing commas |
| `@o3co/ts.hocon/adapters/json5` | — | JSON5 1.0.0, hand-rolled scanner, zero dependencies |
| `@o3co/ts.hocon/adapters/toml` | `smol-toml` | Optional peer dependency |
| `@o3co/ts.hocon/adapters/yaml` | `yaml` 2.9.x | Optional peer dependency; scalar resolution is that library's answer, with `version: '1.2'` declared so it cannot drift |

The TOML and YAML libraries are **optional peer dependencies**, so installing
this package still pulls in nothing — you add the one you actually use. Plain
JSON needs no adapter at all, HOCON being a JSON superset.

Foreign data stays data: a `${a.b}` in a mounted value is literal text, never a
reference, because the file belongs to a program that never agreed to HOCON's
syntax.

### Environment variable names

`__` is the only path separator, so a literal `.` in a variable name is key
text rather than a boundary — `APP_FOO.BAR` and `APP_FOO__BAR` are two
different keys and can be set at the same time:

```ts
const cfg = loadEnv({ prefix: 'APP_', env: { 'APP_FOO.BAR': 'dotted', APP_FOO__BAR: 'nested' } })
cfg.getString('"foo.bar"')   // "dotted"  — one key whose name contains a dot
cfg.getString('foo.bar')     // "nested"  — foo -> bar
```

### Numbers from JSONC, JSON5 and YAML

Integers are ingested losslessly: an integer literal too wide for a JS `number`
keeps its digits instead of being rounded, and one outside the int64 range is
refused rather than silently mangled (JSON5's hex integers included). What you
get back depends on the getter:

```ts
const cfg = parseJsonc('{"id": 9007199254740993}')
cfg.getString('id')   // "9007199254740993"  — exact, the source's own text
cfg.getNumber('id')   // 9007199254740992    — the JS number model rounds
cfg.toObject()        // { id: 9007199254740992 }
```

So read large identifiers (snowflake IDs, ledger sequence numbers) with
`getString`. `getNumber` and `toObject` apply JavaScript's own number
semantics, exactly as they do for the same literal written in HOCON text — the
guarantee is that nothing is lost *on the way in*.

YAML scalar resolution otherwise belongs to the `yaml` library; the adapter
declares `version: '1.2'` rather than trusting a default, and `fromYamlValue`
takes an already-decoded tree so you can use a different library or schema.

## Known Limitations

- **`include url(...)`** is not supported. Fetching remote configuration is outside the scope of this parser. Use your application's HTTP client to fetch the content, then pass it to `parse()`.
- **`include classpath(...)`** is not supported. This is a JVM-specific include form with no equivalent outside Java runtimes.
- **No watch/reload** — the library parses config at load time. For live-reloading, re-call `parse()` or `parseFile()` on change.
- **No streaming parser** — the entire input is loaded into memory. For very large configs, validate input size before parsing (see Security Considerations).

## Security Considerations

When parsing untrusted HOCON input, be aware of:

- **Path traversal in includes:** a relative `include` path resolves against `baseDir` and can climb out of it with `..` segments to reach sensitive files such as `/etc/passwd`. Use a custom `readFileSync`/`readFile` that validates paths if parsing untrusted input.
- **Input size:** The parser has no built-in input size limit. For untrusted input, validate size before calling `parse()`.
- **Include depth:** Limited to 50 levels to prevent stack overflow from deep include chains.
- **Mapped path depth:** an environment variable's `__` segments and a
  `.properties` dotted key are limited to 64 segments. One name produces one
  arbitrarily deep chain, so without the cap a single long variable name was
  enough to exhaust the stack. rs.hocon and py.hocon cap the same mapping at 64.
- **Document nesting depth:** not capped. A document nested past what the
  engine's stack holds fails as `ParseError` or `ConfigError` — never as a bare
  `RangeError` — but the depth at which that happens depends on how deep the
  calling code already is, so validate size before parsing untrusted input (see
  above) rather than relying on a fixed level.
- **Prototype pollution:** keys named `__proto__`, `constructor` or `prototype`
  are **kept as ordinary keys** — a `.properties` file or environment variable
  may legitimately use them, and dropping them would be silent data loss.
  Safety inside this library is structural rather than a denylist: the nesting
  step builds null-prototype objects, which inherit no `__proto__` setter, every
  adapter materializes objects by defining own data properties, and `toObject()`
  does the same. Parsing pollutes nothing, and the returned object's prototype is
  always `Object.prototype`.

  **What you do with the result matters**, because config data can now hand you
  an own `__proto__` key:

  ```ts
  const data = cfg.toObject()
  { ...data }             // safe
  structuredClone(data)   // safe
  Object.assign({}, data) // NOT safe — the key vanishes and config data becomes
                          //            the copy's prototype
  deepMerge({}, data)     // NOT safe — a naive recursive merge can write onto
                          //            the global Object.prototype
  ```

  Both hazards come from the *destination* object's prototype, so they are the
  consumer's to avoid: copy with spread or `structuredClone`, iterate with
  `Object.entries()` / `Object.keys()`, and treat `__proto__` as an ordinary
  key name. `cfg.toObject({ nullPrototype: true })` returns a tree that inherits
  nothing — useful when the data is going somewhere you do not control, though it
  cannot fix a consumer that copies into a plain `{}`.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

Copyright 2026 1o1 Co. Ltd.
