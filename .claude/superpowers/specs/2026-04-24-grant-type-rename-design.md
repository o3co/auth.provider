# Grant Type Rename — Design Spec

**Date:** 2026-04-24
**Scope:** auth.provider v0.5.0 — Core GA must #3 (`grant_type` RFC 準拠 + URN 化)
**Status:** Draft → pending user review

**Revision history:**

- 2026-04-24 initial draft
- 2026-04-24 Codex review round 1 fixes:
  - §3.6 renamed "Audit Event" → "Grant Policy + Audit Event" to include policy interface impact
  - §4.3 updated to note `routes.mts:466` is grant-policy input (breaking for policy adapters)
  - §3.9 new section: "Grant Registration Skip — No Logger" decision + rationale
  - §4.1 Module init sketch updated to match §3.9 (no-log approach)

## 1. Background & Motivation

v0.5.0 の Core GA must 項目のうち、interface freeze に直結する grant_type 整理を行う。現状の grant_type 値には以下の問題がある:

1. **RFC 違反:** `grant_type=authorization` は RFC 6749 §4.1.3 違反。正式値は `authorization_code`。
2. **DID grant の URN 化未実施:** 独自 grant `did` は裸の文字列で登録されているが、RFC 6755 に倣い独自 grant は URN 形式で識別すべき。
3. **Namespace の vendor leak 懸念:** URN 化するときライブラリ側が `o3co` 等の namespace を押し付けると、consumer に library owner のアイデンティティが残留する。

v0.5.0 は 1.0 GA 前の最後の interface 調整ラウンド。ここで RFC 準拠形に倒しきり、1.0 で freeze する。

## 2. Scope

### In Scope

- `authorization` → `authorization_code` の rename (RFC 6749 準拠)
- DID grant の URN 化 + `urnCustomGrantTypePrefix` config 新設
- Audit event の grant_type 表記統一 (wire 値を記録)
- Standalone template / README / CHANGELOG の追従

### Out of Scope

本 spec は **rename と URN 設計のみ**。以下は別 spec で扱う:

- Token Exchange (RFC 8693) 実装 — v0.5.0 #2
- jwt-bearer (RFC 7523) 実装 — v0.5.0 #4
- NonceStore interface — v0.5.0 #5
- DPoP interface 予約 — v0.5.0 #19
- dplaas.auth 追従 — v0.5.0 publish 完了後に一括

ただし Token Exchange と jwt-bearer の URN は IETF 登録済み値なので、本 spec で URN 設計時に「IETF 標準 URN は `urnCustomGrantTypePrefix` の適用外、固定値で register」という棲み分けルールだけ確定させる。実装箇所は別 spec。

## 3. Design Decisions

### 3.1 Compatibility Strategy — Hard Break

- v0.5.0 で旧値 (`authorization` / `did`) を **即座に拒否** する
- Registry lookup が見つからないので既存フロー (`routes.mts:157-173`) で `unsupported_grant_type` を返す
- Dual-accept や legacy alias flag は導入しない

**Rationale:**

- `authorization` は RFC 6749 違反。互換維持はそれ自体が spec 違反の継続
- v0.4.0 → v0.5.0 間で breaking は他にも複数発生 (passport 脱出済 / Token Exchange / jwt-bearer 等)。grant_type だけ dual-accept しても consumer の総移行コストは下がらない
- 内製 consumer (dplaas.auth) は v0.5.0 publish 完了後に一括追従する方針 (Option X) が既に決定済み

### 3.2 URN Structure — Consumer Owns the Prefix Granularity

URN 形式の grant_type 値は以下で組み立てる:

```text
urn:${urnCustomGrantTypePrefix}:did
```

- `urn:` prefix と `:did` suffix はライブラリが付与
- 中間部分 `urnCustomGrantTypePrefix` は **consumer が任意粒度で指定**
- ライブラリは namespace 粒度を強制しない (RFC 6755 の `params:oauth:grant-type` 構造を押し付けない)

**Examples:**

| `urnCustomGrantTypePrefix` | Resulting `grant_type` |
| --- | --- |
| `o3co:oauth:grant-type` | `urn:o3co:oauth:grant-type:did` |
| `acme:oauth:grant-type` | `urn:acme:oauth:grant-type:did` |
| `example.com:grants` | `urn:example.com:grants:did` |
| `acme` | `urn:acme:did` |

**Rationale:**

- `ns` の粒度はライブラリではなく consumer が決めるべき (branding / governance 観点)
- RFC 6755 の `params:oauth:grant-type:*` は IETF が自分の URN namespace 内で IANA parameter registry を指す含意を持つ規約であり、IETF 以外 (consumer 独自 namespace) に `params` を入れる必然性はない
- Consumer が RFC 互換の見た目を望めば `ietf:params:oauth:grant-type` (ただし IETF registry 未登録値を流すのは規約違反なので通常しない) も書ける柔軟性を持たせる

### 3.3 No Default — Omission Disables DID Grant (Pattern β)

- `urnCustomGrantTypePrefix` は **Zod schema で optional、default なし**
- 未指定なら:
  - DID grant module は **register を skip**
  - 起動は成功する
  - Client が DID grant を使おうとすると `unsupported_grant_type` エラーが返る

通知方針 (ログ出力の有無) は §3.9 で詳述。

**Rationale:**

- デフォルト値 (`o3co` 等) を設定すると、そのまま使う consumer が必ず出て vendor leak が発生する
- `did.enabled = true` と `urnCustomGrantTypePrefix` 未指定を config error にする (Pattern α) 案もあるが、Quickstart で DID を試さない consumer (OAuth のみの利用者) に起動障壁を課すことになる
- Pattern β (silent skip) なら:
  - OAuth のみ利用する consumer は config 不要で起動できる
  - DID を使おうとした consumer は `unsupported_grant_type` で即座に気付く

### 3.4 IETF-Registered URN Grants — Fixed Values, Not Customizable

Token Exchange (RFC 8693) / jwt-bearer (RFC 7523) は IETF 登録済み URN:

- `urn:ietf:params:oauth:grant-type:token-exchange`
- `urn:ietf:params:oauth:grant-type:jwt-bearer`

これらは **config 不要の固定値として register** する。`urnCustomGrantTypePrefix` の影響を受けない。

**Rationale:**

- IETF registry 値は RFC 6755 §3 により IETF URN namespace (`urn:ietf:params:*`) に固定される。consumer が prefix を変える余地がない
- 仮に consumer が `ietf:params:oauth:grant-type` を `urnCustomGrantTypePrefix` に指定しても無視する (IETF 規約準拠側が優先)
- 実装時は URN 文字列を const で持ち、comment で "IETF-registered URN per RFC 7523/8693, not customizable" を明示

### 3.5 `session` Grant — Unchanged

- `grant_type=session` はそのまま維持
- Rationale:
  - First-party BFF 固有で、外部 client が呼ばない
  - `session` という既存 OAuth 名称との conflict がない
  - URN 化しても実益がなく、変更コストのみが発生
- RFC 非準拠の独自 grant という事実は変わらないが、使用者が限定的で実害なし

### 3.6 Grant Policy Input + Audit Event — Wire Value

`GrantPolicyRequest.grantType` (policy hook 入力) と audit event の `grantType` field の両方に **client が送った wire 値そのまま** を入れる:

- `grant_type=authorization_code` → `grantType: "authorization_code"`
- `grant_type=urn:acme:oauth:grant-type:did` → `grantType: "urn:acme:oauth:grant-type:did"`
- `grant_type=refresh_token` → `grantType: "refresh_token"` (変更なし、既に正しい)
- `grant_type=session` → `grantType: "session"` (変更なし)

**Breaking surface — Grant Policy:**

`GrantPolicyRequest.grantType` は public interface のパラメータ。Consumer が `grantPolicy.evaluate()` を実装して `switch (req.grantType) { case "authorization": ... }` のように分岐している場合、本 rename で **policy アダプタが破綻する**。

具体的には `packages/oauth/src/routes.mts:466` の `grantType: "authorization"` → `"authorization_code"` 変更により、authorization code flow 中の `/oauth/authorize` フェーズで policy に渡される値が変わる。

影響範囲:

- `GrantPolicyRequest.grantType = "authorization"` → `"authorization_code"` (authorize フェーズ)
- `GrantPolicyRequest.grantType = "refresh_token"` (変更なし、既に RFC 準拠)
- DID grant / session grant は `grantPolicy.evaluate()` を呼び出していない (影響なし)

**Migration (consumers implementing `GrantPolicyHookBase`):**

- `case "authorization":` を `case "authorization_code":` にリネーム
- URN 形式の grant (例えば DID) を policy で判定する場合、文字列完全一致ではなく URN suffix パターン (`:did` で終わる等) で判定する設計に変更

**Rationale:**

- Audit log / policy input は「実際に何が起きたか」を記録するもの。wire 値を入れるのが最も正直
- 短縮 symbolic name (`did` 等) を別途持たせると audit に嘘が記録される (client は URN を送ったのに audit は裸 `did`) ことになり、監査目的に反する
- Policy input で consumer が「意味論的な grant type 区別」を必要とする場合、本ライブラリは wire 値を渡すに留め、consumer 側でパターン判定を行う責務分担とする
- 集計・正規化の都合は consumer 側の監査・policy システムで対応

### 3.7 URN Prefix Validation

`urnCustomGrantTypePrefix` の構文制約:

```typescript
z.string()
  .min(1)
  .regex(
    /^(?!urn:)[A-Za-z0-9][A-Za-z0-9:._-]*$/,
    "invalid urn prefix (must not start with 'urn:')"
  )
  .optional()
```

- 先頭英数、以降は英数 + `:` `.` `_` `-` を許容
- `urn:` で始まる値を reject (`urn:urn:acme:did` のような二重 `urn:` を防止)
- 厳密な RFC 8141 準拠ではないが実用上十分
- 違反時は起動時 Zod error で失敗

### 3.8 DID Grant Registration — URN Only

- DID grant は **URN 形式でのみ registry に登録** される
- 裸の `did` は (URN prefix 設定の有無に関わらず) **一切登録されない**
- よって `grant_type=did` (裸) は常に `unsupported_grant_type` エラー
- この挙動は §3.3 (未設定時 skip) と合わせて grant registration の完全な仕様を定義する

### 3.9 Grant Registration Skip — No Logger Call

DID grant が `urnCustomGrantTypePrefix` 未指定により register されない場合の通知方針:

- **採用: ログ出力を行わない (no-op skip)**
- README (`packages/did/README.md`) で明示: 「`did.enabled = true` でも `urnCustomGrantTypePrefix` 未指定なら DID grant は登録されない」
- Consumer が DID grant を使用しようとすると `unsupported_grant_type` エラーが返るので、その時点で設定不備に気付ける

**Rationale:**

- 現状 `Logger` capability (`packages/core/src/logging/Logger.mts:26`) は `warn(message, ...args)` のみ定義で、`info` は未実装
- `ModuleContext` に `logger` field も未登録 (`packages/core/src/modules/types.mts:56-90`)
- `info` 追加 + `ModuleContext.logger` 追加は 2 点の surface 変更を招き、本 spec (grant_type rename の整理) の scope を超える
- `console.warn` 直接呼び出しは consumer のログ集約パイプラインと切り離れるため避ける
- DID grant が無効化される状況は「consumer が明示的に DID を有効化せず未設定のまま動かす」ケースのため、**silent が問題になるのは DID grant を使おうとした時のみ**。`unsupported_grant_type` エラーで即座に気付けるので UX 上の実害は小さい

**Alternatives considered:**

1. `Logger.info` を追加 + `ModuleContext.logger` 追加 + `context.logger?.info(...)` 呼び出し — v0.5.0 の surface 変更を 2 点増やす。将来的に採用する場合は別 spec
2. `console.warn` 直接 — consumer ログ集約と非連携で避ける
3. `throw` で起動を失敗させる (Pattern α) — `did.enabled=true` が残る consumer の既存 config を壊すため回避

## 4. File-Level Changes

### 4.1 `packages/did/src/module.mts`

**Schema extension:**

```typescript
export const didConfigSchema = z.object({
  did: z.object({
    enabled: z.boolean().default(true),
    urnCustomGrantTypePrefix: z
      .string()
      .min(1)
      .regex(
        /^(?!urn:)[A-Za-z0-9][A-Za-z0-9:._-]*$/,
        "invalid urn prefix (must not start with 'urn:')"
      )
      .optional(),
    // existing fields unchanged (algorithm deprecated, supportedAlgorithms, messageMaxAgeSec, allowedAudiences)
  }).default({
    // existing default preserved; urnCustomGrantTypePrefix is intentionally absent (no default)
    enabled: true,
    supportedAlgorithms: ["ed25519_raw"],
    messageMaxAgeSec: 300,
    allowedAudiences: [],
  }),
});
```

**Module init (per §3.9 decision: no logger call):**

```typescript
async init(context: ModuleContext): Promise<void> {
  const grantConfig = (context.config.oauth.grants as Record<string, ...>).did;
  if (grantConfig?.enabled === false) return;

  const prefix = grantConfig?.urnCustomGrantTypePrefix;
  if (!prefix) {
    // Silent skip. See §3.9 rationale. Consumer is notified via README + the
    // `unsupported_grant_type` error that surfaces when a DID grant request
    // arrives without URN prefix configured.
    return;
  }

  const resolver = /* existing */;
  const handler = createDidGrant(/* existing */);
  const grantType = `urn:${prefix}:did`;
  context.grantRegistry.register(grantType, handler);
}
```

### 4.2 `packages/oauth/src/oauthAuthorization.mts`

```typescript
// Before
context.grantRegistry.register("authorization", handler);
// After
context.grantRegistry.register("authorization_code", handler);
```

### 4.3 `packages/oauth/src/routes.mts`

**Grant policy input** (`line 466`) — これは `grantPolicy.evaluate()` の入力 (`GrantPolicyRequest.grantType`) であり、audit event ではない。Consumer 実装 policy アダプタへの breaking 影響は §3.6 で詳述。

```typescript
// Line 466 — authorize phase, GrantPolicyRequest.grantType
// Before
grantType: "authorization",
// After
grantType: "authorization_code",
```

(他の箇所は `registry.get(grant_type)` 経由の dynamic lookup なので変更不要。`packages/oauth/src/grants/refreshToken.mts:161` の `grantType: "refresh_token"` も既に RFC 準拠で変更不要)

### 4.4 `packages/oauth/src/oauthSession.mts`

変更なし (`"session"` のまま)。

### 4.5 `packages/oauth/src/grants/refreshToken.mts`

変更なし (既に `"refresh_token"` で RFC 準拠)。

### 4.6 Standalone template

- `templates/standalone/config/application.conf`
  - `did.urnCustomGrantTypePrefix = "example:oauth:grant-type"` を追加
  - コメント: `# Override with your organization's URN namespace (e.g. "acme:oauth:grant-type")`
- `templates/standalone/tests/did-grant.test.js`
  - `grant_type: "did"` → `grant_type: "urn:example:oauth:grant-type:did"` (全 8 箇所)
- `templates/standalone/tests/index.test.js`
  - `grant_type=authorization` → `grant_type=authorization_code`
- `README.md` の ASCII 図 (`grant_type=did`) を URN 形式に更新

### 4.7 Docs

- `packages/did/README.md`: URN 設計セクション + migration note
- `packages/oauth/README.md`: `authorization_code` で既に記載済み、念のため全スキャン
- Root `CHANGELOG.md` v0.5.0 Unreleased セクションに breaking change entry

## 5. Migration Notes (for CHANGELOG)

```markdown
### Breaking Changes

- **Wire value (`grant_type`):**
  - `grant_type=authorization` → `grant_type=authorization_code` (RFC 6749 §4.1.3 compliance)
  - `grant_type=did` → `grant_type=urn:${did.urnCustomGrantTypePrefix}:did`
  - `grant_type=session` unchanged
- **Grant policy interface (`GrantPolicyRequest.grantType`):**
  - Authorize flow now passes `"authorization_code"` (was `"authorization"`) to `grantPolicy.evaluate()`
  - DID grant now passes the full URN string (e.g. `"urn:acme:oauth:grant-type:did"`) to any policy — but note that the built-in DID grant handler does not invoke `grantPolicy.evaluate()` today, so this is a forward-looking interface note
  - `refresh_token` unchanged
- **New required config for DID grant consumers:**
  - `did.urnCustomGrantTypePrefix` must be set to register the DID grant handler
  - Omitting the config silently disables DID grant registration; client requests to the DID URN grant receive `unsupported_grant_type`

Migration:

1. Update client requests: `grant_type=authorization` → `authorization_code`
2. If implementing `GrantPolicyHookBase`: rename `case "authorization":` → `case "authorization_code":` in policy dispatch logic
3. If using DID grant: add `did.urnCustomGrantTypePrefix = "<your-namespace>"` to config
4. Update DID client requests: `grant_type=did` → `grant_type=urn:<your-namespace>:did`
```

## 6. Test Plan (TDD outline)

各 rename ごとに RED → GREEN → REFACTOR サイクル:

### 6.1 `authorization_code` rename

- **RED:** 既存 `grant_type=authorization` テスト群を `authorization_code` にリネーム → registry lookup 失敗で unsupported → fail
- **GREEN:** `oauthAuthorization.mts:45` + `routes.mts:466` を `authorization_code` に修正 → pass
- **NEW RED → GREEN:** `grant_type=authorization` (legacy) が `unsupported_grant_type` を返すことを明示的にテスト

### 6.2 DID URN 化

- **RED case A:** `urnCustomGrantTypePrefix = "test:oauth:grant-type"` で起動 → `grant_type=urn:test:oauth:grant-type:did` リクエストが通るテスト → registry lookup miss で fail
- **GREEN A:** `module.mts` を URN 構築ロジックに修正 → pass
- **RED case B:** `urnCustomGrantTypePrefix` 未指定で起動 → DID grant が register されないテスト (registry に URN も裸 `did` も存在しないことを assert)
- **GREEN B:** Skip ロジック実装 → pass (ログ出力なし、§3.9 決定に整合)
- **Negative side-effect test:** `urnCustomGrantTypePrefix` 未指定時、init が `console` に一切の出力を行わないことを確認 (`console.warn` / `console.info` / `console.log` spy の call count 0)。§3.9 で「`ModuleContext.logger` は未導入」と決定しているため logger stub のテストは対象外
- **NEW RED → GREEN:** 裸の `grant_type=did` が `unsupported_grant_type` を返すテスト (URN prefix 設定時・未設定時の両ケース)

### 6.3 Grant Policy Input + Audit Event

- **Grant Policy (`GrantPolicyRequest.grantType`):**
  - `/oauth/authorize` flow で `grantType: "authorization_code"` が `grantPolicy.evaluate()` に渡されるテスト (routes.mts:466 path)
  - `/oauth/token` (refresh_token grant) で `grantType: "refresh_token"` が渡されるテスト (回帰確認)
  - Policy hook の記録値は wire 値と一致すること
- **Audit Event:**
  - `grantType: "authorization_code"` が audit event に記録されるテスト
  - URN DID grant の audit event に `grantType: "urn:test:oauth:grant-type:did"` (wire 値そのまま) が記録されるテスト
  - 実装確認ポイント: `routes.mts` / grant handler の audit 発火箇所は registry lookup に使った `grant_type` 文字列を直接利用するため、`line 466` の hardcoded `"authorization"` 以外は追加修正不要のはず。実装時に全 audit 発火箇所を走査して確認する

### 6.4 Schema validation

- `urnCustomGrantTypePrefix = ""` (空文字) で起動 → Zod error で fail
- `urnCustomGrantTypePrefix = "invalid chars!"` で起動 → Zod regex error で fail
- `urnCustomGrantTypePrefix = "urn:acme"` (先頭 `urn:`) で起動 → Zod regex error で fail
- `urnCustomGrantTypePrefix = "example.com:grants"` (dot 含む) で起動 → pass
- `urnCustomGrantTypePrefix = "valid:prefix-123"` で起動 → pass

## 7. Risks & Mitigations

| Risk | Mitigation |
| --- | --- |
| Consumer が `urnCustomGrantTypePrefix` 未設定で DID を使おうとして混乱 | README で明記 + `unsupported_grant_type` エラー時に原因を推測しやすくする (§3.9 rationale: silent skip は DID grant 未使用 consumer への UX を優先) |
| Audit log / policy input の grant_type が URN で肥大化 | 設計判断として受け入れる (§3.6 rationale)。consumer 側で正規化は可能 |
| 既存 v0.4.x consumer への breaking impact | v0.5.0 全体が breaking ラウンドなので CHANGELOG で明示 + dplaas.auth は Option X で一括追従 |
| `urnCustomGrantTypePrefix` に `urn:` を含めて指定された場合 (例: `urn:acme`) → `urn:urn:acme:did` になる | §3.7 の regex で `urn:` prefix を reject。起動時 Zod error で早期発見 |
| Consumer が `urnCustomGrantTypePrefix = "ietf:params:oauth:grant-type"` を設定し、IETF 未登録値を流す | 本ライブラリは「IETF 値を consumer が自前で流す」シナリオには介入しない (§3.4 rationale)。CHANGELOG + README で「IETF 登録値以外に IETF namespace を使うのは RFC 6755 違反」と警告のみ |
| Consumer 実装 `GrantPolicyHookBase` が `case "authorization":` で分岐していて v0.5.0 で機能停止 | §3.6 Migration で rename 手順を明示 + CHANGELOG で breaking surface として強調 + dplaas.auth Option X 一括追従で内製 consumer は同期 |

## 8. Acceptance Criteria

- [ ] `grant_type=authorization` が `unsupported_grant_type` を返す
- [ ] `grant_type=authorization_code` が正常に token 発行する
- [ ] `grant_type=did` (裸) が常に `unsupported_grant_type` を返す
- [ ] `urnCustomGrantTypePrefix` 未指定時、DID grant module が silent skip (ログ出力なし、起動成功)
- [ ] `urnCustomGrantTypePrefix` 設定時、`grant_type=urn:${prefix}:did` が正常に token 発行する
- [ ] `GrantPolicyRequest.grantType` に wire 値 (`authorization_code` / URN / `refresh_token`) がそのまま渡される
- [ ] Audit event の `grantType` field に wire 値がそのまま記録される
- [ ] Standalone template が新 URN 形式で動作する
- [ ] Zod schema が不正 prefix 値 (空文字 / 不正文字 / `urn:` prefix) を起動時に reject する
- [ ] CHANGELOG に wire 値・policy interface 両方の migration note が記載される
- [ ] `packages/did/README.md` に「prefix 未指定時は silent skip」が明記される
- [ ] 全パッケージのテストが pass する
