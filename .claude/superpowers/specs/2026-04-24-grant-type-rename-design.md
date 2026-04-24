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
- 2026-04-24 design revision (post brainstorming):
  - URN 方針を「consumer が prefix を所有する config」から「wire protocol 定義者 (o3co) が
    URN を所有する固定値」に転換
  - `urnCustomGrantTypePrefix` config を撤回
  - §1.1 新設: 現状 `did` grant の位置付け (「認証 → 認可変換 grant」)
  - §3.2-§3.3 の URN 設計を固定値設計に刷新
  - §4.1 Module init を簡素化 (prefix check 不要)
- 2026-04-24 scope addition (pre plan writing):
  - §3.8 新設: HOCON config key rename (`oauth.grants.authorization` → `oauth.grants.authorization_code`)
  - §4.2 拡張: `oauthAuthorization.mts:35` の `grantsConfig.authorization` → `grantsConfig.authorization_code`
  - §4.6 拡張: `packages/core/config/application.conf` と `templates/standalone/config/application.conf`
    の HOCON section rename + env var rename (`OAUTH_GRANTS_AUTHORIZATION_*` → `OAUTH_GRANTS_AUTHORIZATION_CODE_*`)

## 1. Background & Motivation

v0.5.0 の Core GA must 項目のうち、interface freeze に直結する grant_type 整理を行う。現状の grant_type 値には以下の問題がある:

1. **RFC 違反:** `grant_type=authorization` は RFC 6749 §4.1.3 違反。正式値は `authorization_code`。
2. **独自 grant の URN 化未実施:** 独自 grant `did` は裸の文字列で登録されているが、RFC 6755 に倣い非 IETF grant は URN 形式で識別すべき。
3. **Grant の所有者明示:** URN 化の際、`did` grant の wire protocol 定義者を URN sub-namespace で明示する必要がある (§1.1 参照)。

v0.5.0 は 1.0 GA 前の最後の interface 調整ラウンド。ここで RFC 準拠形に倒しきり、1.0 で freeze する。

### 1.1 現状の `did` grant の位置付け

現状の `did` grant は、DID/VC による identity verification を OAuth 2.0 の token envelope に変換する **auth.provider 固有の wire protocol 拡張** である。OAuth 本来の認証 grant (RFC 6749 `password` / `client_credentials` 等) や RFC 7521/7523 の assertion framework とは異なり、以下の構造を持つ:

- **Wire protocol**: `did` + `message` + `signature` の 3 パラメータで DID-signed assertion を表現
- **Authentication**: DID 秘密鍵の占有確認 (秘密鍵で署名された message の検証) は OAuth token endpoint が実施。DID document resolver で公開鍵を取得するため、pre-established trust relationship (client_id による事前登録) を要求しない
- **Identity semantics**: DID subject が誰で、信頼できるかの判断は OAuth の外側 (allow-list / policy layer) に委ねる
- **能力・権限検証**: VC による能力・権限の検証は access_token 発行後、resource server 側 (auth.policy-verifier 等) に委譲する
- **結果**: DID 認証と OAuth 認可レイヤーの接続点として機能する「認証 → 認可変換 grant」

**論文的位置付け:**

- 03-data-sovereignty ch4 原理 3 (DID 認証接続制御) はパイプライン間ハンドシェークの設計
- 00-integrated ch5.5 は「OAuth 2.0 フローの認証主体として DID を使用する」提案を行い、同時に「この DID 統合は現行 MCP 仕様に含まれておらず、提案される拡張パス」「future specification work」と明記している

現状 `did` grant はこの未標準化領域を埋める **実装例の一つ** であり、IETF 登録値に収まらない。ゆえに independent URN sub-namespace で識別するのが適切である。

### 1.2 Wire protocol の所有者と URN sub-namespace

RFC 6755 §3 は URN sub-namespace が grant の定義主体によって所有されることを定めている (IETF sub-namespace が IANA-registered grant の定義権を持つのと同じ構造)。

現状の `did` grant wire protocol の定義者は **o3co/auth.provider** であり、consumer (dPLaaS など) は wire の利用者 (deployer) にすぎない。複数 deployment が同じ wire を使う場合、それらの grant_type URN は統一されているべきで、consumer ごとに異なる URN で表現すると client SDK / Agent 側の interop が破綻する。

よって本 spec は `did` grant の URN を **`urn:o3co:oauth:grant-type:did` 固定** とする。ここでの `o3co` は library owner の vendor identifier ではなく、**wire protocol version の identifier** として機能する。IETF registry 値が IETF 固有値として consumer に変更不可であるのと同じ扱い。

Consumer が将来 wire protocol を拡張する (VC Presentation を request に含める等) 場合、それは **consumer 固有の別 grant** として consumer 所有 URN (`urn:dplaas.io:oauth:grant-type:did-vp` 等) を別途定義すべきであり、既存の `urn:o3co:oauth:grant-type:did` を置き換えるべきではない。

## 2. Scope

### In Scope

- `authorization` → `authorization_code` の rename (RFC 6749 準拠)
- `did` grant の URN 化 (`urn:o3co:oauth:grant-type:did` 固定)
- Grant policy input + Audit event の grant_type 表記統一 (wire 値を記録)
- Standalone template / README / CHANGELOG の追従

### Out of Scope

本 spec は **rename と URN 化のみ**。以下は別 spec で扱う:

- Token Exchange (RFC 8693) 実装 — v0.5.0 #2
- jwt-bearer (RFC 7523) 実装 — v0.5.0 #4
- NonceStore interface — v0.5.0 #5
- VC Presentation abstract interface — v0.5.0 #6
- DPoP interface 予約 — v0.5.0 #19
- dplaas.auth 追従 — v0.5.0 publish 完了後に一括

Token Exchange と jwt-bearer の URN は IETF 登録済み値なので、本 spec で URN 設計時に「IETF 標準 URN は consumer 固有 URN と独立、固定値で register」という棲み分けルールだけ確定させる。

## 3. Design Decisions

### 3.1 Compatibility Strategy — Hard Break

- v0.5.0 で旧値 (`authorization` / `did`) を **即座に拒否** する
- Registry lookup が見つからないので既存フロー (`routes.mts:157-173`) で `unsupported_grant_type` を返す
- Dual-accept や legacy alias flag は導入しない

**Rationale:**

- `authorization` は RFC 6749 違反。互換維持はそれ自体が spec 違反の継続
- v0.4.0 → v0.5.0 間で breaking は他にも複数発生 (passport 脱出済 / Token Exchange / jwt-bearer 等)。grant_type だけ dual-accept しても consumer の総移行コストは下がらない
- 内製 consumer (dplaas.auth) は v0.5.0 publish 完了後に一括追従する方針 (Option X) が既に決定済み

### 3.2 DID Grant URN — Fixed Value

- DID grant の URN は **`urn:o3co:oauth:grant-type:did` 固定**
- Consumer config 不要、override 不可
- `did.enabled` config のみで on/off を切り替える (`enabled = false` なら DID grant module は no-op)

**Rationale:**

§1.2 の wire protocol 所有権モデルに従う:

- Wire protocol を定義したのは o3co/auth.provider。dPLaaS や他 consumer は wire の利用者
- 同じ wire を使う複数 deployment で URN が統一されていないと Agent/client SDK 側の interop が成立しない
- `o3co` は vendor identifier ではなく **wire protocol version identifier** として機能。IETF registry 値が consumer に変更不可であるのと同じ扱い
- Consumer が wire protocol を拡張する場合、それは consumer 固有の別 grant として別 URN で定義する (既存 URN を書き換えない)

### 3.3 `did.enabled` Semantics

- `did.enabled = true` (default): `oauthDidModule` の init で `urn:o3co:oauth:grant-type:did` を grant registry に register
- `did.enabled = false`: init は no-op、何も register しない
- `oauthDidModule` を `createApp` の `modules` 配列に含めない場合は当然 register されない (既存挙動、variation なし)

**Rationale:**

- §3.2 で config を URN から排除したため、「DID grant を有効化しつつ URN だけ未設定」という曖昧な状態がなくなる
- `enabled` flag は引き続き明示的な on/off スイッチとして機能

### 3.4 IETF-Registered URN Grants — Fixed Values, Independent

Token Exchange (RFC 8693) / jwt-bearer (RFC 7523) は IETF 登録済み URN:

- `urn:ietf:params:oauth:grant-type:token-exchange`
- `urn:ietf:params:oauth:grant-type:jwt-bearer`

これらは **config 不要の固定値として register** する。`urn:o3co:` sub-namespace とは独立。

**Rationale:**

- IETF registry 値は RFC 6755 §3 により IETF URN namespace (`urn:ietf:params:*`) に固定される。auth.provider 側で prefix を変える余地がない
- 実装時は URN 文字列を const で持ち、comment で "IETF-registered URN per RFC 7523/8693" を明示

### 3.5 `session` Grant — Unchanged

- `grant_type=session` はそのまま維持
- Rationale:
  - First-party BFF 固有で、外部 client が呼ばない
  - `session` という既存 OAuth 名称との conflict がない
  - URN 化しても実益がなく、変更コストのみが発生
- RFC 非準拠の独自 grant という事実は変わらないが、使用者が限定的で実害なし

### 3.6 Grant Policy Input + Audit Event — Wire Value

**異なる 2 つの surface に対する扱いを明示する:**

#### 3.6.1 Grant Policy Input (`GrantPolicyRequest.grantType`)

- Field 名: `grantType` (camelCase、TypeScript interface `GrantPolicyRequest`)
- 現状 `packages/oauth/src/routes.mts:466` で authorize フェーズ時に `grantPolicy.evaluate()` に hardcoded `"authorization"` を渡している
- これを `"authorization_code"` に修正 (wire 値に合わせる)
- **変更箇所**: `routes.mts:466` のみ (`refreshToken.mts:161` の `"refresh_token"` は既に RFC 準拠、変更不要)
- DID grant / session grant は現状 `grantPolicy.evaluate()` を呼び出していない。本 spec の scope 内では DID への policy 統合は行わない

**Breaking surface:**

Consumer が `grantPolicy.evaluate()` を実装して `switch (req.grantType) { case "authorization": ... }` のように分岐している場合、本 rename で policy アダプタが破綻する。Migration は `case "authorization":` → `case "authorization_code":` にリネーム。

#### 3.6.2 Audit Event (`details.grant_type`)

- Field 名: `grant_type` (snake_case、`details` object の nested field)
- 現状 `routes.mts:169`, `205`, `220` などで `details: { grant_type }` の形で audit event に出力される
- 値は request body の `grant_type` wire 値をそのまま入れている (既存挙動)
- **本 spec の影響**: schema (field 名) は変更しない。値が client wire と連動して自動的に変わるのみ
  - `grant_type=authorization_code` → `details: { grant_type: "authorization_code" }`
  - `grant_type=urn:o3co:oauth:grant-type:did` → `details: { grant_type: "urn:o3co:oauth:grant-type:did" }`
  - `grant_type=refresh_token` / `session` は変更なし

**Audit schema contract:**

本 spec は audit event の schema (field 名 / 構造) を変更しない。`details.grant_type` field は snake_case のまま維持。値の変化は client が送る wire 値の rename に連動する自動変化であり、ライブラリ側の implementation 変更は不要 (dynamic lookup で wire 値をそのまま記録しているため)。

#### 3.6.3 Rationale

- Policy 入力と audit event は **別の interface** であり、field 命名規約も異なる (前者 camelCase TypeScript interface、後者 snake_case wire-like)
- Audit event は「実際に何が起きたか」を記録するもので、wire 値を入れるのが最も正直
- 短縮 symbolic name (`did` 等) を別途持たせると audit に嘘が記録される (client は URN を送ったのに audit は裸 `did`) ことになり、監査目的に反する
- Policy 入力も同じ理由で wire 値を渡す

### 3.7 DID Grant Registration — URN Only

- DID grant は **`urn:o3co:oauth:grant-type:did` でのみ registry に登録** される
- 裸の `did` は一切登録されない
- よって `grant_type=did` (裸) は常に `unsupported_grant_type` エラー

### 3.8 HOCON Config Key Rename — `authorization` → `authorization_code`

Wire 値 rename に合わせて、HOCON config section の key も rename する。

| Before | After |
| --- | --- |
| `oauth.grants.authorization { ... }` | `oauth.grants.authorization_code { ... }` |
| `oauth.grants.authorization.enabled` | `oauth.grants.authorization_code.enabled` |
| `oauth.grants.authorization.pkce.requireS256` | `oauth.grants.authorization_code.pkce.requireS256` |
| env `OAUTH_GRANTS_AUTHORIZATION_ENABLED` | env `OAUTH_GRANTS_AUTHORIZATION_CODE_ENABLED` |
| env `OAUTH_GRANTS_AUTHORIZATION_PKCE_REQUIRE_S256` | env `OAUTH_GRANTS_AUTHORIZATION_CODE_PKCE_REQUIRE_S256` |

**変更理由:**

- Wire 値 (`grant_type=authorization_code`) と config key (`grants.authorization`) がズレると、README / example / consumer コードで「どちらの名前で呼ぶのか」が混乱する
- v0.5.0 は interface freeze ラウンド。中途半端な整合を残すと 1.0 GA まで引きずる
- v0.5.0 は元々 breaking 集中ラウンドなので、追加の breaking でもトータルコストは変わらない

**変更対象ファイル:**

- `packages/oauth/src/oauthAuthorization.mts:33-35` (`grantsConfig.authorization` → `grantsConfig.authorization_code`)
- `packages/core/config/application.conf:38` (grants block 内の key rename + env var rename)
- `templates/standalone/config/application.conf:38-45` (grants block 内の key rename + env var rename)
- `templates/standalone/README.md:72` / `templates/standalone/README.ja.md:72` (env var 表記更新)
- `README.md:207` (env var 表記更新)

**互換性方針:** Hard break (§3.1 と同じ方針)。旧 key / 旧 env var は一切 fallback しない。Consumer は HOCON ファイルを更新する。

**備考:** `refresh_token` config key は RFC 値と既に一致 (snake_case)、`session` は §3.5 方針で変更なし、DID は `oauth.grants.did.*` (method 名) のまま維持 (URN を config key にすると HOCON syntax 上クォートが必要で扱いにくいため、method 名ベースで参照する現状を維持する)。

## 4. File-Level Changes

### 4.1 `packages/did/src/module.mts`

**Module init (simplified — fixed URN):**

```typescript
const DID_GRANT_TYPE = "urn:o3co:oauth:grant-type:did" as const;

export const oauthDidModule = (options: DidModuleOptions): Module => ({
  name: "oauth-did",
  async init(context: ModuleContext): Promise<void> {
    const grantConfig = (
      context.config.oauth.grants as Record<string, Record<string, unknown> | undefined>
    ).did;
    if (grantConfig?.enabled === false) return;

    const resolver =
      "resolver" in options ? options.resolver : options.resolverFactory(grantConfig ?? {});

    const handler = createDidGrant(
      {
        config: context.config,
        keyStore: context.keyStore,
        pathResolver: context.pathResolver,
      },
      { resolver, verifierRegistry: options.verifierRegistry },
    );
    context.grantRegistry.register(DID_GRANT_TYPE, handler);
  },
});
```

**Schema (unchanged):**

`didConfigSchema` は既存のまま維持。`urnCustomGrantTypePrefix` のような新規 field は追加しない。

### 4.2 `packages/oauth/src/oauthAuthorization.mts`

2 箇所修正:

```typescript
// Line 35 — config key lookup (§3.8)
// Before
if (grantsConfig.authorization?.enabled !== false) {
// After
if (grantsConfig.authorization_code?.enabled !== false) {

// Line 45 — grant registry key (§3.1)
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

### 4.6 Standalone template / HOCON / README

**Standalone template (tests):**

- `templates/standalone/tests/did-grant.test.js`
  - `grant_type: "did"` → `grant_type: "urn:o3co:oauth:grant-type:did"` (全 8 箇所)
- `templates/standalone/tests/index.test.js`
  - `grant_type=authorization` → `grant_type=authorization_code`

**HOCON config files (§3.8):**

- `packages/core/config/application.conf:38`

  ```hocon
  # Before
  authorization { enabled = true, enabled = ${?OAUTH_GRANTS_AUTHORIZATION_ENABLED} }
  # After
  authorization_code { enabled = true, enabled = ${?OAUTH_GRANTS_AUTHORIZATION_CODE_ENABLED} }
  ```

- `templates/standalone/config/application.conf:38-45`

  ```hocon
  # Before
  authorization {
    enabled = true
    enabled = ${?OAUTH_GRANTS_AUTHORIZATION_ENABLED}
    pkce {
      requireS256 = false
      requireS256 = ${?OAUTH_GRANTS_AUTHORIZATION_PKCE_REQUIRE_S256}
    }
  }
  # After
  authorization_code {
    enabled = true
    enabled = ${?OAUTH_GRANTS_AUTHORIZATION_CODE_ENABLED}
    pkce {
      requireS256 = false
      requireS256 = ${?OAUTH_GRANTS_AUTHORIZATION_CODE_PKCE_REQUIRE_S256}
    }
  }
  ```

**Documentation env var tables:**

- `templates/standalone/README.md:72` / `templates/standalone/README.ja.md:72`
  - `OAUTH_GRANTS_AUTHORIZATION_ENABLED` → `OAUTH_GRANTS_AUTHORIZATION_CODE_ENABLED`
- `README.md:207`
  - `OAUTH_GRANTS_AUTHORIZATION_PKCE_REQUIRE_S256` → `OAUTH_GRANTS_AUTHORIZATION_CODE_PKCE_REQUIRE_S256`
- Root `README.md` の ASCII 図 (`grant_type=did`) を URN 形式に更新

### 4.7 Docs

- `packages/did/README.md`:
  - URN 固定値の記載 (`urn:o3co:oauth:grant-type:did`)
  - Migration note (裸 `did` → URN)
- `packages/oauth/README.md`: `authorization_code` で既に記載済み、念のため全スキャン
- Root `CHANGELOG.md` v0.5.0 Unreleased セクションに breaking change entry

## 5. Migration Notes (for CHANGELOG)

```markdown
### Breaking Changes

- **Wire value (`grant_type`):**
  - `grant_type=authorization` → `grant_type=authorization_code` (RFC 6749 §4.1.3 compliance)
  - `grant_type=did` → `grant_type=urn:o3co:oauth:grant-type:did`
  - `grant_type=session` unchanged
- **Grant policy interface (`GrantPolicyRequest.grantType`):**
  - Authorize flow now passes `"authorization_code"` (was `"authorization"`) to `grantPolicy.evaluate()`
  - DID grant handler does not currently invoke `grantPolicy.evaluate()`, but if consumers
    add policy logic for DID grants in the future, use the full URN string
    (`"urn:o3co:oauth:grant-type:did"`) as the match value
  - `refresh_token` unchanged

Migration:

1. Update client requests:
   - `grant_type=authorization` → `authorization_code`
   - `grant_type=did` → `urn:o3co:oauth:grant-type:did`
2. Update HOCON config files:
   - `oauth.grants.authorization { ... }` → `oauth.grants.authorization_code { ... }`
   - env var `OAUTH_GRANTS_AUTHORIZATION_ENABLED` → `OAUTH_GRANTS_AUTHORIZATION_CODE_ENABLED`
   - env var `OAUTH_GRANTS_AUTHORIZATION_PKCE_REQUIRE_S256` → `OAUTH_GRANTS_AUTHORIZATION_CODE_PKCE_REQUIRE_S256`
3. If implementing `GrantPolicyHookBase`: rename `case "authorization":` →
   `case "authorization_code":` in policy dispatch logic
```

## 6. Test Plan (TDD outline)

各 rename ごとに RED → GREEN → REFACTOR サイクル:

### 6.1 `authorization_code` rename

- **RED:** 既存 `grant_type=authorization` テスト群を `authorization_code` にリネーム → registry lookup 失敗で unsupported → fail
- **GREEN:** `oauthAuthorization.mts:45` + `routes.mts:466` を `authorization_code` に修正 → pass
- **NEW RED → GREEN:** `grant_type=authorization` (legacy) が `unsupported_grant_type` を返すことを明示的にテスト

### 6.2 DID URN 化

- **RED:** `grant_type=urn:o3co:oauth:grant-type:did` リクエストが通るテスト → registry lookup miss で fail
- **GREEN:** `module.mts` を固定 URN register に修正 → pass
- **NEW RED → GREEN:** 裸の `grant_type=did` が `unsupported_grant_type` を返すテスト
- **Config test:** `did.enabled = false` で module init が no-op になり、URN が registry に存在しないテスト

### 6.3 Grant Policy Input + Audit Event

- **Grant Policy Input (`GrantPolicyRequest.grantType`, camelCase):**
  - `/oauth/authorize` flow で `grantType: "authorization_code"` が `grantPolicy.evaluate()` に渡されるテスト (routes.mts:466 path)
  - `/oauth/token` (refresh_token grant) で `grantType: "refresh_token"` が渡されるテスト (回帰確認)
  - Policy hook の記録値は wire 値と一致すること
  - DID grant は現状 `grantPolicy.evaluate()` を呼び出していないため policy input テストの対象外 (§3.6.1 参照)
- **Audit Event (`details.grant_type`, snake_case nested):**
  - `grant_type=authorization_code` wire 送信時、audit event の `details.grant_type` に `"authorization_code"` が記録されるテスト
  - `grant_type=urn:o3co:oauth:grant-type:did` wire 送信時、audit event の `details.grant_type` に URN 値そのままが記録されるテスト
  - 実装確認ポイント: `routes.mts:169/205/220` の audit 発火箇所は `details: { grant_type }` の dynamic destructuring で wire 値を直接記録しているため、schema / field 名の修正は不要。値のみが client wire の rename に連動して変化することを確認するテスト

## 7. Risks & Mitigations

| Risk | Mitigation |
| --- | --- |
| `urn:o3co:` が vendor lock-in と見られる | §1.2 で「wire protocol version identifier」としての意味を明文化 + README で理由説明 + RFC 6755 sub-namespace 所有権モデルに準拠していることを示す |
| Audit log / policy input の grant_type が URN で肥大化 | 設計判断として受け入れる (§3.6 rationale)。consumer 側で正規化は可能 |
| 既存 v0.4.x consumer への breaking impact | v0.5.0 全体が breaking ラウンドなので CHANGELOG で明示 + dplaas.auth は Option X で一括追従 |
| Consumer が wire protocol を拡張したい (VC Presentation 追加等) が URN 固定で困る | 拡張は既存 URN の上書きではなく別 grant として扱う (consumer 所有 URN で新規定義)。本 spec で migration path を明示 |
| Consumer 実装 `GrantPolicyHookBase` が `case "authorization":` で分岐していて v0.5.0 で機能停止 | §3.6 Migration で rename 手順を明示 + CHANGELOG で breaking surface として強調 + dplaas.auth Option X 一括追従で内製 consumer は同期 |

## 8. Acceptance Criteria

- [ ] `grant_type=authorization` が `unsupported_grant_type` を返す
- [ ] `grant_type=authorization_code` が正常に token 発行する
- [ ] `grant_type=did` (裸) が常に `unsupported_grant_type` を返す
- [ ] `grant_type=urn:o3co:oauth:grant-type:did` が正常に token 発行する
- [ ] `did.enabled = false` 時、URN が registry に register されない
- [ ] `oauth.grants.authorization_code.enabled = false` 時、`authorization_code` grant が register されない
- [ ] 旧 config key `oauth.grants.authorization` を含む HOCON ファイルで起動しても新 grant が有効化されない (旧 key は silently 無視される)
- [ ] 新 env var (`OAUTH_GRANTS_AUTHORIZATION_CODE_ENABLED` / `_PKCE_REQUIRE_S256`) が正しく適用される
- [ ] `GrantPolicyRequest.grantType` に authorization code / refresh_token path で wire 値がそのまま渡される (DID は現状 policy 呼び出さないため対象外)
- [ ] Audit event の `details.grant_type` field に wire 値がそのまま記録される (既存 schema 維持、値のみ連動変化)
- [ ] Standalone template が新 URN 形式・新 config key で動作する
- [ ] CHANGELOG に wire 値・config key・env var・policy interface の migration note が記載される
- [ ] `packages/did/README.md` に URN 固定値とその rationale が明記される
- [ ] 全パッケージのテストが pass する
