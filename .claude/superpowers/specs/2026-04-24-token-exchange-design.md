# RFC 8693 Token Exchange — Design Spec

**Date:** 2026-04-24
**Scope:** `auth.provider` v0.5.0 scope item #2 (debate R2/R3 で GA must 認定)
**Target version:** v0.5.0
**Status:** Design draft (brainstorming complete, awaiting user review)

---

## 1. Motivation

### 1.1 Debate 起点の根拠

`debate/did-auth-oauth2-idp/` 4 ラウンドで Token Exchange は 1.0 GA 前 must に確定。

- **R1 CON §2.5**: 「A2A の核心は capability (何ができるか/委譲可能か/権限減衰)。**RFC 8693 Token Exchange / OBO flow のサポートが必須** — 無ければ A2A を名乗るのは苦しい」
- **R1 PRO 受諾**: 「Token Exchange は TODO として認識済み。**設計欠陥ではなく実装順序**」「1.0 GA 前に実装」
- **R2 PRO §6**: 「RFC 8693 Token Exchange | 最高 | **1.0 GA 前 must (Option II の核)**」
- **R2 CON priority matrix**: コスト低 / 効用最高 / 実装難易度中
- **R3 PRO §4.1 決着**: GA 前 must gate (shipping 制約) に含む

### 1.2 Persona-level pain (R3 PRO §3.2)

Platform Engineering Lead persona (B2B SaaS multi-cloud) の現状回避策:
> 自前 token exchange broker + cloud 毎の IAM 設定を手動同期

= multi-cloud workload 間で JWT/mTLS を繋ぐのに自前 broker を運用している。これを OSS で置き換えるのが Option II (cross-org A2A) の核ユースケース。

### 1.3 auth.provider 全体戦略での位置付け

- v0.5.0 scope #2 (core GA must)
- interface freeze に関わるので v0.5.0 で確定必要
- jwt-bearer (#4) と近接 (外部 JWT を subject にする経路を共有)
- Token Exchange は OIDC 層で標準化された delegation 窓口。capability-based auth (UCAN/Macaroons) を IdP 内に持ち込まない PRO 側戦略の具体化

## 2. Scope

### 2.1 射程に入れる使用パターン

| # | パターン | 説明 |
|---|---|---|
| A | On-behalf-of / impersonation | サービス A がユーザとして B を呼ぶ |
| B | Delegation (`act` claim) | A.と同じだが `act` claim で代理チェーン追跡 |
| C | Token downgrade / scope narrowing | 強 token から弱 audience/scope の token を発行 |

### 2.2 射程に入れない使用パターン

| # | パターン | 扱い |
|---|---|---|
| D | Cross-domain token translation (SAML 等) | post-0.5 |
| E | Token type conversion (access ↔ id) | `unsupported_token_type` で明示拒否 (§5.3 error table と整合、`requested_token_type` が `access_token` 以外の全値に適用) |

### 2.3 Subject/Actor token の受入 type

| token_type URI | v0.5.0 扱い |
|---|---|
| `urn:ietf:params:oauth:token-type:access_token` | built-in validator 同梱 |
| `urn:ietf:params:oauth:token-type:jwt` | interface のみ提供、実装は consumer |
| `urn:ietf:params:oauth:token-type:refresh_token` | 未対応 (Registry に register 不可ではないが built-in 無し) |
| `urn:ietf:params:oauth:token-type:id_token` | 未対応 |
| `urn:ietf:params:oauth:token-type:saml1` | 未対応 |
| `urn:ietf:params:oauth:token-type:saml2` | post-0.5 |

### 2.4 発行する token type

- `urn:ietf:params:oauth:token-type:access_token` のみ
- refresh_token / id_token は発行しない (RFC 8693 §4.2.2 "NOT RECOMMENDED" 準拠)
- `requested_token_type` が `access_token` 以外 → `unsupported_token_type`

## 3. Package 構成

### 3.1 新規 package

**`@o3co/auth-provider-oauth-token-exchange`**

```text
packages/oauth-token-exchange/
├── src/
│   ├── module.mts              # GrantModule export (token_exchange factory)
│   ├── grant.mts               # Grant handler 実装
│   ├── validator/
│   │   ├── types.mts           # ExchangeTokenValidator / ValidatedToken interfaces
│   │   ├── registry.mts        # ExchangeTokenValidatorRegistry
│   │   └── selfIssuedAccessToken.mts  # built-in validator for access_token type
│   ├── act.mts                 # act claim chain logic (nested delegation)
│   └── __tests__/
└── package.json
```

### 3.2 命名規則

- OAuth 標準拡張系は `auth-provider-oauth-*` prefix で統一
- 今後 federation も `auth-provider-oauth-federation-*` に rename 予定 (別タスク)
- DID grant (OAuth 標準外) は `auth-provider-did` のまま
- WebAuthn (MFA) は `auth-provider-webauthn` のまま

### 3.3 位置付け

- built-in registration しない。consumer が 100% register 責任 (federation split の判例と一貫)
- default 無効化で attack surface 最小化
- consumer の package.json で有効かどうか判別可能 (監査対応)

### 3.4 依存関係

- `@o3co/auth-provider-core` (GrantHandler, KeyStore, RefreshTokenStoreBase, generateToken, GrantPolicyHookBase)
- 外部依存: `jose` (既存 package で使用中)

## 4. 公開 API surface

### 4.1 Interfaces / Types

```ts
export interface ExchangeTokenValidator {
  readonly tokenType: string;
  validate(
    token: string,
    context: { role: "subject" | "actor" },
  ): Promise<ValidatedToken | null>;
}

export interface ValidatedToken {
  sub: string;
  scope?: string;
  aud?: string | string[];
  familyId?: string;              // self-issued access_token のみ
  act?: Record<string, unknown>;  // 既存 act chain (入れ子 delegation 用)
  claims: Record<string, unknown>;
}

export interface TokenExchangeDependencies extends GrantDependencies {
  validatorRegistry: ExchangeTokenValidatorRegistry;
  clientRepository: ClientRepository;
}
```

### 4.2 Classes / Factories

```ts
export class ExchangeTokenValidatorRegistry {
  register(tokenType: string, validator: ExchangeTokenValidator): void;
  get(tokenType: string): ExchangeTokenValidator | undefined;
}

export function createSelfIssuedAccessTokenValidator(deps: {
  keyStore: KeyStore;
  refreshTokenStore?: RefreshTokenStoreBase;
  issuer?: string;
}): ExchangeTokenValidator;

export function createTokenExchangeGrant(
  deps: TokenExchangeDependencies,
): GrantHandler;

export const tokenExchangeModule: GrantModule;
```

### 4.3 Grant type URI

- `urn:ietf:params:oauth:grant-type:token-exchange` (IETF 登録済み、RFC 8693 §2.1)
- `o3co` 独自 URN は使わない (IETF 登録済みだから)

## 5. Request / Response 仕様

### 5.1 Request (POST /oauth/token)

Content-Type: `application/x-www-form-urlencoded`

| field | required | 説明 |
|---|---|---|
| `grant_type` | ✓ | `urn:ietf:params:oauth:grant-type:token-exchange` 固定 |
| `subject_token` | ✓ | 元 token |
| `subject_token_type` | ✓ | 受入 type URI (§2.3 参照) |
| `actor_token` | optional | delegation 時の actor token |
| `actor_token_type` | conditional | actor_token 提示時は required |
| `resource` | optional | 発行 token が使われる API URI (policy hook に渡す)。**RFC 8707 §2 準拠で repeated param** (`resource=a&resource=b`)。express `body-parser` urlencoded は自動で `string[]` に展開 |
| `audience` | optional | 発行 token の `aud` claim。**同じく repeated param で複数指定可**。RFC 8693 §2.1 "space-delimited" 派生形は対応しない (express 側で解釈できないため) |
| `scope` | optional | 発行 token の scope (subject の subset でなければ reject) |
| `requested_token_type` | optional | 省略時は `access_token`。他値なら `unsupported_token_type` |
| `client_id` | ✓ | 呼び出し client の ID |
| `client_secret` | optional | confidential client の認証 |

### 5.2 Response (200 application/json)

```json
{
  "access_token": "eyJ...",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 300,
  "scope": "read:invoice"
}
```

- `issued_token_type` は response に含める (RFC 8693 §2.2 required)
- `refresh_token` / `id_token` は含めない
- `token_type` は "Bearer" hard-code (DPoP は v0.5.0 scope 外)

### 5.3 Error responses (RFC 6749 + RFC 8693)

| 条件 | error | status |
|---|---|---|
| `grant_type` 違い | `unsupported_grant_type` | 400 |
| 必須 field 欠落 | `invalid_request` | 400 |
| `subject_token_type` が Registry にない | `unsupported_token_type` | 400 |
| `requested_token_type` が `access_token` 以外 | `unsupported_token_type` | 400 |
| `actor_token_type` が Registry にない (提示時) | `unsupported_token_type` | 400 |
| subject_token 署名/exp 不正 | `invalid_grant` | 400 |
| subject_token の family revoked | `invalid_grant` (errorDescription: `family_revoked`) | 400 |
| actor_token 検証失敗 | `invalid_grant` | 400 |
| `scope` が subject の subset でない | `invalid_scope` | 400 |
| `audience` が client allowlist 外 | `invalid_target` | 400 (RFC 8707) |
| client 認証失敗 | `invalid_client` | 401 |
| policy hook が deny | `access_denied` | 403 |
| refreshTokenStore not wired (config 不備) | `invalid_grant` | 400 |
| refreshTokenStore runtime unavailable (一時障害) | `temporarily_unavailable` | 503 |

## 6. Grant handler 処理フロー

```text
1. request parse + 必須 field 検証 → invalid_request
2. client authentication (authorization_code と同ロジック流用) → invalid_client
3. requested_token_type check (access_token or undefined のみ許容) → unsupported_token_type
4. subject_token_type を Registry で lookup → unsupported_token_type
5. ExchangeTokenValidator.validate(subject_token, { role: "subject" })
   - self-issued access_token: 署名 + exp + family revocation check (fail-closed)
   - 外部 JWT: consumer 実装に委譲
   - 失敗 → invalid_grant
6. actor_token 提示時:
   - actor_token_type を Registry で lookup → unsupported_token_type
   - ExchangeTokenValidator.validate(actor_token, { role: "actor" }) → invalid_grant
7. scope narrowing check: requested scope ⊆ subject_token.scope → invalid_scope
8. audience allowlist check (client registration):
   - `audience` parameter 指定時のみ check: 全要素が `client.allowedAudiences ∪ { client.clientId }` に含まれる → invalid_target
   - `audience` parameter 省略時の fallback (§8.1 rule 2) は allowlist check をスキップ (derived `aud` は常に subject 由来 = 既に subject_token の `aud` として validate 済み、または clientId = 必ず allowlist に含まれる)
9. GrantPolicyHook 呼び出し (既存 interface 流用、`packages/core/src/policy/types.mts`):
   - 入力: `GrantPolicyRequest` = { grantType, clientId, subject, requestedScope, requestedAudience, originalScope, subjectTokenType, actorTokenType, resource, extras }
   - 出力: `GrantPolicyDecision`:
     - `{ outcome: "allow", grantedScope?, grantedAudience? }` → 発行続行 (以降 grantedScope / grantedAudience を使う)
     - `{ outcome: "deny", error, errorDescription? }` → policy 指定のエラーコードで reject (default は `access_denied`)
10. act claim 構築 (§9 の canonical rule に従う):
    - actor_token あり: act = { sub: <actor.sub>, ...<subject.act があれば act.act として入れ子> }
    - actor_token なし: 発行 token に act claim を載せない (subject.act の継承もしない)
11. family_id 継承 (α 方針):
    - subject が self-issued access_token: subject.familyId を継承
    - 外部 JWT: 新 family_id を発行しない (policy で指定された場合のみ発行、default は無し)
12. generateToken で access_token 発行:
    - data: { family_id?, sid?, act? }
    - options: expiresIn, issuer, audience (narrowed), subject (subject.sub),
              authorizedParty (client_id), scope (narrowed), tokenType: "at+jwt"
13. 成功 response 組み立て + auditSink emit
```

## 7. Revocation / Family 管理

### 7.1 既存 invariant (auth.provider 全体)

現状 auth.provider は `RefreshTokenStoreBase.isFamilyRevoked(familyId)` による cascading revoke が確立済み:

- introspect endpoint で access_token の `family_id` を check (`oauth/src/routes.mts:262-302`)
- userinfo endpoint で同 check
- refresh grant で family revoked 時は `invalid_grant/family_revoked`
- logout cascade で revokeFamily → session 削除

**Token Exchange だけ stateless にするのは repo invariant の regression。**

### 7.2 Token Exchange の revocation 方針

1. **自前発行 access_token (at+jwt) が subject_token の場合**:
   - built-in validator が `family_id` で `isFamilyRevoked()` 照合
   - revoked なら `invalid_grant` (errorDescription: `family_revoked`) で reject

2. **Store failure の 2 状態を分離** (Codex 指摘対応):

   | 状態 | 検出方法 | エラー応答 | 理由 |
   |---|---|---|---|
   | **not wired** (起動時に `refreshTokenStore` が未設定) | `deps.refreshTokenStore === undefined` | `invalid_grant` (400) + startup warning log | 設定不備 = client 側で retry しても無駄。config エラー相当 |
   | **runtime unavailable** (wire 済みだが Redis 等が一時的に応答しない) | `isFamilyRevoked()` が throw | `temporarily_unavailable` (503) + `Retry-After` | 一時障害 = client 側で retry 可能。RFC 6749 §5.2 |

   - introspect endpoint (`routes.mts:273-291`) は両状態を `active: false` に集約しているが、Token Exchange では RFC 6749 §5.2 に沿ってエラーコードを分ける
   - **not wired の場合 fail-closed を選ぶ理由**: Token Exchange は権限が横展開される操作で、revocation 検出能力が欠けた状態で通すと cascading revoke の invariant が破れる

3. **外部 JWT が subject_token の場合**:
   - consumer validator が revocation の責任を持つ (外部 IdP の introspection endpoint 等)
   - core は署名検証のみ強制、revocation は consumer 判断
   - README で明記

4. **actor_token の検証も同じルール**

### 7.3 family_id 継承 (α 方針)

- subject の `family_id` を発行 token に継承
- subject family が revoke されたら delegated token も自動失効 (cascade)
- `RefreshTokenStoreBase` interface 変更不要
- delegated token だけを個別 revoke する運用は post-0.5 で別途検討 (`/oauth/revoke` endpoint の jti 単位 revocation 等)

## 8. Scope / Audience narrowing

### 8.1 Built-in 強制ルール (core)

1. `scope` ⊆ `subject_token.scope` (空集合も有効、scope parameter 省略時は subject の scope を継承)
2. `audience` の全要素が `client.allowedAudiences ∪ { client.clientId }` に含まれる (§8.3 参照)。`audience` parameter 省略時:
   - subject の `aud` が単一値: それを発行 token の `aud` に継承
   - subject の `aud` が複数値 or 未設定: **呼び出し client の clientId を発行 token の `aud` にする** (既存 authorization_code の挙動と一致、`authorization.mts:265-268`)
   - 理由: `generateToken` は単一 `aud` のみ対応 (§8.1.1)。subject が多 aud の場合に「どれを継承するか」を暗黙選択するより、明示的に client 自身を aud にする方が挙動が予測可能
3. `resource` は policy hook がない場合はそのまま通す (URI の意味を core は知らない)
4. 全てが通った後、`GrantPolicyHook` を呼び出し consumer が更に絞れる (`grantedScope` / `grantedAudience` で override 可)

### 8.1.1 Multi-value parameter の処理

- `audience` / `resource` は RFC 8707 §2 の repeated parameter 形式 (`audience=a&audience=b`) で解釈
- express `body-parser` の urlencoded middleware は同名 key を `string[]` に展開するので core 側の追加処理は不要
- 単一値 (`audience=a`) は `string` で届くので、grant handler で `typeof === "string" ? [v] : v` で normalize
- ただし発行 JWT の `aud` claim は現状 `generateToken` が**単一値のみ対応** (`packages/core/src/grants/token.mts:86-114`)。multi-aud 発行は post-0.5 (別 spec で対応)、本 spec では**narrowed audience の先頭 1 つのみを `aud` に載せる** (`authorization.mts:265-268` と同じ挙動)

### 8.2 設計理由

- Policy 未設定でも安全 default (Quickstart 5 分要件 §v0.5.0 DX #7)
- Scope escalation 攻撃を core レベルで防止
- Audience confusion を client registration で防止
- Resource URI は consumer ドメイン依存なので policy hook に委ねる (正しい責任分界)

### 8.3 ClientRepository の shape — **Hard Prerequisite**

現状 `packages/core/src/repositories/types.mts:17` の `Client` 型には `audiences` field が**存在しない**。Token Exchange の `audience` narrowing (§8.1 built-in rule 2) は `Client` の allowlist 情報が必須のため、以下を Token Exchange 実装の**前提**として先行確定する:

**決定事項 (本 spec 内で確定):**

- `Client` interface に `allowedAudiences?: string[]` を追加
  - 命名理由: 既存 `allowedRedirectUris` / `allowedScopes` と命名パターン一致
  - optional (default undefined = `[clientId]` 扱い)
- `undefined` または空配列時の default 挙動: **`audience` parameter が指定されていれば、`clientId` と一致する場合のみ許可**
  - 理由: Token Exchange なしの通常 access_token は現状 `aud = clientId` で発行されている (`authorization.mts:265-268`)。allowlist 未設定の client でも「自分自身を audience にする exchange」は許可するのが自然
- `audience` parameter 省略時の発行 `aud` は §8.1 rule 2 に従う (subject 単一 aud → 継承、多 aud or 未設定 → clientId)

**実装タスク (plan に含める):**

1. `packages/core/src/repositories/types.mts` の `Client` に `allowedAudiences?: string[]` を追加
2. `ClientEntrySchema` (zod) に同 field 追加
3. ClientRepository の既存 in-memory / adapter 実装が field を透過すること確認 (無視して OK)
4. ドキュメント (README / examples) で設定方法を追記

**backward compatibility:**

- field は optional。既存の Client record / config は invalid にならない
- Token Exchange を有効化しない consumer は何も変更不要
- Token Exchange 有効化時、`allowedAudiences` 未設定の client は「自分自身 (clientId) のみ audience 指定可」= 安全 default

## 9. `act` claim の構築

### 9.1 Default policy

- `actor_token` 提示時 → `act: { sub: <actor.sub> }` を必ず JWT に埋める
- `actor_token` 無し → `act` 無しの impersonation
- RFC 8693 §4.1 の素直な実装

### 9.2 Override

- 厳格な delegation 強制が必要な consumer は既存 `GrantPolicyHook` で宣言:
  ```ts
  async evaluate(request: GrantPolicyRequest, ctx: GrantPolicyContext): Promise<GrantPolicyDecision> {
    if (request.grantType === "urn:ietf:params:oauth:grant-type:token-exchange"
        && !request.actorTokenType) {
      return {
        outcome: "deny",
        error: "invalid_request",
        errorDescription: "actor_token required for delegation",
      };
    }
    return { outcome: "allow" };
  }
  ```
- `actorTokenType` / `subjectTokenType` / `resource` は既に `GrantPolicyRequest` interface に乗っている (`packages/core/src/policy/types.mts:19-30`)

### 9.3 入れ子 act (多段 delegation)

`subject_token` 自体が既に `act` claim を持っている場合:

```json
// subject_token の claims
{ "sub": "alice", "act": { "sub": "service-a" } }

// actor_token (service-b)
{ "sub": "service-b" }

// 発行される token の act
{ "sub": "service-b", "act": { "sub": "service-a" } }
```

RFC 8693 §4.1 の nested actor chain に従う。全選択肢で実装必須。

## 10. Consumer registration の shape

### 10.1 最小構成 (built-in access_token validator のみ)

```ts
import { GrantRegistry } from "@o3co/auth-provider-core";
import {
  tokenExchangeModule,
  ExchangeTokenValidatorRegistry,
  createSelfIssuedAccessTokenValidator,
} from "@o3co/auth-provider-oauth-token-exchange";

const validatorRegistry = new ExchangeTokenValidatorRegistry();
validatorRegistry.register(
  "urn:ietf:params:oauth:token-type:access_token",
  createSelfIssuedAccessTokenValidator({ keyStore, refreshTokenStore, issuer }),
);

grantRegistry.addModule(tokenExchangeModule, {
  ...deps,
  validatorRegistry,
  clientRepository,
});
```

### 10.2 外部 JWT も受け入れる consumer

```ts
class ExternalJwtValidator implements ExchangeTokenValidator {
  readonly tokenType = "urn:ietf:params:oauth:token-type:jwt";
  async validate(
    token: string,
    ctx: { role: "subject" | "actor" },
  ): Promise<ValidatedToken | null> {
    // jwks_uri fetch, signature verify, issuer allowlist check, revocation check
  }
}

validatorRegistry.register(
  "urn:ietf:params:oauth:token-type:jwt",
  new ExternalJwtValidator({ allowedIssuers: [...], jwksUri: "..." }),
);
```

### 10.3 登録されていない token type への対応

- Registry が `undefined` を返す → grant handler が `unsupported_token_type` で応答 (default deny)

## 11. Configuration

### 11.1 No module-specific config surface

This module does not expose a config schema. Per Task 9 spec note, the RFC
8693 grant-type URN (`urn:ietf:params:oauth:grant-type:token-exchange`) is
used as the `GrantModule.grants` key for handler dispatch, but core's
`GrantRegistry.addModule` keys module config blocks by that same key.
HOCON-friendly keys like `token_exchange.*` are therefore dropped during
schema parsing.

**audience allowlist は client 単位 (`Client.allowedAudiences`) のみで管理** (§8.3)。全 client 共通の shared allowlist は本 spec では導入しない。理由: 複数ソースの allowlist は merge/precedence を明示しないと security hole になる。必要になれば post-0.5 で `GrantPolicyHook` で consumer 側実装できる。

### 11.2 expiresIn source

Token Exchange access_tokens use `oauth.accessToken.expiresIn` (the global
OAuth access_token lifetime config). This applies to all OAuth grants and is
already configurable at the top level of HOCON. Consumers who want a
different expiresIn specifically for Token Exchange should wrap
`createTokenExchangeGrant()` and pass a custom config, rather than use the
GrantModule pattern.

**`expiresIn` default:** short (300s = 5 min). Token Exchange is short-lived by RFC 8693 recommendation.

### 11.3 Disable mechanism

Consumers disable Token Exchange by **not importing `tokenExchangeModule`**. This matches the federation-package-split philosophy (v0.5.0 #17): registration is 100% consumer opt-in. There is no config-driven disable switch.

Rationale: `GrantModule` in core dispatches handlers by grant-type key (the RFC 8693 URN `urn:ietf:params:oauth:grant-type:token-exchange`), but operator-friendly HOCON uses the `token_exchange` key. Bridging those two via a config-driven `enabled` flag would require a core interface change (adding `configKey?: string` to `GrantModule`) that v0.5.0 interface freeze avoids. Consumer-level opt-in via module import is both simpler and consistent with the rest of v0.5.0 scope.

## 12. Test 戦略

### 12.1 Unit tests (TDD RED → GREEN → REFACTOR)

**ExchangeTokenValidatorRegistry:**
- register / get / unknown type

**createSelfIssuedAccessTokenValidator:**
- 正常 token の validate
- 署名不正 → null
- exp 過ぎ → null
- family revoked → null
- store unavailable → throw (fail-closed)
- 外部発行 issuer の token → null (issuer 一致しない場合)

**createTokenExchangeGrant — happy path:**
- 最小 request (A: impersonation, actor_token 無し) で access_token 発行、`act` claim 無し
- actor_token あり request (B: delegation) で `act: { sub: <actor.sub> }` が載る
- 入れ子 delegation (subject 自体が `act` を持つ + actor_token あり) で `act: { sub: <actor>, act: <subject.act> }` が構築
- actor_token 無し + subject に `act` 付き → 発行 token に `act` 継承しない (§9 canonical rule)
- scope narrowing (C) で subject の subset だけ発行
- scope 省略時: subject の scope を継承
- audience 省略 + subject 単一 aud: 発行 token の `aud` = subject の `aud`
- audience 省略 + subject 多 aud / aud 未設定: 発行 token の `aud` = `clientId`
- audience 指定時: `allowedAudiences ∪ { clientId }` にある値のみ許可
- `allowedAudiences` 未設定 + `audience=<clientId>` → 許可 (safe default §8.3)
- policy hook が `grantedScope` / `grantedAudience` を返したら override を反映

**createTokenExchangeGrant — error cases:**
- 必須 field 欠落 → invalid_request
- unknown subject_token_type → unsupported_token_type
- requested_token_type が access_token 以外 → unsupported_token_type
- unknown actor_token_type (提示時) → unsupported_token_type
- scope superset 要求 → invalid_scope
- audience not in allowlist → invalid_target
- subject family revoked → invalid_grant (errorDescription: `family_revoked`)
- **refreshTokenStore not wired** → invalid_grant (400) + startup warning log (§7.2 state 1)
- **refreshTokenStore runtime throw** → temporarily_unavailable (503) (§7.2 state 2)
- policy hook `{ outcome: "deny", error, errorDescription }` → そのエラーコードで reject
- requested_token_type = id_token / refresh_token → unsupported_token_type (E: token type conversion 明示拒否)

### 12.2 Integration tests

- authorization_code で取った access_token を subject に → token_exchange で別 audience の access_token を発行
- 発行された token を introspect → active (family_id 継承確認)
- 元 family を revoke → 発行された delegated token も introspect で inactive (cascade 動作確認)

## 13. Security considerations

1. **Scope escalation 防止**: built-in subset check (core 強制、policy で bypass 不可)
2. **Token replay 対策**: subject_token の jti を nonce store で one-time にするかは policy hook で consumer 判断 (spec でガイドライン記述、実装は built-in しない)
3. **Family cascade**: subject の family revoke で delegated token も自動失効 (α 方針)
4. **Impersonation 痕跡の欠如**: `actor_token` 無し = `act` claim 無し。監査要件の強い consumer は policy hook で actor_token 必須化を推奨 (README 明記)
5. **外部 JWT の trust anchor**: consumer が implicit に信頼する issuer を明示設定する責任を持つ (README 明記)
6. **Audience confusion**: narrowed audience は client registration の allowlist + policy hook double check
7. **DPoP bound token の扱い**: v0.5.0 では `cnf` claim があっても無視、新 token に `cnf` は載せない (DPoP 段階投入 Y 戦略、1.0 GA で対応)

## 14. 後方互換性

- Interface 追加のみ、既存 interface の変更は §8.3 で明示確定した `Client.allowedAudiences?: string[]` の 1 件のみ (optional field 追加なので backward compat)
- `GrantDependencies` / `GrantHandler` / `RefreshTokenStoreBase` は無変更
- Consumer が module を import しなければ完全に noop (breaking change なし)
- `enabled` フィールドを config schema から削除 (C1 Option D): schema-level のみの変更。`tokenExchangeModule` は v0.5.0 初出なので `enabled` に依存していた consumer はいない。backward compat 問題なし。
- `tokenExchangeConfigSchema` export を削除 (P2 / multi-agent-review follow-up): `GrantRegistry.addModule` が URN キーでモジュール config を管理するため、`token_exchange.*` キーは schema parsing 時に DROP されていた。実質 noop だったため依存 consumer はいない。backward compat 問題なし。

## 15. post-0.5 に残す項目 (out-of-scope)

- 外部 JWT validator の built-in 実装 (`@o3co/auth-provider-oauth-external-jwt` 候補)
- SAML2 token type の受入 (`urn:ietf:params:oauth:token-type:saml2`)
- id_token 発行 Token Exchange
- DPoP-bound token の Token Exchange (v1.0 GA)
- `requested_token_type` 以外の token type 発行
- `/oauth/revoke` endpoint での jti 単位 revocation

## 16. 関連文書

### 16.1 Debate / decision log

- `debate/did-auth-oauth2-idp/` 全 4 ラウンド
- `debate/did-auth-oauth2-idp/191600_CON.md:67` — CON 起点
- `debate/did-auth-oauth2-idp/191619_PRO.md:90,143,175` — PRO 受諾
- `debate/did-auth-oauth2-idp/191845_PRO.md:192` — 最高優先度確定
- `debate/did-auth-oauth2-idp/192516_PRO.md:104,215` — persona pain + GA gate

### 16.2 Existing spec / plan

- `2026-04-21-extension-surface-decisions-design.md` — GrantPolicyHook 仕様 (本 spec が流用)
- `2026-04-21-extension-surface-decisions-design.md:535-537` — subjectTokenType / actorTokenType / resource は既に `GrantPolicyRequest` に定義済み
- `2026-04-23-federation-provider-package-split-design.md` — built-in registration 廃止の判例
- `2026-04-24-grant-type-rename-design.md` — grant_type URN 化、IETF 標準 URN 使用方針

### 16.3 Existing implementation

- `packages/core/src/refresh/types.mts` — `RefreshTokenStoreBase.isFamilyRevoked`
- `packages/oauth/src/routes.mts:262-302` — introspect の family revocation cascade
- `packages/oauth/src/grants/authorization.mts:254-260` — family_id 発行 + cascade 方針
- `packages/core/src/grants/token.mts` — generateToken / generateTokenResponse (流用)

### 16.4 External references

- [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) — OAuth 2.0 Token Exchange
- [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) — Resource Indicators for OAuth 2.0 (`invalid_target` error)
- [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) — OAuth 2.0 core (error response format)
- [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662) — Token Introspection (`active: false` semantics)
