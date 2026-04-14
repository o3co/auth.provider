# @o3co/auth-provider-did

[auth.provider](../../README.md) 向け DID (Decentralized Identifier) 認証 grant。

OAuth 2.0 の `"did"` grant type を追加する。クライアントは DID と署名済みメッセージを提示し、サーバーは DID ドキュメントから解決した公開鍵で署名を検証する。4 種類の署名アルゴリズムをサポートする。

## インストール

このパッケージは **private** です。npm には公開されておらず、`auth.provider` モノリポ内でのみ利用できます。

```jsonc
// packages/*/package.json
{
  "dependencies": {
    "@o3co/auth-provider-did": "workspace:*"
  }
}
```

peer dependencies（ワークスペースルートに別途インストール）:

```
@noble/ed25519@^3.0.1   (optional — "ed25519_raw" アルゴリズムを使用する場合のみ必要)
```

## パブリック API

### `oauthDidModule`

```typescript
function oauthDidModule(options: DidModuleOptions): Module;
```

モジュール（name: `"oauth-did"`）を返すファクトリ関数。`config.oauth.grants.did.enabled` が `true` のとき、grant レジストリに `"did"` grant type を登録する。DID 認証を有効化するには、戻り値を `createApp` の modules に渡すこと。

`DidModuleOptions` には DID ドキュメントリゾルバーを以下のいずれかの形式で渡す:

```typescript
type DidModuleOptions =
  | { resolver: DidDocumentResolver }
  | { resolverFactory: (config: Record<string, unknown>) => DidDocumentResolver };
```

- **`resolver`** — 構築済みのリゾルバーインスタンス
- **`resolverFactory`** — 初期化時に DID grant config セクションを受け取りリゾルバーを返すファクトリ関数

---

### `createDidGrant`

```typescript
function createDidGrant(deps: GrantDependencies): GrantHandler;
```

`"did"` grant ハンドラーを生成するファクトリ関数。ハンドラーが期待するリクエストボディフィールド:

| フィールド           | 説明                                               |
|---------------------|---------------------------------------------------|
| `did`               | 認証するパーティの DID                              |
| _(アルゴリズム依存)_ | 設定されたアルゴリズムによって追加フィールドが異なる  |

アルゴリズムは `config.oauth.grants.did.algorithm` で選択する:

| アルゴリズム      | 説明                                                        |
|-----------------|-------------------------------------------------------------|
| `ed25519_raw`   | 生の Ed25519 署名（デフォルト）。`@noble/ed25519` が必要。   |
| `ed25519_jws`   | JWS エンベロープに包んだ Ed25519 署名                        |
| `es256_jws`     | ES256 (P-256) JWS                                           |
| `es256k_jws`    | ES256K (secp256k1) JWS                                      |

---

### `didConfigSchema`

```typescript
const didConfigSchema: z.ZodObject<{
  did: {
    enabled: boolean;
    algorithm: Algorithm;
    messageMaxAgeSec: number;
  };
}>;
```

DID grant 設定ブロック用の Zod スキーマ。config バリデーションに使用する。

---

### `createVerifier`

```typescript
function createVerifier(
  algorithm: Algorithm,
  pathResolver?: PathResolver,
): Promise<SignatureVerifier>;
```

指定したアルゴリズム用の `SignatureVerifier` を生成する。`pathResolver` はディスク上の鍵マテリアルの場所解決に使用する（一部のアルゴリズムで必要）。

---

### `SignatureVerifier` (interface)

```typescript
interface SignatureVerifier {
  verify(ctx: VerificationContext): Promise<VerificationResult>;
}
```

---

### `VerificationContext` (interface)

```typescript
interface VerificationContext {
  body: Record<string, unknown>;
  did: string;
}
```

---

### `VerificationResult` (type)

```typescript
type VerificationResult =
  | { valid: true; subject: string; audience?: string; parsedMessage: ParsedMessage }
  | { valid: false; error: string; errorDescription: string };
```

`subject` や `parsedMessage` にアクセスする前に `valid` を確認すること。

---

### `ParsedMessage` (interface)

```typescript
interface ParsedMessage {
  did: string;
  timestamp: string;
  nonce: string;
  audience?: string;
}
```

---

### `Algorithm` (type)

```typescript
type Algorithm = "ed25519_raw" | "ed25519_jws" | "es256_jws" | "es256k_jws";
```

## 使い方

```typescript
import express from "express";
import { createApp } from "@o3co/auth-provider-core";
import { oauthDidModule } from "@o3co/auth-provider-did";

// config で DID 認証を有効化:
// config.oauth.grants.did.enabled = true
// config.oauth.grants.did.algorithm = "ed25519_raw"

const app = createApp(express, {
  config,
  keyStore,
  modules: [oauthDidModule({ resolver: myResolver })],
});
await app.init();
```

### 署名の直接検証

```typescript
import { createVerifier } from "@o3co/auth-provider-did";

const verifier = await createVerifier("ed25519_jws");
const result = await verifier.verify({ did, body: requestBody });

if (result.valid) {
  console.log("認証済み subject:", result.subject);
} else {
  console.error(result.error, result.errorDescription);
}
```

## 本番運用における注意事項

### Nonce リプレイ保護

DID grant は nonce のリプレイ保護にインメモリストアを使用しています。これには以下の 2 つの制限があります。

1. **プロセス再起動**: 再起動時に保存済み nonce が失われるため、`messageMaxAgeSec`（デフォルト: 300 秒）の間リプレイ攻撃が可能になります
2. **マルチインスタンス環境**: 各インスタンスが独自の nonce ストアを保持するため、あるインスタンスで使用した nonce を別のインスタンスでリプレイできます

より強固なリプレイ保護が必要な本番環境では、外部の nonce ストア（例: Redis）の使用を推奨します。プラガブルなバックエンドに対応する `NonceStore` インターフェースは将来のリリースで提供予定です。

## 関連

- [`@o3co/auth-provider-oauth`](../oauth/README.ja.md) — OAuth 2.0 トークン・認可ルート
- [`@o3co/auth-provider-session`](../session/README.ja.md) — セッションログイン / フェデレーションルート
- [`@o3co/auth-provider-core`](../core/README.ja.md) — 共有型定義 (`Module`、`GrantModule`、`GrantHandler`、`GrantDependencies`)
