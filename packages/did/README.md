# @o3co/auth-provider-did

DID (Decentralized Identifier) authentication grant for [auth.provider](../../README.md).

Adds a `"did"` OAuth 2.0 grant type. Clients present a DID and a signed message; the server verifies the signature using the public key resolved from the DID document. Supports four signature algorithms.

## Install

This package is **private** — it is not published to npm and is only available within the `auth.provider` monorepo.

```jsonc
// packages/*/package.json
{
  "dependencies": {
    "@o3co/auth-provider-did": "workspace:*"
  }
}
```

Peer dependencies (install separately in the workspace root):

```
@noble/ed25519@^3.0.1   (optional — required only for the "ed25519_raw" algorithm)
```

## Public API

### `oauthDidModule`

```typescript
function oauthDidModule(options: DidModuleOptions): Module;
```

Factory that returns a module (name: `"oauth-did"`). Registers the `"did"` grant type in the grant registry when `config.oauth.grants.did.enabled` is `true`. Pass the result to `createApp` as a module to enable DID authentication.

`DidModuleOptions` must supply a DID document resolver in one of two forms:

```typescript
type DidModuleOptions =
  | { resolver: DidDocumentResolver }
  | { resolverFactory: (config: Record<string, unknown>) => DidDocumentResolver };
```

- **`resolver`** — a pre-built resolver instance
- **`resolverFactory`** — a factory called with the DID grant config section at init time

---

### `createDidGrant`

```typescript
function createDidGrant(deps: GrantDependencies): GrantHandler;
```

Factory that creates the `"did"` grant handler. The handler expects the following request body fields:

| Field                 | Description                                        |
|-----------------------|----------------------------------------------------|
| `did`                 | The DID of the authenticating party                |
| _(algorithm-specific)_ | Additional fields depend on the configured algorithm |

Algorithms are selected via `config.oauth.grants.did.algorithm`:

| Algorithm       | Description                                |
|-----------------|--------------------------------------------|
| `ed25519_raw`   | Raw Ed25519 signature (default). Requires `@noble/ed25519`. |
| `ed25519_jws`   | Ed25519 wrapped in a JWS envelope          |
| `es256_jws`     | ES256 (P-256) JWS                          |
| `es256k_jws`    | ES256K (secp256k1) JWS                     |

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

Zod schema for the DID grant configuration block. Used for config validation.

---

### `createVerifier`

```typescript
function createVerifier(
  algorithm: Algorithm,
  pathResolver?: PathResolver,
): Promise<SignatureVerifier>;
```

Creates a `SignatureVerifier` for the given algorithm. `pathResolver` is used to locate key material on disk (required for some algorithms).

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

Check `valid` before accessing `subject` or `parsedMessage`.

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

## Usage Example

```typescript
import express from "express";
import { createApp } from "@o3co/auth-provider-core";
import { oauthDidModule } from "@o3co/auth-provider-did";

// Enable DID auth via config:
// config.oauth.grants.did.enabled = true
// config.oauth.grants.did.algorithm = "ed25519_raw"

const app = createApp(express, {
  config,
  keyStore,
  modules: [oauthDidModule({ resolver: myResolver })],
});
await app.init();
```

### Verifying a signature directly

```typescript
import { createVerifier } from "@o3co/auth-provider-did";

const verifier = await createVerifier("ed25519_jws");
const result = await verifier.verify({ did, body: requestBody });

if (result.valid) {
  console.log("authenticated subject:", result.subject);
} else {
  console.error(result.error, result.errorDescription);
}
```

## Production Considerations

### Nonce Replay Protection

The DID grant uses an in-memory store for nonce replay protection. This has two limitations:

1. **Process restarts**: Stored nonces are lost on restart, creating a replay window of `messageMaxAgeSec` (default: 300 seconds)
2. **Multi-instance deployments**: Each instance maintains its own nonce store, so a nonce used on one instance can be replayed on another

For production deployments requiring stronger replay protection, an external nonce store (e.g., Redis) is recommended. A `NonceStore` interface for pluggable backends is planned for a future release.

## See Also

- [`@o3co/auth-provider-oauth`](../oauth/README.md) — OAuth 2.0 token and authorization routes
- [`@o3co/auth-provider-session`](../session/README.md) — session login / federation routes
- [`@o3co/auth-provider-core`](../core/README.md) — shared types (`Module`, `GrantModule`, `GrantHandler`, `GrantDependencies`)
