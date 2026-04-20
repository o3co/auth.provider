# auth.provider

[![CI](https://github.com/o3co/auth.provider/actions/workflows/ci.yml/badge.svg)](https://github.com/o3co/auth.provider/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@o3co/auth-provider-core)](https://www.npmjs.com/package/@o3co/auth-provider-core)
[![codecov](https://codecov.io/gh/o3co/auth.provider/graph/badge.svg)](https://codecov.io/gh/o3co/auth.provider)
[![API Docs](https://img.shields.io/badge/docs-API-blue)](https://o3co.github.io/auth.provider/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

OAuth 2.0 provider with DID (Decentralized Identifier) authentication. Issue JWTs from traditional login flows or DID-based cryptographic proof — same token format, same introspection endpoint, same downstream verification.

## DID Authentication

DID authentication lets clients prove identity using cryptographic key pairs tied to a [Decentralized Identifier](https://www.w3.org/TR/did-core/), without passwords or pre-shared secrets. The server resolves the client's DID Document, extracts the public key, and verifies the signature.

```text
Client                              auth.provider
  │                                      │
  │  POST /oauth/token                   │
  │  grant_type=did                      │
  │  did=did:example:org:abc123          │
  │  message={"did":"...","nonce":"..."}  │
  │  signature=<Ed25519 signature>       │
  │ ──────────────────────────────────►  │
  │                                      │  1. Resolve DID Document
  │                                      │  2. Extract public key
  │                                      │  3. Verify signature
  │                                      │  4. Issue JWT
  │  ◄──────────────────────────────────  │
  │  { access_token: "eyJ...", ... }     │
```

The `DidDocumentResolver` interface is pluggable — implement it for your DID method (`did:web`, `did:key`, `did:ion`, or any custom method) and inject it at startup.

### Supported signature algorithms

| Algorithm | Format | Library |
| --- | --- | --- |
| `ed25519_raw` (default) | Raw Ed25519 signature + message | `@noble/ed25519` |
| `ed25519_jws` | Compact JWS with `alg=EdDSA` | `jose` |
| `es256_jws` | Compact JWS with `alg=ES256` | `jose` |
| `es256k_jws` | Compact JWS with `alg=ES256K` | `jose` |

## Features

- **DID authentication grant** — Pluggable `DidDocumentResolver` interface, signature verification from DID Document public keys
- **Modular composition** — Pick only the modules you need. DID-only? Skip session, federation, authorization code entirely.
- **JWT algorithm selection** — HS256, RS256, ES256, EdDSA. JWKS endpoint (`/.well-known/jwks.json`) for asymmetric algorithms.
- **OAuth 2.0 compliance** — Authorization code flow with PKCE (RFC 7636), token introspection (RFC 7662), refresh tokens
- **Session authentication** — Passport.js local strategy + OAuth federation (Google, GitHub, and custom providers via `FederationProviderFactory`)
- **Rate limiting** — Per-endpoint configurable limits
- **HOCON configuration** — Type-safe config with Zod validation and environment variable overrides

## Quick Start

```bash
npx create-o3co-auth-provider my-auth-app
cd my-auth-app
pnpm install
pnpm build
```

For a DID-only deployment (no session, no federation):

```typescript
import express from "express";
import { parseFile, validate } from "@o3co/ts.hocon";
import {
  AppConfigSchema,
  createApp,
  createKeyStoreFactory,
  registerBuiltinKeyStores,
} from "@o3co/auth-provider-core";
import { oauthDidModule } from "@o3co/auth-provider-did";
import { oauthModule } from "@o3co/auth-provider-oauth";

// Load & validate HOCON config (see packages/core/config/application.conf
// for the nested oauth.jwt.signingKey shape).
const config = validate(parseFile("./config/application.conf"), AppConfigSchema);

// flatten() normalises the nested adapter sub-section to { type, ...fields }.
// Accepts both `type` (clients.*, session.storage) and `provider`
// (oauth.jwt.signingKey) selectors. See packages/core/README.md for the
// full helper definition.
const flatten = (section: { type?: string; provider?: string } & Record<string, unknown>) => {
  const selector = section.type ?? section.provider;
  if (typeof selector !== "string") throw new TypeError("missing selector");
  const sub = section[selector];
  return {
    type: selector,
    ...(typeof sub === "object" && sub !== null && !Array.isArray(sub)
      ? (sub as Record<string, unknown>)
      : {}),
  };
};

const keyStoreFactory = createKeyStoreFactory();
registerBuiltinKeyStores(keyStoreFactory);
const keyStore = await keyStoreFactory.create(flatten(config.oauth.jwt.signingKey));

// ... wire up clientRepository / codeRepository / myDidResolver ...

const { init, router } = createApp({
  express,
  config,
  keyStore,
  modules: [
    oauthModule({ clientRepository, codeRepository }),
    oauthDidModule({ resolver: myDidResolver }),
  ],
});

await init();
```

## Architecture

```text
┌─────────────────────────────────────────────────┐
│                 Composition Root                 │
│     (standalone template or your own app)        │
├─────────┬───────────┬───────────┬───────────────┤
│  oauth  │  session  │    did    │  foundation   │
│ /oauth  │ /session  │ DID grant │ Redis, HTTP   │
│ routes  │  routes   │  handler  │  adapters     │
├─────────┴───────────┴───────────┴───────────────┤
│                      core                        │
│  GrantRegistry · KeyStore · Repositories · Config│
└─────────────────────────────────────────────────┘
```

- **core** — Interfaces, config schemas, token service, app factory. Always required.
- **oauth** — OAuth routes (`/oauth/token`, `/oauth/authorize`, `/oauth/introspect`). Required for any token issuance.
- **did** — DID authentication grant. Optional — only needed if you use DID-based auth.
- **session** — Session login + OAuth federation (Google, GitHub, extensible). Optional — skip for API-only deployments.
- **foundation** — Production repository adapters (Redis code store, HTTP user lookup). Optional.

## Packages

| Package | npm | Description |
| --- | --- | --- |
| [`packages/core`](packages/core/) | `@o3co/auth-provider-core` | Grant registry, token service, repository interfaces, config schemas |
| [`packages/did`](packages/did/) | `@o3co/auth-provider-did` | DID authentication grant with pluggable resolver |
| [`packages/oauth`](packages/oauth/) | `@o3co/auth-provider-oauth` | OAuth routes: `/oauth/token`, `/oauth/authorize`, `/oauth/introspect` |
| [`packages/session`](packages/session/) | `@o3co/auth-provider-session` | Session routes, Passport.js, OAuth federation (Google, GitHub, extensible) |
| [`packages/foundation`](packages/foundation/) | `@o3co/auth-provider-foundation` | Redis code store, HTTP user/client repositories |
| [`templates/standalone`](templates/standalone/) | — | Deployable server template (composition root) |
| [`create-app`](create-app/) | `create-o3co-auth-provider` | CLI scaffolder |

## Endpoints

| Endpoint | Module | Description |
| --- | --- | --- |
| `POST /oauth/token` | oauth | Token issuance (session, authorization code, DID, refresh) |
| `GET /oauth/authorize` | oauth | Authorization code flow (PKCE) |
| `POST /oauth/introspect` | oauth | Token introspection (RFC 7662) |
| `GET /.well-known/jwks.json` | core | JWKS endpoint (asymmetric algorithms only) |
| `POST /session/login` | session | Local authentication |
| `POST /session/logout` | session | Session destruction |
| `GET /_healthcheck` | core | Health check |

## Configuration

HOCON config file with environment variable overrides. The config schema depends on which modules are registered:

**Core (always required):**

```hocon
http { port = 3000 }
oauth {
  jwt {
    issuer = ${?OAUTH_JWT_ISSUER}
    signingKey {
      provider = "local"           # "local" is the only built-in; extend via KeyStoreFactory
      local {
        algorithm = "HS256"        # HS256 | RS256 | ES256 | EdDSA
        secret = ${?OAUTH_JWT_SECRET}
        # For asymmetric: privateKey/privateKeyPath + publicKey/publicKeyPath
      }
    }
  }
  accessToken { expiresIn = 3600 }
  refreshToken { expiresIn = 86400 }
}
```

**DID grant (when `oauthDidModule` is registered):**

```hocon
oauth.grants.did {
  enabled = true
  algorithm = "ed25519_raw"   # ed25519_raw | ed25519_jws | es256_jws | es256k_jws
  messageMaxAgeSec = 300
}
```

**Authorization code grant (when `oauthAuthorizationModule` is registered):**

```hocon
oauth.grants.authorization {
  pkce {
    requireS256 = false   # Set to true to reject plain code_challenge_method (S256 only)
    requireS256 = ${?OAUTH_GRANTS_AUTHORIZATION_PKCE_REQUIRE_S256}
  }
}
```

**Session (when `sessionModule` is registered):**

```hocon
session { secret = ${SESSION_SECRET} }

# Shorthand: key name = provider type (google, github, or any registered custom type)
federations {
  google {
    enabled = false
    # clientId, clientSecret, callbackURL — required when enabled = true
  }
  # github { enabled = false }
}
```

See [`templates/standalone/config/application.conf`](templates/standalone/config/application.conf) for a complete example.

## Development

```bash
pnpm install
pnpm -r build     # build all packages
pnpm -r test      # test all packages
```

## Docker

```bash
npx create-o3co-auth-provider my-auth-app
cd my-auth-app
docker build -t my-auth .
```

## Related Projects

- [auth.policy-verifier](https://github.com/o3co/auth.policy-verifier) — ABAC policy engine for authorization decisions
- [auth.proxy](https://github.com/o3co/auth.proxy) — Token validation reverse proxy
- [grpc.authz](https://github.com/o3co/grpc.authz) — gRPC authorization middleware (calls auth.provider for introspection, auth.policy-verifier for authorization)
- [auth](https://github.com/o3co/auth) — Architecture docs and E2E tests

## License

Apache License 2.0 — Copyright 2026 1o1 Co. Ltd.
