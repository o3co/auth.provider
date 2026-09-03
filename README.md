# auth.provider

[![CI](https://github.com/o3co/auth.provider/actions/workflows/ci.yml/badge.svg)](https://github.com/o3co/auth.provider/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@o3co/auth-provider-core)](https://www.npmjs.com/package/@o3co/auth-provider-core)
[![codecov](https://codecov.io/gh/o3co/auth.provider/graph/badge.svg)](https://codecov.io/gh/o3co/auth.provider)
[![API Docs](https://img.shields.io/badge/docs-API-blue)](https://o3co.github.io/auth.provider/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

> This repository handles **authentication and token issuance** in the three-layer separation of concerns (authentication & token issuance / [authorization decision](https://github.com/o3co/auth.policy-verifier) / [authorization enforcement](https://github.com/o3co/protobuf.interceptors)) of the [auth](https://github.com/o3co/auth) stack.

OAuth 2.0 / OIDC provider. Issue JWTs via session-based login or the authorization code flow — same token format, same introspection endpoint, same downstream verification.

## Features

- **Modular composition** — Pick only the modules you need. Skip session, federation, or authorization code for API-only deployments.
- **JWT algorithm selection** — EdDSA (default), ES256, RS256, HS256. The default is asymmetric, so the JWKS endpoint (`/.well-known/jwks.json`) publishes a real verification key and relying parties never hold one that can also mint tokens. HS256 stays selectable and publishes no JWKS.
- **OAuth 2.0 compliance** — Authorization code flow with PKCE (RFC 7636), token introspection (RFC 7662), refresh tokens
- **Session authentication** — Local username/password login + OAuth federation (Google, GitHub, and custom providers via per-federation `defineModule(...)` modules)
- **Rate limiting** — Per-endpoint configurable limits
- **HOCON configuration** — Type-safe config with Zod validation and environment variable overrides

## Quick Start

```bash
npx @o3co/create-auth-provider my-auth-app
cd my-auth-app
pnpm install
pnpm build
```

## Architecture

```text
┌──────────────────────────────────────────┐
│             Composition Root              │
│  (standalone template or your own app)   │
├─────────┬───────────┬────────────────────┤
│  oauth  │  session  │    foundation      │
│ /oauth  │ /session  │  HTTP user         │
│ routes  │  routes   │  adapter           │
├─────────┴───────────┴────────────────────┤
│                   core                    │
│  Module system · KeyStore · Repositories │
└──────────────────────────────────────────┘
```

- **core** — Interfaces, config schemas, token service, app factory. Always required.
- **oauth** — OAuth routes (`/oauth/token`, `/oauth/authorize`, `/oauth/introspect`). Required for any token issuance.
- **session** — Session login + provider-registered OAuth federation. Optional — skip for API-only deployments.
- **federation-google / federation-github** — Concrete OAuth federation providers. Optional — install only the providers you register.
- **foundation** — Production HTTP user-authentication adapter (client of "the Store"). Optional.
- **webauthn / dpop / mtls / oauth-token-exchange / device-grant / redis** — Optional capability and adapter modules; see [Packages](#packages).

## Packages

| Package | npm | Description |
| --- | --- | --- |
| [`packages/core`](packages/core/) | `@o3co/auth-provider-core` | Core abstractions all other packages build on: module system, token service, repository interfaces, config schemas |
| [`packages/oauth`](packages/oauth/) | `@o3co/auth-provider-oauth` | OAuth 2.0 routes module: `/oauth/token`, `/oauth/authorize`, `/oauth/introspect` |
| [`packages/oauth-token-exchange`](packages/oauth-token-exchange/) | `@o3co/auth-provider-oauth-token-exchange` | RFC 8693 Token Exchange grant — on-behalf-of, delegation (`act`), scope/audience narrowing |
| [`packages/device-grant`](packages/device-grant/) | `@o3co/auth-provider-device-grant` | RFC 8628 Device Authorization Grant — the device-code flow for TVs, CLIs and IoT |
| [`packages/session`](packages/session/) | `@o3co/auth-provider-session` | Session and federation routes module: login, logout, OAuth 2.0 federation |
| [`packages/webauthn`](packages/webauthn/) | `@o3co/auth-provider-webauthn` | Passkey (WebAuthn) credential lifecycle + authentication grant, AS-scope only |
| [`packages/dpop`](packages/dpop/) | `@o3co/auth-provider-dpop` | DPoP (RFC 9449) sender-constrained access tokens |
| [`packages/mtls`](packages/mtls/) | `@o3co/auth-provider-mtls` | mTLS (RFC 8705) sender-constrained access tokens |
| [`packages/federation-google`](packages/federation-google/) | `@o3co/auth-provider-federation-google` | Google federation provider |
| [`packages/federation-github`](packages/federation-github/) | `@o3co/auth-provider-federation-github` | GitHub federation provider |
| [`packages/redis`](packages/redis/) | `@o3co/auth-provider-redis` | Redis-backed adapters and `defineModule` manifests |
| [`packages/foundation`](packages/foundation/) | `@o3co/auth-provider-foundation` | Production HTTP user-authentication adapter ("the Store" client) |
| [`templates/standalone`](templates/standalone/) | — | Deployable server template (composition root) |
| [`create-app`](create-app/) | `@o3co/create-auth-provider` | CLI scaffolder |

## Endpoints

| Endpoint | Module | Description |
| --- | --- | --- |
| `POST /oauth/token` | oauth | Token issuance (session, authorization code, refresh) |
| `GET /oauth/authorize` | oauth | Authorization code flow (PKCE) |
| `POST /oauth/introspect` | oauth | Token introspection (RFC 7662) |
| `GET /.well-known/jwks.json` | core | JWKS endpoint (asymmetric algorithms only) |
| `GET /session/csrf` | session | Issue a double-submit CSRF token |
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
    # Required. Canonical issuer stamped as `iss` on every minted token:
    # absolute https URL (http only for a loopback host), no query or fragment.
    # Boot fails when unset — it is never derived from the Host header.
    issuer = ${?OAUTH_JWT_ISSUER}
    signingKey {
      provider = "local"           # "local" is the only built-in; extend via KeyStoreFactory
      local {
        # Default. Asymmetric, so /.well-known/jwks.json publishes a real
        # verification key and no relying party ever holds a key that can
        # also MINT tokens. Required — there is no key-material default:
        #   openssl genpkey -algorithm ed25519 -out jwt-private.pem
        #   openssl pkey -in jwt-private.pem -pubout -out jwt-public.pem
        algorithm = "EdDSA"        # EdDSA | ES256 | RS256 | HS256
        privateKeyPath = ${?OAUTH_JWT_PRIVATE_KEY_PATH}
        publicKeyPath  = ${?OAUTH_JWT_PUBLIC_KEY_PATH}
        # HS256 instead: set algorithm = "HS256" and supply a secret of at
        # least 32 bytes (`openssl rand -hex 32`). No JWKS is published.
        # secret = ${?OAUTH_JWT_SECRET}
      }
    }
  }
  accessToken  { expiresIn = 3600 }   # seconds, positive, <= 1 year
  refreshToken { expiresIn = 86400 }  # seconds, positive, <= 1 year
}
```

**Authorization code grant (when `oauthAuthorizationModule` is registered):**

```hocon
oauth.grants.authorization_code {
  pkce {
    requireS256 = false   # Set to true to reject plain code_challenge_method (S256 only)
    requireS256 = ${?OAUTH_GRANTS_AUTHORIZATION_CODE_PKCE_REQUIRE_S256}
  }
}
```

**Session (when `sessionModule` is registered):**

```hocon
# `secret` signs the cookie that IS the authenticated session: at least
# 32 bytes (256 bits), e.g. `openssl rand -hex 32`.
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
npx @o3co/create-auth-provider my-auth-app
cd my-auth-app
docker build -t my-auth .
```

## Operating

- [docs/operator-runbook.md](docs/operator-runbook.md) — running it: deployment shapes and boot refusals, liveness vs readiness, what fail-closed looks like on each dependency, which log and audit events to alert on, Redis key families and sizing, key rotation, upgrading and rollback.
- [docs/release-runbook.md](docs/release-runbook.md) — cutting a release; [docs/release-policy.md](docs/release-policy.md) — how releases and retired config keys are labelled.
- [docs/adapter-surface.md](docs/adapter-surface.md) — every component slot a composition root can fill, and the boundary that decides what may become one.

## Related Projects

- [auth.policy-verifier](https://github.com/o3co/auth.policy-verifier) — ABAC policy engine for authorization decisions
- [auth.proxy](https://github.com/o3co/auth.proxy) — Token validation reverse proxy
- [protobuf.interceptors](https://github.com/o3co/protobuf.interceptors) — protobuf-option-driven authorization interceptors for gRPC / ConnectRPC (calls auth.provider for introspection, auth.policy-verifier for authorization)
- [auth](https://github.com/o3co/auth) — Architecture docs and E2E tests

## License

Apache License 2.0 — Copyright 2026 1o1 Co. Ltd.
