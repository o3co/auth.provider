# auth.provider

Last updated: 2026-09-24

[![CI](https://github.com/o3co/auth.provider/actions/workflows/ci.yml/badge.svg)](https://github.com/o3co/auth.provider/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@o3co/auth-provider-core)](https://www.npmjs.com/package/@o3co/auth-provider-core)
[![codecov](https://codecov.io/gh/o3co/auth.provider/graph/badge.svg)](https://codecov.io/gh/o3co/auth.provider)
[![API Docs](https://img.shields.io/badge/docs-API-blue)](https://o3co.github.io/auth.provider/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

> This repository handles **authentication and token issuance** in the three-layer separation of concerns (authentication & token issuance / [authorization decision](https://github.com/o3co/auth.policy-verifier) / [authorization enforcement](https://github.com/o3co/protobuf.interceptors)) of the [auth](https://github.com/o3co/auth) stack.

OAuth 2.0 / OpenID Connect provider. It signs users in — with a password your user service checks, through an upstream identity provider, or with a passkey — and issues JWT access tokens, refresh tokens and ID tokens that downstream services verify offline against its published keys. Session login and the authorization code flow produce the same token format, answer at the same introspection endpoint, and are verified the same way downstream.

## Responsibility

**Role.** The authentication and token-issuance layer of the
[auth](https://github.com/o3co/auth) stack. A client sends a user through it,
or authenticates itself, and gets back tokens; the services those tokens are
for verify them against `/.well-known/jwks.json`, or ask `/oauth/introspect`.
Around it:

- [auth.policy-verifier](https://github.com/o3co/auth.policy-verifier) makes the
  authorization decision — may this subject perform this action on this
  resource;
- [protobuf.interceptors](https://github.com/o3co/protobuf.interceptors)
  enforces it inside gRPC / ConnectRPC services, calling this provider for
  introspection and policy-verifier for the decision;
- [auth.proxy](https://github.com/o3co/auth.proxy) is an optional perimeter: a
  reverse proxy that validates tokens before traffic reaches a service.

**Owns:**

- authenticating end users: local login checked by the deployment's user
  service ("the Store"), federated login through upstream identity providers,
  passkeys; the browser session this creates, and logout — including the
  back-channel and front-channel logout of the relying parties it signed in;
- authenticating clients: client secrets, `private_key_jwt`, and public clients
  bound by PKCE;
- issuing tokens: the authorization-code, refresh-token (with rotation and
  replay detection), client-credentials, JWT-bearer and session grants, and
  the optional device, token-exchange and passkey grants; ID tokens and
  userinfo;
- the tokens' lifecycle: introspection, revocation, sender-constraint (DPoP,
  mTLS), and the consent step for clients that are not first-party;
- publishing what verifiers need: the JWKS and the OpenID discovery document;
- holding upstream IdP tokens — for a session, and, with federation grants, for
  a backend acting on a user's standing consent.

**Does not own:**

- authorization decisions: a token says who the subject is and which scopes and
  audience it was issued for; whether a request is allowed is decided by
  auth.policy-verifier or by the service itself;
- enforcement inside services;
- user records: in a deployment, users, passwords and email verification
  live in the deployment's user service, and the provider reaches them only
  through that service's API (core's YAML user repository is a development and
  test adapter);
- the login and consent pages: the deployment serves its own, and the provider
  redirects to them (`endpoints.login.url`, `endpoints.consent.url`);
- signup, account recovery and email.

**Why a separate service.** It holds the signing key and the session state.
Keeping issuance apart from decision and enforcement means no relying party
needs a key that can mint tokens (the default signing algorithm is
asymmetric), the decision point can be replaced without touching issuance, and
each layer is scaled, deployed and audited on its own.

## Features

- **Modular composition** — Pick only the modules you need. Skip session, federation, or authorization code for API-only deployments.
- **JWT algorithm selection** — EdDSA (default), ES256, RS256, HS256. The default is asymmetric, so the JWKS endpoint (`/.well-known/jwks.json`) publishes a real verification key and relying parties never hold one that can also mint tokens. HS256 stays selectable and publishes no JWKS: the route answers `404 jwks_not_published`.
- **OAuth 2.0 compliance** — Authorization code flow with mandatory PKCE (RFC 7636; `S256` unless a client's registration allows `plain`), token introspection (RFC 7662), revocation (RFC 7009), refresh tokens with rotation and replay detection
- **Session authentication** — Local username/password login against your user service, and federated login through the `federation-*` packages (see [Packages](#packages))
- **Rate limiting** — Per-endpoint configurable limits
- **HOCON configuration** — Type-safe config with Zod validation and environment variable overrides

## Quick Start

```bash
npx @o3co/create-auth-provider my-auth-app
cd my-auth-app
pnpm install
```

The scaffold does not boot on its defaults alone. `pnpm run debug` reads no
`.env` file; from the shell's environment it needs the issuer
(`OAUTH_JWT_ISSUER`), a signing key pair, a session secret, the two URLs of your
user service (`CLIENT_USER_AUTHENTICATE_URL`,
`CLIENT_USER_AUTHENTICATE_BY_TOKEN_URL`), and a Redis on `localhost:6379`. The
[template's README](templates/standalone/README.md#usage) gives the commands,
and [create-app](create-app/README.md) says what the scaffolder generates.

## Architecture

Every package under `packages/` depends on `core`, and `core` on none of them.
The dependency direction:

```text
core                          contracts, module system, config, tokens, keys
├── oauth                     /oauth/*
│   ├── federation-grants
│   └── device-grant          (also depends on session)
├── session                   /session/*
│   └── federation-*          one package per upstream identity provider
├── dpop · mtls · webauthn · oauth-token-exchange
├── redis                     (dpop is an optional peer)
└── foundation
templates/standalone          composes the packages above; create-app copies it
```

`oauth` and `session` do not depend on each other; the adapters (`redis`,
`foundation`, `federation-*`) do not depend on one another. A deployment's
composition root — the standalone template, or your own app — chooses which
modules to install and which adapter fills each component slot.

## Packages

Each package's README states what it owns and why it is separate. In brief:

| Package | npm | Owns | Why a separate package |
| --- | --- | --- | --- |
| [`packages/core`](packages/core/) | `@o3co/auth-provider-core` | The ports and component slots every other package fills, the module system and boot planner, the config schema, token signing and verification, the key store, JWKS, discovery, health and readiness routers, and in-process adapters | The one package every other depends on, and which depends on none of them: the contracts live here, so an adapter implements a port without depending on the packages that use it. It carries no database driver |
| [`packages/oauth`](packages/oauth/) | `@o3co/auth-provider-oauth` | `/oauth/*`: the token endpoint and grant dispatch, `/authorize` and consent, introspection, revocation, userinfo, logout; the authorization-code, refresh-token, client-credentials, JWT-bearer and session grants; client authentication | The OAuth HTTP surface; which grants a deployment offers is chosen by the modules it installs |
| [`packages/session`](packages/session/) | `@o3co/auth-provider-session` | Browser sessions: `/session/login`, `/session/logout`, CSRF, the `express-session` store, and the federated-login routes the `federation-*` adapters plug into | Optional: an API-only deployment has no browser session |
| [`packages/device-grant`](packages/device-grant/) | `@o3co/auth-provider-device-grant` | RFC 8628 device authorization grant — the device-code flow for TVs, CLIs and IoT | Optional grant with endpoints and a store of its own |
| [`packages/oauth-token-exchange`](packages/oauth-token-exchange/) | `@o3co/auth-provider-oauth-token-exchange` | RFC 8693 token exchange — on-behalf-of, delegation (`act`), scope and audience narrowing | Optional grant |
| [`packages/webauthn`](packages/webauthn/) | `@o3co/auth-provider-webauthn` | Passkey registration and the passkey authentication grant | Optional; carries an exactly pinned WebAuthn library |
| [`packages/dpop`](packages/dpop/) | `@o3co/auth-provider-dpop` | DPoP (RFC 9449) sender-constrained tokens | A plug-in to core's token-binding slot, off unless installed and enabled |
| [`packages/mtls`](packages/mtls/) | `@o3co/auth-provider-mtls` | mTLS (RFC 8705) certificate-bound tokens, with X.509 path validation and revocation | As dpop; also carries the X.509 libraries and the revocation fetcher |
| [`packages/federation-google`](packages/federation-google/) | `@o3co/auth-provider-federation-google` | Sign-in with Google | One package per upstream identity provider: install only the ones you register |
| [`packages/federation-github`](packages/federation-github/) | `@o3co/auth-provider-federation-github` | Sign-in with GitHub | As above |
| [`packages/federation-apple`](packages/federation-apple/) | `@o3co/auth-provider-federation-apple` | Sign in with Apple — `form_post` callback, rotating ES256 client secret | As above |
| [`packages/federation-oidc`](packages/federation-oidc/) | `@o3co/auth-provider-federation-oidc` | Any OpenID Connect identity provider by issuer, one instance per issuer | As above |
| [`packages/federation-grants`](packages/federation-grants/) | `@o3co/auth-provider-federation-grants` | Federation grants (#593): a client obtains upstream access tokens on a user's standing consent, with no session behind the call | Optional; the delegation routes and their consent flow. Needs `federation-oidc`: the generic OpenID Connect adapter is the only one that can delegate |
| [`packages/redis`](packages/redis/) | `@o3co/auth-provider-redis` | Redis implementations of core's store ports, for a deployment with more than one replica | Keeps a database driver out of core. The standalone template needs it in every deployment (its refresh-token families live in Redis); only a composition root of your own, on one replica, can leave it out |
| [`packages/foundation`](packages/foundation/) | `@o3co/auth-provider-foundation` | The HTTP user repository — the client of your user service ("the Store") | A production adapter for an external service, kept out of core |
| [`templates/standalone`](templates/standalone/) | — | The deployable composition root: module choice, config, logger, shutdown, Docker | Per-deployment choices, copied rather than imported; never published |
| [`create-app`](create-app/) | `@o3co/create-auth-provider` | The `npx` scaffolder that copies the template into a new project | Published on its own with a `bin` |

## Endpoints

The main endpoints of a composition like the standalone template. Optional
packages add their own (device authorization, WebAuthn ceremonies, federation
grants); each package's README lists its routes.

| Endpoint | Package | Description |
| --- | --- | --- |
| `POST /oauth/token` | oauth | Token endpoint: every installed grant, dispatched by `grant_type` |
| `GET`, `POST /oauth/authorize` | oauth | Authorization code flow (PKCE) |
| `GET`, `POST /oauth/consent` | oauth | What the deployment's consent page asks about, and where it posts the answer. Mounted only when a consent store is wired (the template ships `CONSENT_STORE_ADAPTER=none`) |
| `POST /oauth/introspect` | oauth | Token introspection (RFC 7662) |
| `POST /oauth/revoke` | oauth | Token revocation (RFC 7009) |
| `GET`, `POST /oauth/userinfo` | oauth | OpenID Connect userinfo |
| `GET`, `POST /oauth/logout` | oauth | RP-initiated logout, with the back-channel logout cascade |
| `GET /.well-known/openid-configuration` | core | Discovery, served when `oauthModule` is installed |
| `GET /.well-known/jwks.json` | core | Verification keys (`oauth.jwt.jwksPath` moves it); under HS256 it answers `404 jwks_not_published` |
| `GET /session/csrf` | session | Issue a double-submit CSRF token |
| `POST /session/login` | session | Local authentication |
| `POST /session/logout` | session | End the browser session |
| `GET /session/oauth/federation/:name` | session | Start a federated login (its callback is `…/:name/callback`) |
| `GET /_healthcheck`, `GET /readyz` | core | Liveness and readiness routers, mounted by the composition root |

## Configuration

HOCON config file with environment variable overrides. The config schema depends on which modules are registered; `@o3co/auth-provider-core` ships the library defaults in its `reference.conf`, and a composition root layers its own files over them.

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
  # Seconds, positive, <= 1 year. `defaultExpiresIn` is what every grant
  # mints; `maxExpiresIn` (unset = the default) is the most a token-exchange
  # request's `expires_in` can obtain. `expiresIn` is a deprecated alias of
  # `defaultExpiresIn`, still read while that key is unset.
  accessToken  { defaultExpiresIn = 3600, maxExpiresIn = 3600 }
  refreshToken { expiresIn = 86400 }  # seconds, positive, <= 1 year
}
```

**Grants.** Every built-in grant is off in the library defaults; a deployment turns on the ones it serves:

```hocon
oauth.grants {
  authorization_code { enabled = true }   # PKCE is mandatory; S256 unless a client allows plain
  refresh_token      { enabled = true }
  session            { enabled = true }
}
```

**Session (when `sessionModule` is registered):**

```hocon
# `secret` signs the cookie that IS the authenticated session: at least
# 32 bytes (256 bits), e.g. `openssl rand -hex 32`.
session { secret = ${SESSION_SECRET} }

# One section per federation. `type` names the adapter package and defaults
# to the section's name; each adapter's README lists its settings.
federations {
  google {
    enabled = false
    # clientId, clientSecret, callbackURL — required when enabled = true
  }
  # okta { enabled = false, type = "oidc" }   # any OpenID Connect IdP, by issuer
}
```

See [`templates/standalone/config/application.conf`](templates/standalone/config/application.conf) for a complete example.

## Development

```bash
pnpm install
pnpm run build    # build all packages
pnpm run test     # test all packages (the Redis adapters' tests start Redis in Docker)
pnpm run lint
```

## Docker

```bash
npx @o3co/create-auth-provider my-auth-app
cd my-auth-app
docker build --target runtime -t my-auth .   # or: make build IMAGE=my-auth
```

`--target runtime` matters: the Dockerfile's last stage is the hot-reload
`develop` image that `make dev` runs. Running the production image — the
compose file for it, the key files as secrets, the settings it refuses to
start without — is in the template README's [Docker](templates/standalone/README.md#docker)
section and `docker-compose.production.yml`.

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
