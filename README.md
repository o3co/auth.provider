# auth.provider

OAuth 2.0 provider. Handles login, JWT access/refresh token issuance, and token introspection (RFC 7662). Supports PKCE (RFC 7636), DID authentication (Ed25519), and Google OAuth federation.

## Packages

| Package | Description |
| --- | --- |
| `packages/core` (`@o3co/auth-provider-core`) | Core library: OAuth 2.0 logic, token issuance, introspection, repositories |
| `templates/standalone` (`@o3co/auth-provider-standalone`) | Reference standalone application using the core library |
| `create-app` (`create-o3co-auth-provider`) | Project scaffolder |

## Endpoints

| Endpoint | Description |
| --- | --- |
| `POST /oauth/token` | Access token issuance (session / authorization / DID grant) |
| `GET /oauth/authorize` | Authorization code flow (PKCE) |
| `POST /oauth/introspect` | Token introspection (RFC 7662) |
| `POST /session/login` | Local authentication (Passport.js) |
| `POST /session/logout` | Session destruction |

## Features

- JWT (HS256) access/refresh token issuance
- PKCE (RFC 7636): `S256` / `plain`
- Session fixation protection: `session.regenerate()` on login
- Replay attack protection: authorization codes invalidated after use
- DID authentication grant (Ed25519)
- Google OAuth federation
- Rate limiting (login, token, authorize)
- HOCON configuration with Zod validation

## Using the Core Library

Install `@o3co/auth-provider-core` as a dependency in your own project:

```bash
npm install @o3co/auth-provider-core
```

The package provides OAuth 2.0 router factories, token services, repository interfaces, and middleware. Peer dependencies (`express`, `passport`, `passport-local`, `passport-oauth2-client-password`) must be installed separately.

## Scaffolding a New Project

To generate a new standalone application based on the `templates/standalone` template:

```bash
npx create-o3co-auth-provider my-auth-app
cd my-auth-app
pnpm install
pnpm run build
```

## Development

Build all packages:

```bash
pnpm -r run build
```

Run all tests:

```bash
pnpm -r run test
```

Watch mode for the standalone app:

```bash
pnpm -r --filter @o3co/auth-provider-standalone run debug
```

## Docker

```bash
make docker       # Build runtime image
```

## Related Projects

- [auth.proxy](https://github.com/o3co/auth.proxy) — Token validation reverse proxy
- [auth.policy-verifier](https://github.com/o3co/auth.policy-verifier) — No-DSL ABAC policy verifier
- [auth](https://github.com/o3co/auth) — Architecture docs and cross-component E2E tests
- [grpc.authz](https://github.com/o3co/grpc.authz) — gRPC authorization middleware

## License

Apache License 2.0
