# auth.provider

OAuth 2.0 provider — token issuance, introspection, and session authentication.

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

## Setup

```bash
pnpm install
pnpm run build
pnpm run start
```

## Development

```bash
pnpm run debug    # tsx watch mode
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
