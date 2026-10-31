# auth-provider

[![CI](https://github.com/o3co/auth.provider/actions/workflows/ci.yml/badge.svg?branch=develop)](https://github.com/o3co/auth.provider/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@o3co/create-auth-provider)](https://www.npmjs.com/package/@o3co/create-auth-provider)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

English | [日本語](README.ja.md)

auth-provider is a self-hosted OAuth 2.0 authorization server and OpenID Connect (OIDC) provider for Node.js, written in TypeScript. Generate an app with the features you need, then run it on Node.js or build its Docker image.

The generator adds the modules those features depend on. At startup the app checks its configuration and lists every problem it finds, naming the setting or the module.

To upgrade a 0.18 deployment to 0.19, check off the upgrade notices in [From 0.18 to 0.19](docs/migration.md#from-018-to-019): each says what to change and how to tell whether your deployment is affected. 0.18 rewrote 0.17 under new package names; to move an existing 0.17 deployment, read the [migration guide](docs/migration.md) first: there is no in-place upgrade, the configuration must be rewritten, and stored state is not migrated.

## What it does

The provider signs users in, manages their sessions and issues tokens to your applications. It manages the signing keys and gives you endpoints to check and revoke tokens.

| Feature | Specification | Module |
|---|---|---|
| Authorization code flow, with PKCE (S256) required for every client | RFC 6749, RFC 7636 | [authorize](modules/oauth/authorize/README.md), [code-grant](modules/oauth/code-grant/README.md) |
| Refresh tokens, rotated on every use, with reuse detection | RFC 6749 | [refresh](modules/oauth/refresh/README.md) |
| Client credentials grant | RFC 6749 | [client-credentials](modules/oauth/client-credentials/README.md) |
| ID tokens and UserInfo | OpenID Connect Core 1.0 | [oidc](modules/oauth/oidc/README.md), [userinfo](modules/oauth/userinfo/README.md) |
| Discovery documents and public signing keys (JWKS) | OpenID Connect Discovery 1.0, RFC 8414 | [discovery](modules/oauth/discovery/README.md), [keys](modules/foundation/keys/README.md) |
| RP-initiated (client-initiated), front-channel and back-channel logout | OpenID Connect logout specifications | [rp-logout](modules/oauth/rp-logout/README.md) |
| Token introspection and revocation | RFC 7662, RFC 7009 | [token-control](modules/oauth/token-control/README.md) |
| Client secrets and `private_key_jwt`; public clients without client authentication | RFC 6749, RFC 7523 | [clients](modules/identity/clients/README.md), [client-assertion](modules/oauth/client-assertion/README.md) |
| Client ID Metadata Documents (a URL as the client ID) | | [clients-cimd](modules/oauth/clients-cimd/README.md) |
| JWT bearer grant | RFC 7523 | [jwt-bearer](modules/oauth/jwt-bearer/README.md) |
| Device Authorization Grant | RFC 8628 | [device-grant](modules/oauth/device-grant/README.md) |
| Token Exchange | RFC 8693 | [token-exchange](modules/oauth/token-exchange/README.md) |
| Tokens bound to a client-held key (DPoP) | RFC 9449 | [dpop](modules/oauth/dpop/README.md) |
| Certificate-bound tokens (mTLS) | RFC 8705 | [mtls](modules/cert-binding/mtls/README.md) |
| Resource indicators | RFC 8707 | [resource-indicators](modules/oauth/resource-indicators/README.md) |
| Passkey login and registration | WebAuthn | [login-passkey](modules/passkey/login-passkey/README.md), [webauthn-login](modules/passkey/webauthn-login/README.md), [passkey-registration](modules/passkey/passkey-registration/README.md) |
| Second factors: authenticator apps (TOTP), email codes, recovery codes and security keys | RFC 6238, WebAuthn | [mfa](modules/second-factor/mfa/README.md) and the `mfa-*` modules |
| Sign-in through an upstream OpenID Connect provider, Google, GitHub or Apple | OpenID Connect; GitHub OAuth | [federation](modules/upstream-login/federation/README.md) and the `idp-*` modules |

Passkey login through `login-passkey` opens a browser session, as password login does ([Adding passkey login to the app](docs/login-page.md#adding-passkey-login-to-the-app)). `webauthn-login` also offers passkey login as a custom grant at the token endpoint, without opening a browser session. The mTLS module binds tokens to a certificate; clients still authenticate with another method.

Other modules cover consent, step-up authentication, keeping upstream tokens for your clients, and ending a user's sessions when your user store revokes them. The [owner map](modules/README.md) names the module responsible for each concern, and each module's card (its README) describes what it does.

### What you provide

- A login page, and a consent page if some clients need consent. The provider redirects the browser to your login page with a `redirect_to` parameter. Your page gets a CSRF token from `GET /session/csrf`, posts the username, password, token and `redirect_to` to `POST /session/login`, then sends the browser to the `redirect_to` it gets back. Serve the page from the provider's public origin (for example, behind the same reverse proxy): a login posted from another origin is refused. The [login page guide](docs/login-page.md) documents the login page's requests and responses, and the [consent page guide](docs/consent-page.md) those of the consent page. The contracts are in [login-password](modules/identity/login-password/README.md) and [csrf](modules/identity/csrf/README.md).
- User accounts, either listed in the configuration or in your own HTTP service that the provider calls, which the docs call a user ledger ([users-http](modules/user-ledger-http/users-http/README.md)). Sign-up and password recovery are not included.
- A reverse proxy that terminates TLS. The app itself serves plain HTTP.
- Authorization inside your services. Your services, or a separate policy engine, decide what a token allows; see [Related projects](#related-projects).

## Use case: incremental authentication modernization

Move a home-grown sign-in system to OAuth 2.0 and OpenID Connect a step at a time, without replacing it all at once: the provider runs beside what you have, and each step is one you can stop at.

| Step | What you do | What carries it |
|---|---|---|
| 1. Keep the user store | Leave users and passwords where they are: the provider asks your existing authentication API to check a password and to look a user up. That API answers the provider's calls, through a thin adapter where its shape differs. | [users-http](modules/user-ledger-http/users-http/README.md) |
| 2. Adopt OAuth and OIDC first | Your existing services keep running; move new and existing apps to the standard flows one at a time. Devices and backends that already hold keys your systems know can exchange a signed assertion for a token, their keys asked of your ledger, each `jti` used up where your other services see it; a device that names itself by its own key's thumbprint is taken too, as one of a trusted issuer's self-issued signers. | [Endpoints](#endpoints) and [discovery](modules/oauth/discovery/README.md); [jwt-bearer](modules/oauth/jwt-bearer/README.md) with [signer-keys-http](modules/user-ledger-http/signer-keys-http/README.md) and [jti-ledger-http](modules/user-ledger-http/jti-ledger-http/README.md) |
| 3. Strengthen sign-in as you need it | Add second factors, passkeys, sign-in through upstream identity providers (SSO), and the ending of a user's open sessions, with the tokens tied to them, when your user store revokes the user, each a module you add to the generated app. Some tokens are left until they expire, as the runbook's [Revoking a user from the ledger](docs/runbook.md#revoking-a-user-from-the-ledger) says. | [mfa](modules/second-factor/mfa/README.md), [passkeys](modules/passkey/passkeys/README.md), [federation](modules/upstream-login/federation/README.md), [subject-revocation-http](modules/user-ledger-http/subject-revocation-http/README.md); [Choose a pattern and add features](#choose-a-pattern-and-add-features) |
| 4. Improve the sign-in experience | Keep the accounts and change the pages: the login and consent pages are yours, against a documented contract, so you can redesign them or add a passkey button. | [Login page guide](docs/login-page.md), [consent page guide](docs/consent-page.md), [MFA page recipe](docs/recipe-mfa-page.md), [login-passkey](modules/passkey/login-passkey/README.md) |
| 5. Move to another IdP if you need to | Your apps speak only standard OAuth 2.0 and OpenID Connect to the provider, so moving them to another IdP, such as Keycloak, is reconfiguring each client. Meanwhile the provider can sign users in through such an IdP as an upstream. User IDs, sessions and tokens are not carried over: plan their move apart. | [Endpoints](#endpoints); [federation](modules/upstream-login/federation/README.md) with [idp-oidc](modules/upstream-login/idp-oidc/README.md) |
| 6. Or keep running it | Where it meets your requirements, keep the provider as your long-term authentication platform. | [Before production](#before-production), [runbook](docs/runbook.md), [security model](docs/security-model.md), [Versions and support](#versions-and-support) |

What it gives you: you keep your existing assets, and keep migration risk, up-front cost and downtime small while the platform evolves. Nothing assumes a move to a particular IdP, so the choice stays open.

## Requirements

- Node.js 24 or later.
- pnpm, at the version in the generated project's `packageManager` field. `corepack enable` installs that version for you; Node.js 25 and later ship without Corepack, so run `npm install -g corepack` first.
- Redis 7.0 or later, if you use the Redis adapter for persistent state or several instances. See [Before production](#before-production). The settings the server must have, such as an append-only file and no eviction, are in the runbook's [Redis section](docs/runbook.md#redis); the app checks them at startup.
- Docker, if you want to build and run the generated image.

Some patterns also need an HTTP user ledger, an audit collector, an SMTP relay or upstream identity providers. `simple-web` needs none of them.

## Quick start

Start with `simple-web`. It keeps users in the configuration and state in memory, and gives you password login for web apps (authorization code flow, OIDC, refresh tokens). For services that use client credentials, add `--add @mod/client-credentials`.

```sh
npx @o3co/create-auth-provider my-provider --pattern simple-web
cd my-provider
pnpm install
cp .env.example .env
cp config/local.conf.example config/local.conf
```

The generated `README.md` explains the pattern and its settings. In both example files every line is commented out, so copying them sets nothing. Uncomment the settings you need and replace the example values.

In `.env`, set:

- `ISSUER_URL` and `HTTP_PUBLIC_ORIGIN`: the URL clients see, with no trailing slash, and its scheme, host and port. The two must have the same origin.
  - The public origin must be https by default. To try the provider over plain http on your machine, set both to `http://127.0.0.1:8080`, with `HTTP_INSECURE_ORIGIN=true` and `KERNEL_ENVIRONMENT=development` in `.env`. Production is the default, and it refuses a plain-http origin or page; keep `production` for any deployment that others use.
- `KEYS_SIGNING_KID` and `KEYS_SIGNING_ALG`. The example uses RS256, for an RSA key, which every OpenID Connect client can check.
- `AUTHORIZE_LOGIN_PAGE`: the URL of your login page, on the provider's own origin, such as `http://127.0.0.1:8080/login` behind a proxy that serves the page and forwards the other requests to the app. The app does not serve this page. A page on another origin lets the app start, but every login from it is refused with `403 csrf`. A plain-http page on a loopback host, such as this example, requires `KERNEL_ENVIRONMENT=development`. `CONSENT_PAGE` is the URL of [your consent page](docs/consent-page.md); leave it unset if all your clients are first-party.
- `KERNEL_DEPLOYMENT=single`, `STORE_ACCEPT_VOLATILE=true` and `TOKENS_REVOCATION=denylist`. These settings state that the deployment runs one instance and keeps its state in memory, which is lost on restart. `TOKENS_REVOCATION=denylist` keeps revoked access tokens in a denylist and refuses them. `simple-web` issues codes and refresh tokens, which must be revocable, so boot refuses `unsupported` and says why.

Generate a signing key:

```sh
node -e 'const {generateKeyPairSync}=require("node:crypto");process.stdout.write(generateKeyPairSync("rsa",{modulusLength:2048}).privateKey.export({type:"pkcs8",format:"pem"}))' > signing.pem
```

Make a password hash for a test user. The provider accepts bcrypt or scrypt hashes, never plain passwords. This command reads the password from standard input, so it stays out of your shell history, and prints a scrypt hash. Type the password and press Enter, then Ctrl-D:

```sh
node -e 'const c=require("node:crypto"),s=c.randomBytes(16),p=require("node:fs").readFileSync(0,"utf8").replace(/\r?\n$/,""),k=c.scryptSync(p,s,32,{N:2**15,r:8,p:1,maxmem:2**26}),b=(x)=>x.toString("base64").replace(/=+$/,"");console.log(`$scrypt$ln=15,r=8,p=1$${b(s)}$${b(k)}`)'
```

Then write `config/local.conf`. It holds the key (leave `KEYS_SIGNING_PRIVATE_KEY` unset in `.env`), the audit receiver, your users and your clients. `users.registered` is not in the example file, so add it yourself:

```hocon
keys.signing.private-key = """
<paste the contents of signing.pem>
"""

audit.receivers = [log]

users.registered = [
  { identifier = "alice", password-hash = "<the hash printed above>" }
]

clients.registered = [
  {
    id = "my-web-app"
    kind = "public"
    method = "none"
    sections {
      authorize { redirect-uris = ["http://127.0.0.1:3000/callback"] }
      client-allowance {
        grants = ["authorization_code", "refresh_token"]
        scopes = ["openid", "profile"]
        default-scopes = ["openid"]
      }
      consent { first-party = true }
    }
  }
]
```

A client is allowed no grants and no scopes until you list them in `client-allowance`. A code-flow client also needs its `redirect-uris`, and `first-party = true` skips the consent page. A confidential client uses `kind = "confidential"`, a `method` such as `client_secret_basic`, and a hash of its secret in `sections.client-secret.hash`. The [configuration reference](docs/configuration.md#client-metadata-sections) lists every client section.

Start the app:

```sh
APP_CONFIG=config/local.conf,config/application.conf pnpm start
```

If a setting is missing or invalid, the app prints one `refused <setting or module>: <reason>` line for each problem on standard error and exits with status 78. Fix them and start again; fixing one round can bring the next round's refusals.

A trial set-up like this one logs warnings at every start, which are expected, not errors: `http.insecure_origin` (a plain-http public origin, so the session's cookie goes in the clear), `store.volatile_accepted` (state kept in memory, naming its spaces) and `consent.first_party` (each client registered as first-party, which skips consent). A deployment for others sets these the other way, and the warnings stop.

With the default port and the local issuer above, check that it is up:

```sh
curl http://127.0.0.1:8080/readyz
curl http://127.0.0.1:8080/.well-known/openid-configuration
```

If your issuer URL has a path, the discovery document is under that path.

A browser sign-in also needs your login page. To check a sign-in without a browser, walk the steps a login page and a client take: a CSRF token, the login, the authorization request with PKCE, and the code redeemed at the token endpoint. With the user and client above:

```sh
V=$(node -e 'console.log(require("crypto").randomBytes(32).toString("base64url"))')
C=$(node -e 'console.log(require("crypto").createHash("sha256").update(process.argv[1]).digest("base64url"))' "$V")
AUTH="http://127.0.0.1:8080/oauth/authorize?response_type=code&client_id=my-web-app&redirect_uri=http%3A%2F%2F127.0.0.1%3A3000%2Fcallback&scope=openid&state=xyz&code_challenge=$C&code_challenge_method=S256"
TOKEN=$(curl -s -c jar -b jar http://127.0.0.1:8080/session/csrf | node -pe 'JSON.parse(require("fs").readFileSync(0)).csrf_token')
curl -s -c jar -b jar -H "X-CSRF-Token: $TOKEN" --data-urlencode username=alice --data-urlencode password=your-password --data-urlencode "redirect_to=$AUTH" http://127.0.0.1:8080/session/login
curl -s -o /dev/null -w '%{redirect_url}\n' -b jar "$AUTH"
curl -s http://127.0.0.1:8080/oauth/token -d grant_type=authorization_code -d client_id=my-web-app --data-urlencode redirect_uri=http://127.0.0.1:3000/callback -d code=<code> -d code_verifier="$V"
```

The third request prints the redirect to `http://127.0.0.1:3000/callback` with the code; put it in place of `<code>` in the last one, which answers the tokens. The [login page guide](docs/login-page.md) gives each request and answer. A [recipe](docs/recipe-mfa-page.md) goes on to a second factor (TOTP), with every request and answer recorded from a running app.

## Choose a pattern and add features

A pattern is a ready-made selection of modules for one kind of deployment. Choose one with `--pattern`; the generated README lists what it needs. Each pattern has a short card in [modules/scaffold/create-app/src/patterns](modules/scaffold/create-app/src/patterns/README.md).

| Pattern | Use it for | Storage and outside services |
|---|---|---|
| `simple-web` | Password login for web apps (code flow with refresh tokens); client credentials for services with `--add @mod/client-credentials` | In-memory store, one instance; users in the configuration; audit to the log |
| `mfa-web` | `simple-web` with TOTP, email codes and recovery codes | Redis and SMTP |
| `device` | `simple-web` with the Device Authorization Grant, where users approve a code on another screen | In-memory store, one instance |
| `native-app` | Native apps and single-page apps as public clients, with PKCE, refresh tokens and DPoP | In-memory store, one instance |
| `a2a` | Service-to-service tokens with no users: client credentials or JWT bearer, `private_key_jwt`, mTLS and DPoP | In-memory store, one instance; a proxy that forwards client certificates for mTLS |
| `sso-federated` | Sign-in through upstream providers, with no local passwords | In-memory store, one instance; HTTP user ledger and upstream providers |
| `full` | Every feature except those you must opt in to (what 0.17 included by default) | Redis, HTTP user ledger, HTTP audit receiver and SMTP |

If you leave out `--pattern`, you get `full`. Use `simple-web` to start without outside services.

Add features with `--add`, using module names of the form `@mod/<name>`, where `<name>` is the last part of the module's directory, `modules/<group>/<name>`:

```sh
npx @o3co/create-auth-provider my-provider-dpop --pattern simple-web --add @mod/dpop
```

Repeat `--add` for each feature. To keep `simple-web`'s store in Redis, add `--axis @mod/store=@mod/redis`. You can also replace a pattern's login methods, grants or other feature groups. Axis and group options need a pattern other than `full`. Run `npx @o3co/create-auth-provider --help` for all options.

You can also list modules yourself instead of choosing a pattern. The generator then adds what they need to connect, and you write the configuration. See [app-output](modules/scaffold/app-output/README.md) for what each kind of project contains.

To change an existing app's selection, generate a new project into an empty directory and copy your configuration into it. The generator never overwrites a directory that has files in it.

## Configuration

Configuration uses HOCON, with one section per module, named after it: for example `issuer.url`, `keys.signing.alg` and `tokens.access-token-lifetime`. Unknown keys, sections for modules you have not loaded, and invalid values stop the app from starting. Error messages name the setting and never print its value. Times and sizes need a unit, such as `30s` or `5KiB`.

A project generated from a pattern reads two local files. Both are left out of git and out of the Docker build context, so keep your secrets there.

- `.env` supplies the environment variables that `config/application.conf` reads.
- `config/local.conf` holds lists, multi-line values and any other setting you write directly in HOCON.

A variable's name is the setting's path in upper case, with `.` and `-` replaced by `_`: `keys.signing.private-key` becomes `KEYS_SIGNING_PRIVATE_KEY`. A variable only affects a setting that `config/application.conf` reads from it; it is not a general override.

`APP_CONFIG` lists the configuration files, separated by commas. Earlier files win over later ones. Without it, the app reads `config/application.conf`.

Replace every example value before you start. A secret's placeholder starts with `REPLACE-` and is refused if you leave it in.

The [configuration reference](docs/configuration.md) lists every setting with its type, default and environment variable. Each module that takes settings also has a generated `reference.conf` in its directory, listing its defaults; it is for reading only.

## Run in Docker

Run `pnpm install` first so that `pnpm-lock.yaml` exists, then:

```sh
docker build -t auth-provider .
docker run --env-file .env \
  -e HTTP_HOST=0.0.0.0 \
  -e HTTP_PORT=8080 \
  -e APP_CONFIG=config/local.conf,config/application.conf \
  -v "$PWD/config/local.conf:/app/config/local.conf:ro" \
  -p 8080:8080 \
  auth-provider
```

Docker env files take one line per variable, so keep multi-line values such as PEM keys in `config/local.conf`.

The image uses Node 24, installs production dependencies only and runs as a non-root user. Its health check calls `/_healthcheck`.

## Before production

Replace the in-memory store with Redis, or with your own adapter that meets the store contract. The Redis adapter needs Redis 7.0 or later as a single primary; cluster mode is refused. The app checks the server's settings at startup. Read the [Redis requirements](docs/runbook.md#redis) for persistence, replication and managed services.

Read [what each shape of deployment is guaranteed](docs/deployment-guarantees.md), and what is left to it, before choosing one. Set `kernel.deployment` to `single` or `multi`. Which modules `multi` refuses at startup is [promise 5 of the security model](docs/security-model.md#promises-across-modules); read it before running several instances, above all for your own modules.

Put the app behind a TLS-terminating proxy and set `http.trusted-proxies`. The proxy must remove any forwarded or client-certificate headers that clients send before it sets its own. Read the [deployment requirements](docs/runbook.md#before-you-deploy) and the [security model](docs/security-model.md) before you expose the service.

## Endpoints

The [route reference](docs/routes.md) lists the methods, request bodies and policies of every route in the full template with all optional features. Your app serves only the routes of the modules it loads.

Common endpoints:

- `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server`: discovery, when the issuer has no path;
- `/.well-known/jwks.json`: the public signing keys;
- `/oauth/authorize` and `/oauth/token`.

Your deployment's discovery document lists the endpoints it serves.

## Operations

Use `GET /_healthcheck` for liveness and `GET /readyz` for readiness. Readiness returns 503 while a dependency such as Redis is down. Take that instance out of traffic until the dependency recovers; restarting it does not help.

When it is loaded, the Prometheus publisher serves `/metrics` (change the path with `metrics-prometheus.path`). Restrict access to it at your proxy. Logs are JSON lines on standard output; set the level with `kernel.logging.level`.

Choose audit receivers with `audit.receivers`. `log` is built in; `stdout` and `http` need their receiver modules (`audit-stdout`, `audit-http`). Delivery is best effort, so watch `auth_audit_events_lost_total`. The [audit event reference](docs/audit-events.md) lists every event and its attributes.

SIGTERM and SIGINT shut the app down gracefully within `kernel.stop-deadline` (`30s` by default). Give your orchestrator a longer grace period.

The [operations runbook](docs/runbook.md) covers deployment, rotating the signing and sealing keys, upgrades, revoking users and alerts.

## Write your own module

Find the contract you need in the [owner map](modules/README.md), then read that module's README.

Define your module with `defineModule` from `@o3co/auth-provider-foundation/kernel`, and add it to the module list that the generated `src/main.ts` passes to `assemble`. Its head declares `takes`, the handles its factories take from other modules (`[]` for none); boot refuses a module without it. The [recipe for a grant of your own](docs/recipe-external-grant.md) walks through one, as a package of its own, built against the published packages. To have the generator compose such a package, see [packages outside the release](docs/outside-modules.md). The [kernel README](modules/foundation/kernel/README.md) describes the module API. Each release's contracts, from 0.19, are on the [API site](https://o3co.github.io/auth.provider/), each by the name you import it by.

To replace an implementation, such as the store or the user ledger, implement its contract and run the contract tests published at its `testing` subpath, for example `@o3co/auth-provider-foundation/store/testing`.

For modules inside this repository, the [combinations README](modules/scaffold/combinations/README.md) explains how a module's manifest declares adapters and the modules that connect it to others.

**Assembling without the generator.** If you keep your own composition root instead of a generated project:

1. Install `@o3co/auth-provider-scaffold` and get the module names from `@o3co/auth-provider-scaffold/combinations`: `composed` for a selection, or `needed` for the modules you list. Both refuse a name they do not know.
2. Pass the names to `published`. For each, it gives the package to depend on and the path to import the module from (`<entry>/module`).
3. Add those packages to your `package.json` at the scaffold bundle's version (every bundle of a release shares it), with the one holding `@mod/kernel` (`published(["@mod/kernel"])`) for `assemble`.
4. If the names hold no log sink, add one, such as `@mod/log-stdout`; without one, log lines go nowhere.
5. Boot it. Where boot is refused for a setting only you can decide, such as `tokens.subject-check = none` when nothing checks subjects, set it in your configuration.

## Versions and support

The generator picks the packages your app needs. Published packages are named `@o3co/auth-provider-<concern>`, share one version and expose each module as a subpath. The [migration guide](docs/migration.md#packages) maps the 0.17 packages to their 0.18 replacements.

Before 1.0, a minor release may break compatibility, and so may a new release candidate. Read the migration guide and the [changelog](CHANGELOG.md) before you upgrade.

Security fixes are released for the versions [SECURITY.md](SECURITY.md) names as supported; a fix found in a release candidate lands in the next one. What each version keeps compatible, and how a change to it is announced, is in [the release policy](docs/releasing.md#what-a-version-promises). Report a vulnerability privately with **Report a vulnerability** on this repository's Security tab, as [SECURITY.md](SECURITY.md) describes. Please don't open a public issue.

## Contributing

Use Node.js 24 or later and the pnpm version in the repository's `package.json` (`corepack enable` installs it):

```sh
pnpm install
pnpm check
```

`pnpm check` runs type checking, lint, unit tests, the guard and the distribution check. `pnpm test:integration` runs the tests that need Docker.

Modules live under `modules/<group>/<name>`, and each module's README is its contract. Find the module responsible for your change in the [owner map](modules/README.md). The [guard](modules/tooling/guard/README.md) checks dependency direction, each package's public surface and module size.

Read [CONTRIBUTING.md](CONTRIBUTING.md) before you open a pull request, and target `develop`. Maintainers cut releases as [docs/releasing.md](docs/releasing.md) describes.

## Related projects

- [auth](https://github.com/o3co/auth): the umbrella repository, with the architecture and end-to-end tests across components.
- [auth.policy-verifier](https://github.com/o3co/auth.policy-verifier): the policy engine that makes authorization decisions.
- [auth.proxy](https://github.com/o3co/auth.proxy): an optional reverse proxy that validates tokens in front of services.
- [protobuf.interceptors](https://github.com/o3co/protobuf.interceptors): authorization inside gRPC and ConnectRPC services, using this provider's introspection and the policy verifier's decisions.

## License

[Apache License 2.0](LICENSE).

Copyright 2026 1o1 Co. Ltd. Licensed under the Apache License, Version 2.0.
