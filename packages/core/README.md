# @o3co/auth-provider-core

Last updated: 2026-09-25

## Responsibility

`@o3co/auth-provider-core` is the package every other auth.provider package builds on: the module system and the boot planner (`createApp`), the grant-handler contract and the token helpers every grant mints with, the repository and store ports with in-process adapters for a single replica, the key store, and the configuration schema. It sits under every other package and imports none of them. That is why it is a package of its own: a contract several packages share lives here, because those packages do not all depend on one another — `session` and `oauth` are independent, and `oauth-token-exchange` and `webauthn` implement grants without depending on `oauth` — so core is the one place they all depend on.

It owns no grant type and no `/oauth/*` endpoint (`@o3co/auth-provider-oauth` and the grant packages): the only route core mounts itself is the discovery document, and its JWKS, health and readiness routers are installed by a composition root. It owns no durable adapter (`@o3co/auth-provider-redis`), no federation adapter (the `@o3co/auth-provider-federation-*` packages), no login or browser session (`@o3co/auth-provider-session`) and no Store client (`@o3co/auth-provider-foundation`). Which directory inside owns what, and why each is separate, is [src/README.md](src/README.md).

Vocabulary: **the Store** is auth.provider's term for the consumer's upstream user service — the system of record for identity, credentials, and email-verification state. Defined on the `User` doc in [`src/repositories/types.mts`](src/repositories/types.mts); auth.provider reads Store-published state and never writes it. Design-campaign identifiers cited in this package's sources resolve in [docs/design-campaign-index.md](../../docs/design-campaign-index.md).

## Install

```sh
npm install @o3co/auth-provider-core
# and, for createApp:
npm install express@^5.0.0
```

Optional peer dependency: `express@^5.0.0`, needed only for `createApp`. The
package depends on `bcrypt`, `jose`, `js-yaml` and `zod`.

## Public API

### Configuration

`AppConfigSchema` is a [Zod](https://zod.dev/) schema that validates the full application configuration. `AppConfig` is the inferred TypeScript type.

```typescript
import { AppConfigSchema, type AppConfig } from "@o3co/auth-provider-core";

const config: AppConfig = AppConfigSchema.parse(rawConfig);
```

The schema **strips keys it does not declare** — that is Zod's default for an object, and it is what makes the parse a validation rather than a passthrough. It matters here because this parse runs *before* `createApp`, which is where each installed module's own `configSchema` is composed and applied: a section this schema does not know about is gone by the time the module that reads it runs, and most module schemas supply a default, so what follows is not an error but a quietly different deployment.

So the schema declares every configuration section owned by a module in this repository — `oauth.mtls`, `oauth.dpop`, `oauth.deviceAuthorization`, `webauthn`, `memoryRateLimiter` / `redisRateLimiter` and the `redis*` store namespaces included — even though core itself reads none of them. Their bounds and defaults stay with the packages that own them (in each one's `reference.conf` and `configSchema`); the declaration here only keeps the values from being dropped in transit. `module-config-key-parity.test.mts` fails the build if a module declares a key this schema does not.

A module from **outside** this repository is not covered by that check. If one reads its own config section, extend the schema before parsing — `AppConfigSchema.extend({ mySection: … })` — or hand `createApp` the unparsed configuration and let the composed module schemas validate it.

Defaults live in [`config/reference.conf`](config/reference.conf), not in the schema. Top-level fields (the sections every deployment carries; module-owned sections are documented by the package that owns them):

| Field | Description |
| --- | --- |
| `http.port` | HTTP listen port |
| `http.trustProxy` | Express `trust proxy`: `false`, an address list (IPs, CIDR ranges, or the named ranges `loopback` / `linklocal` / `uniquelocal`), a hop count, or `true`. Entries are validated at boot. Prefer naming the proxy over `true`, which believes a forwarded client address from anyone who can reach the process |
| `oauth.jwt` | JWT signing config — `issuer`, `signingKey` (a `provider` plus its sub-section), `jwksPath`, `jwksCacheMaxAge` |
| `oauth.accessToken.defaultExpiresIn` | Access token lifetime, in seconds, that every grant mints when the request asks for none. Only token exchange lets a request ask (its `expires_in` parameter); every other grant ignores that parameter. Read the lifetime with `resolveAccessTokenLifetime(config)`, which throws a `RangeError` naming the key for a value the schema would refuse (`isLifetimeSeconds` is the rule, exported for a lifetime handed over as a number); every bundled grant reads it when it is built, so a hand-built configuration it refuses fails construction (and boot) rather than a request |
| `oauth.accessToken.maxExpiresIn` | The most a token-exchange `expires_in` can obtain; a larger request is clamped to it. Unset means the default, so nothing is extended unless you opt in. A default above it fails boot naming both keys |
| `oauth.accessToken.expiresIn` | **Deprecated** alias of `defaultExpiresIn`, read only while that key is unset (`reference.conf` keeps the shipped `3600` here). The parsed config also carries the resolved default under this name |
| `oauth.refreshToken.expiresIn` | Refresh token lifetime, in seconds: a whole number from 1 to a year. Read it with `resolveRefreshTokenLifetime(config)`, the key's one reader, which throws a `RangeError` naming the key for anything else, absence included. Every grant that mints a refresh token reads it when it is built, so a hand-built configuration it refuses fails construction and never spends a code or a challenge |
| `oauth.grants` | Per-grant-type config, keyed by grant type. The `oauth` package reads `enabled` for the grants it registers — `session`, `authorization_code`, `refresh_token`, `client_credentials` and the jwt-bearer URN — and registers each only when it is true. The other grant packages do not read this key: token exchange and WebAuthn register their grant whenever their module is installed, and the device grant registers its grant only when `oauth.deviceAuthorization.enabled` is true, decided by `deviceGrantModule({ config })` from the config it is handed |
| `session` | The browser session cookie and its store — `secret`, `name`, `maxAge`, `secure`, `sameSite`, `domain`, `redirectAllowlist`, `storage`, `csrf` |
| `session.csrf` | CSRF policy for the state-changing session routes — `trustedOrigins`, `ttlSeconds` |
| `rateLimit` | `login`: the `/session/login` budget (`windowMs`, `limit`) both bundled limiters seed from. `failMode`: what the OAuth-endpoint limiter does when its backend fails — `closed` answers `503`, `open` lets the request through and logs an error. The OAuth-endpoint limits themselves are the limiter module's (`memoryRateLimiter.*` / `redisRateLimiter.*`) |
| `federations` | Federation providers, keyed by name: `{ enabled, type?, … }`. Core reads `enabled` (the federation-stores wiring check at boot); `type` and the rest of the entry belong to the adapter package that reads it — the adapter packages are listed in the [root README](../../README.md) |
| `repositories` | Repository config for clients, users, and codes — each a `type` plus its sub-section |
| `endpoints` | `login.url`: the deployment's login page. `consent.url`: its consent page for clients that are not first-party (default `/consent`) |
| `cors.allowedOrigins` | Browser origins allowed to read the token, userinfo, revocation and discovery/JWKS responses — see [CORS](#cors). Empty (the default) means CORS is off. It grants no CSRF trust — use `session.csrf.trustedOrigins` |

### Grant System

The grant system is the extension point for OAuth 2.0 grant types. Each grant type is implemented as a `GrantHandler` and declared on a module via `contributes.grants`; the boot planner instantiates and registers handlers internally.

#### Interfaces and types

The definitions are in [`src/grants/types.mts`](src/grants/types.mts): `GrantHandler`, `GrantContext`, `SessionData`, `AuthenticatedClient`, `GrantHandlerResult`, `GrantDependencies`, `GrantFactory`. What a handler may trust (`authenticatedClient`, never `body.client_id`) and what it must not do is documented on the fields themselves; the directory's responsibility map is [`src/grants/README.md`](src/grants/README.md).

#### Grant registration

A module declares its grants in `contributes.grants`, keyed by grant type. Whether a grant is contributed at all is the module's decision: the `oauth` package's modules contribute each of their grants only when `oauth.grants.<name>.enabled` is true, while token exchange and WebAuthn contribute theirs whenever their module is installed, and `deviceGrantModule({ config })` contributes the device grant only when `oauth.deviceAuthorization.enabled` is true in the config it is handed. Boot runs each factory, registers the handler under its grant type — two modules contributing the same grant type refuse boot — and freezes the registry at stage 5, so a registration after boot throws. Consumer code never imports or builds the registry: `GrantRegistry` is internal and not exported from the package root.

A `GrantHandler.cleanup?()` is never called. `AppHandle.dispose()` runs each provided component's `lifecycle[K].cleanup` in reverse-topological order, then `Symbol.asyncDispose` on module-provided values that declared none, then the `LifecycleRegistrar` drain — and never touches the registry. A module that holds a resource on a handler's behalf releases it through its own `lifecycle[K].cleanup`; see [`src/grants/README.md`](src/grants/README.md).

#### Resource indicators (RFC 8707)

A grant that honours `resource` reads it with `extractResourceParam`, derives the audience it names with `deriveAudienceFromResources`, and refuses an issued `aud` that does not represent it with `unrepresentedResources` — [`src/grants/resourceIndicator.mts`](src/grants/resourceIndicator.mts). Each value is kept whole (a URI may contain a comma), the empty entries of a repeated parameter are dropped, and an all-empty parameter means none was requested. The oauth grants, `/authorize` and the WebAuthn grant all read it there, so a custom grant that does the same gives the same answer.

### Error text (RFC 6749)

RFC 6749 Appendix A.7 and A.8 limit `error` and `error_description` to `1*NQSCHAR`: printable ASCII without `"` and `\`. The rule is in [`src/errors/envelope.mts`](src/errors/envelope.mts):

- `errorEnvelope(error, description?, uri?)` builds the RFC 6749 §5.2 error body and applies the rule itself, so every writer that goes through it conforms whatever it was handed: core's token-binding middleware (a mechanism's `retryInstruction` or `unavailable` text, the kinds a dispatch conflict names), the protected-resource binding, the rate limiter (a limiter adapter's `reason`), the session routes and a contributed module's own routes. A description character outside the set is sent as `?`; a description that is not a string is dropped like an empty one. A malformed `error` code is sent as `server_error` and logged as `error_envelope_code_malformed` through `consoleLogger`: the code came from server-side code, and the envelope does not know the status its caller answers with. `error_uri` is sent only when it is an `http:` or `https:` URI — §5.2's human-readable web page — or a relative reference, parsed component by component against RFC 3986's grammar (no userinfo — `https://example.com@evil.example/` goes to evil.example — brackets only around an IP-literal host, no colon in a relative path's first segment, one fragment) and resolved by the WHATWG URL parser. Every character that grammar admits is in RFC 6749's `error_uri` set (Appendix A.9). Any other `error_uri` is dropped, not altered, and logged as `error_envelope_uri_malformed`.
- `sanitizeErrorText` replaces every character outside the set with `?`, and answers `undefined` for a value that is not a string, so the caller falls back to its own default. A writer that builds its body itself — a redirect's query, a literal `{ error, error_description }` — sends what it echoes through it.
- `auditErrorText` does the same and caps the text at 200 characters, for a log line or an audit event.
- `isWellFormedErrorCode` checks an `error` code before it goes out. A caller that builds a code from something it does not control and knows its answer is a refusal of the client's request falls back to a client-error code itself: the token-binding middleware answers a refusal whose `invalid_<kind>_proof` would be malformed as `invalid_request`, and `/oauth/token` and `/oauth/authorize` do the same for a grant policy's deny (below).

Text written in this repository's own words is held to the set where it is written by [`__tests__/errorText.drift.test.mts`](src/__tests__/errorText.drift.test.mts): quote a value with `'`, write "section" for the section sign, and use no em dash.

### Token Utilities

`generateToken(data, options)`, `generateTokenResponse(tokens, options?)` and `formatObject` are in [`src/grants/token.mts`](src/grants/token.mts), with `Token`, `TokenResponse` and `GenerateTokenOptions` beside them.

`generateToken` signs a JWT with the current signing key of `options.keyStore`; `alg` and `kid` are the key store's, `typ` is `options.tokenType`, `cnf` is emitted only when `options.confirmation` is given, and `jti` / `issuedAt` are minted unless the caller reserved them first (#449). `exp` is `iat + options.expiresIn`, so `expiresIn` must be a positive whole number of seconds: a fraction, `NaN`, `Infinity`, zero or less is a `RangeError` before anything is signed, and so is a lifetime that would put `exp` past `Number.MAX_SAFE_INTEGER` (the configuration schema refuses the same values for `oauth.accessToken.*` and `oauth.refreshToken.expiresIn`). `generateTokenResponse` formats an access token, an optional refresh token and an optional id_token into the OAuth 2.0 token endpoint response shape, with `token_type` `Bearer` unless `DPoP` is requested. `formatObject` strips `undefined` and `null` values from an object.

### Key Store

The `KeyStore` interface abstracts over symmetric (HS256) and asymmetric (RS256, ES256, EdDSA) signing keys, including key rotation. Rotation is shape-specific: asymmetric algorithms use `previousKeys` (kid + public key + expiry), and HS256 uses `previousSecrets` (kid + secret + expiry). `getVerificationKey(kid)` resolves the key by kid — the keystore returns the matching key directly, never trial-verifies across keys — and throws `UnknownKidError` for a kid it does not hold and `ExpiredKidError` for one whose `expiresAt` has passed, so a caller can tell a fabricated kid from a retired one. Anything else it throws — a remote key service that timed out — is the keystore failing to answer, not a finding about the token: `verifyJwt` reports it as `verification_key_unavailable`, never `kid_unknown`, and every route answers it `503 temporarily_unavailable` (see [Token verification](#token-verification)). `sign(options)` returns a compact JWT; the KeyStore self-injects the `alg` and `kid` protected header fields, so callers cannot override them. This contract lets remote-sign adapters (KMS/HSM) implement `sign()` without exposing private key material. `getSigningKidFallback()` is a cheap accessor returning the current signing kid for verifying legacy/malformed tokens that lack a `kid` header. Do not use it for rotation-safe lookup.

The definitions — `KeyStore`, `SignJwtOptions`, `JWTPayload`, `ManagedKey`, `KeyLike`, the two errors, `AsymmetricKeyStoreOptions`, `SymmetricPreviousSecret`, `createAsymmetricKeyStore` and `createSymmetricKeyStore` — are in [`src/keys/KeyStore.mts`](src/keys/KeyStore.mts).

#### Signing without holding the private key (KMS / HSM / Vault)

`createRemoteSigningKeyStore` is a `KeyStore` whose private key never enters this process. The whole seam is one method, `RemoteSigner.sign(kid, data)`, which answers the signature in JWS form (RFC 7515 §3.3), not the provider's native encoding. Its options carry public key material only, and `verifyOnConstruction` defaults to `true`; the definitions are in [`src/keys/remoteSigning.mts`](src/keys/remoteSigning.mts).

Everything else a `KeyStore` owes — building the protected header, base64url encoding, assembling the compact JWT, rotation bookkeeping, publishing JWKS — is done for you, so an integrator writes the provider call and nothing else.

**No vendor is bundled.** Wire AWS KMS, PKCS#11, or a Vault transit key by supplying `signer`; `core` stays free of any of their SDKs. There is no `remote` entry in the key-store factory for the same reason a `RemoteSigner` is a function: build the store in your composition root and supply it as the `keyStore` component.

**`ES256` returns DER from almost every provider, and JWS does not accept it.** AWS KMS, PKCS#11 and OpenSSL all return an ASN.1 `SEQUENCE`; JWS wants the raw `R || S` concatenation. `derToJoseEcdsaSignature(der)` converts it. Getting this wrong produces signatures that fail at the relying party while the signer reports success, which is why the store signs one token at construction and verifies it against the public key — a signer returning the wrong form fails boot with a message naming both likely causes. Pass `verifyOnConstruction: false` only where a provider call at boot is itself the problem.

**There is no `HS256` variant, deliberately.** A shared secret has no public half, so "the key never leaves the boundary" cannot be true of it — every verifier needs the same bytes the signer has. Offering it here would let a deployment believe it had moved key material out of reach when it had not.

```typescript
// Sketch: AWS KMS, ES256
const store = await createRemoteSigningKeyStore({
  algorithm: "ES256",
  kid: "v1",
  publicKeyPem: await fetchPublicKeyPem(),
  signer: {
    async sign(_kid, data) {
      const { Signature } = await kms.send(new SignCommand({
        KeyId: KMS_KEY_ID,
        Message: data,
        MessageType: "RAW",
        SigningAlgorithm: "ECDSA_SHA_256",
      }));
      return derToJoseEcdsaSignature(Signature!);  // KMS returns DER
    },
  },
});
```

`createKeyStoreFactory()` creates a new factory with no registered types. `registerBuiltinKeyStores(factory)` registers the built-in `"local"` provider, which dispatches to `createAsymmetricKeyStore` or `createSymmetricKeyStore` based on `algorithm`. Both are in [`src/keys/factory.mts`](src/keys/factory.mts). The factory follows the same `AdapterFactory<T>` contract as the `ClientRepository`, `UserRepository`, and `CodeRepository` factories.

#### Algorithm default and key requirements

`reference.conf` ships `algorithm = "EdDSA"` (`DEFAULT_SIGNING_ALGORITHM`). Asymmetric by default because HS256 leaves a relying party with two bad options: verify nothing (there is no public key to publish) or hold the shared secret — which also lets it **mint** tokens.

The `"local"` builder has **no fallbacks**:

- An absent `algorithm` is an error, not an implicit `HS256`.
- An asymmetric algorithm with no `privateKey`/`privateKeyPath` (or no public half) throws a message naming the exact config keys, the exact environment variables, and the `openssl genpkey -algorithm ed25519` command that produces them.
- `HS256` requires `secret` to carry at least `MIN_SECRET_ENTROPY_BYTES` (32) of key material, and so does every `previousSecrets[].secret`.

Entropy is measured on the **decoded** value, taking the smallest plausible reading (`measureSecretEntropyBytes`): a 64-character hex string is 32 bytes and passes; a 32-character hex string is 16 bytes and does not. The same floor applies to `session.secret`, enforced by `AppConfigSchema`. `assertSecretEntropy` / `describeWeakSecret` are exported so a composition root that accepts its own operator secrets can apply the identical check.

Note that the floor lives in the **builder and the schema** — the config boundaries. `createSymmetricKeyStore` is the low-level primitive and does not enforce it, so a composition root calling it directly owns the check.

#### HS256 key rotation

To rotate an HS256 signing key without a maintenance window:

1. Record the current `kid` and `secret` values.
2. Generate a new secret: `openssl rand -hex 32`.
3. Update `application.conf` to set the new `kid` + `secret` and move the old pair into `previousSecrets`:

   ```hocon
   oauth.jwt.signingKey.local {
     algorithm = "HS256"
     kid = "v1"           # new kid
     secret = "<new-secret>"
     previousSecrets = [{
       kid = "v0"          # old kid
       secret = "<old-secret>"
       expiresAt = "2026-06-05T00:00:00Z"  # access-token TTL + buffer
     }]
   }
   ```

4. Restart the server. Tokens signed by `v0` continue to verify (resolved by `kid` from the JWT header) until `expiresAt`.
5. After the overlap window passes (all `v0` tokens have expired), remove `v0` from `previousSecrets` and restart again.

Both the new `secret` and every `previousSecrets[].secret` must clear the 32-byte floor — a retired secret is still a live verification key for the whole overlap window, so it carries the same forgery risk the current one does.

The schema rejects mixing the asymmetric `previousKeys` shape with HS256, and the builder rejects the reverse (`previousSecrets` under RS256/ES256/EdDSA) — operators on an asymmetric algorithm use the `previousKeys` field instead.

### Token verification

`verifyJwt` ([`src/jwt/verify.mts`](src/jwt/verify.mts)) verifies the tokens this provider issued and throws a `JwtVerificationError` whose `reason` is either a finding about the token — a bad signature, a kid nobody holds (`kid_unknown`), a retired one (`kid_expired`), expiry, a revocation (`revoked`) — or an outage: `verification_key_unavailable` (the keystore could not answer) or `revocation_unavailable` (the jti denylist or the subject watermark could not be read). `isVerificationUnavailable(err)` tells the two apart, and `VERIFICATION_UNAVAILABLE_DESCRIPTION` names the dependency for the wire. Every surface in this repository answers an outage `503 temporarily_unavailable` and never with a verdict — not `401 invalid_token`, `400 invalid_grant`, `active: false` or a revocation's `200` — because each of those describes the token and sends the client to replace a credential that may be perfectly good. The token is refused either way.

`REVOCATION_RETENTION_ALLOWANCE_MS` is how long past a token's `exp` a record that revokes it must be kept: the verifier's clock tolerance, a replica allowance and a second of rounding. `/oauth/revoke` keeps a denylisted `jti` that much past `exp`, and a revoked refresh-token family is kept by the same rule ([Refresh-token families](#refresh-token-families-rfc-6819-5223-replay-detection)).

A JWT's `exp`, `iat` and `nbf` are NumericDates (RFC 7519 §2) only when finite and within the Date range: `isNumericDate` and `malformedNumericDateClaim` ([`src/jwt/numericDate.mts`](src/jwt/numericDate.mts)) state the rule, and the jwt-bearer registry verifier, `private_key_jwt` and DPoP refuse an assertion or proof that breaks it before computing any expiry from it. jose checks only that such a claim is a number, and JSON's `1e400` parses to Infinity. A fraction is allowed. An assertion whose `jti` is recorded for single use — a `private_key_jwt` client assertion, an ID-JAG — may also run at most `MAX_ASSERTION_LIFETIME_SECONDS` (an hour) past now, and have been issued at most that long ago ([`src/assertions/lifetime.mts`](src/assertions/lifetime.mts)): its replay record lives until `exp`, so an unbounded `exp` would be an unbounded record.

### Repositories

Repository interfaces define the data access contract. Built-in in-memory implementations are provided for development and testing.

#### Interfaces and types

The ports are [`src/repositories/ClientRepository.mts`](src/repositories/ClientRepository.mts) (`findById`, `authenticate`; `PublicClient` is `Client` without `clientSecret`), [`src/repositories/UserRepository.mts`](src/repositories/UserRepository.mts) (`authenticate`, `authenticateByToken`, and the optional federated-identity link and lookup methods) and [`src/repositories/CodeRepository.mts`](src/repositories/CodeRepository.mts) (`createCode`, `findByCode`, `consumeByCode` — the atomic single-use gate — and `removeByCode`). The records — `Client`, `User`, `CodeData`, `Code`, `TokenEndpointAuthMethod` — are in [`src/repositories/types.mts`](src/repositories/types.mts), where a field's semantics are documented once, on the field — except the three logout URI fields, which carry no doc there: `postLogoutRedirectUris` takes the registered-redirect-URI grammar of `allowedRedirectUris`, custom schemes included, while `backchannelLogoutUri` and `frontchannelLogoutUri` are http/https only; that note sits beside the schema in [`src/repositories/InMemoryClientRepository.mts`](src/repositories/InMemoryClientRepository.mts).

`createCode` requires `client_id` and `redirect_uri`, and `Client.tokenEndpointAuthMethod` is required. Every other `Code` field is a required key holding `undefined` where nothing was recorded, and `createCode` takes `CreateCodeInput`, in which only `expiresIn` may be left out (the repository's default then applies). `nonce` and `sid` carry the OIDC nonce and the session id from `/authorize` to `/token`; `grantedScope` / `grantedAudience` are the grant policy's decision at `/authorize`, which the `authorization_code` grant reads instead of evaluating the policy again. The directory's responsibility map is [`src/repositories/README.md`](src/repositories/README.md).

#### Built-in implementations

`InMemoryClientRepository` and `InMemoryUserRepository` take a `Map` of entries validated by `ClientEntrySchema` / `UserEntrySchema`; `InMemoryCodeRepository` takes an optional `defaultExpiresIn` and runs a GC timer that its `dispose()` clears. `loadYamlMap(filePath, schema)` ([`src/repositories/loadYamlMap.mts`](src/repositories/loadYamlMap.mts)) reads a YAML file whose top-level keys are record IDs and validates each entry against `schema`; pass the result to `InMemoryClientRepository` or `InMemoryUserRepository` — see [Loading clients and users from YAML](#loading-clients-and-users-from-yaml).

#### Adapter factory primitives

`createAdapterFactory<T>(kind, ctx?)`, `AdapterFactory<T>`, `AdapterBuilder<T>` (a function of the config section and a read-only `BuilderContext`, whose fields are all optional and only ever added to), `LifecycleRegistrar` and `AdapterFactoryError` are defined in [`src/adapters/AdapterFactory.mts`](src/adapters/AdapterFactory.mts). `createRepositoryFactories(ctx?)` in [`src/repositories/RepositoryFactory.mts`](src/repositories/RepositoryFactory.mts) returns the client, user and code factories.

Key contract properties:

- `create()` always returns `Promise<T>`, even for synchronous builders.
- `register()` throws if a `type` is registered twice (silent-override prevention); `replace()` is the explicit override and throws for a `type` that is not registered.
- `create()` throws `AdapterFactoryError` when `type` is not registered; the error carries a `reason` (`unknown`, `duplicate` or `unknown-replace`), the `kind`, the `type`, and the `registered` list.
- `BuilderContext` is shared by reference across builder invocations for a given factory. Treat it as read-only from builders.

`createRepositoryFactories` returns three factories pre-registered with the built-in `yaml`/`static` (client, user) and `memory` (code) types. Use `registerBuiltinAdapters` from `@o3co/auth-provider-foundation` to add the `http` user-authentication adapter, or register your own types to support other backends. For Redis-backed code/store adapters, see `@o3co/auth-provider-redis`.

### Module System

Modules extend the app with routes, grant handlers and DI-graph components. A module is a declarative manifest written with `defineModule({...})`: it declares `requires` / `optional` (typed `ProviderDeps` keys), `provides` components, and contributes to `ContributesMap` kinds such as `grants`, `routes` and `federations`. The boot planner injects the typed deps into every factory; a module never mutates shared state. The vocabulary is [`src/modules/manifest/`](src/modules/manifest/README.md), also published as the `@o3co/auth-provider-core/modules/manifest` subpath.

```typescript
const myModule = defineModule({
  name: "my-module",
  requires: ["config", "clientRepository"] as const,
  contributes: {
    routes: [
      (deps) => ({ id: "my-route", mountPath: "/my", handler: makeRouter(deps) }),
    ],
  },
});
```

### App Factory

`createApp(options): Promise<AppHandle>` is the boot planner in [`src/boot/`](src/boot/README.md). `CreateAppOptions` and `AppHandle` are defined in [`src/boot/types.mts`](src/boot/types.mts).

`createApp` validates the manifests, composes and parses the configuration, materialises the component graph, applies every contribution, freezes the world and mounts the routes. The returned `router` is ready to mount (`app.use(handle.router)`) or to serve through `handle.listen(port)`; `handle.dispose()` runs every cleanup in reverse-topological order and rejects with an `AggregateError` carrying every failure. There is no separate `init()` step.

What core mounts on its own, in this order: `corsMw` when `cors.allowedOrigins` is non-empty, the single `tokenBindingMw` composed from the contributed mechanisms when at least one was contributed, the protected-resource sender-constraint check (always, on every request but the token endpoint's POST), the `grantMiddleware` contributions ahead of grant dispatch, and the OIDC discovery route when an issuer is configured and a module declares `providerRoot`. Everything else — JWKS (`jwksModule`), liveness and readiness (`createHealthcheckRouter`, `createReadinessRouter`), the OAuth and session routes — is a module or a router the composition root installs.

`express` is an optional peer dependency, loaded lazily: `createApp` imports it (`await import("express")`) to build the router, and boot also requires it (`createRequire`) for the `express()` factory `handle.listen()` wraps the router in — and for the router, if the import failed.

## CORS

`cors.allowedOrigins` is consumed by `corsMw` (`src/middleware/cors.mts`), which `assembleApp` mounts **first** — ahead of every other middleware and every route contribution. An empty list (the default) mounts nothing: no CORS headers and no `Vary`.

### Surface

`browserFacingCorsRoutes(config)` is the table, and it is an **allowlist** — the opposite polarity to the sender-constraint mount beside it. That one guards a credential and must therefore cover routes core has never heard of; this one *grants* a cross-origin read, so a route core has never heard of is exactly the one that must not silently acquire it.

| Path | Methods |
|---|---|
| `/oauth/token` | `POST` |
| `/oauth/userinfo` | `GET`, `POST` |
| `/oauth/revoke` | `POST` |
| `/.well-known/openid-configuration` | `GET` |
| `/.well-known/oauth-authorization-server` | `GET` |
| `oauth.jwt.jwksPath` (default `/.well-known/jwks.json`) | `GET` |

The two discovery rows are the same document: OIDC Discovery 1.0 appends its suffix to the issuer, RFC 8414 inserts its well-known string between host and path, and `discoveryPathsFor` (`src/discovery/wellKnownPaths.mts`) forms both for the configured issuer — for `https://as.example/tenant-a` that is `/tenant-a/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server/tenant-a` — so the route, its advertisement and this table cannot drift.

`/oauth/introspect` is off the list because it is server-to-server and already refuses public clients; `/oauth/authorize` because it is a top-level navigation, not a `fetch`. The `/oauth/*` paths are coupled to the bundled `oauthModule`'s mountPath, like the `/oauth/token` mounts in `boot/assemble-app.mts` — a downstream that re-mounts the OAuth router elsewhere builds its own table and passes it to `corsMw`.

### Headers

- `Access-Control-Allow-Origin` carries the **matched entry, echoed exactly**. An arbitrary origin is never reflected and `*` is never emitted — not even for the unauthenticated documents, because one code path that can emit `*` is one code path away from emitting it on a response carrying a token.
- **No `Access-Control-Allow-Credentials`, ever.** A cross-origin SPA here is a public client using PKCE and holds no cookie of ours. Allowing credentials would reach the cookie-backed `session` grant, which exchanges an authenticated browser session for tokens — a much larger grant than "may read the response to a request it authenticated itself", and CORS delivers the two together.
- A preflight (`OPTIONS` carrying `Access-Control-Request-Method`) is answered `204` with the route's methods, `Access-Control-Allow-Headers: content-type, authorization, dpop`, and `Access-Control-Max-Age: 600`.
- `Access-Control-Expose-Headers: WWW-Authenticate, Retry-After` — both are diagnostics the caller cannot act on otherwise (an opaque `429` with nothing to back off by; a `401` that will not say which scheme it wanted).
- `Vary: Origin` on **every** response from these routes, including the ones with no CORS headers, so a shared cache cannot serve one origin's response to another.

### Origins

Entries are validated at boot by `checkSerializedOrigin` (`src/net/origin.mts`) and refused by index, because matching is exact string equality: a trailing slash, an explicit `:443`, an uppercase host, a path, or a wildcard is an allowlist that admits nobody with nothing anywhere to say so. `https` is required except for a loopback host, through the shared `isLoopbackHostname` home. `corsMw` re-applies the same check and warns on anything it drops, so a hand-built `AppConfig` that never passed the schema cannot install an entry the schema would have refused.

The list takes two spellings. The comma-separated string an environment variable carries (`CORS_ALLOWED_ORIGINS`) is split on commas, each entry trimmed and empty entries dropped, so an empty variable is no list. An array keeps its string entries, trimmed, and an empty one is refused by the check above; a non-string entry is dropped. `normalizeAllowedOrigins` in the same file reads both and is exported; the WebAuthn package reads `WEBAUTHN_ORIGIN` / `WEBAUTHN_TOP_ORIGIN` with it, so every origin list set from the environment is spelled alike.

## Usage Example

```typescript
import express from "express";
import {
  AppConfigSchema,
  createApp,
  createRepositoryFactories,
  createKeyStoreFactory,
  defineModule,
  registerBuiltinKeyStores,
} from "@o3co/auth-provider-core";

const config = AppConfigSchema.parse(rawConfig);

// Both repositories.* (uses 'type') and oauth.jwt.signingKey (uses 'provider') follow
// the same nested adapter sub-section pattern. flatten() normalises either selector
// to { type, ...subSectionFields } before forwarding to the factory:
const flatten = (
  section: ({ type: string } | { provider: string }) & Record<string, unknown>,
) => {
  const selector =
    (section as { type?: string; provider?: string }).type
    ?? (section as { provider?: string }).provider;
  if (typeof selector !== "string") {
    throw new TypeError("flatten: section requires 'type' or 'provider' string");
  }
  const sub = section[selector];
  const flattenedSub =
    typeof sub === "object" && sub !== null && !Array.isArray(sub)
      ? (sub as Record<string, unknown>)
      : {};
  return { type: selector, ...flattenedSub };
};

const keyStoreFactory = createKeyStoreFactory();
registerBuiltinKeyStores(keyStoreFactory);
const keyStore = await keyStoreFactory.create(flatten(config.oauth.jwt.signingKey));

const { clientFactory, userFactory, codeFactory } = createRepositoryFactories();

const clientRepository = await clientFactory.create(flatten(config.repositories.client));
const userRepository = await userFactory.create(flatten(config.repositories.user));
const codeRepository = await codeFactory.create(flatten(config.repositories.code));

const localComponentsModule = defineModule({
  name: "local-components",
  provides: {
    keyStore: () => keyStore,
    clientRepository: () => clientRepository,
    userRepository: () => userRepository,
    codeRepository: () => codeRepository,
  },
});

const handle = await createApp({
  modules: [
    localComponentsModule,
    // additional modules go here
  ],
  bootstrapComponents: { config, pathResolver: import.meta.resolve },
});

const server = express();
server.use(handle.router);
server.listen(config.http.port);
```

### Implementing a custom grant type

```typescript
import {
  defineModule,
  type GrantFactory,
  generateToken,
  generateTokenResponse,
} from "@o3co/auth-provider-core";

const myGrantFactory: GrantFactory = (deps) => ({
  async handle(ctx) {
    const token = await generateToken({}, {
      keyStore: deps.keyStore,
      subject: "user-id",
      tokenType: "at+jwt",
    });
    return {
      result: { status: 200, tokens: generateTokenResponse({ accessToken: token }) },
    };
  },
});

const myGrantModule = defineModule({
  name: "my-grant",
  requires: ["config", "keyStore"],
  contributes: {
    grants: { my_grant: myGrantFactory },
  },
});
```

Add `myGrantModule` to the `modules` array passed to `createApp`. A `GrantFactory` receives `GrantDependencies`, whose required slots are `config` and `keyStore`, so the module requires both. The boot planner registers the grant under `my_grant`, and `/oauth/token` dispatches to it through the `grantHandlerResolver` synthetic key.

### Loading clients and users from YAML

```typescript
import {
  loadYamlMap,
  ClientEntrySchema,
  UserEntrySchema,
  InMemoryClientRepository,
  InMemoryUserRepository,
} from "@o3co/auth-provider-core";

const clients = loadYamlMap("./clients.yaml", ClientEntrySchema);
const users = loadYamlMap("./users.yaml", UserEntrySchema);

const clientRepo = new InMemoryClientRepository(clients);
const userRepo = new InMemoryUserRepository(users);
```

### Extension points

Five optional extension points: a slot or contribution kind a composition root fills, or leaves empty.

#### MFA

- `MfaProvider`, with the optional `SupportsEnrollment` / `SupportsRevocation` capabilities, the guards `supportsEnrollment()` / `supportsRevocation()`, and the `MfaCoordinator` / `MfaTransactionStore` types — [`src/mfa/types.mts`](src/mfa/types.mts); the factory `createMfaProviderFactory()` — [`src/mfa/factory.mts`](src/mfa/factory.mts).
- `createMfaRouter(express, deps)` builds `POST /auth/mfa/verify { transaction_id, proof }`: it loads the pending transaction from the `MfaTransactionStore`, verifies the proof with the provider of the transaction's `providerKind`, and hands the resumed flow to the `onAuthorizeResume` / `onFederationResume` / `onLoginResume` callbacks you supply.
- Core provides the port and the router and nothing that uses them. No route in this repository consults MFA: `/oauth/authorize`, the session login and the federation callback never call `MfaCoordinator.listEnrolled` or start a transaction, nothing mounts `createMfaRouter`, and no product code reads the `mfaFactors` contributions boot collects. A composition root that wants MFA starts the transaction in its own login flow, mounts the router and supplies the callbacks.
- Boot refuses a composition that provides `mfaCoordinator` without both `mfaProviderFactory` and `mfaTransactionStore` (`mfa-partial-wiring`).
- No factor is bundled; `@o3co/auth-provider-webauthn` ships passkeys as a grant (`contributes.grants`), not as an `mfaFactors` contribution.

#### Audit

- `AuditSink.record(event)` fire-and-forget
- Factory: `createAuditSinkFactory()`, built-in `"console"` via `registerBuiltinAuditSinks()`
- Errors swallowed by core — audit failure never blocks auth flow
- An event carries an error it reports as `details.cause`, `auditedError(err)` ([`src/audit/auditedError.mts`](src/audit/auditedError.mts)): `{ name, code?, cause?: { name, code? } }` — the name and code `loggableError` reads, and one level of its cause, sanitised and capped, and never a message. A sink is a record other systems read, and a store's or an IdP's message is theirs: the arguments a Redis reply quotes, the input a JSON parse error quotes, an upstream's description. `rate_limit.unavailable`, `introspect.store_unavailable` and `federation.logout.idp_unreachable` carry it
- Each `details` key keeps one type in every event, because a sink that fixes a field's type on first sight (Elasticsearch dynamic mapping, a BigQuery schema, a Datadog facet) drops the events that disagree: `details.error` is a string wherever it appears (an OAuth code, a reason), and a code in `details.cause` is a string. [`AuditEventDetails`](src/audit/types.mts) types both keys, and [`auditEventInventory.drift.test.mts`](src/audit/__tests__/auditEventInventory.drift.test.mts) reads every emission for them

##### The details contract: `AuditEventDetails` and `AuditedError`

`AuditEvent.details` is [`AuditEventDetails`](src/audit/types.mts): an open record, with two keys typed so that no event can give them a second type:

| Key | Type | What it holds |
| --- | --- | --- |
| `details.error` | `string` | An OAuth error code or a refusal's reason — never an error object and never an error's message |
| `details.cause` | [`AuditedError`](src/audit/auditedError.mts) | The error the event reports: `{ name: string, code?: string, cause?: { name: string, code?: string } }` |

Every other key is open, and is still expected to keep one type across the events that carry it.

- **A custom emitter** (a module calling `emitAuditEvent`, or a sink wrapper that builds events):
  - puts an error it reports under `details.cause`, built with `auditedError(err)` and nothing else;
  - never writes an error object, its message or its stack anywhere in `details`;
  - writes `details.error` only as a string.

  An event written as an object literal is held to the two keys by the compiler. A `details` built first as a `Record<string, unknown>` is not, so an emitter that assembles one owns the rule itself.
- **A custom sink** (an `AuditSink` implementation, or a wrapper that relays events):
  - may rely on `details.error` being a string and `details.cause` an `AuditedError` wherever they appear;
  - if it transforms or redacts details, keeps those types: a `cause` it will not carry is replaced with an `AuditedError` (federation-grants' sanitised sink uses `{ name: "[redacted]" }`), never with a string or a message;
  - may drop a key, but should not change its type.

  Every name and code in an `AuditedError` is already held to printable ASCII without `"` and `\` and capped at 200 characters.

#### Rate limiter

- `RateLimiter.check(key, ctx)` atomic check + increment
- Factory: `createRateLimiterFactory()`; `registerBuiltinRateLimiters()` registers `"memory"` only. The `"redis"` backend is `@o3co/auth-provider-redis` (`redisRateLimiterBuilder`, or the declarative `redisRateLimiterModule`); `ratelimit/__tests__/factory.test.mts` asserts it is not registered here
- 429 + `Retry-After` emitted by core on denial; the decision's `reason` is the `error_description`, within RFC 6749's characters, and `Rate limit exceeded` when it is absent, empty or not a string

#### Refresh-token families (RFC 6819 §5.2.2.3 replay detection)

- The port is `RefreshTokenFamilyRotation` / `RefreshTokenFamilyRevocation` in [`src/refresh-token-family/types.mts`](src/refresh-token-family/types.mts)
- Every `rt+jwt` carries a `family_id` claim
- Provide the `refreshTokenFamilyRotation` / `refreshTokenFamilyRevocation` slots (`memoryRefreshTokenFamilyStoreModule`, or the Redis adapter) to enable replay detection and family revocation
- A revoked family is remembered until the last access token it could have minted stops being accepted: the revoking write — a revocation, or the replay that revokes the family — keeps the record until the later of the family's own expiry and now plus `oauth.accessToken.maxExpiresIn`, plus `REVOCATION_RETENTION_ALLOWANCE_MS` ([`src/refresh-token-family/retention.mts`](src/refresh-token-family/retention.mts)). A family whose record has already run out is recorded as revoked all the same. `createRefreshTokenFamilyRevocation` and `createRefreshTokenFamilyRotation` take that horizon as `accessTokenHorizonMs` (`resolveFamilyAccessTokenHorizonMs(config)`), and the default modules read it from `config`
- The memory store forgets every family on a restart, revoked ones included, so an access token of a family revoked before the restart passes the family check afterwards until it expires; it is single-replica and development only

#### GrantPolicyHook (scope / audience / token exchange policy)

- `GrantPolicyHook.evaluate(request, ctx)` returns allow (with optional narrowing) or deny
- A deny's `error` must be an RFC 6749 error code, `1*NQSCHAR`: non-empty printable ASCII without `"` and `\` (`isWellFormedErrorCode`, [`errors/envelope.mts`](src/errors/envelope.mts)). `/oauth/token` answers any other code `invalid_request`, and `/oauth/authorize` answers it `access_denied`, logging the policy's code sanitised
- `/oauth/authorize` evaluates once; `/oauth/token` re-uses `grantedScope` / `grantedAudience` persisted on the Code record (no re-evaluation for `authorization_code`)
- Other grants (refresh / client_credentials / token-exchange) evaluate at the token endpoint

All five are optional. The audit sink carries an absence policy (`AUDIT_SINK_ABSENCE_POLICY`): when nothing fills the slot, the config must declare it absent (`audit.sink.type = "none"`) or boot refuses. The other four are simply off when absent.

### Token-binding mechanisms

Sender-constrained token binding is a first-class extension surface. The `tokenBindingMechanisms` contribution slot lets a module ship a custom `TokenBindingMechanism` without forking core. See [ADR 2026-05-20-token-binding-first-class-abstraction.md](docs/adr/2026-05-20-token-binding-first-class-abstraction.md) for the design rationale.

#### Public types

- `TokenBinding` ([`src/grants/tokenBinding.mts`](src/grants/tokenBinding.mts)) — the cross-cutting binding shape: a `kind`, the `confirmation`, and the optional `responseHeaders` a mechanism asks the response to carry (`DPoP-Nonce`). `kind` is open so downstream mechanisms can extend additively.
- `Confirmation` ([`src/grants/confirmation.mts`](src/grants/confirmation.mts)) — the RFC 7800 `cnf` claim payload, a closed union of `jkt` and `x5t#S256`; adding a variant is a core semver-minor change.
- `TokenBindingMechanism` ([`src/middleware/tokenBinding.mts`](src/middleware/tokenBinding.mts)) — the verb-side abstraction: a `kind`, `intentExplicit` (`true` for header-driven mechanisms such as DPoP, `false` for ambient ones such as mTLS) and `extract(req)`.
- `TokenBindingRefusal` (same file) — what `extract` throws to refuse, read by duck type, and the mechanism's word on which of three answers it is. A verdict on the material is `400 <code>` at the token endpoint and `401 invalid_token` with a challenge at a protected resource. A `retryInstruction` (DPoP's `use_dpop_nonce`) is `400 <code>` at the token endpoint and `401` challenging with that code at a protected resource. An `unavailable` outage — the mechanism could not reach a verdict, such as a replay store that cannot be read — is `503 <code>` at both, with no challenge, because the credential is not at fault. The dispatchers never learn a mechanism's codes.
- `TokenBindingMechanismFactory<Deps>` ([`src/modules/manifest/contributes-map.mts`](src/modules/manifest/contributes-map.mts)) — the contribution-slot entry: it answers a mechanism, or `null` when the module is disabled by config (secure-default opt-in).

#### Built-in mechanism packages

- `@o3co/auth-provider-dpop` — RFC 9449 DPoP (explicit-intent).
- `@o3co/auth-provider-mtls` — RFC 8705 mTLS certificate-bound tokens (ambient).

Both packages contribute via `tokenBindingMechanisms`. Core's `assembleApp` collects all contributions, filters nulls, and composes ONE `tokenBindingMw` mounted on `/oauth/token`. It and the `grantMiddleware` contributions run for the token endpoint alone — a POST to `/oauth/token`, with or without a trailing slash, in any letter case — and not for another method or a longer path beneath it; inside them the request is what a `use` mount on `/oauth/token` shows (`req.path` `/`, `req.baseUrl` ending in `/oauth/token`). The sender-constraint check exempts exactly the same requests.

#### Dispatch policy

When multiple mechanisms are installed, `oauth.tokenBinding.dispatch-policy` (in core's bundled `CoreConfigSchema` — single source of truth) arbitrates:

- `intent-explicit` (default) — prefer explicit-intent mechanisms over ambient.
- `strict-mutual-exclusion` — reject `invalid_request` if more than one mechanism's `extract` returns a binding.

Env override: `OAUTH_TOKEN_BINDING_DISPATCH_POLICY`.

#### Grant-side allowlist

The grants in `@o3co/auth-provider-oauth` emit `cnf`-bound RTs only for mechanisms in an explicit allowlist (`bindingIsDpop || bindingIsMtls`). Adding a new mechanism to bound-RT issuance MUST land its refresh-time enforcement matrix in the same PR — see [`packages/oauth`](../oauth/) for the §9.2 matrix pattern.

### Session stores and federation tokens

Two groups of optional slots for federation and OIDC support, provided by a module (`memorySessionStoresModule`, `memoryFederationTokenStoreModule`) or by the Redis adapters:

- `userSessionStore` and its sid- and subject-keyed siblings: session metadata (auth_time, active RPs, family IDs, OIDC claims), the logout fan-out indexes, and subject-wide revocation — [`src/user-sessions/README.md`](src/user-sessions/README.md).
- `federationTokenStore`: `(sid, federationName)`-keyed upstream IdP tokens, deleted at logout. The Redis adapter encrypts `refresh_token` with AES-256-GCM; `allow-plaintext` is opt-in and emits a warning. A store must round-trip every field of `FederationTokens` — `expiresAt: null` included, and `undefined`, never `null`, for a field with nothing recorded. The port contract, field by field, is in [src/README.md](src/README.md#federation-tokens), and what a store implementer changes for the required keys is [docs/upgrading-required-record-keys.md](../../docs/upgrading-required-record-keys.md).

`@o3co/auth-provider-oauth` consumes both: logout and cascading revocation, id_token and `/userinfo`, and `POST /oauth/federation/:name/token`. When any `federations.<name>.enabled` is true, boot refuses a composition missing any of `userSessionStore`, `sessionRPRegistry`, `sessionFamilyIndex`, `sessionFederationIndex`, `federationTokenStore` and `refreshTokenFamilyRevocation` (`federation-stores-incomplete`).

- `SupportsLock` — optional capability on `FederationTokenStore` for per-`(sid, federationName)` advisory locks, which keep concurrent refreshes from stampeding the upstream. Both bundled stores implement it; detect it with the `supportsLock(store)` guard. The lock implementations behind them — core's `createInProcessLock` (`src/federation-tokens/lock/memory.mts`) and `@o3co/auth-provider-redis`'s `createRedisLock` — are internal and not exported; a custom store that needs locking exposes `SupportsLock` instead.
- `Client.allowedAzpForFederationToken` — opt-in flag on the `Client` record; absent means `false`. A client that consumes `POST /oauth/federation/:name/token` must set it to `true`.

### OIDC id_token and claim filter

Two low-level helpers used by the `authorization_code` grant and the `/oauth/userinfo` endpoint.

#### `generateIdToken`

`generateIdToken(opts)` is in [`src/grants/idToken.mts`](src/grants/idToken.mts), with its options, `GenerateIdTokenOptions`, beside it; `expiresIn` defaults to 3600 s.

Signs and returns an OIDC id_token JWT (OIDC Core §2). Claim composition:

- `iss`, `sub`, `aud`, `exp`, `iat`, `jti` — standard JWT claims
- `auth_time` — seconds since epoch, from `opts.authTime`
- `sid` — session identifier for back-channel logout
- `azp` — authorized party, included when provided
- `nonce` — reflected verbatim from the authorization request when provided
- `amr`, `acr` — when the session recorded them; an empty `amr` is omitted, not emitted as `[]`
- scope-filtered user claims via `filterClaimsByScope`

Header uses `typ: "JWT"` — the standard spelling, kept deliberately disjoint from RFC 9068's `at+jwt` so an id_token can never pass an access-token surface. An id_token carrying `id+jwt` is refused as an ordinary `typ` mismatch.

#### `filterClaimsByScope`

`filterClaimsByScope(claims, scopes)` ([`src/grants/claimFilter.mts`](src/grants/claimFilter.mts)) maps `UserSessionClaims` to the JWT-shaped claim subset that the granted scopes authorize. Strict whitelist — only the mappings in the table below are emitted; any other `UserSessionClaims` fields (e.g. provider-specific fields like `hd`) are never forwarded.

| Scope | Emitted claims |
| --- | --- |
| `openid` | *(no claims — governs id_token issuance; `sub` is added by `generateIdToken`)* |
| `profile` | `name`, `picture` |
| `email` | `email`, `email_verified` |
| `groups` | `groups` |

#### `/.well-known/openid-configuration`

OIDC Discovery 1.0 metadata endpoint. Synthesized and mounted by core when `config.oauth.jwt.issuer` is configured AND a module declares the provider surface (`oauthModule` sets `providerRoot: true` on its `discoveryMetadata` contribution). Core aggregates every module's `discoveryMetadata` slice into one document. `issuer` and `id_token_signing_alg_values_supported` are core's own, and a module may not set them; a document missing a field OIDC Discovery requires refuses boot (`discovery-document-invalid`). The slices the bundled modules contribute are below — `oauthModule`'s is defined in [`packages/oauth/src/module.mts`](../oauth/src/module.mts), `jwksModule` contributes `jwks_uri`:

- `issuer`, `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `introspection_endpoint`
- `jwks_uri` — always advertised (contributed by `jwksModule`); an issuer-configured composition MUST install `jwksModule` or boot fails fast with `DiscoveryDocumentError`. The route never publishes an empty key set: an HS256 deployment answers `404 jwks_not_published`, and an asymmetric keystore that yields no exportable public key answers `503 jwks_unavailable`, both with `Cache-Control: no-store`. The symmetric secret is never published either way. A `200` from this route always carries at least one key.
- `revocation_endpoint` — advertised when `POST /oauth/revoke` can revoke **anything at all**. Two arms, resolved the way the route resolves them: the refresh arm is a wired `refreshTokenFamilyRevocation`; the access arm is a wired `accessTokenDenylist` **and** `oauth.revocation.accessToken` not being `"unsupported"` (an explicit `"unsupported"` disables that path however the composition is wired). Either arm suffices: RFC 7009 §2.2.1 defines `unsupported_token_type` precisely so an AS may revoke one token type and not the other, so a refresh-only endpoint is a revocation endpoint, and withholding the URL would leave a client that wants to revoke a refresh token at logout unable to revoke anything. With **neither** arm the route still answers RFC 7009's mandatory `200` and revokes nothing, so advertising it would promise a revocation that does not happen. Which *token types* it revokes is still not derivable from discovery — RFC 7009 / RFC 8414 define no per-type metadata field, and the access-token answer surfaces at the endpoint itself as `unsupported_token_type`.
- `response_types_supported: ["code"]`
- `request_uri_parameter_supported: false` — OIDC Discovery reads an omitted field as `true`, and `/authorize` refuses `request_uri`
- `client_id_metadata_document_supported: true` — only when `oauth.clientIdMetadataDocuments.enabled` is true and a consent store is wired; see the [oauth package README](../oauth/README.md)
- `subject_types_supported: ["public"]`
- `id_token_signing_alg_values_supported` — derived from the configured `KeyStore.algorithm`
- `scopes_supported: ["openid", "profile", "email", "groups"]`
- `grant_types_supported` — read off the grant-handler registry `/oauth/token` dispatches against, so it lists exactly the grants this composition registered and nothing else. Emitted even when empty: RFC 8414 §2 reads an **omitted** `grant_types_supported` as `["authorization_code", "implicit"]`, which would advertise an `implicit` flow this AS does not implement.
- `token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"]`, plus `private_key_jwt` when a `replaySeenSet` is wired. A client registered with `jwks` / `jwksUri` presents a JWT it signed (RFC 7523 §2.2), verified under those keys, with `iss = sub = client_id`, `aud` the issuer or the token endpoint, `exp` at most an hour out and a single-use `jti` recorded in the `replaySeenSet`. **That store is the condition**: without it the verifier answers `500 server_error` rather than accepting an unchecked `jti`, so the method is advertised only where it can be honoured — the same "on and completable" rule as `revocation_endpoint` above. See the [oauth package README](../oauth/README.md#client-authentication-private_key_jwt-rfc-7523-22).
- `token_endpoint_auth_signing_alg_values_supported` — the assertion algorithms, asymmetric only (`RS*`, `PS*`, `ES*`, `EdDSA`); the same list is emitted for the introspection and revocation endpoints as `*_endpoint_auth_signing_alg_values_supported`. All three travel with the method: when no `replaySeenSet` is wired they are omitted along with it, because algorithms for a method that is not offered say nothing a client can act on.
- `introspection_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"]`, plus `private_key_jwt` on the same condition — no `none`: `/oauth/introspect` refuses public clients per RFC 7662 §2.1. Two things the metadata cannot say, and an operator needs: (a) RFC 6749 §2.3.1 requires the `client_id` and secret to be form-urlencoded **before** base64 for `client_secret_basic`, so a `client_id` holding reserved characters — a resource URI, whose `:` would otherwise read as the Basic field separator — must be percent-encoded (`https%3A%2F%2Fapi.example.com`); (b) an authenticated caller may introspect tokens whose `aud` is in that client's `allowedAudiences` ∪ `{client_id}`, which is what lets a resource server introspect the tokens issued for its resource URI under RFC 8707. Both are stated in full in the [oauth package README](../oauth/README.md#introspection-which-tokens-a-caller-may-ask-about).
- `revocation_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"]`, plus `private_key_jwt` on the same condition — alongside `revocation_endpoint`; `none` is present because RFC 7009 §2.1 lets a public client revoke its own tokens
- `acr_values_supported` — the keys of `oauth.authorize.acrValues`, when the table is non-empty: the Authentication Context Class References `/authorize` can satisfy from a session's recorded `amr`. Omitted when there is no table, and `acr_values` is then `unmet_authentication_requirements`.
- `code_challenge_methods_supported: ["S256"]` — `S256` only, and deliberately **not** derived from `oauth.grants.authorization_code.pkce.supportedMethods`. This array is server-wide metadata: every client that reads it concludes "I may use any of these". `plain` never satisfies that (`/authorize` refuses it outright for public clients per RFC 9700 §2.1.1), so it stays out — a per-client exception does not belong in a server-wide array in either direction.
- `dpop_signing_alg_values_supported` — contributed by `@o3co/auth-provider-dpop` when `oauth.dpop.enabled = true`, carrying that module's `alg-whitelist` verbatim (RFC 9449 §5.1)
- `tls_client_certificate_bound_access_tokens: true` — contributed by `@o3co/auth-provider-mtls` when `oauth.mtls.enabled = true` (RFC 8705 §3.3). Omitted otherwise, which the RFC already defines as `false`. Independent of `oauth.mtls.source`: both the TLS-layer and the trusted-proxy header path produce the same `cnf["x5t#S256"]` on the token, and this flag describes the token.
- `end_session_endpoint`, and `backchannel_logout_supported`, `backchannel_logout_session_supported`, `frontchannel_logout_supported`, `frontchannel_logout_session_supported` (all `true`) — when every store the logout cascade needs is wired: `userSessionStore`, `sessionRPRegistry`, `sessionFamilyIndex`, `sessionFederationIndex`, `federationTokenStore` and `refreshTokenFamilyRevocation`

### Logout helpers

Low-level helpers used by `POST /oauth/logout` in `@o3co/auth-provider-oauth`, in [`src/grants/logoutToken.mts`](src/grants/logoutToken.mts).

#### `generateLogoutToken`

`generateLogoutToken(opts)` takes `GenerateLogoutTokenOptions`, defined beside it; `includeSid` defaults to `true` and `expiresIn` to 300 s. It generates a signed `logout_token` JWT (OIDC Back-Channel Logout 1.0 §2.4). Header `typ: logout+jwt`. Claim composition: `iss`, `sub`, `aud`, `iat`, `exp`, `jti`, and `events` carrying `{ [BACKCHANNEL_LOGOUT_EVENT_URI]: {} }`. The `sid` claim is included by default; set `includeSid: false` for RPs registered with `backchannel_logout_session_required: false`. The `nonce` claim is never included (spec §2.4 requirement).

#### `BACKCHANNEL_LOGOUT_EVENT_URI`

The canonical event URI every `logout_token`'s `events` claim carries, `http://schemas.openid.net/event/backchannel-logout`. Exported so downstream code and tests can reference it without re-literalizing.

### Logger

The structural, pino-compatible logger in [`src/logging/Logger.mts`](src/logging/Logger.mts): `trace` / `debug` / `info` / `warn` / `error` / `fatal`, each accepting an object-first or a string-first call, plus `child(bindings)`. A pino instance satisfies it without an adapter, and `consoleLogger` is the default. It is also the optional `logger` component slot.

[`loggableError(err)`](src/logging/loggableError.mts) is what a call site hands the logger instead of an error that came out of a library or a store talking to another system. Every logger call that reports a caught error goes through it — in every workspace package's `src` and in the standalone template's — and [`src/__tests__/logErrorProjection.drift.test.mts`](src/__tests__/logErrorProjection.drift.test.mts) keeps it so: its `SOURCE_ROOTS` lists the trees it reads, and a package added to the workspace fails it until it is listed. A file that hands a caught error to a stricter projection of its own instead is named there, with the reason (federation-grants' last error handler, which logs a classification and a status and nothing of the error's text).

Why: an error built from a parsed upstream response carries whatever that response said — an OAuth library puts the token answer it refused on the cause chain, a JSON parser quotes the text it could not parse, a Redis reply echoes the command it refused, and ioredis puts that command's arguments (a token record, for a store write under `allow-plaintext`) on the error. What the projection does:

- **The projection is plain data, and the line is the projection.** It has no `message`: a serializer takes a value with a string `message` for an Error and rewrites it — pino's err serializer folds each `cause` into one message and stack, writes none of the cause's fields, and writes the name over `type`. pino's `err` and `errWithCause` serializers, like any that follow the same convention, hand anything else through untouched. So under pino's defaults, the standalone template's logger or `consoleLogger`, every field below reaches the line at every level, with no serializer to configure. Every level carries `name`; pino adds no `type` of its own.
- **`detail`** is the error's message — `detail` (RFC 7807's name for an occurrence's human-readable explanation) rather than `message`, for the reason above — with the two known quoting shapes removed: a `SyntaxError`'s message is dropped — V8's `JSON.parse` and body-parser quote the input — keeping only ` at position N` (at most ten digits) as `position`; and Redis's `, with args beginning with: …` is cut from every message, whichever client's class carries it. Other text a peer wrote into a message is kept: the projection cannot tell it from this process's own.
- **`error_description`** is the one peer-written string kept on purpose, because it tells a revoked grant from a broken client: its first line only (Azure AD's AADSTS line, not its Trace ID lines), when that line is within RFC 6749 §5.2's character set, cut at the start of the word that holds its first run of twenty or more token characters (`[A-Za-z0-9._~+/=-]`) and trimmed, so that no part of the token and no fragment of its word is left — legacy Spring's "Invalid refresh token: <the token>" keeps "Invalid refresh token:", Azure AD's AADSTS700016 keeps "AADSTS700016: Application with identifier", a redirect URI Azure AD or Okta names goes whole with its `https:` — and omitted when nothing is left.
- **`stack`** keeps the frames and never the header that carries the message: at most ten frames, 2048 characters, at every cause. It is kept only when the stack starts with the whole header its name, code and message give — `name: message`, Node's `name [code]: message`, and for an empty message also `name` or `name [code]` — ending its line; a message rewritten after the stack was formatted, or one that is not a string, leaves no stack.
- Also kept: `name`, a string or numeric `code`, an integer `status`, a string `type` (body-parser's `entity.too.large`), an `error` within §5.2's set, `response: { status, contentType }` for a `Response` on the cause or on `response` (a gateway's 503 page), and the Error causes the same way, three deep.
- **Closed-set fields** a store's or a client's error records, kept because their shape cannot hold free text: an own `reason` that is a code — lowercase words joined by `_` or `-`, at most 64 characters (a Store transport failure's `unreachable`, a challenge store's `expired-at-issue`) — and up to four own `<word>Status` fields holding an HTTP status, 100–599 (a Store refusal's `storeStatus`). A field of that kind records an upstream's answer beside the error's own `status`, which Express reads as this server's, so it is kept under its own name rather than any package's being named here.
- **An AggregateError's members** (any error's `errors` array), as `aggregateErrors`: of the first five (`LOGGED_AGGREGATE_MAX_ERRORS`), the Errors, each projected as a cause is and within the same three levels; `aggregateErrorsOmitted` counts the members not among them. `aggregateErrors` is the name pino writes a raw AggregateError's members under, so one query finds both. A `handle.dispose()` failure is logged with the name and code of every cleanup that failed.
- **The command a store's error answered**, by name alone: `command: { name }` from ioredis's `command: { name, args }`, when the name is a token of at most 32 letters, digits and `_`, or two joined by one `.` — which Redis command failed (`set`, `evalsha`, `hello`, a module's `JSON.SET`), never its arguments. It stays at ioredis's own path, so a query on `err.command.name` reads a raw and a projected line alike; a `command` that is a string (execa's shell line) is not kept.
- **A budget for one line**: at most sixteen projections (`LOGGED_MAX_PROJECTIONS`) — the error, its causes and its members together — taken nearest first, so the error's own cause and members come before any of theirs. Every cut shows, whether the budget or the depth limit made it: a member left out counts in `aggregateErrorsOmitted`, and a cause left out leaves `causeOmitted: true`. With every string capped, a line stays under about 64 KB.
- Never kept: a cause or a member that is not an Error (where openid-client puts the answer it refused), any other field (a command's `args`, `body`, `buffer`), and anything of a thrown non-Error but its `typeof`, as `thrown`.
- Every string is capped at 256 characters. It never throws. `consoleLogger` prints a projected error eight levels deep (`LOGGED_PRINT_DEPTH`); other objects print as before. The depth is past the deepest level a projection nests to, so its causes and members print whole rather than as `[Object]`. Each projection carries its own non-enumerable `util.inspect.custom` that does this, and `consoleLogger` hands the console its arguments unchanged. Any other object a caller logs, such as a request or a config, keeps Node's default two levels. JSON, pino and a spy never see the hook.

## See Also

- Root [README](../../README.md) — architecture overview, configuration reference, Docker setup
- [`@o3co/auth-provider-oauth`](../oauth/README.md) — OAuth 2.0 endpoints (authorization, token, introspection)
- [`@o3co/auth-provider-session`](../session/README.md) — session-based login flow
- [`@o3co/auth-provider-foundation`](../foundation/README.md) — the HTTP user-repository adapter (the Store client), registered as the `"http"` user adapter type
