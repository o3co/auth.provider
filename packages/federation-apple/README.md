# @o3co/auth-provider-federation-apple

Last updated: 2026-10-03

Sign in with Apple federation provider for `auth.provider` — Apple's **web**
flow, in a browser, back to this server.

The package does the web flow only: `clientId` is the Services ID, and the App
ID — the `client_id` of an iOS app's native Sign in with Apple
(AuthenticationServices) — goes nowhere in this config, so a code from the
native flow is not exchanged here. App Store guidelines may require an app that
offers third-party login to offer an equivalent privacy-preserving login option
as well; this package is how a deployment of this stack offers Sign in with
Apple through the browser.

## Responsibility

**Role.** An adapter: it implements core's federation contract
([`core/src/federations`](../core/src/federations/README.md)) for Sign in with
Apple. It contributes the federation type `apple`: core hands it each enabled
`core.federations` entry of that type, and it builds one federation per entry,
registered for the session router with its redirect policy under the entry's
name.

**Owns:** Apple's endpoints and issuer (written into the adapter, not
discovered); the rotating ES256 client secret
([`src/client-secret.mts`](src/client-secret.mts)); the checks on the return
URL; how the id_token is verified; how Apple's claims become a profile —
`email_verified` and `is_private_email` normalised to booleans, the display
name read from the first authorization's POST body; and the schema of an
`apple` entry's own keys ([`src/entry.mts`](src/entry.mts)).

**Does not own:** the contract (core); the `core.federations` map, the keys
core owns on every entry (`enabled`, `type`, `trustUpstreamAmr`,
`callbackURL`) and the dispatch of an entry by its type (core's boot); the
routes, the `form_post` callback, the federation transaction and its cookie,
`state` / PKCE verifier / `nonce` generation, the redirect-allowlist rules and
claim precedence — all [`@o3co/auth-provider-session`](../session/README.md),
which drives every `form_post` federation the same way; who the user is (the
Store); the refresh and logout routes that call this adapter
([`@o3co/auth-provider-oauth`](../oauth/README.md)).

**Why a separate package.** Each adapter is its own package so that a deployment
installs only the IdPs it uses, and `openid-client` only with an adapter. Why Apple is not a `type = "oidc"` section of
[`@o3co/auth-provider-federation-oidc`](../federation-oidc/README.md) — five
things the generic adapter does not do:

1. Apple's scopes are `name` and `email`, without `openid`; the generic adapter
   refuses a scope list without `openid` at boot.
2. The client secret is an ES256 JWT this relying party signs and must rotate,
   sent as `client_secret_post`; the generic adapter authenticates with
   `client_secret_basic` or `private_key_jwt`.
3. Apple POSTs the callback, so the provider declares
   `responseMode: "form_post"`.
4. The display name arrives only in the first authorization's POST body (`user`),
   never in the id_token.
5. The return URL must be `https` and not loopback, which the provider checks at
   boot.

## Install

```sh
npm install @o3co/auth-provider-federation-apple @o3co/auth-provider-core @o3co/auth-provider-session
```

Peer dependencies: `@o3co/auth-provider-core` and
`@o3co/auth-provider-session`. The package depends on `jose`,
`openid-client` and `zod`.

## Usage

One module, `appleFederationTypeModule()`
([`src/type-module.mts`](src/type-module.mts)), handles every enabled
`core.federations` entry whose `type` is `apple`. It contributes
`federationTypes.apple`; core parses each such entry with the type's schema at
boot and calls the module's factories with the entry's name, its
`callbackURL` and its parsed keys, so the composition root fills no slot. The
module requires no dependency.

```ts
import { createApp } from "@o3co/auth-provider-core";
import { appleFederationTypeModule } from "@o3co/auth-provider-federation-apple";
import { sessionModule, sessionStoreModuleFor } from "@o3co/auth-provider-session";

const handle = await createApp({
  modules: [
    sessionStoreModuleFor(config), // the form_post transaction lives in this store
    sessionModule,
    appleFederationTypeModule(),
    // ... composition-root modules supplying userRepository and the session stores
  ],
  bootstrapComponents: { config, pathResolver },
});
```

`appleFederationTypeModule({ fetch })` sends every request to Apple of every
`apple` entry — the token and JWKS requests — through that fetch: a proxy, or a
test double. Without it the global `fetch` is used.

### Configuration

```hocon
core.federations {
  apple {
    enabled     = true
    type        = "apple"
    clientId    = "com.example.app.service"   # the Services ID
    callbackURL = "https://auth.example.com/session/oauth/federation/apple/callback"
    teamId      = "ABCDE12345"
    keyId       = "XYZW98765F"
    privateKey  = ${APPLE_PRIVATE_KEY}         # the .p8 file's contents
    clientUrl   = "https://app.example.com/"
  }
}
```

The entry's name is the federation's: the `:name` route segment
(`/session/oauth/federation/<name>`), the name its upstream tokens are stored
under, and the prefix of the identity handed to the Store (`<name>:<sub>`).
Two entries of type `apple` — two Services IDs — are two federations.

An entry is flat, and its schema is strict: the keys core owns (`enabled`,
`type`, `trustUpstreamAmr`, `callbackURL`) and the keys below, nothing else.
The schema is `appleEntrySchema` in [`src/entry.mts`](src/entry.mts). A key it
does not name — a typo, or a nested `apple { ... }` section — refuses boot with
`config-validation-failed`, naming `core.federations.<name>.<field>`; so does a
missing or malformed key. A key written `null` counts as absent. An absent key
means what the table says, read by the provider or the redirect policy; the
schema fills in no default.

| Field | Required | Meaning |
| --- | --- | --- |
| `clientId` | yes | The **Services ID** (see below), not the App ID. |
| `callbackURL` | yes | The return URL registered against the Services ID: `https`, and not loopback (below). A key core owns: boot requires it of every entry it dispatches, and the session routes read it from the same entry. |
| `clientSecret` | one of | A client secret produced elsewhere, as a string. |
| `teamId`, `keyId`, `privateKey` | one of, all three | The key material this package signs the client secret with ([below](#the-rotating-client-secret)). `privateKey` is the `.p8` file's PEM contents, not its path. |
| `clientUrl` | in practice | Where the browser lands after a login whose start carried no `redirect_to`. Without it such a login ends in `500 misconfiguration` after the session has been saved — so it is needed unless every start carries a `redirect_to` and `authCallbackUrl` is set. |
| `redirectAllowlist`, `authCallbackUrl`, `sessionDomain` | no | The `redirect_to` policy, as for every federation — see the [session package's redirect rules](../session/README.md#redirect-allowlists). A start that carries `redirect_to` needs both an allowlist entry for it and `authCallbackUrl`, or it is refused (`400`) or ends in `500 misconfiguration`. |
| `endSessionEndpoint` | no | An upstream logout endpoint ([Refresh and logout](#refresh-and-logout)). Apple publishes none. |
| `jwksUri` | no | Overrides Apple's JWKS URI, `https://appleid.apple.com/auth/keys`. For tests; a production entry leaves it absent. |

`fetch` is not an entry key: it is the type module's option (above), and an
`AppleProviderConfig` field for `createAppleProvider` and the deprecated slot.
Neither is a resolver for `clientSecret`, nor a `privateKey` read anew at every
token exchange: a configuration holds strings, read at boot. Those two are
code-only, through `createAppleProvider`.

### Deprecated: the fixed-name module

`appleFederationModule` and the `appleFederationConfig` slot it requires are
deprecated in favour of `appleFederationTypeModule()`. They still work: the
module contributes `federations.apple` and `federationRedirectPolicies.apple`
— single-tenant, `provider.name` fixed at `"apple"` — from an
[`AppleProviderConfig`](src/apple.mts) that a bridge module in the composition
root builds from the `core.federations.apple` entry and provides as
`appleFederationConfig`. The redirect policy is built from that same object,
so a redirect field the bridge leaves out is one the policy never sees. For
the same entry both paths build the same provider and the same redirect
policy. Composing the type module and `appleFederationModule` for the same
entry refuses boot (`duplicate-contribute`): one federation has one handler.

## What you need from Apple, and which one goes where

Apple's console has two identifiers that both look like a bundle ID, and
picking the wrong one produces `invalid_client` with no further explanation.

| Apple concept | Where it goes | Notes |
| --- | --- | --- |
| **App ID** (`com.example.app`) | nowhere in this config | Identifies the *app*. Enable "Sign in with Apple" on it; it is the parent of the Services ID, and it is the `client_id` for the **native iOS** flow only. |
| **Services ID** (`com.example.app.service`) | `clientId` | Identifies the *web* OAuth client. This is the `client_id` for every request this package makes. Register the return URL against it. |
| **Team ID** (`ABCDE12345`) | `teamId` | Top right of the developer portal. Becomes the client secret's `iss`. |
| **Key ID** (`XYZW98765F`) | `keyId` | Shown when you create a "Sign in with Apple" key. Becomes the client secret's header `kid`. |
| **`AuthKey_XYZW98765F.p8`** | `privateKey` | The EC P-256 private key, PKCS#8 PEM. **Downloadable exactly once** — if it is lost, revoke the key and create another. Pass the file's contents, not its path. |

The **return URL** registered against the Services ID must equal `callbackURL`
exactly, and Apple imposes two separate rules on it: the scheme must be
`https`, **and** the host must not be loopback. `https://localhost/cb`
satisfies the first and still fails, as do `https://127.0.0.1/cb`, the rest of
`127.0.0.0/8`, and `https://[::1]/cb` — so local development needs a tunnel or
a dev hostname holding a certificate. The provider checks both at
construction, through core's loopback predicate (`isLoopbackHostname`), rather
than letting the authorization endpoint answer the first login with an opaque
`invalid_request`. The value the flow actually sends is held to it as well: the
session module derives the `redirect_uri` from `core.federations.<name>.callbackURL`,
and a request whose derived URL is not the configured `callbackURL` is refused
before anything reaches Apple. Under the type module they are one value, the
entry's; under the deprecated module they are one value only if the bridge
copies it, and a composition where they drift fails at the first request
instead of validating one URL and sending another.

## The rotating client secret

Apple's `client_secret` is not a string you paste. It is an ES256 JWT the
relying party signs with the `.p8` key:

```text
header  { alg: "ES256", kid: <Key ID> }
payload { iss: <Team ID>, sub: <Services ID>, aud: "https://appleid.apple.com",
          iat: <now>, exp: <now + at most six months> }
```

Supply the key material (`teamId` + `keyId` + `privateKey`) and this package
builds the signer for you. It caches the JWT and re-signs only once the cached
one comes within 24 h of `exp`, so the signature is computed about twice a year
rather than on every login. The default lifetime is 180 days — deliberately
short of Apple's 15 777 000-second ceiling, so clock skew between this process
and Apple's cannot turn a boundary comparison into an outage.

Concurrent logins share one in-flight signature, and a failed signature leaves
the cache untouched. The key is imported once per distinct key material: when
`privateKey` reads differently from what the held key was imported from — a
repaired mount, or a leaked `.p8` revoked and replaced — the key is
re-imported and the cached secret dropped on the next request, without a
restart. A signature still in progress under the old key is neither handed to a
caller that arrives after the rotation nor kept once it completes. That works
through whatever you passed as `privateKey`, to `createAppleProvider` as much as
to `createAppleClientSecret`: the option is read at every token exchange, not
copied at construction. An entry's `privateKey` is the PEM the configuration
held at boot, so a key replaced under the type module takes effect on the next
restart. To pick one up without a restart, build the provider with
`createAppleProvider` and make `privateKey` a getter that re-reads the file —
`get privateKey() { return readFileSync(path, "utf8"); }` — which then runs on
every token exchange.

If you already produce the secret elsewhere, pass `clientSecret` instead — in
an entry a string; in code either a string or a resolver (`() => string | Promise<string>`), the
`FederationClientSecret` form, which this adapter resolves with core's
`resolveClientSecret` on every token request. Supply **one** of the two: both is ambiguous and neither is
unconfigured, and either fails at boot — for an entry, as a
`config-validation-failed` naming it, as does key material missing one of its
three keys.

```ts
import { readFileSync } from "node:fs";
import { createAppleClientSecret } from "@o3co/auth-provider-federation-apple";

const clientSecret = createAppleClientSecret({
  teamId: "ABCDE12345",
  clientId: "com.example.app.service",
  keyId: "XYZW98765F",
  privateKey: readFileSync("AuthKey_XYZW98765F.p8", "utf8"),
});
```

## `form_post`: Apple POSTs the callback

Whenever the requested `scope` includes `name` or `email` — which this
provider's always does — Apple does **not** redirect back with query
parameters. It POSTs an `application/x-www-form-urlencoded` body to the
callback, because the first-authorization `user` field does not fit a redirect
URL. The provider declares `responseMode: "form_post"`, and the session router
does the rest: `response_mode=form_post` on the authorization request,
`POST /session/oauth/federation/<name>/callback` (a GET there is
`405 method_not_allowed`), and the flow's `state`, PKCE verifier, nonce and
post-login redirect held in a federation transaction — a record in the session
store and a dedicated `HttpOnly; Secure; SameSite=None` cookie path-scoped to
the callback — instead of in the session. **The start leg does not modify the
application session cookie**, for the browser doing the Apple login or anyone
else; the callback, as for any login, regenerates the session with the cookie
attributes the deployment configured.

How the transaction is bound, spent and single-used is the session package's —
see [Response modes](../session/README.md#response-modes-query-and-form_post) —
and so is the one thing to settle before deploying:
**[every host on the auth host's registrable domain is inside the trust boundary](../session/README.md#every-host-on-the-auth-hosts-registrable-domain-is-inside-the-trust-boundary)**.
The transaction cookie is `__Secure-`, not `__Host-`, so any host under the same
registrable domain (any `*.example.com` for `auth.example.com`) can plant one
and log a victim's browser into the attacker's own Apple account. Run no
untrusted content on any of those hosts; `session-store.domain = null` protects the
session cookie, not this one.

An RFC 9207 `iss` in the posted body is compared with
`https://appleid.apple.com` before the code is spent, and another issuer's is
refused. None is required: Apple's discovery document does not advertise
`authorization_response_iss_parameter_supported`.

## Claims

Apple publishes no `userinfo_endpoint`, so the verified id_token (RS256, keys
at `https://appleid.apple.com/auth/keys`) is the only source of identity.
`nonce` is required, not optional: `buildAuthorizationUrl` and `exchangeCode`
both fail closed without one.

- **`email_verified` may arrive as the string `"true"`.** It is normalised to a
  boolean. This matters more than it looks: `Boolean("false")` is `true`, so a
  coercion would report an unverified address as verified. A claim that is
  neither a boolean nor `"true"` / `"false"` reads as absent, because absence is
  not `false`.
- **`is_private_email` marks a Hide My Email relay address**
  (`…@privaterelay.appleid.com`) and is surfaced as `isPrivateEmail` so a
  deployment can decide about it — it is namespaced under
  `claims.federated.<name>` (the entry's name; `apple` under the deprecated
  module), never promoted. Relay addresses forward mail and the
  user can disable them at any time; if reaching a real inbox matters, this is
  the value to act on. `isPrivateRelayEmail(email)` is exported for the same
  decision elsewhere. Apple's own marker wins; the relay domain is consulted
  only when Apple sends no marker.
- **The user's name arrives once**, in the POST body's `user` JSON field, on the
  first authorization only — never in the id_token, and never again on a later
  login. It is mapped to the same `name` claim the other adapters produce, so
  the session package's promotion rules apply unchanged: `email` and `name` fill
  a gap the local record left, and everything else stays under
  `claims.federated.<name>` (see `PROMOTABLE_FEDERATED_CLAIMS`). Persist it on
  first login if you want to keep it.
- **The `user` body is not signed.** The `state` check binds it to the session
  and binds nothing else, so treat the name as self-asserted — which is exactly
  what claim precedence already assumes of every federated claim.
- **Each name part is capped** at 128 UTF-16 code units (`APPLE_NAME_PART_MAX_LENGTH`):
  a longer `firstName` or `lastName` is dropped whole, not truncated, so the
  unsigned body cannot push tens of kilobytes into the claims envelope and the
  session store. A malformed `user` body yields no name rather than a failed
  login.
- **No `picture`.** Apple asserts none.

What `exchangeCode` returns:

| Field | Value |
| --- | --- |
| `issuer` | `https://appleid.apple.com` |
| `sub` | the id_token's `sub` — Apple's stable, team-scoped identifier |
| `email` | the id_token's `email`, when a string |
| `emailVerified` | normalised as above |
| `name` | from the POST body's `user`, first authorization only |
| `isPrivateEmail` | normalised as above; absent when neither the marker nor an address says |
| `accessToken`, `idToken`, `refreshToken` | as Apple issued them; `idToken` and `refreshToken` only when non-empty strings |
| `scope` | Apple's `scope` as sent; absent when Apple sent none (the session router then records the requested scope). A `scope` that is not a string is refused by `openid-client` before the adapter sees it, and the login answers `502 exchange_failed` |
| `expiresAt` | when `openid-client` handed the answer over (after it verified the id_token, a JWKS fetch included) + `expiresIn`; **`null` when Apple sent no `expires_in`** (Apple documents it on every token response), which `oauth`'s `POST /oauth/federation/:name/token` reads as "do not refresh; reuse the stored token" |
| `expiresIn` | `expires_in` as `openid-client` read it — it applies `parseFloat`, so `"1000seconds"` is 1000 — or `null` when Apple sent none |
| `tokenType` | `token_type` as `openid-client` reports it (lower-cased `bearer`), recorded by the session router verbatim |

`mapClaims` maps `email`, `emailVerified`, `name` and `isPrivateEmail`.

## Refresh and logout

- **`refreshToken()`** (`SupportsRefresh`) runs the `refresh_token` grant with a
  freshly resolved client secret and returns the token fields of the table
  above by the same rules — `accessToken`, `refreshToken` when rotated,
  `idToken`, `scope`, `expiresAt`, `expiresIn` and `tokenType` (a non-string
  `scope` fails the refresh). It returns no `issuer` or `sub` — the caller
  keeps the stored identity.
- **`endSession()`** (`SupportsLogout`): Apple publishes no
  `end_session_endpoint`, and unlike Google there is no Apple logout URL to fall
  back to. With `endSessionEndpoint` configured, that URL with `id_token_hint`,
  `post_logout_redirect_uri` and `state`; otherwise `postLogoutRedirectUri`
  with `state`; otherwise it throws rather than inventing a destination. Local
  session destruction is unaffected. An unparsable URL throws too; the message
  names the field and quotes no value it was handed.
  Redirecting straight to `postLogoutRedirectUri` is safe because the caller
  hands only a URI it has matched against the client's registered
  `postLogoutRedirectUris`, or none — core's `EndSessionRequest` states the
  rule, and `oauth`'s logout routes keep it. A composition that calls
  `endSession()` itself must do the same.

## Public API

Exported from [`src/index.mts`](src/index.mts), each from the file linked:

- `appleFederationTypeModule` ([`src/type-module.mts`](src/type-module.mts)) —
  the Module contributing `federationTypes.apple`, with its options
  `AppleFederationTypeModuleOptions`, and `APPLE_FEDERATION_TYPE` (`"apple"`).
- `createAppleProvider(config)` ([`src/apple.mts`](src/apple.mts)) — the
  provider for the federation `apple`.
- `createAppleClientSecret(options)`
  ([`src/client-secret.mts`](src/client-secret.mts)) — the ES256 signer, a
  resolver for `clientSecret`.
- `isPrivateRelayEmail(email)` ([`src/apple.mts`](src/apple.mts)).
- Constants: `APPLE_ISSUER`, `APPLE_AUDIENCE`, `APPLE_PRIVATE_RELAY_DOMAIN`,
  `APPLE_NAME_PART_MAX_LENGTH`, `APPLE_CLIENT_SECRET_MAX_LIFETIME_SECONDS`,
  `APPLE_CLIENT_SECRET_DEFAULT_LIFETIME_SECONDS`,
  `APPLE_CLIENT_SECRET_RENEWAL_WINDOW_SECONDS`.
- Types: `AppleEntry` ([`src/entry.mts`](src/entry.mts)), an entry's own keys
  as the schema answers them; `AppleProviderConfig`, `AppleProvider`,
  `AppleClientSecretOptions`.
- Deprecated, for `appleFederationTypeModule`: `appleFederationModule`
  ([`src/apple.mts`](src/apple.mts)), and the `appleFederationConfig`
  `ComponentMap` slot it requires, declared there by module augmentation (not
  an export).

## Tests

| Test file | Pins |
| --- | --- |
| [`apple.test.mts`](src/__tests__/apple.test.mts) | construction and its boot refusals, the return-URL rules, the authorization request, the exchange and the profile, refresh, `mapClaims`, `endSession` and `isPrivateRelayEmail` |
| [`client-secret.test.mts`](src/__tests__/client-secret.test.mts) | the JWT Apple documents, and its caching and rotation |
| [`apple.signature.test.mts`](src/__tests__/apple.signature.test.mts) | that the id_token's signature is verified against the JWKS |
| [`apple.token-snapshot.test.mts`](src/__tests__/apple.token-snapshot.test.mts) | the lifetime, `expiresIn` and `tokenType` a login and a refresh report, with and without `expires_in`, and that a non-string `scope` is refused by the library |
| [`apple.issuer-parameter.test.mts`](src/__tests__/apple.issuer-parameter.test.mts) | the RFC 9207 `iss` check |
| [`claim-precedence.test.mts`](src/__tests__/claim-precedence.test.mts) | Apple's claims under the session package's precedence rules |
| [`apple-type-module.test.mts`](src/__tests__/apple-type-module.test.mts) | the type module through `createApp`: one provider and policy per entry, a login through the session routes, the strict, flat schema, the `fetch` option, refusals that quote no credential, parity with the deprecated module, and the refusal of both for one entry |
| [`apple-module.test.mts`](src/__tests__/apple-module.test.mts), [`apple-module-boot.test.mts`](src/__tests__/apple-module-boot.test.mts) | the deprecated module's contributions and boot |
