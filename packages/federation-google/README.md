# @o3co/auth-provider-federation-google

Last updated: 2026-09-24

Google federation provider for `auth.provider`: sign-in with a Google account
through Google's OpenID Connect endpoints, with token refresh, upstream logout
and claim mapping.

## Responsibility

**Role.** An adapter: it implements core's federation contract
([`core/src/federations`](../core/src/federations/README.md)) for Google, and
`googleFederationModule` contributes it to the session router as the federation
`google`, with its redirect policy.

**Owns:** Google's endpoints and issuer (written into the adapter, not
discovered), how the id_token and UserInfo are verified, which parameters the
authorization request carries, and what a Google login profile, a refresh and a
logout URL contain.

**Does not own:** the contract (core); the routes, `state` / PKCE verifier /
`nonce` generation, the redirect-allowlist rules and claim precedence
([`@o3co/auth-provider-session`](../session/README.md)); who the user is (the
Store); the refresh and logout routes that call this adapter
([`@o3co/auth-provider-oauth`](../oauth/README.md)).

**Why a separate package.** Each adapter is its own package so that a deployment
installs only the IdPs it uses, and `openid-client` only with one of them. Why
Google is not a `type = "oidc"` section of
[`@o3co/auth-provider-federation-oidc`](../federation-oidc/README.md): this
adapter does four things the generic one does not — it sends
`access_type=offline` at login, the parameter Google requires before it issues
a refresh token; it carries Google's `hd` (Workspace domain) claim through to
the profile and `mapClaims`; it requires the RFC 9207 `iss` without fetching
Google's discovery document; and without an `endSessionEndpoint` it still
offers logout, redirecting to `postLogoutRedirectUri` or to Google's own logout
URL, where the generic adapter offers logout only when an end-session endpoint
is discovered or configured. The generic adapter already verifies what this one
verifies.

## Install

```sh
npm install @o3co/auth-provider-federation-google
```

Peer dependencies: `@o3co/auth-provider-core` and
`@o3co/auth-provider-session`. `openid-client` is installed with it.

## Usage

Add `googleFederationModule` to the manifest list passed to `createApp`. A small
config-bootstrap module supplies the typed `googleFederationConfig` slot:

```ts
import { createApp, defineModule } from "@o3co/auth-provider-core";
import {
  extractFederationSection,
  sessionModule,
  sessionStoreModuleFor,
} from "@o3co/auth-provider-session";
import {
  googleFederationModule,
  type GoogleProviderConfig,
} from "@o3co/auth-provider-federation-google";

const googleConfigBridgeModule = defineModule({
  name: "google-federation-config",
  requires: ["config"] as const,
  provides: {
    googleFederationConfig: (deps): GoogleProviderConfig => {
      const slice = extractFederationSection(deps.config.federations, "google");
      if (slice?.type !== "google") throw new Error("federations.google must be enabled, with type google");
      return {
        clientId: slice.clientId as string,
        clientSecret: slice.clientSecret as string,
        callbackURL: slice.callbackURL as string,
        // The redirect policy is built from this same object: a redirect
        // field left out here is one the policy never sees.
        redirectAllowlist: slice.redirectAllowlist as readonly string[] | undefined,
        sessionDomain: slice.sessionDomain as string | undefined,
        authCallbackUrl: slice.authCallbackUrl as string | undefined,
        clientUrl: slice.clientUrl as string | undefined,
      };
    },
  },
});

const handle = await createApp({
  modules: [
    sessionStoreModuleFor(config),
    sessionModule,
    googleFederationModule,
    googleConfigBridgeModule,
    // ... composition-root modules supplying userRepository and the session stores
  ],
  bootstrapComponents: { config, pathResolver },
});
```

Single-tenant: `provider.name` is fixed at `"google"`, so the federation is
`federations.google` and a deployment has one Google client. The config fields
are [`GoogleProviderConfig`](src/google.mts). The four redirect fields
(`redirectAllowlist`, `sessionDomain`, `authCallbackUrl`, `clientUrl`) follow the
[session package's redirect rules](../session/README.md#redirect-allowlists),
and they reach the redirect policy only through this slot. **Set `clientUrl`:**
a login whose start carried no `redirect_to` lands there, and without it the
callback answers `500 misconfiguration` after the session has been saved; a
start that carries `redirect_to` needs an allowlist entry for it and
`authCallbackUrl` as well. A bridge that forwards the credentials alone
therefore ends every such login on a `500` instead of in the app. The bridge above does not forward the other
optional fields (`endSessionEndpoint`, `requireAuthorizationResponseIss`); forward them if the deployment sets them. It
reads the section only when its `type` is `google` (the default for a section
named `google`), as the standalone template does (in `buildModules.mts`), so a `type = "oidc"` section
under that name is not read as this adapter's. It casts; a production bridge
checks each field's type, as the template's Google bridge
(`googleFederationConfigModule` in
[`templates/standalone/src/modules.mts`](../../templates/standalone/src/modules.mts)) does.
`clientSecret` is a string. `createGoogleProvider` throws at boot when
`clientId`, `clientSecret` or `callbackURL` is missing.

## What a login does

- **Authorization request:** scope `openid profile email`, PKCE S256,
  `access_type=offline`, and the `nonce` the session router minted. There is no
  request without a nonce: `buildAuthorizationUrl` and `exchangeCode` both throw
  when it is missing. No `prompt=consent` is sent, and Google returns a refresh
  token only when the user consents — normally the first login. Later logins
  store no refresh token, so `oauth`'s `POST /oauth/federation/:name/token`
  cannot refresh those sessions' Google tokens (`410 refresh_token_absent`).
- **Code exchange:** at Google's token endpoint, the client secret in the
  request body (`client_secret_post`, `openid-client`'s default), with the PKCE
  verifier. The callback's `iss` is checked first (below). The id_token's signature is
  verified against Google's JWKS with `RS256` pinned, and its `nonce` against the
  session's; a response without an id_token is refused.
- **UserInfo** is fetched and bound to the id_token's `sub`; an id_token without
  a `sub`, or a UserInfo answer for another subject, is refused. Any refusal
  reaches the browser as the session router's `502 exchange_failed`.

What `exchangeCode` returns:

| Field | Value |
| --- | --- |
| `issuer` | `https://accounts.google.com` |
| `sub` | Google's account ID, from UserInfo (bound to the id_token's) |
| `email`, `name`, `picture` | from UserInfo, when strings |
| `emailVerified` | UserInfo's `email_verified` when it is a boolean; otherwise absent |
| `hd` | the Workspace domain, when UserInfo carries it — recorded, not enforced (below) |
| `accessToken`, `idToken`, `refreshToken` | as Google issued them; `idToken` and `refreshToken` only when non-empty strings |
| `scope` | Google's `scope` as sent; absent when Google sent none. A `scope` that is not a string is refused by `openid-client` before the adapter sees it, and the login answers `502 exchange_failed` |
| `expiresAt` | when the answer arrived + `expires_in`; **`null` when Google sent no `expires_in`** (both IdPs document it on every token response), which `oauth`'s `POST /oauth/federation/:name/token` reads as "do not refresh; reuse the stored token" |
| `expiresIn` | the `expires_in` Google sent, `null` when none |
| `tokenType` | `token_type` as `openid-client` reports it (lower-cased `bearer`), recorded by the session router verbatim |

`mapClaims` maps `email`, `emailVerified`, `name`, `picture` and `hd`; the session
package promotes only `email`, `name` and `picture`, and only where the local
record is silent. **`hd` is not enforced:** nothing here refuses an account from
another domain, and the claim lands only in `claims.federated.google`. A
Workspace-domain restriction belongs in the Store, which decides who
`google:<sub>` is.

### The callback's `iss` (RFC 9207)

Google's discovery document advertises
`authorization_response_iss_parameter_supported`, and its OpenID Connect
reference says of the authorization response's `iss`: "Per RFC 9207, this
parameter is always returned and set to `https://accounts.google.com`". So this
provider compares the callback's `iss` with Google's issuer, as an exact
string, and **refuses a callback that carries none**. Both refusals happen
before the code is spent at the token endpoint.

The server metadata here is written by hand, not discovered, so a deployment
could not otherwise react if Google ever stopped sending the parameter.
`requireAuthorizationResponseIss: false` in `GoogleProviderConfig` is the way
out: it permits a missing `iss` and nothing else. One that is sent and is not
Google's is refused either way. The bridge above does not forward it; forward
it too if the deployment should be able to set it, as the standalone
template's bridge does. **It must be a boolean.** An environment override
arrives as the string `"false"`, which is truthy, so `createGoogleProvider`
refuses anything that is not a boolean instead of quietly keeping the
requirement on; coerce the string in the bridge.

If every Google login starts answering `502 exchange_failed` with the log cause
`response parameter "iss" (issuer) missing`, either Google stopped sending the
parameter or something between Google and this server drops it: a gateway with
a query-parameter allowlist, or a front end that relays only `code` and
`state` to `callbackURL`. Let `iss` through; the switch above is the stopgap.

## Refresh and logout

- **`refreshToken()`** (`SupportsRefresh`, called by `oauth`'s
  `POST /oauth/federation/:name/token`) runs the `refresh_token` grant and
  returns the token fields of the table above by the same rules —
  `accessToken`, `refreshToken` when rotated, `idToken`, `scope`, `expiresAt`,
  `expiresIn` and `tokenType` (a non-string `scope` fails the refresh). It
  returns no `issuer` or `sub` — the caller keeps the stored identity.
- **`endSession()`** (`SupportsLogout`, called by `oauth`'s logout routes):
  Google publishes no `end_session_endpoint`. With `endSessionEndpoint`
  configured, that URL with `id_token_hint`, `post_logout_redirect_uri` and
  `state`; otherwise `postLogoutRedirectUri`, and without one
  `https://accounts.google.com/Logout`, with `state`. An unparsable URL throws.

## Public API

Defined in [`src/google.mts`](src/google.mts), exported from
[`src/index.mts`](src/index.mts):

- `googleFederationModule` — const Module contributing `federations.google` and
  `federationRedirectPolicies.google`; requires `googleFederationConfig`.
- `createGoogleProvider(config)` — the provider.
- `GoogleProviderConfig`, `GoogleProvider` — types.
- `googleFederationConfig` — the `ComponentMap` slot the module requires,
  declared by module augmentation (not an export).

## Tests

| Test file | Pins |
| --- | --- |
| [`google.test.mts`](src/__tests__/google.test.mts) | the authorization request, the nonce requirement, the UserInfo `sub` binding, the profile, refresh and `mapClaims` (`endSession` has no test here) |
| [`google.signature.test.mts`](src/__tests__/google.signature.test.mts) | that the id_token's signature is verified against the JWKS |
| [`google.token-snapshot.test.mts`](src/__tests__/google.token-snapshot.test.mts) | the lifetime, `expiresIn` and `tokenType` a login and a refresh report, with and without `expires_in`, and that a non-string `scope` is refused by the library |
| [`google.issuer-parameter.test.mts`](src/__tests__/google.issuer-parameter.test.mts) | the RFC 9207 `iss` check and `requireAuthorizationResponseIss` |
| [`google-module.test.mts`](src/__tests__/google-module.test.mts), [`google-module-boot.test.mts`](src/__tests__/google-module-boot.test.mts) | the module's contributions and boot with the session module |
