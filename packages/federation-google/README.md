# @o3co/auth-provider-federation-google

Last updated: 2026-10-03

Google federation provider for `auth.provider`: sign-in with a Google account
through Google's OpenID Connect endpoints, with token refresh, upstream logout
and claim mapping.

## Responsibility

**Role.** An adapter: it implements core's federation contract
([`core/src/federations`](../core/src/federations/README.md)) for Google. It
contributes the federation type `google`: core hands it each enabled
`core.federations` entry of that type, and it builds one federation per entry,
under the entry's name, registered for the session router with its redirect
policy.

**Owns:** Google's endpoints and issuer (written into the adapter, not
discovered), how the id_token and UserInfo are verified, which parameters the
authorization request carries, what a Google login profile, a refresh and a
logout URL contain, and the schema of a `google` entry's own keys
([`src/entry.mts`](src/entry.mts)).

**Does not own:** the contract (core); the `core.federations` map, the keys
core owns on every entry (`enabled`, `type`, `trustUpstreamAmr`,
`callbackURL`) and the dispatch of an entry by its type (core's boot); the routes, `state` / PKCE verifier /
`nonce` generation, the redirect-allowlist rules and claim precedence
([`@o3co/auth-provider-session`](../session/README.md)); who the user is (the
Store); the refresh and logout routes that call this adapter
([`@o3co/auth-provider-oauth`](../oauth/README.md)).

**Why a separate package.** Each adapter is its own package so that a deployment
installs only the IdPs it uses, and `openid-client` only with one of them. Why
Google is not a `type = "oidc"` section of
[`@o3co/auth-provider-federation-oidc`](../federation-oidc/README.md): this
adapter does four things the generic one does not — it sends
`access_type=offline` and `prompt=consent` at login, what Google requires before
it issues a refresh token (below); it carries Google's `hd` (Workspace domain) claim through to
the profile and `mapClaims`; it requires the RFC 9207 `iss` without fetching
Google's discovery document; and without an `endSessionEndpoint` it still
offers logout, redirecting to `postLogoutRedirectUri` or to Google's own logout
URL, where the generic adapter offers logout only when an end-session endpoint
is discovered or configured. The generic adapter already verifies what this one
verifies.

Nor is this adapter a preset built on the generic one. That was weighed and
declined: it would make this package depend on `federation-oidc`; the generic
provider is built asynchronously (discovery, key import) while
`createGoogleProvider` is synchronous, so it would have to be split; it would
need four new options for the four differences above; and it would change how
this adapter authenticates to Google (`client_secret_post` today, the generic
adapter's `client_secret_basic`). What the two did share — the PKCE
challenge, the code-exchange URL, the reading of the token response — is
core's toolkit, used by both, so little duplication is left to remove.

## Install

```sh
npm install @o3co/auth-provider-federation-google @o3co/auth-provider-core @o3co/auth-provider-session
```

Peer dependencies: `@o3co/auth-provider-core` and
`@o3co/auth-provider-session`. The package depends on `openid-client` and
`zod`.

## Usage

One module, `googleFederationTypeModule()`
([`src/type-module.mts`](src/type-module.mts)), handles every enabled
`core.federations` entry whose `type` is `google`. It contributes
`federationTypes.google`; core parses each such entry with the type's schema
at boot and calls the module's factories with the entry's name, its
`callbackURL` and its parsed keys, so the composition root fills no slot. The
module requires no dependency.

```ts
import { createApp } from "@o3co/auth-provider-core";
import { googleFederationTypeModule } from "@o3co/auth-provider-federation-google";
import { sessionModule, sessionStoreModuleFor } from "@o3co/auth-provider-session";

const handle = await createApp({
  modules: [
    sessionStoreModuleFor(config),
    sessionModule,
    googleFederationTypeModule(),
    // ... composition-root modules supplying userRepository and the session stores
  ],
  bootstrapComponents: { config, pathResolver },
});
```

`googleFederationTypeModule({ fetch })` sends every request to Google of every
`google` entry — token, UserInfo, JWKS — through that fetch: a proxy, or a
test double. Without it the global `fetch` is used. Its module name is
`federation-google-type`.

The fixed-name module `googleFederationModule` and its `googleFederationConfig`
slot were removed in favour of `googleFederationTypeModule()`.

### Configuration

```hocon
core.federations {
  google {
    enabled = true
    type = "google"
    clientId = ${?CORE_FEDERATIONS_GOOGLE_CLIENT_ID}
    clientSecret = ${?CORE_FEDERATIONS_GOOGLE_CLIENT_SECRET}
    callbackURL = "https://auth.example.com/session/oauth/federation/google/callback"
    clientUrl = "https://app.example.com/"
  }
}
```

The entry's name is the federation's: the `:name` segment of
`/session/oauth/federation/:name`, the key its upstream tokens are stored
under, and the prefix of the identity handed to the Store (`<name>:<sub>`).
Two entries of type `google` — two Google clients, say one per OAuth consent
screen — are two federations side by side, each under its own name.

An entry is flat, and its schema is strict: the keys core owns (`enabled`,
`type`, `trustUpstreamAmr`, `callbackURL`) and the keys below, nothing else.
The schema is `googleEntrySchema` in [`src/entry.mts`](src/entry.mts). A key it
does not name — a typo, or a nested `google { ... }` section — refuses boot with `config-validation-failed` at `core.federations.<name>`,
naming the key; a missing or malformed key is refused at
`core.federations.<name>.<field>`. No refusal quotes the value it refuses, so a
misplaced `clientSecret` does not reach the log. A key written `null` counts as
absent. An absent key means what the table says, read by the provider and the
redirect policy; the schema fills in no default.

| Field | Required | Meaning |
| --- | --- | --- |
| `clientId` | yes | The OAuth client ID Google issued. |
| `clientSecret` | yes | Its client secret, sent in the token request's body (`client_secret_post`). |
| `callbackURL` | yes | Where Google sends the browser back. A key core owns: boot requires it of every entry it dispatches, and the session routes read it from the same entry. |
| `clientUrl` | in practice | Where the browser lands after a login whose start carried no `redirect_to`. Without it such a login ends in `500 misconfiguration` after the session has been saved — so it is needed unless every start carries a `redirect_to` and `authCallbackUrl` is set. |
| `redirectAllowlist`, `authCallbackUrl`, `sessionDomain` | no | The `redirect_to` policy, as for every federation — see the [session package README](../session/README.md#redirect-allowlists). A start that carries `redirect_to` needs both an allowlist entry for it and `authCallbackUrl`, or it is refused (`400`) or ends in `500 misconfiguration`. |
| `accessType` | no | `"offline"` (absent means this) or `"online"`: whether sign-in asks Google for a refresh token — [below](#refresh-tokens-and-the-consent-screen). |
| `requireAuthorizationResponseIss` | no | Absent means `true`: a callback without the RFC 9207 `iss` is refused — [below](#the-callbacks-iss-rfc-9207). Also takes `"true"`, `"false"`, `"1"` and `"0"` (trimmed, any case), as an environment variable writes them; an empty string is refused. |
| `endSessionEndpoint` | no | An upstream end-session URL for logout; Google publishes none — [below](#refresh-and-logout). |

`fetch` is not an entry key: it is the type module's option (above), and a
`GoogleProviderConfig` field for `createGoogleProvider`. Nor is `jwksUri`: where Google's signing keys are fetched from is not the
configuration's to move. It stays a `GoogleProviderConfig` field.

## What a login does

- **Authorization request:** scope `openid profile email`, PKCE S256,
  `access_type=offline` with `prompt=consent` (see below), and the `nonce` the
  session router minted. There is no request without a nonce:
  `buildAuthorizationUrl` and `exchangeCode` both throw when it is missing.
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
| `expiresAt` | when `openid-client` handed the answer over (after it verified the id_token, a JWKS fetch included) + `expiresIn`; **`null` when Google sent no `expires_in`** (Google documents it on every token response), which `oauth`'s `POST /oauth/federation/:name/token` reads as "do not refresh; reuse the stored token" |
| `expiresIn` | `expires_in` as `openid-client` read it — it applies `parseFloat`, so `"1000seconds"` is 1000 — or `null` when Google sent none |
| `tokenType` | `token_type` as `openid-client` reports it (lower-cased `bearer`), recorded by the session router verbatim |

`mapClaims` maps `email`, `emailVerified`, `name`, `picture` and `hd`; the session
package promotes only `email`, `name` and `picture`, and only where the local
record is silent. **`hd` is not enforced:** nothing here refuses an account from
another domain, and the claim lands only in `claims.federated.<name>`. A
Workspace-domain restriction belongs in the Store, which decides who
`<name>:<sub>` is.

### Refresh tokens and the consent screen

Google issues a refresh token only when the user is shown its consent screen,
and without `prompt` it shows that screen only the first time an app asks.
Upstream tokens are stored per session, so a user's second session would have
no refresh token, and `oauth`'s `POST /oauth/federation/:name/token` would
answer `410 refresh_token_absent` once the access token expired. So with
`accessType: "offline"` — the default in `GoogleProviderConfig` — every
sign-in sends `access_type=offline` **and** `prompt=consent`:

- **Every sign-in shows Google's consent screen**, and every session gets a
  refresh token.
- **Every sign-in mints a refresh token.** Google keeps at most 100 per Google
  account per client ID and silently invalidates the oldest when a new one is
  issued, so a user with more than 100 live sessions loses refresh on the
  oldest.

`accessType: "online"` sends neither parameter: no consent screen after the
first sign-in, and no refresh token at all — for a deployment that uses Google
to sign in and never refreshes Google's access token through the federation
token route (it answers `410 refresh_token_absent` once that token expires).
In code, only an omitted field means the default: any other value, `null`
included, is refused at construction (an entry's `null` reads as absent
first). The standalone template's entry binds
`accessType` to `CORE_FEDERATIONS_GOOGLE_ACCESS_TYPE`, and the type module
reads it.

Keeping an earlier session's refresh token for the same `<name>:<sub>` is not
done: it would need a credential store that outlives sessions.

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
Google's is refused either way. An entry's schema reads the string spellings
of an environment variable (above). In code **it must be a boolean**: an
environment override arrives as the string `"false"`, which is truthy, so
`createGoogleProvider` refuses anything that is not a boolean instead of
quietly keeping the requirement on.

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
  `https://accounts.google.com/Logout`, with `state`. An unparsable URL throws;
  the message names the field and quotes no value it was handed.
  Redirecting straight to `postLogoutRedirectUri` is safe because the caller
  hands only a URI it has matched against the client's registered
  `postLogoutRedirectUris`, or none — core's `EndSessionRequest` states the
  rule, and `oauth`'s logout routes keep it. A composition that calls
  `endSession()` itself must do the same.

## Public API

Exported from [`src/index.mts`](src/index.mts):

- `googleFederationTypeModule` ([`src/type-module.mts`](src/type-module.mts)) —
  the Module contributing `federationTypes.google`, with its options
  `GoogleFederationTypeModuleOptions`.
- `GOOGLE_FEDERATION_TYPE` (`"google"`, [`src/type-module.mts`](src/type-module.mts)).
- `createGoogleProvider(config)` ([`src/google.mts`](src/google.mts)) — the
  provider, named `google`.
- Types: `GoogleEntry` ([`src/entry.mts`](src/entry.mts)), an entry's own keys
  as the schema answers them; [`GoogleProviderConfig`](src/google.mts),
  `GoogleProvider`.

## Tests

| Test file | Pins |
| --- | --- |
| [`google.test.mts`](src/__tests__/google.test.mts) | the authorization request, the nonce requirement, the UserInfo `sub` binding, the profile, refresh and `mapClaims` |
| [`google.end-session.test.mts`](src/__tests__/google.end-session.test.mts) | `endSession`: a configured endpoint, the handed `postLogoutRedirectUri`, Google's logout page, and a refusal that quotes nothing it was handed |
| [`google.consent.test.mts`](src/__tests__/google.consent.test.mts) | that a returning user's sign-in yields a refresh token, `prompt=consent` beside `access_type=offline`, and `accessType` |
| [`google.signature.test.mts`](src/__tests__/google.signature.test.mts) | that the id_token's signature is verified against the JWKS |
| [`google.token-snapshot.test.mts`](src/__tests__/google.token-snapshot.test.mts) | the lifetime, `expiresIn` and `tokenType` a login and a refresh report, with and without `expires_in`, and that a non-string `scope` is refused by the library |
| [`google.issuer-parameter.test.mts`](src/__tests__/google.issuer-parameter.test.mts) | the RFC 9207 `iss` check and `requireAuthorizationResponseIss` |
| [`google-type-module.test.mts`](src/__tests__/google-type-module.test.mts) | the type module through `createApp`: one provider and policy per entry, a login through the session routes, the strict, flat schema, refusals that quote no secret, the `fetch` option, and each entry key reaching the provider or the redirect policy |
