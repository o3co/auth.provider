# @o3co/auth-provider-federation-oidc

Last updated: 2026-09-24

Generic OpenID Connect federation provider for `auth.provider`: any
OIDC-compliant identity provider — Okta, Entra ID, Auth0, Keycloak, a
customer's own tenant — from configuration alone, and as many instances as a
deployment has issuers.

## Responsibility

**Role.** An adapter: it implements core's federation contract
([`core/src/federations`](../core/src/federations/README.md)) for any OpenID
Connect IdP — configured from its discovery document, or by hand with
`discovery = false` — so adding an IdP is a config section, not a package. Each `type = "oidc"` section of `federations` becomes one
federation, contributed to the session router with its redirect policy. It is
also the only bundled adapter with `SupportsDelegatedAuthorization`, the
capability `@o3co/auth-provider-federation-grants` delegates through.

**Owns:** issuer discovery at boot and the refusals that go with it; client
authentication (`client_secret_basic` or `private_key_jwt`,
[`src/client-auth.mts`](src/client-auth.mts)); id_token verification, including
`at_hash` ([`src/at-hash.mts`](src/at-hash.mts)); the UserInfo binding; what a
profile, a refresh and a delegated exchange contain; and reading `type = "oidc"`
sections into provider configs ([`src/module.mts`](src/module.mts)).

**Does not own:** the contract (core); the routes, `state` / PKCE verifier /
`nonce` generation, the redirect-allowlist rules and claim precedence
([`@o3co/auth-provider-session`](../session/README.md)); who the user is (the
Store); the refresh and logout routes that call this adapter
([`@o3co/auth-provider-oauth`](../oauth/README.md)); federation grants
([`@o3co/auth-provider-federation-grants`](../federation-grants/README.md)).

**Why a separate package.** Each adapter is its own package so that a deployment
installs only the IdPs it uses, and `openid-client` only with an adapter.
The Google, GitHub and Apple packages implement the same contract for one IdP
each, for what a generic OpenID Connect client cannot express: GitHub is not
OpenID Connect, Apple's scopes, client secret and callback are not standard, and
Google's adapter sends `access_type=offline` and carries the `hd` claim — each
package's README says which. This package has no setting for a login-time
authorization parameter or an extension claim.

## Install

```sh
npm install @o3co/auth-provider-federation-oidc
```

Peer dependencies: `@o3co/auth-provider-core` and
`@o3co/auth-provider-session`. Its dependencies are `openid-client` and `jose`.

## Usage

Each instance is one module, made by `oidcFederationModule(<name>)`. Every
instance reads its config from the shared `oidcFederationConfigs` slot, which
the composition root fills — normally straight from the `federations` config
section with `readOidcFederationConfigs`:

```ts
import { createApp, defineModule } from "@o3co/auth-provider-core";
import {
  oidcFederationModule,
  oidcFederationNames,
  readOidcFederationConfigs,
} from "@o3co/auth-provider-federation-oidc";
import { sessionModule, sessionStoreModuleFor } from "@o3co/auth-provider-session";

const oidcConfigBridgeModule = defineModule({
  name: "oidc-federation-config",
  requires: ["config"] as const,
  provides: {
    oidcFederationConfigs: ({ config }) => readOidcFederationConfigs(config.federations),
  },
});

const handle = await createApp({
  modules: [
    sessionStoreModuleFor(config),
    sessionModule,
    oidcConfigBridgeModule,
    ...oidcFederationNames(config.federations).map((name) => oidcFederationModule(name)),
    // ... composition-root modules supplying userRepository + the session stores
  ],
  bootstrapComponents: { config, pathResolver },
});
```

The scaffold (`@o3co/create-auth-provider`) does exactly this in
`src/buildModules.mts`, so a scaffolded deployment adds an IdP by editing
`config/application.conf` alone.

### Configuration

A `federations.<name>` section whose `type` is `oidc`. The section name is the
federation name: the browser starts at `/session/oauth/federation/<name>`, the
IdP sends it back to `callbackURL`, and the identity handed to the Store is
`<name>:<sub>`.

```hocon
federations {
  okta {
    enabled = true
    type = "oidc"
    issuer = "https://dev-123.okta.com"
    clientId = ${OKTA_CLIENT_ID}
    clientSecret = ${OKTA_CLIENT_SECRET}
    callbackURL = "https://auth.example.com/session/oauth/federation/okta/callback"
    clientUrl = "https://app.example.com/"
    redirectAllowlist = ["https://app.example.com/welcome"]
    authCallbackUrl = "https://app.example.com/auth/callback"
  }

  keycloak {
    enabled = true
    type = "oidc"
    issuer = "https://sso.example.com/realms/staff"
    clientId = ${KEYCLOAK_CLIENT_ID}
    privateKey = ${KEYCLOAK_PRIVATE_KEY_PEM}     # private_key_jwt
    callbackURL = "https://auth.example.com/session/oauth/federation/keycloak/callback"
    clientUrl = "https://app.example.com/"
    scopes = ["openid", "profile", "email", "groups"]
  }
}
```

Two issuers, two sections, two callbacks — that is the whole of multi-IdP
support. The nested shape (`okta { type = "oidc", oidc { ... } }`) that
`extractFederationSection` accepts works too.

| Field | Required | Meaning |
| --- | --- | --- |
| `issuer` | yes | Issuer identifier, exactly as the IdP writes it into `iss`. `https`; plain `http` only on a loopback host (local Keycloak). |
| `clientId` | yes | Client identifier registered at the IdP. |
| `clientSecret` | one of | `client_secret_basic` (RFC 6749 §2.3.1). In code the value may be a resolver (`() => Promise<string>`), consulted on every token request, for secrets that rotate. |
| `privateKey` | one of | `private_key_jwt` (RFC 7523 / OIDC Core §9). A PEM-encoded PKCS#8 key, or `{ pem, kid?, alg? }`. The JWS algorithm is inferred from the key (RSA → RS256, P-256 → ES256, P-384 → ES384, P-521 → ES512, Ed25519 → EdDSA) unless `alg` says otherwise; `kid` goes in the assertion header. |
| `callbackURL` | yes | Where the IdP sends the browser back. The session routes read it from the same section. |
| `scopes` | no | Default `["openid", "profile", "email"]`. `openid` is mandatory — without it there is no id_token — and its absence refuses boot. |
| `discovery` | no | Default `true`. See below. |
| `endpoints` | no | `authorizationEndpoint`, `tokenEndpoint`, `jwksUri`, `userinfoEndpoint`, `endSessionEndpoint`. Applied over the discovered metadata; the first three are mandatory when `discovery = false`. |
| `idTokenSignedResponseAlg` | no | Pin the id_token JWS algorithm. Otherwise the issuer's advertised `id_token_signing_alg_values_supported` is trusted. With `discovery = false` nothing is advertised, and `openid-client` then accepts `RS256` only — so an IdP that signs with ES256 or EdDSA needs this set, or every login fails. `none` and symmetric algorithms are never accepted against a JWKS. |
| `userInfo` | no | Default: call UserInfo when the issuer publishes an endpoint. `false` builds the profile from the id_token alone; `true` refuses boot if there is no endpoint. |
| `clockToleranceSeconds` | no | Skew tolerated on `exp` / `iat`. Passed to `openid-client` only when set; its own default is 30. |
| `clientUrl` | in practice | Where the browser lands after a login whose start carried no `redirect_to`. Without it such a login ends in `500 misconfiguration` after the session has been saved — so it is needed unless every start carries a `redirect_to` and `authCallbackUrl` is set. |
| `redirectAllowlist`, `authCallbackUrl`, `sessionDomain` | no | The `redirect_to` policy, as for every federation — see the [session package README](../session/README.md#redirect-allowlists). A start that carries `redirect_to` needs both an allowlist entry for it and `authCallbackUrl`, or it is refused (`400`) or ends in `500 misconfiguration`. |

`fetch` (code only) replaces the fetch every upstream request goes through —
for a proxy, or a test double.

### What happens at boot

Discovery. Each instance fetches `<issuer>/.well-known/openid-configuration`
when the app boots, checks the document's `issuer` against the configured one,
and keeps the whole document, with any `endpoints` applied over it. **A failure is fatal**: an
unreachable issuer, a document naming another issuer, or one without a
`jwks_uri` refuses boot with the federation's name in the error. There is no
silent fallback to hand-typed endpoints — a deployment that wants those sets
`discovery = false` and writes them under `endpoints`, and then no document is
fetched at all.

Boot also refuses a config with both `clientSecret` and `privateKey`, with
neither, with a name that is not one URL path segment, or with a private key
that cannot be parsed.

### What happens at login

1. **Authorization request** — `authorization_code` with PKCE S256, `state`
   and `nonce`. All three are minted by the session routes per transaction and
   stored in the session; the provider refuses to build a request without a
   nonce (OIDC Core §3.1.3.7).
2. **Code exchange** — at `token_endpoint`, authenticated with the configured
   method, `redirect_uri` echoing the callback and `code_verifier` closing the
   PKCE loop. Before it, the callback's `iss` parameter (RFC 9207) is compared
   with the configured issuer, as an exact string: a different one is refused
   without spending the code. An issuer whose discovered metadata advertises
   `authorization_response_iss_parameter_supported` — Keycloak's does by
   default — must also send one. With `discovery = false` there is no metadata
   to advertise it, so `iss` is compared when present and never required.
3. **ID token validation** — signature against the issuer's JWKS (fetched by
   `kid`, cached, refetched when an unknown `kid` appears — but not within a
   minute of the last fetch, so an IdP that rotates keys must publish the new
   key before signing with it, which every IdP does); `iss` equal to the
   configured issuer; `aud` containing the client id — with more than one
   audience, `azp` must be present and equal the client id; `exp` and `iat` within tolerance; `nonce` equal to the
   transaction's; `at_hash` recomputed from the access token when the claim is
   present (OIDC Core §3.3.2.11). A response without an id_token is refused.
4. **UserInfo** — when enabled, fetched with the access token and bound to the
   id_token's `sub`; a mismatch is refused. UserInfo values fill `email`,
   `emailVerified`, `name`, `picture` and `groups`, falling back to the
   id_token's claim only where UserInfo does not carry one (a `null` counts as not carrying one). `email_verified` is normalised to a boolean (some IdPs
   send `"true"`); `groups` is carried only as a string array.
5. **Identity** — `sub` is opaque and stable per issuer; the profile is never
   keyed on `email`. The session routes hand `<name>:<sub>` to the Store
   exactly as they do for Google or GitHub. **An identity the Store does not
   know is refused with `401 unknown_user`** — this package provisions nothing;
   the Store stays the source of truth for who exists.

Any refusal in steps 2–4 surfaces from the callback as `502 exchange_failed`
(the session routes' answer to an upstream exchange the provider refused) and
never reaches the Store.

What `exchangeCode` returns:

| Field | Value |
| --- | --- |
| `issuer` | the id_token's `iss` — the configured issuer |
| `sub` | the id_token's `sub` |
| `email`, `name`, `picture` | UserInfo's value when UserInfo carries the claim, otherwise the id_token's; kept only when a non-empty string. A UserInfo value that is present (not `null`) but malformed is dropped, not replaced by the id_token's; a `null` counts as absent |
| `emailVerified` | read the same way, then normalised to a boolean (`"true"` / `"false"` included); any other shape is absent |
| `groups` | read the same way; kept only when an array of strings |
| `accessToken` | as the issuer sent it |
| `idToken`, `refreshToken` | as the issuer sent them, when non-empty strings |
| `scope` | the token response's `scope`, an empty one included; absent when the response carried none (the session router then records the requested scope). A `scope` that is not a string is refused by `openid-client` before the adapter sees it, and the login answers `502 exchange_failed` |
| `expiresAt` | when `openid-client` handed the answer over (after it verified the id_token, a JWKS fetch included) + `expiresIn`; **`null` when the response carried no `expires_in`**, which `oauth`'s `POST /oauth/federation/:name/token` reads as "do not refresh; reuse the stored token" |
| `expiresIn` | `expires_in` as `openid-client` read it — it applies `parseFloat`, so `"1000seconds"` is 1000 — or `null` when none. The delegated capability below reads the raw answer instead and refuses such a lifetime: a grant's eligibility judges the lifetime a token was issued with, where a login's expiry only says when a refresh is due |
| `tokenType` | `token_type` as `openid-client` reports it (lower-cased), recorded by the session router verbatim |

The token fields are core's `federationTokenSnapshot`, the one reading every
bundled adapter gives a token response.

### Optional capabilities

- `SupportsRefresh` — `refreshToken()` runs the `refresh_token` grant at the
  issuer and returns the token fields of the table above, by the same rules (a non-string `scope` fails the refresh rather than a login),
  with no `issuer` or `sub`.
- `SupportsDelegatedAuthorization` — `buildDelegatedAuthorizationUrl()`
  builds the authorization request for a federation grant: the intent's
  scopes, which must include `openid`; a required nonce; the RFC 8707
  `resource`; `prompt=consent` when `offline_access` is asked for, unless the
  connection's `authorizationParams` sets its own `prompt`; and those
  `authorizationParams`, whose values must be strings and which may not name a
  parameter the adapter owns. `exchangeDelegatedCode()`
  exchanges the connect callback's code — PKCE, the nonce, the `resource` at
  the token endpoint, `iss` forwarded — never calls UserInfo, and answers the
  verified id_token's issuer and subject, plus the claims the caller names in
  `identityClaims`, copied from that id_token only, as non-empty strings
  only. `refreshDelegatedToken()` runs the `refresh_token` grant with the
  grant's scopes and resource under the caller's `AbortSignal`, answers
  `expires_in` as the IdP sent it, `scope`, and `token_type` as the library
  reports it (lower-cased), and keeps the rotated refresh token from an answer
  the library did not accept — one it could not parse, or one whose id_token it
  could not verify — returning `{ refreshToken }` alone rather than losing it.
- `SupportsLogout` — present only when the issuer publishes an
  `end_session_endpoint` (or `endpoints.endSessionEndpoint` names one):
  RP-initiated logout with `client_id`, `id_token_hint`,
  `post_logout_redirect_uri` and `state`.
- `SupportsClaimMapping` — `mapClaims()` maps `email`, `emailVerified`,
  `name`, `picture` and `groups`. The session package promotes only `email`,
  `name` and `picture` into the top-level claims, and only where the local record
  is silent; `groups` and `emailVerified` stay under
  `claims.federated.<name>`, so an IdP's `groups` never becomes an authorization
  claim ([claim precedence](../session/README.md#claim-precedence-local-wins-federated-is-namespaced)).

### Scaffold environment variables

The scaffold ships one instance, `federations.oidc`, disabled by default:

| Variable | Default | Description |
| --- | --- | --- |
| `FEDERATIONS_OIDC_ENABLED` | `false` | Enable the instance |
| `FEDERATIONS_OIDC_ISSUER` | — | Issuer identifier |
| `FEDERATIONS_OIDC_CLIENT_ID` | — | Client ID |
| `FEDERATIONS_OIDC_CLIENT_SECRET` | — | Client secret (`client_secret_basic`) |
| `FEDERATIONS_OIDC_CALLBACK_URL` | `http://localhost:3000/session/oauth/federation/oidc/callback` | Callback |

More instances are more sections in `config/application.conf`.

## Public API

Exported from [`src/index.mts`](src/index.mts); the signatures are in the files
linked:

- `createOidcProvider` ([`src/oidc.mts`](src/oidc.mts)) — the provider;
  asynchronous, because discovery happens here.
- `oidcFederationModule` ([`src/module.mts`](src/module.mts)) — one Module per
  instance, requiring `oidcFederationConfigs` and contributing
  `federations.<name>` and `federationRedirectPolicies.<name>`.
- `readOidcFederationConfigs` ([`src/module.mts`](src/module.mts)) — fills that
  slot from a `federations` config section, refusing a malformed field by
  `federations.<name>.<field>`.
- `oidcFederationNames` ([`src/module.mts`](src/module.mts)) — the names of every
  enabled section of type `oidc`, sorted.
- `OIDC_FEDERATION_TYPE` (`"oidc"`), `DEFAULT_OIDC_SCOPES`.
- `oidcFederationConfigs` — the `ComponentMap` slot every instance requires,
  declared by module augmentation in [`src/module.mts`](src/module.mts) (not an
  export).
- Types: [`OidcProviderConfig`](src/oidc.mts) (the config fields above),
  `OidcEndpointOverrides`, `OidcProvider` ([`src/oidc.mts`](src/oidc.mts));
  `OidcPrivateKey` ([`src/client-auth.mts`](src/client-auth.mts)).

## Tests

The tests run the real `openid-client` against core's shared fake OpenID
Provider (`createFakeIdp` from `@o3co/auth-provider-core/testing`), set up in
[`helpers.mts`](src/__tests__/helpers.mts) as an issuer that is discovered:
it serves the discovery document, signs real RS256 id_tokens under a key it
publishes, and records every request.

| Test file | Pins |
| --- | --- |
| [`oidc.test.mts`](src/__tests__/oidc.test.mts) | discovery and its refusals, client authentication, the login steps above, the profile, refresh, logout and `mapClaims` |
| [`at-hash.test.mts`](src/__tests__/at-hash.test.mts) | the `at_hash` check |
| [`delegated.test.mts`](src/__tests__/delegated.test.mts) | `SupportsDelegatedAuthorization` |
| [`oidc-module.test.mts`](src/__tests__/oidc-module.test.mts), [`oidc-module-boot.test.mts`](src/__tests__/oidc-module-boot.test.mts) | reading `type = "oidc"` sections, the module per instance, and boot |
| [`session-routes.e2e.test.mts`](src/__tests__/session-routes.e2e.test.mts) | a login through the session routes, end to end, and that a failed exchange is logged without the token response the library carries on the error |
