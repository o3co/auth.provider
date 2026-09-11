# @o3co/auth-provider-federation-oidc

Generic OpenID Connect federation provider for `auth.provider`: any
OIDC-compliant identity provider — Okta, Entra ID, Auth0, Keycloak, a
customer's own tenant — from configuration alone, and as many instances as a
deployment has issuers (#524).

The `FederationProvider` contract lives in `@o3co/auth-provider-session`; the
Google, GitHub and Apple packages implement it for one IdP each. This package
implements it for every IdP that publishes an OpenID Connect discovery
document, so adding an IdP is a config section, not a package.

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
import { sessionModule } from "@o3co/auth-provider-session";

const oidcConfigBridgeModule = defineModule({
  name: "oidc-federation-config",
  requires: ["config"] as const,
  provides: {
    oidcFederationConfigs: ({ config }) => readOidcFederationConfigs(config.federations),
  },
});

const handle = await createApp({
  modules: [
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
    redirectAllowlist = ["https://app.example.com/welcome"]
  }

  keycloak {
    enabled = true
    type = "oidc"
    issuer = "https://sso.example.com/realms/staff"
    clientId = ${KEYCLOAK_CLIENT_ID}
    privateKey = ${KEYCLOAK_PRIVATE_KEY_PEM}     # private_key_jwt
    callbackURL = "https://auth.example.com/session/oauth/federation/keycloak/callback"
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
| `idTokenSignedResponseAlg` | no | Pin the id_token JWS algorithm. Otherwise the issuer's advertised `id_token_signing_alg_values_supported` is trusted; `none` and symmetric algorithms are never accepted against a JWKS. |
| `userInfo` | no | Default: call UserInfo when the issuer publishes an endpoint. `false` builds the profile from the id_token alone; `true` refuses boot if there is no endpoint. |
| `clockToleranceSeconds` | no | Skew tolerated on `exp` / `iat`. Default 30. |
| `redirectAllowlist`, `sessionDomain`, `authCallbackUrl`, `clientUrl` | no | The `redirect_to` policy, as for every federation — see the session package README. |

`fetch` (code only) replaces the fetch every upstream request goes through —
for a proxy, or a test double.

### What happens at boot

Discovery. Each instance fetches `<issuer>/.well-known/openid-configuration`
when the app boots, checks the document's `issuer` against the configured one,
and keeps `authorization_endpoint`, `token_endpoint`, `jwks_uri`,
`userinfo_endpoint` and `end_session_endpoint`. **A failure is fatal**: an
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
   PKCE loop.
3. **ID token validation** — signature against the issuer's JWKS (fetched by
   `kid`, cached, refetched when an unknown `kid` appears — but not within a
   minute of the last fetch, so an IdP that rotates keys must publish the new
   key before signing with it, which every IdP does); `iss` equal to the
   configured issuer; `aud` containing the client id and no untrusted extra
   audience; `exp` and `iat` within tolerance; `nonce` equal to the
   transaction's; `at_hash` recomputed from the access token when the claim is
   present (OIDC Core §3.3.2.11). A response without an id_token is refused.
4. **UserInfo** — when enabled, fetched with the access token and bound to the
   id_token's `sub`; a mismatch is refused. UserInfo values fill `email`,
   `emailVerified`, `name`, `picture` and `groups`, falling back to the
   id_token's claims. `email_verified` is normalised to a boolean (some IdPs
   send `"true"`); `groups` is carried only as a string array.
5. **Identity** — `sub` is opaque and stable per issuer; the profile is never
   keyed on `email`. The session routes hand `<name>:<sub>` to the Store
   exactly as they do for Google or GitHub. **An identity the Store does not
   know is refused with `401 unknown_user`** — this package provisions nothing;
   the Store stays the source of truth for who exists.

Any refusal in steps 2–4 surfaces from the callback as `502 exchange_failed`
(the session routes' answer to an upstream exchange the provider refused) and
never reaches the Store.

### Optional capabilities

- `SupportsRefresh` — `refreshToken()` runs the `refresh_token` grant at the
  issuer.
- `SupportsLogout` — present only when the issuer publishes an
  `end_session_endpoint` (or `endpoints.endSessionEndpoint` names one):
  RP-initiated logout with `id_token_hint`, `post_logout_redirect_uri` and
  `state`.
- `SupportsClaimMapping` — `mapClaims()` promotes `email`, `emailVerified`,
  `name`, `picture` and `groups`; everything else stays namespaced under the
  federation per the claim precedence rules in the session package.

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

- `createOidcProvider(name, config): Promise<OidcProvider>` — the provider
  itself; asynchronous because discovery happens here.
- `oidcFederationModule(name): Module` — one const-Module per instance,
  requiring `oidcFederationConfigs` and contributing `federations.<name>` and
  `federationRedirectPolicies.<name>`.
- `readOidcFederationConfigs(federations)` — the slot from a `federations`
  config section; refuses a malformed field by `federations.<name>.<field>`.
- `oidcFederationNames(federations)` — the names of every enabled section of
  type `oidc`, sorted.
- `OIDC_FEDERATION_TYPE` (`"oidc"`), `DEFAULT_OIDC_SCOPES`.
- Types: `OidcProviderConfig`, `OidcEndpointOverrides`, `OidcPrivateKey`,
  `OidcProvider`.
