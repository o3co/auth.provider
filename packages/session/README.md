# @o3co/auth-provider-session

Session and federation routes module for [auth.provider](../../README.md).

Handles username/password login, logout, and OAuth 2.0 federation. Concrete
providers such as Google and GitHub live in separate provider packages and
contribute their `FederationProvider` to this module via the manifest model
(per-federation `defineModule(...)` — see
[`@o3co/auth-provider-federation-google`](../federation-google/README.md) and
[`@o3co/auth-provider-federation-github`](../federation-github/README.md)).
Uses RFC 6749 authorization code flow internally.

## Install

This package is **private** — it is not published to npm and is only available within the `auth.provider` monorepo.

```jsonc
// packages/*/package.json
{
  "dependencies": {
    "@o3co/auth-provider-session": "workspace:*"
  }
}
```

Peer dependencies (install separately in the workspace root):

```
express@^5.0.0
```

## Public API

### `sessionModule`

```typescript
import { sessionModule } from "@o3co/auth-provider-session";
// → sessionModule is a const Module (manifest), NOT a factory.
// Add it to the manifest list passed to createApp / createTestApp.
```

Const Module. Contributes two route bundles, both mounted at `/session`:

| Method | Path                                              | Description                     |
|--------|---------------------------------------------------|---------------------------------|
| GET    | /session/csrf                                     | Issue a double-submit CSRF token |
| POST   | /session/login                                    | Username / password login       |
| POST   | /session/logout                                   | Session logout                  |
| GET    | /session/oauth/federation/:name                   | Initiate OAuth federation flow  |
| GET    | /session/oauth/federation/:name/callback          | Federation callback             |

The `:name` path parameter corresponds to the federation key in `config.federations` (e.g. `google`, `github`, `google-work`). Unknown names return `404`.

#### CSRF on the state-changing routes (#272)

`POST /session/login` and `POST /session/logout` accept a request that carries
**either** a same-origin (or explicitly trusted) `Origin` / `Referer`, **or** a
valid double-submit CSRF token. A request carrying neither is rejected with
`403 access_denied` — previously a missing `Origin` header skipped the check
entirely.

- **Browsers** need no change: the browser sets `Origin` on a same-origin
  `fetch` / form post, and that satisfies the check on its own.
- **Header-less clients** (curl, server-side agents, test harnesses) call
  `GET /session/csrf`, which sets a JS-readable `<session.name>.csrf` cookie
  and returns the same value as `csrf_token`. Send both back: the cookie plus
  either an `x-csrf-token` header or a `csrf_token` form field.
- A **foreign** `Origin` is rejected even when a token is present, since it is
  positive evidence of a cross-site request.
- A successful login returns a **fresh** CSRF cookie, so the follow-up logout
  needs no extra round trip.

The token is a signed, stateless HMAC over a random nonce and an expiry, keyed
by an HKDF expansion of `session.secret` — a subdomain able to write the
parent-domain cookie still cannot forge one. Cross-origin login UIs list their
origin on `session.csrf.trustedOrigins`; `cors.allowedOrigins` no longer grants
CSRF trust.

`checkRequestOrigin`, `createCsrfProtection`, `createCsrfProtectionFromConfig`,
`createCsrfGuard` and `createCsrfIssueHandler` are exported for compositions
that mount their own login page or protect their own routes.

`requires`: `userRepository`, `userSessionStore`, `federationTokenStore`,
`sessionFederationIndex` (sibling stores), plus the synthetic keys
`federationProviders` and `federationRedirectPolicyResolver` populated by the
boot planner from per-federation modules. See
[`@o3co/auth-provider-federation-google`](../federation-google/README.md) for an
example federation module.

---

### `extractFederationSection`

```typescript
function extractFederationSection(
  federations: Record<string, unknown>,
  name: string,
): { type: string; [key: string]: unknown } | undefined;
```

Pure utility — normalizes a federation config slice into a flat credential
object. Handles flat (`{ enabled, clientId, callbackURL }`), nested
(`{ enabled, type, [type]: {...} }`), and shorthand (key serves as type)
shapes; rejects mixed shapes; returns `undefined` for absent or
`enabled !== true` entries. Used by per-federation modules to read their own
config slice.

---

### `FederationProvider` (interface)

```typescript
interface FederationProvider {
  readonly name: string;
  readonly scope: readonly string[];

  buildAuthorizationUrl(params: {
    readonly redirectUri: string;
    readonly state: string;
    readonly codeVerifier: string;
  }): URL;

  exchangeCode(params: {
    readonly code: string;
    readonly codeVerifier: string;
    readonly redirectUri: string;
  }): Promise<FederationProfile>;
}
```

Implement this interface to add a custom OAuth 2.0 / OIDC federation provider. Optionally mix in `SupportsLogout`, `SupportsClaimMapping`, or `SupportsRefresh`.

- `name` — unique provider identifier. Used as both the Map key in `federationProviders` and the route `:name` parameter.
- `scope` — OAuth 2.0 scopes to request.
- `buildAuthorizationUrl` — builds the RFC 6749 §4.1 + RFC 7636 authorization URL. Receives a pre-generated `codeVerifier` from the route layer; implementations should compute `code_challenge` via `codeChallenge(codeVerifier)`.
- `exchangeCode` — exchanges an authorization code for a normalized `FederationProfile`. Must include `issuer` and `sub`; all other fields are optional.

> **Note (A5 split, v0.5.0):** redirect URL handling — `validateRedirect` /
> `resolveCallbackRedirect` — was moved off `FederationProvider` and onto a
> dedicated `FederationRedirectPolicy` capability. Per-federation modules
> contribute the policy via `federationRedirectPolicies.<name>`; built-ins
> use `createFederationRedirectPolicy(...)`. Custom providers do not
> implement these methods on `FederationProvider`.

---

### `SupportsLogout` (optional capability)

Optional capability for providers whose IdP exposes an OIDC RP-Initiated Logout (end-session) endpoint.

```ts
interface EndSessionRequest {
  idTokenHint?: string;
  postLogoutRedirectUri?: string;
  state?: string;
}

interface EndSessionResult {
  url: URL;
  method: "GET";
}

interface SupportsLogout {
  endSession(req: EndSessionRequest): Promise<EndSessionResult>;
}

function supportsLogout(
  provider: FederationProvider | undefined | null,
): provider is FederationProvider & SupportsLogout;
```

Provider packages may implement `SupportsLogout` when the upstream IdP exposes
an end-session endpoint. External integrations (Microsoft Entra ID, Auth0,
Okta, etc.) can add the capability by mixing it into their custom provider.

Minimum custom provider example:

```ts
import type {
  FederationProvider,
  SupportsLogout,
  EndSessionRequest,
  EndSessionResult,
} from "@o3co/auth-provider-session";

function createMyIdPProvider(): FederationProvider & SupportsLogout {
  return {
    name: "myidp",
    scope: ["openid"],
    buildAuthorizationUrl({ redirectUri, state, codeVerifier }) { /* ... */ },
    async exchangeCode({ code, codeVerifier, redirectUri }) { /* ... */ },
    async endSession(req: EndSessionRequest): Promise<EndSessionResult> {
      const url = new URL("https://myidp.example/oidc/logout");
      if (req.idTokenHint) url.searchParams.set("id_token_hint", req.idTokenHint);
      if (req.postLogoutRedirectUri) url.searchParams.set("post_logout_redirect_uri", req.postLogoutRedirectUri);
      if (req.state) url.searchParams.set("state", req.state);
      return { url, method: "GET" };
    },
  };
}
```

Consumers detect the capability at the call site:

```ts
import { supportsLogout } from "@o3co/auth-provider-session";

if (supportsLogout(provider)) {
  const { url } = await provider.endSession({ idTokenHint, postLogoutRedirectUri, state });
  res.redirect(url.toString());
} else {
  // fall back to local session destroy only
}
```

---

### `SupportsClaimMapping` (optional capability)

Optional capability for providers that can produce a normalized claim set from an OAuth profile.

```ts
interface MappedClaims {
  readonly email?: string;
  readonly emailVerified?: boolean;
  readonly name?: string;
  readonly picture?: string;
  readonly groups?: ReadonlyArray<string>;
  readonly [key: string]: unknown;   // non-standard IdP claims (e.g. Google's "hd")
}

interface FederationProfile {
  readonly issuer: string;
  readonly sub: string;             // OIDC sub — stable identifier at this IdP
  readonly email?: string;
  readonly emailVerified?: boolean;
  readonly name?: string;
  readonly picture?: string;
  readonly accessToken?: string;
  readonly refreshToken?: string;
  readonly idToken?: string;
  // absolute expiry of accessToken, or null when the provider issues no finite expiry
  // (e.g. GitHub OAuth Apps classic tokens). Required; consumers MUST treat null as
  // "do not refresh; reuse".
  readonly expiresAt: Date | null;
  readonly [key: string]: unknown;  // provider-specific extension claims
}

interface SupportsClaimMapping {
  mapClaims(profile: FederationProfile): MappedClaims;
}

function supportsClaimMapping(
  provider: FederationProvider | undefined | null,
): provider is FederationProvider & SupportsClaimMapping;
```

Providers that implement `SupportsClaimMapping` translate a `FederationProfile` into OIDC-standard claim names. Custom providers can add it by exposing a `mapClaims` method:

```ts
import { supportsClaimMapping } from "@o3co/auth-provider-session";

if (supportsClaimMapping(provider)) {
  const claims = provider.mapClaims(profile);
  // claims.email, claims.name, claims.picture …
}
```

---

### `SupportsRefresh` (optional capability)

Optional capability for providers that can exchange a refresh token for a fresh access token.

> **Note**: `SupportsRefresh` and `supportsRefresh` are internal capability types used by the session package's federation wiring. They are not re-exported from `@o3co/auth-provider-session`'s public entrypoint and are not a stable public API (subject to change before 1.0). Custom providers implementing this capability should declare the interface shape locally or import from the package's internal federations module.

The interface shape is:

```ts
type RefreshedTokens = Omit<FederationProfile, "issuer" | "sub"> & {
  readonly issuer?: string;
  readonly sub?: string;
};

interface SupportsRefresh {
  refreshToken(refreshToken: string): Promise<RefreshedTokens>;
}
```

Providers implementing `SupportsRefresh` can keep federation tokens alive without user interaction. The `FederationTokenStore` (wired via `AppOptions`) stores the initial tokens; the refresh flow retrieves and updates them automatically.

---

### Provider package notes

**`@o3co/auth-provider-federation-google`**

- Requests `openid profile email` scope by default.
- Uses stable Google OAuth/OIDC endpoints.
- `FederationProfile.sub` is the Google numeric account ID.

**`@o3co/auth-provider-federation-github`**

- Default scope is `["read:user", "user:email"]`.
- When the primary profile object omits an `email` field, the provider enriches the profile by calling the GitHub `/user/emails` API to retrieve the primary verified email.
- `FederationProfile.sub` is the GitHub numeric user ID.
- Federation token format: `${federationName}:${sub}` where `federationName` equals the configured `name` (e.g. `"github"` by default, or `"github-enterprise"` for a custom tenant).

---

### `FederationResult<T>` (type)

```typescript
type FederationResult<T> =
  | { ok: true; value: T }
  | { ok: false; status: number; error: string; errorDescription: string };
```

Discriminated union returned by `FederationProvider` methods. Check `ok` before accessing `value`.

## Usage Example

### Basic usage

```typescript
import { createApp } from "@o3co/auth-provider-core";
import { sessionModule } from "@o3co/auth-provider-session";
import { googleFederationModule } from "@o3co/auth-provider-federation-google";

const handle = await createApp({
  modules: [
    sessionModule,                 // const — no factory call
    googleFederationModule,        // contributes federations.google + federationRedirectPolicies.google
    // ... composition-root modules that supply userRepository, the four-store split, etc.
  ],
  bootstrapComponents: { config, pathResolver },
});
```

The boot planner aggregates `federations.<name>` and
`federationRedirectPolicies.<name>` contributions from per-federation modules
into the synthetic `federationProviders` and `federationRedirectPolicyResolver`
ComponentMap entries that `sessionModule`'s federation routes consume. The
planner enforces the pairing invariant **between contribution kinds**: every
contributed `federations.<name>` MUST have a paired
`federationRedirectPolicies.<name>` and vice versa, otherwise boot fails with
`BootError({ reason: "federation-redirect-policy-unpaired" })`.

The planner does NOT cross-check `config.federations` against contributions —
if a federation is enabled in config but no module contributes its provider
pair, boot still succeeds and `/session/oauth/federation/:name` returns `404`
at request time. Composition roots that want fail-fast on misconfiguration
should add the matching per-federation module (or a config-bootstrap module
that throws when its federation slice is enabled but no provider package is
installed). `sessionModule` does enforce one config-derived invariant at boot:
every enabled federation in `config.federations` must declare a `callbackURL`,
otherwise boot fails (the same fail-fast invariant the v0.4.x module
enforced at `init()` time).

### HOCON federation configuration

**Shorthand (key name = provider type):**

```hocon
federations {
  google {
    enabled = true
    clientId = ${FEDERATIONS_GOOGLE_CLIENT_ID}
    clientSecret = ${FEDERATIONS_GOOGLE_CLIENT_SECRET}
    callbackURL = "https://auth.example.com/session/oauth/federation/google/callback"
  }

  github {
    enabled = true
    clientId = ${FEDERATIONS_GITHUB_CLIENT_ID}
    clientSecret = ${FEDERATIONS_GITHUB_CLIENT_SECRET}
    callbackURL = "https://auth.example.com/session/oauth/federation/github/callback"
  }
}
```

**Explicit multi-tenant (two Google instances):**

```hocon
federations {
  google-personal {
    enabled = true
    type = "google"
    google {
      clientId = ${FEDERATIONS_GOOGLE_PERSONAL_CLIENT_ID}
      clientSecret = ${FEDERATIONS_GOOGLE_PERSONAL_CLIENT_SECRET}
      callbackURL = "https://auth.example.com/session/oauth/federation/google-personal/callback"
    }
  }

  google-work {
    enabled = true
    type = "google"
    google {
      clientId = ${FEDERATIONS_GOOGLE_WORK_CLIENT_ID}
      clientSecret = ${FEDERATIONS_GOOGLE_WORK_CLIENT_SECRET}
      callbackURL = "https://auth.example.com/session/oauth/federation/google-work/callback"
    }
  }
}
```

Mixed shape — top-level fields alongside a nested sub-section — is rejected with a clear error at startup.

### Custom federation provider

Custom federations are added by writing a per-federation `defineModule(...)`
that contributes both `federations.<name>` (the `FederationProvider`) and
`federationRedirectPolicies.<name>` (the redirect policy). The const-Module
pattern with a typed `ComponentMap` config slot is the recommended shape — see
[`@o3co/auth-provider-federation-google`'s `google.mts`](../federation-google/src/google.mts)
for the reference implementation. The minimal sketch:

```typescript
import { defineModule } from "@o3co/auth-provider-core";
import {
  codeChallenge,
  createFederationRedirectPolicy,
  type FederationProvider,
} from "@o3co/auth-provider-session";

declare module "@o3co/auth-provider-core" {
  interface ComponentMap {
    readonly microsoftFederationConfig?: { clientId: string; callbackURL: string };
  }
}

export const microsoftFederationModule = defineModule({
  name: "federation:microsoft",
  requires: ["microsoftFederationConfig"] as const,
  contributes: {
    federations: {
      microsoft: (deps) => buildMicrosoftProvider(deps.microsoftFederationConfig),
    },
    federationRedirectPolicies: {
      microsoft: (deps) => createFederationRedirectPolicy(deps.microsoftFederationConfig),
    },
  },
});

function buildMicrosoftProvider(cfg: { clientId: string; callbackURL: string }): FederationProvider {
  return {
    name: "microsoft",
    scope: ["openid", "profile", "email"],
    buildAuthorizationUrl({ redirectUri, state, codeVerifier }) {
      const url = new URL("https://login.microsoftonline.com/common/oauth2/v2.0/authorize");
      url.searchParams.set("client_id", cfg.clientId);
      url.searchParams.set("redirect_uri", redirectUri);
      url.searchParams.set("state", state);
      url.searchParams.set("code_challenge", codeChallenge(codeVerifier));
      url.searchParams.set("code_challenge_method", "S256");
      url.searchParams.set("scope", "openid profile email");
      return url;
    },
    async exchangeCode({ code, codeVerifier, redirectUri }) {
      // POST to token endpoint + optional userinfo; normalize to FederationProfile
      return { issuer: "https://login.microsoftonline.com/common/v2.0", sub: "...", expiresAt: null };
    },
  };
}
```

The composition root supplies `microsoftFederationConfig` via a small
config-bootstrap module that runs `extractFederationSection(config.federations,
"microsoft")` and surfaces the credentials on the typed slot. The session
module's federation routes consume the aggregated `federationProviders` map
and route by `:name`.

## TODO-F-3 changes

- **Local login session tracking.** `POST /session/login` now creates a `UserSession` record via `userSessionStore.create()` and writes the resulting `sid` into `req.session.sid` when `AppOptions.userSessionStore` is wired. This mirrors the federation-callback session-creation path established in F-2 and ensures that tokens issued after a local login carry a valid `sid` claim.

## Migrating from v0.3.x to v0.4.0

v0.4.0 removes passport as a direct dependency from this package.

### Breaking changes

1. **`FederationProviderBase` renamed to `FederationProvider`.** If you implement custom providers, rename the interface in your imports.
2. **`setupPassportStrategy(passport, ctx)` removed.** Implement `buildAuthorizationUrl({ redirectUri, state, codeVerifier }): URL` and `exchangeCode({ code, codeVerifier, redirectUri }): Promise<FederationProfile>` instead. The new interface is vendor-agnostic — no passport types leak into the signature.
3. **`FederationProfile.raw` removed.** OIDC-standard claims are first-class fields (`sub`, `email`, `emailVerified`, `name`, `picture`, `accessToken`, `refreshToken`, `idToken`, `expiresAt`). Provider-specific claims (Google `hd`, Microsoft `tid`) are carried by the index signature `[key: string]: unknown`.
4. **`FederationProfile.id` renamed to `sub`, `expiresIn: number` replaced with `expiresAt: Date | null` (required).** Adapters MUST make an explicit decision: return a `Date` when the provider issues a finite expiry, `null` when it does not (e.g. GitHub OAuth Apps classic tokens). The route layer no longer invents a fallback expiry — `null` signals "do not refresh; reuse until the provider invalidates". `FederationTokens.expiresAt` on `FederationTokenStore` follows the same contract.
5. **`createPassport()` and `SetupPassportContext` removed from the public API.** State (CSRF) and PKCE are managed by the route layer internally; providers are pure functions.
6. **`UserSessionStore` and `FederationTokenStore` are now required** (previously optional with legacy fallback). They are now declared in `sessionModule.requires`; the boot planner rejects with `BootError(reason: 'missing-required-component')` if no module provides them.
7. **`/login` error responses** follow RFC 6749 §5.2 shape: `{ error, error_description }`. If your client parses the old `{ message: "..." }` format, update accordingly.
8. **`SupportsRefresh.refreshToken`** returns `RefreshedTokens` (new type): `Omit<FederationProfile, "issuer"|"sub"> & { issuer?: string; sub?: string }`. Google/GitHub refresh responses legitimately omit `sub`; the route layer preserves stored identity.

### Custom provider migration example

**Before (v0.3.x, passport-based):**

```ts
class CustomProvider implements FederationProviderBase {
  name = "custom";
  scope = ["openid"];
  async setupPassportStrategy(passport, ctx) {
    passport.use(this.name, new CustomStrategy({...}, (accessToken, refreshToken, profile, done) => {
      done(null, { id: profile.id, raw: profile });
    }));
  }
  validateRedirect(url) { /* ... */ }
  resolveCallbackRedirect(session) { /* ... */ }
}
```

**After (v0.4.0, pure-function interface):**

```ts
import { codeChallenge } from "@o3co/auth-provider-session";

class CustomProvider implements FederationProvider, SupportsClaimMapping {
  readonly name = "custom";
  readonly scope = ["openid"] as const;
  buildAuthorizationUrl({ redirectUri, state, codeVerifier }) {
    const url = new URL("https://idp.example.com/authorize");
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", this.clientId);
    url.searchParams.set("redirect_uri", redirectUri);
    url.searchParams.set("state", state);
    url.searchParams.set("code_challenge", codeChallenge(codeVerifier));
    url.searchParams.set("code_challenge_method", "S256");
    url.searchParams.set("scope", this.scope.join(" "));
    return url;
  }
  async exchangeCode({ code, codeVerifier, redirectUri }) {
    // POST to token endpoint + optional userinfo; normalize to FederationProfile
    return {
      issuer: "https://idp.example.com",
      sub: userId,
      email,
      accessToken,
      refreshToken,
      expiresAt,
    };
  }
  mapClaims(profile) { return { email: profile.email }; }
  validateRedirect(url) { /* unchanged */ }
  resolveCallbackRedirect(session) { /* unchanged */ }
}
```

### Module wiring

In v0.5.0 `sessionModule` is a const Module (no factory call). Its
`requires` declares the dependencies the boot planner must supply:
`userRepository`, the four-store split (`userSessionStore`,
`federationTokenStore`, `sessionFederationIndex`), and the synthetic keys
`federationProviders` + `federationRedirectPolicyResolver`.

## See Also

- [`@o3co/auth-provider-oauth`](../oauth/README.md) — OAuth 2.0 token and authorization routes
- [`@o3co/auth-provider-core`](../core/README.md) — shared types (`Module`, `UserRepository`, `PathResolver`, `AppConfig`)
