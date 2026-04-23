# @o3co/auth-provider-session

Session and federation routes module for [auth.provider](../../README.md).

Handles username/password login, logout, and OAuth 2.0 federation for providers
registered with `FederationProviderFactory`. Uses RFC 6749 authorization code
flow internally. Concrete providers such as Google and GitHub live in separate
provider packages.

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
function sessionModule(params: {
  userRepository: UserRepository;
  express?: ExpressLike;
  federationProviderFactory?: FederationProviderFactory;
}): Module;
```

Top-level module. Mounts session and federation routes onto the Express app.

Routes mounted:

| Method | Path                                              | Description                     |
|--------|---------------------------------------------------|---------------------------------|
| POST   | /session/login                                    | Username / password login       |
| POST   | /session/logout                                   | Session logout                  |
| GET    | /session/oauth/federation/:name                   | Initiate OAuth federation flow  |
| GET    | /session/oauth/federation/:name/callback          | Federation callback             |

The `:name` path parameter corresponds to the federation key in `config.federations` (e.g. `google`, `github`, `google-work`). Unknown names return `404`.

---

### `createFederationProviderFactory`

```typescript
function createFederationProviderFactory(): FederationProviderFactory;
```

Creates an empty `FederationProviderFactory` (an `AdapterFactory<FederationProvider>` with no provider types registered). Install provider packages and register them in the composition root, then pass the factory to `sessionModule`.

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

  validateRedirect(url: string): FederationResult<void>;
  resolveCallbackRedirect(session: { redirectTo?: string }): FederationResult<string>;
}
```

Implement this interface to add a custom OAuth 2.0 / OIDC federation provider. Optionally mix in `SupportsLogout` for IdPs that expose an end-session endpoint.

- `name` — unique provider identifier. Used as both the Map key in `federationProviders` and the route `:name` parameter.
- `scope` — OAuth 2.0 scopes to request.
- `buildAuthorizationUrl` — builds the RFC 6749 §4.1 + RFC 7636 authorization URL. Receives a pre-generated `codeVerifier` from the route layer; implementations should compute `code_challenge` via `codeChallenge(codeVerifier)`.
- `exchangeCode` — exchanges an authorization code for a normalized `FederationProfile`. Must include `issuer` and `sub`; all other fields are optional.
- `validateRedirect` — validates whether a redirect URL is permitted before initiating the federation flow.
- `resolveCallbackRedirect` — resolves the post-callback redirect target from the session.

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
    validateRedirect(url) { /* ... */ },
    resolveCallbackRedirect(session) { /* ... */ },
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

### `FederationProviderFactory` (type)

```typescript
type FederationProviderFactory = AdapterFactory<FederationProvider>;
```

An `AdapterFactory<FederationProvider>`. Register custom provider types via `factory.register(type, builder)`.

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
import express from "express";
import { createApp } from "@o3co/auth-provider-core";
import {
  createFederationProviderFactory,
  sessionModule,
} from "@o3co/auth-provider-session";
import { registerGoogleFederation } from "@o3co/auth-provider-federation-google";

const federationProviderFactory = createFederationProviderFactory();
registerGoogleFederation(federationProviderFactory);

const app = createApp(express, {
  config,
  keyStore,
  modules: [
    sessionModule({
      userRepository,
      federationProviderFactory,
    }),
  ],
});
await app.init();
```

The `sessionModule` reads `config.federations` and creates providers using the
factory supplied by the composition root. If a federation type is enabled in
config but no package registered that type, boot fails fast.

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

```typescript
import {
  codeChallenge,
  createFederationProviderFactory,
  type FederationProvider,
  type FederationProviderFactory,
} from "@o3co/auth-provider-session";

const factory = createFederationProviderFactory();

// Register a custom provider type
factory.register("microsoft", async (config) => {
  // build and return a FederationProvider
  return {
    name: config.name as string,
    scope: ["openid", "profile", "email"],
    buildAuthorizationUrl({ redirectUri, state, codeVerifier }) {
      const url = new URL("https://login.microsoftonline.com/common/oauth2/v2.0/authorize");
      url.searchParams.set("response_type", "code");
      url.searchParams.set("client_id", config.clientId as string);
      url.searchParams.set("redirect_uri", redirectUri);
      url.searchParams.set("state", state);
      url.searchParams.set("code_challenge", codeChallenge(codeVerifier));
      url.searchParams.set("code_challenge_method", "S256");
      url.searchParams.set("scope", "openid profile email");
      return url;
    },
    async exchangeCode({ code, codeVerifier, redirectUri }) {
      // POST to token endpoint + optional userinfo; normalize to FederationProfile
      return { issuer: "https://login.microsoftonline.com/common/v2.0", sub: userId, email, accessToken, expiresAt };
    },
    validateRedirect: (url) => ({ ok: true, value: undefined }),
    resolveCallbackRedirect: (session) => ({ ok: true, value: session.redirectTo ?? "/" }),
  };
});

// Build the provider map from config — mirrors the normalization in module.mts
const federationProviders = new Map<string, FederationProvider>();
for (const [name, section] of Object.entries(config.federations)) {
  if (!section.enabled) continue;

  const type = (typeof section.type === "string" ? section.type : undefined) ?? name;
  const subSection = (section as Record<string, unknown>)[type];
  const isNested =
    typeof subSection === "object" && subSection !== null && !Array.isArray(subSection);

  const rawBuilderConfig = isNested
    ? (() => {
        const { enabled: _e, type: _t, [type]: _sub, ...topLevel } = section as Record<string, unknown>;
        return { type, ...topLevel, ...(subSection as Record<string, unknown>) };
      })()
    : { type, ...(section as Record<string, unknown>) };

  const { enabled: _e2, type: _t2, ...flatConfig } = rawBuilderConfig as Record<string, unknown>;
  const provider = await factory.create({ type, name, ...flatConfig });
  federationProviders.set(name, provider);
}
```

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
6. **`UserSessionStore` and `FederationTokenStore` are now required** (previously optional with legacy fallback). The `sessionModule` throws at `init()` time if either is absent from `ModuleContext`.
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

`sessionModule` requires `userRepository` (for `/login`). `userSessionStore` + `federationTokenStore` from `ModuleContext` are now **required**.

## See Also

- [`@o3co/auth-provider-oauth`](../oauth/README.md) — OAuth 2.0 token and authorization routes
- [`@o3co/auth-provider-did`](../did/README.md) — DID authentication grant
- [`@o3co/auth-provider-core`](../core/README.md) — shared types (`Module`, `UserRepository`, `PathResolver`, `AppConfig`)
