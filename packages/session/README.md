# @o3co/auth-provider-session

Session and federation routes module for [auth.provider](../../README.md).

Handles username/password login, logout, and OAuth 2.0 federation (Google, GitHub, and any provider registered via `FederationProviderFactory`). Uses Passport.js internally for strategy management.

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
passport@^0.7.0               (optional)
passport-local@^1.0.0         (optional)
passport-google-oauth20@^2.0.0 (optional)
passport-github2@^0.1.12      (optional — GitHub federation only)
```

GitHub federation requires `passport-github2` and `@types/passport-github2` to be installed separately. Since they are optional peer dependencies, you opt in by running:

```bash
pnpm add passport-github2 @types/passport-github2
```

Google-only or federation-less deployments pay no install cost for this package.

## Public API

### `sessionModule`

```typescript
function sessionModule(params: {
  userRepository: UserRepository;
  express?: ExpressLike;
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

### `createPassport`

```typescript
function createPassport(options: {
  userRepository: UserRepository;
  federationProviders: ReadonlyMap<string, FederationProviderBase>;
  pathResolver: PathResolver;  // required; used for dynamic imports of passport/passport-local and threaded through to FederationProviderBase.setupPassportStrategy
}): Promise<PassportStatic>;
```

Creates and configures a Passport instance.

- **LocalStrategy** — authenticates with `username` and `password` fields.
- **Federation strategies** — registered for each provider in `federationProviders` by calling `provider.setupPassportStrategy(passport, { verifyUser, pathResolver })`.

---

### `createFederationProviderFactory`

```typescript
function createFederationProviderFactory(): FederationProviderFactory;
```

Creates an empty `FederationProviderFactory` (an `AdapterFactory<FederationProviderBase>` with no built-in types registered). Call `registerBuiltinFederations(factory)` to register the built-in `"google"` and `"github"` types, then call `factory.register(type, builder)` to add your own.

---

### `registerBuiltinFederations`

```typescript
function registerBuiltinFederations(factory: FederationProviderFactory): void;
```

Registers the built-in federation adapters into `factory`:

| Type       | Provider               | Required peer dep              |
|------------|------------------------|--------------------------------|
| `"google"` | `createGoogleProvider` | `passport-google-oauth20`      |
| `"github"` | `createGithubProvider` | `passport-github2` (optional)  |

---

### `createGoogleProvider`

```typescript
function createGoogleProvider(config: {
  name: string;
  clientId: string;
  clientSecret: string;
  callbackURL: string;
  sessionDomain?: string;
  authCallbackUrl?: string;
  clientUrl?: string;
}): FederationProviderBase;
```

Creates a `FederationProviderBase` for Google OAuth 2.0. The strategy is registered in Passport under `config.name`, which enables multi-tenant usage (e.g. `google` and `google-work` as separate instances).

---

### `createGithubProvider`

```typescript
function createGithubProvider(config: {
  name: string;
  clientId: string;
  clientSecret: string;
  callbackURL: string;
  sessionDomain?: string;
  authCallbackUrl?: string;
  clientUrl?: string;
}): FederationProviderBase;
```

Creates a `FederationProviderBase` for GitHub OAuth 2.0. Uses `passport-github2` (optional peer dep — must be installed separately). The default scope is `["read:user", "user:email"]`. The `externalId` format is `${federationName}:${profile.id}` where `federationName` is the configured `name` on the provider (e.g. `"github"` by default, or `"github-enterprise"` if you customize).

---

### `FederationProviderBase` (interface)

```typescript
interface FederationProviderBase {
  readonly name: string;
  readonly scope: readonly string[];
  validateRedirect(url: string): FederationResult<void>;
  resolveCallbackRedirect(session: { redirectTo?: string }): FederationResult<string>;
  setupPassportStrategy(passport: PassportStatic, ctx: SetupPassportContext): Promise<void>;
}

interface SetupPassportContext {
  verifyUser: (externalId: string) => Promise<User | null>;
  pathResolver?: (spec: string) => string;  // optional; for Yarn PnP and other non-standard module layouts
}
```

Implement this interface to add a custom OAuth 2.0 / OIDC federation provider. Optionally mix in `SupportsLogout` for IdPs that expose an end-session endpoint.

- `name` — unique passport strategy identifier. Used as both the Map key in `federationProviders` and the strategy name passed to `passport.use()`.
- `scope` — OAuth 2.0 scopes to request.
- `validateRedirect` — validates whether a redirect URL is permitted before initiating the federation flow.
- `resolveCallbackRedirect` — resolves the post-callback redirect target from the session.
- `setupPassportStrategy` — registers the Passport strategy. Called once during module initialization.

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
  provider: FederationProviderBase | undefined | null,
): provider is FederationProviderBase & SupportsLogout;
```

The built-in `"google"` and `"github"` providers **do not** implement `SupportsLogout`: Google has no public OIDC end-session endpoint, and GitHub is OAuth2-only. External integrations (Microsoft Entra ID, Auth0, Okta, …) can add the capability by mixing it into their custom provider.

Minimum custom provider example:

```ts
import type {
  FederationProviderBase,
  SupportsLogout,
  EndSessionRequest,
  EndSessionResult,
} from "@o3co/auth-provider-session";

function createMyIdPProvider(): FederationProviderBase & SupportsLogout {
  return {
    name: "myidp",
    scope: ["openid"],
    validateRedirect(url) { /* ... */ },
    resolveCallbackRedirect(session) { /* ... */ },
    async setupPassportStrategy(passport, ctx) { /* ... */ },
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
  readonly id: string;                 // provider-internal user id
  readonly raw: Readonly<Record<string, unknown>>;  // raw passport profile object
  readonly accessToken?: string;
  readonly refreshToken?: string;
  readonly idToken?: string;
  readonly expiresIn?: number;
}

interface SupportsClaimMapping {
  mapClaims(profile: FederationProfile): MappedClaims;
}

function supportsClaimMapping(
  provider: FederationProviderBase | undefined | null,
): provider is FederationProviderBase & SupportsClaimMapping;
```

Providers that implement `SupportsClaimMapping` translate raw passport profile data into OIDC-standard claim names. The built-in `"google"` and `"github"` providers implement this capability. Custom providers can add it by exposing a `mapClaims` method:

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

```ts
interface RefreshedTokens {
  readonly accessToken: string;
  readonly refreshToken?: string;
  readonly idToken?: string;
  readonly expiresAt: Date;
}

interface SupportsRefresh {
  refreshFederationToken(refreshToken: string): Promise<RefreshedTokens>;
}

function supportsRefresh(
  provider: FederationProviderBase | undefined | null,
): provider is FederationProviderBase & SupportsRefresh;
```

Providers implementing `SupportsRefresh` can keep federation tokens alive without user interaction. The `FederationTokenStore` (wired via `AppOptions`) stores the initial tokens; the refresh flow retrieves and updates them automatically.

```ts
import { supportsRefresh } from "@o3co/auth-provider-session";

if (supportsRefresh(provider)) {
  const refreshed = await provider.refreshFederationToken(storedRefreshToken);
  // refreshed.accessToken, refreshed.expiresAt …
}
```

---

### `onFederationCallback` hook

`SetupPassportContext` carries an optional `onFederationCallback` hook:

```ts
readonly onFederationCallback?: (params: {
  readonly federationName: string;
  readonly profile: FederationProfile;
  readonly req: import("express").Request;
  readonly done: (err: Error | null, user: User | false) => void;
}) => Promise<void>;
```

**Built-in behaviour:** When `sessionModule` wires the passport context, it injects a built-in `onFederationCallback` implementation automatically — but only when **both** `UserSessionStore` and `FederationTokenStore` are configured in `AppOptions`. The built-in hook:

1. Looks up a `User` via `UserRepository.authenticateByToken(`${federationName}:${profile.id}`)`. If your deployment auto-provisions users on first federation login, implement that inside your `authenticateByToken`.
2. Saves the IdP tokens to `FederationTokenStore`.
3. Calls `done(null, user)` on success.

When either store is absent the module falls back to the legacy `verifyUser(externalId)` path, which is sufficient for deployments that do not need token persistence.

Custom providers never need to implement this hook — they receive it via `SetupPassportContext.onFederationCallback` and call it from inside `setupPassportStrategy`. The hook abstraction keeps provider code free of store dependencies.

---

### Built-in provider notes

**Google provider (`createGoogleProvider`)**

- Requests `openid profile email` scope by default (the `openid` scope was added to ensure Google returns an ID token alongside the access token).
- Uses `passReqToCallback: true` so the `onFederationCallback` hook can access the Express request object for session data.

**GitHub provider (`createGithubProvider`)**

- Default scope is `["read:user", "user:email"]`.
- When the primary profile object omits an `email` field, the provider enriches the profile by calling the GitHub `/user/emails` API to retrieve the primary verified email.
- `externalId` format: `${federationName}:${profile.id}` where `federationName` equals the configured `name` (e.g. `"github"` by default, or `"github-enterprise"` for a custom tenant).

---

### `FederationProviderFactory` (type)

```typescript
type FederationProviderFactory = AdapterFactory<FederationProviderBase>;
```

An `AdapterFactory<FederationProviderBase>`. Register custom provider types via `factory.register(type, builder)`.

---

### `FederationResult<T>` (type)

```typescript
type FederationResult<T> =
  | { ok: true; value: T }
  | { ok: false; status: number; error: string; errorDescription: string };
```

Discriminated union returned by `FederationProviderBase` methods. Check `ok` before accessing `value`.

## Usage Example

### Basic usage

```typescript
import express from "express";
import { createApp } from "@o3co/auth-provider-core";
import { sessionModule } from "@o3co/auth-provider-session";

const app = createApp(express, {
  config,
  keyStore,
  modules: [
    sessionModule({
      userRepository,
    }),
  ],
});
await app.init();
```

The `sessionModule` reads `config.federations` and wires up providers automatically using `createFederationProviderFactory` + `registerBuiltinFederations` internally.

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
  createFederationProviderFactory,
  registerBuiltinFederations,
  type FederationProviderBase,
  type FederationProviderFactory,
} from "@o3co/auth-provider-session";

// Create factory and register built-ins
const factory = createFederationProviderFactory();
registerBuiltinFederations(factory);

// Register a custom provider type
factory.register("microsoft", async (config) => {
  // build and return a FederationProviderBase
  return {
    name: config.name as string,
    scope: ["openid", "profile", "email"],
    validateRedirect: (url) => ({ ok: true, value: undefined }),
    resolveCallbackRedirect: (session) => ({ ok: true, value: session.redirectTo ?? "/" }),
    setupPassportStrategy: async (passport, { verifyUser }) => {
      // register passport-microsoft or similar
    },
  };
});

// Build the provider map from config — mirrors the normalization in module.mts
const federationProviders = new Map<string, FederationProviderBase>();
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

## See Also

- [`@o3co/auth-provider-oauth`](../oauth/README.md) — OAuth 2.0 token and authorization routes
- [`@o3co/auth-provider-did`](../did/README.md) — DID authentication grant
- [`@o3co/auth-provider-core`](../core/README.md) — shared types (`Module`, `UserRepository`, `PathResolver`, `AppConfig`)
