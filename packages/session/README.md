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
  readonly responseMode?: "query" | "form_post";   // default "query"

  buildAuthorizationUrl(params: {
    readonly redirectUri: string;
    readonly state: string;
    readonly codeVerifier: string;
    readonly nonce?: string;
  }): URL;

  exchangeCode(params: {
    readonly code: string;
    readonly codeVerifier: string;
    readonly redirectUri: string;
    readonly nonce?: string;
    readonly callbackParams?: Readonly<Record<string, string>>;
  }): Promise<FederationProfile>;
}
```

Implement this interface to add a custom OAuth 2.0 / OIDC federation provider. Optionally mix in `SupportsLogout`, `SupportsClaimMapping`, or `SupportsRefresh`.

- `name` — unique provider identifier. Used as both the Map key in `federationProviders` and the route `:name` parameter.
- `scope` — OAuth 2.0 scopes to request.
- `buildAuthorizationUrl` — builds the RFC 6749 §4.1 + RFC 7636 authorization URL. Receives a pre-generated `codeVerifier` from the route layer; implementations should compute `code_challenge` via `codeChallenge(codeVerifier)`.
- `exchangeCode` — exchanges an authorization code for a normalized `FederationProfile`. Must include `issuer` and `sub`; all other fields are optional.
- `responseMode` — how the IdP delivers the authorization response. Optional, and absence means `"query"`, so every provider written before #479 is unaffected. See below.
- `callbackParams` — the rest of the callback's parameters (query string or form body), string values only, **excluding `code` and `state`**. Those two are the framework's to bind and are already accounted for — `code` has its own field, `state` is what the route compared against the session — so they are not repeated in a generic bag where an adapter could read the unvalidated copy. What remains is present so an IdP that returns identity data *beside* the token response can be adapted: Sign in with Apple sends the end user's name once, in a `user` JSON field on the first authorization, and never in the id_token. **The values are relayed through the user agent and are not signed** — the `state` check binds them to the session and binds nothing else, so treat anything read here as self-asserted and let `mapClaims` + claim precedence decide where it may land.

> **Note (A5 split, v0.5.0):** redirect URL handling — `validateRedirect` /
> `resolveCallbackRedirect` — was moved off `FederationProvider` and onto a
> dedicated `FederationRedirectPolicy` capability. Per-federation modules
> contribute the policy via `federationRedirectPolicies.<name>`; built-ins
> use `createFederationRedirectPolicy(...)`. Custom providers do not
> implement these methods on `FederationProvider`.

---

### Response mode: `query` and `form_post` (#479)

Most IdPs redirect the browser back to the callback with the authorization response in the query string. Sign in with Apple does not: whenever the requested `scope` includes `name` or `email`, Apple **POSTs** an `application/x-www-form-urlencoded` body to the callback, because the first-authorization `user` field does not fit a redirect URL.

A provider opts in by declaring one field:

```typescript
const appleProvider: FederationProvider = {
  name: "apple",
  scope: ["name", "email"],
  responseMode: "form_post",
  // …
};
```

That single declaration changes three things in the route layer, and nothing in the adapter:

1. **The start route appends `response_mode=form_post`** to the URL `buildAuthorizationUrl` returned. The parameter is written once, in the router, rather than in every adapter — and nothing at all is appended for the default mode, so a `"query"` federation's authorization URL is byte-for-byte what its adapter produced.
2. **`POST /oauth/federation/<name>/callback` starts accepting the form body.** It is the *same handler* as the GET callback over a different parameter source: same envelope lookup, same `state` comparison, same consume-before-any-async-work reuse prevention, same PKCE verifier and nonce read from the stored envelope rather than from the request, same rollback ladder. One handler, but not one surface: **each response mode accepts exactly one method.** A provider that did not declare `form_post` answers `405 method_not_allowed` (with `Allow: GET`) to a POST, so no existing federation gains a POST surface; a `form_post` provider answers `405 method_not_allowed` (with `Allow: POST`) to a GET, since its IdP only ever posts and its transaction cookie is offered to every cross-site request that reaches the path ([#502](https://github.com/o3co/auth.provider/issues/502)).
3. **That federation's ephemeral state moves out of the session** and into a *federation transaction* with a cookie of its own. The application session cookie is not modified.

#### The `SameSite` consequence, and what actually carries the state

A `form_post` callback arrives as a **cross-site POST** from the IdP's origin. A `SameSite=Lax` cookie — the deployment default, and the right default — is not sent on a cross-site POST, so a callback relying on the session cookie would land with no session: no `state` to compare against, no PKCE verifier. It fails closed, but it fails for everyone.

The flow therefore needs *a* cookie that survives a cross-site POST. It does **not** need the session cookie to be that cookie, and making it one was [#494](https://github.com/o3co/auth.provider/issues/494): `GET /oauth/federation/<name>` requires no authentication, and a `SameSite=Lax` cookie **is** sent on a top-level GET, so any third party who caused one navigation permanently downgraded the victim's authenticated session cookie. Permanently, because express-session serialises `req.session.cookie` into the store and `Store.prototype.createSession` rebuilds it from there — with every own key — on every later request.

So the cross-site part gets its own cookie and its own record:

| | value |
|---|---|
| cookie name | `__Secure-<session.name, minus any prefix>.federation` — e.g. `__Host-auth.session` and `auth.session` both give `__Secure-auth.session.federation` |
| attributes | `HttpOnly; Secure; SameSite=None`, `Path` scoped to that provider's callback URL, `Max-Age` = the transaction TTL (10 minutes by default) |
| contents | an opaque 256-bit id, and nothing else |
| record | `state`, `codeVerifier`, `nonce`, `redirectTo` and the provider name, in the session store under a `fedtx:` key prefix |

The name is derived from `session.name` the way the CSRF cookie's is, so it inherits the operator's naming. The prefix is the one deviation, and it is applied **unconditionally** — a session cookie with no prefix still yields a `__Secure-` transaction cookie.

`__Secure-` rather than `__Host-` because `__Host-` requires `Path=/`, and this cookie is deliberately path-scoped to the callback, so a `__Host-` name would be dropped by every browser. Unconditionally because, unlike the session cookie — whose `Secure` flag is the operator's `session.secure` to set — this cookie is `SameSite=None` and therefore always issued with `Secure` (every current browser drops a `SameSite=None` cookie that is not `Secure`; the pairing `application.schema.mts` already enforces for the config-level value, #282 — and Apple refuses a non-`https` redirect URI anyway). The prefix states that invariant where the browser will enforce it.

**The application session cookie keeps the attributes the deployment configured**, on every session, whether or not it ever started a `form_post` federation — a deployment running Apple beside Google sees no difference on any Google login, and no difference on the Apple browser's own session either.

The transaction is what binds the callback to the browser that started it, which is the property the session cookie used to provide. The `state` comparison is unchanged and still runs; the transaction cookie is an addition to it, never a replacement. A caller who presents a stolen `state` without the matching transaction cookie is refused before `state` is read at all.

Both the record and the cookie are dropped on every callback exit that **judged** the transaction — success, `invalid_state`, `exchange_failed`, `unknown_user` alike — so a transaction is single-use in the strict sense.

They are deliberately *not* dropped by a refusal that judged nothing ([#502](https://github.com/o3co/auth.provider/issues/502)). The rule is: **a refusal spends the transaction when the request made a claim about it, and leaves it alone when it made none.** A `state` is that claim. A callback carrying no `state` claims nothing and costs nothing (`400 invalid_request`, record untouched); a GET is refused with `405` before the cookie is read at all. A *wrong* `state` is different in kind — that is an attempt on this transaction, and it still spends it, so a guess gets no second try. The distinction matters because the cookie is `SameSite=None` by necessity, so it accompanies any cross-site request to the callback path: while every refusal consumed the record, a third party could destroy a victim's in-flight login with one `<img>` tag.

An abandoned flow leaves only the short-lived cookie, and the record expires with it: the expiry is written into the record as `cookie.expires`, which is exactly what `MemoryStore` reaps on read and what `connect-redis` turns into the key's `EX`.

A `"query"` federation is untouched by all of this. Its callback is a same-site top-level GET, its envelope stays in `req.session.federation`, and its authorization URL, cookies and error surface are byte-for-byte what they were.

---

### Client secrets that rotate (#479)

`clientSecret` was a `string` because most IdPs issue a long-lived opaque one. Apple's is an ES256 JWT the relying party signs itself, capped at six months, so a value would mean a deployment that silently stops authenticating half a year after it was configured.

The contract widens to a union — one field, one meaning, with the callable form saying only that the secret is computed rather than stored:

```typescript
type FederationClientSecret = string | (() => string | Promise<string>);

const secret = await resolveClientSecret(config.clientSecret);
```

- **The static form is unchanged.** `federations.google.clientSecret = "…"` in HOCON, and Google's / GitHub's provider config, keep working exactly as before — a config file can still only carry the string form.
- **`resolveClientSecret` is called once per token exchange** (and per refresh) and deliberately does **not** cache. Only the adapter knows when its secret expires, so caching belongs there: `federation-apple` regenerates its JWT when it comes within 24 h of `exp`.
- **An empty or non-string result is rejected locally**, rather than posted upstream as an empty `client_secret` and returned as an opaque `invalid_client`.

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

#### Claim precedence: local wins, federated is namespaced

What `mapClaims` returns is an **assertion by an upstream IdP**, not a fact about this deployment. The federation callback route therefore never merges it into the session's claims envelope. It applies one rule (#279):

- **The local record is authoritative.** Any claim `extractUserClaims` read off the `User` stands; a federated value never replaces it.
- **Three claims may fill a gap** — `email`, `name`, `picture` (`PROMOTABLE_FEDERATED_CLAIMS`), and only where the local record left the field absent, and only when the federated value is a string.
- **Everything else is namespaced** under `claims.federated[<providerName>]`, verbatim and complete — including values that were also promoted and values that lost to a local claim.

So an IdP cannot contribute `groups` (nor a `roles` / `scope` / `permissions` an adapter invents): those reach `claims.federated[<providerName>]` and nothing else. `filterClaimsByScope` never emits provider-specific claims, so nothing under the namespace can appear in an id_token or `/userinfo` response by accident.

**The `federated` claim is optional — read it with a presence check.** It is written only when the provider actually mapped at least one claim, so it is absent on a session whose provider implements no `SupportsClaimMapping`, and on one whose `mapClaims` returned `{}` or a non-object. The provider key is likewise not guaranteed: a session carries the one provider that authenticated it. Use `claims.federated?.[name]?.groups`, never `claims.federated[name].groups`. Absence rather than an empty `federated: {}` is deliberate — it says "this IdP asserted nothing" instead of only "a code path ran", the same absent-is-not-a-value discipline #297 established for `emailVerified`.

`emailVerified` is excluded from promotion for the same reason. Since #297 it is Store-owned state that `oauth.requireEmailVerified` can read as a gate on token issuance, and an upstream IdP verifies an address *it* controls — the `provider:sub` linkage never forces that to be the local account's address. A deployment that wants to act on the assertion reads `claims.federated?.[<providerName>]?.emailVerified` and publishes the result on the `User`, which is where #297 put the field.

```ts
// user: { id, username, email: "alice@corp.example", groups: ["staff"] }
// mapClaims → { email: "alice@gmail.example", picture: "https://…", groups: ["admin"] }
{
  email: "alice@corp.example",          // local wins
  groups: ["staff"],                    // federated groups cannot reach here
  picture: "https://…",                 // gap filled
  federated: {
    google: { email: "alice@gmail.example", picture: "https://…", groups: ["admin"] },
  },
}
```

#### `emailVerified` is a boolean here, whatever the IdP sent

`MappedClaims.emailVerified` is `boolean | undefined`, and normalising to it is the **adapter's** job — the merge does not coerce, and nothing downstream does either.

This is not a formality. Sign in with Apple sends `email_verified` as the *string* `"true"` on some responses and as a boolean on others, and `is_private_email` behaves the same way. `Boolean("false")` is `true`, so an adapter that passes the raw claim through — or coerces it — reports an unverified address as verified, on a claim that gates token issuance through `oauth.requireEmailVerified`. `federation-apple` reads `"true"` / `"false"` to their booleans and treats every other shape as **absent**, because absence is not `false` (#297); a new adapter for an IdP with the same habit should do likewise.

A non-boolean that does reach `mapClaims`'s output is not promoted — `emailVerified` is not in `PROMOTABLE_FEDERATED_CLAIMS` at all — but it *is* recorded verbatim under `claims.federated[<providerName>]`, where a deployment reading it as a gate would then be reading a string.

The merge is exported as `mergeFederatedClaims` for consumers that build a claims envelope of their own.

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

**`@o3co/auth-provider-federation-apple`**

- Default scope is `["name", "email"]` — Apple's two documented values, and requesting either is what makes Apple POST the callback, so the module declares `responseMode: "form_post"`.
- `FederationProfile.sub` is Apple's stable team-scoped opaque identifier.
- The verified id_token is the only identity source (Apple publishes no `userinfo_endpoint`), `nonce` is required, and `email_verified` may arrive as the string `"true"` — see the note above.
- `is_private_email` is surfaced as `isPrivateEmail` for Hide My Email relay addresses; it is namespaced, never promoted.
- The user's display name arrives once, in the first authorization's POST `user` body, and never in the id_token.

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

### Redirect allowlist (`redirectAllowlist`)

`GET /session/oauth/federation/:name` accepts a `redirect_to` query parameter
naming where the browser lands after the callback. Every value it may name has
to be listed:

```hocon
federations {
  google {
    enabled = true
    # …credentials…

    redirectAllowlist = [
      "https://app.example.com/welcome"
      "https://app.example.com/account/linked"
      "http://localhost:5173/welcome"      # local dev front-end
    ]

    sessionDomain    = ".example.com"
    authCallbackUrl  = "https://app.example.com/auth/callback"
    clientUrl        = "https://app.example.com/"
  }
}
```

Four rules are worth knowing before writing the list:

- **Matching is exact.** Scheme, host, port, path, query and fragment all
  count. Only case, the default port, `..` segments and percent-encoding are
  normalized away. There is no wildcard, prefix or subdomain matching — an
  entry does not admit its own siblings, and a target that carries dynamic
  query parameters cannot be listed as a family. Make it a fixed path and carry
  the variable part in the session.
- **An absent or empty list refuses every `redirect_to`.** That is the right
  setting for a deployment that does not use the parameter; it is not a way to
  allow everything. Before #278 an unset allowlist accepted any http(s) URL,
  which made the endpoint an open redirect — nothing falls back to that now.
- **`https` is required, except on loopback.** `localhost`, `127.0.0.0/8` and
  `[::1]` may use `http://`, which is what lets a local development front-end
  and a native client's loopback listener work without a certificate. The port
  is still matched, so list the port the client binds — RFC 8252 §7.3's
  port-agnostic loopback comparison is not implemented here.
- **`sessionDomain`, when set, constrains the list itself.** Every non-loopback
  entry must be inside it, checked when the policy is built, so an entry outside
  it fails startup rather than sitting in the config looking effective. Unset
  `sessionDomain` if a cross-domain redirect target is genuinely intended.

`authCallbackUrl` and `clientUrl` are read by `resolveCallbackRedirect`, not by
the allowlist: the former is the bridge page a `redirect_to` is handed to, the
latter the fallback for a callback that carries none.

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
