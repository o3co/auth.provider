# @o3co/auth-provider-federation-apple

Sign in with Apple federation provider for `auth.provider`.

An iOS app that offers Google or GitHub login must offer Sign in with Apple as
well (App Store Review Guideline 4.8), so this is the provider an iOS client of
this stack needs to ship social login at all.

## Usage

Add `appleFederationModule` to the manifest list passed to `createApp`. A small
config-bootstrap module supplies the typed `appleFederationConfig` slot (per
A5 §10.1 const-Module pattern).

```ts
import { readFileSync } from "node:fs";
import { createApp, defineModule } from "@o3co/auth-provider-core";
import { extractFederationSection, sessionModule } from "@o3co/auth-provider-session";
import {
  appleFederationModule,
  type AppleProviderConfig,
} from "@o3co/auth-provider-federation-apple";

const appleConfigBridgeModule = defineModule({
  name: "apple-federation-config",
  requires: ["config"] as const,
  provides: {
    appleFederationConfig: (deps): AppleProviderConfig => {
      const slice = extractFederationSection(deps.config.federations, "apple");
      if (!slice) throw new Error("federations.apple must be enabled");
      return {
        clientId: slice.clientId as string,          // Services ID
        callbackURL: slice.callbackURL as string,    // must be https
        teamId: slice.teamId as string,
        keyId: slice.keyId as string,
        privateKey: readFileSync(slice.privateKeyPath as string, "utf8"),
      };
    },
  },
});

const handle = await createApp({
  modules: [
    sessionModule,
    appleFederationModule,
    appleConfigBridgeModule,
    // ... composition-root modules supplying userRepository + four-store split
  ],
  bootstrapComponents: { config, pathResolver },
});
```

Single-tenant, as `federation-google` and `federation-github` are:
`provider.name` is fixed at `"apple"`.

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
construction, through the repo's one loopback predicate (`isLoopbackHostname`,
#364), rather than letting the authorization endpoint answer the first login
with an opaque `invalid_request`.

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
the cache untouched: a deployment whose mounted key is repaired or rotated
under it recovers on the next request instead of at the next restart.

If you already produce the secret elsewhere, pass `clientSecret` instead —
either a string or a resolver (`() => string | Promise<string>`), the widened
`FederationClientSecret` form the session package resolves per token exchange.
Supply **one** of the two: both is ambiguous and neither is unconfigured, and
either fails at boot.

```ts
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
URL.

The provider declares `responseMode: "form_post"`, and the session router does
the rest: it appends `response_mode=form_post` to the authorization request,
mounts `POST /session/oauth/federation/apple/callback` with the same state /
CSRF / PKCE / nonce binding as the GET callback, and carries the flow's
ephemeral state in a **federation transaction** rather than in the session.

The GET on that path answers `405 method_not_allowed` with `Allow: POST`, the
mirror of the `405` a query federation answers to a POST. Apple only ever posts
here, and the transaction cookie below is offered to *every* cross-site request
that reaches the path, so refusing the method before the cookie is read is what
keeps a third party's `<img src="…/callback">` from touching the flow
([#502](https://github.com/o3co/auth.provider/issues/502)).

That last one is the part worth knowing about before deploying. The callback is
a **cross-site POST** from `appleid.apple.com`, and a `SameSite=Lax` cookie is
not sent on one — a callback relying on the session cookie would arrive with no
session, no `state` to compare against and no PKCE verifier. So the start leg
issues a second, dedicated cookie: `HttpOnly; Secure; SameSite=None`,
path-scoped to `/session/oauth/federation/apple/callback`, expiring in ten
minutes, and carrying nothing but an opaque id. The `state`, PKCE verifier,
nonce and post-login redirect are held in the session store under that id.

Both are deleted as soon as a callback **judges** the transaction — on success,
and on every refusal that compared a `state`. A callback carrying no `state`
judges nothing and leaves the flow intact, which is what stops a cross-site
request from cancelling a login in progress. The single use that buys you is
sequential: a callback arriving after an earlier one completed is refused. Two
callbacks that *overlap* can both get past the record, because retiring it is a
read and then a delete over an API with no compare-and-delete; what stops them
becoming two logins is Apple's authorization code, which is itself single-use,
so at most one exchange succeeds and the rest end in `502 exchange_failed`.
There is nothing for you to configure either way — it is stated here because
the alternative is a guarantee you might plan around
([#502](https://github.com/o3co/auth.provider/issues/502)).

**Your application session cookie is not modified.** Not its `SameSite`, not
its `Secure` flag, not for the browser doing the Apple login and not for anyone
else; `session.sameSite` in config is likewise never touched. A deployment
running Apple beside Google keeps `SameSite=Lax` on every session in it. (Until
[#494](https://github.com/o3co/auth.provider/issues/494) this was not true: the
start leg relaxed the session cookie in place, and because express-session
persists cookie attributes into the store, any third party who caused one
navigation to the unauthenticated start route downgraded that browser's session
cookie for good. If you are reading this against an older release, treat that as
the reason to upgrade.)

`Secure` is on the transaction cookie because browsers drop a `SameSite=None`
cookie that is not `Secure` — and since Apple already requires an `https`
return URL, an Apple deployment is HTTPS-only regardless.

## Claims

Apple publishes no `userinfo_endpoint`, so the verified id_token (RS256, keys
at `https://appleid.apple.com/auth/keys`) is the only source of identity.
`nonce` is required, not optional: `buildAuthorizationUrl` and `exchangeCode`
both fail closed without one.

- **`email_verified` may arrive as the string `"true"`.** It is normalised to a
  boolean. This matters more than it looks: `Boolean("false")` is `true`, so a
  coercion would report an unverified address as verified. A claim that is
  neither a boolean nor `"true"` / `"false"` reads as absent, because absence is
  not `false` (#297).
- **`is_private_email` marks a Hide My Email relay address**
  (`…@privaterelay.appleid.com`) and is surfaced as `isPrivateEmail` so a
  deployment can decide about it — it is namespaced under
  `claims.federated.apple`, never promoted. Relay addresses forward mail and the
  user can disable them at any time; if reaching a real inbox matters, this is
  the value to act on. `isPrivateRelayEmail(email)` is exported for the same
  decision elsewhere. Apple's own marker wins; the relay domain is consulted
  only when Apple sends no marker.
- **The user's name arrives once**, in the POST body's `user` JSON field, on the
  first authorization only — never in the id_token, and never again on a later
  login. It is mapped to the same `name` claim Google's module produces, so the
  session package's existing promotion rules apply unchanged: `email` and `name`
  fill a gap the local record left, and everything else stays under
  `claims.federated.apple` (see `PROMOTABLE_FEDERATED_CLAIMS`). Persist it on
  first login if you want to keep it.
- **The `user` body is not signed.** The `state` check binds it to the session
  and binds nothing else, so treat the name as self-asserted — which is exactly
  what claim precedence already assumes of every federated claim.
- **No `picture`.** Apple asserts none.

## Logout

Apple publishes no OIDC `end_session_endpoint` — the same situation
`federation-google` documents, minus Google's fallback, because there is no
`appleid.apple.com` logout URL to send a browser to. `endSession` therefore
uses a configured `endSessionEndpoint` if you supply one, otherwise redirects
to `postLogoutRedirectUri`, and otherwise throws rather than inventing a
destination. Local session destruction is unaffected.

## Public API

- `appleFederationModule` — const Module contributing `federations.apple` +
  `federationRedirectPolicies.apple`
- `createAppleProvider(config: AppleProviderConfig): AppleProvider` — pure
  constructor
- `createAppleClientSecret(options): () => Promise<string>` — the ES256 signer
- `isPrivateRelayEmail(email): boolean`
- `APPLE_ISSUER`, `APPLE_AUDIENCE`, `APPLE_PRIVATE_RELAY_DOMAIN`,
  `APPLE_CLIENT_SECRET_MAX_LIFETIME_SECONDS`,
  `APPLE_CLIENT_SECRET_DEFAULT_LIFETIME_SECONDS`,
  `APPLE_CLIENT_SECRET_RENEWAL_WINDOW_SECONDS`
- `AppleProviderConfig`, `AppleProvider`, `AppleClientSecretOptions` — types
- `appleFederationConfig` — declared ComponentMap slot for the config bridge
