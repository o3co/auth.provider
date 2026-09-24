# @o3co/auth-provider-webauthn

Last updated: 2026-09-25

Passkey (WebAuthn) credential registration and an authentication grant for [`auth.provider`](../../README.md): a user enrolls a passkey from an authenticated session, and later exchanges a passkey assertion for tokens at `/oauth/token`.

## Responsibility

**Role.** Passkeys as a primary login at the authorization server. The package adds three ceremony routes under `/oauth/webauthn/` and the `urn:o3co:oauth:grant-type:webauthn` grant, which `/oauth/token` dispatches like any other grant.

**Owns:**

- the ceremonies: generating registration and authentication options, verifying the attestation and persisting the credential, verifying an assertion and its sign count, and minting tokens for it;
- the WebAuthn configuration (`webauthnConfigSchema`, the `webauthnConfig` slot) and its defaults ([`config/reference.conf`](config/reference.conf), exported as `@o3co/auth-provider-webauthn/reference.conf`);
- the algorithm set offered and accepted (`WEBAUTHN_ALGORITHM_IDS`), and the rate limit on the unauthenticated `authentication/options` route;
- the boundary with `@simplewebauthn/server`, the WebAuthn library the verification runs on.

**Does not own:**

- the stores and their contracts — `WebAuthnCredentialStore`, `ChallengeStore` and `ChallengeCeremony` are core's ports (with core's memory implementations); a deployment wires a persistent credential store;
- who the user is at registration: `req.webauthnSubject` is set by middleware the deployment writes (from its session or a bearer token); no package in this repository sets it;
- scope decisions — the deployment's `grantPolicy`, which this grant requires;
- signup, account recovery, email: the deployment's own flows, outside the authorization server.

**Why a separate package.** Passkeys are optional, and the verification runs on a WebAuthn library pinned to an exact version, whose upgrades are security reviews of their own ([Dependency: SimpleWebAuthn](#dependency-simplewebauthn)). A deployment without passkeys installs none of it, and the library's version moves without touching core or oauth.

## Install

```sh
npm install @o3co/auth-provider-webauthn @o3co/auth-provider-core express
```

Peer dependencies: `@o3co/auth-provider-core` and `express@^5.0.0`. The
package depends on `@simplewebauthn/server` and `zod`.

Core is a peer because the package augments core's `ComponentMap` with the
`webauthnConfig` slot: the augmentation reaches only the copy of core it
resolves, and as a peer that is your composition's one copy.

## Bootstrap

The WebAuthn settings live in your HOCON configuration under `webauthn`, beside everything else the composition root loads. Layer this package's [`config/reference.conf`](config/reference.conf) between your `application.conf` and core's own `reference.conf`: it carries the package's defaults and the `WEBAUTHN_*` environment variables that override them. Core's `AppConfigSchema` passes through the `webauthn` keys it names — every key `webauthnConfigSchema` reads, which `config.test.mts` pins ([#496](https://github.com/o3co/auth.provider/issues/496)) — checking little more than their types, and a small module hands that section to `webauthnConfigSchema`, which owns the rules:

```hocon
# config/application.conf — what has no default
webauthn {
  rpId = "example.com"
  rpName = "Example App"
  origin = ["https://example.com"]
  origin = ${?WEBAUTHN_ORIGIN}   # repeated, so the variable still wins over the line above
}
```

A key your `application.conf` sets shadows the substitution `reference.conf` makes for it; repeat the `${?VAR}` line after your value, as above, to let the environment override it again.

```ts
import { fileURLToPath } from "node:url";
import {
    AppConfigSchema,
    createApp,
    defineModule,
    memoryWebAuthnCredentialStoreModule,
    memoryChallengeStoreModule,
    defaultChallengeCeremonyModule,
    memoryReplaySeenSetModule,
} from "@o3co/auth-provider-core";
import { webauthnModule, webauthnConfigSchema } from "@o3co/auth-provider-webauthn";
import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";

const shipped = (specifier: string) => parseFile(fileURLToPath(import.meta.resolve(specifier)));

const config = validate(
    parseFile("config/application.conf")
        .withFallback(shipped("@o3co/auth-provider-webauthn/reference.conf"))
        .withFallback(shipped("@o3co/auth-provider-core/reference.conf")),
    AppConfigSchema,
);

const webauthnBootstrap = defineModule({
    name: "my-webauthn-config",
    requires: ["config"] as const,
    provides: {
        webauthnConfig: ({ config }) => webauthnConfigSchema.parse(config.webauthn),
    },
});

const app = await createApp({
    modules: [
        webauthnModule,
        webauthnBootstrap,
        memoryWebAuthnCredentialStoreModule,   // dev only; wire a persistent WebAuthnCredentialStore in prod
        memoryChallengeStoreModule,
        defaultChallengeCeremonyModule,
        memoryReplaySeenSetModule,
        grantPolicyModule,                     // required — see SECURITY — scope authorization
        // ... rest of your auth-provider stack (oauthAuthorizationModule, keyStore, etc.)
    ],
    bootstrapComponents: { config, pathResolver: import.meta.resolve },
});
```

A module that hard-codes the settings instead (`webauthnConfigSchema.parse({ rpId: …, … })`) works only if it supplies every required field, the ones `reference.conf` defaults included — the schema has no defaults of its own — and then none of the `WEBAUTHN_*` variables below reaches the schema.

## Multi-origin: one RP for the site and the Android app

`origin` is a list because one Relying Party is normally reached from more than
one place. Every entry is compared against the authenticator's
`clientDataJSON` by **exact string** — SimpleWebAuthn does no normalisation, no
subdomain matching and no wildcards — so each entry has to be written exactly
as the client sends it.

| Client | Entry | Notes |
|---|---|---|
| Browser | `https://example.com` | Bare serialized origin: scheme + host + a port only when it is not the default. **No trailing slash**, path or uppercase host — such an entry would never match, so the schema refuses it at boot and names the origin it should have been. |
| Browser, sub-domain | `https://app.example.com:8443` | Sharing one `rpId` across sub-domains means listing each origin. |
| Browser, local dev | `http://localhost:3000` | `http:` is accepted for `localhost` only. An IP address — `127.0.0.1`, `[::1]`, any other — is refused: WebAuthn needs the origin's host to be a domain (W3C WebAuthn §5.1.3), so no browser runs a ceremony on one. |
| Android app | `android:apk-key-hash:<base64url>` | What Credential Manager sends in place of an origin ([#497](https://github.com/o3co/auth.provider/issues/497)). |

```hocon
webauthn {
  rpId = "example.com"
  rpName = "Example App"
  origin = [
    "https://example.com"
    "android:apk-key-hash:pNiP5iKyQ8JwgLTSKGZmcRHqvOUP1qGP8FfEcCQPvVI"
  ]
}
```

**From the environment**, `WEBAUTHN_ORIGIN` (which `reference.conf` substitutes
into `origin`) carries the same list comma-separated — the spelling
`CORS_ALLOWED_ORIGINS` uses, read by the same function in core
(`normalizeAllowedOrigins`): each entry is trimmed, empty entries are dropped,
and every entry meets the rules in the table above exactly as it would in the
list. The split yields only pieces of what you wrote, each checked as a list
entry would be, so the environment spelling cannot admit an origin the list
would refuse. (A comma inside a host is legal URL syntax, and the environment
spelling cannot express one: `https://a,b.example` splits into `https://a`,
which is a valid origin, and `b.example`, which has no scheme — so the whole
list is refused.)

```sh
WEBAUTHN_ORIGIN=https://example.com,android:apk-key-hash:pNiP5iKyQ8JwgLTSKGZmcRHqvOUP1qGP8FfEcCQPvVI
```

An empty `WEBAUTHN_ORIGIN` leaves the relying party with no origin, which the
schema refuses at boot.

### Being framed: `topOrigin`

`origin` is where the ceremony runs. `topOrigin` is the page it runs *inside*,
when that is a different origin — a passkey prompt in an iframe. The browser
reports it, and `@simplewebauthn/server` 14 refuses such a response unless the
deployment named the embedding origins it accepts:

```hocon
webauthn {
  topOrigin = ["https://partner.example"]
}
```

From the environment, `WEBAUTHN_TOP_ORIGIN` is comma-separated the same way,
and an exported-but-empty one reads as unset.

Absent, a reported cross-origin authentication is refused, which is the right
answer for a deployment that never meant to be embedded — and the refusal is
`top_origin_mismatch`, not `origin_mismatch`, so it does not send an operator
to the `origin` list above, which cannot fix it. Same shape rules as `origin`,
minus the Android app form: a top origin is a browsing context, and Credential
Manager's origin has no frame above it.

Safari does not send `topOrigin` as of the version vendored here, so the check
applies only where a browser reports one.

**The Android entry.** Android's Credential Manager identifies the calling app
by the base64url SHA-256 of its **signing certificate**, not by a host, and
presents `android:apk-key-hash:<that hash>` as the ceremony origin. Derive it
from the certificate that signs the build you are registering — a debug build
and a Play-signed release have different signing keys and therefore different
entries, so list both if both must work:

```bash
keytool -exportcert -alias <alias> -keystore <keystore> \
  | openssl sha256 -binary \
  | openssl base64 -A | tr '+/' '-_' | tr -d '='
```

The schema validates the shape only — the lowercase `android:apk-key-hash:`
prefix and exactly the value the command above prints: 43 characters of
unpadded base64url, the length of a SHA-256, with nothing after it. It refuses
padding, a truncated value, and the hex fingerprint `keytool -list` shows (64
characters once the colons are gone, and every one of them happens to be
base64url). It cannot check that the hash is *your* app's, so an entry pasted
from the wrong build is a ceremony that fails at runtime rather than a boot
error. Standard-base64 `+` and `/` are refused: Credential Manager emits the
URL-safe alphabet, so those characters are a transcription error every time.

Serving `/.well-known/assetlinks.json` on the `rpId` domain is what lets the
app use the RP ID; it is an Android platform requirement and outside this
package.

The package ships defaults for `attestationPreference`, `userVerification`, `challengeTtlMs`, `allowCredentialsForKnownUser`, and `rateLimit.authenticationOptions` in [`config/reference.conf`](config/reference.conf), for the composition root's HOCON `withFallback` chain; the schema itself has no defaults. Each of those defaults can be overridden by the environment variable `reference.conf` names beside it (`WEBAUTHN_CHALLENGE_TTL_MS`, `WEBAUTHN_ALLOW_CREDENTIALS_FOR_KNOWN_USER`, …), and the schema takes the string such a variable delivers: a number as a number, a switch as `true` / `false` / `1` / `0` in any case and with surrounding spaces ignored (empty reads as `false`; any other value fails the parse) — the same reading core gives its own switches. Consumers MUST supply `rpId` / `rpName` / `origin` — these have no library defaults and the schema reports useful errors if missing (per ADR [`2026-04-30-config-schema-strict-defaults-from-hocon.md`](../core/docs/adr/2026-04-30-config-schema-strict-defaults-from-hocon.md)).

## First-credential bootstrap

WebAuthn registration requires an authenticated subject. For greenfield deployments, the usual path is **federation**: users first sign in through a federation package (Google, GitHub, any OpenID Connect IdP — see the [package list](../../README.md#packages)), then enroll a passkey from the authenticated session. The bridge from that session to `req.webauthnSubject` is middleware the deployment writes; this package does not ship one.

For consumer-driven account flows (signup forms, magic-link, etc.) establishing trust in the first credential is the consumer's, outside the authorization server.

## Endpoints

- `POST /oauth/webauthn/registration/options` — generates `PublicKeyCredentialCreationOptions`. Requires an authenticated subject: `req.webauthnSubject`, set by the deployment's own upstream middleware (session or bearer).
- `POST /oauth/webauthn/registration/verify` — verifies the attestation response and persists a `WebAuthnCredential`. Single-use challenge via `ChallengeCeremony`.
- `POST /oauth/webauthn/authentication/options` — generates `PublicKeyCredentialRequestOptions`. Unauthenticated, rate-limited, and discoverable-credential only: the response never carries an `allowCredentials` list derived from the request. The allow-list flow is available behind `allowCredentialsForKnownUser` — see [SECURITY — `authentication/options` enumeration](#security--authenticationoptions-enumeration).
- Grant: `urn:o3co:oauth:grant-type:webauthn` — exchanges a verified assertion for an access token, plus a refresh token when the authenticated client is allowed one. A sender-bound request produces sender-bound tokens. See [SECURITY — refresh-token issuance](#security--refresh-token-issuance) and [SECURITY — sender-constrained tokens](#security--sender-constrained-tokens).

## SECURITY — `userId` opacity

`WebAuthnCredential.userId` is presented to the authenticator as the WebAuthn `user.id` (WebAuthn §5.4.3). It MUST be opaque — no email, no username, no PII. Authenticators persist it and may sync across devices. If your `UserRepository` keys by email or username, map to an opaque handle before calling `webauthnCredentialStore.registerCredential(...)`:

```ts
const opaqueUserId = await deriveOpaqueHandle(realUserId);
await store.registerCredential({ userId: opaqueUserId, /* ... */ });
```

The middleware that sets `req.webauthnSubject` should therefore expose the opaque handle as `userId`, not the email or username.

The registration endpoints enforce a 1..64-byte length on `webauthnSubject.userId` (WebAuthn §5.4.3 user-handle constraint). Requests with a userId outside this range fail with 500 `server_error` — this is a consumer-misconfiguration check, not a runtime user error. `authentication/options` enforces the same bound on the `userId` a *caller* may supply, but as `400 invalid_request`: there the value is untrusted request data, not your configuration.

## SECURITY — scope authorization

The webauthn grant has **no library-side `allowedScopes` ceiling**. Client credentials and authorization code grants bind issued scope to `client.allowedScopes` at the handler level; webauthn cannot, because the passkey is the authentication event, not a scope authorization token.

The requested `scope` is read strictly by RFC 6749 §3.3's grammar (core's `readSpaceDelimitedParameter`) before the policy sees it: a value that is not a space-delimited list of scope-tokens — a tab, a quote — is `400 invalid_scope`, so a malformed scope never reaches a token's `scope` claim as sent, whatever the policy allows. A value of spaces alone requests no scope; a tab alone is malformed.

`grantPolicy` is the **only scope-bounding gate** for this grant. Policy invocation is unconditional whenever `grantPolicy` is wired — it is NOT gated on `oauth.resourceIndicator.enabled` (that flag controls only whether `body.resource` is forwarded to the policy). This mirrors the `refresh_token` grant pattern.

**`grantPolicy` is REQUIRED at boot.** Wiring `webauthnModule` without a `grantPolicy` slot fails fast at `createApp(...)` with a clear error. There is no silent-allow-all path. Deployments that intentionally accept unbounded scope (NOT recommended for production) must wire an explicit no-op policy returning `{ outcome: "allow" }` — making the choice visible in the composition root.

**The policy is yours to write.** No package ships a `GrantPolicyHook`; the interface is exported by `@o3co/auth-provider-core` (defined in core's [`src/policy/types.mts`](../core/src/policy/types.mts)). Fill the `grantPolicy` component slot with your implementation, from a module or from `createApp`'s `bootstrapComponents`:

```ts
import { defineModule, type GrantPolicyHook } from "@o3co/auth-provider-core";

const grantPolicy: GrantPolicyHook = {
    kind: "my-policy",
    async evaluate(request) {
        // request.grantType, request.subject, request.requestedScope, request.resource, ...
        return { outcome: "allow", grantedScope: scopesFor(request.subject, request.requestedScope) };
    },
};

const grantPolicyModule = defineModule({
    name: "my-grant-policy",
    provides: { grantPolicy: () => grantPolicy },
});
// or: createApp({ modules, bootstrapComponents: { config, pathResolver, grantPolicy } })
```

## SECURITY — refresh-token issuance

A passkey is the primary login on a native app and the access token is short-lived, so without a refresh token a passkey-only user is sent back to the platform authenticator at every expiry. The grant issues one — but only for a client that is **named** for it.

**The gate is deny-by-absence.** The refresh token is issued only when the request carried an authenticated client AND that client's `allowedGrantTypes` includes `refresh_token`. A registration that omits it, or declares no `allowedGrantTypes` at all, gets the access token alone. A refresh token is a standing credential with a lifetime measured in days; it is exactly the thing that must not be acquired by omission ([#268](https://github.com/o3co/auth.provider/issues/268) / [#311](https://github.com/o3co/auth.provider/issues/311) / [#326](https://github.com/o3co/auth.provider/issues/326)).

**An authenticated client is what makes a refresh token possible.** `/oauth/token` as `oauthModule` mounts it authenticates the client before any grant runs — a public client by its `client_id` — so a request reaching this grant through it has one. The grant handler itself does not require a client (the passkey is the authentication event), which matters only to a composition that dispatches the grant from a route of its own without client authentication: there it has no `allowedGrantTypes` to consult, and the `refresh_token` grant refuses an unauthenticated caller and binds every refresh token to its issuing client via `azp` — so a token minted there could never be redeemed, and none is.

**Rotation and replay detection are the shared ones.** The grant opens a refresh-token family through the `refreshTokenFamilyRotation` component, the same one the authorization-code grant registers its initial `rt+jwt` with: one active token per family, and a replayed token revokes the whole family (RFC 6819 §5.2.2.3). The lifetime comes from `oauth.refreshToken.expiresIn`. Registration is fail-closed, and a refresh token never leaves the grant unless its family was registered: if the family store cannot be reached, or the token's `jti` / `exp` cannot be read back to register it under (an unset `oauth.refreshToken.expiresIn` is one way to get there), the request answers `503 temporarily_unavailable` rather than serving a token with no replay detection behind it. Both the access and the refresh token carry the `family_id` claim, so revoking the family reaches the access token too.

**Sender-bound requests produce sender-bound refresh tokens.** A DPoP or mTLS request has its RFC 7800 confirmation (`cnf.jkt` / `cnf.x5t#S256`) carried into the refresh token on the same gate the other grants apply: public clients always; confidential clients only when the deployment sets `oauth.tokenBinding.bindConfidentialClientRefreshTokens` ([#275](https://github.com/o3co/auth.provider/issues/275)), since their client secret is already the refresh-time authenticator. The access token binds on its own, wider gate — see below.

## SECURITY — sender-constrained tokens

**A sender-bound request produces a sender-bound access token.** When the request carries a DPoP proof or a client certificate, the resulting access token carries the matching RFC 7800 confirmation — `cnf.jkt` for DPoP, `cnf.x5t#S256` for mTLS — and a resource server that enforces binding accepts it only from the same key or certificate. This is the mechanism-agnostic copy the authorization-code and client-credentials grants perform; the webauthn grant does not have one of its own.

**The gate is wider than the refresh token's.** The access token binds whenever the request carried a confirmation, with no further condition — including for a confidential client, whose refresh token stays unbound by default. The two are different questions: a confidential client re-authenticates itself at every refresh, which is why RFC 9449 §5 leaves its refresh token unbound rather than pin it to one key for days; nothing of the sort protects an access token, which a resource server checks on every call.

**`token_type` says which kind was minted.** A DPoP-bound access token is announced as `DPoP` (RFC 9449 §5). An mTLS-bound one keeps `Bearer` — it travels as a bearer token and is checked against the TLS client certificate (RFC 8705 §3). An unbound request is answered exactly as before: `Bearer`, and no `cnf` on either token.

**A client registered `senderConstrained` is refused before this grant runs.** The `/token` route's shared dispatch gate rejects a request that presents no binding with `401 invalid_client`, and one whose binding kind is not in the client's `methods` with `400 unauthorized_client` — for every `grant_type`, this one included. The grant handler holds no second copy of that rule; its part is the other half, above — a request that proves its key gets a token bound to it ([#489](https://github.com/o3co/auth.provider/issues/489)).

## SECURITY — token revocation limitations

Webauthn access tokens are revocable via `POST /oauth/revoke` ONLY when the grant was invoked with an authenticated client. The access token then carries the client's `client_id`. Without one it carries no `client_id` / `azp` claim — the revoke endpoint's ownership check (`client_id ?? azp ?? aud` must match the revoking client) cannot match, and the request returns 200 with no denylist insertion (RFC 7009 fail-closed). Through `oauthModule`'s `/oauth/token` the client is always authenticated; a composition that dispatches the grant from its own route must authenticate the client there too (`createClientAuthMiddleware` from `@o3co/auth-provider-oauth`) if it relies on access-token revocation.

## SECURITY — registration authorization strength

The registration endpoints accept any authenticated subject. Deployments SHOULD enforce step-up reauthentication (NIST SP 800-63B): require recent `auth_time` OR MFA OR fresh federation login before allowing registration. The endpoints do not enforce this, and `grantPolicy` does not reach them — it gates the grant at `/oauth/token`, not registration. Gate registration in the upstream middleware that sets `req.webauthnSubject`: set it only for a session strong enough to enroll a credential.

## SECURITY — `authentication/options` enumeration

`POST /oauth/webauthn/authentication/options` is unauthenticated by design — the passkey assertion *is* the authentication event. That makes its response body a public oracle, so the endpoint answers the same thing to everyone.

**The response is always the discoverable-credential shape.** No `allowCredentials` member is derived from a body-supplied `userId`, the credential store is not consulted, and the body, its key set, and the work behind it are identical for a registered account, an unregistered one, and a request naming no account at all. A populated `allowCredentials` for a real account and an empty or absent one otherwise would be an unauthenticated "does this account exist, and how many passkeys does it have?" query for anyone who asked ([#281](https://github.com/o3co/auth.provider/issues/281)).

**`allowCredentialsForKnownUser: true`** derives `allowCredentials` from a supplied `userId`. Set it only for a deployment whose authenticators cannot do discoverable credentials — non-resident keys, typically an older security-key fleet — where the client genuinely needs to be told which credential ids to offer. It reinstates the enumeration oracle for that deployment; the `200`-for-everyone / no-error-shape mitigation is all that remains, and it is not enough on its own. Pair it with a tight `rateLimit.authenticationOptions` and, where you can, put an authenticated identifier-first step in front of the endpoint instead.

**`userId` is bounded before it reaches any store.** The optional body field must be an opaque handle of 1–64 UTF-8 bytes with no control characters (WebAuthn §5.4.3, the same bound the registration endpoint enforces on the session-derived handle). Anything else is `400 invalid_request` with a single fixed `error_description` that does not vary with what the server knows about the value.

## SECURITY — rate-limiting `authentication/options`

The endpoint is rate-limited by the module itself; it is not something a composition root has to remember to add. `webauthnModule` mounts core's shared `createRateLimitGuard` in front of the route:

- **Keyed** `webauthn-authentication-options:ip:<ip>` — exported as `WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG`, which is also the `limits` key an adapter resolves a per-endpoint spec by.
- **Spec** from `webauthnConfig.rateLimit.authenticationOptions` (`limit` / `windowSeconds`; reference default 30 per 60 s). It also backs the RFC `RateLimit-*` headers when the adapter reports no applied limit of its own.
- **Outage policy** from `config.rateLimit.failMode`, the same product-wide key `/oauth/token` and `/session/login` read — a limiter outage must not shed load on one surface and wave everything through on another. An outage logs `rate_limiter_failed_open` / `rate_limiter_failed_closed` and emits a `rate_limit.unavailable` audit event when an `auditSink` is wired.

Wire the `rateLimiter` ComponentMap slot (the Redis adapter in a scaled deployment) so the buckets are shared across replicas. **Without it the route is still guarded**, by a per-process memory limiter, and boot warns `webauthn_authentication_options_rate_limiter_not_shared` naming the spec in force — a per-process bucket is weak protection, not absent protection, and the warning says which one you have. That is the unset-`deployment.mode` behaviour: under `deployment.mode = "multi"` the fallback is refused at boot instead (a `replica-unsafe-adapter` BootError naming the route, wrapped in `contribute-factory-failed`), because a per-replica budget is the limit multiplied by the replica count; under `"single"` it is silent (#474).

## SECURITY — `attestationPreference` default

`attestationPreference` defaults to `"none"`: attestation chain verification adds nothing for the common platform-authenticator case. Deployments using platform authenticators (Touch ID, Windows Hello, Android biometrics) typically don't need attestation chain verification. Set `"direct"` only when:

- Your threat model requires authenticator provenance verification (e.g. enterprise device fleet, FIDO2 metadata service consumer)
- You have a curated trust anchor set (FIDO MDS root list) wired into your verifier

Attestation root verification is partial, and which half you get depends on the format. `@simplewebauthn/server` ships default trust anchors for `apple`, `android-key` and `android-safetynet`, and validates the `x5c` chain against them. For `packed`, `tpm` and `fido-u2f` it holds no anchors and skips path validation entirely, so provenance for those formats remains your responsibility.

For the anchored formats the check is fail-closed (the library's fix for GHSA-6hxq-p678-4hr2): a chain that does not actually terminate at a shipped anchor is rejected. The library throws on a chain failure, and none of the reason regexes below match its message, so it surfaces from the verify endpoint as `400 {"error": "unknown"}` — there is no dedicated discriminant for it.

## SECURITY — sign-count handling

The grant rejects sign-count regressions per WebAuthn §2.4 (clone detection). The §2.4 corner case where both stored and reported sign counts are `0` is allowed (some authenticators always report `0`). The sign-count update is atomic CAS — concurrent assertion races return `false` and the grant fails with `invalid_grant` rather than minting tokens for a stale view.

## Dependency: SimpleWebAuthn

`@simplewebauthn/server` is pinned to exactly `14.0.1`. The verification helpers and options generators wrap this library; Dependabot tracks major bumps, so each one arrives as a deliberate security review.

The pin is past `13.3.1` for GHSA-6hxq-p678-4hr2 — registration attestation certificate chains were not reliably checked against a trust anchor. Deployments on the `attestationPreference = "none"` default are unaffected: that path never inspects a certificate. See [`attestationPreference` default](#security--attestationpreference-default) for who is.

14.x accepts an `x5c` carrying a cross-signed certificate, which 13.3.2 and 13.3.3 rejected (their path validation required every certificate in `x5c` to appear in the chain it built). A deployment relying on Apple or Android attestation should still canary real authenticators when moving between library versions.

**The advertised algorithm set is this package's, not the library's.** `WEBAUTHN_ALGORITHM_IDS` — EdDSA (`-8`), ES256 (`-7`), RS256 (`-257`), most preferred first — is passed to both `generateRegistrationOptions()` and `verifyRegistrationResponse()`, so what an authenticator is offered and what is accepted back cannot drift apart. The library keeps its own default in a mutable module-level array and prepends ML-DSA-44 to it whenever the runtime reports support, which would make the offer depend on the Node build the provider happens to run on and change it under a dependency bump. A credential outlives the process that registered it, so the set is stated here. It is exported (`import { WEBAUTHN_ALGORITHM_IDS } from "@o3co/auth-provider-webauthn"`) and frozen, and a registration whose credential uses an algorithm outside it is refused as `400 {"error":"algorithm_not_allowed"}` rather than `unknown`. Offering ML-DSA-44 on purpose is [#554](https://github.com/o3co/auth.provider/issues/554).

## Scope

Implemented:

- Primary-login passkeys
- Registration + authentication ceremonies
- Multi-origin support (`config.origin: string[]`), web and Android — see [Multi-origin](#multi-origin-one-rp-for-the-site-and-the-android-app)
- RFC 8707 `resource` forwarded to `grantPolicy` when `oauth.resourceIndicator.enabled` is set, read by core's `extractResourceParam` exactly as the oauth grants read it: each value whole, the empty entries of a repeated parameter dropped (`resource=&resource=https://x` reaches the policy as `["https://x"]`), and an all-empty parameter as no resource
- Refresh-token issuance for allowed clients ([#480](https://github.com/o3co/auth.provider/issues/480))

Not implemented:

- WebAuthn as an MFA factor
- Audience derivation from `resource` for this grant — `client_credentials`, `refresh_token` and `/authorize` derive it; here `resource` reaches the policy hook and nothing else, and the audience a passkey token gets is the rule on `AuthenticatedClient.allowedAudiences` ([#520](https://github.com/o3co/auth.provider/issues/520))
- Attestation root verification for the formats the library ships no trust anchors for (`packed`, `tpm`, `fido-u2f`) — see [`attestationPreference` default](#security--attestationpreference-default)

## Source layout

- [`src/module.mts`](src/module.mts) — the assembly: the manifest, its required and optional slots, the three routes and the grant, the rate-limit guard and its replica-safety refusal.
- [`src/grant.mts`](src/grant.mts) — the grant: assertion verification, the sign-count update, the policy call, and token minting.
- `src/routes/` — the three ceremony handlers, one per endpoint.
- `src/internal/` — the SimpleWebAuthn boundary (options generation and response verification, and the mapping of library failures onto this package's error codes), plus one helper copied from `@o3co/auth-provider-oauth`'s grants rather than imported, because this package does not depend on oauth: the unverified payload decode the grant reads its own freshly minted refresh token with, to register its family. The copy is not checked against the original.
- [`src/config.mts`](src/config.mts) — the config schema and the `webauthnConfig` slot; [`src/request.mts`](src/request.mts) — the `req.webauthnSubject` augmentation.

The ports these depend on (`WebAuthnCredentialStore`, `ChallengeCeremony`, `ChallengeStore`) are core's.

## License

Apache-2.0 © 1o1 Co. Ltd.
