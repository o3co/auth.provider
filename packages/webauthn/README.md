# @o3co/auth-provider-webauthn

Passkey (WebAuthn) credential lifecycle + authentication grant for [@o3co/auth-provider](https://github.com/o3co/auth.provider) — the toolkit's first Passkey slice, shipped in v0.7.0 (roadmap Wave 1). **AS-scope only**: no signup, no recovery, no email infrastructure (consumer's domain per the auth-provider scope discipline). Campaign identifiers in this README (S7–S12, T-series) resolve in [docs/design-campaign-index.md](../../docs/design-campaign-index.md).

## Install

```sh
pnpm add @o3co/auth-provider-webauthn @o3co/auth-provider-core
```

## Bootstrap

Define a config-providing module and wire `webauthnModule` plus the required adapter modules:

```ts
import {
    createApp,
    defineModule,
    memoryWebAuthnCredentialStoreModule,
    memoryChallengeStoreModule,
    defaultChallengeCeremonyModule,
    memoryReplaySeenSetModule,
} from "@o3co/auth-provider-core";
import { webauthnModule, webauthnConfigSchema } from "@o3co/auth-provider-webauthn";

const webauthnBootstrap = defineModule({
    name: "my-webauthn-config",
    requires: [] as const,
    provides: {
        webauthnConfig: () => webauthnConfigSchema.parse({
            rpId: "example.com",
            rpName: "Example App",
            origin: ["https://example.com"],
            attestationPreference: "none",   // dogfood baseline: platform authenticators need no attestation chain (S11)
            userVerification: "preferred",
            challengeTtlMs: 120_000,         // 120s survives slow mobile networks (spec §2.4.1 baseline)
            allowCredentialsForKnownUser: false,  // enumeration-resistant (#281)
            rateLimit: {
                authenticationOptions: { limit: 30, windowSeconds: 60 },
            },
        }),
    },
});

const app = await createApp({
    modules: [
        webauthnModule,
        webauthnBootstrap,
        memoryWebAuthnCredentialStoreModule,   // dev only; swap for Redis/Postgres in prod
        memoryChallengeStoreModule,
        defaultChallengeCeremonyModule,
        memoryReplaySeenSetModule,
        // ... rest of your auth-provider stack (oauthAuthorizationModule, keyStore, etc.)
    ],
    bootstrapComponents: { /* keystore, userRepository, clientRepository, ... */ },
});
```

## Multi-origin: one RP for the site and the Android app

`origin` is a list because one Relying Party is normally reached from more than
one place. Every entry is compared against the authenticator's
`clientDataJSON` by **exact string** — SimpleWebAuthn does no normalisation, no
subdomain matching and no wildcards — so each entry has to be written exactly
as the client sends it.

| Client | Entry | Notes |
|---|---|---|
| Browser | `https://example.com` | Literal origin: scheme + host + optional port. **No trailing slash** — `https://example.com/` never matches. |
| Browser, sub-domain | `https://app.example.com:8443` | Sharing one `rpId` across sub-domains means listing each origin. |
| Browser, local dev | `http://localhost:3000` | `http:` is accepted for loopback only (`localhost`, `127.0.0.1`, `[::1]`). |
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
prefix plus a non-empty base64url body, with nothing after it. It cannot check
that the hash is *your* app's, so an entry pasted from the wrong build is a
ceremony that fails at runtime rather than a boot error. Standard-base64 `+`
and `/` are refused: Credential Manager emits the URL-safe alphabet, so those
characters are a transcription error every time.

Serving `/.well-known/assetlinks.json` on the `rpId` domain is what lets the
app use the RP ID; it is an Android platform requirement and outside this
package.

The library ships safe defaults for `attestationPreference`, `userVerification`, `challengeTtlMs`, `allowCredentialsForKnownUser`, and `rateLimit.authenticationOptions` in `config/reference.conf` (resolved via composition-root `withFallback` chain per PR #171 discipline). Consumers MUST supply `rpId` / `rpName` / `origin` — these have no library defaults and the schema reports useful errors if missing (per ADR `packages/core/docs/adr/2026-04-30-config-schema-strict-defaults-from-hocon.md`).

## First-credential bootstrap (dogfood)

WebAuthn registration requires an authenticated subject. For greenfield deployments, the canonical bootstrap path is **federation**: users first authenticate via `@o3co/auth-provider-federation-github` (or `-federation-google`), then enroll a passkey from the authenticated session. Both federation packages ship and are documented separately.

For consumer-driven account flows (signup forms, magic-link, etc.) the consumer owns the first-credential trust establishment outside auth-provider scope (per the `feedback_auth_provider_scope_discipline` rule).

## Endpoints

- `POST /oauth/webauthn/registration/options` — generates `PublicKeyCredentialCreationOptions`. Requires an authenticated subject (upstream session / bearer middleware sets `req.webauthnSubject`).
- `POST /oauth/webauthn/registration/verify` — verifies the attestation response and persists a `WebAuthnCredential`. Single-use challenge via `ChallengeCeremony`.
- `POST /oauth/webauthn/authentication/options` — generates `PublicKeyCredentialRequestOptions`. Unauthenticated, rate-limited, and discoverable-credential only: the response never carries an `allowCredentials` list derived from the request. The allow-list flow is available behind `allowCredentialsForKnownUser` — see [SECURITY — `authentication/options` enumeration](#security--authenticationoptions-enumeration).
- Grant: `urn:o3co:oauth:grant-type:webauthn` — exchanges a verified assertion for an access token, plus a refresh token when the authenticated client is allowed one. A sender-bound request produces sender-bound tokens. See [SECURITY — refresh-token issuance](#security--refresh-token-issuance) and [SECURITY — sender-constrained tokens](#security--sender-constrained-tokens).

## SECURITY — `userId` opacity

`WebAuthnCredential.userId` is presented to the authenticator as the WebAuthn `user.id` (WebAuthn §5.4.3). It MUST be opaque — no email, no username, no PII. Authenticators persist it and may sync across devices. If your `UserRepository` keys by email or username, map to an opaque handle before calling `webauthnCredentialStore.registerCredential(...)`:

```ts
const opaqueUserId = await deriveOpaqueHandle(realUserId);
await store.registerCredential({ userId: opaqueUserId, /* ... */ });
```

The bootstrap module's `webauthnSubject` should therefore expose the opaque handle as `userId`, not the email or username.

The registration endpoints enforce a 1..64-byte length on `webauthnSubject.userId` (WebAuthn §5.4.3 user-handle constraint). Requests with a userId outside this range fail with 500 `server_error` — this is a consumer-misconfiguration check, not a runtime user error. `authentication/options` enforces the same bound on the `userId` a *caller* may supply, but as `400 invalid_request`: there the value is untrusted request data, not your configuration.

## SECURITY — scope authorization

The webauthn grant has **no library-side `allowedScopes` ceiling**. Client credentials and authorization code grants bind issued scope to `client.allowedScopes` at the handler level; webauthn cannot, because the passkey is the authentication event, not a scope authorization token.

`grantPolicy` is the **only scope-bounding gate** for this grant. Policy invocation is unconditional whenever `grantPolicy` is wired — it is NOT gated on `oauth.resourceIndicator.enabled` (that flag controls only whether `body.resource` is forwarded to the policy, per Stage 1 RFC 8707 plumbing). This mirrors the `refresh_token` grant pattern.

**`grantPolicy` is REQUIRED at boot.** As of the Wave 1 post-merge security fix, wiring `webauthnModule` without a `grantPolicy` slot fails fast at `createApp(...)` with a clear error. There is no silent-allow-all path. Deployments that intentionally accept unbounded scope (NOT recommended for production) must wire an explicit no-op policy returning `{ outcome: "allow" }` — making the choice visible in the composition root.

## SECURITY — refresh-token issuance

A passkey is the primary login on a native app and the access token is short-lived, so without a refresh token a passkey-only user is sent back to the platform authenticator at every expiry. The grant issues one — but only for a client that is **named** for it.

**The gate is deny-by-absence.** The refresh token is issued only when the request carried an authenticated client AND that client's `allowedGrantTypes` includes `refresh_token`. A registration that omits it, or declares no `allowedGrantTypes` at all, gets the access token alone — the response it got before this shipped. A refresh token is a standing credential with a lifetime measured in days; it is exactly the thing that must not be acquired by a registration written before the feature existed ([#268](https://github.com/o3co/auth.provider/issues/268) / [#311](https://github.com/o3co/auth.provider/issues/311) / [#326](https://github.com/o3co/auth.provider/issues/326)).

**Client authentication is required in practice.** In the client-less passkey-is-the-auth-event mode there is no `allowedGrantTypes` to consult, and the `refresh_token` grant refuses an unauthenticated caller and binds every refresh token to its issuing client via `azp` — so a token minted there could never be redeemed. Wire `clientAuthMw` in front of the grant if you want refresh tokens.

**Rotation and replay detection are the shared ones.** The grant opens a refresh-token family through the `refreshTokenFamilyRotation` component, the same one the authorization-code grant registers its initial `rt+jwt` with: one active token per family, and a replayed token revokes the whole family (RFC 6819 §5.2.2.3). The lifetime comes from `oauth.refreshToken.expiresIn`. Registration is fail-closed, and a refresh token never leaves the grant unless its family was registered: if the family store cannot be reached, or the token's `jti` / `exp` cannot be read back to register it under (an unset `oauth.refreshToken.expiresIn` is one way to get there), the request answers `503 temporarily_unavailable` rather than serving a token with no replay detection behind it. Both the access and the refresh token carry the `family_id` claim, so revoking the family reaches the access token too.

**Sender-bound requests produce sender-bound refresh tokens.** A DPoP or mTLS request has its RFC 7800 confirmation (`cnf.jkt` / `cnf.x5t#S256`) carried into the refresh token on the same gate the other grants apply: public clients always; confidential clients only when the deployment sets `oauth.tokenBinding.bindConfidentialClientRefreshTokens` ([#275](https://github.com/o3co/auth.provider/issues/275)), since their client secret is already the refresh-time authenticator. The access token binds on its own, wider gate — see below.

## SECURITY — sender-constrained tokens

**A sender-bound request produces a sender-bound access token.** When the request carries a DPoP proof or a client certificate, the resulting access token carries the matching RFC 7800 confirmation — `cnf.jkt` for DPoP, `cnf.x5t#S256` for mTLS — and a resource server that enforces binding accepts it only from the same key or certificate. This is the mechanism-agnostic copy the authorization-code and client-credentials grants perform; the webauthn grant does not have one of its own.

**The gate is wider than the refresh token's.** The access token binds whenever the request carried a confirmation, with no further condition — including for a confidential client, whose refresh token stays unbound by default. The two are different questions: a confidential client re-authenticates itself at every refresh, which is why RFC 9449 §5 leaves its refresh token unbound rather than pin it to one key for days; nothing of the sort protects an access token, which a resource server checks on every call.

**`token_type` says which kind was minted.** A DPoP-bound access token is announced as `DPoP` (RFC 9449 §5). An mTLS-bound one keeps `Bearer` — it travels as a bearer token and is checked against the TLS client certificate (RFC 8705 §3). An unbound request is answered exactly as before: `Bearer`, and no `cnf` on either token.

**A client registered `senderConstrained` is refused before this grant runs.** The `/token` route's shared dispatch gate rejects a request that presents no binding with `401 invalid_client`, and one whose binding kind is not in the client's `methods` with `400 unauthorized_client` — for every `grant_type`, this one included. The grant handler holds no second copy of that rule. Until [#489](https://github.com/o3co/auth.provider/issues/489) the other half was missing: a request that *did* prove its key still received an unbound access token, so the proof bought the client nothing.

## SECURITY — token revocation limitations

Webauthn access tokens are revocable via `POST /oauth/revoke` ONLY when the grant was invoked with an authenticated client. Without client auth, the AT carries no `client_id` / `azp` claim — the revoke endpoint's ownership check (`client_id ?? azp ?? aud` must match the revoking client) cannot match, and the request returns 200 with no denylist insertion (RFC 7009 fail-closed). Operators relying on AT revocation MUST require client auth on the webauthn grant path (e.g. wire `clientAuthMw` before the grant handler).

## SECURITY — registration authorization strength

The registration endpoints accept any authenticated subject. Deployments SHOULD enforce step-up reauthentication (NIST SP 800-63B): require recent `auth_time` OR MFA OR fresh federation login before allowing registration. The bare endpoint does not enforce this — wire your `grantPolicy` hook or an upstream Express middleware to gate registration to high-assurance sessions.

## SECURITY — `authentication/options` enumeration

`POST /oauth/webauthn/authentication/options` is unauthenticated by design — the passkey assertion *is* the authentication event. That makes its response body a public oracle, so the endpoint answers the same thing to everyone.

**The response is always the discoverable-credential shape.** No `allowCredentials` member is derived from a body-supplied `userId`, the credential store is not consulted, and the body, its key set, and the work behind it are identical for a registered account, an unregistered one, and a request naming no account at all. Previously a supplied `userId` produced a populated `allowCredentials` for a real account and an empty/absent one otherwise — an unauthenticated "does this account exist, and how many passkeys does it have?" query for anyone who asked ([#281](https://github.com/o3co/auth.provider/issues/281)).

**`allowCredentialsForKnownUser: true`** restores the old behaviour. Set it only for a deployment whose authenticators cannot do discoverable credentials — non-resident keys, typically an older security-key fleet — where the client genuinely needs to be told which credential ids to offer. It reinstates the enumeration oracle for that deployment; the `200`-for-everyone / no-error-shape mitigation is all that remains, and it is not enough on its own. Pair it with a tight `rateLimit.authenticationOptions` and, where you can, put an authenticated identifier-first step in front of the endpoint instead.

**`userId` is bounded before it reaches any store.** The optional body field must be an opaque handle of 1–64 UTF-8 bytes with no control characters (WebAuthn §5.4.3, the same bound the registration endpoint enforces on the session-derived handle). Anything else is `400 invalid_request` with a single fixed `error_description` that does not vary with what the server knows about the value.

## SECURITY — rate-limiting `authentication/options`

The endpoint is rate-limited by the module itself; it is not something a composition root has to remember to add. `webauthnModule` mounts core's shared `createRateLimitGuard` in front of the route:

- **Keyed** `webauthn-authentication-options:ip:<ip>` — exported as `WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG`, which is also the `limits` key an adapter resolves a per-endpoint spec by.
- **Spec** from `webauthnConfig.rateLimit.authenticationOptions` (`limit` / `windowSeconds`; reference default 30 per 60 s). It also backs the RFC `RateLimit-*` headers when the adapter reports no applied limit of its own.
- **Outage policy** from `config.rateLimit.failMode`, the same product-wide key `/oauth/token` and `/session/login` read — a limiter outage must not shed load on one surface and wave everything through on another. An outage logs `rate_limiter_failed_open` / `rate_limiter_failed_closed` and emits a `rate_limit.unavailable` audit event when an `auditSink` is wired.

Wire the `rateLimiter` ComponentMap slot (the Redis adapter in a scaled deployment) so the buckets are shared across replicas. **Without it the route is still guarded**, by a per-process memory limiter, and boot warns `webauthn_authentication_options_rate_limiter_not_shared` naming the spec in force — a per-process bucket is weak protection, not absent protection, and the warning says which one you have. That is the unset-`deployment.mode` behaviour: under `deployment.mode = "multi"` the fallback is refused at boot instead (a `replica-unsafe-adapter` BootError naming the route, wrapped in `contribute-factory-failed`), because a per-replica budget is the limit multiplied by the replica count; under `"single"` it is silent (#474).

## SECURITY — `attestationPreference` default

`attestationPreference` defaults to `"none"` — the dogfood baseline (S11): attestation chain verification adds nothing for the common platform-authenticator case. Dogfood deployments using platform authenticators (Touch ID, Windows Hello, Android biometrics) typically don't need attestation chain verification. Set `"direct"` only when:

- Your threat model requires authenticator provenance verification (e.g. enterprise device fleet, FIDO2 metadata service consumer)
- You have a curated trust anchor set (FIDO MDS root list) wired into your verifier

The library does NOT ship attestation root verification — `"direct"` extracts the chain but consumer-side validation is your responsibility.

## SECURITY — sign-count handling

The grant rejects sign-count regressions per WebAuthn §2.4 (clone detection). The §2.4 corner case where both stored and reported sign counts are `0` is allowed (some authenticators always report `0`). The sign-count update is atomic CAS — concurrent assertion races return `false` and the grant fails with `invalid_grant` rather than minting tokens for a stale view.

## Dependency: SimpleWebAuthn

`@simplewebauthn/server` is pinned to `13.1.1` (S12). The verification helpers and options generators wrap this library; Dependabot tracks major bumps.

## Wave 1 scope boundaries

This package implements **Wave 1 first slice**:

- Primary-login passkeys
- Registration + authentication ceremonies
- Multi-origin support (`config.origin: string[]`), web and Android — see [Multi-origin](#multi-origin-one-rp-for-the-site-and-the-android-app)
- RFC 8707 resource indicator opt-in plumbing (Stage 1, mirroring `client_credentials` / `refresh_token`)
- Refresh-token issuance for allowed clients ([issue #480](https://github.com/o3co/auth.provider/issues/480))

Deferred to subsequent waves:

- WebAuthn as MFA factor (Wave 3)
- RFC 8707 Stage 2 audience-restrict enforcement ([issue #173](https://github.com/o3co/auth.provider/issues/173))
- Attestation root chain verification (Stage 2+)

## License

Apache-2.0 © 1o1 Co. Ltd.
