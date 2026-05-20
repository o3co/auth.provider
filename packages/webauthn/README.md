# @o3co/auth-provider-webauthn

Wave 1 first slice for the [@o3co/auth-provider](https://github.com/o3co/auth.provider) Passkey-native auth toolkit. **AS-scope only** — credential lifecycle + authentication grant. No signup, no recovery, no email infrastructure (consumer's domain per the auth-provider scope discipline).

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
            attestationPreference: "none",   // S11 recommended for dogfood
            userVerification: "preferred",
            challengeTtlMs: 120_000,         // mobile-network safe (spec §2.4.1)
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

The library ships safe defaults for `attestationPreference`, `userVerification`, and `challengeTtlMs` in `config/reference.conf` (resolved via composition-root `withFallback` chain per PR #171 discipline). Consumers MUST supply `rpId` / `rpName` / `origin` — these have no library defaults and the schema reports useful errors if missing (per ADR `packages/core/docs/adr/2026-04-30-config-schema-strict-defaults-from-hocon.md`).

## First-credential bootstrap (dogfood)

WebAuthn registration requires an authenticated subject. For greenfield deployments, the canonical bootstrap path is **federation**: users first authenticate via `@o3co/auth-provider-federation-github` (or `-federation-google`), then enroll a passkey from the authenticated session. Both federation packages ship and are documented separately.

For consumer-driven account flows (signup forms, magic-link, etc.) the consumer owns the first-credential trust establishment outside auth-provider scope (per the `feedback_auth_provider_scope_discipline` rule).

## Endpoints

- `POST /oauth/webauthn/registration/options` — generates `PublicKeyCredentialCreationOptions`. Requires an authenticated subject (upstream session / bearer middleware sets `req.webauthnSubject`).
- `POST /oauth/webauthn/registration/verify` — verifies the attestation response and persists a `WebAuthnCredential`. Single-use challenge via `ChallengeCeremony`.
- `POST /oauth/webauthn/authentication/options` — generates `PublicKeyCredentialRequestOptions`. Unauthenticated; supports both allow-list (`{userId}` body) and discoverable (empty body) flows.
- Grant: `urn:o3co:oauth:grant-type:webauthn` — exchanges a verified assertion for an access token. No refresh token in Wave 1 (deferred to a future minor).

## SECURITY — `userId` opacity

`WebAuthnCredential.userId` is presented to the authenticator as the WebAuthn `user.id` (WebAuthn §5.4.3). It MUST be opaque — no email, no username, no PII. Authenticators persist it and may sync across devices. If your `UserRepository` keys by email or username, map to an opaque handle before calling `webauthnCredentialStore.registerCredential(...)`:

```ts
const opaqueUserId = await deriveOpaqueHandle(realUserId);
await store.registerCredential({ userId: opaqueUserId, /* ... */ });
```

The bootstrap module's `webauthnSubject` should therefore expose the opaque handle as `userId`, not the email or username.

The registration endpoints enforce a 1..64-byte length on `webauthnSubject.userId` (WebAuthn §5.4.3 user-handle constraint). Requests with a userId outside this range fail with 500 `server_error` — this is a consumer-misconfiguration check, not a runtime user error.

## SECURITY — scope authorization

The webauthn grant has **no library-side `allowedScopes` ceiling**. Client credentials and authorization code grants bind issued scope to `client.allowedScopes` at the handler level; webauthn cannot, because the passkey is the authentication event, not a scope authorization token.

`grantPolicy` is the **only scope-bounding gate** for this grant. Policy invocation is unconditional whenever `grantPolicy` is wired — it is NOT gated on `oauth.resourceIndicator.enabled` (that flag controls only whether `body.resource` is forwarded to the policy, per Stage 1 RFC 8707 plumbing). This mirrors the `refresh_token` grant pattern.

**`grantPolicy` is REQUIRED at boot.** As of the Wave 1 post-merge security fix, wiring `webauthnModule` without a `grantPolicy` slot fails fast at `createApp(...)` with a clear error. There is no silent-allow-all path. Deployments that intentionally accept unbounded scope (NOT recommended for production) must wire an explicit no-op policy returning `{ outcome: "allow" }` — making the choice visible in the composition root.

## SECURITY — token revocation limitations

Webauthn access tokens are revocable via `POST /oauth/revoke` ONLY when the grant was invoked with an authenticated client. Without client auth, the AT carries no `client_id` / `azp` claim — the revoke endpoint's ownership check (`client_id ?? azp ?? aud` must match the revoking client) cannot match, and the request returns 200 with no denylist insertion (RFC 7009 fail-closed). Operators relying on AT revocation MUST require client auth on the webauthn grant path (e.g. wire `clientAuthMw` before the grant handler).

## SECURITY — registration authorization strength

The registration endpoints accept any authenticated subject. Deployments SHOULD enforce step-up reauthentication (NIST SP 800-63B): require recent `auth_time` OR MFA OR fresh federation login before allowing registration. The bare endpoint does not enforce this — wire your `grantPolicy` hook or an upstream Express middleware to gate registration to high-assurance sessions.

## SECURITY — rate-limiting `authentication/options`

`POST /oauth/webauthn/authentication/options` is unauthenticated and accepts an optional `userId` body field; the response shape leaks whether a user has registered credentials when `userId` is supplied. Wire the `RateLimiter` ComponentMap slot to throttle by source IP and by supplied `userId` (S10 / S15 wiring established by the OAuth revoke endpoint). Deployments needing full enumeration resistance should omit `userId` and rely on the discoverable-credentials flow exclusively.

## SECURITY — `attestationPreference` default

`attestationPreference` defaults to `"none"` (S11). Dogfood deployments using platform authenticators (Touch ID, Windows Hello, Android biometrics) typically don't need attestation chain verification. Set `"direct"` only when:

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
- Multi-origin support (`config.origin: string[]`)
- RFC 8707 resource indicator opt-in plumbing (Stage 1, mirroring `client_credentials` / `refresh_token`)

Deferred to subsequent waves:

- WebAuthn as MFA factor (Wave 3)
- Refresh-token issuance for the webauthn grant
- RFC 8707 Stage 2 audience-restrict enforcement ([issue #173](https://github.com/o3co/auth.provider/issues/173))
- Attestation root chain verification (Stage 2+)

## License

Apache-2.0 © 1o1 Co. Ltd.
