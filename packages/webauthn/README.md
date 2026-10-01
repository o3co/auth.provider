# @o3co/auth-provider-webauthn

Last updated: 2026-10-02

Passkey (WebAuthn) credential registration and an authentication grant for [`auth.provider`](../../README.md): a user enrolls a passkey from an authenticated session, and later exchanges a passkey assertion for tokens at `/oauth/token`. The package also contributes WebAuthn as a second factor to the MFA package — [WebAuthn as a second factor](#webauthn-as-a-second-factor).

## Responsibility

**Role.** Passkeys as a primary login at the authorization server, and WebAuthn as a second factor after a password. The package adds three ceremony routes under `/oauth/webauthn/` and the `urn:o3co:oauth:grant-type:webauthn` grant, which `/oauth/token` dispatches like any other grant, a module that bridges the browser's session to the registration routes, and a module that contributes the `webauthn` second factor under core's `mfaFactors` kind.

**Owns:**

- the ceremonies: generating registration and authentication options, verifying the attestation and persisting the credential, verifying an assertion and its sign count, and minting tokens for it;
- the bridge from an admitted browser session to `req.webauthnSubject`, `webauthnSessionSubjectModule` — [Registering from a browser session](#registering-from-a-browser-session);
- the WebAuthn second factor, `webauthnMfaFactorModule`: its ceremonies, what it keeps of a credential, and its `amr` — [WebAuthn as a second factor](#webauthn-as-a-second-factor);
- the WebAuthn configuration (`webauthnConfigSchema`, the `webauthnConfig` slot), the second factor's section (`webauthn-mfa-factor`), and their defaults ([`config/reference.conf`](config/reference.conf), exported as `@o3co/auth-provider-webauthn/reference.conf`);
- the algorithm set offered and accepted (`WEBAUTHN_ALGORITHM_IDS`), and the rate limit on the unauthenticated `authentication/options` route;
- the boundary with `@simplewebauthn/server`, the WebAuthn library the verification runs on.

**Does not own:**

- the stores and their contracts — `WebAuthnCredentialStore`, `ChallengeStore` and `ChallengeCeremony` are core's ports (with core's memory implementations); a deployment wires a persistent credential store, and holds it to the port with `webAuthnCredentialStoreContract` from `@o3co/auth-provider-test-kit`;
- the second factor's ceremony — its transaction, its routes under `/session/mfa`, the sealing of what it keeps, the subject lock — and its records (core's `MfaFactorStore`): the MFA package's and core's; this package imports nothing of the MFA package;
- who the user is at registration: the user handle a session maps to is the deployment's `subjectFor`, and whether that session may proceed is core's session admission; a subject taken from a bearer token, or from a cookie session without a user-session store, is set by middleware the deployment writes;
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

The WebAuthn settings live in your HOCON configuration under `webauthn`, beside everything else the composition root loads. Layer this package's [`config/reference.conf`](config/reference.conf) between your `application.conf` and core's own `reference.conf`: it carries the package's defaults and the `WEBAUTHN_*` environment variables that override them. `webauthnModule` declares it as its section's reference, so core's `moduleReferences(modules)` names it among the files to layer (#728). Hand `createApp` what you resolved: boot parses it once, and keeps the `webauthn` section whole — core's schema still mirrors it, checking little more than its keys' types ([#496](https://github.com/o3co/auth.provider/issues/496)) — and a small module hands that section to `webauthnConfigSchema`, which owns the rules:

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
    type AppConfig,
    createApp,
    defineModule,
    memoryWebAuthnCredentialStoreModule,
    memoryChallengeStoreModule,
    defaultChallengeCeremonyModule,
    memoryReplaySeenSetModule,
} from "@o3co/auth-provider-core";
import { webauthnModule, webauthnConfigSchema } from "@o3co/auth-provider-webauthn";
import { parseFile } from "@o3co/ts.hocon";

const shipped = (specifier: string) => parseFile(fileURLToPath(import.meta.resolve(specifier)));

// Resolved, not parsed: createApp parses it once, with every loaded module's schema (#728).
const config = parseFile("config/application.conf")
    .withFallback(shipped("@o3co/auth-provider-webauthn/reference.conf"))
    .withFallback(shipped("@o3co/auth-provider-core/reference.conf"))
    .toObject() as unknown as AppConfig;

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

A module that hard-codes the settings instead (`webauthnConfigSchema.parse({ rpId: …, … })`) works only if it supplies every required field, the ones `reference.conf` defaults included — the schema has no defaults of its own — and then none of the `WEBAUTHN_*` variables below reaches the schema. **With a shared `rateLimiter` wired, the authentication/options budget is not read from this slot.** The module contributes it to the limiter from the app config's `webauthn.rateLimit.authenticationOptions`, so a composition that hard-codes the slot must also set that key to the same values. Otherwise the route runs on the limiter's default (no key), or on the key's values (a different key). Boot warns `webauthn_authentication_options_budget_mismatch` with both values when they disagree (see [SECURITY — rate-limiting](#security--rate-limiting-authenticationoptions)). The warning compares only the app config key with the slot. An explicit `limits.webauthn-authentication-options` in the limiter's own section, which the limiter applies over both, is not compared.

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
`HTTP_CORS_ALLOWED_ORIGINS` uses, read by the same function in core
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
reports it, and a registration or an authentication that reports one is
refused unless the deployment named the embedding origins it accepts.
`@simplewebauthn/server` 14 holds an authentication to that rule and checks no
top origin at registration, so this package holds a registration to the same
rule — both the grant's and the second factor's:

```hocon
webauthn {
  topOrigin = ["https://partner.example"]
}
```

From the environment, `WEBAUTHN_TOP_ORIGIN` is comma-separated the same way,
and an exported-but-empty one reads as unset.

Absent, a reported cross-origin registration or authentication is refused,
which is the right answer for a deployment that never meant to be embedded. A
top origin reported for a ceremony that is not cross-origin is refused too. The
grant's routes answer the refusal as `top_origin_mismatch`
(`400 {"error":"top_origin_mismatch"}` at `registration/verify`), not
`origin_mismatch`, so it does not send an operator to the `origin` list above,
which cannot fix it. The second factor answers it `invalid`, as it answers
every refusal. Same shape rules as `origin`,
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

WebAuthn registration requires an authenticated subject. For greenfield deployments, the usual path is **federation**: users first sign in through a federation package (Google, GitHub, any OpenID Connect IdP — see the [package list](../../README.md#packages)), then enroll a passkey from the authenticated session. The bridge from that session to `req.webauthnSubject` is `webauthnSessionSubjectModule` — [Registering from a browser session](#registering-from-a-browser-session).

For consumer-driven account flows (signup forms, magic-link, etc.) establishing trust in the first credential is the consumer's, outside the authorization server.

## Registering from a browser session

The registration routes read `req.webauthnSubject`; they do not read a session. `webauthnSessionSubjectModule` sets it from the browser's cookie session, through core's [session admission](../core/src/session-admission/README.md) — the one reading of a live session every consumer shares ([the session-admission ADR](../core/docs/adr/2026-09-28-session-admission.md)):

```ts
import { sessionStoreModule } from "@o3co/auth-provider-session";
import { webauthnModule, webauthnSessionSubjectModule } from "@o3co/auth-provider-webauthn";

const app = await createApp({
    modules: [
        sessionStoreModule, // the cookie session it reads — `session-middleware`
        webauthnModule,     // the two registration routes it runs before
        webauthnSessionSubjectModule({
            // The user handle for the admitted session: opaque, 1–64 bytes, never an
            // e-mail or a username (SECURITY — `userId` opacity). Synchronous.
            subjectFor: (session) => ({ userId: session.sub }),
        }),
        // ... the user-session store, the rest of the stack
    ],
    // ...
});
```

- **What it needs.** It requires `sessionRequirementResolver` and `userSessionStore`: the cookie path it serves is the store-backed one, so an admitted session is always a live record the mapper reads. `subjectRevocation`, `auditSink` and `logger` are taken when they are wired; the first two unwired are declared (`oauth.revocation.subject = "unsupported"`, `core.declaredAbsent = ["auditSink"]`), as for every module that takes them. It is a consumer of admission, so the composition declares `core.sessionRequirements.expected`.
- **Where it runs.** One route, `webauthn-session-subject` (`WEBAUTHN_SESSION_SUBJECT_ROUTE_ID`), at `/oauth/webauthn/registration`, after `session-middleware` and before both registration routes, on their two `POST`s alone. Both sides of that order must be installed: without `webauthnModule`, or without the module that contributes `session-middleware` (`sessionStoreModule` / `sessionStoreModuleFor` in `@o3co/auth-provider-session`), boot refuses with `route-order-target-missing`, naming the missing route; without a `userSessionStore`, with `missing-required-component`.
- **`subjectFor` is synchronous in this release.** It is called with the live `UserSession` and answers the subject directly; a Promise is refused as an answer of the wrong shape. Accepting a Promise later widens the type and breaks no mapper written now.
- **What it answers.** It admits the session as `webauthn.register`, which it registers graded `credential_change` — a passkey is a new way into the account, so a registered requirement (MFA's recent-authentication rule, when installed) applies:

| Admission | The request |
| --- | --- |
| `admitted` | `req.webauthnSubject` is `subjectFor(session)`, copied to `userId`, `userName`, `userDisplayName`; the route runs |
| `step_up` | `403 {"error":"step_up_required","error_description":"Registering a passkey requires a step-up first","requirement":"<name>","page":"<absolute URL>"}` — the requirement's page as registered: one absolute URL, resolved at registration on the issuer (`oauth.jwt.issuer`), not on the account page's origin, with its params on the query and no return parameter, as every consumer answers it; the account page sends the user to it — adding its own return parameter if it wants one — and then retries |
| `unavailable` | `503 temporarily_unavailable`, described by what could not answer (core's `describeAdmissionOutage`): "session store unavailable" for the session store, "revocation store unavailable" for the revocation boundary, "session requirement unavailable" for a requirement; logged once by admission as `session_admission_unavailable` (`action: "webauthn.register"`) |
| not signed in (`unauthenticated`) | nothing set or cleared: a subject an earlier middleware set — a bearer-token bridge — stands; without one, the route answers its `401 unauthorized` |
| anything else — not live, past its `expiresAt`, another subject's, revoked, a requirement's `reauthenticate` or `unmet` | no subject — one an earlier middleware set is **cleared**, so a dead cookie session registers nothing — and the route answers its `401 unauthorized` |

A `subjectFor` that throws, answers a subject whose fields throw when read, or answers anything but an object with a non-empty string `userId` (and string `userName` / `userDisplayName` when present), is the composition's fault: `500 server_error`, logged once at error as `webauthn_session_subject_invalid` with `reason` (`threw`, with the error's projection, or `shape`) — never the answer.

**Installing the module replaces the deployment's own cookie bridge — remove it.** A bridge that sets `req.webauthnSubject` from `req.session` would otherwise run beside the module. Mounted before it, its subject is cleared for a dead session and replaced for an admitted one, so it does nothing but add a second reading of the cookie; mounted after it, it overwrites what admission decided with an unchecked reading — a revoked session's subject included.

**Two bridges stay the deployment's own middleware.** A subject taken from a bearer token is not a session this module reads, and the module leaves it in place for a request that carries no signed-in cookie; and a cookie-only composition without a `userSessionStore` cannot install the module (the store is required), so it writes its own bridge too. Either sets `req.webauthnSubject` before the registration routes (a route contribution with `before: ["webauthn-registration-options", "webauthn-registration-verify"]`) and holds itself to the rules below — the opaque handle, and a session strong enough to enroll a credential.

## WebAuthn as a second factor

`webauthnMfaFactorModule` ([`src/mfaFactor/module.mts`](src/mfaFactor/module.mts)) contributes the `webauthn` factor ([`src/mfaFactor/factor.mts`](src/mfaFactor/factor.mts)) under core's `mfaFactors` kind, where the MFA package's `mfa` requirement reads it. It reads its own section, and takes the `webauthnConfig` slot — the relying party the grant uses — when it is wired: with the factor off, the module boots without it; with the factor on and no relying party, the boot is refused (`contribute-factory-failed`, naming `webauthnConfig` and `webauthn.rpId`, `rpName`, `origin`). Installed while the relying party has `allowCredentialsForKnownUser` on, with the factor on or off, the boot is refused too (`contribute-factory-failed`, naming `webauthn.allowCredentialsForKnownUser` and `WEBAUTHN_ALLOW_CREDENTIALS_FOR_KNOWN_USER`): see [SECURITY — an assertion's user handle](#security--an-assertions-user-handle). It is stateless.

```ts
import { webauthnMfaFactorModule } from "@o3co/auth-provider-webauthn";

modules: [
    ...mfaModules({ environment }),   // @o3co/auth-provider-mfa
    webauthnBootstrap,                // the webauthnConfig slot, as above
    webauthnMfaFactorModule,
    // ...
]
```

| Key | Env | Default | Meaning |
| --- | --- | --- | --- |
| `webauthn-mfa-factor.enabled` | `WEBAUTHN_MFA_FACTOR_ENABLED` | `false` | Whether the factor is offered; off, the kind is claimed and no factor is contributed |
| `webauthn-mfa-factor.userVerification` | `WEBAUTHN_MFA_FACTOR_USER_VERIFICATION` | `preferred` | What its registrations and assertions ask for (`required`, `preferred`, `discouraged`); `required` also refuses a response without the UV flag |

The defaults are in [`config/reference.conf`](config/reference.conf); a composition that does not layer it is refused at boot, naming the file. An unknown key in the section is refused by its name.

**What it keeps.** Each factor's data is `{credentialId, publicKey, signCount, transports, backupEligible, backedUp, userHandle}`, which the MFA package seals before it reaches the factor store. `backupEligible` (BE) is fixed at registration and decides the `amr`; `backedUp` (BS) is the backup state the credential last reported, kept for the record and read by no decision. The factor writes its credentials to the MFA factor store only, and none to the grant's `WebAuthnCredentialStore`. Another account can register one there, though, by its id and public key, and the two ceremonies share the relying party's id (below).

**Registration**, which the MFA package's enrollment drives (not yet built there): the options ask for a credential under the subject's WebAuthn user handle — 32 random bytes made at its first WebAuthn enrollment and kept in each such factor's data, never an account name — named for the authenticator by the account's username, never its address (the provider keeps none, and a page shows none), exclude every WebAuthn credential the subject holds, ask for no attestation, offer `WEBAUTHN_ALGORITHM_IDS`, ask for the section's user verification and a resident key `discouraged`. The proof is the `RegistrationResponseJSON`; its attestation is verified, its top origin is held to `webauthn.topOrigin` as an assertion's is ([Being framed](#being-framed-toporigin)), and a credential id the subject already holds is refused as a duplicate. A credential is only ever looked up among its own subject's factors, so one id held by two subjects is not refused.

**Identity.** The factor's `identity` ([`MfaFactor`](../core/src/mfa/factor.mts)) is the credential id a record holds, read as the record's data is: two of a subject's WebAuthn records with one identity hold one credential enrolled twice. A verification leaves it as it was; a new sign count or backup state does not change it. Data the factor cannot read — any field above not as the factor writes it — has no identity, and is judged a duplicate of none; the identity never throws.

**`residentKey: "discouraged"` is advisory.** A synced platform passkey is discoverable whatever is asked. It may then appear in the browser's passkey picker for this relying party and be chosen for the passwordless grant. The grant finds a record for it only if its own store holds that credential id, and a `none` attestation — made from the credential's id and public key alone — can register it there as another account's passkey. The authenticator answers with the subject's second-factor user handle, not that account's, so the grant refuses it ([SECURITY — an assertion's user handle](#security--an-assertions-user-handle)); the credential still works as the second factor.

**Assertion.** The factor's challenge (`POST /session/mfa/challenge`) answers the request options, listing every WebAuthn factor of the subject in `allowCredentials`; its challenge is kept on the MFA transaction, sealed, until the relying party's `challengeTtlMs` or the transaction's end, whichever comes first. The page names the same `factor_id` at the challenge and at the verification, and sends the `AuthenticationResponseJSON` as the `proof`. A verification takes the challenge from the transaction — read and cleared in one step — so an assertion is checked against a challenge once: a second answer to it, or one past its time, is refused (`expired`) and the page asks for a new one. The credential is found by its id among the subject's WebAuthn factors, whichever of them the request named; a user handle the response carries must be that credential's, in the one form the grant accepts, its unpadded base64url, judged once the signature verified (a `null` one is none), and the backup eligibility it reports must be the one registered — BE is fixed when a credential is made (WebAuthn §6.1.3) — or it is refused as invalid. The new sign count and the backup state the assertion reports are written by compare-and-set on the record's version; a lost compare-and-set is no evidence of anything, and the MFA package reads the factor again and checks the assertion again against it.

**The sign count** (WebAuthn §6.1.1) is judged only once the signature verified: an assertion whose signature does not verify is refused as invalid whatever its counter. A signed counter that did not increase over the stored one is refused and audited as `mfa.verify.failure` with `reason: "sign_count_regression"` and `factorId`, the record id of the factor whose credential asserted — a possibly cloned authenticator. A counter of `0` against a stored `0` is an authenticator that keeps no counter: it passes and stays `0`, and gives no clone signal.

**`amr`**: `hwk` for a credential that is not backup-eligible (BE = 0), bound to one device; `swk` for one that is (BE = 1), a multi-device credential, whether or not it is backed up yet; `mfa` beside either. With attestation `none` — what this factor asks for — BE and BS are what the authenticator reports about itself: `hwk` means *reported* device-bound, not proof of hardware. Attested hardware would be `phrh` with attestation, which this factor does not offer.

**Guessing.** A signature cannot be guessed: the factor is not held to the subject lock that bounds TOTP codes, and counts as MFA.

## Endpoints

- `POST /oauth/webauthn/registration/options` — generates `PublicKeyCredentialCreationOptions`. Requires an authenticated subject: `req.webauthnSubject`, set by `webauthnSessionSubjectModule` from the browser's session, or by the deployment's own middleware (a bearer token, a store-less cookie session).
- `POST /oauth/webauthn/registration/verify` — verifies the attestation response and persists a `WebAuthnCredential`. Single-use challenge via `ChallengeCeremony`.
- `POST /oauth/webauthn/authentication/options` — generates `PublicKeyCredentialRequestOptions`. Unauthenticated, rate-limited, and discoverable-credential only: the response never carries an `allowCredentials` list derived from the request. The allow-list flow is available behind `allowCredentialsForKnownUser` — see [SECURITY — `authentication/options` enumeration](#security--authenticationoptions-enumeration).
- Grant: `urn:o3co:oauth:grant-type:webauthn` — exchanges a verified assertion for an access token, plus a refresh token when the authenticated client is allowed one. A sender-bound request produces sender-bound tokens. See [SECURITY — refresh-token issuance](#security--refresh-token-issuance) and [SECURITY — sender-constrained tokens](#security--sender-constrained-tokens).

A store any of these cannot reach is `503 temporarily_unavailable`, logged once — see [Store outages](#store-outages).

## Store outages

A store the grant or a ceremony route needs that cannot answer — the credential store, the challenge store or the ceremony over it (with its replay seen-set), the refresh-token family store — is the server's outage, never a verdict on the passkey: `503 temporarily_unavailable`, with an `error_description` naming the kind of store (`credential store unavailable`, `challenge store unavailable`, `refresh token store unavailable`), logged once at error level with `store`, `step` and the error's projection ([`src/internal/storeUnavailable.mts`](src/internal/storeUnavailable.mts)). No token is issued and no credential is reported stored. Core's in-process challenge store counts as one that cannot answer once it holds its cap of live challenges (`core-challenge-store-memory.maxEntries`, a million by default): it refuses a new challenge with `ChallengeStoreFullError` rather than evict one a user is completing, and the options route answers `503`.

| Where | Store / step | Log line | What a retry meets |
| --- | --- | --- | --- |
| Grant (`/oauth/token`) | `webauthn_credential` / `find` | `webauthn_grant_store_unavailable`, with the client id when one authenticated | nothing was spent: the same assertion can be presented again within the challenge's lifetime |
| | `challenge_ceremony` / `consume` | same | the failure can land after the challenge was deleted (the seen-set write comes after): the retried assertion is then `400 invalid_grant` (`challenge_unknown` / `challenge_replayed`) and the user runs the ceremony again |
| | `webauthn_credential` / `update_sign_count` | same | the challenge is spent, so the user runs the ceremony again; a count the store wrote before losing its reply is below what the next assertion reports |
| | `refresh_token_family` / `register` | same | the challenge is spent, nothing was signed and nothing served; the user runs the ceremony again |
| `registration/options`, `authentication/options` | `webauthn_credential` / `list` (`authentication/options` only with `allowCredentialsForKnownUser`); `challenge` / `issue` | `webauthn_ceremony_store_unavailable`, with `site` naming the route — never the caller's `userId` | ask for options again |
| `registration/verify` | `challenge_ceremony` / `consume`; `webauthn_credential` / `register` | same | the challenge may already be spent, so the same response is then `400 challenge_invalid` and the user registers again; an insert whose reply was lost may have stored the credential, and the new ceremony's `excludeCredentials` then names it — the browser reports the authenticator as already registered, and the passkey signs in |

A duplicate credential is still the client's `400 credential_id_conflict`. The grant and the routes log through the `logger` component, `consoleLogger` when it is unwired.

## SECURITY — `userId` opacity

`WebAuthnCredential.userId` is presented to the authenticator as the WebAuthn `user.id` (WebAuthn §5.4.3). It MUST be opaque — no email, no username, no PII. Authenticators persist it and may sync across devices. If your `UserRepository` keys by email or username, map to an opaque handle before calling `webauthnCredentialStore.registerCredential(...)`:

```ts
const opaqueUserId = await deriveOpaqueHandle(realUserId);
await store.registerCredential({ userId: opaqueUserId, /* ... */ });
```

The `subjectFor` given to `webauthnSessionSubjectModule` — or the deployment's own middleware that sets `req.webauthnSubject` — should therefore expose the opaque handle as `userId`, not the email or username.

**A deployment that shares its RP ID with another system MUST use UUIDs, random bytes or a keyed hash for `userId`s, never sequential or otherwise guessable ids.** The WebAuthn specification asks only that a user handle contain no PII, and SimpleWebAuthn's default handle is random, but this Provider passes `userId` as the handle unchanged (`userHandleOf` in [`src/internal/options.mts`](src/internal/options.mts)). Where another system's handle can equal one of this Provider's `userId`s, a copy of that system's credential, registered to the account with that `userId`, passes the grant's user-handle check and signs its owner in to that account — [Known limitations](#known-limitations), path 2.

The registration endpoints enforce a 1..64-byte length on `webauthnSubject.userId` (WebAuthn §5.4.3 user-handle constraint). Requests with a userId outside this range fail with 500 `server_error` — this is a consumer-misconfiguration check, not a runtime user error — logged once at error level as `webauthn_subject_user_handle_invalid` with the route's `site` and the handle's `byteLength`, never the handle itself. `authentication/options` enforces the same bound on the `userId` a *caller* may supply, but as `400 invalid_request`: there the value is untrusted request data, not your configuration.

## SECURITY — scope authorization

The webauthn grant has **no library-side `allowedScopes` ceiling**. Client credentials and authorization code grants bind issued scope to `client.allowedScopes` at the handler level; webauthn cannot, because the passkey is the authentication event, not a scope authorization token.

The requested `scope` is read strictly by RFC 6749 §3.3's grammar (core's `readSpaceDelimitedParameter`) before the policy sees it: a value that is not a space-delimited list of scope-tokens — a tab, a quote — is `400 invalid_scope`, so a malformed scope never reaches a token's `scope` claim as sent, whatever the policy allows. A value of spaces alone, or a JSON `null` (RFC 6749 §3.2), requests no scope; a tab alone is malformed, and a value that is not a string is `400 invalid_request`.

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

**Its lifetimes are read when the grant is built.** `createWebAuthnGrant` reads them from the oauth module's `oauthTokenSettings` when the composition holds the slot ([#728](https://github.com/o3co/auth.provider/issues/728)) — as it does `resourceIndicator.enabled` — and otherwise reads `oauth.accessToken` and `oauth.refreshToken.expiresIn` through core's `resolveAccessTokenLifetime` and `resolveRefreshTokenLifetime` in its factory. A hand-built configuration they refuse — a missing refresh lifetime included, which used to sign a refresh token with no `exp` — throws a `RangeError` naming the key, so no request reaches the ceremony and no challenge is consumed. It requires `oauth.refreshToken.expiresIn` even in a deployment where no client can receive a refresh token — no registration names `refresh_token` in its `allowedGrantTypes`. That only matters for a configuration built by hand: the schema requires the key in every loaded configuration, and `reference.conf` ships a value. Both lifetimes are read once, so changing either on the configuration object after boot has no effect until the grant is built again.

**Rotation and replay detection are the shared ones.** The grant opens a refresh-token family through the `refreshTokenFamilyRotation` component, the same one the authorization-code grant registers its initial `rt+jwt` with: one active token per family, and a replayed token revokes the whole family (RFC 6819 §5.2.2.3). The lifetime comes from `oauth.refreshToken.expiresIn`. Registration is fail-closed and comes first: the refresh token's `jti` and the instant its lifetime is measured from are reserved, and the family registered under them with the expiry `issuedAt + oauth.refreshToken.expiresIn`, before either token is signed — core's `generateToken` then signs exactly that `jti` and `iat` (#449, as the refresh grant does). A family store that cannot be reached therefore answers `503 temporarily_unavailable`, logged as `webauthn_grant_store_unavailable` (see [Store outages](#store-outages)), with nothing signed and nothing served. The reverse case — signing fails after the family was registered, a KMS outage — leaves a family no token was served for: harmless, and gone at the expiry it was registered with. Both the access and the refresh token carry the `family_id` claim, so revoking the family reaches the access token too.

**Sender-bound requests produce sender-bound refresh tokens.** A DPoP or mTLS request has its RFC 7800 confirmation (`cnf.jkt` / `cnf.x5t#S256`) carried into the refresh token on the same gate the other grants apply: public clients always; confidential clients only when the deployment sets `core.tokenBinding.bindConfidentialClientRefreshTokens` ([#275](https://github.com/o3co/auth.provider/issues/275)), since their client secret is already the refresh-time authenticator. The setting is core's, read through core's `resolveTokenBindingSettings` as the oauth grants read it ([#728](https://github.com/o3co/auth.provider/issues/728)). The access token binds on its own, wider gate — see below.

## SECURITY — `auth_time` is one challenge lifetime pessimistic

The access and refresh tokens carry `amr: ["hwk"]` and `auth_time` (RFC 9470 §6.1), which the refresh grant carries forward. A signed assertion stays redeemable until its challenge expires, so the grant cannot tell when within that window the user made the gesture, and stamps the earliest instant it could have been made: the time the grant received the assertion, read before it spends the challenge, less `challengeTtlMs` — the challenge was still live when spent, so it was issued no earlier than that, and the gesture came after its issuance. `auth_time` is therefore never later than the authentication and at most one challenge lifetime earlier (120 s with the shipped default). A resource server applying `max_age` may ask a user who authenticated just inside its limit to authenticate again, and a `max_age` shorter than `challengeTtlMs` is never met by a passkey token. `createWebAuthnGrant` reads the lifetime from `webauthnConfig.challengeTtlMs`, which `webauthnModule` fills from the `webauthn` section; a test builds that section with `createTestWebAuthnConfig` from `@o3co/auth-provider-webauthn/testing`.

## SECURITY — sender-constrained tokens

**A sender-bound request produces a sender-bound access token.** When the request carries a DPoP proof or a client certificate, the resulting access token carries the matching RFC 7800 confirmation — `cnf.jkt` for DPoP, `cnf.x5t#S256` for mTLS — and a resource server that enforces binding accepts it only from the same key or certificate. It is the member the binding's mechanism owns (core's `ownedConfirmation`), the rule every grant applies: a contributed mechanism whose kind owns neither member, or a binding carrying a member its kind does not own, gets an unbound token, and a compound confirmation keeps the owned member alone. The webauthn grant has no rule of its own.

**The gate is wider than the refresh token's.** The access token binds whenever the request carried a confirmation its mechanism owns, with no further condition — including for a confidential client, whose refresh token stays unbound by default. The two are different questions: a confidential client re-authenticates itself at every refresh, which is why RFC 9449 §5 leaves its refresh token unbound rather than pin it to one key for days; nothing of the sort protects an access token, which a resource server checks on every call.

**`token_type` says which kind was minted** — core's `generateTokenResponse` reads it off the access token's `cnf`. A DPoP-bound access token is announced as `DPoP` (RFC 9449 §5). An mTLS-bound one keeps `Bearer` — it travels as a bearer token and is checked against the TLS client certificate (RFC 8705 §3). An unbound request is answered exactly as before: `Bearer`, and no `cnf` on either token.

**A client registered `senderConstrained` is refused before this grant runs.** The `/token` route's shared dispatch gate rejects a request that presents no binding with `401 invalid_client`, one whose binding kind is not in the client's `methods` with `400 unauthorized_client`, and one whose binding carries no confirmation its kind owns with `400 invalid_request` — for every `grant_type`, this one included. The grant handler holds no second copy of that rule; its part is the other half, above — a request that proves its key gets a token bound to it ([#489](https://github.com/o3co/auth.provider/issues/489)).

## SECURITY — token revocation limitations

Webauthn access tokens are revocable via `POST /oauth/revoke` ONLY when the grant was invoked with an authenticated client. The access token then carries the client's `client_id`. Without one it carries no `client_id` / `azp` claim — the revoke endpoint's ownership check (`client_id ?? azp ?? aud` must match the revoking client) cannot match, and the request returns 200 with no denylist insertion (RFC 7009 fail-closed). Through `oauthModule`'s `/oauth/token` the client is always authenticated; a composition that dispatches the grant from its own route must authenticate the client there too (`createClientAuthMiddleware` from `@o3co/auth-provider-oauth`) if it relies on access-token revocation.

## SECURITY — registration authorization strength

The registration endpoints accept any authenticated subject. Deployments SHOULD enforce step-up reauthentication (NIST SP 800-63B): require recent `auth_time` OR MFA OR fresh federation login before allowing registration. The endpoints do not enforce this, and `grantPolicy` does not reach them — it gates the grant at `/oauth/token`, not registration.

With `webauthnSessionSubjectModule`, registration is admitted as `webauthn.register`, graded `credential_change`: every registered session requirement is asked, and one that demands recent authentication — the MFA requirement's rule for that grade — answers `403 step_up_required` until the session meets it. With no requirement registered, the module checks that the session is live, is its own subject's, and is not covered by the subject-revocation boundary — nothing about how recent it is. A deployment's own bridge gates registration itself: set the subject only for a session strong enough to enroll a credential.

## SECURITY — `authentication/options` enumeration

`POST /oauth/webauthn/authentication/options` is unauthenticated by design — the passkey assertion *is* the authentication event. That makes its response body a public oracle, so the endpoint answers the same thing to everyone.

**The response is always the discoverable-credential shape.** No `allowCredentials` member is derived from a body-supplied `userId`, the credential store is not consulted, and the body, its key set, and the work behind it are identical for a registered account, an unregistered one, and a request naming no account at all. A populated `allowCredentials` for a real account and an empty or absent one otherwise would be an unauthenticated "does this account exist, and how many passkeys does it have?" query for anyone who asked ([#281](https://github.com/o3co/auth.provider/issues/281)).

**`allowCredentialsForKnownUser: true`** derives `allowCredentials` from a supplied `userId`. Set it only for a deployment whose authenticators cannot do discoverable credentials — non-resident keys, typically an older security-key fleet — where the client genuinely needs to be told which credential ids to offer. It reinstates the enumeration oracle for that deployment; the `200`-for-everyone / no-error-shape mitigation is all that remains, and it is not enough on its own. Pair it with a tight `rateLimit.authenticationOptions` and, where you can, put an authenticated identifier-first step in front of the endpoint instead. With the flag on, a credential that returns no user handle — a non-resident security key, such as a WebAuthn second factor's — can be registered by another account through the grant and then sign its owner in as that account ([an assertion's user handle](#security--an-assertions-user-handle)): keep the flag off where WebAuthn second factors are enrolled. `webauthnMfaFactorModule` refuses the boot while it is on. The same holds for such a credential — one that returns no user handle — from another system on the RP ID, which the refusal does not see: [Known limitations](#known-limitations), path 1. Path 2 there, a discoverable credential whose user handle equals another account's `userId`, does not depend on the flag.

**`userId` is bounded before it reaches any store.** The optional body field must be an opaque handle of 1–64 UTF-8 bytes with no control characters (WebAuthn §5.4.3, the same bound the registration endpoint enforces on the session-derived handle). Anything else is `400 invalid_request` with a single fixed `error_description` that does not vary with what the server knows about the value.

## SECURITY — rate-limiting `authentication/options`

The endpoint is rate-limited by the module itself; it is not something a composition root has to remember to add. `webauthnModule` mounts core's shared `createRateLimitGuard` in front of the route:

- **Keyed** `webauthn-authentication-options:ip:<ip>` — exported as `WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG`, which is also the prefix the module contributes its budget under and the `limits` key an operator overrides it by.
- **Spec** from `webauthn.rateLimit.authenticationOptions` (`limit` / `windowSeconds`; reference default 30 per 60 s; the window at most one year). The module contributes that key as the tag's budget (a `rateLimitBudgets` contribution), which both bundled limiter modules, core's memory one and Redis's, read — as they read the `login` budget the session module contributes from `session.rateLimit.login` — so a shared limiter applies the configured budget rather than its own `defaultLimit`. An explicit `limits.webauthn-authentication-options` wins. If the key is given but no limiter can apply it, boot is refused with a `RangeError` naming `webauthn.rateLimit.authenticationOptions`; the budget is never replaced by the default. A custom limiter reads the contributed budget from the `rateLimitBudgetResolver` slot, or has to be given the spec itself. Only the per-process fallback below is built from the `webauthnConfig` slot, so a composition's bootstrap should read `webauthnConfig` from that same section. The RFC `RateLimit-*` headers show the budget the limiter actually applied, which both bundled adapters report. The slot backs them only for an adapter that reports no `limit` of its own. When a shared limiter is wired and the contributed budget for the tag (`rateLimitBudgetResolver`, which the module requires) is missing, or differs from the slot, boot logs `webauthn_authentication_options_budget_mismatch` (warn, once) with `key`, `contributed` and `webauthnConfig`. The contributed budget is the key's, numeric strings counting as their numbers, unless another module overrode it — an override may only tighten it. An explicit `limits.webauthn-authentication-options`, which the limiter applies over both, is not compared.
- **Outage policy** is the limiter's own `failMode` — the Redis limiter's is `redis-rate-limiter.failMode` — the one `/oauth/token` and `/session/login` apply on the same limiter: a limiter outage must not shed load on one surface and wave everything through on another. An outage logs `rate_limiter_failed_open` / `rate_limiter_failed_closed` and emits a `rate_limit.unavailable` audit event when an `auditSink` is wired.

Wire the `rateLimiter` ComponentMap slot (the Redis adapter in a scaled deployment) so the buckets are shared across replicas. **Without it the route is still guarded**, by a per-process memory limiter, and boot warns `webauthn_authentication_options_rate_limiter_not_shared` naming the spec in force — a per-process bucket is weak protection, not absent protection, and the warning says which one you have. That is the unset-`core.deployment.mode` behaviour: under `core.deployment.mode = "multi"` the fallback is refused at boot instead (a `replica-unsafe-adapter` BootError naming the route, wrapped in `contribute-factory-failed`), because a per-replica budget is the limit multiplied by the replica count; under `"single"` it is silent. The module reads the mode from core's `deploymentMode` slot, which it requires and core fills from `core.deployment.mode`; it reads nothing of `deployment` itself.

## SECURITY — `attestationPreference` default

`attestationPreference` defaults to `"none"`: attestation chain verification adds nothing for the common platform-authenticator case. Deployments using platform authenticators (Touch ID, Windows Hello, Android biometrics) typically don't need attestation chain verification. Set `"direct"` only when:

- Your threat model requires authenticator provenance verification (e.g. enterprise device fleet, FIDO2 metadata service consumer)
- You have a curated trust anchor set (FIDO MDS root list) wired into your verifier

Attestation root verification is partial, and which half you get depends on the format. `@simplewebauthn/server` ships default trust anchors for `apple`, `android-key` and `android-safetynet`, and validates the `x5c` chain against them. For `packed`, `tpm` and `fido-u2f` it holds no anchors and skips path validation entirely, so provenance for those formats remains your responsibility.

For the anchored formats the check is fail-closed (the library's fix for GHSA-6hxq-p678-4hr2): a chain that does not actually terminate at a shipped anchor is rejected. The library throws on a chain failure, and none of the reason regexes below match its message, so it surfaces from the verify endpoint as `400 {"error": "unknown"}` — there is no dedicated discriminant for it.

## SECURITY — sign-count handling

The grant rejects sign-count regressions per WebAuthn §2.4 (clone detection), judged only once the assertion's signature verified: the library is handed a stored count of `0`, so its own count check, which runs before the signature's, never refuses. The §2.4 corner case where both stored and reported sign counts are `0` is allowed (some authenticators always report `0`). The sign-count update is atomic CAS — concurrent assertion races return `false` and the grant fails with `invalid_grant` rather than minting tokens for a stale view. The second factor applies the same counter rule, and reads a lost compare-and-set again rather than failing — [WebAuthn as a second factor](#webauthn-as-a-second-factor).

## SECURITY — an assertion's user handle

The grant refuses an assertion whose user handle is not that of the account its credential record belongs to (WebAuthn §7.2 step 6): `400 invalid_grant`, `error_description` `user_handle_mismatch`, audited as `token.issued.failure` with `details.reason` `user_handle_mismatch`. The owner's handle is the UTF-8 bytes of the record's `userId`, which the registration options name as `user.id`. The one form accepted is its unpadded base64url, the form the options carry it in and `PublicKeyCredential.toJSON()` writes. It is judged once the challenge is spent and the signature verified, so only the holder of the key learns the reason.

**Clients that answer another form are refused.** Each of these was signed in before the check, and now gets `400 user_handle_mismatch`:

- a passkey registered through a frontend on `@simplewebauthn/browser` before v10, and asserted through v10 or later or a native client. Before v10 the browser library makes the handle from the text of the options' `user.id`, its UTF-8 bytes, so the authenticator answers those bytes;
- the reverse: a passkey registered through v10 or later or a native client, and asserted through a frontend before v10, which answers the handle's bytes read as text — the raw `userId`;
- a client of the deployment's own that pads the handle, or writes it in the standard base64 alphabet.

A client on v10 or later, or a native one, answering the handle as the options gave it is not affected. After upgrading, watch `token.issued.failure` with `details.reason` `user_handle_mismatch`: a steady rate from one client is one of these clients.

This relying party's other ceremonies — the [second factor](#webauthn-as-a-second-factor) — make credentials under other user handles, and a `none` attestation proves no possession of the key: anyone who knows a credential's id and public key can register it as their own passkey. The check keeps that credential, asserted by its owner's authenticator, from signing its owner in as the account that registered it.

An assertion carrying no user handle — absent, or `null` — is not refused on this ground: a non-discoverable credential returns none. Such a credential answers only a ceremony whose options list it, which `authentication/options` does only under `allowCredentialsForKnownUser`, for the `userId` the caller supplies ([enumeration](#security--authenticationoptions-enumeration)). The registration does not see the second factor's credential ids, so it does not refuse one: with the flag on, a second factor's non-resident key registered by another account could sign its owner in as that account. `webauthnMfaFactorModule` therefore refuses the boot while `allowCredentialsForKnownUser` is on. Such a credential from another system on the RP ID is not covered by that refusal, and a credential whose handle equals its record owner's passes this check whoever holds it: see [Known limitations](#known-limitations), paths 1 and 2.

## Known limitations

**A passkey registration does not prove possession of the key.** `registration/verify` accepts a `none` attestation, whatever `attestationPreference` asks for: the verify endpoint does not require the format it requested, and `packed`, `tpm` and `fido-u2f` chains are not validated ([`attestationPreference` default](#security--attestationpreference-default)). The new credential is not asked to sign a second challenge. So an account can register, as its own passkey, a credential whose id and public key it knows but whose private key it does not hold. Neither is secret: an assertion carries the credential's id, and one observed ES256 assertion is enough to recover the public key (ECDSA public-key recovery leaves at most a few candidates, which a second assertion tells apart).

[The user-handle check](#security--an-assertions-user-handle) refuses such a credential when its assertion carries a handle other than its record owner's. Two paths stay open, and on both the attacker must know the credential's id and public key.

**Path 1 — a credential that returns no user handle, while `allowCredentialsForKnownUser` is on.** A non-discoverable credential from another system that shares the RP ID returns no user handle, so the check does not apply. `authentication/options` lists it only under the flag, for the `userId` the caller names: the attacker registers the credential to the attacker's own account and has its owner — the victim — sign in on an identifier-first page that names that account. The default settings close this path: the flag is `false` in [`config/reference.conf`](config/reference.conf), and then `authentication/options` lists no credentials. This Provider's own WebAuthn second factor is such another system: combining the flag with `webauthnMfaFactorModule` is refused at boot ([WebAuthn as a second factor](#webauthn-as-a-second-factor)). The refusal holds only while the module is installed: second-factor keys enrolled before it was removed fall outside it, as another system's keys do. The boot cannot see systems outside this Provider: a deployment that turns the flag on checks for them itself.

**Path 2 — a discoverable credential whose user handle equals another account's `userId`.** Another system that shares the RP ID issues a discoverable credential to the victim under a user handle that equals this Provider's `userId` for the attacker's account — as two separate id spaces of sequential numbers can. The attacker registers the credential to that account. The handle check passes, so the flag does not matter: the discoverable flow needs no `allowCredentials`, and the victim's browser offers the credential on this Provider's sign-in page. Only `userId`s that cannot collide close this path — [`userId` opacity](#security--userid-opacity).

On either path, the grant verifies the victim's assertion against the copied public key and mints tokens for the account the record belongs to. The victim is signed in to the attacker's account. It is not a takeover of the victim's account: the attacker gains no access to it. But what the victim then does or enters, believing it is their own account, lands in the attacker's account, where the attacker can see it. The copied credential stays registered, so the attack can be repeated.

**The root fix is a proof of possession at registration:** the new credential signs a second, fresh challenge before it is stored, which closes both paths. That adds one more touch of the authenticator to every registration and changes the registration API. It will be added when a deployment needs it.

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
- WebAuthn as a second factor, contributed to the MFA package: asserted through its routes; enrolled through its enrollment, which the MFA package does not yet offer

Not implemented:

- The passwordless grant stamping `hwk` or `swk` by the backup state: it stamps `hwk` for every passkey
- Audience derivation from `resource` for this grant — `client_credentials`, `refresh_token` and `/authorize` derive it; here `resource` reaches the policy hook and nothing else, and the audience a passkey token gets is the rule on `AuthenticatedClient.allowedAudiences` ([#520](https://github.com/o3co/auth.provider/issues/520))
- Attestation root verification for the formats the library ships no trust anchors for (`packed`, `tpm`, `fido-u2f`) — see [`attestationPreference` default](#security--attestationpreference-default)
- Proof of possession at registration — see [Known limitations](#known-limitations)

## Source layout

- [`src/module.mts`](src/module.mts) — the assembly: the manifest, its required and optional slots, the three routes and the grant, the rate-limit guard and its replica-safety refusal.
- [`src/grant.mts`](src/grant.mts) — the grant: assertion verification, the sign-count update, the policy call, and token minting.
- `src/routes/` — the three ceremony handlers, one per endpoint.
- `src/internal/` — the SimpleWebAuthn boundary (options generation, response verification, a response's client data read as the library decodes it, and the mapping of library failures onto this package's error codes), and the one answer to a store outage the grant and the routes share.
- [`src/sessionSubject.mts`](src/sessionSubject.mts) — `webauthnSessionSubjectModule`: the session bridge on core's admission.
- `src/mfaFactor/` — the second factor: its module, the factor and its section's schema.
- [`src/config.mts`](src/config.mts) — the config schema and the `webauthnConfig` slot; [`src/request.mts`](src/request.mts) — the `req.webauthnSubject` augmentation.
- [`src/testing/index.mts`](src/testing/index.mts) — the testing entry, `@o3co/auth-provider-webauthn/testing`: `createTestWebAuthnConfig`, the `webauthn` section a test builds, and `webauthnMfaFactorConfigForTests`, the `webauthn-mfa-factor` section.

The ports these depend on (`WebAuthnCredentialStore`, `ChallengeCeremony`, `ChallengeStore`, and the second factor's `MfaFactor` contract) are core's.

## License

Apache-2.0 © 1o1 Co. Ltd.
