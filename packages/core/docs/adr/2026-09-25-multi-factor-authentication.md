# Multi-factor authentication: a second factor after password login, and step-up at `/authorize`

- Status: accepted (2026-09-25); not implemented yet — the build order below is the plan at acceptance
- Date: 2026-09-25
- Replaces: the MFA extension surface added by #69 (2026-04-21) in `packages/core/src/mfa/`, which no product code has ever called (D3)
- Written against: `develop` at `d3d9c8f2` (#692). Every "today" below was checked there, and the sibling repositories at their `develop`.

## Context

### What the owner decided

- **Where a second factor is required.** (a) After a password login (`POST /session/login`). (c) As a step-up, when a relying party asks at `/authorize` through `acr_values` and/or `max_age` (and `prompt=login` where it applies). Not now, with room left for both: after a federated login, and a per-client mandatory requirement.
- **Factors.** WebAuthn as a second factor (reusing `packages/webauthn`); an email one-time code sent over SMTP; TOTP (RFC 6238) with the standard `otpauth://` provisioning URI and QR code, SHA-1 / 6 digits / 30 s by default, working with authenticator apps and Apple's Passwords app.
- **Enrollment.** Self-service, and forced at the first login of a user who has no factor. Enrollment data may live in the deployment's Store. Administrators never enroll a factor for a user.
- **Tokens.** RFC 8176 `amr`, an `acr` scheme, `acr_values` honoured by a step-up or a re-authentication, `auth_time`.
- **Default.** On by default; opt-out through create-app / the template's switches and config.
- **Packaging.** A separate package is preferred; core is acceptable. Decide and justify.

### What exists today

**The login.** `POST /session/login` (`packages/session/src/routes/Session.mts`) is a JSON endpoint behind the session CSRF guard and the shared `login` rate-limit guard. On a correct password it creates a `UserSession` with `amr: ["pwd"]` and `authTime: now`, records it in `SubjectSessionIndex`, regenerates the express session, sets `isAuthenticated` / `user` / `sid`, saves before answering, issues a fresh CSRF token, and answers `200 {"message":"Logged in successfully"}`. Every store it cannot do without is `503`, logged once as `login_store_unavailable`. The login page is the deployment's: `/authorize` sends the browser to `endpoints.login.url?redirect_to=<the authorize URL>`, and the page navigates back to that URL verbatim.

**The federated login.** The federation callback (`packages/session/src/routes/Federation.mts`) creates the `UserSession` with `amr` = the upstream IdP's `amr` as the provider surfaced it, **plus** `fed` (`federatedAmr`). `FEDERATED_AMR` (`"fed"`) is exported from `@o3co/auth-provider-session` (`packages/session/src/index.mts`), not from core. So today an upstream `pwd`, `mfa` or `hwk` sits in the session's `amr` beside `fed`, is stamped on tokens, and satisfies `acr_values` (#481 chose this).

**`/authorize`** (`packages/oauth/src/routes/authorize.mts`). It reads the live `UserSession` behind `req.session.sid` (`readLiveSession`, fail-closed); a session with no `sid`, or a composition with no store, reads as `session: null`. An unauthenticated request is sent to the login page before the client is even looked up, and no ask is written for it. `prompt` is read strictly (`none`, `login`, `consent`). `max_age` and `prompt=login` go through `evaluateReauthentication`: a stale or forced session is sent to the login page with a **re-authentication ask** (`packages/oauth/src/routes/reauthAsk.mts`) — a record in the express-session store under `reauth:<256-bit id>`, 10-minute TTL, bound to the canonical authorize URL. Whenever `max_age` or `prompt=login` is present, any presented ask is **consumed**, and the request proceeds only if `authTime` is later than the ask. `acr_values` goes through `resolveAcr` against `oauth.authorize.acrValues` (acr → the `amr` values a session must carry): the first requested value the session satisfies becomes the code's `acr`; none is `unmet_authentication_requirements`. There is no step-up. A `claims` parameter is ignored. Consent (`packages/oauth/src/routes/consent.mts`) parks the request in a `PendingConsentStore` record bound to the express session id; its resume URL (`resumeUrl`) carries every parameter back — `prompt=login`, `max_age` and `reauth_ask` included — and its comment still says the login ask is "recorded on the session", which it has not been since the ask became a record of its own.

**Other consumers of an authenticated browser session.** The `session` grant (`packages/oauth/src/grants/session.mts`) mints from the tracked session. Device verification (`packages/device-grant/src/verificationEndpoint.mts`) approves a device code on `req.session.isAuthenticated` alone — no liveness read, no `amr` — and the device grant mints an access token with no `amr` and no refresh token. The federation-grants browser half (`packages/federation-grants/src/browserRoutes.mts`) checks the same flag and re-reads the durable session. The federation route's `?link=1` binds a new federated identity to the authenticated user. WebAuthn registration trusts `req.webauthnSubject`, set by middleware the deployment writes.

**Claims.** `wellFormedAmr` / `wellFormedAcr` (`packages/core/src/grants/authenticationClaims.mts`) are the one reading of the two claims. The `authorization_code` grant (`packages/oauth/src/grants/authorization.mts`) reads `amr` from the `UserSession` at `/token` and `acr` from the code, and stamps both on the id_token, the access token and the refresh token; `auth_time` goes on the id_token only (`packages/core/src/grants/idToken.mts`). The refresh grant copies `amr` / `acr` forward from the refresh token without reading a session. The `session` grant mirrors the tracked session's `amr`. The WebAuthn grant stamps `["hwk"]` and creates no session. Discovery advertises the keys of `acrValues` as `acr_values_supported` (`packages/oauth/src/module.mts`). Introspection answers neither `acr`, `amr` nor `auth_time` (`packages/oauth/src/types/introspect.mts`).

**The session record.** `UserSession` (`packages/core/src/user-sessions/types.mts`) is `sid`, `sub`, `authTime`, `createdAt`, `expiresAt`, `claims`, and `amr` (a required key since #626). It is immutable after `create`; the store is `create` / `get` / `delete`. The Redis adapter (`packages/redis/src/userSessionStore.mts`) is one JSON string key with a PX TTL. `revokeAllForSubject` (`packages/core/src/user-sessions/revokeAllForSubject.mts`) is what a Store calls after a credential change.

**WebAuthn** (`packages/webauthn`). Passkeys as a *primary* login: three ceremony routes under `/oauth/webauthn/`, the `urn:o3co:oauth:grant-type:webauthn` grant, `@simplewebauthn/server` pinned exactly. The ceremony helpers are `internal/options.mts` — `generateRegistrationOptionsForUser` and `generateAuthenticationOptionsForUser`, which take `WebAuthnCredential[]` and hard-code `residentKey: "preferred"` — and `internal/verification.mts`. Challenges go through core's `ChallengeStore` + `ChallengeCeremony` over the `ReplaySeenSet`. Credentials live in core's `WebAuthnCredentialStore` port, which has a memory adapter and **no** Redis adapter. The standalone template does not install the package.

**Rate limits** (`packages/core/src/ratelimit/`). `createRateLimitGuard` keys `<tag>:ip:<ip>` and applies `rateLimit.failMode` (default `closed`); `checkWithFailMode` is the same policy for a caller-built key. Per-endpoint budgets in their own config slices are seeded into both limiter adapters by `resolveSeededLimitSpecs`, and their prefixes are core constants (`webauthnSpec.mts` is the pattern).

**CSRF** (`packages/session/src/csrf.mts`). A stateless, HMAC-signed double-submit token plus a strict `Origin` / `Referer` check, not bound to a session — on purpose, because `/session/login` is reached before there is one.

**Stores and sealing.** A port lives in core with its memory adapter and `memory…Module`, which declares `replicaSafety` (`packages/core/src/boot/replica-safety.mts`); the Redis adapter, its client interface (`packages/redis/src/clients.mts`) and its module live in `packages/redis`; each port has a shared contract suite. Federation grants seal their credential with a `v2` AES-256-GCM envelope under a key ring (`sealCredential` / `openSealedCredential` in `packages/redis/src/internal/crypto.mts`).

**The Store** (`packages/foundation`). `HttpUserRepository` posts JSON to one URL per operation, with one bearer token for the trust domain, `https` (or loopback `http`), no redirects, a deadline, a response cap, and errors that never carry what the transport saw. `docs/adapter-surface.md` holds the library to "verify-only" with the Store, with one write-causing seam (`linkFederatedIdentity`).

**Switches.** The template's `buildModules` (`templates/standalone/src/buildModules.mts`) installs modules from config switches and nothing for a feature that is off. `create-app` (`create-app/src/index.mts`) copies the template and has no feature flags (`--dir`, `--no-lockfile`). A scaffold owns its copy: upgrading packages never changes its `buildModules` or `application.conf`.

**Sibling repositories.** The umbrella E2E (o3co/auth) pins the provider by commit (`PROVIDER_REV` in its `Makefile`, since o3co/auth#31), logs in through `POST /session/login` expecting a session (`tests/shared/oauthFlow.js`), and mounts `tests/abac/application.conf` over the template. auth.proxy's session-grant client (`src/modes/injection/session-grant-client.mts`) maps a `400 invalid_grant` to `session_unauthorized` and any other `400` to `provider_config_error`.

**The #69 surface** (`packages/core/src/mfa/`). `MfaProvider` (`issue(userId)` / `verify(challengeId, proof)`), the `SupportsEnrollment` / `SupportsRevocation` capabilities and guards, `createMfaProviderFactory`, `MfaCoordinator` (`listEnrolled`), `MfaTransactionStore` (`set` / `get` / `delete` of an `MfaPendingTransaction` carrying an `MfaResumeState`), `createMfaRouter` (`POST /auth/mfa/verify`, resuming through three callbacks the composition root supplies), the `mfaFactors` contribution kind (`MfaFactor = MfaProvider`), and the boot check `mfa-partial-wiring`. The three slot names are not even declared on `ComponentMap`. The core README says: "Core provides the port and the router and nothing that uses them."

**Conventions this design keeps.** A store outage is `503 temporarily_unavailable`, logged once at error with `store`, `step` and `loggableError`'s projection, and never read as a verdict. An optional slot with a security consequence is "optional to wire, not optional to decide" (`AbsencePolicy`). An unsupported security-relevant request parameter is refused, not ignored (#284). Pages are the deployment's. A record answered by one party is consumed atomically (#552). Every concept has one home (`docs/design-vocabulary.md`).

## Vocabulary

- **Primary authentication**: what establishes who the user is — today a password (`pwd`) or a federation (`fed`). Recorded as `authentication.primary` (D9).
- **Upstream `amr`**: what a federated IdP asserted about its own login — the IdP's statement, not this provider's (D13).
- **Second factor** (a *factor*): a verifier bound to one subject after the primary — a TOTP secret, an email address, a WebAuthn credential, a set of recovery codes. A **counting factor** satisfies "this user has MFA" (TOTP, WebAuthn, email); recovery codes do not count.
- **Guessable / exempt**: a guessable proof (a TOTP code, the email factor's 6-digit code) is subject to the subject lock; an exempt one cannot be guessed (a WebAuthn signature, an 80-bit code) and is not (D21).
- **First binding**: the enrollment of a subject's first counting factor, authorized by the primary alone — or by the primary and an email proof (D24).
- **MFA transaction**: the short-lived, single-use record of one second-factor ceremony, bound to the browser session that started it.
- **Step-up**: adding a second factor to an existing, live session without repeating the primary.
- **Re-authentication**: a new session — primary and second factor again — as `max_age` and `prompt=login` ask.
- **Baseline**: the deployment's own requirement (`mfa.mode`), as opposed to one a relying party asks for with `acr_values`.
- **Recent MFA**: a second factor verified in this session within `mfa.manage.maxAgeSeconds`.
- **The flip**: the release in which MFA becomes on by default (§8, PR 22).

---

## 1. Architecture

### D1 — One new package, `@o3co/auth-provider-mfa`; the ports and the requirement rule in core

| Home | Holds |
| --- | --- |
| `packages/core/src/mfa/` (reshaped) | The `MfaFactor` contract; the `MfaFactorStore` and `MfaTransactionStore` ports with memory adapters, factories and `memory…Module`s; the `MfaCoordinator` slot type and `MFA_ABSENCE_POLICY`; the `mfaFactorResolver` synthetic key; the requirement rule (`requirement.mts`); the `amr` constants and composition, `FEDERATED_AMR` among them (moved from session, D13). |
| `packages/core/src/mail/` (new) | The `MailSender` port and the `mailSender` slot; a recording sender under `testing/`. |
| `packages/core/src/sealing/` (new leaf) | The `v2` key-ring envelope, moved from `packages/redis/src/internal/crypto.mts`. |
| `packages/core/src/ratelimit/` | The MFA budgets' prefixes and seeds (`mfaSpec.mts`), beside `loginSpec.mts` and `webauthnSpec.mts`. |
| `packages/core/src/repositories/` | The enrollment witness (D12): `User.mfaEnrolled` documented, and an optional `UserRepository` capability `markMfaEnrolled` with its guard. |
| `packages/core/src/user-sessions/` | `UserSession.authentication` and the step-up capability (D9); `revokeAllForSubject` also clears the subject's MFA lock state (D21). |
| `packages/mfa` (new) | The coordinator (fills `mfaCoordinator`); the browser API under `/session/mfa/*`; the TOTP, email and recovery-code factors; key-ring configuration; lockout; audit; notices; the operator reset. Modules: `mfaModule`, `mfaTotpFactorModule`, `mfaEmailFactorModule`, `mfaRecoveryCodeFactorModule`, `mfaModules`. `"private": true` until the template wires it (§8, PR 20). |
| `packages/webauthn` | `webauthnMfaFactorModule`, contributing `mfaFactors.webauthn` (D4). |
| `packages/smtp` (new) | `smtpMailSenderModule`, a `MailSender` over SMTP (D5). |
| `packages/redis` | `redisMfaFactorStoreModule`, `redisMfaTransactionStoreModule`, their client interfaces and ioredis wrappers; the Redis `UserSessionStore` round-trips `authentication` and gains the step-up capability. |
| `packages/foundation` | `HttpMfaFactorStore`, and `markMfaEnrolled` over `markMfaEnrolledUrl` (D12). |
| `packages/session` | Exports `establishSession` (the tail of a login, extracted); the login route consults `mfaCoordinator`; the federation callback keeps upstream `amr` apart (D13); `?link=1` requires recent MFA (D16). |
| `packages/oauth` | `/authorize`'s single decision (D17), the `session` grant's and the refresh grant's gates. |
| `packages/device-grant`, `packages/federation-grants` | Their browser consumers gated through core's rule (D16); the device grant stamps the approving session's `amr`. |

**Why a package and not core.** Core mounts no route but discovery and imports no sibling. The MFA routes are browser routes: they need the session's CSRF guard, its cookie-session helpers and the login tail, all in `packages/session`, which core cannot import. A package also lets a deployment that opts out install none of it, and lets the factor code move on its own review cadence — the reason `packages/webauthn` gives for existing.

**Why not inside `packages/session`.** The session package is "the browser session"; folding factor implementations, a key ring and a mail path into it makes every browser-session deployment carry them, and makes the opt-out switches inside a package rather than not installing one. The federation-grants package is the precedent.

**Why the coordinator is a slot and not an import.** `/session/login` (session) and `/authorize` (oauth) both consult MFA, and neither may import a sibling that is not a peer — `oauth` and `session` do not depend on each other, and neither should depend on an optional feature.

Rejected: **core-only**, for the route rule; **two packages (routes, factors)**, which splits one flow's state across a package boundary for no deployment that would install one without the other.

### D2 — The dependency directions, checked against the repository's rules

| Package | Depends on (peers) | New? | Rule it satisfies |
| --- | --- | --- | --- |
| `core` | — | — | "Core imports no other `@o3co/auth-provider-*` package." `sealing/` uses `node:crypto`; `mail/` holds only types. |
| `mfa` | `core`, `session`, `express`, `express-session` | new | A package names each sibling as a peer. `device-grant` and the four federation adapters (`federation-google`, `-github`, `-apple`, `-oidc`) already depend on `session` (`federation-grants` depends on `oauth` instead). `express-session` is a peer for the `SessionData` augmentation and `req.sessionStore`, as it is for `oauth`. `mfa` does **not** depend on `oauth` (it returns to `/authorize` by redirect, D17) nor on `webauthn` (a contribution). |
| `webauthn` | `core`, `express` | unchanged | Contributes `mfaFactors.webauthn`; imports nothing from `mfa`. |
| `smtp` | `core` | new | An adapter depends on core only. Carries `nodemailer`. |
| `redis`, `foundation` | `core` | unchanged | More adapters for more core ports. |
| `session`, `oauth`, `device-grant`, `federation-grants` | as today | unchanged | Consult `mfaCoordinator` (a core type) and the requirement rule (core). |
| `templates/standalone` | all of the above | — | Composes. |

Inside core, `mfa/` imports `user-sessions/` (types), `adapters/`, `sealing/` (the ring type), `modules/manifest/`, `grants/` (`authenticationClaims.mts`); `user-sessions/` takes the `MfaTransactionStore` type for the credential-change cascade; `sealing/` and `mail/` are leaves added to the list `importBoundaries.drift.test.mts` enforces.

### D3 — The #69 surface is replaced; four names survive with new meanings

The surface was designed before any flow existed, and it does not fit the flows this design needs:

- `createMfaRouter` puts the continuation of three flows into callbacks a composition root writes, so the product's own login and `/authorize` could never use it; it is mounted at `/auth/mfa/verify`, outside `/session` and `/oauth`, with no CSRF guard; it is HTTP in core.
- `MfaTransactionStore` is `set` / `get` / `delete`: two verifications in flight both pass `get` before either `delete` — the race #552 fixed for consent — and nothing bounds guesses made in parallel.
- `MfaProvider.verify(challengeId, proof)` has no enrolled instance, no enrollment ceremony, no state to advance, and no `amr`.

| Item | Decision | Why |
| --- | --- | --- |
| `mfaFactors` contribution kind | **Keep**, new value type; a factory may answer `null` (disabled by config), as `tokenBindingMechanisms` does | The seam through which a factor from a package MFA does not depend on reaches the coordinator. |
| `MfaFactor` (type alias) | **Keep the name**, as the new contract (D7) | One name for "a second factor". |
| `MfaCoordinator` | **Keep the name**, reshaped (D8); declared on `ComponentMap` as `mfaCoordinator` with `MFA_ABSENCE_POLICY` | What session and oauth consult. |
| `MfaTransactionStore` | **Keep the name**, reshaped (D8), with memory and Redis adapters and a contract suite | Same concept; its operations must be atomic. |
| `MfaProvider`, `SupportsEnrollment`, `SupportsRevocation`, their guards | **Remove** | Enrollment is part of every factor's contract; removal is a store operation. |
| `createMfaProviderFactory`, `MfaProviderFactory`, the `mfaProviderFactory` key | **Remove** | Factors arrive as contributions keyed by kind. |
| `createMfaRouter`, `MfaRouteDeps`, `MfaResumeState`, `MfaPendingTransaction`, `MfaChallenge`, `MfaIssueContext`, `MfaVerifyResult`, `MfaVerifyFailureReason` | **Remove** | The routes are the MFA package's; a flow resumes by returning to the request it came from, and `/authorize` decides again (D17). |
| `mfa-partial-wiring`, `checkMfaPartialWiring`, `MfaPartialWiringDetails` | **Remove** | The MFA module `requires` its stores; the declared-absence guard covers the rest (D20). |

A breaking change to core's barrel, for names nothing in this repository imports (§7).

### D4 — The WebAuthn factor lives in `packages/webauthn`, as an `mfaFactors` contribution

`webauthnMfaFactorModule` (requires `webauthnConfig`) contributes `mfaFactors.webauthn`. It reuses the options builders, the verification wrappers and their error mapping, `WEBAUTHN_ALGORITHM_IDS`, the relying-party configuration and the exact pin of `@simplewebauthn/server`. Reuse needs two signature changes in `internal/options.mts`: both builders take credential **descriptors** (`{credentialId, transports}`) instead of `WebAuthnCredential[]`, and the registration builder takes `residentKey` as an argument (the grant's routes keep passing `"preferred"`). It does **not** reuse:

- **`WebAuthnCredentialStore`.** A second-factor credential is kept in `MfaFactorStore`. Beside passkeys, one registered without user verification would become a one-factor passwordless login through the WebAuthn grant. It also buys the three adapters the credential store lacks.
- **`ChallengeStore` / `ChallengeCeremony` / `ReplaySeenSet`.** The challenge is kept in the MFA transaction and taken from it atomically (D8): the transaction is already the single-use, session-bound, attempt-counted record of the ceremony.
- **The routes and `req.webauthnSubject`.** The factor is driven through `/session/mfa/*` (F7).

Rejected: the factor in `packages/mfa`, which would make MFA depend on the WebAuthn library or duplicate the ceremony code.

### D5 — Email goes through a core `MailSender` port; SMTP is a package of its own

```ts
// packages/core/src/mail/types.mts
export interface MailMessage {
	readonly to: string;
	readonly subject: string;
	readonly text: string;
}
export interface MailSender {
	readonly kind: string;
	/** Resolves when the relay accepted the message; rejects on anything else. */
	send(message: MailMessage): Promise<void>;
}
// ComponentMap: readonly mailSender?: MailSender;
```

The port is in core because its implementer (`smtp`) and its consumer (`mfa`) must not depend on each other. The MFA package renders messages from configurable text (`mfa.factors.email.subject` / `body`, with `{code}` and `{minutes}`; the notices likewise), so a deployment that delivers through its own mail service implements `send` and nothing else. `@o3co/auth-provider-smtp` depends on core and `nodemailer` (caret range: a transport, not a verifier). Its rules follow `foundation`'s: STARTTLS or implicit TLS, plaintext only to a loopback host; credentials from the environment; errors thrown as a `MailTransportError` with a reason (`unreachable`, `auth_failed`, `rejected`, `timeout`) and never the server's reply text. No readiness probe: an SMTP outage should not take the provider out of rotation when most users have another factor.

The root README's "Does not own: signup, account recovery and email" gains "…except the one-time codes and security notices MFA sends".

Rejected: SMTP on a subpath of `packages/mfa` with an optional peer (it ties a mail library's cadence to MFA's); delivery through a new Store URL (possible through a deployment's own `MailSender`, but the owner chose SMTP).

### D6 — The provider serves JSON; the pages are the deployment's

As for login and consent, the provider owns `/session/mfa/*` (JSON) and redirects to `endpoints.mfa.url` (default `/mfa`) when `/authorize` needs a step-up. The login page continues from the login response without a redirect (F1). The self-service screen is the deployment's account page. The QR code is rendered by the page from the `otpauth://` URI. The page contract is documented in the MFA package README with a worked example, and requires: same origin as the provider (the session cookie is `__Host-`); navigation back to `redirect_to` only when it is on the provider's origin; code inputs with `autocomplete="one-time-code"` and `inputmode="numeric"`, and long codes accepted pasted with or without hyphens; `frame-ancestors 'none'`; and a lock answer (`429 mfa_locked`) shown with the factors that still work (D21).

Rejected for the first release (O11): provider-served reference pages, and a server-rendered QR image.

---

## 2. Flows

Common to every flow: all `/session/mfa/*` POSTs sit behind the session's CSRF guard (`createCsrfGuard`) and the shared rate-limit guard under prefix `mfa`; every response carries `Cache-Control: no-store`; bodies are parsed on the routes' own paths. A transaction id is 32 bytes from the CSPRNG (base64url), travels only in request bodies and the `MFA-Transaction` request header — never in a URL — and is **not** a bearer: every use compares the record's bound session id with `req.sessionID` in constant time, and a mismatch reads exactly like an unknown id. Errors use core's envelope: `400 invalid_request` for a missing, expired, spent or foreign transaction, `401 mfa_invalid` with `attempts_remaining`, `429 mfa_locked` with `Retry-After` (or none, for a hold only an exempt factor lifts) and `usable_kinds`, `503 temporarily_unavailable` for any store or mail outage. Every code verification has the limits of D21's table.

### The HTTP surface (`packages/mfa`, mounted after `session-middleware`)

| Route | Purpose | Requires |
| --- | --- | --- |
| `GET /session/mfa/transaction` (id in `MFA-Transaction`) | What the transaction is for; usable factors (`id`, `kind`, `label`, `hint`); whether enrollment or an email proof follows; `expires_in`; `attempts_remaining` | a transaction bound to this session |
| `POST /session/mfa/step-up` `{acr_values?}` | Open a step-up transaction; the factors offered are those that would satisfy one of the hinted `acr_values` | an authenticated session with a live `UserSession` |
| `POST /session/mfa/challenge` `{transaction_id, factor_id}` | Send an email code (a factor's, or the `account-email` proof), or answer WebAuthn request options; TOTP and recovery codes need none | a transaction |
| `POST /session/mfa/verify` `{transaction_id, factor_id, proof}` | Verify; on success finish the login or the step-up, or record the proof | a transaction |
| `POST /session/mfa/enrollment` `{kind, transaction_id?}` | Begin enrolling. Without `transaction_id` it opens a self-service enrollment transaction | forced: the login/step-up transaction; self-service: F4's rules |
| `POST /session/mfa/enrollment/complete` `{transaction_id, proof, label?}` | Verify the proof of possession and store the factor | the transaction holding the pending enrollment |
| `GET /session/mfa/factors` | The user's own factors (never their data) | authenticated |
| `POST /session/mfa/factors/rename` `{factor_id, label}` | Change a label | authenticated |
| `POST /session/mfa/factors/remove` `{factor_id}` | Remove a factor | recent MFA; not the last counting factor under `required` |
| `POST /session/mfa/recovery-codes` | Replace the recovery codes; answers them once | recent MFA |

### F1 — Password login → second factor → session

Mode `required`, or `optional` with at least one factor on record.

| # | Request | What happens | State read / written |
| --- | --- | --- | --- |
| 1 | `POST /session/login {username, password, redirect_to?}` | CSRF, `login` guard, `redirect_to` allowlist, Store `authenticate` — unchanged. Then `mfaCoordinator.decideAfterPrimary` reads the subject's factors and the witness (`User.mfaEnrolled`, D12). | Reads the Store and `MfaFactorStore.list(subject)`. An outage of either: `503`, one error line, nothing written. |
| 2 | (same request) | Decision `challenge`: the express session is **regenerated** and left unauthenticated; the coordinator opens a login transaction bound to the new session id; the route saves the session and answers **`403 {"error":"mfa_required", "mfa_transaction":"<id>", "expires_in":600}`**. | The regenerated express session (no `isAuthenticated`, no `sid`); an `MfaTransaction` (purpose `login`, subject, bound session id, primary `{method:"pwd", authTime}`, the `User` snapshot, validated `redirectTo`). No `UserSession` yet. |
| 3 | `GET /session/mfa/transaction` | Lists usable factors. | Reads the transaction and the factor store. |
| 4 | `POST /session/mfa/challenge` | Email → F5; WebAuthn → F7; TOTP, recovery code → nothing to do. | Email / WebAuthn: the transaction's challenge (compare-and-set on its version). |
| 5 | `POST /session/mfa/verify` | (a) reserve a transaction attempt; (b) reserve a subject attempt if the proof is guessable (D21); (c) verify the proof; (d) **consume the transaction**; (e) advance the factor's state (compare-and-set); (f) settle the subject attempt — a success, or **void** if (e) lost its compare-and-set or hit an outage, since the proof was right; (g) reconcile the witness if it is missing (D12); (h) `establishSession`. | Attempts +1; the subject state; transaction deleted; the factor record (version +1, re-sealed data, `lastUsedAt`); a `UserSession` (`amr` per D14, `authTime` = step 1, `authentication` = `{primary:"pwd", mfaAt: now}`); `SubjectSessionIndex`; express session regenerated with `isAuthenticated`, `user`, `sid`, `redirectTo`. |
| 6 | `200 {"message":"Logged in successfully", "recovery_codes_remaining"?}` | The page navigates to its `redirect_to`. | — |

Attempts are **reserved before** the proof is checked, so fifty guesses sent at once spend fifty attempts, not one. The transaction is **consumed before** anything else is written, so two verifications in flight produce one session and a lost race spends the transaction, never a recovery code or a TOTP step. A factor write that then fails is `401 mfa_invalid` (lost compare-and-set) or `503`, and the user starts again from the password.

`optional` with no factor on record, and a composition whose `mfa.mode` is `off`, log in as today, with `authentication = {primary:"pwd", mfaAt: undefined}`.

### F2 — `/authorize` with `acr_values` / `max_age` / `prompt=login` → step-up → back

`/authorize` makes one decision per request, over one ask record that accumulates what has been asked (D17).

| # | Request | What happens | State |
| --- | --- | --- | --- |
| 1 | `GET /oauth/authorize?…&acr_values=urn:o3co:acr:mfa` | The live `UserSession` is read. D17 decides: freshness first, then methods. **Met** → continue. **A step-up can meet it** → `prompt=none` answers `interaction_required`; otherwise the ask is written (or updated) with `mfaAskedAt` and the browser goes to `endpoints.mfa.url?redirect_to=<this request, with reauth_ask=<id>>&acr_values=<the values a step-up can meet>`. **Nothing can** → `unmet_authentication_requirements`. | Reads the `UserSession`; writes the ask. |
| 2 | The page: `POST /session/mfa/step-up {acr_values}` | Checks the session is authenticated and its `UserSession` live; opens a step-up transaction bound to the session id **and** the `sid`. The factors offered are those whose `amr` would meet one hinted value; none → `no_qualifying_factor`, and the page goes straight back. | Reads the `UserSession` and the factor store; writes the transaction. |
| 3 | challenge / verify | As F1 steps 4–5, except the finish: `recordSecondFactor(sid, {amr, at: now})`; **regenerate** the express session keeping `isAuthenticated`, `user`, `sid` (D27). | `UserSession.amr` (union), `authentication.mfaAt`; the express session id. |
| 4 | The page navigates to `redirect_to` | D17 decides again with the ask. Met → consent if needed (the ask travels through it), policy, a code carrying the chosen `acr`; the ask is consumed on that pass. Not met by the session that was sent → `unmet_authentication_requirements` (`acr_values`) or `login_required` (the baseline). | The ask; the code record carries `acr`. |
| 5 | `POST /oauth/token` | id_token `amr` from the `UserSession`, `acr` from the code, `auth_time` = `UserSession.authTime` (D18). | — |

Branches. **No factor record, fresh primary** (`authTime` within `mfa.enrollment.maxPrimaryAgeSeconds`): the step-up transaction carries a first binding (F3, D24). **No factor, stale primary**: D17 asks for a re-authentication, which reaches F3 at the login — a factor is never bound to a session hours old. **A `UserSessionStore` without the step-up capability** (D9): D17 asks for a re-authentication instead; boot has warned once.

Why a redirect back and not a resume callback (the #69 design): `/authorize` stays the one place that decides, from fresh state; the MFA package does not import `oauth`; and the ask is what keeps a failed round trip from looping.

### F3 — First login with no factor → first binding → completion

| # | Request | What happens | State |
| --- | --- | --- | --- |
| 1 | `POST /session/login` | As F1 steps 1–2, decision `enroll` (mode `required`, zero factor records, the witness not `true` — D12): `403 {"error":"mfa_enrollment_required", "mfa_transaction":"<id>", "enrollable":["totp", …], "email_proof": true|false}`. | A transaction with `enrollment: "required"` and `emailProof` per D24. |
| 2 | *(when `email_proof`)* `POST /session/mfa/challenge {transaction_id, factor_id:"account-email"}`, then `verify` | A 16-character code (80 bits) to the Store's address for the account. Exempt from the subject lock; limited by the transaction (D21). | The transaction records `emailProof.provedAtMs`. |
| 3 | `POST /session/mfa/enrollment {transaction_id, kind:"totp"}` | The factor begins its enrollment (F6 / F5 / F7). Refused while a required proof is missing. | The pending enrollment, sealed (D11). |
| 4 | `POST /session/mfa/enrollment/complete {transaction_id, proof, label?}` | Reserve a transaction attempt; the factor verifies possession; consume the transaction; create the factor record (`binding: "email_proof"` or `"password"`, D24) and — first counting factor — **recovery codes**; mark the witness (D12); `establishSession` with `amr` per D14 and `authentication.mfaAt` = now. | Factor records; transaction deleted; `UserSession` and express session as F1 step 5; the witness. |
| 5 | `200 {"factor":{id,kind,label}, "recovery_codes":[…]}` | The page shows the codes once, then navigates to `redirect_to`. Audit `mfa.factor.enrolled` (`binding`); a notice under `mfa.notices = "mail"`. | — |

**Only zero records — and no witness saying the subject enrolled — open a first binding.** A subject with any record (recovery codes only, a factor of a kind no longer installed, one whose sealed data cannot be opened) must verify a usable factor first; if that leaves no usable counting factor (a recovery code, under `required`), `verify` answers `403 mfa_enrollment_required` with the same transaction, which now allows enrollment, and the session is written only when an enrollment completes. Treating "records I cannot use" as "none" would let a password alone replace someone's second factor. What a first binding cannot defend without mail is an account whose password leaked before its owner first enrolled: D24, O4.

### F4 — Self-service enrollment and removal

1. The account page calls `GET /session/mfa/factors`.
2. **To add a factor when the user already has a counting factor**: `POST /session/mfa/enrollment {kind}` requires recent MFA — `authentication.mfaAt` within `mfa.manage.maxAgeSeconds` (300), else `403 {"error":"mfa_step_up_required"}`, and the page runs F2 steps 2–3 without a `redirect_to` and retries. An enrollment transaction (purpose `enroll`, bound to session id and `sid`) is opened; F3 steps 3–4 follow, the new factor recorded with `binding: "mfa"`, the session unchanged.
3. **To add the first counting factor** (possible under `optional`): a first binding under D24's rules — a recent primary (`authTime` within the same window, else `401 login_required`) and the email proof when D24 requires it.
4. **To remove**: `POST /session/mfa/factors/remove {factor_id}`, recent MFA. Under `required`, removing the last counting factor is `409 last_factor`. Sessions are not ended; removing the last counting factor clears the witness (removal first, then the witness).
5. `POST /session/mfa/recovery-codes` replaces the set (recent MFA) and answers the new codes once.
6. Every add, remove and regeneration is audited and, under `mfa.notices = "mail"`, mailed to the account's address as a notice, never with a link.

A subject holds at most `mfa.maxFactorsPerSubject` (10; recovery codes are one record) — `409 mfa_factor_limit`.

### F5 — Email codes: send and verify

Two lengths, by what a code protects (D21, D22):

- **The email factor's login and step-up code**: 6 digits, typed from a phone — guessable, so under the subject lock.
- **Every code that stands in for a factor the subject does not have yet** — the `account-email` proof before a first binding, and the code that enrolls an email factor: 16 Crockford base32 characters (80 bits), meant to be pasted — exempt from the lock, which would otherwise let a password holder lock an unenrolled user out with no way in.

| # | Request | What happens | State |
| --- | --- | --- | --- |
| 1 | `POST /session/mfa/challenge {transaction_id, factor_id}` | Refused while the subject's guessable factors are locked, for a 6-digit code (D21). Per transaction: at most `maxSends` (3), one per `resendAfterSeconds` (30). Per subject: `sendLimit` (5 per hour) through `checkWithFailMode` under prefix `mfa-email`. A code from the CSPRNG; its keyed digest **replaces** any earlier one; then `mailSender.send`. `200 {"sent_to":"k***@example.com", "expires_in":600, "resend_after":30}`. | The transaction's challenge `{factorId, kind, digest, keyId, expiresAt}`; `sends` +1. |
| 2 | delivery fails | The digest is cleared best-effort; `503` "mail delivery unavailable"; one `mfa_mail_unavailable` error line with `subject`, `factorId`, the transport reason — never the address or the code. The transaction stays. | The challenge cleared. |
| 3 | `POST /session/mfa/verify {…, proof}` | As F1 step 5 with D21's limits for the code's kind; compare digests in constant time; check `expiresAt`; only the latest code counts. | As F1, or the recorded proof. |

The factor's address is the one enrolled: the account's `email` from the Store at enrollment time, proven by a code, and kept (sealed) in the factor record — never an address typed at challenge time. A later change of the Store's address does not redirect codes; the user re-enrolls. The `account-email` proof uses the Store's current address. An account without an address is not offered the kind, and cannot give a proof.

### F6 — TOTP: enroll (secret and QR) and verify

**Enroll.** `POST /session/mfa/enrollment {kind:"totp"}` → a secret of the algorithm's output length (20 bytes for SHA-1, 32 for SHA-256, 64 for SHA-512 — RFC 6238's reference seeds), sealed into the pending enrollment, answered once:

```json
{
  "transaction_id": "…",
  "secret": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
  "otpauth_uri": "otpauth://totp/Example:alice%40example.com?secret=JBSW…&issuer=Example&algorithm=SHA1&digits=6&period=30",
  "algorithm": "SHA1", "digits": 6, "period": 30
}
```

The label is `issuer:account`, the account the user's `email`, else `username`; the issuer is `mfa.factors.totp.issuer` (default: the host of `oauth.jwt.issuer`). The secret is RFC 4648 base32 without padding. The page renders the URI as a QR code, shows the secret for manual entry, and offers the URI as a link for same-device setup — what authenticator apps and Apple's Passwords app read. **The parameters are stored per factor**, so a configuration change never breaks an existing enrollment. The PR that ships TOTP records a manual check with Apple Passwords (iOS and macOS), Google Authenticator and one other app, by QR and by link.

`POST /session/mfa/enrollment/complete {proof:"<code>"}` checks the code against the pending secret and stores the factor with `lastUsedStep` = the matched step. That proof is not subject-limited: the enroller was handed the secret in step one, so a guess wins nothing they do not already hold (D21).

**Verify.** The factor named by `factor_id` only. Accept a code at time steps `T-window … T+window` (`window` default 1, at most 2) **only if its step is greater than the factor's `lastUsedStep`**; the new `lastUsedStep` is compare-and-set on the record's version, and a lost compare-and-set re-reads and re-checks, so a code used twice at once succeeds once. This is RFC 6238 §5.2's rule, and it also refuses an older, unused code once a newer one was accepted. HMAC-SHA-1/256/512 and dynamic truncation run on `node:crypto`, pinned by RFC 6238 Appendix B's vectors.

### F7 — WebAuthn as a second factor: register and assert

**Register.** `POST /session/mfa/enrollment {kind:"webauthn"}` → `generateRegistrationOptionsForUser` with: `user.id` = the subject's WebAuthn user handle (32 random bytes, created at the first WebAuthn enrollment and kept in each such factor's data); `excludeCredentials` = the subject's WebAuthn factors; `residentKey: "discouraged"`; `userVerification` from `mfa.factors.webauthn.userVerification` (`preferred`); attestation `none`; `WEBAUTHN_ALGORITHM_IDS`. `residentKey: "discouraged"` is advisory: a synced platform passkey is discoverable whatever is asked, may appear in the browser's passkey picker for this relying party, and fails there as an unknown credential — cosmetic, and documented. WebAuthn Level 3 `hints` are not set (option). `complete {proof: <RegistrationResponseJSON>, label?}` → `verifyWebAuthnAttestation`; the factor stores `{credentialId, publicKey, signCount, transports, backedUp, userHandle}` (sealed). A credential id already on this subject is `409`.

**Assert.** `challenge` → `generateAuthenticationOptionsForUser` with `allowCredentials` = every WebAuthn factor of the subject; the challenge goes on the transaction. `verify {proof: <AuthenticationResponseJSON>}` → the challenge is **taken** (read and cleared in one operation, so an assertion is checked against a challenge exactly once); the factor is found by credential id among the subject's; `verifyWebAuthnAssertion`; the new sign count is compare-and-set on the record's version. A lost compare-and-set is **not** evidence of anything — another write moved the version — so it re-reads and re-evaluates; only a counter that did not increase over the stored one is refused and audited as a possible clone. `amr` per D14. Exempt from the subject lock (D21).

---

## 3. Data model and stores

### D7 — The enrolled-factor record and `MfaFactorStore`; memory, Redis and Store adapters

```ts
export interface MfaFactorRecord {
	readonly id: string; // 16 bytes, base64url
	readonly subject: string;
	readonly kind: string; // "totp" | "email" | "webauthn" | "recovery_code" | a contributed kind
	readonly label: string | undefined; // ≤ 64 printable characters
	/** What authorized the binding (D24): recorded for audit; not enforced (O4). */
	readonly binding: "password" | "email_proof" | "mfa" | undefined;
	readonly createdAt: Date;
	readonly lastUsedAt: Date | undefined;
	readonly version: number; // bumped by every update; the compare-and-set token
	readonly data: string; // the factor's own state, sealed (D11); opaque to every store
}

export interface MfaFactorStore {
	readonly kind: string;
	list(subject: string): Promise<readonly MfaFactorRecord[]>;
	create(record: MfaFactorRecord): Promise<void>; // rejects a duplicate (subject, id)
	/** Compare-and-set on `version`; `null` when the version moved or the record is gone. */
	update(
		subject: string,
		id: string,
		expectedVersion: number,
		next: { readonly data: string; readonly label: string | undefined; readonly lastUsedAt: Date | undefined },
	): Promise<MfaFactorRecord | null>;
	remove(subject: string, id: string): Promise<void>; // idempotent
	removeAllForSubject(subject: string): Promise<void>; // account deletion, operator reset; idempotent
}
```

The contract a factor implements:

```ts
export interface MfaFactor {
	readonly kind: string;
	/** What a verification adds (D14); may depend on the factor's data (hwk / swk). */
	amrFor(data: FactorData): readonly string[];
	readonly addsMfa: boolean; // whether a verification also adds `mfa` (D14; email: configurable, O7)
	readonly counting: boolean; // satisfies "this user has MFA"
	readonly guessable: boolean; // the subject lock applies (D21)
	describe(data: FactorData): { readonly hint?: string };
	challenge?(ctx: ChallengeContext): Promise<{ readonly state?: FactorState; readonly response: unknown }>;
	verify(ctx: VerifyContext): Promise<
		| { readonly ok: true; readonly factorId: string; readonly next?: FactorData }
		| { readonly ok: false; readonly reason: "invalid" | "expired" | "replayed" | "malformed" }
	>;
	beginEnrollment(ctx: EnrollmentContext): Promise<{ readonly state: FactorState; readonly response: unknown }>;
	completeEnrollment(ctx: CompletionContext): Promise<
		| { readonly ok: true; readonly data: FactorData; readonly label?: string }
		| { readonly ok: false; readonly reason: "invalid" | "expired" | "malformed" | "duplicate" }
	>;
}
```

A factor never sees a key, a store or a transaction: the coordinator opens and seals data, passes the subject's records of that kind decoded, and writes what the factor returns. That keeps sealing in one place and lets `packages/webauthn` implement a factor without depending on `packages/mfa`.

**Adapters.**

- **Memory** (core, `memoryMfaFactorStoreModule`): `replicaSafety.unsafe` — "enrolled second factors fork per replica and vanish on restart". Development only; D12 is why that matters.
- **Redis** (`redisMfaFactorStoreModule`): one hash per subject (`<prefix>{<subject>}`, a field per factor), one key on a Cluster. The version comparison runs in a Lua script that does not decode the JSON (`cjson` re-encodes an empty array as an object). No TTL. `keyPrefix` default `mfaf:`. D12's durability check runs at boot.
- **The Store** (`HttpMfaFactorStore`, `packages/foundation`): selected by `mfaFactorStore.adapter = "store"`, built from `repositories.user.http` — same bearer token, transport rules and error classes — with four optional URLs, each a `POST` of JSON:

  | URL | Body | Answers |
  | --- | --- | --- |
  | `listMfaFactorsUrl` | `{subject}` | `2xx {factors: [record…]}`, an empty list for a subject with none; **anything else throws** — never "no factors" |
  | `createMfaFactorUrl` | `{factor}` | `2xx`; `409` duplicate; else throws |
  | `updateMfaFactorUrl` | `{subject, id, expectedVersion, factor}` | `2xx {factor}`; `409` (version moved) or `404` (gone) → `null`; else throws |
  | `deleteMfaFactorUrl` | `{subject, id}` or `{subject, all: true}` | `2xx` or `404`; else throws |

  The Store keeps `data` verbatim and never decodes, logs or derives anything from it; the provider seals it first. The Store must compare-and-set atomically on `version`. This write path, and the witness's (D12), are justified in `docs/adapter-surface.md` beside `linkFederatedIdentity`: the flows are the library's own, end to end; unlike linking, the provider decides and the Store only persists.

One shared contract suite (`packages/core/src/mfa/__tests__/factorStore.contract.mts`): every field round-trips; duplicates refused; N concurrent updates at one version → one success; idempotent removal; subjects kept apart. The Redis copy is held to core's by a parity test; the Store adapter runs it against a fake Store.

### D8 — The MFA transaction and `MfaTransactionStore`; the coordinator slot

```ts
export interface MfaTransaction {
	readonly id: string; // 32 bytes, base64url
	readonly purpose: "login" | "step_up" | "enroll";
	readonly sessionId: string; // the express session it is bound to
	readonly subject: string;
	readonly sid: string | undefined; // step_up / enroll: the UserSession it upgrades
	readonly primary: { readonly method: string; readonly authTimeMs: number } | undefined; // login
	readonly user: Readonly<Record<string, unknown>> | undefined; // login: the User the session is built from
	readonly redirectTo: string | undefined; // login: validated against session.redirectAllowlist
	readonly enrollment: "none" | "allowed" | "required";
	readonly emailProof: "not_required" | "required" | { readonly provedAtMs: number };
	readonly acrValues: readonly string[] | undefined; // step_up: the hint, for offering factors
	readonly challenge: { readonly factorId: string; readonly kind: string; readonly state: string; readonly expiresAtMs: number } | undefined;
	readonly pendingEnrollment: { readonly kind: string; readonly state: string; readonly expiresAtMs: number } | undefined;
	readonly attempts: number;
	readonly sends: number;
	readonly lastSentAtMs: number | undefined;
	readonly createdAtMs: number;
	readonly expiresAtMs: number;
	readonly version: number;
}

export interface MfaTransactionStore {
	readonly kind: string;
	create(tx: MfaTransaction): Promise<void>; // insert-only
	get(id: string): Promise<MfaTransaction | null>; // expired → null
	update(id: string, expectedVersion: number, patch: MfaTransactionPatch): Promise<MfaTransaction | null>;
	/** Atomic: attempts +1; deletes the record past `max`. */
	reserveAttempt(id: string, max: number): Promise<{ readonly ok: boolean; readonly attempts: number }>;
	/** Atomic read-and-clear of the pending challenge. */
	takeChallenge(id: string, expectedVersion: number): Promise<MfaTransaction["challenge"] | null>;
	/** Atomic delete if still at `expectedVersion`; the one winner gets the record. */
	consume(id: string, expectedVersion: number): Promise<MfaTransaction | null>;

	// The subject state of D21, for guessable proofs only.
	/** Refuse while held (unless `browser` is trusted and the hold is the weekly one); else count a pending failure. */
	reserveSubjectAttempt(subject: string, nowMs: number, policy: LockoutPolicy, browser: string | undefined): Promise<
		| { readonly ok: true; readonly reservation: string }
		| { readonly ok: false; readonly hold: "backoff" | "weekly" | "hard"; readonly retryAfterMs: number | null }
	>;
	/** failure: stands. success: ends the consecutive run, and is not a failure. void: the proof was right, the write lost. */
	settleSubjectAttempt(subject: string, reservation: string, outcome: "failure" | "success" | "void"): Promise<void>;
	/** An exempt success: ends the run and a hard hold, and trusts this browser against the weekly hold. */
	noteExemptSuccess(subject: string, nowMs: number, policy: LockoutPolicy): Promise<{ readonly browser: string }>;
	/** The operator reset, and a credential change (D21, D25). */
	clearSubjectState(subject: string): Promise<void>;
}
```

A transaction lives `mfa.transactionTtlSeconds` (600). The subject state lives as long as D21's rules need it. `challenge.state` and `pendingEnrollment.state` are sealed or digested (D11). The login `user` snapshot is what `req.session.user` holds today, for at most ten minutes; `UserRepository` has no read by id.

Adapters: **memory** (core, `memoryMfaTransactionStoreModule`, `replicaSafety.unsafe`: "a transaction started on one replica is unknown to the replica that receives the verification, and the attempt limits are per replica") and **Redis** (`redisMfaTransactionStoreModule`: a hash per transaction; a hash per subject for D21's state, with the weekly window as a sorted set of failure times; Lua for every atomic operation; `keyPrefix` default `mfat:`). No Store variant: this is verification state. The contract suite pins the races (N parallel `reserveAttempt` → at most `max` succeed; N parallel `consume` → one winner; `takeChallenge` answers once) and D21's schedule under an injected clock.

**The coordinator slot.** What `session` and `oauth` read, declared in core and filled by `mfaModule`:

```ts
export interface PrimaryAuthentication {
	readonly subject: string;
	readonly method: string; // "pwd" from /session/login; a federation's "fed", later
	readonly amr: readonly string[];
	readonly authTime: Date;
	readonly user: Readonly<Record<string, unknown>>; // what req.session.user will hold
	readonly redirectTo: string | undefined;
	readonly request: { readonly ip?: string; readonly userAgent?: string };
}

export interface MfaCoordinator {
	/** The `amr` values installed factors can add: what a step-up can reach. */
	readonly secondFactorMethods: ReadonlySet<string>;
	/** Reads the subject's factors and the witness; throws on an outage (the caller answers 503). */
	decideAfterPrimary(p: PrimaryAuthentication): Promise<"none" | "challenge" | "enroll">;
	/** After the caller regenerated the express session: binds the transaction to the new id. */
	openLoginTransaction(
		p: PrimaryAuthentication,
		decision: "challenge" | "enroll",
		sessionId: string,
	): Promise<{ readonly id: string; readonly expiresInSeconds: number }>;
}
```

Two calls, because the express session is regenerated between them: the transaction must be bound to the id the browser will hold, and the factor read must happen before anything is written.

### D9 — What the session records

`UserSession` and `CreateUserSessionInput` gain one required key (the #626 shape, so a copy that forgets it fails to compile):

```ts
export interface SessionAuthentication {
	/** How the session was established: "pwd" (POST /session/login), "fed" (a federation callback). */
	readonly primary: string;
	readonly federation: string | undefined; // for "fed"
	/** What an untrusted upstream IdP asserted (D13): kept for the record, never stamped, never read for `acr`. */
	readonly upstreamAmr: readonly string[] | undefined;
	/** When a second factor was last verified — or bound (D24) — in this session. */
	readonly mfaAt: Date | undefined;
}
// UserSession / CreateUserSessionInput:
readonly authentication: SessionAuthentication | undefined; // undefined: written before this design
```

- **`amr`** keeps its meaning: what this provider vouches for — the primary, trusted upstream values (D13), each verified factor, and `mfa` once (D14).
- **`authTime`** is the **primary** authentication's time; a step-up never moves it (D18).
- **A session written before this design** (`authentication: undefined`) is read through one core function, `sessionAuthentication(session)`: `amr` carrying `fed` → `{primary: "fed"}`, every other value an untrusted upstream value; else `amr` carrying `pwd` → `{primary: "pwd"}`; else unknown (re-authenticated, D16). The same function gives `vouchedAmr(session)`, which `/token` and the `session` grant stamp.
- **The step-up capability**, detected by method presence like `supportsSessionsOnlyRevocation`:

  ```ts
  export interface SupportsSecondFactorUpdate {
  	/** Monotonic; nothing but amr and authentication changes. `null` when the session is gone. */
  	recordSecondFactor(sid: string, event: { readonly amr: readonly string[]; readonly at: Date }): Promise<UserSession | null>;
  }
  ```

  With `authentication` present: `amr` becomes the union, `mfaAt` the later of the two. **With `authentication` absent** (a pre-upgrade session), the record is split first, so an untrusted upstream value can never become a vouched one: `authentication` := `sessionAuthentication(old)` with `mfaAt`; `amr` := `vouchedAmr(old)` ∪ the factor's values; `upstreamAmr` := the old values `vouchedAmr` left out. A pre-upgrade `["hwk", "fed"]` plus TOTP becomes `amr: ["fed", "otp", "mfa"]`, `upstreamAmr: ["hwk"]` — never `["hwk", "fed", "otp", "mfa"]`, whose `hwk` would meet `phr`.

  Both bundled adapters implement it. Memory: a field write. Redis: read, compute in JavaScript, then a script that writes the new value with `KEEPTTL` only if the stored value is still the one read, retried a bounded number of times — the refresh-token family's compare-and-set pattern. A custom adapter without it keeps working: D17 asks for a re-authentication instead, and boot says so once (`mfa_step_up_unsupported`, warn).
- **No release writes `authentication` beside an unsplit `amr`**: the key, the federation callback's split and the split in `recordSecondFactor` land in one PR (§8, PR 5).
- **The express session** carries nothing about MFA: `isAuthenticated` is set only when a login completes.

Rejected: **three separate keys**, three things a copy can forget; **a new `sid` on step-up** — the logout indexes of the old `sid` would not follow; **MFA state on the express session only** — `/token` reads the `UserSession`; **the capability mandatory** — every custom session store would fail to boot for a safe degradation.

### D10 — Replica safety

| Module | Declaration |
| --- | --- |
| `memoryMfaFactorStoreModule`, `memoryMfaTransactionStoreModule` (core) | `replicaSafety.unsafe`; in `REPLICA_UNSAFE_BUNDLED_MODULES`; refused under `deployment.mode = "multi"` |
| `redisMfaFactorStoreModule`, `redisMfaTransactionStoreModule` | safe; `require` their client slots off the shared socket |
| `HttpMfaFactorStore` | safe (external) |
| `mfaModule` | stateless, but builds a per-process fallback limiter when no `rateLimiter` is wired — refused under `multi`, warned when unset, silent under `single`, as `/session/login` does |
| `smtpMailSenderModule` | stateless |

### D11 — Secrets at rest

- **One key ring**, `mfa.encryptionKeys` (`[{id, key}]`, 32 bytes base64; the first seals, every entry opens) — the federation-grant ring's rules, moved with its code into core's `sealing/` leaf. The envelope code takes a purpose label bound into the authenticated data; the federation-grant store keeps passing its existing header, so every grant sealed before the move still opens.
- **Every factor's `data` is sealed**, with authenticated data `o3co:mfa:factor` ‖ subject ‖ factor id ‖ kind, length-prefixed: a record copied to another subject, or relabelled as another kind, does not open.
- **Pending enrollment state** is sealed with the transaction id in the authenticated data.
- **Codes that are compared, never recovered, are digested** under the ring (HMAC-SHA-256): email codes over `(transaction id, factor id, code)`; recovery codes over the normalised code. Each digest is stored **with its key id**, so rotation never makes a code unverifiable. Comparison uses core's `constantTimeStringEqual`.
- **Rotation**: add the new key last, then move it first. Factors do not expire, so a retired key stays until nothing is sealed under it; every TOTP or WebAuthn use re-seals under the current key; dormant factors do not migrate. The runbook has the procedure; the coordinator logs `mfa_factor_sealed_with_retired_key` (info, once per key id per process).
- **A factor that does not open** is never "no factor": it counts for F3's rule, its verification is `503` with one `mfa_factor_unreadable` error line, and the user uses another factor or a recovery code.
- **No plaintext mode**, and **a development sample key**: the template's `config/development.conf` carries a published sample key; the MFA schema refuses that exact key when the environment the configuration was selected by is `production` or `staging`, or `deployment.mode = "multi"` (#473's rule).

### D12 — Losing the factor store must not downgrade every account

"Only zero records open a first binding" (F3) is only as strong as the store that holds the records. A Redis without persistence restarting, an eviction, a `FLUSHALL`, a Store restored from an old backup — each empties the list, and every affected account then accepts a first binding from whoever holds its password.

- **Durability requirements.** The runbook requires, for the Redis factor store: a `maxmemory-policy` that cannot evict its keys (`noeviction`, or a `volatile-*` policy — factor keys carry no TTL); AOF persistence (`appendfsync everysec`); preferably a dedicated database or instance. At boot the Redis module reads `CONFIG GET maxmemory-policy` and `INFO persistence` where the server allows: an `allkeys-*` policy is refused (`mfa-factor-store-evictable`); RDB snapshots without AOF are a warning (`mfa_factor_store_lossy`: the last snapshot interval of enrollments is lost on a crash); no persistence at all is a warning (`mfa_factor_store_volatile`); a server that refuses `CONFIG` is one warning that the check could not run.
- **An enrollment witness outside the factor store.** The core port (§8, PR 3): `User.mfaEnrolled` (a boolean the Store answers on `authenticate`, through `User`'s index signature), and an optional `UserRepository` capability, `markMfaEnrolled(subject, enrolled): Promise<void>`, with a guard. foundation implements it as `markMfaEnrolledUrl` (`POST {subject, enrolled}`); a Store-backed factor store may maintain the field itself instead.
  - **Writes**: create-then-mark — the first counting factor is written, then the witness set; a removal of the last counting factor, then the witness cleared; the operator reset clears it last. A crash between the two leaves a factor without a witness, never a witness without a cause.
  - **Reconciliation**: every successful verification whose `User` snapshot lacks `mfaEnrolled: true` while a counting factor exists marks it again, so a failed mark heals at the next login.
  - **Reads**: at login, from the fresh `authenticate` answer; for a step-up or a self-service first binding, from the session's `user` snapshot (the login's `User`, at most `session.maxAge` old — a flag that only ever blocks a first binding, never admits one).
  - **Effect**: witness `true` with zero factor records is `503 temporarily_unavailable`, one `mfa_enrollment_state_inconsistent` error line and an audit event — never a first binding.
  - A repository without the capability and a Store that answers no field leave the witness absent; the durability requirements are then the whole defence.
- **Recovering from a lost factor store** (runbook): the mass `503` is the design refusing to downgrade. Restore the factor store from its AOF or a backup; if that is impossible, reset the affected subjects (`resetMfaForSubject` with `requireEmailProof: true`, D25), in bulk from the Store's list of users marked enrolled, and tell them they will re-enroll.
- Rejected: **a marker in the same Redis** (lost with the records); **refusing a first binding for any subject seen before** (the provider keeps no subject list).

The template's default is decided in O6.

---

## 4. Tokens, claims and the requirement

### D13 — How a session was established, and what an upstream IdP said

- **The baseline is decided on `authentication.primary`**, never on which `amr` values are present (D16).
- **Upstream `amr` is kept apart by default.** The federation callback records `amr: ["fed"]` and puts the upstream values in `authentication.upstreamAmr`, where nothing stamps or reads them for `acr`. A federation configured with `federations.<name>.trustUpstreamAmr = true` records them in `amr` beside `fed`, as today, and they then count for `acr`.
- **`FEDERATED_AMR` moves to core** (`packages/core/src/grants/authenticationClaims.mts`); `@o3co/auth-provider-session` keeps re-exporting it.
- **Pre-upgrade sessions** are read through `sessionAuthentication` / `vouchedAmr` and split on their first step-up (D9).
- **Breaking**: #481 stamps upstream values and honours them for `acr_values` today. The acr entries only they satisfied are dropped at boot with a warning (D15), in the same PR as the split, so no release advertises an entry it can no longer meet.
- Rejected: **namespacing** (`upstream:mfa`), which spends `amr` on values no RP can act on; **dropping** the values, which loses the audit record. Decided in O1.

### D14 — `amr` per factor

| Factor | `amr` added | `mfa` too? | Source |
| --- | --- | --- | --- |
| TOTP | `otp` | yes | RFC 8176 |
| WebAuthn, device-bound (backup-state flag clear) | `hwk` | yes | RFC 8176 |
| WebAuthn, backed up / synced | `swk` | yes | RFC 8176: protected by the platform's sync, not bound to one device's hardware |
| Email code | `email` | **no**, unless `mfa.factors.email.addsMfa` (O7) | deployment-defined, as `fed` is |
| Recovery code | `recovery` | yes | deployment-defined |

`mfa` is RFC 8176's "multiple-factor authentication", added by a verification of a factor whose `addsMfa` is true — at a login, a step-up or a first binding alike (D24). A login is `["pwd", "otp", "mfa"]`; a step-up appends (`["pwd", "otp", "mfa", "hwk"]`); an email login is `["pwd", "email"]` — the baseline is met (`mfaAt` is set) but `urn:o3co:acr:mfa` is not. Order is insertion, `mfa` never repeated. The values are core constants (`MFA_AMR`, `EMAIL_OTP_AMR`, `RECOVERY_CODE_AMR`, beside `FEDERATED_AMR`), composed by one function (`composeAmr`) with a design-vocabulary row. The passwordless WebAuthn grant keeps stamping `hwk` for every passkey, synced or not; aligning it is a separate change (Outside the first release, O9).

### D15 — The `acr` scheme, discovery, and the `claims` parameter

- **The table stays the only source** of what `/authorize` vouches for. It gains **alternatives**: an entry is either a list (every value required) or a list of lists (any one list satisfied), so "any WebAuthn assertion" is `"urn:o3co:acr:phr" = [["hwk"], ["swk"]]`.
- **The template ships one entry**, `"urn:o3co:acr:mfa" = ["mfa"]`, with `phr` commented out; `create-app --no-mfa` comments the `mfa` entry out too. Core's reference stays `{}`.
- **An entry nothing installed can satisfy is dropped**: excluded from `acr_values_supported`, answered `unmet_authentication_requirements`. It is warned once at boot (`acr_value_unsatisfiable`) — except under `mfa.mode = "off"`, where an entry unmet only for want of a second factor is an `info` line, so an MFA-off deployment is not warned on every boot. Producible values: `pwd` and `fed`, the installed factors' values, `mfa` (with a coordinator), and — only for a federation that trusts its upstream — anything.
- **`acr` is stamped only when requested.** An unrequested `acr` is a claim no RP validates.
- **`acr_values` is treated as mandatory**: this provider answers `unmet_authentication_requirements` rather than a token that does not meet it.
- **Preference order.** Among the requested values, one the session already meets wins over stepping up to an earlier-listed one. An RP that will accept only `phr` asks only for `phr`.
- **The `claims` parameter**: a request whose `claims` names `acr` — essential or not, in `id_token` or `userinfo` — is refused with `invalid_request` ("request acr through acr_values"), by #284's rule. Every other use of `claims` stays ignored, and discovery keeps `claims_parameter_supported` absent.
- The names are decided in O9.

### D16 — The requirement rule, and every consumer of an authenticated browser session

Core's requirement rule (`packages/core/src/mfa/requirement.mts`) is one pure function over `sessionAuthentication(session)`, `vouchedAmr(session)`, the configuration and `mfaCoordinator.secondFactorMethods`:

- **Baseline** (`mfa.mode = "required"`): met when the primary is not in the baseline's set (`mfa.requiredAfter`, fixed to `["pwd"]` for now, D13), or when `mfaAt` is set. A session whose primary is unknown is not met and is re-authenticated. **`session: null`** — no `sid`, or no store — **is not met** under `required` and is re-authenticated.
- **`acr_values`**: D15's selection over `vouchedAmr`; an unmet value is a step-up target when the values it lacks are all in `secondFactorMethods` ∪ `{mfa}`.
- **Recent MFA** (for enrollment-grade actions): `mfaAt` within `mfa.manage.maxAgeSeconds`; for a subject with no counting factor, a recent primary (`authTime` within the same window) instead, as F4; under `mfa.mode = "off"`, no requirement.
- **Conditional requirements are boot checks.** A manifest's `requires` is static, so `oauthModule` and `deviceGrantModule` keep `userSessionStore` optional and their factories refuse (`mfa-requires-user-session-store`) when `mfa.mode` is not `off` and it is unwired. `mfaModule` requires it outright. (Amended: `deviceGrantModule` already refuses an enabled grant without it, whatever the mode — see the note after the table.)

| Consumer | Where | Today | With MFA |
| --- | --- | --- | --- |
| `/authorize` | `packages/oauth/src/routes/authorize.mts` | live session; `amr` for `acr` | D17 |
| `session` grant | `packages/oauth/src/grants/session.mts` | live tracked session | baseline; unmet → `400 {"error":"invalid_grant", "error_description":"…", "step_up":"mfa"}` — `invalid_grant` so existing clients keep their mapping (auth.proxy: `session_unauthorized`, which sends the user to log in, now with MFA), `step_up` so an updated client can offer a step-up |
| refresh grant | `packages/oauth/src/grants/refreshToken.mts` | no session read | under `required` (O3): a refresh token whose carried `amr` is **absent** (pre-#481, or unknown), or holds `pwd`, not `fed`, and no second-factor value, is `invalid_grant` — only tokens issued before the flip look like that |
| `/oauth/consent` (GET, POST) | `packages/oauth/src/routes/consent.mts` | authenticated, live | no gate: it records consent and returns to `/authorize`, which decides and mints (D17) |
| device verification | `packages/device-grant/src/verificationEndpoint.mts` | `isAuthenticated` only | reads the live `UserSession` (a new optional `userSessionStore` slot, checked as above); a dead session is `401 login_required`; `approve` on an unmet baseline is `403 {"error":"mfa_step_up_required"}`. The device grant then stamps the approving session's `vouchedAmr` on its access token (it mints no refresh token) |
| federation-grants connect, consent, callback | `packages/federation-grants/src/browserRoutes.mts` | authenticated, durable session re-read | the rule on the durable session it already reads; connect sends an unmet session through login or the MFA page before anything is bound |
| federation `?link=1` | `packages/session/src/routes/Federation.mts` | authenticated | recent MFA: a linked identity is a new way in that the baseline does not cover |
| WebAuthn registration (`req.webauthnSubject`) | the deployment's middleware | the deployment's | a core helper, `authenticatedSubject(req, { recentMfa: true })`, which the WebAuthn README's bridge uses; registering a passkey adds a way in |
| `/session/mfa/*` | `packages/mfa` | — | its own rules |
| `/session/logout`, `/oauth/logout` | session, oauth | — | none: they reduce privilege |
| `/oauth/userinfo`, `/oauth/introspect`, `POST /oauth/federation/:name/token` | oauth | bearer tokens | none: they read tokens minted at the gated points |

**Amended 2026-09-26 (before implementation): device verification already reads the live session.** The device grant's liveness read shipped ahead of this ADR, as a security fix rather than an MFA slice, and in a stricter form than the row above plans. `deviceGrantModule` refuses to boot an enabled grant without a `userSessionStore` whatever `mfa.mode` is (`enabled = true requires a userSessionStore component`), so the `mfa-requires-user-session-store` refusal is subsumed for it and `oauthModule` alone keeps the MFA-conditional one. Device verification answers a missing `sid` or a dead session `401 login_required` today, reads the subject's sessions boundary when `subjectRevocation` is wired, and the grant refuses an approval that boundary covers at the poll. What the MFA slice (build order step 14) still adds to the device grant is only its baseline gate on `approve` (`403 mfa_step_up_required`) and the `vouchedAmr` stamp on the device token. The rows and steps below that describe the refusal as MFA-conditional read with this amendment.

### D17 — `acr_values`, `max_age` and `prompt=login`: one decision over one ask per request

Today's ask carries one fact and is consumed whenever `max_age` or `prompt=login` is present; a second kind of trip breaks it (`max_age=300&acr_values=phr` comes back from the MFA page and is answered `login_required`).

**One ask record per authorization request accumulates what was asked:**

```ts
interface AuthorizeAsk { // the `reauth:` record, reshaped
	readonly request: string; // the canonical authorize URL without the ask parameter
	readonly createdAt: number;
	readonly loginAskedAt: number | undefined; // sent to the login page
	readonly mfaAskedAt: number | undefined; // sent to the MFA page
}
```

**One function in `authorize.mts` decides, in order,** replacing `evaluateReauthentication` and `resolveAcr`:

1. **Read** the presented ask without consuming it; one bound to another request, expired or unknown is treated as none.
2. **Freshness** — needed for `prompt=login`, or when `max_age` is exceeded by `authTime`. Met when `loginAskedAt` is set and `authTime` is later. Not met: when `loginAskedAt` is set and `authTime` is not later, the user came back without logging in → `login_required`; `prompt=none` → `login_required`; otherwise set `loginAskedAt` and go to the login page.
3. **Methods** — D16's rule. Met → the chosen `acr`. A step-up can meet it: when `mfaAskedAt` is set and **`authTime` is not later than it**, this session was already sent → refuse (`unmet_authentication_requirements` for `acr_values`, `login_required` for the baseline); a session established after the MFA ask — `max_age` ran out during the trip and the user logged in again — may make one more trip. `prompt=none` → `interaction_required`. No step-up capability (D9) → a login trip instead, and a session still unmet after it → `unmet_authentication_requirements`. Otherwise set `mfaAskedAt` and go to the MFA page. Nothing can meet it → `unmet_authentication_requirements`.
4. **All met** → continue. The ask is **consumed on the pass that mints the code**. When consent must be asked first, the ask stays, and consent's resume URL — which already carries every parameter back, `reauth_ask` included — returns it; the pass after consent finds freshness and methods met and consumes it. (`resumeUrl`'s comment, "recorded on the session", is corrected: the ask is a record of its own.)

- **An unauthenticated request with `prompt=login`** writes the ask, with `loginAskedAt`, on its first redirect to the login page, so the user logs in once, not twice. Only for `prompt=login` (a fresh login satisfies `max_age` by itself), and under the `/authorize` rate-limit guard that already bounds the anonymous path.
- **Lifetime**: each stage write sets the record's TTL to 10 minutes from that write, capped at 30 minutes from `createdAt` — a first binding with an email proof can outlast ten minutes in one stage.
- A record in the previous shape (`askedAt`) reads as `createdAt` and `loginAskedAt`, so a trip in flight survives a rolling upgrade.
- Reading without consuming is safe: the ask grants nothing; it only records that this server sent the browser away.

| Request | Session | Answer |
| --- | --- | --- |
| nothing | primary `pwd`, `mfaAt` set | proceed |
| | primary `pwd`, no `mfaAt`, `required` | step-up (F2); `prompt=none` → `interaction_required` |
| | primary `fed`, any upstream `amr` | proceed — the baseline does not apply |
| | `session: null`, or primary unknown, `required` | re-authentication |
| | pre-upgrade, `amr` `["pwd"]` / holding `fed` | step-up / proceed (primary read as `pwd` / `fed`) |
| `acr_values` met | any | proceed; D15's preference order |
| `acr_values=urn:o3co:acr:mfa` | `fed`, upstream `mfa`, untrusted | step-up if the user holds a factor that adds `mfa`, else `unmet_authentication_requirements` |
| | `fed`, upstream `mfa`, federation trusted | proceed |
| | an email-only login | step-up with a factor that adds `mfa`, else `unmet_authentication_requirements` |
| `acr_values` a step-up can meet | the user holds a qualifying factor | step-up; `prompt=none` → `interaction_required` |
| | the user holds none | `unmet_authentication_requirements` after the trip (zero records and a fresh primary: a first binding first, F2) |
| `acr_values` nothing can meet | any | `unmet_authentication_requirements` |
| `max_age` exceeded, or `prompt=login` | any | re-authentication; then methods on the new session |
| `max_age` + `acr_values=phr` | TOTP session, old `authTime` | login trip, MFA trip, proceed — one ask |
| `prompt=login` + `acr_values=phr` | any | login trip, MFA trip, proceed — one ask |
| `max_age` runs out during the MFA trip | any | login trip, then at most one more MFA trip for the new session |
| unauthenticated, `prompt=login` | none | one login trip (the ask written on the first redirect), then as above |
| a client that needs consent, `prompt=login` + `acr_values` | any | login, MFA, consent, code — the ask consumed at the code, not before consent |
| returning without doing what was asked | the same session | `login_required` / `unmet_authentication_requirements` |
| no step-up capability, still unmet after the login trip | any | `unmet_authentication_requirements` |
| `max_age` within bounds | older `mfaAt` | proceed: `max_age` measures `auth_time`, which a step-up does not move |
| `claims` naming `acr` | any | `invalid_request` (D15) |

**`acr_values` is about methods, `max_age` and `prompt=login` about age**: an RP that wants a fresh second factor sends `max_age` or `prompt=login` and gets a full re-authentication.

### D18 — `auth_time`, and RFC 9470 alignment

- `auth_time` on the id_token stays `UserSession.authTime`: the **primary**, the conservative reading for an RP applying `max_age`.
- For RFC 9470 resource servers — `auth.policy-verifier` among them — the access token gains `auth_time` beside its `acr` and `amr` (the refresh token carries it forward), and introspection answers `acr`, `amr` and `auth_time`. Additive, a PR of its own that can be dropped (§8, PR 15).

---

## 5. Configuration and defaults

### D19 — Keys and switches

Core's reference and schema hold what core's consumers read with the MFA package absent; the MFA and SMTP packages ship their own `reference.conf`, layered by the composition root.

| Key | Env | Default | Meaning |
| --- | --- | --- | --- |
| `mfa.mode` (core) | `MFA_MODE` | core: `"off"` until the flip, then **no default** (O2); template and create-app: `"off"` until the flip, then `"required"` | `required`: every password login has a second factor and every consumer in D16 enforces it. `optional`: users with factors are challenged; nobody is forced; step-up works. `off`: no MFA; the package need not be installed. |
| `mfa.notices` | `MFA_NOTICES` | `mail` when a `mailSender` is wired; with none wired it has no default and `none` must be written (D20, D24) | `mail` or `none` |
| `endpoints.mfa.url` (core) | `ENDPOINTS_MFA_URL` | `/mfa` | The deployment's MFA page for step-ups |
| `federations.<name>.trustUpstreamAmr` (session) | per federation | `false` | D13 |
| `mfaFactorStore.adapter` (core) | `MFA_FACTOR_STORE_ADAPTER` | core `memory`; template `redis` (O6) | `memory` · `redis` · `store` |
| `mfaTransactionStore.adapter` (core) | `MFA_TRANSACTION_STORE_ADAPTER` | core `memory`; template `redis` | `memory` · `redis` |
| `redisMfaFactorStore.keyPrefix`, `redisMfaTransactionStore.keyPrefix` (core) | `REDIS_MFA_*_KEY_PREFIX` | `mfaf:`, `mfat:` | as for the other Redis stores |
| `mfa.encryptionKeys` | the first entry's `key` is `${?MFA_ENCRYPTION_KEY}` | none (development: the sample key, D11) | D11 |
| `mfa.transactionTtlSeconds` / `maxAttemptsPerTransaction` | — | 600 / 5 | D8, D21 |
| `mfa.lockout { threshold, baseSeconds, maxSeconds, memorySeconds, weeklyBudget, hardLimit, trustedBrowsers, trustedBrowserDays }` | — | 5 / 900 / 86400 / 86400 / 10 / 100 / 5 / 30 | D21 |
| `mfa.rateLimit.routes { limit, windowSeconds }` | — | 60 / 300 | seeded under prefix `mfa` (core `ratelimit/mfaSpec.mts`) |
| `mfa.manage.maxAgeSeconds` | — | 300 | recent MFA (F4, D16) |
| `mfa.enrollment { maxPrimaryAgeSeconds, requireEmailProof }` | `MFA_ENROLLMENT_REQUIRE_EMAIL_PROOF` | 600, `"when-mail"` | D24 |
| `mfa.maxFactorsPerSubject` | — | 10 | F4 |
| `mfa.factors.totp { enabled, algorithm, digits, period, window, issuer }` | `MFA_TOTP_ENABLED`, `MFA_TOTP_ISSUER` | `true`, `SHA1`, 6, 30, 1, the issuer's host | F6 |
| `mfa.factors.email { enabled, addsMfa, codeTtlSeconds, maxSends, resendAfterSeconds, sendLimit, subject, body }` | `MFA_EMAIL_ENABLED` | `false`, `false`, 600, 3, 30, 5 / 3600 s (prefix `mfa-email`), `"Your sign-in code"`, a template with `{code}` and `{minutes}` | F5, D14; needs a `mailSender` |
| `mfa.factors.webauthn { enabled, userVerification }` | `MFA_WEBAUTHN_ENABLED` | `false`, `preferred` | F7; needs `webauthn.rpId` / `rpName` / `origin` |
| `mfa.recoveryCodes { enabled, count }` | — | `true`, 10 | D25 |
| `mail.smtp { host, port, secure, user, password, from }` (smtp) | `SMTP_*` | port 587, `starttls` | D5 |
| `repositories.user.http.{list,create,update,delete}MfaFactor(s)Url`, `markMfaEnrolledUrl` (foundation) | `CLIENT_USER_*` | unset | D7, D12 |

**Amended 2026-09-27 (build-order step 3): what core's schema accepts before the MFA package exists.** Core's schema admits only `mfa.mode = "off"` until a module honours another mode — the build order's step 7 or 8, whichever comes first, widens it — so an operator who writes `required` before then is refused at boot rather than left believing logins ask for a second factor. Until the flip (step 22) the schema also defaults a missing section or mode to `"off"`, as core's `reference.conf` does, so a hand-built configuration declares the coordinator's absence once a module attaches `MFA_ABSENCE_POLICY`; the flip removes both defaults (O2). Core also owns `mfaTransactionStore.memory.maxEntries` (default 100 000): the in-process transaction store's cap, at which it refuses a new transaction as a store fault rather than evict one in flight.

**Why TOTP is the only counting factor on by default.** It needs nothing from the deployment. Email needs an SMTP relay and WebAuthn a relying-party id that depends on where the page is served.

**The template** (`templates/standalone`): `buildModules` installs `mfaModules` and the two stores when `mfa.mode` is not `off`, `mfaEmailFactorModule` when email is enabled, `smtpMailSenderModule` when `SMTP_HOST` is set, and `webauthnMfaFactorModule` with a `webauthnConfig` bootstrap when WebAuthn is enabled; nothing when the mode is `off`. `application.conf` repeats each `${?…}` line and ships D15's table. `.env.example` gains `MFA_ENCRYPTION_KEY` (`openssl rand -base64 32`) and `MFA_NOTICES`; `docker-compose.yml` gains a Mailpit service and points `SMTP_HOST` at it.

**create-app** gains `--no-mfa`, which writes `mode = "off"` on a marked line of the scaffold's `config/application.conf` and comments out the marked `acr` entry (the `MFA_MODE` line stays, so the environment still wins). A test scaffolds with and without it, loads the HOCON and asserts both.

### D20 — What "off" means, and what boot refuses

**Off** means: no MFA module installed; `/session/login` answers as today; `/authorize` has no baseline and answers `acr_values` needing a second factor with `unmet_authentication_requirements`; the `session` grant, device verification and the grants browser half have no MFA gate; `?link=1` and the WebAuthn bridge need no recent MFA; sessions record `mfaAt: undefined`. D13 applies whatever the mode: it is about what this provider vouches for.

"Off" is a statement: `sessionModule` and `oauthModule` declare `mfaCoordinator` optional with `MFA_ABSENCE_POLICY` (`configKey: ["mfa", "mode"]`, `absentValue: "off"`). An API-only deployment writes `mfa.mode = "off"`. `mfaModule` declares `mailSender` optional with `configKey: ["mfa", "notices"]`, `absentValue: "none"`.

| Composition | Refused by | Names |
| --- | --- | --- |
| `mfaCoordinator` unfilled and `mfa.mode` not `off` (after the flip, an unset mode too) | core, `component-absence-undeclared` | `mfa.mode = "off"`, and what is lost |
| MFA installed, `mfa.mode` `off` or unset | `mfaModule` | "remove the module, or set `mfa.mode` to `required` or `optional`" |
| MFA installed, no `mailSender`, `mfa.notices` not `"none"` | core, `component-absence-undeclared` | `mfa.notices = "none"` or the SMTP keys |
| `required`, no counting factor enabled | `mfaModule` (`mfa-no-counting-factor`) | the `mfa.factors.*.enabled` keys |
| `requireEmailProof = "always"`, no `mailSender` | `mfaModule` | nobody could enroll |
| email enabled, no `mailSender` | `mfaEmailFactorModule` requires the slot; the planner's missing-required refusal, with a hint naming `SMTP_HOST` | **email is never silently disabled** |
| WebAuthn factor enabled, no `webauthnConfig` | `webauthnMfaFactorModule` requires the slot | `webauthn.rpId` / `rpName` / `origin` |
| key ring empty, a key not 32 bytes, a duplicate id, or the sample key where D11 refuses it | the MFA config schema | `mfa.encryptionKeys` / `MFA_ENCRYPTION_KEY` |
| `mfa.mode` not `off`, `oauthModule` or `deviceGrantModule` without `userSessionStore` | their factories (`mfa-requires-user-session-store`; amended: `deviceGrantModule` refuses an enabled grant without it whatever the mode, D16) | the slot |
| memory MFA stores under `deployment.mode = "multi"` | core, replica safety | the modules and what forks |
| Redis factor store on an `allkeys-*` eviction policy | `redisMfaFactorStoreModule` (D12) | the policy |
| `mfaFactorStore.adapter = "store"` without the four URLs | foundation's builder | the missing URLs |
| `mail.smtp.secure = "none"` to a host that is not loopback | smtp's schema | the host |
| an `acrValues` entry nothing installed can satisfy | dropped; warned, or `info` under `off` (D15) | the entry |
| a `UserSessionStore` without `recordSecondFactor` | warned (`mfa_step_up_unsupported`); D17 re-authenticates | the adapter kind |

---

## 6. Security

### D21 — Attempts, lockout and rate limits

**Every code verification and its limits.** The per-transaction limit applies to all of them; the subject lock only to guessable ones.

| Proof | Entropy | Per transaction | Subject lock | Why |
| --- | --- | --- | --- | --- |
| TOTP at a login or step-up | 6 digits, 3 steps valid | 5 | yes | guessable |
| TOTP enrollment proof | 6 digits | 5 | no | the enroller was handed the secret; a guess wins nothing they do not hold |
| email factor code at a login or step-up | 6 digits | 5 (and 3 sends) | yes | guessable |
| `account-email` proof; email-factor enrollment code | 80 bits | 5 (and 3 sends) | no | not guessable; locking it would lock an unenrolled user out with no way in |
| recovery code | 80 bits | 5 | no | not guessable (NIST SP 800-63B-4 lets a look-up secret of 64 bits or more go unthrottled) |
| WebAuthn assertion or attestation | a signature | 5 | no | not guessable |

**The subject lock — exactly.** For guessable proofs only, per subject:

- **Consecutive run**: each reserved attempt counts as a failure until settled; `success` (a guessable proof) or an exempt success ends the run; `void` (the proof was right but the factor write lost or failed, F1 step 5) removes the attempt.
- **Short backoff**: from the 5th consecutive failure, locked 15 min, doubling per further failure to 24 h; forgotten 24 h after the last lock ends.
- **Weekly budget**: at most 10 failures in any rolling 7 days. **No success removes a failure** — neither the victim's own logins nor an exempt success — so the attacker's budget does not grow with the victim's activity. Past it, guessable proofs are held for the subject **except from a trusted browser**.
- **Trusted browser**: an exempt success (a recovery code, WebAuthn, and the 80-bit email proof) sets an `httpOnly` cookie (`<session.name>.mfa-trust`, 32 random bytes) whose digest is kept in the subject's state — at most 5 browsers, each until the weekly window next empties or 30 days. A guessable attempt presenting it passes the weekly hold; the transaction limit, the short backoff and the hard limit still apply to it, and its own failures still count. The attacker's browser holds no such cookie. This is not a remembered device (D26): it skips no factor; it only exempts one browser from a hold another browser caused.
- **Hard limit**: 100 consecutive failures hold guessable proofs until an exempt success, a credential change or an operator reset — NIST SP 800-63B-4's cap on consecutive failures.
- **Credential change**: `revokeAllForSubject` — what a Store calls after a password change — clears the subject's MFA lock state (`clearSubjectState`) when an `MfaTransactionStore` is wired. The password change is the remedy for an attacker who holds the password, and it ends the lock that attacker caused.

| Other control | Scope | Default | Where | On its store's outage |
| --- | --- | --- | --- | --- |
| Flood guard | per IP, every `/session/mfa` POST | 60 per 5 min | `rateLimiter`, prefix `mfa` | `rateLimit.failMode` |
| Email sends | per transaction; per subject | 3, 30 s apart; 5 per hour | the transaction; `rateLimiter` prefix `mfa-email` via `checkWithFailMode` | `503`; failMode |
| Subject lock, transaction limit | as above | as above | `MfaTransactionStore` | `503` |

**Why these numbers.** One TOTP guess succeeds with probability about 3 × 10⁻⁶. The short backoff alone, at the attacker's best schedule, allows about 2,500 guesses a year (≈ 0.75 %) plus five more every time the victim logs in; with daily victim logins, about 4,300 (≈ 1.3 %). The weekly budget bounds it regardless of the victim at about 520 guesses a year (≈ 0.16 %), and the hard limit stops a campaign the victim never interrupts at 100 (≈ 3 × 10⁻⁴).

**What it costs, stated.** Whoever holds the password can keep a user's guessable factors held indefinitely — ten failures a week. The user signs in with WebAuthn or a recovery code; that browser is then trusted and uses TOTP again. A TOTP-only user therefore spends one recovery code per browser per episode, not per login, and a password change ends the episode. The user's own typos count toward the week — ten is meant to be generous. The lock answer (`429 mfa_locked`, with `hold`, `Retry-After` where there is one, and `usable_kinds`) lets the page say which factors still work; under `mfa.notices = "mail"` the first hold is also mailed ("someone entered your password and failed the second factor"), and under `"none"` the page is all the user sees. The trade-off is decided in O5.

### D22 — Codes: entropy, lifetime, single use, replay

- **TOTP**: a secret of the algorithm's output length (F6); 6 digits; window ±1 step (configurable 0–2); **no automatic drift resynchronisation** (RFC 6238 §6); the provider's clock NTP-synced (runbook). Reuse within a step refused by `lastUsedStep` (F6).
- **Email**: the factor's code 6 digits, the proof and enrollment codes 16 Crockford base32 characters (80 bits), all from the CSPRNG; 10 minutes; only the latest counts; spent with the transaction; keyed digests at rest.
- **Recovery codes**: 10 codes of 16 Crockford base32 characters (80 bits), shown `XXXX-XXXX-XXXX-XXXX`, read case-insensitively with the hyphens and Crockford's `O`/`I`/`L` substitutions; single use by a compare-and-set after the transaction is consumed; keyed digests with their key id inside sealed data.
- **WebAuthn**: a 32-byte challenge taken once from the transaction; sign count per F7.
- **Transactions**: 256-bit id, session-bound, 10 minutes, consumed once.

### D23 — Email: enumeration and delivery failure

The email factor is reachable only after a correct password (F1) or from an authenticated session (F2, F4), so it cannot probe for accounts. The login's `403 mfa_required` reveals that the password was right — as every MFA-after-password design does; the `login` limiter, D21 and the notices bound what that is worth. Hints are masked (`k***@example.com`). Codes go only to an enrolled address or, for a proof, the Store's address for the account. A failed delivery is `503`, never "sent". Messages carry the code and nothing clickable.

### D24 — The first binding: trust on first use, stated

A first binding is authorized by the password — and, where mail is wired, by the mailbox too. In the default configuration (no mail) and at the flip, which makes every existing user unenrolled at once, that is a trust-on-first-use window for the whole user base: whoever holds a leaked password and logs in first binds their own authenticator, and the owner is then locked out. Self-service enrollment under `optional` is the same window. What the design does:

- **Notices are a declared decision.** `mfa.notices` is `"mail"` (every enrollment, removal, regeneration, reset and first hold is mailed to the account's address) or `"none"`, which a composition without a `mailSender` must write (D20).
- **Email proof before a first binding, by default when mail is wired.** `mfa.enrollment.requireEmailProof`: `"when-mail"` (default) requires the 80-bit `account-email` proof before the first counting factor is bound, whenever a `mailSender` is wired and the account has an address; `"always"` refuses a first binding without it; `"never"` skips it. Forced (F3) and self-service (F4) alike. It moves the window from "holds the password" to "holds the password and the mailbox" — what an email password reset already requires.
- **Binding strength is recorded on the factor**, not withheld from the session: each record carries `binding` (`"password"`, `"email_proof"`, `"mfa"`, D7), for audit; enforcing it was rejected (O4). Rejected as well: withholding `mfa` from a first-binding session. It would be a speed bump — the same session could step up with the factor it had just bound, every later login is a full `mfa` session anyway, and inside an MFA trip it would answer `unmet` right after enrolling. NIST's binding strength lives in the factor, not in one session.
- **Upgrade in two steps.** The upgrade guide tells an existing deployment to go `optional` first — users enroll at their own pace, with notices and email proof where mail is wired — and `required` once most have. New scaffolds start `required`.
- **The operator reset** (D25) is the remedy for a hijacked first binding.

The honest statement for a deployment without mail: MFA protects every account from the moment its owner enrolls, and does not protect an account whose password an attacker holds before then. Decided in O4.

### D25 — Recovery when a factor is lost: recovery codes, plus an operator reset

- **Recovery codes** (on by default): generated with the first counting factor, shown once, regenerated with recent MFA; exempt from the subject lock, and an exempt success (D21); each use audited and answered with the count left. A recovery code satisfies the second factor (`amr` `recovery`, plus `mfa`); under `required`, a subject with no usable counting factor left must enroll one before the session is written (F3).
- **An operator reset** for a user who lost everything: `resetMfaForSubject(subject, { requireEmailProof?, revokeSessions? })`, reached as `handle.components` like `revokeAllForSubject`. It removes every factor record, clears the subject's lock state, clears the witness last (D12), audits `mfa.factor.removed` (`by: "operator"`), and mails a notice under `mail`. `requireEmailProof: true` makes the user's next first binding require the email proof whatever `mfa.enrollment.requireEmailProof` says; `revokeSessions: true` also calls `revokeAllForSubject`. No HTTP admin surface; it never enrolls anything. The runbook requires out-of-band identity proofing before calling it: the reset is the account-takeover path if it is not.
- Rejected: **no recovery**; **email-link recovery** — it makes the mailbox a single factor that bypasses the second one; **security questions** (`kba`).

Decided in O8.

### D26 — No remembered devices in the first release

A "trust this browser for 30 days" cookie turns the second factor into possession of a cookie, is one more long-lived bearer to steal and revoke, and makes `acr` and `amr` ambiguous. D21's trusted browser is not this: it exempts a browser from a hold, never from a factor. Room is left: a device record would be a factor kind of its own (`remembered_device`, not counting, never satisfying an `acr`), meeting only the login baseline. O10.

### D27 — CSRF, session fixation and regeneration

- **CSRF.** The session's token is a stateless, signed double-submit, not bound to a session. What stops a forged `verify` or `enrollment/complete` is that every transaction is bound to the express session id and every use compares it. The login's `403` reissues a token only as a convenience after the regeneration. `GET` routes change nothing and are not readable cross-origin.
- **Transaction ids stay out of URLs** (§2).
- **Fixation.** The express session id is regenerated when the password is accepted, when the login completes, and after a step-up (a copy of the id taken before the step-up does not gain it). A session id planted before the login is dead by the first step.
- **What regeneration on step-up costs.** Records bound to the express session id are orphaned: a consent parked by `/authorize` (#552) and a federation-grant browser binding. Inside one flow the order prevents it — D17 decides before consent is parked, and the grants' connect gate runs before anything is bound. A consent or connect flow in another tab is lost and starts again.
- **The trusted-browser cookie** (D21) is `httpOnly`, `Secure`, `SameSite=Lax`, path `/session/mfa`, and useless without the subject state that names its digest.
- **Cache and framing.** `no-store` on every MFA response; the TOTP secret, the URI and recovery codes appear in exactly one response each. The page contract requires `frame-ancestors 'none'`.
- **Redirects.** `redirect_to` from `/authorize` is followed by the page only on the provider's origin; the login's `redirect_to` keeps its exact-match allowlist.

### D28 — Outages, logs and audit

- **Outages.** Every store the MFA routes read or write — the factor store, the transaction store, the `UserSession` store, the cookie session, the mail sender, the Store's witness — is `503 temporarily_unavailable`, logged once at error with `store`, `step` and `loggableError`'s projection. An outage is never "no factors", never "wrong code", never "sent". `/authorize` gains no new store read beyond the ask it already writes; device verification's new session read is `503` on an outage. A failed witness *write* after a successful binding is one warning and heals at the next login (D12).
- **Logs never carry** a code, a secret, an `otpauth://` URI, a recovery code, an address, factor data, a transaction id, a trusted-browser cookie, or a username.
- **Audit** (added to `BUILT_IN_AUDIT_EVENT_TYPES` and the runbook inventory): `mfa.challenge.sent`, `mfa.verified`, `mfa.verify.failure` (`reason`: `invalid` / `expired` / `replayed` / `sign_count_regression` / `exhausted`), `mfa.locked` (`hold`: `backoff` / `weekly` / `hard`), `mfa.factor.enrolled` (`binding`), `mfa.factor.removed` (`by`), `mfa.recovery_code.used` (`remaining`), `mfa.recovery_codes.generated`, `mfa.enrollment_state_inconsistent`. Each carries `subject`, `ip`, `userAgent`, `kind` and `purpose`; the MFA module declares `auditSink` optional under `AUDIT_SINK_ABSENCE_POLICY`.

---

## 7. Migration and compatibility

### Existing users, sessions and tokens at the flip

- **Users with no factor** meet a first binding at their next password login (F3, D24). The upgrade guide recommends `optional` first.
- **Sessions created before the flip** are read through `sessionAuthentication` (D9), and every consumer in D16 applies the baseline to them. The template's `session.maxAge` is one hour.
- **Federated sessions** are untouched by the baseline. Their upstream `amr` stops counting at once (D13) — breaking.
- **Tokens issued before the flip** keep their `amr`. Access tokens run out their lifetime. Refresh tokens are gated (O3): without a gate, a 30-day refresh token would keep minting password-only access for a month after "MFA required"; with D16's refresh-grant rule, each stops at its next refresh — a token with no `amr` at all counting as unknown — and its client sends the user through a login.

### Upgrading an existing deployment

A scaffold owns its `buildModules` and `application.conf`, so **upgrading packages never silently turns MFA on**: after the flip, a composition that installs `sessionModule` or `oauthModule` without the MFA modules meets a boot refusal naming `mfa.mode` (D20). The port checklist the upgrade guide carries:

1. Add `@o3co/auth-provider-mfa` (and `@o3co/auth-provider-smtp` for mail) to `package.json`.
2. Port the MFA block of `buildModules` and the `mfa`, `mfaFactorStore`, `mfaTransactionStore`, `endpoints.mfa` and `oauth.authorize.acrValues` blocks of `application.conf`, with their `${?…}` lines.
3. Set `MFA_ENCRYPTION_KEY`, and `SMTP_*` or `MFA_NOTICES=none`.
4. Make the Redis the factor store uses durable (D12); give the Store `mfaEnrolled` and `markMfaEnrolledUrl` if it can.
5. Teach the login page `403 mfa_required` / `mfa_enrollment_required`; build the MFA page and the account page (D6).
6. Teach BFFs using the `session` grant the `step_up` member, the device-verification page `403 mfa_step_up_required`, and the `req.webauthnSubject` middleware the `authenticatedSubject` helper.
7. Decide `trustUpstreamAmr` per federation.
8. Set `mfa.mode = "optional"`; move to `required` later.

### BREAKING for integrators

1. **Boot** (after the flip): a composition with `sessionModule` or `oauthModule` must install the MFA modules or write `mfa.mode = "off"`; with MFA installed, it must wire mail or write `mfa.notices = "none"`; `oauthModule` and `deviceGrantModule` need `userSessionStore` when MFA is on (amended: an enabled `deviceGrantModule` needs it already, whatever the mode — D16).
2. **The login page**: `POST /session/login` can answer `403 mfa_required` / `mfa_enrollment_required`. A page that ignores it shows the error text rather than looping.
3. **New pages**: `endpoints.mfa.url`, and the account page.
4. **The `session` grant** answers `400 invalid_grant` (with `step_up: "mfa"`) for a session without the second factor.
5. **Device verification** can answer `403 mfa_step_up_required`. (Amended: the live-`UserSession` requirement and its `401 login_required` shipped before this ADR — see D16.)
6. **Federation `?link=1`** and WebAuthn registration through the helper require recent MFA.
7. **Upstream `amr`** (#481): no longer stamped or honoured for `acr` unless the federation is trusted; acr entries only it satisfied are dropped with a warning.
8. **`claims` naming `acr`** is refused with `invalid_request`.
9. **A new required secret**: `MFA_ENCRYPTION_KEY`.
10. **`UserSession` / `CreateUserSessionInput`** gain the required key `authentication`: a custom `UserSessionStore` must round-trip it, a custom login path must pass it (compile errors, the #626 shape; `docs/upgrading-required-record-keys.md` gains a section); a custom store should implement `recordSecondFactor`.
11. **Core's barrel** loses the #69 names (D3), and `BootErrorReason` loses `mfa-partial-wiring`; `webauthn`'s internal option builders change signature (D4).
12. **Rate limiting**: two new key prefixes, `mfa` and `mfa-email`. The bundled limiters seed them; a custom `RateLimiter` that resolves specs by prefix learns them or falls to its default.
13. **Redis**: two new key families (`mfaf:`, `mfat:`) and the factor store's durability requirements; the `UserSession` envelope gains `authentication`.
14. **`revokeAllForSubject`** also clears the subject's MFA lock state.
15. **Discovery**: a template deployment advertises `urn:o3co:acr:mfa`.

Additive: `amr` gains `otp` / `hwk` / `swk` / `email` / `recovery` / `mfa`; device-grant access tokens gain `amr`; access tokens gain `auth_time`; introspection gains `acr` / `amr` / `auth_time`.

### Sibling repositories

- **o3co/auth (the umbrella E2E)** pins the provider by commit (`PROVIDER_REV`), logs in with `POST /session/login` expecting a session, and mounts `tests/abac/application.conf` over the template. `tests/abac/application.conf` sets `mfa.mode = "off"` — or `tests/shared/oauthFlow.js` learns a TOTP step against a seeded factor — in o3co/auth **before the PR there that bumps `PROVIDER_REV`** to a commit containing the flip. The pin means nothing breaks until that bump; the fix only has to precede it.
- **auth.proxy** maps the `session` grant's `400 invalid_grant` to `session_unauthorized` (`src/modes/injection/session-grant-client.mts`), so a BFF user without the second factor is sent to log in again — which now includes MFA: safe. A follow-up there can read `step_up` and route to the MFA page. Keeping `invalid_grant` is deliberate: a new error code would fall into "any other 400", `provider_config_error`.

### The unused core MFA surface

Replaced by D3 in one breaking PR early in the build order. Nothing in this repository imports the removed names; an external composition root that did gets compile errors naming them, and the CHANGELOG entry points it at `@o3co/auth-provider-mfa`.

### Rolling back

An older release reads a `UserSession` envelope with `authentication` (its shape check ignores the extra field) and `amr` values it does not know; a federated session written by the newer release carries `["fed"]` only. An ask record in the new shape lacks the `askedAt` the older reader requires, so it reads as no ask: a browser returning with `prompt=login` or an exceeded `max_age` is sent to the login page again, and one returning with `acr_values` alone is answered `unmet_authentication_requirements`, as the older release always did. The MFA key families and the trusted-browser cookie are ignored. Rolling back forfeits MFA; factors stay for the next roll forward.

---

## 8. Build order

The PR numbers below are the plan at acceptance, and the rest of this record cites them; the CHANGELOG records what each release actually shipped. Each PR is RED → GREEN → REFACTOR: the contract or route test first, watched failing. Flow tests boot the real modules through `createApp` (session, oauth, MFA, memory stores) and drive them with a supertest agent holding the cookie jar, as the federation-grants acceptance tests do. A PR that adds a module or slot also adds its rows to `docs/adapter-surface.md`, the replica-safety declarations, the audit inventory, `tools/composition`'s fixture and the template's all-modules test, because their drift tests require it of whichever PR adds one.

**Every intermediate release is safe.** Core's `mfa.mode` reference default is `off` until PR 22. `@o3co/auth-provider-mfa` is `"private": true` — built and tested in the workspace, never published — until PR 20 wires it, so no release publishes verification before the lock (PR 10) exists. The requirement rule (PR 4) lands before the upstream split (PR 5), and PR 5 teaches the drop rule about trust in the same change, so no release advertises an entry it can no longer meet or writes `authentication` beside an unsplit `amr`.

| PR | Delivers | Tests |
| --- | --- | --- |
| 1. `docs(core)`: this ADR | The design under `packages/core/docs/adr/` | — |
| 2. `refactor(core,redis)`: a sealing leaf | `core/src/sealing/` with a purpose label; `redis` imports it | Envelope tests move; a grant sealed by the old code opens with the new; the leaf rule |
| 3. `feat(core)!`: ports | D3's removals; `MfaFactor`, `MfaFactorStore`, `MfaTransactionStore` (D21's operations), `MfaCoordinator` + `MFA_ABSENCE_POLICY` (unattached); `mfaFactorResolver`; nullable `mfaFactors`; memory adapters and modules; `mail/` and the recording sender; the witness (`User.mfaEnrolled`, `markMfaEnrolled` + guard) and its adapter-surface justification; `ratelimit/mfaSpec.mts`; `mfa.mode` (`off`), `endpoints.mfa.url`, the store switches | Both contract suites against memory, races and D21's schedule under an injected clock (void, trusted browser, weekly window untouched by success); replica-safety drift; the synthetic key rejected from `provides`; seeding in both limiters; config drift |
| 4. `feat(core,oauth)!`: the requirement rule | `mfa/requirement.mts` (primary-based baseline, `session: null`, `acr` with step-up targets, any-of entries, preference order); `composeAmr` and the constants; unsatisfiable entries dropped (every federation counted as trusted — today's behaviour); `claims` naming `acr` refused | Table-driven tests over D17's rows; discovery without a dropped entry; `claims` cases |
| 5. `feat(core,redis,session,oauth,federation-grants)!`: `UserSession.authentication` and the upstream split | The required key through every call site — the login route, the federation callback, the Redis envelope, the memory store, and every test that builds a `UserSession` (session's, oauth's, and federation-grants' `browserRoutes.test.mts` and `acquisition.acceptance.test.mts` among them); `sessionAuthentication` / `vouchedAmr` at `/token` and the `session` grant; `recordSecondFactor` with D9's split on both adapters; `trustUpstreamAmr`; the drop rule honouring trust; `FEDERATED_AMR` in core | `userSessionStore.contract.mts` (both copies): round-trip, monotonic update, the split of a pre-upgrade `["hwk","fed"]`, `null` for a gone session, TTL unchanged; upstream values absent from tokens and `acr` by default, present when trusted; a now-unmet entry dropped in the same release |
| 6. `feat(redis)`: the MFA stores | `redisMfaFactorStoreModule` (+ D12's boot check), `redisMfaTransactionStoreModule`, clients, ioredis wrappers, Lua; runbook key families | Core's suites on a testcontainer with the parity test; `allkeys-lru` refused; RDB-only and a `CONFIG`-less server warned |
| 7. `feat(session)!`: the login hands off | `establishSession` extracted (existing tests unchanged — the refactor's proof); `sessionModule` declares `mfaCoordinator` with the policy; the two `403`s; regeneration into the pending state | With a stub coordinator: the pending browser is not authenticated at `/authorize`, the id rotates, a coordinator outage is `503` with nothing written, `off` unchanged |
| 8. `feat(mfa)`: the package (private), verification | `packages/mfa`: coordinator, `GET transaction`, `challenge`, `verify`; TOTP verification; the key ring and the sample-key refusal; audit (factors seeded in tests) | RFC 6238 Appendix B; a TOTP login; reuse and an older code refused; window edges; N parallel wrong codes spend N; consume before advance; data copied to another subject does not open; every outage `503` once; ids never in a URL |
| 9. `feat(mfa)`: enrollment and the first binding | Forced and self-service TOTP enrollment; recovery-code generation; `binding` recorded; the 80-bit `account-email` proof over the recording sender; `mfa.notices` declared and sent; witness writes through the port (create-then-mark, reconciliation) | First login binds TOTP and gets codes; with a sender, no binding without the proof, and 5 wrong proofs end the transaction without touching the subject lock; MFA without mail refuses boot unless `notices = "none"`; unreadable data never binds; a failed mark heals at the next login |
| 10. `feat(mfa,core)`: the lock and recovery codes | Backoff, weekly budget, trusted browser, hard limit, void; exempt factors; recovery-code verification; `revokeAllForSubject` clears the lock | The schedule under an injected clock; the victim's successes do not refund the week; a recovery code works while TOTP is held and trusts that browser only; another browser stays held; a password change clears it; a lost compare-and-set does not count |
| 11. `feat(mfa)`: step-up transactions | `POST /session/mfa/step-up`; `recordSecondFactor`; regeneration | Step-up on a live session; a gone session refused; `no_qualifying_factor`; the id rotates, the `sid` stays |
| 12. `feat(mfa)`: management, reset, witness reads | List / rename / remove / regenerate; recent-MFA and last-factor rules; `resetMfaForSubject`; the witness read at login and from the session snapshot | `mfa_step_up_required` then success through PR 11's route; `last_factor`; the reset clears locks, factors and the witness in that order and honours its options; witness `true` with zero records is `503`, never a binding |
| 13. `feat(oauth)!`: `/authorize`, the `session` grant, the refresh grant | D17: one accumulating ask, per-stage TTL, consumption at the code, the ask carried through consent, the ask on an unauthenticated `prompt=login`, `interaction_required`, the degrade path; `oauthModule`'s policy and store check; the `session` grant's `step_up`; the refresh-grant rule (O3); `resumeUrl`'s comment corrected | Every D17 row — `max_age`+`acr_values` and `prompt=login`+`acr_values` in one ask, `max_age` running out mid-trip, consent after both trips, returning without doing what was asked, a replayed ask; id_token `amr`/`acr`/`auth_time` after a step-up; a pre-flip session and refresh token, one without `amr` |
| 14. `feat(device-grant,federation-grants,session,core)!`: the other consumers | Device verification reads the live session and gates `approve`, and the device grant stamps `vouchedAmr`; the grants' browser half gates connect; `?link=1` requires recent MFA; `authenticatedSubject` (recent-primary fallback, `off` exemption) and the WebAuthn README's bridge; `deviceGrantModule`'s store check | Per consumer through `createApp`: unmet → step-up answer, met → as today, dead session → `401`, outage → `503`, `off` → as today |
| 15. `feat(oauth)`: RFC 9470 alignment | `auth_time` on access and refresh tokens; `acr` / `amr` / `auth_time` in introspection | Grant and introspection tests; the refresh chain keeps `auth_time` |
| 16. `feat(mfa)`: email codes | `mfaEmailFactorModule`: 6-digit login codes, 80-bit enrollment codes, `addsMfa`; send limits; delivery failure | Enrollment to the account's address only; resend invalidates; `maxSends` and cooldown; per-subject sends under both fail modes; a throwing sender is `503` and the transaction survives; an email login meets the baseline and not `urn:o3co:acr:mfa`; no code or address in a log line |
| 17. `feat(smtp)`: SMTP `MailSender` | `packages/smtp` over `nodemailer`; TLS rules; `MailTransportError` | Against Mailpit in a testcontainer: delivery; STARTTLS off loopback; reasons mapped; a sentinel address never in an error |
| 18. `feat(webauthn)`: WebAuthn as a second factor | `webauthnMfaFactorModule`; descriptor-taking option builders with `residentKey`; `hwk` / `swk`; challenge in the transaction; sign-count handling | Verification mocked at `#/internal/verification.mjs`, as the grant's tests do; register then assert through `createApp`; a challenge answered twice fails the second; a lost compare-and-set retries, a regression is refused; WebAuthn works while TOTP is held; the grant's routes unchanged |
| 19. `feat(foundation)`: factors and the witness in the Store | `HttpMfaFactorStore`, the four URLs, `markMfaEnrolled` over `markMfaEnrolledUrl`, README wire contract | Core's suite over an `msw` fake Store; `404` / `5xx` / a redirect from `list` throw; the Store never receives unsealed data; the witness kept on bind, remove and reset |
| 20. `feat(template,create-app)`: MFA wired, still off | `packages/mfa` published (`private` removed); the template's composition and switches (`mfa.mode = "off"`), `acrValues`, env, Mailpit, the sample key; `create-app --no-mfa`; runbook (boot refusals, fail-closed rows, alerts, key rotation, Redis durability, recovering from a lost factor store, the reset procedure); READMEs; the upgrade guide and port checklist | All-modules composition with MFA on and off; `MFA_MODE=required` boots with Mailpit and refuses without mail unless `MFA_NOTICES=none`; email on without SMTP refused naming `SMTP_HOST`; the sample key refused under `CONFIG_ENV=production`; create-app with and without the flag, no `acr` warning under `off` |
| 21. o3co/auth: the umbrella E2E declares MFA off | `tests/abac/application.conf` sets `mfa.mode = "off"` (or `oauthFlow.js` gains a TOTP step) — merged before the o3co/auth PR that bumps `PROVIDER_REV` past PR 22 | The umbrella suite green at the current pin and at the new one |
| 22. `feat!`: on by default | Core's `mfa.mode` reference default removed (O2), the template's and create-app's default `required`; CHANGELOG draft in the PR description (release policy R2) | Core: a composition with neither the modules nor a declaration refused; the template: a fresh scaffold refuses until `MFA_ENCRYPTION_KEY` and mail or `MFA_NOTICES`, then logs in through a first binding |

A follow-up outside this repository: auth.proxy maps `step_up` to a step-up route instead of `session_unauthorized`.

---

## 9. Owner decisions (2026-09-25)

The decisions this design left to the owner, as taken, with what was rejected.

**O1 — Upstream `amr` does not count by default.** Upstream values are kept apart (`authentication.upstreamAmr`, never stamped, never matched for `acr`), and `federations.<name>.trustUpstreamAmr` opts a federation back in. The breaking change is accepted; the acr entries only upstream values satisfied are dropped at boot with a warning, which is where an operator sees it (D13). Rejected: trusting by default, as #481 does today, which lets an IdP's word meet this provider's `acr`; namespacing the values (`upstream:mfa`), which spends `amr` on values no relying party can act on.

**O2 — "On by default" lives in the template and create-app.** They default to `required`; core's reference removes its default for `mfa.mode`, so every composition root — the template's, and one written by hand — states `required`, `optional` or `off`, the repository's rule for security-relevant slots. Rejected: flipping core's reference to `required`, under which the MFA module, installed without a mode, would enforce silently; keeping core's reference at `off`, under which a hand-written composition gets no MFA and no signal.

**O3 — What was issued before the flip is gated at its next use.** Every session consumer applies the baseline (D16) — no mass logout — and the refresh grant refuses a refresh token issued without a second factor, a token with no `amr` at all (issued before #481) counting as unknown, so password-only refresh tokens end at their next refresh. Access tokens run out their lifetime. Rejected: leaving refresh tokens alone, which keeps password-only access alive for their whole lifetime; revoking every password-only session at the flip.

**O4 — The first binding is trust on first use, stated, and narrowed where mail is wired.** Notices are a declared decision; the 80-bit email proof is required before a first binding whenever mail is wired; binding strength is recorded on the factor and not enforced; existing deployments go `optional` first (D24). Rejected: enforcing binding strength per factor — a factor bound on the password alone meeting the baseline but adding no `mfa` until an out-of-band confirmation — honest by NIST's binding rules, but it leaves a deployment without mail with no user who can meet `urn:o3co:acr:mfa`; `requireEmailProof = "always"`, which stops a deployment without mail from enrolling anyone.

**O5 — Guessing is bounded over the week, and the user keeps a way in.** The weekly budget that no success refunds (about 0.16 % a year for an attacker who holds the password), a browser trusted after an exempt success, a credential change clearing the lock, and a lock answer that names the factors that still work (D21). Rejected: no weekly budget, which allows about 1.3 % a year with daily victim logins; a weekly budget that an exempt success resets, under which a user who signs in with WebAuthn every day hands an attacker ten guesses a day.

**O6 — Enrollments default to Redis, and their loss is caught.** The template keeps factors in Redis, with D12's durability requirements checked at boot where the server allows; the Store witness is recommended for production; the Store-backed factor store serves deployments whose Store can host it, where losing the factors means losing the users. Rejected: the Store as the template's default, which would make every deployment implement four factor endpoints with compare-and-set, and the witness, before its first login.

**O7 — An email code meets the baseline and does not add `mfa`.** `mfa.factors.email.addsMfa` is `false` by default, so an email login never meets `urn:o3co:acr:mfa`; a deployment that does not reset passwords by email may set it to `true`. The factor is off by default and never meets `phr`. NIST SP 800-63B-4 does not accept email as an out-of-band authenticator, and wherever passwords are reset by email, an email code makes the mailbox a single factor for any user who picks it — the objection D25 raises against email-link recovery. Rejected: counting email as a full second factor; not offering email at all where passwords are reset by email.

**O8 — Recovery is recovery codes plus an operator reset.** Recovery codes are on by default (80 bits, exempt from the lock); the operator reset is a library call, and the runbook requires out-of-band identity proofing before it (D25). Rejected: no recovery; email-link recovery; an HTTP admin surface.

**O9 — The public names.** `urn:o3co:acr:mfa`, and — commented out in the template — `urn:o3co:acr:phr = [["hwk"], ["swk"]]`; the `amr` values `email` and `recovery` beside `fed`; `hwk` or `swk` by the WebAuthn backup-state flag. Taken knowing two things: `o3co` is not a registered URN namespace (RFC 8141), and the factor's `hwk` / `swk` split differs from the passwordless grant, which stamps `hwk` for synced passkeys until it is aligned. Rejected: an `https` URI under a domain o3co controls; the REFEDS MFA profile URI, which carries a profile's compliance obligations; the EAP draft's bare `phr`; shipping no values.

**O10 — No remembered devices in the first release** (D26). Rejected for now: a cookie that lets a browser skip the second factor.

**O11 — The product ships no UI.** A documented page contract with a worked example, and QR rendering in the page (D6). Rejected: reference pages in the template and a QR-encoder dependency, which the template would then maintain as product.

---

## Consequences

**Good.** A password alone no longer signs anyone in, by default, with an explicit way out. Every consumer of a browser session asks the same question the same way. `/authorize` meets an RP's `acr_values` in one decision per request. The provider's tokens say only what it vouches for. Every stored secret is sealed and bound to its record. Guessing is bounded under concurrency, across transactions and across the victim's own logins, while the user keeps a way in. An outage, or a lost factor store, is never a downgrade. The #69 surface is gone.

**Bad.** A large surface: two packages, four ports, five store adapters, ten routes, a page contract, a trusted-browser cookie, and changes in six existing packages. Integrators change their login page, build two pages, add a secret, declare notices, and decide explicitly if they want none of it. A federated deployment loses upstream `amr` until it trusts its IdPs. Custom session stores gain a required key. A dropped ring key or a switched-off factor kind strands its users until a recovery code or a reset. A password holder can hold a user's guessable factors. Without mail, the first binding is trust on first use.

**Neutral.** TOTP is the only counting factor on by default. An email login meets the baseline and no `acr`. `acr` is still stamped only when asked. A step-up never satisfies `max_age`.

## Outside the first release

**Planned — room is left.**

- **MFA after a federated login.** The federation callback calls `mfaCoordinator.decideAfterPrimary` with `method: "fed"`, and `mfa.requiredAfter` gains `fed`; a trusted upstream `mfa` meets it.
- **A per-client requirement.** A client registration field (`requireMfa`) that D17 adds as an implicit `["mfa"]` requirement.

**Options — no delivery commitment.** Remembered devices (D26). Factor-level binding strength enforced (O4). TOTP drift resynchronisation. The passwordless WebAuthn grant stamping `hwk` / `swk` by the backup-state flag. `phrh` with attestation. WebAuthn Level 3 `hints`. Localised mail templates. A server-rendered QR code and reference pages (O11). A browser session created by the passwordless WebAuthn grant.

**Not planned.** SMS; an HTTP admin API for factors.

## References

- RFC 4226 (HOTP), RFC 6238 (TOTP) §5.2, §6 and Appendix B, RFC 4648 (base32), RFC 8176 (`amr`), RFC 8141 (URNs), RFC 9470 (Step-Up Authentication Challenge), RFC 6749 §4.1.2.1 and §5.2
- OpenID Connect Core 1.0 §2, §3.1.2.1, §3.1.2.6, §5.5 and §5.5.1.1; OpenID Connect Unmet Authentication Requirements 1.0; OpenID Connect EAP ACR Values (draft); the REFEDS MFA Profile
- W3C Web Authentication Level 3 (backup state, `hints`); Google Authenticator Key Uri Format
- NIST SP 800-63B-4 (August 2025): out-of-band devices, look-up secrets, one-time-password devices, authenticator binding, rate limiting
- This repository: #69, #284, #297, #363 / #375 / #406, #455, #473, #481, #527 / #552, #593, #626, #689 / #692
- Sibling repositories: o3co/auth `Makefile` (`PROVIDER_REV`, o3co/auth#31), `tests/shared/oauthFlow.js`, `tests/abac/application.conf`; auth.proxy `src/modes/injection/session-grant-client.mts`

