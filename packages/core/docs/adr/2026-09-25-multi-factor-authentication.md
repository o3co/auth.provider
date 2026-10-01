# Multi-factor authentication: a second factor after password login, and step-up at `/authorize`

- Status: accepted (2026-09-25); build-order steps 1–8 implemented, the rest planned. Amended 2026-09-29 (module review): the build order below is the plan at acceptance, amended at its places. Steps 1–6 landed as #693, #695, #702, #706, #707 and #720; step 7 was replaced by the session-admission ADR's series (#709, #715–#719, on #713's extraction of `establishSession`); step 8's first two parts landed as #721 (8a) and #729 (8b), and its third as #809 (8c). Steps 9–22 are planned.
- Date: 2026-09-25
- Replaces: the MFA extension surface added by #69 (2026-04-21) in `packages/core/src/mfa/`, which no product code has ever called (D3)
- Written against: `develop` at `d3d9c8f2` (#692). Every "today" below was checked there, and the sibling repositories at their `develop`.
- Amended 2026-09-28 (session admission): after step 5 (#707), [the session-admission ADR](2026-09-28-session-admission.md) moved the question "may this session proceed?" out of each consumer and into one core decision point, and made MFA the first *requirement* registered with it. D8's coordinator slot, D16's per-consumer wiring, D19/D20's `mfa.mode` in core, build-order steps 7, 13, 14 and 22, and O2 are amended below, each at its place; that record's §7 lists them together. Steps 1–5 stand as built.
- Amended 2026-09-30 (rate-limit budgets, #782): the bundled limiters no longer seed budgets; the module that keys a prefix contributes its budget (`rateLimitBudgets`). The MFA module contributes `mfa` from `mfa.rateLimit.routes`, and the email factor's module is to contribute its own `mfa-email` from `mfa.factors.email.sendLimit` *(superseded 2026-09-30, #810: there is no `mfa-email` budget; limits on sending are the mail sender's)*; where this record says the limiters seed them, or names core's `ratelimit/mfaSpec.mts`, read that.
- Amended 2026-09-30 (the Store's MFA contract over HTTP, #754): the contract suites of what code outside core implements live in a published package of their own, `@o3co/auth-provider-test-kit`, which depends on core alone — the enrollment witness's is written there, with a fake Store, and D7's factor-store suite and the Redis package's copies follow before 1.0, their parity test going with them. The Store adapter's four URLs are the `foundation-mfa-factor-store` section's (`FOUNDATION_MFA_FACTOR_STORE_*_URL`), not `repositories.user.http`'s, and each is required: a missing one refuses boot (D7's "four optional URLs", D19). An update names the record by `subject` and `id` and carries the expected version and, as its changes, only `data`, `label` and `lastUsedAtMs`; the wire contract is `@o3co/auth-provider-foundation`'s README.
- Amended 2026-09-30 (#810): **the Provider's duties end at its interfaces.** It keeps what verifying a code needs — issuing it, its expiry and single use, a resend replacing it, the attempt limits and the lock — and hands off what is not the verifier's: rendering and sending mail, limits on sending, and notifying the account holder. At each place:
  - **D5.** `MailSender` carries meaning only: the purpose — `login_code`, `account_email_proof` or `email_factor_enrollment` — the account's subject, the recipient, the code and its expiry. It answers delivered or refused at a limit, read one way (`mailSendOutcome`): anything else is an outage, as a rejection is. Rendering, language, delivery and send limits are the sender's. `@o3co/auth-provider-standard` holds the SMTP sender — its section and its rendering — and a development sender that logs the code, installed only where the configuration was selected as development or test; there is no `@o3co/auth-provider-smtp`. A factor's `challenge` or `beginEnrollment` answers the purpose and the code to mail, never text; the coordinator keeps the state, then sends.
  - **D5 and F5: the recipient.** A code goes to the address on the account's user record at the moment it is sent, in one normalised spelling, one addr-spec alone. The provider stores no address: the coordinator keeps, with the pending state, the keyed digest of the address it sent to, and hands that digest — never one of a later read of the Store — to the call that takes the code; an email factor records the one its enrollment's completion is handed (D11: under the key ring, with the key's id, made again under the current first key when a verification is handed a newer one). A login code goes only when the current address's digest matches the recorded one. On a mismatch, no address, or a recorded digest the factor cannot read (it mails `null`), the factor is refused until the user enrolls it again after recent MFA, and `mfa.email_address_mismatch` records it; so a change of the Store's address never redirects a code. The cost: a user whose address changes loses the email factor until re-enrollment, and one with no other factor needs a recovery code or the operator reset (D25). The `account-email` proof goes to the current address.
  - **D8.** A transaction counts no sends, and the transaction store keeps no trusted browser. A refused attempt says whether it begins a hold — the first refusal since an attempt was let through — which step 10's `mfa.locked.first` is recorded from.
  - **D19.** `mfa-email-factor` holds the switch, whether a verification adds `mfa`, and a code's life: no text, no send limits, no `mfa-email` budget. `mfa.lockout` has no trusted-browser keys. There is no `mfa.notices`. The SMTP settings are the standard package's section, `standard-smtp-mail-sender`.
  - **D20.** The row refusing MFA without a `mailSender` while `mfa.notices` is not `none` goes.
  - **D21.** The trusted browser goes: no `<session.name>.mfa-trust` cookie, no five-browser cap, renewal or expiry, and no attempt passes the weekly hold. Five attempts per transaction, the backoff (from five consecutive failures, 15 minutes doubling to 24 hours), ten failures in seven days, the hard limit of 100, and `revokeAllForSubject` → `clearSubjectState` clearing the lock stay; an exempt proof still passes during a lock, ends the consecutive run and refunds no weekly failure. A TOTP-only user under attack therefore needs a recovery code at each login until the password changes, which is the remedy. The controls table's email-sends row goes.
  - **D23.** A mail refused at a limit is `429`; an outage is `503` and leaves the transaction standing. Either clears the code the send was for.
  - **D24.** Notices are the deployment's, built from the audit events (`auditSink`); the provider sends none, and the runbook requires them. The events cover every former trigger — `mfa.factor.enrolled`, `mfa.factor.removed`, `mfa.recovery_codes.generated`, `mfa.reset` (step 12) and `mfa.locked.first` (step 10) — each carrying the subject, the kind, the binding it concerns, who acted where someone did, and when; and `mfa.email_address_mismatch` (step 16) marks an email factor refused at a changed address, with the subject and the kind, never an address.
  - **D26.** "D21's trusted browser is not this" goes: there is none.
  - **Build order.** Row 9 declares and sends no notice: it records the audit events. Row 10 builds no trusted browser: a recovery code passes during a hold and trusts nothing. Row 16 has no send limits — no `maxSends`, cooldown or per-subject sends — and keeps a resend replacing the code, D5's recipient rule and D23's answers. Row 17 is the SMTP sender's delivery in `@o3co/auth-provider-standard`. Row 20 has no `MFA_NOTICES`, and its SMTP variables are the standard package's (`STANDARD_SMTP_MAIL_SENDER_*`).
  - **Upgrading and BREAKING.** The port checklist's mail package is `@o3co/auth-provider-standard`, its variables `STANDARD_SMTP_MAIL_SENDER_*`, and there is no `MFA_NOTICES`; BREAKING item 1 loses its `mfa.notices` clause. Rate limiting gains one prefix, `mfa`, which the MFA module contributes (#782).
- Amended 2026-09-30 (build-order step 19, first part): the Store-backed factor store trusts the Store with the factors' integrity and freshness (D7's amendment of that date).
- Amended 2026-09-30 (build-order step 18; owner, provisional): a WebAuthn factor is `hwk` only when it is not backup-eligible (BE = 0), and keeps its BE from registration (D14's amendment of that date).
- Amended 2026-10-01 (#857): a second factor's credential shown in the passwordless grant's picker is not cosmetic; the grant refuses an assertion whose user handle is not its record owner's, and `webauthnMfaFactorModule` refuses the boot while `webauthn.allowCredentialsForKnownUser` is on (F7's amendment of that date).
- Amended 2026-10-01 (build-order step 19b, owner decision): the Store answers the enrollment witness on `authenticateByToken` as on `authenticate` (D12's amendment of that date); `markMfaEnrolledUrl` is a key of the user repository's settings (D19's amendment of that date); the witness kept on remove and reset is step 12's test (the build order's amendment of that date).
- Amended 2026-10-01 (build-order step 10, owner decision): an exempt success no longer lifts the hard limit; a rebind or an operator reset does (D21's amendment of that date).

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
- **A transaction's binding** (amended 2026-09-29, #742): what an MFA transaction is bound to — `binding: { kind: "session", id }`, the express session id, alone today (D8's amendment). Not the **first binding** above, which enrolls a factor, nor a factor record's `binding` (`"email_proof"` or `"password"`, D24), which says what authorized that enrollment.
- **Step-up**: adding a second factor to an existing, live session without repeating the primary.
- **Re-authentication**: a new session — primary and second factor again — as `max_age` and `prompt=login` ask.
- **Baseline**: the deployment's own requirement (`mfa.mode`), as opposed to one a relying party asks for with `acr_values`.
- **Recent MFA**: a second factor verified in this session within `mfa.manage.maxAgeSeconds`. *(2026-09-30: for a subject with no counting factor, a primary that recent instead — D16's alternative; its one reading is the design vocabulary's row "Recent MFA", `isRecentMfa`.)*
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

**Amended 2026-09-28 (session admission): the rows above that name the coordinator slot are superseded.** In the table: `packages/core/src/mfa/` no longer holds "the `MfaCoordinator` slot type and `MFA_ABSENCE_POLICY`", and the requirement rule's merge moves to `packages/core/src/session-admission/` (`acr.mts`, `admit.mts`) while its baseline moves to `packages/mfa`; `packages/mfa` "fills `mfaCoordinator`" reads "contributes `sessionRequirements.mfa`", the coordinator being its internal; `packages/session`'s "the login route consults `mfaCoordinator`" reads "the login route calls `admitPrimary` and establishes with the `Establishment` it returns", and `packages/oauth`, `packages/device-grant` and `packages/federation-grants` are "gated through `admitSession`" rather than "through core's rule"; `packages/webauthn` also gains `webauthnSessionSubjectModule`. The paragraph "Why the coordinator is a slot and not an import" keeps its reasoning — neither `session` nor `oauth` may import an optional feature — but the port they reach is admission, and the extension is a contribution, not a slot (the session-admission ADR's D1, D3, D6). The package split itself stands.

**Amended 2026-09-30 (#733): the requirement declares the second-factor authority; core knows no requirement by name.** The MFA package's requirement declares, in its contract, that it is the second-factor authority (`secondFactorAuthority: true`; the session-admission ADR's D3 and D7, as amended). Core enforces on whichever registered requirement declares it, whatever its name, what it enforced on the name `mfa`, and at most one may declare it. `MFA_REQUIREMENT_NAME` leaves core; the name `mfa` is the package's own.

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

**Amended 2026-09-28 (session admission): the dependency rows that consult the coordinator or the rule directly are superseded.** Wherever the table above says a package consults `mfaCoordinator` or core's requirement rule — `session`, `oauth`, `device-grant`, `federation-grants` — it reads: the package lists `sessionRequirementResolver` in its `requires` and calls `admitSession` / `admitPrimary`; it never names MFA. The MFA package's row gains one arrow — it contributes `sessionRequirements.mfa` to core's kind — and loses "fills `mfaCoordinator`". Every direction the table checks against the repository's rules still holds: core imports no sibling, `session` and `oauth` import neither each other nor MFA, and MFA imports `session` for `establishSession` and its helpers (the session-admission ADR's D1, D3, D6, §7).

**Amended 2026-09-29 (module review): the edges inside core, as built.** The "Inside core" paragraph above was written before the ports, and the session-admission amendment left it as it was. As built (steps 3–6 and the session-admission ADR's A2), `mfa/` imports `adapters/` (the factory, and the expiry checks), `logging/`, `single-use/` (the memory transaction store's cap and sweep), `security/` (a constant-time comparison) and `modules/manifest/` (the memory stores' modules); and from `session-admission/` one value, `primary.mts`'s `checkPrimaryContinuation`, which `MfaTransactionStore.create` holds a login's continuation to, beside the `PrimaryContinuation` type. It imports nothing from `user-sessions/`, `sealing/` or `grants/`: the MFA package seals a factor's data before it reaches a store, and takes the envelope, the ring rule and the `amr` values from core's barrel. Nor does `user-sessions/` take the `MfaTransactionStore` type yet: the credential-change cascade that needs it — `revokeAllForSubject` clearing the subject's lock (D21) — is step 10's obligation. `sealing/` and `mail/` are leaves, as planned, which `importBoundaries.drift.test.mts` holds; `mfa/` → `session-admission/` is a value import one way, and `user-sessions/` → `session-admission/` is type-only, as `packages/core/src/README.md` records.

**Amended 2026-09-30 (#733): the requirement's name no longer crosses the edge.** The MFA package no longer takes its requirement's name from core; it declares the second-factor authority in the requirement contract core owns. Every direction above holds.

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

**Amended 2026-09-28 (session admission): the `MfaCoordinator` row above is superseded.** The name no longer survives as a `ComponentMap` slot with `MFA_ABSENCE_POLICY`: `mfa/coordinator.mts` leaves core (its `PrimaryAuthentication` moves to `session-admission/`), and "the coordinator" is an internal of `packages/mfa` behind the `mfa` requirement it contributes (the session-admission ADR's D6). The other three surviving names stand.

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

*(amended 2026-09-30, #810: a send carries meaning and the sender renders it; the recipient rule and `@o3co/auth-provider-standard` — see the amendment above)* The port is in core because its implementer (`smtp`) and its consumer (`mfa`) must not depend on each other. The MFA package renders messages from configurable text (`mfa.factors.email.subject` / `body`, with `{code}` and `{minutes}`; the notices likewise), so a deployment that delivers through its own mail service implements `send` and nothing else. `@o3co/auth-provider-smtp` depends on core and `nodemailer` (caret range: a transport, not a verifier). Its rules follow `foundation`'s: STARTTLS or implicit TLS, plaintext only to a loopback host; credentials from the environment; errors thrown as a `MailTransportError` with a reason (`unreachable`, `auth_failed`, `rejected`, `timeout`) and never the server's reply text. No readiness probe: an SMTP outage should not take the provider out of rotation when most users have another factor.

The root README's "Does not own: signup, account recovery and email" gains "…except the one-time codes and security notices MFA sends".

Rejected: SMTP on a subpath of `packages/mfa` with an optional peer (it ties a mail library's cadence to MFA's); delivery through a new Store URL (possible through a deployment's own `MailSender`, but the owner chose SMTP).

### D6 — The provider serves JSON; the pages are the deployment's

As for login and consent, the provider owns `/session/mfa/*` (JSON) and redirects to `endpoints.mfa.url` (default `/mfa`) when `/authorize` needs a step-up. The login page continues from the login response without a redirect (F1). The self-service screen is the deployment's account page. The QR code is rendered by the page from the `otpauth://` URI. The page contract is documented in the MFA package README with a worked example, and requires: same origin as the provider (the session cookie is `__Host-`); navigation back to `redirect_to` only when it is on the provider's origin; code inputs with `autocomplete="one-time-code"` and `inputmode="numeric"`, and long codes accepted pasted with or without hyphens; `frame-ancestors 'none'`; and a lock answer (`429 mfa_locked`) shown with the factors that still work (D21).

Amended 2026-09-30 (#803): the MFA page's URL is `mfa.page.url`, the MFA module's key.

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

**Amended 2026-09-28 (session admission): F1's steps 1, 2 and 5(h) are superseded.** Step 1's "`mfaCoordinator.decideAfterPrimary` reads the subject's factors and the witness" reads: the login route calls `admitPrimary` (the session-admission ADR's D5), and the `mfa` requirement's `admitPrimary` does that reading. Step 2's record is the continuation: the route regenerates, `open(req.sessionID)` writes the `MfaTransaction` with `continuation` — the primary as the route built it and what earlier requirements added — in place of `primary` and `user` (D8's amendment), and answers the closed body of D5 (`transaction`, `expires_in`, `hints.enrollable`, `hints.email_proof`; the F3 amendment below). Step 5(h) reads: `resumePrimary(deps, continuation, { requirement: "mfa", adds: { amr per D14, mfaAt: now } })`, then `establishSession` with the `Establishment` it returns — or, when another requirement interrupts, that requirement's answer. Core refuses an `mfa` completion that is not a verified second factor: one without a factor's own value, without `mfa` beside a factor that adds it (every factor but the email code, O7), or without `mfaAt` (that record's D5). Steps 3, 4 and 5(a)–(g), and the paragraph after the table, stand. The same reading applies to F3's steps 1 and 4.

### F2 — `/authorize` with `acr_values` / `max_age` / `prompt=login` → step-up → back

`/authorize` makes one decision per request, over one ask record that accumulates what has been asked (D17).

| # | Request | What happens | State |
| --- | --- | --- | --- |
| 1 | `GET /oauth/authorize?…&acr_values=urn:o3co:acr:mfa` | The live `UserSession` is read. D17 decides: freshness first, then methods. **Met** → continue. **A step-up can meet it** → `prompt=none` answers `interaction_required`; otherwise the ask is written (or updated) with `mfaAskedAt` and the browser goes to `endpoints.mfa.url?redirect_to=<this request, with reauth_ask=<id>>&acr_values=<the values a step-up can meet>` *(amended 2026-09-28: `admitSession` reads and decides; the ask's `stepUpAskedAt.mfa`; the page is `Admission.step_up.page` — the D17 amendment)*. **Nothing can** → `unmet_authentication_requirements`. | Reads the `UserSession`; writes the ask. |
| 2 | The page: `POST /session/mfa/step-up {acr_values}` | Checks the session is authenticated and its `UserSession` live; opens a step-up transaction bound to the session id **and** the `sid`. The factors offered are those whose `amr` would meet one hinted value; none → `no_qualifying_factor`, and the page goes straight back. | Reads the `UserSession` and the factor store; writes the transaction. |
| 3 | challenge / verify | As F1 steps 4–5, except the finish: `recordSecondFactor(sid, {amr, at: now})`; **regenerate** the express session keeping `isAuthenticated`, `user`, `sid` (D27). | `UserSession.amr` (union), `authentication.mfaAt`; the express session id. |
| 4 | The page navigates to `redirect_to` | D17 decides again with the ask. Met → consent if needed (the ask travels through it), policy, a code carrying the chosen `acr`; the ask is consumed on that pass. Not met by the session that was sent → `unmet_authentication_requirements` (`acr_values`) or `login_required` (the baseline). | The ask; the code record carries `acr`. |
| 5 | `POST /oauth/token` | id_token `amr` from the `UserSession`, `acr` from the code, `auth_time` = `UserSession.authTime` (D18). | — |

Branches. **No factor record, fresh primary** (`authTime` within `mfa.enrollment.maxPrimaryAgeSeconds`): the step-up transaction carries a first binding (F3, D24). **No factor, stale primary**: D17 asks for a re-authentication, which reaches F3 at the login — a factor is never bound to a session hours old. **A `UserSessionStore` without the step-up capability** (D9): D17 asks for a re-authentication instead; boot has warned once.

**Amended 2026-10-01 (build-order step 9, owner decision): the first-binding branch.** A step-up does not carry a first binding under `required`: there a password session without a second factor whose subject may hold no counting factor is sent to log in again, and the login's forced first binding (F3) binds its factor and records `mfaAt` — so a session live when `optional` was switched to `required` is asked to log in again at its next action. Under `optional`, and for a federated session, a first binding in a session goes through D24's gate, whose account-email proof the step-up gives (D24's amendment); its fresh primary is `authTime` within `mfa.manage.maxAgeSeconds`, the one window. `mfa.enrollment.maxPrimaryAgeSeconds` is not added (D19's amendment).

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

**Amended 2026-09-28 (session admission): the interruption's body.** F1's step 2 and F3's step 1 answer the closed body every requirement's interruption shares (the session-admission ADR's D5): `{ "error": "mfa_required" | "mfa_enrollment_required", "transaction": "<id>", "expires_in": 600, "hints": { "enrollable": [...], "email_proof": true|false } }` — `mfa_transaction` is `transaction`, and `enrollable` and `email_proof` move under `hints`. The `MFA-Transaction` header and every `/session/mfa/*` route are unchanged.

### F4 — Self-service enrollment and removal

1. The account page calls `GET /session/mfa/factors`.
2. **To add a factor when the user already has a counting factor**: `POST /session/mfa/enrollment {kind}` requires recent MFA — `authentication.mfaAt` within `mfa.manage.maxAgeSeconds` (300), else `403 {"error":"mfa_step_up_required"}` *(amended 2026-09-28: `403 {"error":"step_up_required","requirement":"mfa"}`, the one step-up code — the D16 amendment)*, and the page runs F2 steps 2–3 without a `redirect_to` and retries. An enrollment transaction (purpose `enroll`, bound to session id and `sid`) is opened; F3 steps 3–4 follow, the new factor recorded with `binding: "mfa"`, the session unchanged.
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

The factor's address is the one enrolled: the account's `email` from the Store at enrollment time, proven by a code, and kept (sealed) in the factor record — never an address typed at challenge time. *(amended 2026-09-30, #810: the factor keeps a keyed digest of that address, not the address; a code goes to the Store's current address only when it matches, and a mismatch refuses the factor until re-enrollment. Row 1 has no send limits. See the amendment above.)* A later change of the Store's address does not redirect codes; the user re-enrolls. The `account-email` proof uses the Store's current address. An account without an address is not offered the kind, and cannot give a proof.

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

**Amended 2026-10-01 (#857): the shared RP ID is not cosmetic.** "Fails there as an unknown credential — cosmetic" does not hold. The grant and the factor share the RP ID, so an authenticator presents a second factor's credential to the passwordless grant, and a `none` attestation made from that credential's id and public key registers it in the grant's store as another account's passkey. The grant found that record by the id and verified the assertion against the copied key: the factor's owner was signed in as that account. The grant now refuses an assertion whose user handle is not its record owner's (WebAuthn L3 §7.2 step 6), and a second factor's handle — the subject's 32 random bytes — is not. An assertion carrying no user handle is not refused on that ground, and the grant's registration does not see the factor store's credential ids (D7: sealed, and kept by subject). So a non-resident second-factor key registered by another account could still answer a ceremony listing it, which the grant's `authentication/options` writes only under `webauthn.allowCredentialsForKnownUser`: `webauthnMfaFactorModule`, installed while that flag is on, refuses the boot (owner, provisional).

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

**Amended 2026-09-27 (build-order step 3): what the contract hands a factor.** D11's keyed digests — an email code over (transaction id, factor id, code), a recovery code over the normalised code, each kept with its key id — need the transaction id and the ring, and a factor holds neither. Every context therefore carries `transactionId` and `digests`: `digest(parts)` answers `{keyId, digest}` (HMAC-SHA-256 under the current key, the parts length-prefixed, bound to the factor's kind) and `matchesDigest(parts, stored)` compares in constant time under the key `stored` names, answering `"match"`, `"mismatch"` or `"key_unavailable"` — the last when that key has left the ring, which the factor answers as an outage (the coordinator's `503` and `mfa_factor_unreadable`), never as a wrong code. The ring stays with the coordinator. Every call runs under a transaction: one outside a login or step-up — self-service enrollment, regenerating recovery codes (F4) — runs under an `enroll` transaction the coordinator opens for it. The contract also gains: `sign_count_regression` among a verification's refusals (F7, D28); `reusableChallenge`, by which a factor opts in to a challenge that stays across attempts (an email code, F5) — absent, a verification takes it (WebAuthn), so a factor that forgets the flag fails closed; and an optional `enrollable(user)`, so a kind a user cannot enroll (email without an address) is not offered and no throw is read as an outage.

**Amended 2026-09-28 (session admission): `MfaFactor.amrValues`.** The port gains a static `amrValues: readonly string[]` beside the data-dependent `amrFor(data)` — every value `amrFor` can answer for that kind (`hwk` and `swk` for WebAuthn, `otp` for TOTP, `email`, `recovery`), non-empty, no primary's marker, never `mfa` (that is `addsMfa`'s) — and a factor-type test holds `amrFor`'s answers to it. D8's `secondFactorMethods` ("every value an enabled factor's `amrFor` can answer") is that union, which nothing could compute from records; and it is what core compares the `mfa` requirement's `reach` against (the session-admission ADR's D7). Added in that record's A2.

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

**Amended 2026-09-30 (build-order step 19, first part): the Store is trusted with the factors it keeps.** A Store that keeps the MFA factors is responsible for their integrity and freshness: it never rolls a factor back, hides one from a list, answers one it acknowledged removing, or lets two updates at one version both succeed; a version never goes back, and an acknowledged write is never lost across a restore or a failover. The provider does not check it. The runbook says what breaking it opens and what a failover or a restore requires, beside O6's advice.

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
	/** An exempt success: ends a run shorter than `policy.hardLimit`; at or past it the run stands (D21's amendment of 2026-10-01). */
	noteExemptSuccess(subject: string, nowMs: number, policy: LockoutPolicy): Promise<void>;
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

**Amended 2026-09-27 (build-order step 3).** `MfaTransactionStore` also keeps D25's email-proof requirement, apart from the lock state (see D25's amendment), and `noteExemptSuccess` takes the presented browser so a trusted one is renewed rather than added (D21's amendment). A patch clears `challenge`, `pendingEnrollment` or `lastSentAtMs` with `null`; a key present with `undefined` is absent, so no patch clears a limit by omission; a value a field does not admit is a `RangeError`, and keys outside the patch are ignored (`mfaTransactionPatchWrites`, which every adapter calls first). `create` refuses a transaction whose `attempts` is not `0`, whose `version` or `sends` is not a safe non-negative integer, or whose fields its type does not admit, and keeps only the fields a transaction has (`newMfaTransactionRecord`). `update` refuses a transition that would refund a limit or undo a requirement — `sends` going down, `lastSentAtMs` moving back (clearing it after a failed delivery is allowed: the retry still costs a send), a required email proof becoming anything but met, a met one undone, `enrollment` lowered (`checkMfaTransactionTransitions`); sub-objects keep only their known fields. The coordinator bounds the transactions one session holds: the store's bound is its expiry, and for the in-process adapter a global cap.

**Amended 2026-09-28 (session admission): the coordinator is no longer a slot.** `mfaCoordinator` and `MFA_ABSENCE_POLICY` leave core (they were declared at step 3 and consulted by nobody). The MFA package contributes one `SessionRequirement` named `mfa` under the `sessionRequirements` kind (the session-admission ADR's D3, D6): its `reach` is the coordinator's `secondFactorMethods`; its `admit` is the baseline of D16 under `mfa.mode`; its `admitPrimary` is `decideAfterPrimary` and `openLoginTransaction` behind one `Interruption`, which the login route opens after regenerating the express session — the two-phase shape above, kept. `PrimaryAuthentication` moves to `session-admission/` and carries `recorded: RecordedAuthentication` (#707) in place of `method` and `amr`. `session` and `oauth` read no coordinator: they call `admitSession` / `admitPrimary` and see a requirement only as a verdict. F1's step 5(h) and F3's step 4 — the MFA package finishing a login with `establishSession` — go through `resumePrimary(deps, continuation, { requirement: "mfa", adds })` first, presenting the continuation the login transaction persisted at step 2, and establish only on its `establish`, so every other requirement not yet done in that login is asked too — the `mfa` requirement, done, is not asked again (that record's D5). **`MfaTransaction` changes shape** for that: its `primary` and `user` fields are replaced by `continuation: PrimaryContinuation | undefined` (a login transaction carries one; a step-up or enrollment transaction does not), which `newMfaTransactionRecord` validates and the memory adapter's field rules follow — done in that record's A2, before the Redis adapter (step 6) is written, so no adapter is written against the old shape. The store's operations and the rest of the record are unchanged.

**Amended 2026-09-29 (#742): a typed binding in place of `sessionId`.** `MfaTransaction.sessionId: string` becomes `binding: MfaTransactionBinding`, a union discriminated by `kind` — `{ kind: "session"; id: string }`, the express session id, alone today — so that a later transport without a browser (the IETF draft "OAuth 2.0 for First-Party Applications", say) adds its own kinds, a key or a client, without breaking every custom `MfaTransactionStore`: below the HTTP routes the factor contract, `MfaFactorStore` and `MfaTransactionStore` are independent of the transport, and the binding was the one exception. A store keeps the binding whole, as data, reading neither its kind nor its id; `newMfaTransactionRecord` refuses a binding of a kind it does not know or with an empty id, and copies it to its known fields. Every use compares the whole binding, kind included: `isMfaTransactionBoundTo` is the one comparison (the ids in constant time), and `getBoundMfaTransaction` the read every use starts with, which answers a transaction bound to anything else as an unknown id. The login opens its transaction bound to `{ kind: "session", id }` of the regenerated session. The bound read is necessary, not sufficient: a `step_up` or `enroll` transaction also carries the `sid` of the `UserSession` it upgrades, which the route compares with the session's `sid`, outside the binding (F2 step 2). And it comes first: after it a route calls only operations that carry the version it read, and `reserveAttempt` — which carries none, and deletes the transaction past `max` — only once the read held, or anyone holding a transaction id could destroy the ceremony. The ids are compared in constant time for ids of one length; the session kind's length is public (32 characters, in the cookie), and a later kind with variable, secret-length ids compares digests. D27's rule — every transaction bound to the express session id, every use comparing it — is the `session` kind's, unchanged. The contract suite holds each store to keeping the binding whole, and a transaction bound to one session is not readable through a binding of another kind or id. No migration: no Redis store holds deployed data, and the port is unreleased. The `sessionId` field in the code above reads as this binding.

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
- **Rotation**: add the new key last, then move it first. Factors do not expire, so a retired key stays until nothing is sealed under it and no stored digest names it (recovery-code digests live inside sealed data but name their own key; count both); every TOTP or WebAuthn use re-seals under the current key; dormant factors do not migrate. The runbook has the procedure; the coordinator logs `mfa_factor_sealed_with_retired_key` (info, once per key id per process).
- **A factor that does not open** is never "no factor": it counts for F3's rule, its verification is `503` with one `mfa_factor_unreadable` error line, and the user uses another factor or a recovery code.
- **No plaintext mode**, and **a development sample key**: the template's `config/development.conf` carries a published sample key; the MFA schema refuses that exact key when the environment the configuration was selected by is `production` or `staging`, or `deployment.mode = "multi"` (#473's rule).

**Amended 2026-09-27 (build-order step 3).** A factor asks for these digests through its context's `digests` (`digest`, `matchesDigest`); the coordinator makes them under the ring and binds them to the factor's kind, so no factor holds a key (D7's amendment).

### D12 — Losing the factor store must not downgrade every account

"Only zero records open a first binding" (F3) is only as strong as the store that holds the records. A Redis without persistence restarting, an eviction, a `FLUSHALL`, a Store restored from an old backup — each empties the list, and every affected account then accepts a first binding from whoever holds its password.

- **Durability requirements.** The runbook requires, for the Redis factor store: a `maxmemory-policy` that cannot evict its keys (`noeviction`, or a `volatile-*` policy — factor keys carry no TTL); AOF persistence (`appendfsync everysec`); preferably a dedicated database or instance. At boot the Redis module reads `CONFIG GET maxmemory-policy` and `INFO persistence` where the server allows: an `allkeys-*` policy is refused (`mfa-factor-store-evictable`); RDB snapshots without AOF are a warning (`mfa_factor_store_lossy`: the last snapshot interval of enrollments is lost on a crash); no persistence at all is a warning (`mfa_factor_store_volatile`); a server that refuses `CONFIG` is one warning that the check could not run.
- **An enrollment witness outside the factor store.** The core port (§8, PR 3): `User.mfaEnrolled` (a boolean the Store answers on `authenticate`, through `User`'s index signature), and an optional `UserRepository` capability, `markMfaEnrolled(subject, enrolled): Promise<void>`, with a guard. foundation implements it as `markMfaEnrolledUrl` (`POST {subject, enrolled}`); a Store-backed factor store may maintain the field itself instead.
  - **Writes**: create-then-mark — the first counting factor is written, then the witness set; a removal of the last counting factor, then the witness cleared; the operator reset clears it last. A crash between the two leaves a factor without a witness, never a witness without a cause.
  - **Reconciliation**: every successful verification whose `User` snapshot lacks `mfaEnrolled: true` while a counting factor exists marks it again, so a failed mark heals at the next login.
  - **Reads**: at login, from the fresh `authenticate` answer; for a step-up or a self-service first binding, from the session's `user` snapshot (the login's `User`, at most `session.maxAge` old — a flag that only ever blocks a first binding, never admits one).
  - **Effect**: witness `true` with zero factor records is `503 temporarily_unavailable`, one `mfa_enrollment_state_inconsistent` error line and an audit event — never a first binding. *(Amended 2026-09-29, module review: at login the read is the `mfa` requirement's, in `admitPrimary`, and the one error line is admission's. With zero records and a witness `true`, or a malformed witness, the requirement emits the audit event `mfa.enrollment_state_inconsistent` (D28) and throws, with a cause that names the inconsistency (`mfa_enrollment_state_inconsistent`); admission logs its one `session_admission_unavailable` line, with `store: "mfa"`, whose `loggableError` projection carries that cause, and the login is `503`. So the effect's one error line holds, and it is admission's.)*
  - A repository without the capability and a Store that answers no field leave the witness absent; the durability requirements are then the whole defence.
- **Recovering from a lost factor store** (runbook): the mass `503` is the design refusing to downgrade. Restore the factor store from its AOF or a backup; if that is impossible, reset the affected subjects (`resetMfaForSubject` with `requireEmailProof: true`, D25), in bulk from the Store's list of users marked enrolled, and tell them they will re-enroll.
- Rejected: **a marker in the same Redis** (lost with the records); **refusing a first binding for any subject seen before** (the provider keeps no subject list).

**Amended 2026-09-27 (build-order step 3).** The durability requirements extend to the transaction store's key family that holds D25's email-proof requirement: a lost requirement lets a password holder bind without the proof. PR 6's `redisMfaTransactionStoreModule` therefore runs the same boot check as the factor store — it refuses an `allkeys-*` eviction policy and warns when there is no persistence — or the runbook requires the same of it; the in-process transaction store says in its replica-safety reason that a restart loses the requirement. The witness is read only through `readMfaEnrollmentWitness`: `true` enrolled, `false` or absent not enrolled, anything else (`null` included) malformed — `503`, never a first binding; a drift guard holds every package to it.

**Amended 2026-09-29 (build-order step 6): what the Redis stores settled that D7, D8 and D12 did not say.** Every subject, factor id and transaction id is written inside its key's hash tag as base64url of its JSON (`mfaf:{<subject>}`, `mfat:tx:{<id>}`, `mfat:lock:`, `mfat:week:` and `mfat:proof:{<subject>}`), as the federation grant store spells its ids, so no brace a value carries moves the tag and two values that differ only in a lone surrogate never share a key; a prefix with a brace is refused. A factor is one field holding three lines, `<version>\n<fixed JSON>\n<mutable JSON>`, which is what lets D7's compare-and-set compare the version as text and carry the fixed part over byte for byte without decoding any JSON. A transaction's `update` compares, beside the version, a random `incarnation` its `create` wrote, so a transaction consumed and created again under the same id at the same version is never written with a patch that was checked against the one before it. The boot check reads each part on its own: the policy from `INFO memory` — `CONFIG GET maxmemory-policy` only as a fallback — so managed servers that block `CONFIG` are still held to the refusal; AOF from `INFO persistence`; and `CONFIG GET save` only when AOF is off, because `INFO persistence` does not say whether RDB snapshots are configured. The policy is judged by an allow-list: `noeviction` passes, the three `allkeys-*` refuse whatever else could not be read, the four `volatile-*` are each store's to judge, and any other policy is one the check cannot judge. A part refused by a reply that refuses the question (`NOPERM`, an unknown or renamed command, a disabled one) or answered without its value, and a policy the check cannot judge, are named in the warning that the check could not run; any other reply error, and a server that cannot be reached, fails the boot. The names: the refusal is a `RedisMfaStoreEvictableError` (`reason` `mfa-factor-store-evictable` or `mfa-transaction-store-evictable`, with the policy), the `cause` of a `provides-factory-failed` BootError; the warnings are `mfa_factor_store_lossy`, `mfa_factor_store_volatile`, `mfa_factor_store_durability_unchecked` and their `mfa_transaction_store_…` counterparts; and the transaction store also warns on a `volatile-*` policy (`mfa_transaction_store_lock_evictable`), because its subject lock and weekly window carry a TTL once no run is counted and an evicted one lifts a D21 hold early — `noeviction` is what the MFA key families are meant to run on, while the factor store, whose keys carry no TTL, accepts `volatile-*` silently. A transaction's key expires on the server's clock, but the store also answers one at or past its `expiresAtMs` on its own clock as absent, so a server running behind cannot let a ceremony complete past its deadline.

**Amended 2026-09-29 (retro review of step 6): the version's bound, the store's clock in every operation, and what a factor record holds.** Both ports now refuse an `update` at `Number.MAX_SAFE_INTEGER` with a `RangeError`, whatever the stored version, before anything is read or written: its next version would be no safe integer — the in-process stores kept 2^53, a version that no longer moves, and the Redis ones wrote a value their own read refuses. `checkMfaVersionAdvances` (core, `mfa/version.mts`) is the rule, and every adapter calls it — a fourth helper beside the three of the step-3 amendment (`mfaTransactionPatchWrites`, `newMfaTransactionRecord`, `checkMfaTransactionTransitions`) for the transaction store, and the one helper of the factor store's `update`. The store-clock expiry above covers every operation, `reserveAttempt` and `takeChallenge` included: an expired transaction spends no attempt and gives up no challenge, whatever the server's clock says. On Redis both are one script each, so the store's clock is handed to the script, and the deadline is read from a hash field of its own that `create` writes (`expiresAtMs`, as the text `String` gives, which `tonumber` reads back as the same double) — never by decoding the record, which `cjson` reads more narrowly than `JSON.parse` (a lone-surrogate escape, nesting past a thousand levels) and would answer gone for its whole life; a missing or non-finite deadline is answered absent, as a read answers a record without one. A factor's compare-and-set matches all three lines of the value, to its end, so a value with a fourth is answered `null` rather than cut to three; and a factor's `createdAt` and `lastUsedAt` are whole instants within the Date range (±8.64e15 ms, core's `isStorableExpiry`), refused on write with a `RangeError` and on read as a record the adapter cannot read.

**Amended 2026-09-30 (build-order step 9, owner decision): where the witness is recorded for a session.** The witness is recorded on the session at login — password and federated alike, with what the account's address is: none, one the provider reads, or one it cannot (`UserSession.enrollmentFacts`, which core's primary builders derive from the login's `User`, copied as plain data) — and the `mfa` requirement reads it there wherever a subject with no counting factor would be let through, the `credential_change` rule included, besides the login's own read of the fresh `User`. This replaces every read from the session's `user` snapshot in this record: D12's reads above, build-order row 9's, and those of the 2026-09-29 amendment that moves the witness reads to step 9, step 11's step-up included. It is compared against counting records, so `true` beside recovery codes alone is the same inconsistency. A session that recorded nothing is sent to log in.

**Amended 2026-10-01 (build-order step 19b, owner decision): the Store answers `mfaEnrolled` on `authenticateByToken` as on `authenticate`,** since a federated session records the witness from that `User` (step 9's amendment); a Store that answers it on `authenticate` alone leaves federated sessions without D12's defence. The test kit's witness suite holds a Store to both.

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

**Amended 2026-09-30 (build-order step 18; owner, provisional): device-bound is BE = 0.** The table's "device-bound (backup-state flag clear)" reads: not backup-eligible (the BE flag clear). `hwk` only when BE = 0; `swk` when BE = 1, whatever the backup state (BS), which is only the credential's current backup state — a multi-device credential not yet synced is `swk`. The factor keeps `backupEligible` from registration in its sealed data (F7's list gains it) and refuses as `invalid` an assertion reporting another BE (WebAuthn L3 §6.1.3, §7.2), not audited as a clone. With attestation `none`, BE and BS are what the authenticator reports about itself: `hwk` means *reported* device-bound, not proof of hardware; attested hardware stays `phrh` with attestation (Options).

### D15 — The `acr` scheme, discovery, and the `claims` parameter

- **The table stays the only source** of what `/authorize` vouches for. It gains **alternatives**: an entry is either a list (every value required) or a list of lists (any one list satisfied), so "any WebAuthn assertion" is `"urn:o3co:acr:phr" = [["hwk"], ["swk"]]`.
- **The template ships one entry**, `"urn:o3co:acr:mfa" = ["mfa"]`, with `phr` commented out; `create-app --no-mfa` comments the `mfa` entry out too. Core's reference stays `{}`.
- **An entry nothing installed can satisfy is dropped**: excluded from `acr_values_supported`, answered `unmet_authentication_requirements`. It is warned once at boot (`acr_value_unsatisfiable`) — except under `mfa.mode = "off"`, where an entry unmet only for want of a second factor is an `info` line, so an MFA-off deployment is not warned on every boot. Producible values: `pwd` and `fed`, the installed factors' values, `mfa` (with a coordinator), and — only for a federation that trusts its upstream — anything.
- **`acr` is stamped only when requested.** An unrequested `acr` is a claim no RP validates.
- **`acr_values` is treated as mandatory**: this provider answers `unmet_authentication_requirements` rather than a token that does not meet it.
- **Preference order.** Among the requested values, one the session already meets wins over stepping up to an earlier-listed one. An RP that will accept only `phr` asks only for `phr`.
- **The `claims` parameter**: a request whose `claims` names `acr` — essential or not, in `id_token` or `userinfo` — is refused with `invalid_request` ("request acr through acr_values"), by #284's rule. Every other use of `claims` stays ignored, and discovery keeps `claims_parameter_supported` absent.
- The names are decided in O9.

**Amended 2026-09-28 (session admission): D15's drop and its severity.** Where D15 says an entry is producible "with a coordinator" and the boot line's severity depends on `mfa.mode`, it reads: an entry is producible when `pwd`, `fed` (a federation installed), a trusted federation's anything, or the union of the registered requirements' `reach` covers one of its alternatives — `mfa` among them when the `mfa` requirement's reach carries it — and a dropped entry is logged `info` when one alternative lacks only second-factor values and no registered requirement reaches them, `warn` otherwise, whatever `mfa.mode` says (the session-admission ADR's D6). The table, `acr_values_supported`, the `claims` refusal and the `phr` / `phrh` examples stand.

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

**Amended 2026-09-28 (session admission): the rule is split, and the table above is superseded.** `decideMfaRequirement` (step 4) is taken apart: its merge — "both halves must be met; one step-up for both; unmet before re-authentication when no requested value is in the table" — becomes the admission's own step (the session-admission ADR's D2, step 7), applied for every consumer and every requirement; its baseline becomes the `mfa` requirement's `admit`, in the MFA package. `selectAcr`, `readAcrTable`, `producibleAmr` and `vouchableAcrTable` stay in core as the provider's `acr` vocabulary, `producibleAmr` taking the union of every requirement's `reach` where it took `secondFactorMethods`. The consumer table above is replaced by that record's D8: each consumer calls `admitSession` with its own slots and a claim core built — once, or twice where it re-checks before a write — names its graded action (D4) and maps the `Admission` to its protocol's answer — the answers listed here (`invalid_grant` with `step_up` on the token endpoint, `403` on device approval, the trips at `/authorize`) stand, except that every `403` step-up — device approval, F4's management routes, step 12 — carries the one code `step_up_required` with `requirement` in a field, not `mfa_step_up_required`; device verification admits `lookup`, `approve` and `deny` as three actions and is stepped up on `approve` alone. "Conditional requirements are boot checks" is withdrawn: the MFA package's module `requires: ["userSessionStore"]`, and a composition without one is refused at the requires-closure; `oauthModule` keeps no MFA-conditional refusal. Recent MFA is the requirement's rule for the `credential_change` grade (`mfa.manage`, `session.link`, `webauthn.register`), and the `authenticatedSubject` helper is `webauthnSessionSubjectModule` in `packages/webauthn`, a module the deployment installs in place of writing the bridge. The liveness read itself — no `sid`, a gone session, a `sub` that does not match the cookie, the subject-revocation boundary, a store outage — is admission's, in that order, for every consumer.

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

**Amended 2026-09-28 (session admission): the ask is per requirement, and the decision reads the admission.** "D16's rule" in step 3 reads "the admission" (the session-admission ADR's D2), applied after step 2's freshness on the session the verdict carries; `mfaAskedAt` becomes `stepUpAskedAt`, keyed by the requirement's name, so that with two requirements that step up, the second one's trip is not refused as "already sent"; the page the browser is sent to is `Admission.step_up.page`, so `/authorize` no longer reads `endpoints.mfa.url`. So the `AuthorizeAsk` shape above and the algorithm's step 3 are superseded where they write `mfaAskedAt` and redirect to `endpoints.mfa.url?…`; the table's **outcome** rows — what each request and session combination is answered — stand.

### D18 — `auth_time`, and RFC 9470 alignment

- `auth_time` on the id_token stays `UserSession.authTime`: the **primary**, the conservative reading for an RP applying `max_age`.
- For RFC 9470 resource servers — `auth.policy-verifier` among them — the access token gains `auth_time` beside its `acr` and `amr` (the refresh token carries it forward), and introspection answers `acr`, `amr` and `auth_time`. Additive, a PR of its own that can be dropped (§8, PR 15).

---

## 5. Configuration and defaults

### D19 — Keys and switches

Core's reference and schema hold what core's consumers read with the MFA package absent; the MFA and SMTP packages ship their own `reference.conf`, layered by the composition root.

| Key | Env | Default | Meaning |
| --- | --- | --- | --- |
| `mfa.mode` (core) | `MFA_MODE` | core: `"off"` until the flip, then **no default** (O2) *(superseded 2026-09-28: core keeps `"off"` after the flip too — the session-admission ADR's D7 and O2's amendment)*; template and create-app: `"off"` until the flip, then `"required"` | `required`: every password login has a second factor and every consumer in D16 enforces it. `optional`: users with factors are challenged; nobody is forced; step-up works. `off`: no MFA; the package need not be installed. |
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

**Amended 2026-09-27 (build-order step 3): what core's schema accepts before the MFA package exists.** Core's schema admits only `mfa.mode = "off"` until a module honours another mode — the build order's step 7 or 8, whichever comes first, widens it *(superseded 2026-09-28: the widening is the session-admission ADR's A2, before step 6, and the refusal an operator gets for `required` with nothing installed is `session-requirement-missing`; see the amendment at the end of D20)* — so an operator who writes `required` before then is refused at boot rather than left believing logins ask for a second factor. Until the flip (step 22) the schema also defaults a missing section or mode to `"off"`, as core's `reference.conf` does, so a hand-built configuration declares the coordinator's absence once a module attaches `MFA_ABSENCE_POLICY`; the flip removes both defaults (O2) *(superseded 2026-09-28: neither default is removed — core keeps `"off"`, and `sessionRequirements.expected` is the declaration; O2's amendment)*. Core also owns `mfaTransactionStore.memory.maxEntries` (default 100 000): the in-process transaction store's cap, at which it refuses a new transaction as a store fault rather than evict one in flight.

**Amended 2026-09-30 (config ownership): each module reads its own section, named after it.** The TOTP factor's settings are `mfa-totp-factor { enabled, algorithm, digits, period, window, issuer }`, the section of `mfaTotpFactorModule`, fed by `MFA_TOTP_FACTOR_ENABLED` and `MFA_TOTP_FACTOR_ISSUER`; the table's `mfa.factors.totp` row, F6's issuer and the step-8a note below read so. `mfa.factors.totp`, and `MFA_TOTP_ENABLED` / `MFA_TOTP_ISSUER`, which the package's `reference.conf` still binds there with no default, refuse the boot wherever that module is installed (`config-path-relocated`), naming the new path and its variable. The rule holds for every factor: its settings are its module's section, named after the module, not a key under `mfa`. `mfa.mode` is the MFA module's key, not core's (the table's `mfa.mode (core)` row reads so): the module's section schema holds it to the three values, and the package's `reference.conf` carries its default `off` and `MFA_MODE`; core's schema and `reference.conf` name no `mfa` section, and core exports no `readMfaMode`. The standalone template reads the key itself before it chooses its modules — raw from its own layers, where its `application.conf` binds `MFA_MODE` with no default, held to the three values, absent read as `off` — and declares `mfa` from it, until step 20 (below) removes that reading.

**Amended 2026-10-01 (build-order step 19b): `markMfaEnrolledUrl` is a key of the user repository's settings,** `repositories.user.http.markMfaEnrolledUrl` (`REPOSITORIES_USER_HTTP_MARK_MFA_ENROLLED_URL`), unset by default. Without it the repository has no `markMfaEnrolled`, and a composition with MFA on is warned at boot whatever keeps the factors. The table's `CLIENT_USER_*` reads so.

**Amended 2026-10-01 (build-order step 9, owner decision): two rows.** `mfa.enrollment.maxPrimaryAgeSeconds` is not added: every first binding in a session, and the account-email proof given there, reads `mfa.manage.maxAgeSeconds`, the one window (F2's amendment). `mfa.maxFactorsPerSubject` (10) is the MFA module's key, 2 to 100 records, with no variable.

**Why TOTP is the only counting factor on by default.** It needs nothing from the deployment. Email needs an SMTP relay and WebAuthn a relying-party id that depends on where the page is served.

**The template** (`templates/standalone`): `buildModules` installs `mfaModules` and the two stores when `mfa.mode` is not `off`, `mfaEmailFactorModule` when email is enabled, `smtpMailSenderModule` when `SMTP_HOST` is set, and `webauthnMfaFactorModule` with a `webauthnConfig` bootstrap when WebAuthn is enabled; nothing when the mode is `off`. `application.conf` repeats each `${?…}` line and ships D15's table. `.env.example` gains `MFA_ENCRYPTION_KEY` (`openssl rand -base64 32`) and `MFA_NOTICES`; `docker-compose.yml` gains a Mailpit service and points `SMTP_HOST` at it.

**create-app** gains `--no-mfa`, which writes `mode = "off"` on a marked line of the scaffold's `config/application.conf` and comments out the marked `acr` entry (the `MFA_MODE` line stays, so the environment still wins). A test scaffolds with and without it, loads the HOCON and asserts both.

### D20 — What "off" means, and what boot refuses

**Off** means: no MFA module installed; `/session/login` answers as today; `/authorize` has no baseline and answers `acr_values` needing a second factor with `unmet_authentication_requirements`; the `session` grant, device verification and the grants browser half have no MFA gate; `?link=1` and the WebAuthn bridge need no recent MFA; sessions record `mfaAt: undefined`. D13 applies whatever the mode: it is about what this provider vouches for.

"Off" is a statement: `sessionModule` and `oauthModule` declare `mfaCoordinator` optional with `MFA_ABSENCE_POLICY` (`configKey: ["mfa", "mode"]`, `absentValue: "off"`). An API-only deployment writes `mfa.mode = "off"`. `mfaModule` declares `mailSender` optional with `configKey: ["mfa", "notices"]`, `absentValue: "none"`.

| Composition | Refused by | Names |
| --- | --- | --- |
| `mfaCoordinator` unfilled and `mfa.mode` not `off` (after the flip, an unset mode too) *(superseded 2026-09-28: no such slot; `session-requirement-missing` and `session-requirements-undeclared` take its place — the amendment at the end of this section)* | core, `component-absence-undeclared` | `mfa.mode = "off"`, and what is lost |
| MFA installed, `mfa.mode` `off` or unset | `mfaModule` | "remove the module, or set `mfa.mode` to `required` or `optional`" |
| MFA installed, no `mailSender`, `mfa.notices` not `"none"` | core, `component-absence-undeclared` | `mfa.notices = "none"` or the SMTP keys |
| `required`, no counting factor enabled | `mfaModule` (`mfa-no-counting-factor`) | the `mfa.factors.*.enabled` keys |
| `requireEmailProof = "always"`, no `mailSender` | `mfaModule` | nobody could enroll |
| email enabled, no `mailSender` | `mfaEmailFactorModule` requires the slot; the planner's missing-required refusal, with a hint naming `SMTP_HOST` | **email is never silently disabled** |
| WebAuthn factor enabled, no `webauthnConfig` | `webauthnMfaFactorModule` requires the slot | `webauthn.rpId` / `rpName` / `origin` |
| key ring empty, a key not 32 bytes, a duplicate id, or the sample key where D11 refuses it | the MFA config schema | `mfa.encryptionKeys` / `MFA_ENCRYPTION_KEY` |
| `mfa.mode` not `off`, `oauthModule` or `deviceGrantModule` without `userSessionStore` *(superseded 2026-09-28: never built; the MFA module `requires: ["userSessionStore"]` instead, and the requires-closure refuses — the amendment at the end of this section)* | their factories (`mfa-requires-user-session-store`; amended: `deviceGrantModule` refuses an enabled grant without it whatever the mode, D16) | the slot |
| memory MFA stores under `deployment.mode = "multi"` | core, replica safety | the modules and what forks |
| Redis factor store on an `allkeys-*` eviction policy | `redisMfaFactorStoreModule` (D12) | the policy |
| `mfaFactorStore.adapter = "store"` without the four URLs | foundation's builder | the missing URLs |
| `mail.smtp.secure = "none"` to a host that is not loopback | smtp's schema | the host |
| an `acrValues` entry nothing installed can satisfy | dropped; warned, or `info` under `off` (D15) | the entry |
| a `UserSessionStore` without `recordSecondFactor` | warned (`mfa_step_up_unsupported`); D17 re-authenticates | the adapter kind |

**Amended 2026-09-28 (session admission): the statement is generic, and asking for MFA without installing it is refused.** D19's row for `mfa.mode` reads: core's key, as it is, admitting `off`, `optional` and `required` from the session-admission ADR's A2 (the step-3 lock to `"off"` is lifted), with the reference default `off` kept; the MFA package reads it; the template and create-app keep `MFA_MODE` as the switch that installs the MFA modules, with `off` installing nothing and the default `required` at the flip. In D20, the paragraph "Off is a statement" and `MFA_ABSENCE_POLICY` are withdrawn in favour of a generic declaration: `sessionRequirements.expected`, a list of requirement names (`[]` allowed), required wherever a consumer of admission is installed, and compared with the registrations at the end of stage 4 (that record's D3, D7). The refusal table changes in four rows: `mfaCoordinator` unfilled is gone; `mfa-requires-user-session-store` is gone — the MFA module `requires: ["userSessionStore"]` instead; `session-requirements-undeclared` — the declaration missing, or naming a requirement that is not registered *(amended 2026-09-30: a declared name nothing registers is `session-requirement-missing`; `-undeclared` is a registered requirement left out of a written declaration, or no declaration beside a consumer — the session-admission ADR's D7 note)*; and `session-requirement-missing` — `mfa.mode` not `off` while no requirement named `mfa` is registered, naming the module to install and `mfa.mode = "off"` as the alternative — the step-3 guard ("refused at boot rather than left believing logins ask for a second factor"), kept without an absence policy *(amended 2026-09-30: `session-requirement-missing` is a name in `sessionRequirements.expected` that no module registers; core's checks do not act on `mfa.mode`, and the template declares `mfa` from it, so the guard holds there — the session-admission ADR's D7 note)*. Every other row stands. What "off" *means* — no MFA module installed, `/session/login` as today, no baseline anywhere — is unchanged.

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

**Amended 2026-09-27 (build-order step 3): the lock's readings, as the port states them.** (a) Before any lock, `memorySeconds` without a failure starts the count again, as it does after a lock ends; neither ends the run the hard limit counts. (b) A guessable success ends the run up to its own reservation, and an exempt success up to its time: an attempt reserved after it, still in flight, starts the next run. (c) Each answer is judged on the time its caller passes, so callers' clocks must agree (NTP, D22); a store forgets a failure or a trust only a day (`MFA_CLOCK_SKEW_ALLOWANCE_MS`) after it stops counting, judged no later than the store's own clock, so a caller ahead by less than the allowance erases nothing another still counts, and a caller far ahead — on any subject, the in-process sweep included — erases nothing. (d) An exempt success from a browser already trusted renews that browser's trust under a fresh cookie value rather than adding one, so a user's daily WebAuthn sign-ins never push their other browsers out of the five. (e) `threshold` must not exceed `hardLimit`, and `hardLimit` must not exceed NIST's 100. (f) A password change clearing the week (`clearSubjectState`) is kept, as decided: it ends the hold the password's holder caused.

**Amended 2026-10-01 (build-order step 10, owner decision): a rebind lifts the hard limit; an exempt success does not.** `hardLimit` consecutive failures (100) hold the subject's guessable proofs until the subject rebinds: the held factor is replaced (step 12), or an operator resets the subject, applied through the authorized-recovery entry (NIST SP 800-63B-4 §3.2.2). An exempt proof still passes during the hard hold, and an exempt success still ends a run below the limit, but at or past the limit it ends nothing: `noteExemptSuccess` takes the lockout policy, and a store keeps a run at `hardLimit` through it. Until step 12, only the operator's deletion of the lock state lifts it.

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

**Amended 2026-09-30 (build-order step 9, owner decision (d)): one gate for every first binding.** A subject with no counting factor goes through one gate whatever it binds first — a factor, a passkey (`webauthn.register`), a linked identity (`session.link`) — under `mfa.enrollment.requireEmailProof` and D25's flag. At a login the proof is kept on the login's transaction; in a session it is kept for that session alone for `mfa.manage.maxAgeSeconds`, the one window for every first binding in a session, and is given through the MFA page's step-up. Without mail nothing changes.

The honest statement for a deployment without mail: MFA protects every account from the moment its owner enrolls, and does not protect an account whose password an attacker holds before then. Decided in O4.

### D25 — Recovery when a factor is lost: recovery codes, plus an operator reset

- **Recovery codes** (on by default): generated with the first counting factor, shown once, regenerated with recent MFA; exempt from the subject lock, and an exempt success (D21); each use audited and answered with the count left. A recovery code satisfies the second factor (`amr` `recovery`, plus `mfa`); under `required`, a subject with no usable counting factor left must enroll one before the session is written (F3).
- **An operator reset** for a user who lost everything: `resetMfaForSubject(subject, { requireEmailProof?, revokeSessions? })`, reached as `handle.components` like `revokeAllForSubject`. It removes every factor record, clears the subject's lock state, clears the witness last (D12), audits `mfa.factor.removed` (`by: "operator"`), and mails a notice under `mail`. `requireEmailProof: true` makes the user's next first binding require the email proof whatever `mfa.enrollment.requireEmailProof` says; `revokeSessions: true` also calls `revokeAllForSubject`. No HTTP admin surface; it never enrolls anything. The runbook requires out-of-band identity proofing before calling it: the reset is the account-takeover path if it is not.
- Rejected: **no recovery**; **email-link recovery** — it makes the mailbox a single factor that bypasses the second one; **security questions** (`kba`).

**Amended 2026-09-27 (build-order step 3): where `requireEmailProof: true` is kept.** The reset empties the factor store, the witness is a boolean, and the lock state is cleared by the reset and by every later password change, so none of them can hold the requirement until the next first binding. `MfaTransactionStore` keeps it as a flag of its own (D8): `requireEmailProofAtNextBinding(subject)` sets it, `emailProofRequiredAtNextBinding(subject)` reads it when deciding whether a first binding needs the proof, and `consumeEmailProofRequirement(subject)` clears it atomically at that binding. It has no expiry, and `clearSubjectState` leaves it.

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

1. Add `@o3co/auth-provider-mfa` (and `@o3co/auth-provider-smtp` for mail) to `package.json`. *(amended 2026-09-30, #810: `@o3co/auth-provider-standard` for mail)*
2. Port the MFA block of `buildModules` and the `mfa`, `mfaFactorStore`, `mfaTransactionStore`, `endpoints.mfa` and `oauth.authorize.acrValues` blocks of `application.conf`, with their `${?…}` lines.
3. Set `MFA_ENCRYPTION_KEY`, and `SMTP_*` or `MFA_NOTICES=none`. *(amended 2026-09-30, #810: `STANDARD_SMTP_MAIL_SENDER_*` where mail is sent; there is no `MFA_NOTICES`)*
4. Make the Redis the factor store uses durable (D12); give the Store `mfaEnrolled` and `markMfaEnrolledUrl` if it can.
5. Teach the login page `403 mfa_required` / `mfa_enrollment_required`; build the MFA page and the account page (D6).
6. Teach BFFs using the `session` grant the `step_up` member, the device-verification page `403 mfa_step_up_required`, and the `req.webauthnSubject` middleware the `authenticatedSubject` helper.
7. Decide `trustUpstreamAmr` per federation.
8. Set `mfa.mode = "optional"`; move to `required` later.

### BREAKING for integrators

1. **Boot** (after the flip): a composition with `sessionModule` or `oauthModule` must install the MFA modules or write `mfa.mode = "off"`; with MFA installed, it must wire mail or write `mfa.notices = "none"` *(amended 2026-09-30, #810: there is no `mfa.notices`)*; `oauthModule` and `deviceGrantModule` need `userSessionStore` when MFA is on (amended: an enabled `deviceGrantModule` needs it already, whatever the mode — D16).
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
12. **Rate limiting**: two new key prefixes, `mfa` and `mfa-email`. The bundled limiters seed them; *(amended 2026-09-30, #810 and #782: one prefix, `mfa`, which the MFA module contributes)* a custom `RateLimiter` that resolves specs by prefix learns them or falls to its default.
13. **Redis**: two new key families (`mfaf:`, `mfat:`) and the factor store's durability requirements; the `UserSession` envelope gains `authentication`.
14. **`revokeAllForSubject`** also clears the subject's MFA lock state.
15. **Discovery**: a template deployment advertises `urn:o3co:acr:mfa`.

**Amended 2026-09-28 (session admission): the upgrade checklist and the integrator list, where they name what that record removed or renamed.** Upgrading: the boot refusal a composition without the MFA modules meets names `sessionRequirements.expected` (`session-requirements-undeclared`), or `session-requirement-missing` when it wrote `mfa.mode` — not `mfa.mode` alone *(amended 2026-09-30: `session-requirement-missing` when `sessionRequirements.expected` names `mfa` and nothing registers it — the template declares it from `mfa.mode` — with `configKey: "sessionRequirements.expected"`; the session-admission ADR's D7 note)*; step 2 also ports the `sessionRequirements` block; step 5's `403` bodies are the closed shape (`error`, `transaction`, `expires_in`, `hints`) of the F3 amendment; step 6 reads: teach the device-verification page `403 step_up_required` (with `requirement`), and install `webauthnSessionSubjectModule` in place of writing the `req.webauthnSubject` middleware. Integrators: item 1 reads "a composition with a consumer of admission must declare `sessionRequirements.expected`; with MFA installed it must wire mail or write `mfa.notices = "none"`; the MFA module requires `userSessionStore`"; item 5's code is `step_up_required`; item 6's helper is the module; item 4 stands (`step_up: "mfa"`); everything else stands. The build-order rows 7, 13, 14 and 22 below carry their own notes.

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
| 7. `feat(session)!`: the login hands off *(superseded 2026-09-28 by the session-admission ADR's A6: `admitPrimary`, the continuation, `resumePrimary`; `establishSession` landed in #713; no coordinator slot)* | `establishSession` extracted (existing tests unchanged — the refactor's proof); `sessionModule` declares `mfaCoordinator` with the policy; the two `403`s; regeneration into the pending state | With a stub coordinator: the pending browser is not authenticated at `/authorize`, the id rotates, a coordinator outage is `503` with nothing written, `off` unchanged |
| 8. `feat(mfa)`: the package (private), verification | `packages/mfa`: coordinator, `GET transaction`, `challenge`, `verify`; TOTP verification; the key ring and the sample-key refusal; audit (factors seeded in tests) | RFC 6238 Appendix B; a TOTP login; reuse and an older code refused; window edges; N parallel wrong codes spend N; consume before advance; data copied to another subject does not open; every outage `503` once; ids never in a URL |
| 9. `feat(mfa)`: enrollment and the first binding *(amended 2026-09-30, #810: no `mfa.notices`; the enrollment's audit events)* | Forced and self-service TOTP enrollment; recovery-code generation; `binding` recorded; the 80-bit `account-email` proof over the recording sender; `mfa.notices` declared and sent; witness writes through the port (create-then-mark, reconciliation); *(amended 2026-09-29, module review)* the witness reads — at login, in the `mfa` requirement's `admitPrimary`, and from the session's `user` snapshot before a self-service first binding (and, from step 11, a step-up) | First login binds TOTP and gets codes; with a sender, no binding without the proof, and 5 wrong proofs end the transaction without touching the subject lock; MFA without mail refuses boot unless `notices = "none"`; unreadable data never binds; a failed mark heals at the next login; witness `true` with zero records, and a malformed witness, are `503` with nothing written, at login and before a self-service first binding — never a binding |
| 10. `feat(mfa,core)`: the lock and recovery codes *(amended 2026-09-30, #810: no trusted browser; `mfa.locked.first` from the store's first refusal)* | Backoff, weekly budget, trusted browser, hard limit, void; exempt factors; recovery-code verification; `revokeAllForSubject` clears the lock | The schedule under an injected clock; the victim's successes do not refund the week; a recovery code works while TOTP is held and trusts that browser only; another browser stays held; a password change clears it; a lost compare-and-set does not count |
| 11. `feat(mfa)`: step-up transactions | `POST /session/mfa/step-up`; `recordSecondFactor`; regeneration | Step-up on a live session; a gone session refused; `no_qualifying_factor`; the id rotates, the `sid` stays |
| 12. `feat(mfa)`: management, reset, witness reads *(amended 2026-09-29, module review: both witness reads moved to step 9)* | List / rename / remove / regenerate; recent-MFA and last-factor rules; `resetMfaForSubject` | `mfa_step_up_required` then success through PR 11's route; `last_factor`; the reset clears locks, factors and the witness in that order and honours its options |
| 13. `feat(oauth)!`: `/authorize`, the `session` grant, the refresh grant *(amended 2026-09-28: the reads and the refusals are A3's, through `admitSession` / `tokenClaim`; what this step still delivers is D17's ask handling over the `Admission` and, in the `mfa` requirement, O3's token rows)* | D17: one accumulating ask, per-stage TTL, consumption at the code, the ask carried through consent, the ask on an unauthenticated `prompt=login`, `interaction_required`, the degrade path; `oauthModule`'s policy and store check; the `session` grant's `step_up`; the refresh-grant rule (O3); `resumeUrl`'s comment corrected | Every D17 row — `max_age`+`acr_values` and `prompt=login`+`acr_values` in one ask, `max_age` running out mid-trip, consent after both trips, returning without doing what was asked, a replayed ask; id_token `amr`/`acr`/`auth_time` after a step-up; a pre-flip session and refresh token, one without `amr` |
| 14. `feat(device-grant,federation-grants,session,core)!`: the other consumers *(amended 2026-09-28: the reads are A4's and A5's; `authenticatedSubject` is `webauthnSessionSubjectModule` in `packages/webauthn`; `403 mfa_step_up_required` is `403 step_up_required` with `requirement`; what this step still delivers is the `mfa` requirement's per-grade table and the device token's `vouchedAmr` stamp)* | Device verification reads the live session and gates `approve`, and the device grant stamps `vouchedAmr`; the grants' browser half gates connect; `?link=1` requires recent MFA; `authenticatedSubject` (recent-primary fallback, `off` exemption) and the WebAuthn README's bridge; `deviceGrantModule`'s store check | Per consumer through `createApp`: unmet → step-up answer, met → as today, dead session → `401`, outage → `503`, `off` → as today |
| 15. `feat(oauth)`: RFC 9470 alignment | `auth_time` on access and refresh tokens; `acr` / `amr` / `auth_time` in introspection | Grant and introspection tests; the refresh chain keeps `auth_time` |
| 16. `feat(mfa)`: email codes *(amended 2026-09-30, #810: no send limits; the keyed-digest recipient and `mfa.email_address_mismatch`)* | `mfaEmailFactorModule`: 6-digit login codes, 80-bit enrollment codes, `addsMfa`; send limits; delivery failure | Enrollment to the account's address only; resend invalidates; `maxSends` and cooldown; per-subject sends under both fail modes; a throwing sender is `503` and the transaction survives; an email login meets the baseline and not `urn:o3co:acr:mfa`; no code or address in a log line |
| 17. `feat(smtp)`: SMTP `MailSender` *(amended 2026-09-30, #810: the SMTP sender's delivery in `@o3co/auth-provider-standard`, whose section and rendering exist)* | `packages/smtp` over `nodemailer`; TLS rules; `MailTransportError` | Against Mailpit in a testcontainer: delivery; STARTTLS off loopback; reasons mapped; a sentinel address never in an error |
| 18. `feat(webauthn)`: WebAuthn as a second factor | `webauthnMfaFactorModule`; descriptor-taking option builders with `residentKey`; `hwk` / `swk`; challenge in the transaction; sign-count handling | Verification mocked at `#/internal/verification.mjs`, as the grant's tests do; register then assert through `createApp`; a challenge answered twice fails the second; a lost compare-and-set retries, a regression is refused; WebAuthn works while TOTP is held; the grant's routes unchanged |
| 19. `feat(foundation)`: factors and the witness in the Store | `HttpMfaFactorStore`, the four URLs, `markMfaEnrolled` over `markMfaEnrolledUrl`, README wire contract | Core's suite over an `msw` fake Store; `404` / `5xx` / a redirect from `list` throw; the Store never receives unsealed data; the witness kept on bind, remove and reset |
| 20. `feat(template,create-app)`: MFA wired, still off *(amended 2026-09-30, #810: no `MFA_NOTICES`; SMTP is `STANDARD_SMTP_MAIL_SENDER_*`)* | `packages/mfa` published (`private` removed); the template's composition and switches (`mfa.mode = "off"`), `acrValues`, env, Mailpit, the sample key; `create-app --no-mfa`; runbook (boot refusals, fail-closed rows, alerts, key rotation, Redis durability, recovering from a lost factor store, the reset procedure); READMEs; the upgrade guide and port checklist *(amended 2026-09-30: the same pull request that installs the MFA module removes the template's own reading of `mfa.mode` — its `readMfaMode`, the `MFA_MODE` binding in its `application.conf`, and the exception that let a composition root read a module's key before choosing its modules. After it, a composition without the MFA module treats an `mfa` section as unowned, and a composition that must require MFA declares `sessionRequirements.expected = ["mfa"]`, which boot refuses unmet)* | All-modules composition with MFA on and off; `MFA_MODE=required` boots with Mailpit and refuses without mail unless `MFA_NOTICES=none`; email on without SMTP refused naming `SMTP_HOST`; the sample key refused under `CONFIG_ENV=production`; create-app with and without the flag, no `acr` warning under `off` |
| 21. o3co/auth: the umbrella E2E declares MFA off | `tests/abac/application.conf` sets `mfa.mode = "off"` (or `oauthFlow.js` gains a TOTP step) — merged before the o3co/auth PR that bumps `PROVIDER_REV` past PR 22 | The umbrella suite green at the current pin and at the new one |
| 22. `feat!`: on by default *(amended 2026-09-28: template and create-app only — core's `mfa.mode` reference default `off` stays, and the composition's statement is `sessionRequirements.expected`; O2's amendment)* | The template's and create-app's default `required`, with `sessionRequirements.expected` written from it (core's `mfa.mode` reference default `off` stays — O2's amendment); CHANGELOG draft in the PR description (release policy R2) | Core: unchanged — a composition with a consumer of admission and no declaration has been refused (`session-requirements-undeclared`) since the session-admission ADR's A2; the template: a fresh scaffold refuses until `MFA_ENCRYPTION_KEY` and mail or `MFA_NOTICES`, then logs in through a first binding |

A follow-up outside this repository: auth.proxy maps `step_up` to a step-up route instead of `session_unauthorized`.

**Amended 2026-09-27 (build-order step 3): what the ports oblige later steps to do.**

- **Step 6** (Redis stores): `redisMfaTransactionStoreModule` holds the email-proof requirement's key family to D12's durability check (refuses `allkeys-*`, warns without persistence). Both stores meet the contract suites as amended at step 3: the clock-skew and far-ahead cases, create-side field validation, the transition rules, trust renewal scoped to the subject, and the email-proof requirement.
- **Step 8** (verification): the store has no lifetime ceiling of its own. The MFA module refuses at boot a `mfa.transactionTtlSeconds` outside its range, and the coordinator derives every `expiresAtMs` from it and nothing else. `mfa.lockout` is checked at boot with `checkMfaLockoutPolicy(policy, "mfa.lockout")`. `secondFactorMethods` is computed lazily from `mfaFactorResolver`. `noteExemptSuccess` is called only after the exempt proof's transaction is consumed.
- **Step 12** (reset): `resetMfaForSubject(subject, { requireEmailProof: true })` refuses when no `mailSender` is wired or the account has no address — nobody could then give the proof. The first binding consumes the requirement only after the first counting factor is written.
- **Step 19** (foundation): the Store's wire contract says `mfaEnrolled` is a boolean or absent; `null`, a number or a string reads as malformed, which is `503`.
- **Step 20** (runbook): the reset procedure says that an in-process transaction store loses the email-proof requirement at a restart.

**Amended 2026-09-28 (build-order step 4): what the requirement rule settled, and what it obliges later steps to do.**

- **Where the `amr` values live.** D1's row places the constants in `mfa/`; D13 and D2 place them in `grants/authenticationClaims.mts`, which `mfa/` imports. They are there: `PASSWORD_AMR`, `FEDERATED_AMR`, `OTP_AMR`, `HARDWARE_KEY_AMR`, `SOFTWARE_KEY_AMR`, `MFA_AMR`, `EMAIL_OTP_AMR`, `RECOVERY_CODE_AMR` and `composeAmr`. `FEDERATED_AMR` moved at step 4, not step 5, because the rule reads `fed` and core cannot import `session`; `session` re-exports it. `composeAmr` refuses, with a `RangeError`, a factor that lists among its own values `mfa` (which comes from `addsMfa` alone), a primary's marker (`pwd`, `fed` — a second factor must not change the primary the baseline is decided on), or an empty or non-string value. It copies the session's `held` values as they are, so step 11's `recordSecondFactor` composes onto `vouchedAmr` after D9's split — never onto the raw `session.amr`.
- **The one reading of a session exists from step 4.** `sessionAuthentication` and `vouchedAmr` are in `user-sessions/authentication.mts`, and `SessionAuthentication` in `user-sessions/types.mts`. Until step 5 they read the `amr` alone: `fed` makes the primary a federation, else `pwd` a password, else it is unknown; `mfaAt` is never set; and every federation is trusted, so `vouchedAmr` is the recorded `amr`. Step 5 adds the `authentication` key and the split inside these two functions, and their callers do not change.
- **The rule's shape.** `decideMfaRequirement` (`mfa/requirement.mts`) answers `met` (with the chosen `acr`), `reauthenticate`, `step_up` (the values a step-up can meet, in request order — the MFA page's hint — and whether a session that comes back still unmet is refused for `acr` or for the baseline), or `unmet`. **Both halves must be met**: a met `acr` does not meet the baseline, so D17's "`acr_values` met → proceed" assumes the baseline is met already, and a password session under `required` that meets its `acr` still steps up for the baseline. `secondFactorMethods` is `undefined` without a coordinator. A step-up needs a live session: outside `required`, `session: null` with an unmet `acr_values` is `unmet`. Under `required`, a primary the rule does not know — anything but `pwd` and `fed` — is re-authenticated like one that cannot be told, never met; a request none of whose values the table carries is `unmet` before any re-authentication, since no login can meet it. An alternative that requires nothing is never met and never a step-up target, and the drop reads it as unsatisfiable, whoever built the table.
- **The rule's input.** A consumer builds it with `requirementSession(session)` (`user-sessions/authentication.mts`) and never by hand: one built from the record's own `amr` would, after step 5, let an untrusted upstream value meet an `acr`. `/authorize` does from step 4; every consumer from step 13 on (and step 14's) must, inside the call's own arguments — `designVocabulary.drift.test.mts` fails any `decideMfaRequirement(` or `selectAcr(` call outside the rule's file whose arguments do not build the input with `requirementSession(`.
- **`mfa` in reach.** D16's "∪ {`mfa`}" is the coordinator's to include: from step 8, `MfaCoordinator.secondFactorMethods` carries `mfa` when, and only when, an installed factor adds it (`addsMfa`), and `stepUpReach` / `producibleAmr` add nothing of their own. So a deployment whose only factor is the email code (O7) neither advertises nor steps up to `urn:o3co:acr:mfa`.
- **`mfa.mode` as a consumer reads it.** Through `readMfaMode` (`mfa/requirement.mts`): before the flip only an **absent** mode maps to `off`; a present value that is not `off`, `optional` or `required` is a `RangeError` naming `mfa.mode`, which refuses the composition — never read as `off`, which would switch MFA off on a typo. Step 13's `/authorize`, step 7's login route and step 14's consumers read the mode through it *(superseded 2026-09-28: only the `mfa` requirement reads the mode; the consumers call admission and never read it — the session-admission ADR's D6, and its D7 for the two boot checks core makes on it)*.
- **Recent MFA** (D16) is not part of step 4. Step 12 adds it to `mfa/requirement.mts`, beside the rule, and step 14's consumers (`?link=1`, `authenticatedSubject`) call it *(superseded 2026-09-28: recent MFA is the `mfa` requirement's rule for the `credential_change` grade, in `packages/mfa`; no consumer calls it, and `authenticatedSubject` is withdrawn — the session-admission ADR's D6, D8)*.
- **What `/authorize` uses at step 4.** Only the `acr_values` half: `selectAcr` over `requirementSession(session)`'s `amr`, with an empty step-up reach and no baseline. The table it answers from, and discovery advertises, is `vouchableAcrValues` (`packages/oauth/src/acrValues.mts`): the configured table less the entries nothing installed can satisfy, computed with no second-factor values because no module consults a coordinator yet. Step 13 replaces the `acr_values` half with `decideMfaRequirement` under `mfa.mode` (read with `readMfaMode`), and passes the coordinator's `secondFactorMethods` to the drop and to the reach *(superseded 2026-09-28: `/authorize` calls `admitSession`, which decides both halves; the drop and the reach read the registered requirements' `reach` through the resolver — the session-admission ADR's D2, D6)*. Where: in `oauthModule`'s route factory (the router) and its discovery-metadata factory, both through `vouchableAcrValues`, so they keep sharing one input. Those are list-shaped contributions, which the boot planner invokes after the name-keyed ones — `mfaFactors` and `federations` among them — have registered, so the lazy getter answers by then and the drop's line stays once per process, at boot.
- **The drop.** `producibleAmr` and `vouchableAcrTable` keep an entry that one alternative can meet, whole, and report the rest. What can be produced: `pwd`; `fed` only once a federation is installed (`federationInstalled`); the coordinator's `secondFactorMethods`; anything with a trusted federation (`trustedFederation`, which requires an installed one). `oauth` logs each dropped entry once at composition as `acr_value_unsatisfiable`, with `acr` and `unproducible` (and `emptyAlternative` when an alternative requires nothing), as the operator runbook lists. The line is `info` under `mfa.mode = "off"` when one alternative lacks only the values D14 assigns to second factors (`otp`, `hwk`, `swk`, `email`, `recovery`, `mfa`), and `warn` otherwise. A dropped entry is answered with the description of a value the table does not carry. Step 5 narrows `trustedFederation` from "a federation is installed" to "an installed federation with `trustUpstreamAmr`", leaving `federationInstalled` as it is.
- **`claims`.** Besides naming `acr`, a `claims` value that is not a JSON object, or is repeated, is refused as malformed (`invalid_request`). It cannot be told not to name `acr`, and a malformed `acr_values` is refused the same way. "Every other use stays ignored" reads as every other well-formed use. An empty `claims=` is omitted, as RFC 6749 §3.1 requires; step 4 reads an empty `max_age=` the same way, which `/authorize` had refused since #481.

**Amended 2026-09-28 (build-order step 5): what the upstream split settled, and what it obliges later steps to do.**

- **The key.** `UserSession.authentication` and `CreateUserSessionInput.authentication` are `SessionAuthentication | undefined`, required keys, and `SessionAuthentication`'s four fields are required keys too, so a copy names each one. Both bundled stores round-trip it with their own copies of `upstreamAmr` and `mfaAt`. Both refuse at `create`, with a `RangeError` and nothing recorded, what `recordableSessionAuthentication` refuses: an `authentication` that is not an object or `undefined`, a `primary` that is not a non-empty string, a `federation` that is neither a string nor `undefined`, an `upstreamAmr` that is not a list of strings or `undefined`, and an `mfaAt` that is not a `Date` at or after the epoch and no further ahead of the store's clock than the clock skew tolerated between hosts — core's `DEFAULT_CLOCK_SKEW_MS`, five minutes, the tolerance the JWT verifier gives an `iat` another host stamped ahead of it. (The MFA stores' `MFA_CLOCK_SKEW_ALLOWANCE_MS`, a day, is a retention allowance, where larger is the safe direction; it is not a bound on accepting a time, and is not reused.) An accepted `mfaAt` is recorded no later than the store's own clock: a store records what `recordableSessionAuthentication` answers — a copy — never its own input. The Redis envelope stores it as a key of its own (`mfaAt` as `mfaAtMs`): an envelope without it reads as `undefined`, one whose `authentication` is malformed — `null` included — is refused as corrupt rather than read as a pre-upgrade session, and an older release ignores it.
- **The reading of a pre-upgrade session.** D9's split, in `sessionAuthentication` and `vouchedAmr`: a session carrying `fed` vouches for `fed` alone, and every other value is `upstreamAmr` — **whatever that federation's `trustUpstreamAmr` says now**, because such a session does not name its federation. The reading never makes a session more trusted than it was written; a trusted federation's user who wants an upstream value to count logs in again. A session with `authentication` present is read from it, and its `amr` is vouched for as recorded.
- **What each login path records** is composed in core (`user-sessions/authentication.mts`): `passwordSessionAuthentication()` for `POST /session/login`, and `federatedSessionAuthentication({ federation, upstreamAmr, trusted })` for the callback — a trusted IdP's values beside `fed` and `upstreamAmr: undefined`, an untrusted one's in `upstreamAmr` (only when it asserted something) and `amr` `["fed"]`.
- **Where the switch is read.** `federations.<name>.trustUpstreamAmr` sits beside `enabled` in every section shape; written inside the nested shape's sub-section (`federations.<name>.<type>.trustUpstreamAmr`, or the sub-section a shorthand key names) it is a `RangeError` saying so, never ignored. Its schema entry is core's `federationEntrySchema` (a boolean coerced like every env-overridable one); no environment variable is wired for it, because no bundled adapter surfaces an upstream `amr` — it is set in configuration, beside `enabled`. D19's "(session)" names who writes by it; it is read by one core function, `federationTrustsUpstreamAmr(config, name)`, because `oauth`'s drop reads it too and `session` and `oauth` import nothing from each other. `true` trusts; absent or `false` does not; anything else is a `RangeError` naming the key. `federationTrustsUpstreamAmr` answers `false` for a section whose own `enabled` is not `true` — a disabled federation signs nobody in — after its refusals, so a disabled federation's unusable switch still refuses the composition. The federation routes read it for each installed federation when they are built, keyed by the name it is installed under, and the callback decides — and records as `authentication.federation` — under the name it resolved the provider by. oauth's `vouchableAcrValues`, now taking the configuration, sets `trustedFederation` when it answers `true` for an installed federation: the split and the drop read one function, and cannot disagree. `authentication.federation` is therefore the name the federation is installed under — equal to the adapter's `provider.name` in every bundled composition — while the federation index, logout, the federation-token store and the callback's own lookups use `provider.name`; a composition that installs an adapter under another key would record two names for one login, and refusing such a key at composition is left to a later change. Trust is decided when the session is written: changing the switch applies to sessions established afterwards (below).
- **`/token` and the `session` grant** stamp `vouchedAmr`. `designVocabulary.drift.test.mts` finds, by shape, every read of a field named `amr` or `authentication` in every TypeScript and JavaScript source of every package and of the standalone template — a property access on any receiver, an element access by the literal name, `Reflect.get`, a destructuring by declaration, parameter or assignment, renamed or keyed by a computed literal — and every spread into an object handed to a function that takes an `amr` (a token minter, the id_token builder, the key store's signer through the claims it takes, the amr composer, a store's `create`, the step-up, the coordinator, the rule), unless it spreads only literals. A spread of a local, and a local handed whole to such a function, is followed to its declaration in the same file, so a pinned local re-initialised from a session fails; an argument that is a call to something else (`formatObject({ … })`) is looked through to what that call is handed. No file is exempt whole: each read that stays — the readers', the rule's and the two stores' included, and those that are not a session's (a factor's `verified.amr`, an id_token option, a refresh token's carried claims, the rule input's `amr`, a profile's upstream `amr`) — is pinned to its file, its receiver's text and its count, with a reason, so a new read, a second one or a swap of receiver fails, and so does a stale entry. What it cannot follow is left to review, and to a branded type for a vouched `amr` planned for a later change: a local it cannot resolve in the file (a parameter, an import, a value built elsewhere), a reassigned `let` or a `var` hoisted from an inner block, a callee reached under another name, a copy that is not a spread (`Object.assign`), a cast that relabels a record, and reflection with a key that is not a literal.
- **The step-up capability.** `SupportsSecondFactorUpdate.recordSecondFactor(sid, { amr, at })`, detected by `supportsSecondFactorUpdate`, with a contract suite of its own (`runSecondFactorUpdateContract`) that runs only against a store claiming it; the base `UserSessionStore` suite asks nothing optional. `amr` is what the verification **adds** — the factor's values, and `mfa` when it adds that (`composeAmr([], { amr, addsMfa })`) — and the store composes it onto `vouchedAmr` of the stored session (`sessionAfterSecondFactor`, which both stores write), so the caller never composes onto the record's own `amr`. The event is refused with a `RangeError`, before anything is read, when it has no values, an empty one, `pwd` or `fed`, only `mfa` (which comes beside a factor's own values and alone names none), or an `at` that is not a date at or after the epoch or is further ahead of the store's clock than `DEFAULT_CLOCK_SKEW_MS`. An accepted `at` is recorded no later than the store's clock, and a stored `mfaAt` ahead of it — written by a replica whose clock ran ahead — is brought back to it before the later of the two is taken, so a step-up repairs it rather than keeping it as the later: D9's "monotonic" holds on the recording store's clock. That `RangeError` is the caller's fault — a programming error, never an outage; a rejection of any other kind is the store's outage. A pre-upgrade session whose primary cannot be told answers `null` and is not written, as a gone session does: no second factor can name its primary. Under `mfa.mode = "required"` the requirement rule re-authenticates such a session before a step-up is ever asked; under `optional` it does not, since a request's `acr_values` can still name a step-up target for it — hence step 13's obligation below. The Redis store reads, computes in JavaScript and writes through a new client operation, `UserSessionStoreClient.replaceIfUnchanged` (a script that `SET`s with `KEEPTTL` only while the key holds what was read), at most five times before it throws; it refuses a client without the operation when it is built, and rewrites only `amr` and the fields of `authentication` it knows, keeping what a newer release added beside or inside them.
- **What was issued before the upgrade keeps what it carries.** The split applies to sessions as they are read; it does not reach what a session already minted. An authorization code issued before the upgrade — or by a replica still on the older release during a rolling one — keeps the `acr` its `/authorize` chose, possibly met by an untrusted IdP's values, and `/token` stamps it as it is. A refresh token carries its `amr` and `acr` forward at every refresh (the refresh grant copies them, as it copies `auth_time`), untrusted upstream values included, until its family ends: the family's expiry is set once, from `oauth.refreshToken.expiresIn` (a day by default), at the login that began it — and under `oauth.refreshToken.unknownFamilyPolicy = "accept"` a token with no family record has no such bound. Documented rather than re-checked at `/token`: the remedy is `revokeAllForSubject` for the affected subjects, or revoking a known token's family. `revokeAllForSubject` ends their sessions, the refresh families and codes minted from them, and every access token this provider itself verifies (introspection, `/oauth/userinfo`, the federation-token route, token exchange, the refresh grant); an access token a resource server validates offline lives until its `exp`. It needs `subjectRevocation` and `subjectSessionIndex` wired, and reports itself `incomplete` without them.
- **Withdrawing trust.** Turning `trustUpstreamAmr` from `true` to `false` applies to sessions established afterwards. A session recorded while it was `true` keeps the IdP's values in its `amr` — they were vouched for when it was written — so tokens minted from it keep carrying them, and its refresh families carry them until they end. To withdraw at once, call `revokeAllForSubject` for the subjects who signed in through that federation, with the reach just stated: every session, family and code, every access token this provider verifies — not one a resource server validates offline, which lives until its `exp`.
- **What this obliges later steps to do.** The step that creates a session after a completed second factor (F1 step 5; steps 7–8) records `mfaAt` then, widening what core composes for a password login at that point and holding the verification's time to `checkSecondFactorEvent` — no parameter is added to `passwordSessionAuthentication()` before a caller needs it. Step 11's step-up passes `recordSecondFactor` the factor's additions as above, reads `null` as "log in again", a `RangeError` as its own fault (a server error, never an outage) and any other rejection as the store's outage (`503`); D20's boot line (`mfa_step_up_unsupported`), in whichever step adds it, detects the capability with `supportsSecondFactorUpdate`. Step 12's recent-MFA reading takes an `mfaAt` up to `DEFAULT_CLOCK_SKEW_MS` ahead of its own clock as now — the skew between the replica that recorded it and the one reading it, since no store records a time ahead of its own clock — and one further ahead as not recent. Step 13's `/authorize`, when it would ask a step-up of a session whose primary cannot be told (`sessionAuthentication` answers `undefined`), sends it to the login page instead of the MFA page, whatever `mfa.mode` is — as D17 does for a store without the capability — since a step-up could not be recorded on it. Steps 13 and 14 read a session only through `requirementSession` / `vouchedAmr`, as the drift test enforces.

**Amended 2026-09-28 (session admission): the build order after step 5.** Before step 6 resumes, the session-admission ADR's A1–A6 land: the ADRs (A1); core's `session-admission/` directory with the `sessionRequirements` kind, the declaration `sessionRequirements.expected`, and the removal of `mfaCoordinator`, `MFA_ABSENCE_POLICY` and `decideMfaRequirement` — `readMfaMode`, `MfaMode` and core's `mfa.mode` stay, the mode widened to its three values (A2); `oauth`'s four consumers on admission (A3); device verification and the federation-grants browser half (A4); the link flow and the WebAuthn bridge (A5); `establishSession` in both login paths and `admitPrimary` in the password route (A6, which replaces step 7 — the federation callback does not consult admission in this release, and an interruption there is that record's "Outside the first release"). Then: step 6 unchanged; step 8 contributes `sessionRequirements: { mfa }`, reads `mfa.mode` through core's `readMfaMode`, and completes a login through `resumePrimary`; step 11's `POST /session/mfa/step-up` admits with the `remediation` action `mfa.step_up`, which the requirement declares; steps 13 and 14 shrink to `/authorize`'s ask handling (D17) over the `Admission` and the requirement's per-grade table — the liveness and revocation halves of their rows are done by A3–A5; step 22 is the template's and create-app's default only, with no core change (O2's amendment). "Every intermediate release is safe" still holds: until step 8 no requirement is registered, a composition with a consumer of admission declares `sessionRequirements.expected = []`, and admission with none registered admits what today's readings admit, less the disagreements A3–A5 remove.

**Amended 2026-09-29 (build-order step 8a): what the package's foundation settled.** Step 8 lands in three pull requests; the first builds `packages/mfa` without the coordinator — the configuration it reads, the key ring and what is sealed under it, and the TOTP factor with `mfaTotpFactorModule` — and registers no requirement, so `mfa.mode` other than `off` is still refused at boot. It settled what this record did not say; no decision above changes.

- **Dependencies.** The package names a peer only once it imports it: today `@o3co/auth-provider-core` alone, with `zod` a dependency. `session`, `express` and `express-session` (D2) join with the MFA module, the routes and the completion; D2's directions stand.
- **What the settings read.** `readMfaSettings(config, { environment })` reads `mfa.encryptionKeys` and `mfa.factors.totp` alone, and the package's `reference.conf` carries only those keys — the ring's first key from `MFA_ENCRYPTION_KEY`, with no default. Step 3's obligations for step 8 — an `mfa.transactionTtlSeconds` outside its range refused at boot, and `checkMfaLockoutPolicy(policy, "mfa.lockout")` — move with their keys to the MFA module's pull request. The TOTP factor's module reads `mfa.factors.totp` alone (`readMfaTotpSettings`): a factor never holds a key, so it never reads the ring. *(Amended 2026-09-29, module review: `readMfaSettings` — what the MFA module reads, as step 8b left it — reads no factor's section. `mfa.factors.totp` is read by the TOTP factor's module alone, so a composition without that factor, whose factors are all another package's, is never refused over TOTP's issuer or parameters; each factor's module reads its own `mfa.factors.<kind>`.)*
- **TOTP's ranges.** `digits` 6 to 8 and `period` 15 to 120 seconds, as the owner decided for step 8 (this record states no bounds for them); `window` 0 to 2 (D22); `algorithm` `SHA1`, `SHA256` or `SHA512`.
- **The issuer.** D19's default, "the issuer's host", is the *hostname* of `oauth.jwt.issuer`, without its port: the `otpauth://` label is `issuer:account`, and a port's colon would split it. It is derived only for a factor that is on: when no host can be derived (not a URL, an IPv6 literal) such a factor's settings are refused, naming `MFA_TOTP_ISSUER`, and a switched-off factor derives nothing and never refuses over it. A written issuer must be well-formed text, not blank once trimmed, with no C0 or C1 control character, DEL or colon. The label's account — the email, else the username — must be well-formed text, else enrollment throws a `RangeError`.
- **The development sample key.** The package exports it as `MFA_DEVELOPMENT_SAMPLE_KEY` (canonical base64 of 32 bytes); step 20 copies it into the template's `config/development.conf`. D11's refusal applies wherever it sits in the ring, by #473's rule: the environment the configuration was selected by, or `NODE_ENV` — each read whatever its case and the whitespace around it — is `production` or `staging`, or `deployment.mode` is `"multi"`. No other name is an alias for either.
- **Key ids.** A ring entry may leave out its `id`; it is then named by its key's fingerprint — `k` and the first 16 characters of base64url(HMAC-SHA-256(key, `o3co:mfa:key-id`)), a PRF's output that tells nothing of the key — and `reference.conf`'s entry, which `MFA_ENCRYPTION_KEY` feeds, has none. So a key changed in place leaves what the old one sealed `key_unavailable`, naming the old fingerprint, rather than `unreadable` under an id both keys shared, which would tell the operator nothing. A key under a written `id` is never changed in place: rotating adds an entry of its own, and the old key stays until nothing sealed under it, and no digest naming it, is left. A fingerprint that equals a written id, or one key listed twice, is refused as a duplicate. Core's envelope seals with a random 96-bit nonce and a factor's data is re-sealed at every use, so a key is rotated well before 2^32 seals under it (NIST SP 800-38D).
- **Ceremony state.** D11 seals a pending enrollment with the transaction id in the authenticated data. The state of a challenge and of a pending enrollment are each sealed under a purpose of their own — `o3co:mfa:challenge`, `o3co:mfa:enrollment` — with transaction id ‖ kind, length-prefixed, as the record, so neither opens as the other, as another kind's, or as a factor's data (`o3co:mfa:factor`, subject ‖ id ‖ kind). Every binding part is non-empty, well-formed text — UTF-8 writes a lone surrogate as U+FFFD's bytes, which would make two bindings one — so sealing refuses such a part and opening answers `unreadable`. What is sealed is a JSON object of JSON values that JSON gives back as it is — no Date, Map, class instance, `toJSON`, BigInt, NaN, cycle or hole — else a `RangeError` that quotes nothing. Opening answers `unreadable` or `key_unavailable` and never throws.
- **Digests.** D11's HMAC-SHA-256 "under the ring" is keyed with a key HKDF-SHA-256 derives from the ring key the digest names (info `o3co:mfa:digest`), not with that AES-GCM key itself, so no key serves two algorithms; the input is the factor's kind and the parts, each length-prefixed and well-formed text, and a test holds the format to a known answer. `matchesDigest` answers `key_unavailable` only for a well-formed digest under a key the ring lacks; a stored value that is not `{ keyId, digest }` as `digest` made it is a `RangeError` — neither a missing key nor, D11 says, ever a wrong code.
- **The retired-key line.** `mfa_factor_sealed_with_retired_key` (info, `keyId`) is logged once per key id per sealing, which one boot builds — D11's "per process".
- **The TOTP factor.** A proof is exactly `digits` ASCII digits, and anything else is `malformed` — D6's pasting rule is for the long codes. A factor's data is its base32 secret, `algorithm`, `digits`, `period` and `lastUsedStep`; a secret shorter than 16 bytes (`HOTP_SHARED_SECRET_MIN_BYTES`, RFC 4226 R6), or a field it cannot read, is thrown — an unreadable factor, the coordinator's `503` — never answered `invalid`. `beginEnrollment` and `completeEnrollment` exist from this step, as pure functions with no route, because core's `MfaFactor` requires them; the enrollment routes and the first binding stay step 9's.

**Amended 2026-09-29 (build-order step 8b): the `mfa` requirement, and what its pull request settled.** The second of step 8's three pull requests adds `mfaModule` and `mfaModules`, the `mfa` requirement and the login's transaction, and wires the package into `tools/composition`'s full set (memory MFA stores, and #720's Redis ones where the full set runs Redis; `mfa.mode = "optional"`; `mfa` declared). The routes, the verification, the completion through `resumePrimary` and audit are the third pull request's. The owner's decisions for step 8 that this pull request carries out, as taken:

- **D6's rows now** (owner decision 1): the requirement's `admit` is the `use` baseline under `mfa.mode`, O3's three token rows, and `device.lookup` / `device.deny` met on any live session — the cookie baseline alone would refuse every refresh of an MFA session, since a token carrier has no `mfaAt`. `credential_change` is held to the same baseline until steps 12 and 14 add recent MFA. *(2026-09-30: recent MFA landed before those steps, as the `mfa` requirement's rule for the grade, #823.)*
- **A first binding's interruption in its final shape** (owner decision 2): zero records under `required` open the `mfa_enrollment_required` transaction (`enrollment: "required"`) with `hints.enrollable` and `hints.email_proof`, and no enrollment witness is read before step 12 *(amended 2026-09-29, module review: before step 9 — the note after this one)*. Nothing can bind before step 9.
- **The step-up declared before its route** (owner decision 3): the requirement declares `mfa.step_up` and its page, `endpoints.mfa.url`; the page's `POST /session/mfa/step-up` answers `404` until step 11, and the package README says so.
- **#720 before 8b** (owner decision 5): the Redis MFA stores landed first, so the full set's Redis run uses them.

What it settled that this record did not say:

- **The keys.** `mfa.transactionTtlSeconds` is held to 60–1800 seconds (owner decision 7; this record states no bounds) and every `expiresAtMs` is derived from it alone; `mfa.maxAttemptsPerTransaction` to 1–10 (the owner's bound, asked after the first review round; this record states none); `mfa.lockout` to a positive whole number per field and then core's `checkMfaLockoutPolicy(policy, "mfa.lockout")`. Their defaults are D19's, in the package's `reference.conf`; the TOTP factor's module still reads `mfa.factors.totp` alone.
- **A token is judged on its own `amr`, record or not** (confirmed by the owner). D6's null-session row and its token rows both describe a refresh token without a `sid`; the token rows decide, since D2's step 5 builds a token carrier's input from the token "whether or not a record was read" and D9 skips the read for a token without one. The rows are read in D6's order — `fed` is met; a factor's own second-factor value (`SECOND_FACTOR_AMR` but `mfa` alone, which core never lets stand without a factor's value: `otp`, `hwk`, `swk`, `email`, `recovery`) is met whatever the primary; `pwd` alone is unmet; anything else — no `amr` at all, `[]`, an unknown value, `mfa` alone — is re-authenticated. The first version read the primary's marker first and re-authenticated a token with neither `pwd` nor `fed` before looking at its second-factor values, which refused every refresh of a passkey sign-in: the WebAuthn grant mints `["hwk"]` and no `sid`. The review of 8b found it; a composition test now signs in with a software passkey under `required` and refreshes. D6's token row ("`fed`, or a second-factor value present → met") and D16's O3 row read this way. The null-session row is the cookie's, the code's and the link's.
- **Any record interrupts** (confirmed by the owner). A subject with any factor record — recovery codes alone, a kind no longer installed — is answered `mfa_required` under either mode, never a first binding (F3); `counting` decides only what a first binding offers and the boot refusal. `hints.enrollable` lists the enabled counting factors whose `enrollable(user)` does not refuse, in registration order; `hints.email_proof` is `false` and the transaction's `emailProof` `"not_required"` until step 9 wires the proof. `mfa_required` carries no hints. A primary that is not a password login is established without a read (D13); none reaches the requirement in this release.
- **The step-up's second verdict.** The baseline's `step_up` is answered `whenStillUnmet: "reauthenticate"`, D2's mapping of the rule's `baseline`; with no factor enabled the baseline is `unmet` instead, since nothing could finish a trip. The page stays registered with an empty reach, which D3 allows.
- **A step-up only where it can be recorded.** The module asks core's `supportsSecondFactorUpdate` of the `userSessionStore` — the guard's first caller — and, for a store without `recordSecondFactor`, warns once at boot (`mfa_step_up_unsupported`, the adapter's kind: D20's row) and has the requirement answer `reauthenticate` where the baseline would step a session up; a login records the second factor from the start. What `/authorize` does for an `acr_values` step-up over such a store (D17's login trip) is step 13's.
- **The reach is read once.** The requirement keeps the reach of its first read — core's, at the end of the name-keyed pass, which core seals and merges with — and its own baseline reads that too, so the two cannot disagree after boot.
- **Where the installed factors are checked.** In the MFA routes' factory — list-shaped, so it runs after every factor has registered — each refusal the `cause` of the boot's, with a `reason`: an enabled factor whose kind core's hint grammar refuses (`isHintToken`, `^[a-z][a-z0-9_-]{0,63}$`), naming the kind, under either mode (`MfaFactorKindUnhintableError`, `mfa-factor-kind-unhintable`; the owner's answer); more than 16 enabled counting factors, core's cap on a hint list, which core does not export and a test holds the package's to (`MfaTooManyFactorsError`, `mfa-too-many-factors`); and, under `required`, none (`MfaNoCountingFactorError`, `mfa-no-counting-factor`). A first binding's `hints.enrollable` lists the counting kinds, and core would otherwise refuse that answer at every such login. When every counting factor's `enrollable(user)` refuses the user, the list is empty: the answer stands, and each such login is said at warn (`mfa_enrollment_nothing_enrollable`, the kinds alone, never the subject). That contribution (`mfa-routes` at `/session/mfa`, after `session-middleware`) lands in this pull request for the check alone; until the routes do, every request passes through it.
- **The other refusals.** `mfa.mode` `off` or unset with the module installed is refused by the requirement's factory — "remove the MFA module, or set `mfa.mode`", D20's row — as a failed contribution; so is a missing `endpoints.mfa.url`, the page a step-up starts on.
- **One boot's state.** The requirement's factory builds, once per boot, the key ring's sealing on the composition's logger (what keeps `mfa_factor_sealed_with_retired_key` to once per key id) and the requirement, and keeps both — the requirement being the object core issued `mfa.step_up` to, which step 11's route needs — for the routes of the same boot, keyed by that boot's `mfaFactorResolver`, a projection core builds once per boot. When the ring carries the development sample key, which only a development configuration may, it logs `mfa_development_sample_key_in_use` (warn) once.
- **Acceptance criterion 4 against the real requirement.** Core's merge rows are one list, as data on core's testing entry (`session-admission/testing/merge.rows.mts`, `MERGE_ROW_GROUPS`): core's merge test runs them against its stand-in, and the package against `createMfaRequirement`, over factors declaring what the rule was handed as `secondFactorMethods`; the `mfa.mode = "off"` rows run against admission with no requirement registered, which is what an MFA-off composition is. (The first version ran a copy held to core's by row names alone.)
- **Fixation, pinned end to end.** `GET /session/csrf` is stateless and hands the browser no session, so the suite plants one before the login; the transaction is bound to the id the `403` hands the browser, never the planted one, which holds nothing afterwards. A transaction store that cannot keep the transaction at the open is `503`, the regenerated cookie session dropped, no `UserSession`.
- **Key ids, corrected (the retro review of #721).** "One key listed twice is refused as a duplicate" now holds whatever ids it is written under: the ring's entries are compared by their decoded keys as well as by id, so one AES key cannot pose as two rotation generations.
- **What is sealed, corrected (the same review).** A value is read once, each own data property through its descriptor, into the copy that is checked and serialised; an accessor anywhere in it — a getter or a setter, at any depth, an array index among them — an Array subclass, and an object over a prototype other than `Object.prototype` or none are refused as well, so nothing a getter answers can differ between the check and the sealed text.
- **Left for later.** D11's "count both" — logging a retired key when a digest matches under a key that is no longer first, as sealed data does — is step 8's third pull request's or step 10's, with the first digest a verification compares. The account-email proof is step 9's: until then the login's interruption admits `hints.email_proof: false` alone — in its type, and at run time a `RangeError` before anything is stored — so no answer advertises a proof its transaction (`emailProof: "not_required"`) does not require (Copilot on #729).

**Amended 2026-09-29 (module review): the witness reads move from step 12 to step 9.** Step 8b opens a first binding's transaction without reading the enrollment witness, on the ground that nothing can bind before step 9 (owner decision 2, above). But step 9 is the step that makes a first binding possible, so D12's reads cannot wait for step 12. At login: from step 9, the `mfa` requirement's `admitPrimary` reads the witness from the primary's `user` — the fresh `authenticate` answer — through `readMfaEnrollmentWitness` when it finds no factor record for the subject. A witness `true` there, and a malformed one, are an outage: the requirement emits the audit event `mfa.enrollment_state_inconsistent` and throws, with a cause that names the inconsistency; admission answers `unavailable` and logs its one `session_admission_unavailable` line, which carries that cause; and the login route answers `503` with nothing written (the session-admission ADR's D5) — never a first binding, as D12 (amended with this note) and the step-3 amendment say. From the session's `user` snapshot (the login's `User`, D12): step 9 also delivers self-service TOTP enrollment, which for a subject with no counting factor is a first binding (F4, step 3), so it reads the witness from the snapshot before it binds and answers a witness `true` with zero records, or a malformed one, the same way — and step 11's step-up reads it so from its first version. Whichever way a first binding is reached, a lost factor store never lets a password holder bind a first factor over an enrolled account. Rows 9 and 12 above are amended with it: step 12 keeps management and the reset, which clears the witness last. Decided by the owner on the module review of 2026-09-29.

**Amended 2026-10-01 (build-order step 19b, owner decision): the witness kept on remove and reset is tested in step 12,** which builds those flows; row 19 tests the bind and the reconciliation.

---

## 9. Owner decisions (2026-09-25)

The decisions this design left to the owner, as taken, with what was rejected.

**O1 — Upstream `amr` does not count by default.** Upstream values are kept apart (`authentication.upstreamAmr`, never stamped, never matched for `acr`), and `federations.<name>.trustUpstreamAmr` opts a federation back in. The breaking change is accepted; the acr entries only upstream values satisfied are dropped at boot with a warning, which is where an operator sees it (D13). Rejected: trusting by default, as #481 does today, which lets an IdP's word meet this provider's `acr`; namespacing the values (`upstream:mfa`), which spends `amr` on values no relying party can act on.

**O2 — "On by default" lives in the template and create-app.** They default to `required`; core's reference removes its default for `mfa.mode`, so every composition root — the template's, and one written by hand — states `required`, `optional` or `off`, the repository's rule for security-relevant slots. Rejected: flipping core's reference to `required`, under which the MFA module, installed without a mode, would enforce silently; keeping core's reference at `off`, under which a hand-written composition gets no MFA and no signal.

**Amended 2026-09-28 (session admission): O2 re-decided by the owner.** "On by default" stays the template's and create-app's (`required` at the flip); core keeps its reference default `off` — the review found that moving the key out of core does not work against core's strip-mode schema. A hand-written composition that installs the package has MFA on; one that writes `mfa.mode = "required"` without installing it is refused (`session-requirement-missing`) *(amended 2026-09-30: through the template, which declares `mfa` from the mode; a hand-written composition is refused when it declares `mfa` in `sessionRequirements.expected` without installing it — the session-admission ADR's D7 note)*; every composition with a consumer of admission declares what it expects (`sessionRequirements.expected`, `[]` allowed) and is refused without the declaration or when a declared requirement is not registered (`session-requirements-undeclared`) *(amended 2026-09-30: a declared requirement that is not registered is `session-requirement-missing` — the session-admission ADR's D7 note)*. O2's substance — every composition states its posture — is kept in that generic form; what changes is where the statement lives (one core key, no absence policy on a slot) and that installing the package is itself the "on". The reasoning is the session-admission ADR's D7, which records that its first draft's warning was rejected by both reviews.

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

- **MFA after a federated login.** The federation callback calls `mfaCoordinator.decideAfterPrimary` with `method: "fed"`, and `mfa.requiredAfter` gains `fed`; a trusted upstream `mfa` meets it. *Amended 2026-09-28 (session admission): the coordinator is no longer a slot, so this reads — the federation callback consults `admitPrimary` (the session-admission ADR's D5) in place of `establishWithoutAsking`, which needs a navigation-shaped `InterruptionAnswer` (a redirect chosen by the redirect policy, not a `403` body) and the upstream tokens carried in the continuation the MFA transaction persists; then `mfa.requiredAfter` gains `fed` in the `mfa` requirement's own table, and a trusted upstream `mfa` meets it.*
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

