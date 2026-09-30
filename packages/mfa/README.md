# @o3co/auth-provider-mfa

Last updated: 2026-09-30

Multi-factor authentication for [`auth.provider`](../../README.md): a second factor after a password login, and a step-up when a relying party asks for one at `/authorize` — the package [the MFA ADR](../core/docs/adr/2026-09-25-multi-factor-authentication.md) designs (its D1).

> **Private.** The package is `"private": true`: built and tested in this workspace, never published, until the standalone template wires it (the ADR's build-order step 20). No release publishes a second-factor verification before the lock that bounds guessing exists (step 10). Nothing here is a supported API yet.

## Responsibility

**Role.** Everything MFA needs that is not a shared port: the `mfa` session requirement it contributes to core's session admission — what the MFA ADR called the coordinator — the browser API under `/session/mfa/*`, the factors that are not another package's, the key ring and what is sealed under it, lockout and audit. Core holds the ports the factors and the stores share; a factor from another package (WebAuthn's) reaches the requirement as an `mfaFactors` contribution.

**Owns, as of the build-order step 8's first two parts:**

- the `mfa` session requirement — what MFA is to every consumer of a session, through core's admission — and `mfaModule`, which registers it as `sessionRequirements.mfa` and refuses the compositions that could not honour it;
- the login's MFA transaction: opened when the requirement interrupts a password login, and the `403` the login is answered with;
- the TOTP factor (RFC 6238 on `node:crypto`), contributed as `mfaFactors.totp` by `mfaTotpFactorModule`;
- the sections its modules read — `mfa`, the MFA module's (the mode, the MFA page, the key ring, a transaction's life and attempts, the subject lock, recent MFA's window), `mfa-totp-factor`, the TOTP factor's module's, and `mfa-recovery-code-factor`, the recovery-code factor's module's — their defaults ([`config/reference.conf`](config/reference.conf), exported as `@o3co/auth-provider-mfa/reference.conf`) and their refusals, the development sample key among them;
- sealing a factor's data and a ceremony's state under the key ring, and keyed digests for codes that are compared and never recovered — so that no factor holds a key.

**Not yet here:** the recovery codes — their module and section are declared, and nothing reads the section; the routes under `/session/mfa` — reading a transaction, a challenge, a verification — completing a login, and audit (step 8's third part): until they land, a login the requirement interrupts cannot be finished, and `mfa_required` ends there; enrollment, the first binding and the enrollment witness — its writes, and its reads at login and before a self-service first binding (step 9); the lock and recovery codes (step 10); the step-up route, `POST /session/mfa/step-up`, which the MFA page calls to meet a step-up and which answers `404` until step 11; management and the operator reset (step 12).

**Does not own:**

- the `MfaFactor` contract, the `MfaFactorStore` and `MfaTransactionStore` ports and their adapters, the `mfaFactors` kind and `mfaFactorResolver` — core's (`packages/core/src/mfa/`), with Redis adapters in `@o3co/auth-provider-redis`;
- the WebAuthn factor — `@o3co/auth-provider-webauthn`'s (the ADR's D4);
- the pages: the login page's second step, the MFA page and the account page are the deployment's (D6).

**Why a separate package.** Core mounts no route but discovery and imports no sibling, and the MFA routes are browser routes that need the session package's CSRF guard and its login tail. A package also lets a deployment that opts out install none of it, and lets the factor code move on its own review cadence (D1).

## Configuration

Three sections, each its module's and named after it: `mfa`, the MFA module's; `mfa-totp-factor`, the TOTP factor's module's; `mfa-recovery-code-factor`, the recovery-code factor's. Boot parses each with its module's schema before any factory runs, and hands it to the module's factories. Layer [`config/reference.conf`](config/reference.conf) between your `application.conf` and core's `reference.conf`, as for the WebAuthn package; it carries the defaults and the environment variables that override them. `mfaModule`, `mfaTotpFactorModule` and `mfaRecoveryCodeFactorModule` declare it as their sections' reference, so core's `moduleReferences(modules)` names it among the files to layer.

| Key | Env | Default | Meaning |
| --- | --- | --- | --- |
| `mfa.mode` | `MFA_MODE` | `off` | `required` or `optional`, the two the module honours; `off`, or unset, with the module installed is refused. Any other value is refused before any factory runs, naming `mfa.mode` |
| `mfa.page.url` | `MFA_PAGE_URL` | `/mfa` | The deployment's MFA page, where a step-up starts: the requirement registers it as its step-up page (D6) |
| `mfa.encryptionKeys` | `MFA_ENCRYPTION_KEY` feeds the first entry | none | The key ring, `[{ id?, key }]`: each key canonical base64 of 32 bytes (`openssl rand -base64 32`); the first seals, every key opens (D11). An entry without an `id` is named by its key's fingerprint |
| `mfa-totp-factor.enabled` | `MFA_TOTP_FACTOR_ENABLED` | `true` | Whether the TOTP factor is offered |
| `mfa-totp-factor.algorithm` | `MFA_TOTP_FACTOR_ALGORITHM` | `SHA1` | `SHA1`, `SHA256` or `SHA512`, for new enrollments |
| `mfa-totp-factor.digits` | `MFA_TOTP_FACTOR_DIGITS` | `6` | 6 to 8, for new enrollments |
| `mfa-totp-factor.period` | `MFA_TOTP_FACTOR_PERIOD` | `30` | 15 to 120 seconds, for new enrollments |
| `mfa-totp-factor.window` | `MFA_TOTP_FACTOR_WINDOW` | `1` | 0 to 2 steps either side of now, for every verification |
| `mfa-totp-factor.issuer` | `MFA_TOTP_FACTOR_ISSUER` | for a factor that is on, the hostname of the deployment's issuer — the oauth module's `oauthTokenSettings` when a composition holds it, `oauth.jwt.issuer` otherwise | The issuer an authenticator app shows: well-formed text, not blank, with no control character and no colon |
| `mfa.transactionTtlSeconds` | — | `600` | How long one second-factor ceremony lives, 60 to 1800 seconds; every transaction's expiry is derived from it alone (D8) |
| `mfa.maxAttemptsPerTransaction` | — | `5` | The attempts one transaction allows: 1 to 10 (D21) |
| `mfa.rateLimit.routes` | — | none: the limiter's `defaultLimit` | `{ limit, windowSeconds }`, the budget every `/session/mfa` POST is limited by under the prefix `mfa` (`mfa:ip:<ip>`); the MFA module contributes it for every limiter to read, and a limiter's own `limits.mfa` wins. Given but not a budget a limiter can apply, it refuses boot naming the key |
| `mfa.manage.maxAgeSeconds` | — | `300` | Recent MFA: how long a second factor verified in a session stays recent, 60 to 3600 seconds — what enrolling a factor outside a login, removing one or regenerating recovery codes asks of the session (F4, D16) |
| `mfa-recovery-code-factor.enabled`, `.count` | `MFA_RECOVERY_CODE_FACTOR_ENABLED`, `MFA_RECOVERY_CODE_FACTOR_COUNT` | `true`, `10` | Recovery codes (D25), and how many a set holds, 1 to 20. Nothing reads the section: this build has no recovery codes |
| `mfa.lockout` | — | `threshold` 5, `baseSeconds` 900, `maxSeconds` 86400, `memorySeconds` 86400, `weeklyBudget` 10, `hardLimit` 100, `trustedBrowsers` 5, `trustedBrowserDays` 30 | The subject lock on guessable proofs (D21): each a positive whole number, held to core's `checkMfaLockoutPolicy` — `threshold` at most `hardLimit`, `hardLimit` at most 100, `maxSeconds` at least `baseSeconds` |

A key your `application.conf` sets shadows the substitution `reference.conf` makes for it; repeat the `${?VAR}` line after your value to let the environment override it again. `digits`, `period` and `window` are whole numbers, or their decimal digits as an environment variable carries them.

**The TOTP factor's old path.** `mfa.factors.totp` refuses the boot wherever `mfaTotpFactorModule` is installed (`config-path-relocated`), naming each key's path under `mfa-totp-factor` and the variable `reference.conf` binds it to (a value written at `mfa.factors.totp` itself names the section alone). Its variables, `MFA_TOTP_ENABLED` and `MFA_TOTP_ISSUER`, are bound to no setting and declared renamed on the factor's module (`section.renamedVariables`); `reference.conf` captures them and their new names in `renamed-variables`, so a composition that layers it is judged by what its resolution saw: exported alone, or beside `MFA_TOTP_FACTOR_ENABLED` / `MFA_TOTP_FACTOR_ISSUER` set to a different value, one refuses the boot (`environment-variable-renamed`), naming the new variable and its path; set to the same value as its new name, it boots. Set `MFA_TOTP_FACTOR_ENABLED` or `MFA_TOTP_FACTOR_ISSUER` instead.

**The MFA page's old path.** `endpoints.mfa.url` refuses the boot wherever `mfaModule` is installed (`config-path-relocated`), naming `mfa.page.url` and `MFA_PAGE_URL`. Its variable, `ENDPOINTS_MFA_URL`, is bound to no setting and declared renamed on the MFA module; `reference.conf` captures it and `MFA_PAGE_URL` in `renamed-variables`: exported alone, or beside `MFA_PAGE_URL` set to a different value, it refuses the boot (`environment-variable-renamed`); set to the same value, it boots. Set `MFA_PAGE_URL` instead.

**Key ids and rotation.** An entry written without an `id` — as `reference.conf`'s, which `MFA_ENCRYPTION_KEY` feeds — is named by its key's fingerprint: `k` and the first 16 characters of base64url(HMAC-SHA-256(key, `o3co:mfa:key-id`)), which tells nothing of the key. So a key changed in place leaves what the old one sealed `key_unavailable`, naming the old fingerprint — put that key back — never `unreadable`, which no key cures. An entry written with an `id` keeps it: never change its key in place. To rotate, write the ring in a deployment-owned layer: add the new key last as an entry of its own (a new `id`, or none), then move it first, and keep the old key until nothing sealed under it, and no digest naming it, is left. Opening data sealed under a key that is no longer first logs `mfa_factor_sealed_with_retired_key` (info, the key id) once per key id. Core's envelope seals with a random 96-bit AES-GCM nonce, and a factor's data is re-sealed at every use, so rotate each key well before 2^32 seals under it — the bound NIST SP 800-38D sets for random nonces.

**Refused**, each naming the key and quoting no key or id.

- Before any factory runs (`config-validation-failed`, the key's path with its section's): `mfa.mode` outside `off`, `optional` and `required`; an `mfa.page` that is not a section with a string `url`; in `mfa-totp-factor`, a parameter out of its range, an algorithm it does not take, an `enabled` that is no switch, or an issuer outside its rule; in `mfa-recovery-code-factor`, a key the section does not know, or a count outside its range; a factor's section missing, because `reference.conf` is not layered; a section written as a value rather than a section of keys.
- By the MFA module's factory, a `RangeError` whose message starts with the key: `mfa.mode` `off` or unset, which a missing `mfa` section reads as; an empty ring or one without `MFA_ENCRYPTION_KEY`; a key that is not canonical base64 of 32 bytes; a duplicate id — a fingerprint that equals a written id among them — or one outside `A-Za-z0-9_-` (1 to 64 characters); one key listed twice, whatever ids it is written under; a transaction's life outside 60 to 1800 seconds, its attempts outside 1 to 10, recent MFA's window outside 60 to 3600 seconds, or a lock core's rule refuses.
- By the TOTP factor's factory: for a factor that is on and has no issuer written, an `oauth.jwt.issuer` with no host to default it to (naming `MFA_TOTP_FACTOR_ISSUER`).

`mfaConfigSchema` holds each shape and range of the `mfa` section: the mode, the page (a section with a string `url`, which may be left out), the transaction's life (60 to 1800 seconds) and attempts (1 to 10), and each lock field a positive whole number. Reading the settings makes the rest: the ring's refusals and the sample key's, where the keys are decoded and the environment is known, and core's `checkMfaLockoutPolicy` on how the lock's fields relate to each other (`threshold` at most `hardLimit`, `hardLimit` at most 100, `maxSeconds` at least `baseSeconds`, every duration within the Date range). The TOTP factor's module alone reads `mfa-totp-factor`; `mfaModule` reads every `mfa` key above and no factor's section, so a composition without the TOTP factor — its factors all another package's — is never refused over TOTP's.

**The development sample key.** [`MFA_DEVELOPMENT_SAMPLE_KEY`](src/config.mts) is a published key a development configuration may put in the ring in place of a key of its own. Everyone holds it, so it is refused — wherever it sits in the ring — when the environment the configuration was selected by is `production` or `staging`, when `NODE_ENV` is either (each read whatever its case and the whitespace around it), and under `core.deployment.mode = "multi"`, which the module reads from core's `deploymentMode` slot and never off the configuration — the rule the Redis federation stores' plaintext mode follows too. The environment reaches the refusal from the composition root (the standalone passes `CONFIG_ENV || NODE_ENV`) as `mfaModule({ environment })`. Where it is accepted, the module says so once at boot: `mfa_development_sample_key_in_use` (warn).

## Installing

Installed is on (the session-admission ADR's D7): a composition that wants no MFA installs none of this package, and an `mfa` section it writes is one no module reads. The standalone template reads `mfa.mode` itself before it chooses its modules, and declares `mfa` from it, until it installs this package at the MFA ADR's build-order step 20. One that wants it lists `mfaModules({ environment })` — the TOTP factor's module, the recovery-code factor's and `mfaModule` — with an `MfaFactorStore` and an `MfaTransactionStore` (core's memory modules on one replica, `@o3co/auth-provider-redis`'s on several), the session package's login and its user-session store; sets `mfa.mode` to `optional` or `required`; and declares `"mfa"` in `core.sessionRequirements.expected`.

`mfaModule` requires `mfaFactorResolver`, `mfaFactorStore`, `mfaTransactionStore`, `userSessionStore`, `sessionRequirementResolver` and `deploymentMode` — core's, filled from `core.deployment.mode`, which the development sample key's refusal reads — and reads `auditSink` — its absence declared with `audit.sink.type = "none"` — and `logger`. It mounts `mfa-routes` (`MFA_ROUTES_ID`) at `/session/mfa`, after the session middleware; nothing answers there before step 8's third part. It contributes `mfa.rateLimit.routes`, when the section gives it, as the budget of the `mfa` prefix (`MFA_RATE_LIMIT_PREFIX`). The boot is refused:

- `mfa.mode = "off"`, or unset, with the module installed: remove the module, or set the mode;
- once every factor has registered, for what a first binding's `hints.enrollable` would have to list, each `cause` carrying a `reason`: an enabled factor — this package's or another's — whose kind core's hint grammar refuses (`^[a-z][a-z0-9_-]{0,63}$`; `MfaFactorKindUnhintableError`, `mfa-factor-kind-unhintable`, naming the kind); more than 16 enabled counting factors, the most a hint list carries (`MfaTooManyFactorsError`, `mfa-too-many-factors`); and `mfa.mode = "required"` with no counting factor enabled, which nobody could meet (`MfaNoCountingFactorError`, `mfa-no-counting-factor`: it names the enabled factors that do not count, and asks for an installed counting factor's `enabled` key — the TOTP factor's, `mfa-totp-factor.enabled` (`MFA_TOTP_FACTOR_ENABLED`), where its module is installed);
- without a `userSessionStore`, at the requires-closure, naming the slot;
- for a key ring, a transaction life, attempts or a lock the settings refuse (above), and without `mfa.page.url`, the page a step-up starts on (`MFA_PAGE_URL`; `reference.conf` ships `/mfa`);
- by core, when the requirement's reach is not what the enabled factors reach, when `mfa` is not declared in `core.sessionRequirements.expected`, or when another installed requirement declares the second-factor authority too (`duplicate-second-factor-authority`).

A `userSessionStore` without `recordSecondFactor` (core's `supportsSecondFactorUpdate`) cannot record a step-up: the module boots, says so once at warn (`mfa_step_up_unsupported`, with the adapter's `kind`), and the requirement sends a session to log in again where it would step it up.

## The `mfa` requirement

Registered as `sessionRequirements.mfa` ([`src/requirement.mts`](src/requirement.mts); the session-admission ADR's D6):

- **The second-factor authority** — the requirement declares it (`secondFactorAuthority`), which is what core weighs, never the name: core lets the authority alone reach and add a second factor's `amr` values and `mfaAt`, holds its completion of a login to a verified second factor, and binds it at boot to `mfaFactorResolver`, `mfaFactorStore` and `mfaTransactionStore`. The name `mfa` is this package's own.

- **Reach** — what a step-up can add to a session: each enabled factor's `amrValues`, and `mfa` when one of them adds it (TOTP: `otp` and `mfa`), read once — at boot, after every factor registered — and kept: core seals that reach and merges with it, and the requirement's own verdicts read it too. The page a step-up starts on is `mfa.page.url`; the one remediation the requirement declares is `mfa.step_up`, the step-up route's.
- **At each use** (`admit`), under `optional` every session is met. Under `required`: a session a cookie, a code or a link carries is met when its primary is a federation, or when a second factor was verified in it (`mfaAt`); a password session without one is stepped up to the MFA page — or unmet, when no factor is enabled, and sent to log in again when the session store cannot record a step-up — and a session whose primary cannot be told, or no live session, is sent to log in again. An action graded `grants_nothing` — device verification's `device.lookup` and `device.deny` — is met on any live session a cookie, a code or a link carries, whatever it is named: a user refuses a phished device request without a step-up. A token is judged on its own `amr` whatever the grade: `grants_nothing` exempts only an admission a record carries. The requirement decides by grade and names no action. A refresh token is judged on what it was issued with, its own `amr`, whether or not it names a live session: a federation's is met; one carrying a factor's own second-factor value (`otp`, `hwk`, `swk`, `email`, `recovery` — never `mfa` alone) is met whatever its primary, so a passkey sign-in's `["hwk"]` token keeps refreshing; a password alone is unmet; anything else — no `amr` at all (a token issued before #481), an unknown value — is sent to log in again. An action that adds a way into the account (`credential_change`) is held to the same rule until the recent-MFA rule arrives (steps 12 and 14).
- **At a password login** (`admitPrimary`), the subject's factor records are listed — a store that cannot answer is `503`, with nothing written. Any record at all interrupts the login for a second factor; a record this deployment cannot use (a retired kind, recovery codes alone) is never read as none. With no record, `optional` establishes the session as before, and `required` interrupts it for a first binding — when every counting factor refuses this user (`enrollable(user)`), the list is empty and each such login is said at warn (`mfa_enrollment_nothing_enrollable`, the kinds alone). No enrollment witness is read before step 9, the step that makes a first binding possible. A federated login is not asked (the federation callback does not consult admission in this release).

## The login's interruption

A password login the requirement interrupts is answered `403` once the express session is regenerated — left unauthenticated — and the login's MFA transaction opened, bound to the regenerated session (`binding: { kind: "session", id }`, which every later use compares whole); no session is written until the ceremony completes. The body is the closed shape core validates, and the page reads nothing else:

```json
{ "error": "mfa_required", "transaction": "<id>", "expires_in": 600 }
```

```json
{ "error": "mfa_enrollment_required", "transaction": "<id>", "expires_in": 600,
  "hints": { "enrollable": ["totp"], "email_proof": false } }
```

- `transaction` is 32 random bytes, base64url. It is not a bearer: every use compares the session it is bound to with the browser's, so the page keeps the cookie the `403` set. It travels only in request bodies and the `MFA-Transaction` request header, which the MFA routes will read (step 8's third part) — never in a URL.
- `expires_in` is `mfa.transactionTtlSeconds`; the transaction expires then, and the user starts again from the password.
- `mfa_required`: the subject holds a factor; the page asks for it.
- `mfa_enrollment_required` (`required`, no factor on record): `hints.enrollable` lists the counting factors this user may enroll, in registration order; `hints.email_proof` says whether an account-email proof comes first — `false` until step 9 wires mail.
- The `403` carries a fresh CSRF token, as a successful login does.

## The TOTP factor

`mfaTotpFactorModule` ([`src/totp/module.mts`](src/totp/module.mts)) contributes the factor ([`src/totp/factor.mts`](src/totp/factor.mts)), built from its section, `mfa-totp-factor`; it answers `null` when the factor is switched off, which leaves the kind absent from `mfaFactorResolver`. It holds no state and reads no key.

- A verification adds `otp`, and `mfa` beside it (D14). The factor counts as MFA, and its six-to-eight-digit proof is guessable, so the subject lock applies to it (D21).
- A code is accepted at the steps `T - window` to `T + window`, and only when its step is after the factor's `lastUsedStep` — the same code twice, or an older code once a newer one was accepted, is refused as `replayed` (RFC 6238 §5.2). There is no drift resynchronisation (D22). HOTP and TOTP are pinned by RFC 4226 Appendix D's and RFC 6238 Appendix B's vectors.
- Each factor keeps the algorithm, digits and period it was enrolled with, so changing them in the configuration never breaks an enrollment; the window applies to every verification.
- Enrolling hands out a secret of the algorithm's output length (20, 32 or 64 bytes) in RFC 4648 base32 without padding, and the `otpauth://totp/<issuer>:<account>?secret=…&issuer=…&algorithm=…&digits=…&period=…` URI authenticator apps read, the account being the user's email, else the username — well-formed text, or the enrollment is refused. The page renders it as a QR code (D6). The proof of possession binds the factor at the step it matched.

## API

| Export | What it is |
| --- | --- |
| [`mfaModules`](src/module.mts) | What a composition lists: the TOTP factor's module, the recovery-code factor's and `mfaModule` |
| [`mfaModule`](src/module.mts) | The module registering the `mfa` requirement and mounting the MFA routes |
| [`MfaModuleOptions`](src/module.mts) | `{ environment? }`: the name the configuration was selected by, for the sample key's refusal |
| [`MFA_ROUTES_ID`](src/module.mts) | The id of the MFA routes' contribution, `mfa-routes` |
| [`MFA_RATE_LIMIT_PREFIX`](src/module.mts) | The prefix the MFA routes limit under and the module contributes their budget for, `mfa` |
| [`MFA_ADMISSION_ACTIONS`](src/admissionActions.mts), `MfaAdmissionAction` | The admission actions the MFA routes admit a browser session for, with their grades: one action, `mfa.manage`, graded `credential_change` — enrolling a factor outside a login, removing one, regenerating recovery codes. Declared, and registered by no module: the module whose route admits a session contributes it as its `admissionActions` |
| [`mfaTotpFactorModule`](src/totp/module.mts) | The module contributing `mfaFactors.totp` |
| [`mfaRecoveryCodeFactorModule`](src/recovery/module.mts) | The recovery-code factor's module, `mfa-recovery-code-factor`: its section alone |
| [`mfaConfigSchema`](src/config.mts) | The shapes and ranges of the MFA module's `mfa` section — the mode, the page, the transaction's life and attempts, the lock's fields, recent MFA's window — not the ring's, the sample key's or how the lock's fields relate, which reading the settings checks |
| [`MFA_DEVELOPMENT_SAMPLE_KEY`](src/config.mts) | The published development key, refused outside development |
