# @o3co/auth-provider-mfa

Last updated: 2026-09-29

Multi-factor authentication for [`auth.provider`](../../README.md): a second factor after a password login, and a step-up when a relying party asks for one at `/authorize` — the package [the MFA ADR](../core/docs/adr/2026-09-25-multi-factor-authentication.md) designs (its D1).

> **Private.** The package is `"private": true`: built and tested in this workspace, never published, until the standalone template wires it (the ADR's build-order step 20). No release publishes a second-factor verification before the lock that bounds guessing exists (step 10). Nothing here is a supported API yet.

## Responsibility

**Role.** The MFA coordinator and everything it needs that is not a shared port: the `mfa` session requirement it contributes to core's session admission, the browser API under `/session/mfa/*`, the factors that are not another package's, the key ring and what is sealed under it, lockout and audit. Core holds the ports the factors and the stores share; a factor from another package (WebAuthn's) reaches the coordinator as an `mfaFactors` contribution.

**Owns, as of the build-order step 8's first part:**

- the TOTP factor (RFC 6238 on `node:crypto`), contributed as `mfaFactors.totp` by `mfaTotpFactorModule`;
- the `mfa` keys this package reads — the key ring and `mfa.factors.totp` — their defaults ([`config/reference.conf`](config/reference.conf), exported as `@o3co/auth-provider-mfa/reference.conf`) and their refusals, the development sample key among them;
- sealing a factor's data and a ceremony's state under the key ring, and keyed digests for codes that are compared and never recovered — the coordinator's, so that no factor holds a key.

**Not yet here** — the rest of step 8: `mfaModule` and the `mfa` requirement it registers, MFA transactions, the routes, verification and completing a login, audit. Until they land, installing this package's module adds a factor that nothing asks for: `mfa.mode` other than `off` is still refused at boot (`session-requirement-missing`).

**Does not own:**

- `mfa.mode` — core's key, which the MFA requirement will read through core's `readMfaMode`;
- the `MfaFactor` contract, the `MfaFactorStore` and `MfaTransactionStore` ports and their adapters, the `mfaFactors` kind and `mfaFactorResolver` — core's (`packages/core/src/mfa/`), with Redis adapters in `@o3co/auth-provider-redis`;
- the WebAuthn factor — `@o3co/auth-provider-webauthn`'s (the ADR's D4);
- the pages: the login page's second step, the MFA page and the account page are the deployment's (D6).

**Why a separate package.** Core mounts no route but discovery and imports no sibling, and the MFA routes are browser routes that need the session package's CSRF guard and its login tail. A package also lets a deployment that opts out install none of it, and lets the factor code move on its own review cadence (D1).

## Configuration

The `mfa` section beside core's `mfa.mode`. Core's `AppConfigSchema` passes the rest of the section through, and this package reads it. Layer [`config/reference.conf`](config/reference.conf) between your `application.conf` and core's `reference.conf`, as for the WebAuthn package; it carries the defaults and the environment variables that override them.

| Key | Env | Default | Meaning |
| --- | --- | --- | --- |
| `mfa.encryptionKeys` | `MFA_ENCRYPTION_KEY` feeds the first entry | none | The key ring, `[{ id?, key }]`: each key canonical base64 of 32 bytes (`openssl rand -base64 32`); the first seals, every key opens (D11). An entry without an `id` is named by its key's fingerprint |
| `mfa.factors.totp.enabled` | `MFA_TOTP_ENABLED` | `true` | Whether the TOTP factor is offered |
| `mfa.factors.totp.algorithm` | — | `SHA1` | `SHA1`, `SHA256` or `SHA512`, for new enrollments |
| `mfa.factors.totp.digits` | — | `6` | 6 to 8, for new enrollments |
| `mfa.factors.totp.period` | — | `30` | 15 to 120 seconds, for new enrollments |
| `mfa.factors.totp.window` | — | `1` | 0 to 2 steps either side of now, for every verification |
| `mfa.factors.totp.issuer` | `MFA_TOTP_ISSUER` | for a factor that is on, the hostname of `oauth.jwt.issuer` | The issuer an authenticator app shows: well-formed text, not blank, with no control character and no colon |
| `mfa.transactionTtlSeconds` | — | `600` | How long one second-factor ceremony lives, 60 to 1800 seconds; every transaction's expiry is derived from it alone (D8) |
| `mfa.maxAttemptsPerTransaction` | — | `5` | The attempts one transaction allows: a positive whole number (D21) |
| `mfa.lockout` | — | `threshold` 5, `baseSeconds` 900, `maxSeconds` 86400, `memorySeconds` 86400, `weeklyBudget` 10, `hardLimit` 100, `trustedBrowsers` 5, `trustedBrowserDays` 30 | The subject lock on guessable proofs (D21): each a positive whole number, held to core's `checkMfaLockoutPolicy` — `threshold` at most `hardLimit`, `hardLimit` at most 100, `maxSeconds` at least `baseSeconds` |

A key your `application.conf` sets shadows the substitution `reference.conf` makes for it; repeat the `${?VAR}` line after your value to let the environment override it again.

**Key ids and rotation.** An entry written without an `id` — as `reference.conf`'s, which `MFA_ENCRYPTION_KEY` feeds — is named by its key's fingerprint: `k` and the first 16 characters of base64url(HMAC-SHA-256(key, `o3co:mfa:key-id`)), which tells nothing of the key. So a key changed in place leaves what the old one sealed `key_unavailable`, naming the old fingerprint — put that key back — never `unreadable`, which no key cures. An entry written with an `id` keeps it: never change its key in place. To rotate, write the ring in a deployment-owned layer: add the new key last as an entry of its own (a new `id`, or none), then move it first, and keep the old key until nothing sealed under it, and no digest naming it, is left. Opening data sealed under a key that is no longer first logs `mfa_factor_sealed_with_retired_key` (info, the key id) once per key id. Core's envelope seals with a random 96-bit AES-GCM nonce, and a factor's data is re-sealed at every use, so rotate each key well before 2^32 seals under it — the bound NIST SP 800-38D sets for random nonces.

**Refused**, each a `RangeError` whose message starts with the key and quotes no key or id: an empty ring or one without `MFA_ENCRYPTION_KEY`; a key that is not canonical base64 of 32 bytes; a duplicate id — a fingerprint that equals a written id, or one key listed twice, among them — or one outside `A-Za-z0-9_-` (1 to 64 characters); a TOTP parameter out of its range, or an issuer outside its rule; a transaction's life outside 60 to 1800 seconds, its attempts not a positive whole number, or a lock core's rule refuses; for a factor that is on and has no issuer written, an `oauth.jwt.issuer` with no host to default it to (naming `MFA_TOTP_ISSUER`); a section missing because `reference.conf` is not layered. `mfaConfigSchema` holds the shapes and TOTP's ranges; the ring's refusals and the sample key's are made when the settings are read, where the keys are decoded and the environment is known.

**The development sample key.** [`MFA_DEVELOPMENT_SAMPLE_KEY`](src/config.mts) is a published key a development configuration may put in the ring in place of a key of its own. Everyone holds it, so it is refused — wherever it sits in the ring — when the environment the configuration was selected by is `production` or `staging`, when `NODE_ENV` is either (each read whatever its case and the whitespace around it), and under `deployment.mode = "multi"`: #473's rule, as for the Redis federation stores' plaintext mode. The environment reaches the refusal from the composition root (the standalone passes `CONFIG_ENV || NODE_ENV`), through the MFA module's options once that module lands.

## The TOTP factor

`mfaTotpFactorModule` ([`src/totp/module.mts`](src/totp/module.mts)) contributes the factor ([`src/totp/factor.mts`](src/totp/factor.mts)), built from `mfa.factors.totp`; it answers `null` when the factor is switched off, which leaves the kind absent from `mfaFactorResolver`. It holds no state and reads no key.

- A verification adds `otp`, and `mfa` beside it (D14). The factor counts as MFA, and its six-to-eight-digit proof is guessable, so the subject lock applies to it (D21).
- A code is accepted at the steps `T - window` to `T + window`, and only when its step is after the factor's `lastUsedStep` — the same code twice, or an older code once a newer one was accepted, is refused as `replayed` (RFC 6238 §5.2). There is no drift resynchronisation (D22). HOTP and TOTP are pinned by RFC 4226 Appendix D's and RFC 6238 Appendix B's vectors.
- Each factor keeps the algorithm, digits and period it was enrolled with, so changing them in the configuration never breaks an enrollment; the window applies to every verification.
- Enrolling hands out a secret of the algorithm's output length (20, 32 or 64 bytes) in RFC 4648 base32 without padding, and the `otpauth://totp/<issuer>:<account>?secret=…&issuer=…&algorithm=…&digits=…&period=…` URI authenticator apps read, the account being the user's email, else the username — well-formed text, or the enrollment is refused. The page renders it as a QR code (D6). The proof of possession binds the factor at the step it matched.

## API

| Export | What it is |
| --- | --- |
| [`mfaTotpFactorModule`](src/totp/module.mts) | The module contributing `mfaFactors.totp` |
| [`mfaConfigSchema`](src/config.mts) | The shapes of the `mfa` keys this package reads, and TOTP's ranges — not the ring's or the sample key's refusals, which reading the settings makes |
| [`MFA_DEVELOPMENT_SAMPLE_KEY`](src/config.mts) | The published development key, refused outside development |
