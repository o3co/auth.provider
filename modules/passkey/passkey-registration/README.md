# passkey-registration

## Responsibilities
- Registers passkeys from a session: routes that ask `passkeys`' `registrations` for creation options, then to keep the passkey a response creates.
- Lists, renames and removes the session's subject's passkeys, through `passkeys`.

## Not here
- The ceremonies (`webauthn`). The passkey records, the limit per subject and the user handle (`passkeys`). Whether a session may enter at `credentials` (the entry requirements `session` composes). Logging in with a passkey (`webauthn-login`).

## Offers
- Composition definition. It comes wherever `passkeys` and `session` are both composed, so a deployment that keeps passkeys gets it too.
- Route `POST /oauth/webauthn/registration/options`: `passkeys`' creation options for the session's subject.
- Route `POST /oauth/webauthn/registration/verify`: takes `{response, nickname?}`, answers `{credentialId, transports, backedUp}`, with `transports` only when the authenticator names some.
- Route `GET /oauth/webauthn/registrations`: `{passkeys: [{credentialId, nickname?, transports?, backupEligible, backedUp, createdAt?}]}`, the subject's own; `createdAt` (epoch ms) only for one registered where it was kept.
- Routes `POST /oauth/webauthn/registrations/rename` (`{id, nickname}` → `{}`) and `/remove` (`{id}` → `{last}`, `true` when the subject holds no passkey after); an id the subject does not hold is `404 not_found`.
  - The POST routes take JSON or no body, use `csrf`'s policy and `rate-limit`'s requests policy; every route enters the session at level `credentials`. Every answer is `no-store`.
  - Errors: `401 unauthorized`, `403` `csrf` or the requirement's answer, `400` (`invalid_request`, `challenge_invalid`, `credential_id_conflict`, `credential_limit`, or the ceremony's refusal: `origin_mismatch`, `top_origin_mismatch`, `challenge_mismatch`, `rp_id_mismatch`, `algorithm_not_allowed`, `attestation_invalid`, `user_verification_required`, `unknown`), `415` for another body, `429 rate_limited`, `503` `temporarily_unavailable` (a store) or `service_unavailable` (requests not counted).
- Audit events `passkey.registered`, `passkey.renamed` and `passkey.removed`, with the subject and `source` (when determined), once done; never a credential id, nickname or ceremony. Declared in `./audit-events`, listed in the audit event reference.
- Operator section: `requests` (1–100000, default 60) in `window` (1s–1d, default `5m`, written with its unit), over the POST routes.

## Invariants
- The subject comes from the session, never from the body.
- A registration a revocation since its challenge reaches (`subject-revocation`, a reset's included) leaves nothing usable: `passkeys` asks this check once its record is written and again once it is listed, and keeps nothing on a no or a failure. It is answered `401 unauthorized`, recording nothing.
- `response` must be an object, and a `nickname` sent is a label (`labels`' `isLabel`); otherwise `invalid_request`, before `passkeys` is asked.
- Client data that does not read is `invalid_request`; `passkeys`' `no-challenge` is `challenge_invalid`.
- `credential_id_conflict` tells a signed-in session that some subject lists an id. Ids are high-entropy, made by the authenticator, so this answers only for an id already known.
- Each refusal of `passkeys` maps to one error word here, and nowhere else.
- A store that cannot tell is `503`, never a refusal.
- Entry at `credentials` is `mfa`'s judgement where it is composed; else `session` needs a recent sign-in at a known time.

## Depends on
- `kernel`, `http`, `request-source`, `labels`, `passkeys`, `session`, `subject-revocation`, `csrf`, `rate-limit`, `audit`
