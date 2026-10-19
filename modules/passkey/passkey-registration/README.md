# passkey-registration

## Responsibilities
- Registers passkeys from a session: routes that ask `webauthn`'s `registrations` for creation options, then to keep the passkey a response creates.

## Not here
- The ceremonies, the passkey records, the limit per subject and the user handle (`webauthn`). Whether a session may enter at `credentials` (the entry requirements `session` composes). Logging in with a passkey (`webauthn-login`).

## Offers
- Composition definition. It comes wherever `webauthn` and `session` are both composed, so a deployment that adds a passkey feature gets it too.
- Route `POST /oauth/webauthn/registration/options`: `webauthn`'s creation options for the session's subject.
- Route `POST /oauth/webauthn/registration/verify`: takes `{response, nickname?}`, answers `{credentialId, transports, backedUp}`, with `transports` only when the authenticator names some.
  - Both take JSON or no body, use `csrf`'s policy and `rate-limit`'s requests policy, and enter the session at level `credentials`. Every answer is `no-store`.
  - Errors: `401 unauthorized`, `403` `csrf` or the requirement's answer, `400` (`invalid_request`, `challenge_invalid`, `credential_id_conflict`, `credential_limit`, or the ceremony's refusal: `origin_mismatch`, `top_origin_mismatch`, `challenge_mismatch`, `rp_id_mismatch`, `algorithm_not_allowed`, `attestation_invalid`, `user_verification_required`, `unknown`), `415` for another body, `429 rate_limited`, `503` `temporarily_unavailable` (a store) or `service_unavailable` (requests not counted).
- Operator section: `requests` (1–100000, default 60) in `window` (1s–1d, default `5m`, written with its unit), over both routes.

## Invariants
- The subject comes from the session, never from the body.
- `response` must be an object, and a `nickname` sent is a label (`labels`' `isLabel`); otherwise `invalid_request`, before `webauthn` is asked.
- Client data that does not read is `invalid_request`; `webauthn`'s `no-challenge` is `challenge_invalid`.
- `credential_id_conflict` tells a signed-in session that some subject lists an id. Ids are high-entropy, made by the authenticator, so this answers only for an id already known.
- Each refusal of `webauthn` maps to one error word here, and nowhere else.
- A store that cannot tell is `503`, never a refusal.
- Entry at `credentials` is `mfa`'s judgement where it is composed; else `session` needs a recent sign-in at a known time.

## Depends on
- `kernel`, `http`, `labels`, `webauthn`, `session`, `csrf`, `rate-limit`
