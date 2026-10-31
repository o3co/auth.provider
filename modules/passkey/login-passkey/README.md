# login-passkey

## Responsibilities
- Provides the passkey login into a browser session: options whose challenge only the browser that asked redeems, then the assertion, which opens a session for its subject through `login-gates`. Its internal modules: `routes` (the two routes and the assertion), `opening` (the checks after it and the session), `facts` (the login's facts), `audited` (what it records), `gate` (`credential-policy`).
- Where the operator says so, refuses a password login of a subject holding a passkey (the gate `credential-policy`).

## Not here
- Passkeys, assertions and whether a subject holds one: `passkeys`. Steps after the assertion, such as a second factor: `login-gates` and its gates. Registering passkeys: `passkey-registration`. The login screen: the deployer's.

## Offers
- Routes `POST /session/login/passkey/options` (no body needed) and `POST /session/login/passkey` (JSON: `response`, the assertion; `redirect_to`).
  - Options are the same for everyone (discoverable credentials, no credential listed, usable with `mediation: conditional`) and set the requester's cookie for the challenge's lifetime (`webauthn`'s `challenge-lifetime`).
  - The login answers `200` with `{}` or `{redirect_to}`; a gate holding the login is `403` with the gate's answer and cookies, unread.
  - Every refusal is `401` `{"error": "passkey_login_failed"}`. Other errors: `csrf` (403), `repeated_parameter`, `invalid_redirect`, `invalid_request` (400), too many requests (429), a login's body other than JSON (415), `temporarily_unavailable` (503, a store) or `service_unavailable` (503, requests not counted).
- Contribution to `login-gates`: the amr a passkey login proves, `pop`, and `mfa` where `counts-as-mfa` and the authenticator verified the user; and the gate `credential-policy`.
- Audit events (declared in `./audit-events`): `passkey.session.opened`, `passkey.session.held`, `passkey.session.refused` (`reason`), `passkey.password_refused`, each with the `source` where `request-source` determined it.
- Operator section: `counts-as-mfa` (default true, and no weakening: holding the key and the user verified in one operation make a multi-factor cryptographic authenticator, so it warns of nothing), `attempts` per source on each route (1–100, default 20) in `window` (1m–1d, default `15m`), `password` (`allowed`, the default, or `refused-when-held`), `password-exempt-group` (under `refused-when-held`, every start warns `login-passkey.password_exempt_group`).

## Invariants
- Checks run in this order on both routes: `csrf`, then attempts per source; on the login, then repeated parameters, the destination, the assertion's presence.
- An assertion is redeemed only with the cookie its options set: another browser's, or none, is refused as the assertion's `challenge`. Every answer the login's handler gives ends that cookie; one refused before it (csrf, the request limit, the body) takes no challenge.
- A refusal tells nothing of why: whether the credential is registered, the user known or a revocation landed is the same `401`; the reason is recorded only.
- The login's facts: the assertion's subject, the amr, the session's opening as the authentication time (`opening`), and the user's attributes from `users`. The amr is `pop`, with `mfa` (`mfa-extensions`' `secondFactorAmr`) added only where `counts-as-mfa` is on and the assertion says the authenticator verified the user; with `mfa`, the gate `mfa` passes the login unasked (`mfa-flows`' card).
- A revocation of the subject since the challenge was made refuses the login before the gates, before a gate's hold is handed on, and once a session opened, closing it before its cookie goes out.
- A subject `users` does not know is refused; one it cannot look up by subject is `503`, so the ledger must answer by subject.
- Before the gates, whether the subject holds a passkey is settled with the witness composed, which fills its mark there.
- `credential-policy` runs before `mfa` (gates run by name), and again when a login a later gate held resumes, before the gates after it.
- With `password = refused-when-held`, a password login (amr `pwd`) of a subject holding a passkey is refused, but in `password-exempt-group`: a federated login whose upstream amr maps to `pwd` too. Its caller answers it with its own failure; the subject and source are recorded as `passkey.password_refused`. Boot is refused in that mode without a passkey witness composed, as a lost passkey store would read as holding none.
- Answers are never cached. An audit event never carries a credential id or anything the request sent.

## Depends on
- `kernel`, `http`, `login-gates` (through its internal modules: `passkeys`, `webauthn`, `cookies`, `csrf`, `rate-limit`, `session`, `subject-revocation`, `users`, `login-attributes`, `mfa-extensions`, `audit`, `request-source`)
