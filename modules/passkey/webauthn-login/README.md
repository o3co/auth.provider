# webauthn-login

## Responsibilities
- Contributes the passkey login grant `urn:o3co:oauth:grant-type:webauthn` to `grants`' grant extension point.
- Answers request options for a passkey login: the same for everyone, the challenge made for the client that asks.
- Declares the amr this login gives: `hwk`, which means only possession of the key and includes no user verification.

## Not here
- Checking a ceremony, and keeping credentials and challenges: `webauthn`.
- Client authentication, the body a grant takes, and whether it is allowed: `token-endpoint`.
- Refresh families: `refresh`. The token format: `tokens`.
- A browser login: there is none, so no session opens.

## Offers
- Composition definition, and `passkeyAmr` (`["hwk"]`).
- The grant takes a JSON body only: `assertion` (the authenticator's response, an object) and `scope`.
- Route `POST /oauth/webauthn/authentication/options`: takes JSON, a form or no body, and reads only `client_id`.
  - It answers `passkeys`' options with `no-store`, their challenge made for that client.
  - A missing `client_id`, or one that is not one non-empty string, is `400 invalid_request`.
- Audit event `passkey.login.refused`, with `client` and `reason`: a kind from a fixed list, one per refusal of `passkeys`, and `authentication_revoked`.
- Operator section: `requests` (1–100000, default 60) in `window-seconds` (1–86400, default 60), for the options route.

## Invariants
- Order: the assertion's shape, then `passkeys` (user handle, the challenge once and its client, signature, count), then the scope, then the subject's revocation boundary, then the access token, then the refresh token.
- A missing assertion is `invalid_request`; one that is not an object is `invalid_grant`.
- Every refusal of `passkeys`, and the revocation boundary, is the same `invalid_grant`, so no answer tells whether a credential is registered.
- A challenge made for another client is one of those refusals.
- The audit event holds no credential id and nothing else the request sent.
- The subject is the passkey's holder.
- The authentication time is when the challenge was made, and is what the revocation boundary is compared with.
- Scope and audience are the client's allowance (`client-allowance`); beyond it, `invalid_scope`.
- The access token is the client's, bound to the request's binding, with amr `hwk` and the authentication time, issued through `tokens`' issuance policies without a session; a refusal starts no family. The policies are first asked once `passkeys` has taken the challenge, since only then is the holder known.
- The amr is `hwk` whatever the passkey's backup eligibility; the second factor's rule (`swk` when backup eligible) does not apply to a login.
- The refresh token starts a family bound to no session, only for a client allowed `refresh_token`, after the access token; it carries the same amr and time.
- The options route lists no credential and reads no store but the challenge's.
- A store that cannot answer is `503`, never a refusal.

## Depends on
- `kernel`, `http`, `grants`, `client-allowance`, `webauthn`, `refresh`, `subject-revocation`, `issuer`, `rate-limit`, `audit`
