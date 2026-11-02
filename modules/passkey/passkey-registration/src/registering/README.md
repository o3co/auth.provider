# registering

Internal module of `passkey-registration`: registering a passkey from a session.

## Responsibilities
- Asks `passkeys`' `registrations` for creation options, then to keep the passkey a response creates, unless a revocation since its challenge reaches it.

## Not here
- The ceremony and the records (`webauthn`, `passkeys`). Entering the session and the POST route (`exchange`).

## Offers
- `registeringRoutes` (`exchange`, `registrations`, `subject-revocation`'s check, audit) → `options` and `verify`, as the package's card says.

## Invariants
- `response` must be an object, and a `nickname` sent is a label (`labels`' `isLabel`); otherwise `invalid_request`, before `passkeys` is asked.
- Each refusal of `passkeys` maps to one error word here, and nowhere else; `revoked` is `401 unauthorized`, recording nothing.
- `passkey.registered` is recorded once the passkey is kept, with the subject and `source`.

## Depends on
- `passkeys`, `subject-revocation`, `labels`, `audit`, `http`; `exchange`; the package's audit events.
