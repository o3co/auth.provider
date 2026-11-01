# opening

Internal module of `login-passkey`: what follows an assertion, up to the session.

## Responsibilities
- Checks the revocation, the user and the holding, then logs in through `login-gates`, and answers.

## Not here
- The assertion (`routes`). The facts (`facts`). The gates themselves (`login-gates`).

## Offers
- `openingIn` → a function (request, what the assertion proved, the answer once done) → the answer.

## Invariants
- A revocation of the subject since the challenge was made (`subject-revocation`'s `check`, at the challenge's time) refuses: before the facts are read (step 1), before a held login's hold is handed on, after its transaction began (step 5), and the login states the challenge's time as `provenSince`, which `session` compares once it opens (step 6).
- A subject `users` does not know is refused (`unknown_user`); one it cannot look up is `503`. A subject holding no passkey once settled with the witness is refused (`unknown-credential`).
- A gate's refusal is refused (`gate_refused`), opening nothing. A hold goes out with the gate's answer and cookies.
- A refusal is `401` `passkey_login_failed`, its reason recorded.

## Depends on
- `http`, `passkeys` (`passkeyHolders`), `subject-revocation`, `login-gates`, `session`; the internal modules `facts` and `audited`
