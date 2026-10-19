# mfa-management

## Responsibilities
- Owns the routes for managing factors from within a session (list, name, remove, reissue recovery codes).

## Not here
- The decisions on factors and the label's shape (`mfa`). Session records and entry (`session`). Transactions, enrollment, step-up and lockouts (`mfa-flows`).

## Offers
- Composition definition.
- Routes under `/session/mfa/`, whose URLs outside users rely on: `GET factors`, `POST factors/rename`, `POST factors/remove`, `POST recovery-codes`.
- `GET factors` answers `200 {factors}`, the session's factors as `mfa` shows them (`id`, `kind`, and `label` where one is set).
- `POST factors/rename` takes `factor_id` and `label`, `POST factors/remove` takes `factor_id`; each answers `200 {}`, or `404 unknown_factor` for a factor the subject does not hold. A label refused is `400 invalid_request` (`invalid label`).
- `POST factors/remove` of the last counting factor under `mfa`'s required mode is `409 mfa_last_factor`.
- `POST recovery-codes` answers `200 {recovery_codes}`; without a counting factor `409 mfa_no_qualifying_factor`, and `404 unknown_kind` when no kind of recovery codes is composed.
- Without a live session, `401 login_required`; a session short of the level is `403` with the requirement's answer. A store that cannot answer is `503 temporarily_unavailable`. Every answer is `no-store`.
- Operator section: `requests` (POSTs per source in each window, over the three POSTs, 1–100000, default 60), `window` (1s–1d, default `5m`, written with its unit).

## Invariants
- The list needs a live session; the others enter it at the credential-changing level (`mfa` contributes the requirement).
- Removing a factor and reissuing codes also ask a second factor proven recently (`mfa-entry`'s `provenRecently`), else `403 step_up_required`: a recent sign-in holding no counting factor, judged before a factor is bound, never stands for one.
- Renaming takes `mfa`'s refusal of a label, after the session enters and before the factor; a missing label is refused too.
- Every POST declares `csrf`'s policy, then `rate-limit`'s requests per source, and takes a form or JSON body read by name, a JSON member that is not a string being absent.
- The subject comes from the session, never from the body.

## Depends on
- `kernel`, `http` (`jsonAnswer`), `csrf`, `rate-limit`, `session` (entry, `refusedEntry`), `mfa` (factor decisions, the label's shape), `mfa-entry` (`provenRecently`)
