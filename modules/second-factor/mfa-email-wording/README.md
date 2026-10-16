# mfa-email-wording

## Responsibilities
- Words the mails `mfa-email` sends: a template for each of its purposes. It is `mfa-email`'s default adapter on its wording axis: composed where `mfa-email` is, unless another adapter of that axis is.

## Not here
- What is sent, to whom and when (`mfa-email`). Rendering and sending (`mail`).

## Offers
- Contributions to `mail`'s templates: `mfa-email.enrollment`, `mfa-email.login` and `mfa-email.proof`, plain text in English for every locale, taking `code` and `minutes`.

## Invariants
- Every purpose `mfa-email` names has a template here, and no other: the type ties the two.
- A deployment words the mails its own way with another adapter of `mfa-email`'s axis contributing the same purposes; this default is then not composed.

## Data
- None.

## Depends on
- `kernel`, `mail`, `mfa-email` (its purposes)
