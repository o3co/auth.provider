# mfa-email-proof-wording

## Responsibilities
- Words the mails `mfa-email-proof` names: a template for each of its purposes. It is `mfa-email-proof`'s default adapter on its wording axis: composed where `mfa-email-proof` is, unless another adapter of that axis is.

## Not here
- What is sent, to whom and when (`mfa-email-proof`). Rendering and sending (`mail`).

## Offers
- Contribution to `mail`'s templates: `mfa-email-proof.account-email`, plain text in English for every locale, taking `code` and `minutes`.

## Invariants
- Every purpose `mfa-email-proof` names has a template here, and no other: the type ties the two.
- A deployment words the mails its own way with another adapter of `mfa-email-proof`'s axis contributing the same purposes; this default is then not composed.

## Data
- None.

## Depends on
- `kernel`, `mail`, `mfa-email-proof` (its purposes)
