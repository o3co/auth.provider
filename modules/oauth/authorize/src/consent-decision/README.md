# consent-decision

Internal module of `authorize`: whether a request needs the user's consent before its code.

## Responsibilities
- Decides whether a request goes on to its code, is refused, or is sent to ask for consent, and refuses a request that comes back from a denial.

## Not here
- Consent records, the first-party decision and the consent page (`consent`). Which scope is asked (`checks`).

## Offers
- `consentDecisionOver` (the build context) → `consentDecisionWith` (`consent`'s records) → denied (single values → a refusal / none), served (client → a refusal / none), decide (client, session, scope, prompt words, the endpoint's URL again → none / a refusal / the consent page), consented (client, subject, one scope → whether agreed to, always for a first-party client).

## Invariants
- `served` refuses a client that is not first-party with `unauthorized_client` while `consent` is not `asking`; `decide` is asked after it, and reads no records for a first-party client.
- `consent`'s records are read only for a client that is not first-party and did not ask `prompt=consent`.
- Under `prompt=none`, a request that would be asked is refused with `consent_required`, with that as its reason.
- The destinations after consent and after denial are both the endpoint's URL. After consent it drops the re-authentication record, `max_age`, and the prompt words `login` and `consent`; denial adds `consent_denied`, and a request carrying it is refused with `access_denied`.

## Depends on
- `consent` (covers, asking, ask, first-party); `clients` (the client type); `session` (the session type); `kernel` (the build context)
