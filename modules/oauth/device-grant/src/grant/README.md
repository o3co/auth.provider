# grant

Internal module of `device-grant`: the `device_code` grant (RFC 8628 §3.4–3.5), which a device polls until its code is decided or ends.

## Responsibilities
- Decides each poll on the record it reads, and issues the access token once for an approved code.

## Not here
- Client authentication and the answer's form (`token-endpoint`). Approving a code (`verification`).

## Offers
- `grantOver` (the build context) → `grantWith` (the device store, `subject-revocation`, `session`'s entry (whether it is open, and when it ends), the runtime) → the grant `token-endpoint` takes.


## Invariants
- A poll is one rewrite of the record it reads. Two polls at once issue once, carrying the approval's amr and authentication time (none where the session did not know it), if `tokens`' issuance policies allow, asked with the approving session before the poll takes the code.
  - Another client's poll writes nothing and is `invalid_grant`.
  - A poll before the interval is over is `slow_down`, and widens the interval by 5 seconds.
  - An approval or a denial is answered once, and the record is taken.
- A subject revoked since the approving session's authentication is `invalid_grant`, and so is an approving session that does not enter at use, checked before the poll takes the code and again once the token is made, which is then never answered.
- The token is an access token to the approving subject, with the scope and audience decided at device authorization, ending no later than the approving session; one from an approval kept with no session stands from its authentication.

## Depends on
- `token-endpoint` (the grant, admits and issue); `subject-revocation` (the check); `kernel` (the build context, the clock); the package's record and store interfaces
