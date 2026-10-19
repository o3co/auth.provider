# grant

Internal module of `device-grant`: the `device_code` grant (RFC 8628 §3.4–3.5), which a device polls until its code is decided or ends.

## Responsibilities
- Decides each poll on the record it reads, and issues the access token once for an approved code.

## Not here
- Client authentication and the answer's form (`token-endpoint`). Approving a code (`verification`).

## Offers
- `grantOver` (the build context) → `grantWith` (the device store, `subject-revocation`, `session`'s entry (whether it is open, and when it ends), the runtime) → the grant `token-endpoint` takes.

## Depends on
- `token-endpoint` (the grant, admits and issue); `subject-revocation` (the check); `kernel` (the build context, the clock); the package's record and store interfaces
