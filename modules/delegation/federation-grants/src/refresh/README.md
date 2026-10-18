# refresh

Internal module of `federation-grants`: handing a grant's upstream token, and renewing it.

## Responsibilities
- Hands the held token, or refreshes it under a lock within the rotation budget.

## Not here
- Who may ask and the answer's shape (`api`), the refresh request (the IdP type), when a token ends (`grant`).

## Offers
- `refreshOver` (the build context, records, the grants' judge) → `refreshWith` (grants, locks, records, the judge's `revoked` and `endOf`, runtime, settings): `current` (grant, what is asked → handed, or an outcome `api` answers).

## Invariants
- A token is due near its end, below the asked `min_ttl`, or lacking an asked scope, and only past half its life.
- One lock holder per grant refreshes, under a mark of 128 random bits, and reads the grant again under the lock.
- The lock is let go (ending a millisecond later) only while it holds that mark, never one another took after it ran out.
- A write lands only as its own write over the version read, and never on a grant no longer in use.
- A rotation is written before the upstream is asked; with the window spent, the held token serves, else `limited`.
- The upstream down, limiting or refusing leaves the credential, and a live held token serves; only `invalid_grant`, or `interaction_required` (the user must act at the upstream), removes it, each under its own reason (`upstream_invalid_grant`, `upstream_interaction_required`).
- A rotated refresh token is written before the rest is judged; an answer that cannot be held marks the grant ineligible.

## Data
- The lock lives 10 seconds; a request waits up to 5.
- A held token serves in place of a refresh that cannot be made only while the grant, read again then, is still in use, not past its end, and not ended by its subject's revocation: one revoked or ended while the upstream was asked hands out nothing (`gone`).
- A refresh the upstream answered hands out and writes nothing when the grant is past its end by then, or its subject's revocation ends it, even a grant its subject's listing missed, which only the boundary ends.

## Depends on
- `federation`, `kernel`; `grant`, the package's store interfaces
