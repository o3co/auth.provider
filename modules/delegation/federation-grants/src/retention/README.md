# retention

Internal module of `federation-grants`: how long a grant's record and its subject listing are kept once it can no longer be used.

## Responsibilities
- Makes the revoked rewrite of a grant, with how long its record is then kept, and takes a revoked grant off its subject's listing.

## Not here
- When a grant is revoked (`api`'s client revocation and backstop, its follower, `sweep`). How long a grant is kept as it is lodged or connected (`api`, `intents`). A grant's end (`grant`'s judge).

## Offers
- `retention`, built by `retentionOver` (the build context: `grant`'s shared judge, the section's `retention`, the subject listing) once for the package: `revocation` and `unlisted`, which `api`, its follower and `sweep` take. The package's module starts the sweep where it builds them.
- `revocationWith` (the judge, `retention` in ms) → a grant revoked for its reason at a time, without its credentials, and its record's lifetime from then. Every revoking write takes it.
- `unlistingWith` (the subject listing, log) → takes a grant off its subject's listing.

## Invariants
- A grant is kept `retention` past its end once connected, past its connect time's end while never connected, and past its revocation as below; each is set as the record is written, so a change applies to grants lodged, connected or revoked after it.
- A revoked grant is kept `retention` past the earlier of its revocation and its end (a grant never connected, its intent's end), at least a millisecond, so one revoked past its end is never kept longer for it.
- A revoked grant is taken off its subject's listing; a failed write is logged as `federation-grants.listing_failed` and passed, as a listing's is: the boundary still refuses.

## Depends on
- `grant` (the record, `withoutCredentials`, its shared judge and the judge's end); the package's subject listing and section; `kernel` (the build context, the log).
