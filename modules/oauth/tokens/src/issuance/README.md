# issuance

Internal module of `tokens`: the judgment `admits` and `issue` share, and the issuing `issue` does over it.

## Responsibilities
- Judges whether an access token may be issued: tokens' own rule, then the issuance policies, within one deadline.
- Issues over the judgment, from one frozen copy of the request and its limits, and answers what is left of the token.

## Not here
- The token's claims, its signing, its lifetime and its cap (the package's). The policies: those composed at `issuancePolicies`.

## Offers
- `judging` (the policies, the clock, the deadline) → the judgment `admits` and `issue` share.
- `issuing` (the judgment, the issuing, the clock) → `admits` and `issue`, alike for tokens and its stand-in; `IssueAccess`, the issuing it takes.
- `authenticatedAheadMs`, `issuanceTimeoutMs`: tokens' own rule's bound and the policies' default deadline.

## Invariants
- The order policies are asked in: tokens' own rule first (an authentication time over 300 s ahead of the clock), then the issuance policies in name order, each asked the grant as its caller verified it; any answer but allowed refuses. All of them answer within `issuance-timeout` together: past it the issuance is unavailable, and the signal each policy is given aborts.
- `admits` makes the same judgment without issuing, but for the lifetime, which only `issue`'s limits and signing fix; a policy that cannot tell is unavailable. `issue` takes one frozen copy of the request and its limits before anything waits: every policy reads it and the issuing signs it, so neither a policy nor a caller changing its own objects meanwhile changes what is signed.
- A token with less than a second left once signed, its end come, its cap passed or its signing slow, is refused as tokens' own rule: policy `tokens`, reason `no_lifetime_left`, the client's word `expired`, which `token-endpoint` answers `invalid_grant` whatever the grant. Any other answers its expires-in: what is left once signed, rounded up to whole seconds, at least 1.
- What an issuing keeps of a token (`IssueAccess`' `keep`) is kept only once the token is handed out, so one refused leaves no trace. tokens keeps nothing: a token is signed and handed back, no store, ledger or record written. The stand-in keeps what it issued.

## Depends on
- `added-claims` (the claims a grant adds, checked), `kernel` (freezing, unavailable), and the package's contract and limits.
