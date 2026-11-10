# fetching

Internal module of `revocation`: an issuer's CRL for the checks waiting on it.

## Responsibilities
- Fetches an issuer's CRL once for every check waiting on it, verifies it, keeps it through `kept`, and fetches it again when due.

## Not here
- How a fetch goes, its admission and place: the package's `crl-fetch`. Keeping: `kept`. Judging a certificate: `revocation`.

## Offers
- `crlsOver` (`kept`, how CRLs are fetched and when) → `crlFor` (an issuer's key, the issuer, its URLs, a check's signal) → the CRL, or why it is unconfirmed. `Unconfirmed`, `Fetched`, `Fetching`.

## Invariants
- One fetch per issuer at a time; a check waits no longer than its own signal (`unreachable`).
- A check that leaves on its signal is answered at once; its wait on the shared fetch lives on until that fetch ends, bounded by the fetch's 5 seconds and one read.
- A fetch cut short by the check that started it is remembered as nothing, and one waiting fetches again, once, where time is left.
- A CRL is verified by `x509-path` (one read at a time in the process; an abort by its signal is `aborted`, as a fetch cut short), this update up to 5 minutes ahead taken.
- A CRL its issuer could not have signed (its name, its right to sign CRLs, its dates) is `issuer`; one signed otherwise, `signature`.
- A fetch that failed is remembered `failure-lifetime` (4,096 at most, the oldest going first), its checks unconfirmed by its reason meanwhile.
- A CRL kept answers until its next update; after `crl-ttl`, or within a tenth of its span (a minute at least) of its next update, it is fetched again in a place of its own where one is free, the one kept answering meanwhile.

## Depends on
- `x509-path` (`verifyCrl`), `kept`
