# kept

Internal module of `revocation`: what outbound keeps of revocation, by issuer (its name's DER and key's SHA-256), in this process alone.

## Responsibilities
- Keeps CRLs as verified, each issuer's high-water mark, and the revocations seen.

## Not here
- Fetching, verifying and judging CRLs: `fetching`, `x509-path`, `revocation`.

## Offers
- `keptOver` (`crl-entries`) → `take` (an issuer, a verified CRL) → `kept`, `same`, `rollback`, `state-full` or `too-large`; `crlOf`; `isRevoked`, `recordRevoked` and `isUnrecorded` by issuer and serial.

## Invariants
- A CRL is taken only at or past its issuer's mark: by CRLNumber, then this update; none without a number once one was seen. The same number keeps the one kept, or takes it again once evicted, its next update its own.
- CRLs: at most `crl-entries`, and 2^19 listed serials together, the oldest going first; one listing more alone is not taken. Eviction only means a fetch again.
- Their serial maps, measured: some 46 to 60 MiB at the full budget (`x509-path` holds a serial to 20 octets and keeps copies alone); with mtls's, some 92 to 120 MiB a process. Apart from them: each body's issuer name, 4 KiB at most; fetched bodies waiting to be read, up to `max-concurrent` × 1 MiB; and the one being read, a dense 1 MiB CRL near 165 MB, a measured case. Their sum is no bound.
- Marks of 4,096 issuers and 4,096 revocations other than a hold, of certificates checked here (never a CRL's listing): never evicted, as either would reopen a rollback or turn a revoked peer good. Past them, a new issuer's CRL is not taken, and an issuer whose revocation went unrecorded has its good refused.
- All of it is lost at restart.

## Depends on
- `x509-path` (`VerifiedCrl`)
