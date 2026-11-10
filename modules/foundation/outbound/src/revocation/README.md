# revocation

## Responsibilities
- Checks the revocation of the certificates a TLS peer of an outbound request presents, by CRL, before the request goes: good, revoked, or unconfirmed with a reason.
- Keeps CRLs, each issuer's high-water mark and the revocations seen, and fetches a CRL once for the checks waiting on it.

## Not here
- The TLS connection, when it is checked and what the result does to the request: `transport` and the package (0.20 warns and lets the request go). Fetching, its admission and its place: the package's, as signed material. Choosing and validating the path, and reading and judging CRLs: `x509-path`.

## Offers
- `revocationOver` (the trust, the CRL hosts, `crl-entries`, how CRLs are fetched and when) → a check of a peer's leaf and what it sent, under a signal. `storeTrust`: the platform's store, read once. `noticesOver`: the warnings. `revocationSection`: the operator's keys, and `startWarnings`: what they leave unchecked or accept, said at every start.

## Invariants
- Path: the one `x509-path` chooses toward the store (its self-signed certificates the anchors, the rest intermediates a peer may leave out), under rules beyond OpenSSL's: every certificate's extended key usage, where it has one, for server authentication; RSA of 2048 bits at least, EC on P-256, P-384 or P-521, anchor included; six intermediates at most. Refused, it is unconfirmed (`path`). Confirmed means this path alone: another, OpenSSL's among them, may differ.
- Each certificate on it but the anchor is checked by its issuer's CRL. No CRL distribution points: nothing to ask, good. Points unreadable: `malformed`; none for every reason by the issuer: `unsupported`; https alone: `https-only`; at no host listed: `unlisted`. Two plain http points at most are fetched.
- An issuer's CRL comes through the internal module `fetching` (once for every check waiting, failures remembered, fetched again when due), fetched by the package's `crl-fetch` as signed material, through the proxy where one is set, and kept by the internal module `kept` (high-water marks, bounds), as their cards say.
- A revocation other than a hold stands, by issuer and serial, though a later CRL leaves it out; a hold is asked again.
- Log lines carry a reason and a count, never a host, a URL or a parser's words: `outbound.revocation_unconfirmed` (debug where `accept-unconfirmed`), `outbound.revocation_revoked`, each reason at most once a minute, counting those since.
- Cost: a check under one intermediate, its CRLs kept, about 2.6 ms, beside the path's choice `x509-path` measures against the store.

## Data
- What `kept` and `fetching` hold, in this process alone, lost at restart. An older CRL not yet seen may be served until its next update: a signature keeps it whole, not fresh.

## Depends on
- `x509-path` (path, rules, judging a CRL), `kept`, `fetching`, `host-entries` (the hosts listed), `kernel` (a duration setting); node's `crypto` and `tls` (the store)
