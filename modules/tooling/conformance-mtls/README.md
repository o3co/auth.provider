# conformance-mtls

## Responsibilities
- Owns the conformance scenes of the mTLS area: tokens bound to the client's certificate as a trusted proxy forwards it (one PEM block, or Envoy's XFCC), self-signed or under PKI with revocation by CRL, OCSP or both.
- Sets up the mTLS part (the header and its form, the trusted proxies, the anchors, the revocation mode and its sources) on each target.
- Issues the scenes' certificates, CRLs and OCSP answers.
- Serves the scenes' certificates, CRLs and OCSP answers on the base's fake HTTP server, each client certificate at locations of its own.
- The OCSP answers carry the request's nonce back unless the scene says otherwise.
- The served answers say their media type.

## Not here
- Scene composition and drivers (`conformance`). Starting the legacy system (`conformance-legacy`). Key and client parts (their own areas).

## Offers
- Area `mtls` and the shape of its part
- Scene builder (builds the key, OAuth and mTLS parts from the form written in a scene)
- `issue` (a certificate, self-signed or under an issuer), `pemOf` and `thumbprintOf` (its `x5t#S256`), for other areas' scenes of a certificate-bound token

## Invariants
- The legacy set-up, the needs the legacy system cannot provide, and what it answers otherwise (`differs`) live only in `src/legacy.ts`.
- A scene the legacy system answers otherwise runs on the new target alone, by a difference `src/legacy.ts` declares.
- Touches only the HTTP interface.
- Whether a token is bound is read from the access token's `cnf` and at introspection.
- The new target reaches the fake revocation sources only because the scene names their hosts in outbound's `allow` and the sources as plain-http loopback destinations.

## Depends on
- `conformance`, `conformance-legacy`, `conformance-keys`, `conformance-oauth`
