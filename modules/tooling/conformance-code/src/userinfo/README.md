# userinfo

Internal module of `conformance-code`: the scenes of OpenID Connect's userinfo.

## Responsibilities
- Checks what userinfo answers an access token: the subject and the claims of its scope while its session is open, the subject only for a token issued in no session, a refusal once the session ended or the token was revoked, and for a refresh or ID token presented in its place; a request with no token, the origins whose pages may read it, and the metadata document's item.
- Checks a token bound to its holder's key (DPoP): the holder's proof admitted, the token as a Bearer token, and proofs by another key or for another token refused.
- Checks a token bound to the client's certificate (mTLS): the certificate it is bound to admitted, another one or none refused.

## Depends on
- The package's scene builder and browser; `conformance` (the target); `conformance-oauth` (clients); `conformance-mtls` (its part and its certificates)
