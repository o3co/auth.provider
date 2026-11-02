# json

Internal module of `outbound`: a JSON call, as a caller speaking a JSON wire makes it through `outbound`.

## Responsibilities
- Posts a body as JSON with its credential, names why a send failed, and reads an answer as one JSON object.

## Not here
- Sending the request, and the credential's rules: the package's `fetch` and the internal module `credential`.
- What a wire's answers mean, and the failure a caller logs and throws: the caller's.

## Offers
- `postJson` (outbound, url, body, credential, credential header, narrower; failed), offered on the package's contract: a `POST` of the body as JSON, asking JSON back, the credential a Bearer token or, with a header named, as given there; a send that fails throws what `failed` makes of its kind.
- `sendFailureOf` (error), offered on the package's contract: a refused destination's reason, outbound's failure, or `no-answer` for anything else.
- `jsonObjectOf` (answer, status), offered on the package's contract: one frozen UTF-8 object from the status named (`200` by default), or any other answer with its status.

## Invariants
- `postJson` sends `Accept` and `Content-Type: application/json`, and no credential where none is given; any answer it gets is the caller's to read.
- `jsonObjectOf` reads bytes that are not UTF-8, JSON that is no object, and an answer of another status as other, never throwing.

## Depends on
- The package's `fetch`, request and answer types and `isOutboundUnavailable`; `outbound-policy` (`DestinationRefused`); `kernel` (`deepFreeze`)
