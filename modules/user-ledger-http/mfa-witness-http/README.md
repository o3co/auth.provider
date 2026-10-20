# mfa-witness-http

## Responsibilities
- Contributes `mfa`'s enrollment witness kept at the operator's HTTP ledger: whether a subject carries the mark, setting it to a token unless one is set, and removing it, each asked of the ledger through `outbound`.
- Reads each answer once, at this boundary, into the witness's answer.

## Not here
- When the witness is read, enrolled or cleared, and what is decided with it (`mfa`). The witness's contract (`mfa-witness`). Whether the ledger may be reached, redirects, and the caps on size and time (`outbound`). Keeping the mark (the ledger's).

## Offers
- Composition definition only (a contribution to `mfa-witness.enrollment-witnesses`). Opt-in: no axis's default, so composing `mfa` alone never brings it.
- `./testing`: `mfaWitnessHttpConfig`, the section of a test's configuration.
  - `witnessLedger`, a fake ledger keeping the witness as an operator's ledger does, behind a credential of its own: its answer to these calls (none for a call not its own) and the section pointing mfa-witness-http at it, for a scene or an operator's trial.
- Operator section: `read-url`, `enroll-url` and `clear-url` (required: each URL whole, https or a plain-http pair outbound names, no fragment, all three at one origin); `credential` (required: `keys`' `bearerToken` of at least 32 bytes of key material, never a `REPLACE-` sample), sent on every call; `timeout` (default 5s) and `max-response-size`, each narrowing outbound's cap, written with its unit.
- The calls: `POST` to the URL as written, nothing added; `Content-Type` and `Accept: application/json`; `Authorization: Bearer {credential}`. A write's `deadline` is the `kernel` clock's epoch milliseconds when it is sent, plus the time outbound holds the call to (`outbound-policy`'s `outbound.limits` for the call: `timeout`, or outbound's own where shorter).

  | Call | Body | Answer read | Read as |
  |---|---|---|---|
  | read | `{"subject"}` | `200`, a JSON object with `enrolled`, a boolean | whether the subject carries the mark |
  | enroll | `{"subject", "token", "deadline"}` | `200`, a JSON object with `owner`, a boolean | whether the mark is that token's |
  | clear | `{"subject", "deadline"}` | `204` | removed |

  Any other answer, `404` included, is unavailable: a subject the ledger does not know is never read as unmarked.

## Invariants
- Nothing is kept between calls: each asks the ledger again.
- The ledger is reached only through `outbound`, at the URLs' host alone; a redirect is not followed. The URLs are internal destinations, named to `outbound` by one of them (they share one origin): a private address is reached only when their host is in `outbound.internal-hosts`, and only at their origin (scheme, host and port).
- Boot is refused on a URL that outbound's destination policy refuses (at that URL's key, saying which of `outbound`'s keys to set, by `outbound.refusals`), and on URLs `outbound.credentials` will not send the credential to, as when they are at two origins (at `credential`); `outbound` sends the credential as its `credential`.
- A destination refused when sending, or no answer in time or size, is unavailable. Each failure logs one `mfa-witness-http.ledger_failed` warning with its `call` and its status, or its kind alone: outbound's refusal reason or failure, `no-answer` or `malformed`. No subject, token, text or bytes from the ledger, nor the credential, are logged.
- The deployment's to keep, not checked here: the ledger keeps `mfa-witness`'s promises (per subject linearizable, `enroll`'s set-if-absent atomic, an answered write lasting, no read behind it), and does not carry out a write it receives past its `deadline`.
- Holds no state, so it is safe on multiple instances.

## Depends on
- `kernel`, `mfa-witness`, `outbound`, `outbound-policy`, `url-setting`, `keys` (the credential's rule)
