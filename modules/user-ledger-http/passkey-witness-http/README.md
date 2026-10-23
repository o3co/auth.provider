# passkey-witness-http

## Responsibilities
- Contributes `passkeys`' witness kept at the operator's HTTP ledger: whether a subject carries the mark and its token, setting it to a token unless one is set, removing it only where it is a token's, and removing it, each asked of the ledger through `outbound`.
- Reads each answer once, at this boundary, into the witness's answer.

## Not here
- When the witness is read, enrolled, withdrawn or cleared, and what is decided with it, and the witness's contract (`passkeys`). Whether the ledger may be reached, redirects, and the caps on size and time (`outbound`). Keeping the mark (the ledger's).

## Offers
- Composition definition only (a contribution to `passkeys.witnesses`). Opt-in: no axis's default, so composing `passkeys` alone never brings it.
- `./testing`: `passkeyWitnessHttpConfig`, the section of a test's configuration.
  - `witnessLedger`, a fake ledger keeping the witness as an operator's ledger does (its read naming the mark's token), behind a credential of its own: its answer to these calls (none for a call not its own) and the section pointing passkey-witness-http at it, for a scene or an operator's trial.
- Operator section: `read-url`, `enroll-url`, `withdraw-url` and `clear-url` (required: each URL whole, https or a plain-http pair outbound names, no fragment, all four at one origin, `withdraw-url` another target than `clear-url`); `credential` (required: `keys`' `bearerToken` of at least 32 bytes of key material, never a `REPLACE-` sample), sent on every call; `timeout` (default 5s) and `max-response-size`, each narrowing outbound's cap, written with its unit.
- The calls: `POST` to the URL as written, nothing added; `Content-Type` and `Accept: application/json`; `Authorization: Bearer {credential}`. A write's `deadline` is the `kernel` clock's epoch milliseconds when it is sent, plus the time outbound holds the call to (`outbound-policy`'s `outbound.limits` for the call: `timeout`, or outbound's own where shorter).

  | Call | Body | Answer read | Read as |
  |---|---|---|---|
  | read | `{"subject"}` | `200`, a JSON object with `enrolled`, a boolean, and where it is `true` the mark's `token`, a non-empty string exactly as enroll sent it | whether the subject carries the mark (`read`), and its token (`markedWith`) |
  | enroll | `{"subject", "token", "deadline"}` | `200`, a JSON object with `owner`, a boolean | whether the mark is that token's |
  | withdraw | `{"subject", "token", "deadline"}` | `204`, once the ledger judged the token and removed the mark where it was the token's | withdrawn, or left as another's or none |
  | clear | `{"subject", "deadline"}` | `204` | removed |

  Any other answer, `404` included, is unavailable: a subject the ledger does not know is never read as unmarked, and a marked answer naming no token is never read as another call's.

## Invariants
- Nothing is kept between calls: each asks the ledger again.
- The ledger is reached only through `outbound`, at the URLs' host alone; a redirect is not followed. The URLs are internal destinations, named to `outbound` by one of them (they share one origin): a private address is reached only when their host is in `outbound.internal-hosts` or, over plain http, when `outbound.plain-internal` names their `host:port`, and only at their origin (scheme, host and port).
- Boot is refused on a `withdraw-url` reaching the target `clear-url` does, compared as outbound sends them (origin, path and query; a host's case or IDN spelling, a default port, a bare `?`, a fragment, dot segments, an unreserved character percent-encoded, or the case of an encoding's hex are not another): one route for both would clear whoever's mark a withdraw names.
- Boot is refused on a URL that outbound's destination policy refuses (at that URL's key, saying which of `outbound`'s keys to set, by `outbound.refusals`), and on URLs `outbound.credentials` will not send the credential to, as when they are at two origins (at `credential`); `outbound` sends the credential as its `credential`.
- A destination refused when sending, or no answer in time or size, is unavailable. Each failure logs one `passkey-witness-http.ledger_failed` warning with its `call` and its status, or its kind alone: outbound's refusal reason or failure, `no-answer` or `malformed`. No subject, token, text or bytes from the ledger, nor the credential, are logged.
- The deployment's to keep, not checked here: the ledger keeps the witness's promises (per subject linearizable, `enroll`'s set-if-absent and `withdraw`'s compare-and-delete atomic on the subject's own row, a token compared whole, an answered write lasting, no read behind it), and does not carry out a write it receives past its `deadline`.
- Holds no state, so it is safe on multiple instances.

## Depends on
- `kernel`, `passkeys`, `outbound`, `outbound-policy`, `url-setting` (also `sameTarget`, telling two of its URLs at one target), `keys` (the credential's rule)
