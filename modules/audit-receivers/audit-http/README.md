# audit-http

## Responsibilities
- Contributes the audit receiver `http` to `audit`, posting each event to the operator's URL through `outbound`.

## Not here
- Which events there are and what they carry: the emitting side's.
- Whether the URL may be reached, plain http included, and how long a request may run: `outbound`'s policy.
- Counting and logging a failed delivery: `audit`'s.

## Offers
- Composition definition: the receiver `http`.
- Operator section: `url` (required), an http or https URL as `url-setting` takes it.
- Operator section: `authorization` (optional), the whole value of the Authorization header the collector asks for, a secret.
- Test configuration builders (`./testing`): an https URL and a new Authorization value, unless a test sets them.

## Invariants
- One request per event: `POST`, `content-type: application/json`, and the event as one JSON object, values included.
- The Authorization header is sent only when given; its value is printable ASCII on one line, and is never logged or told in a refusal.
- An Authorization value beginning `REPLACE-`, the fragment's placeholder, refuses boot.
- With an Authorization value, the URL must be https; boot is refused otherwise.
- Boot is refused, saying why, when `outbound`'s destination policy refuses the URL.
- Events go to the configured URL alone; a redirect is a failure, never followed. The URL is named to `outbound` as the operator's own (`internal`), so a collector at a host in `internal-hosts` is reached at a private address.
- Any answer other than 2xx, a refused destination, or no usable answer is this receiver failing; the event is not sent again.

## Data
- None, so it is safe on many instances.

## Depends on
- `kernel`, `audit`, `url-setting`, `outbound`
