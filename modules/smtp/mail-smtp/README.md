# mail-smtp

## Responsibilities
- Implements the `mail` contract by sending each message over SMTP to the one relay the operator names.
- Secures the connection, writes the envelope and the `To` header itself, and maps the relay's answers to limited or unavailable.

## Not here
- Purposes, wording and locale (the sending side and mail's templates). Checking and rendering a message (mail's `preparer`; only what it returns is sent). The address rule (mail's `isAddress`). Counting sends (the relay's limits).

## Interface
- Composition definition only (provides `mail`); it cannot be composed beside mail's logging-only sender.
- Operator section: `host` (required), `port` (default 587), `security` (`starttls` by default, `tls` or `none`), `from` (one address mail's `isAddress` takes, a display name allowed), `user` and `password` (both or neither), `deadline` (the whole send, 100ms–10m, default `40s`, written with its unit), `concurrent-sends` (sends at once on a host, 1–1000, default 20).

## Invariants
- Connects to the relay itself, apart from `outbound`, which carries HTTP alone (`network`: `smtp`).
- One connection per send, never reused. It holds no state but the count of sends at once, so it is safe on multiple instances.
- Past `concurrent-sends`, a send is unavailable at once, opening no connection, logged as `mail-smtp.busy` with the purpose. A send ends at its answer or its deadline; a name lookup its deadline gave up on holds no socket and is bounded by the resolver's pool, not by this count.
- `tls` is TLS from the first byte. `starttls` always uses STARTTLS and sends nothing more when it is missing or refused.
- The certificate is always checked against `host`, at TLS 1.2 or later; no environment variable turns that off.
- `none` boots only when `host` is `localhost` or a loopback address, logs one warn line at boot, and sends nothing when the connected peer is not loopback.
- Neither plaintext nor the choice of this sender depends on the environment's name (`NODE_ENV`).
- AUTH is sent only over the connection `security` asks for, and only when an account is set.
- One recipient in the envelope and in `To`. No received string is read as a header.
- The recipient's and `from`'s domains go into the envelope and the headers in their IDNA ASCII form. An address still beyond ASCII goes only to a relay offering SMTPUTF8; otherwise it is unavailable and nothing is sent.
- Limited only for a 421, 450, 451 or 452 reply to MAIL, RCPT or DATA with the enhanced code 4.7.1, 4.7.28 or 4.5.3. Everything else is unavailable.
- Errors and log lines carry the stage, the reply codes and a listed connection code, never the relay's words, the password, the address or values.
- Connecting, the greeting, each silence and the whole send have deadlines, each logged as its own stage; a relay answering bit by bit cannot extend the whole one. A failed QUIT after sending keeps sent.
- Boot refuses a missing host, a `from` that is not one mailbox or whose address mail refuses, half an account and control characters, naming the key and never the value.

## Deployment
- A relay at `host` and `port` offering STARTTLS, or TLS from the first byte with `security` `tls`, with a certificate valid for `host` at TLS 1.2 or later.
- Plain SMTP only from a relay on this host's loopback, with `security` `none`.
- SMTPUTF8 on the relay, where an address beyond ASCII must be delivered.
- An account in `user` and `password`, where the relay asks for AUTH.
- The relay's sending limits, its reputation and what it does after it takes a message are the operator's.

## Depends on
- `kernel`, `mail` (the contract, `preparer`, `isAddress`). `nodemailer` (pinned) only inside the internal module `relay`.

## Vocabulary
- relay: the SMTP server that takes the message from here.
