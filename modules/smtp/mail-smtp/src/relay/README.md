# relay

Internal module of `mail-smtp`: one SMTP conversation per send, over a pinned `nodemailer`. It knows no mail purpose.

## Responsibilities
- Opens the connection, secures it, signs in, sends one message and ends with QUIT.
- Sends to the address as it is given (the package hands it in mail's canonical form); it checks no address.
- Maps the relay's answers and the library's failures to limited, or to a failure with a stage and codes.

## Offers
- `relayOver(settings, open?)` gives a function from a letter (one checked address in mail's canonical form, subject, text) to sent or limited; it throws `RelayFailure` (stage, codes). No library type crosses it.
- `mailboxOf(from)` (splits off a display name; the section checks the address), `isLoopback(address)` and `isLoopbackHost(host)`, for the section's checks.

## Invariants
- Before STARTTLS, only EHLO and STARTTLS are sent in the clear.
- Connecting (the TLS handshake too, under `tls`) and the greeting get a quarter of the deadline each, a silence half; the whole send ends at the deadline.
- A `RelayFailure` keeps no text from the relay or the library, and no cause.

## Depends on
- `nodemailer` (SMTP connection, message composer, address parser); nothing in the workspace.
