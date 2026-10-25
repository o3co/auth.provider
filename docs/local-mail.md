# Email codes on your machine

The module cards are the source of truth. Where this page and a card disagree, the card wins.

No sender writes a mailed code to the log or to a file: the `mail` module's own sender (`mail.accept-unsent = true`) logs the purpose, a hash of the address and the names of the message's values, never a value. To read the codes a second factor by email sends while you develop, run [Mailpit](https://mailpit.axllent.org/) on your machine, bound to loopback, and point `mail-smtp` at it. Mailpit takes each message over SMTP, keeps it, and shows it in its web UI; nothing leaves the machine.

This is for a developer's machine alone. Mailpit's UI shows every message, codes included, to whoever reaches it.

## 1. Run Mailpit on loopback

Give both its SMTP server and its web UI a loopback address, as written here: the defaults differ between builds.

```sh
mailpit --smtp 127.0.0.1:1025 --listen 127.0.0.1:8025
```

Or in a container, publishing both ports on loopback alone:

```sh
docker run --rm -p 127.0.0.1:1025:1025 -p 127.0.0.1:8025:8025 axllent/mailpit
```

Give it no relay configuration: Mailpit relays mail elsewhere only when told to. The messages are at `http://127.0.0.1:8025`.

## 2. Point `mail-smtp` at it

The `mfa-web` pattern composes `mail-smtp` with a second factor by email (`mfa-email`):

```sh
npx @o3co/create-auth-provider my-provider --pattern mfa-web
```

Set its section to Mailpit's SMTP address:

```hocon
mail-smtp {
  host = "127.0.0.1"
  port = 1025
  security = none
  from = "auth@example.invalid"
}
```

`security = none` boots only where `host` is a loopback host, logs one warn line at boot, and sends nothing when the connected peer is not a loopback address (the `mail-smtp` card). Every other key the pattern asks for is in its generated README and the [configuration reference](configuration.md).

## 3. Try a code

A user who holds an email factor logs in as the [second-factor recipe](recipe-mfa-page.md) shows: the login is held (`403`, `mfa_required`) and names a transaction, and `GET /session/mfa/transaction` lists the user's factors. Ask the email factor for a code:

```http
POST /session/mfa/challenge
content-type: application/json
x-csrf-token: <csrf_token>

{
  "transaction_id": "<transaction>",
  "factor_id": "<factor_id>"
}
```

The answer shows where the code went, the address's first character and its domain (`sent_to`), and how long it lives (`expires_in`). The message arrives in Mailpit, to the account's address, with six digits. Prove it:

```http
POST /session/mfa/verify
content-type: application/json
x-csrf-token: <csrf_token>

{
  "transaction_id": "<transaction>",
  "factor_id": "<factor_id>",
  "proof": "<six digits from the message>"
}
```

The answer sends the browser on (`redirect_to`), as with any other factor.

Binding an email factor mails codes too, and each arrives in Mailpit the same way: first the proof of the account's address (`mfa-email-proof`), then a 16-character code the binding completes with (`mfa-email`). The `mfa-enrollment` and `mfa-email-proof` cards give the requests. A code by email counts toward a required second factor only where `mfa-email.adds-second-factor` is set (the `mfa-email` card).
