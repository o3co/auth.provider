# @o3co/auth-provider-standard

Last updated: 2026-09-30

Standard, replaceable implementations of the duties outside [`auth.provider`](../../README.md): what a deployment needs beside the provider and may write for itself instead. For now, the mail senders the one-time codes the provider issues leave through.

## Responsibility

**Role.** The provider's duties end at its interfaces. It issues a code and hands a `MailSender` what the mail means — its purpose, the account, the recipient, the code and its expiry (core's `MailSend`) — and a sender renders it, delivers it and applies any limit on sending. This package holds the senders a deployment can install as they are: an SMTP sender and a development sender.

**Owns:**
- the text each purpose is rendered as (`renderStandardMail`): a subject line and a plain-text body in English, carrying the code and the minutes it has left, and nothing else of the send — not the account, not the recipient, nothing clickable;
- the SMTP sender — how it delivers, secures the connection and reads the relay's replies — its module, `standardSmtpMailSenderModule`, and its section, `standard-smtp-mail-sender`, with their defaults in [`config/reference.conf`](config/reference.conf) (exported as `@o3co/auth-provider-standard/reference.conf`);
- the development sender and its module, `standardDevelopmentMailSenderModule`, which alone publishes it;
- the builders a test assembles this package's configuration with, on `@o3co/auth-provider-standard/testing`.

**Does not own:** the `MailSender` port, `MailSend`, the closed list of purposes and the `mailSender` slot — core's ([`packages/core/src/mail/`](../core/src/mail/types.mts)); the conformance suite a sender runs, `mailSenderContract` — [`@o3co/auth-provider-test-kit`](../test-kit/README.md)'s; which code is issued, when, and to whom — the provider's.

**Why a separate package.** A sender is replaceable: a deployment that delivers through its own mail service implements `send` and installs none of this. Of the workspace's packages this one depends on core alone, as the provider's do; its mail library, [`nodemailer`](https://nodemailer.com/), is its own, and no package of the provider reaches it.

## The SMTP sender

`standardSmtpMailSenderModule` fills the `mailSender` slot with the SMTP sender (kind `standard-smtp`). The sender is built only where something reads the slot: a composition that sends nothing boots with the section as the reference defaults it, and one that sends refuses the boot when the section cannot send — no `host`, no `from` naming one address (alone, or after a display name), or a `user` without a `password` or the other way round — naming the key and its variable, and quoting no value.

**Delivery.** Each send is one connection to the relay, over nodemailer's SMTP connection, carrying `renderStandardMail`'s text of the mail from `from`. **One mailbox per send:** the envelope names one recipient, the send's `to` exactly as written, and the `To` header carries it alone in angle brackets, written by the sender rather than by an address parser, so nothing in the address can add or change a recipient. A `to` that is not one address in the spelling core's `normaliseMailAddress` gives it, or whose quoted local part holds `<` or `>`, which the transport would refuse or rewrite, is refused before any connection (a `RangeError` quoting nothing of it). The sender logs nothing, and holds no connection between sends.

**TLS.** The relay's certificate is always verified — against the platform's CAs, and those `NODE_EXTRA_CA_CERTS` adds — for the configured `host`.

| `secure` | The connection |
| --- | --- |
| `starttls` (default) | STARTTLS is required: a relay that does not offer it, or refuses it, or whose handshake or certificate fails, gets nothing more, and the send is an outage. Never continued in the clear |
| `tls` | TLS from the first byte (port 465, usually) |
| `none` | Plaintext, taken by the section only to `localhost` or a canonical loopback address; the sender also checks the address the connection reached, and sends nothing unless it is loopback, so a name that resolves elsewhere is refused |

The account signs in only once the connection is secured as `secure` says. Connecting (with implicit TLS's handshake) has 10 seconds, the greeting 10 seconds, and each answer 20 seconds.

**Answers.** What the relay replies to the sender (`MAIL FROM`), the recipient (`RCPT TO`) or the message decides the answer:

| The relay | `send` |
| --- | --- |
| accepts the message | resolves `{ outcome: "delivered" }` |
| replies `421`, `450`, `451` or `452` with the enhanced status code (RFC 3463) `4.7.1`, `4.7.28` (mail flood) or `4.5.3` (too many recipients), to the sender, the recipient or the message | resolves `{ outcome: "refused_at_limit" }`: the provider answers `429` |
| any other reply — a transient one without one of those codes, `4.3.2` or `4.4.5` among them, a reply with no enhanced code, any permanent one — or no answer | rejects with a `MailTransportError`: the provider answers `503` |

A reply at the connection, the greeting, EHLO, STARTTLS or AUTH is never a limit. `MailTransportError`'s `reason` is `unreachable` (no connection the sender may deliver over: the name did not resolve, the connection was refused, closed or turned away, or it could not be secured as `secure` requires), `auth_failed` (the relay refused the account), `rejected` (it refused the sender, the recipient or the message, or put it off with a reply that is not a limit) or `timeout`. Its message names the stage and the reply's codes (`replyCode`, `enhancedCode`), never the reply's text or the transport's, which can quote the recipient, the code or the credentials, and it carries no `cause`.

The rules are pinned against a relay a test scripts ([`smtpSender.test.mts`](src/mail/__tests__/smtpSender.test.mts), [`smtpFailure.test.mts`](src/mail/__tests__/smtpFailure.test.mts)), and the test kit's `mailSenderContract` runs over it and over Mailpit in a container ([`smtpSender.contract.test.mts`](src/mail/__tests__/smtpSender.contract.test.mts), [`smtpSender.mailpit.test.mts`](src/mail/__tests__/smtpSender.mailpit.test.mts)), which needs a container runtime.

One section, the module's and named after it: `standard-smtp-mail-sender`. Boot parses it with the module's schema before any factory runs and refuses a key the section does not know, by its name. No refusal quotes a value, the password included. Layer [`config/reference.conf`](config/reference.conf) between your `application.conf` and core's `reference.conf`; the module declares it as its section's reference, so core's `moduleReferences(modules)` names it among the files to layer.

| Key | Env | Default | Meaning |
| --- | --- | --- | --- |
| `standard-smtp-mail-sender.host` | `STANDARD_SMTP_MAIL_SENDER_HOST` | none | The relay's host: one line of well-formed text, not blank, with no control character. Required to send |
| `standard-smtp-mail-sender.port` | `STANDARD_SMTP_MAIL_SENDER_PORT` | `587` | 1 to 65535 |
| `standard-smtp-mail-sender.secure` | `STANDARD_SMTP_MAIL_SENDER_SECURE` | `starttls` | `starttls` (upgrade a plain connection), `tls` (implicit TLS) or `none` — plaintext, taken only to `localhost` or a loopback address written in its canonical form (`127.0.0.1`, `::1`), and refused with no host: another spelling of an address (`127.0.0.08`, `2130706433`) is a name a resolver may send anywhere |
| `standard-smtp-mail-sender.user` | `STANDARD_SMTP_MAIL_SENDER_USER` | none | The account the relay is signed in with; none, and the sender signs in to nothing. Set with `password` or not at all |
| `standard-smtp-mail-sender.password` | `STANDARD_SMTP_MAIL_SENDER_PASSWORD` | none | Its password, from the environment |
| `standard-smtp-mail-sender.from` | `STANDARD_SMTP_MAIL_SENDER_FROM` | none | The sender: one address, alone or after a display name (`Sign-in <no-reply@example.com>`), on one line; the envelope's sender is the address. Required to send |

## The development sender

`standardDevelopmentMailSenderModule({ environment })` fills the `mailSender` slot with a sender that delivers nothing: each send is one line at info, `mail_code_issued`, carrying the purpose and the code, so a developer reads the code off the log. It has no settings and no section, and the sender is published only through it.

A code in a log line is a secret wherever more than the developer reads the log, so the module lets the sender in only where it should be: an allow-list rather than a list of what to refuse. Its factory runs at every boot, whether or not anything reads the slot, and refuses the boot unless every name it reads says `development` or `test`: `environment` — the name the configuration was selected by; the standalone template passes `CONFIG_ENV || NODE_ENV || "development"` — and `CONFIG_ENV` and `NODE_ENV` wherever they are set, each read whatever its case and the whitespace around it, none lifting another's refusal. The refusal names each name it read: one that says `production` or `staging` (core's `productionEnvironmentIn`) as that, any other as not development or test. It refuses too where `core.deployment.mode` is `"multi"`.

## API

| Export | What it is |
| --- | --- |
| [`renderStandardMail`](src/mail/render.mts) | A send's subject line and body at a given time; a `RangeError` that quotes nothing of the send for one it cannot render |
| [`standardSmtpMailSenderModule`](src/mail/smtp/module.mts) | The SMTP mail sender's module, `standard-smtp-mail-sender`: its section, and the sender over it |
| [`standardSmtpMailSenderConfigSchema`](src/mail/smtp/config.mts) | The shape and rules of `standard-smtp-mail-sender` |
| [`MailTransportError`](src/mail/smtp/failure.mts) | What the SMTP sender rejects with: `reason`, `replyCode`, `enhancedCode` |
| [`standardDevelopmentMailSenderModule`](src/mail/development/module.mts) | The development sender's module, for the environment the configuration was selected by |

On `@o3co/auth-provider-standard/testing`:

| Export | What it is |
| --- | --- |
| [`standardSmtpMailSenderConfigForTests`](src/testing/index.mts) | The SMTP sender's section, keyed by its module's name, as the reference defaults it, with the keys a test lays over it |
