# @o3co/auth-provider-standard

Last updated: 2026-09-30

Standard, replaceable implementations of the duties outside [`auth.provider`](../../README.md): what a deployment needs beside the provider and may write for itself instead. For now, the mail senders the one-time codes the provider issues leave through.

## Responsibility

**Role.** The provider's duties end at its interfaces. It issues a code and hands a `MailSender` what the mail means — its purpose, the account, the recipient, the code and its expiry (core's `MailSend`) — and a sender renders it, delivers it and applies any limit on sending. This package holds the senders a deployment can install as they are: an SMTP sender and a development sender.

**Owns:**
- the text each purpose is rendered as (`renderStandardMail`): a subject line and a plain-text body in English, carrying the code and the minutes it has left, and nothing else of the send — not the account, not the recipient, nothing clickable;
- `standardSmtpMailSenderModule` and its section, `standard-smtp-mail-sender`, with their defaults in [`config/reference.conf`](config/reference.conf) (exported as `@o3co/auth-provider-standard/reference.conf`);
- the development sender and its module, `standardDevelopmentMailSenderModule`, which alone publishes it;
- the builders a test assembles this package's configuration with, on `@o3co/auth-provider-standard/testing`.

**Does not own:** the `MailSender` port, `MailSend`, the closed list of purposes and the `mailSender` slot — core's ([`packages/core/src/mail/`](../core/src/mail/types.mts)); the conformance suite a sender runs, `mailSenderContract` — [`@o3co/auth-provider-test-kit`](../test-kit/README.md)'s; which code is issued, when, and to whom — the provider's.

**Why a separate package.** A sender is replaceable: a deployment that delivers through its own mail service implements `send` and installs none of this. The provider's packages depend on core alone, and so does this one, so the provider never reaches a mail library through it.

## The SMTP sender

`standardSmtpMailSenderModule` declares its section, which boot parses and holds to its rules. This build has no SMTP delivery: the module provides no sender, so a composition that needs a `mailSender` and installs only this module is refused for want of one.

One section, the module's and named after it: `standard-smtp-mail-sender`. Boot parses it with the module's schema before any factory runs and refuses a key the section does not know, by its name. No refusal quotes a value, the password included. Layer [`config/reference.conf`](config/reference.conf) between your `application.conf` and core's `reference.conf`; the module declares it as its section's reference, so core's `moduleReferences(modules)` names it among the files to layer.

| Key | Env | Default | Meaning |
| --- | --- | --- | --- |
| `standard-smtp-mail-sender.host` | `STANDARD_SMTP_MAIL_SENDER_HOST` | none | The relay's host: one line of well-formed text, not blank, with no control character |
| `standard-smtp-mail-sender.port` | `STANDARD_SMTP_MAIL_SENDER_PORT` | `587` | 1 to 65535 |
| `standard-smtp-mail-sender.secure` | `STANDARD_SMTP_MAIL_SENDER_SECURE` | `starttls` | `starttls` (upgrade a plain connection), `tls` (implicit TLS) or `none` — plaintext, taken only to `localhost` or a loopback address written in its canonical form (`127.0.0.1`, `::1`), and refused with no host: another spelling of an address (`127.0.0.08`, `2130706433`) is a name a resolver may send anywhere |
| `standard-smtp-mail-sender.user` | `STANDARD_SMTP_MAIL_SENDER_USER` | none | The account the relay is signed in with |
| `standard-smtp-mail-sender.password` | `STANDARD_SMTP_MAIL_SENDER_PASSWORD` | none | Its password, from the environment |
| `standard-smtp-mail-sender.from` | `STANDARD_SMTP_MAIL_SENDER_FROM` | none | The sender's address, one line |

## The development sender

`standardDevelopmentMailSenderModule({ environment })` fills the `mailSender` slot with a sender that delivers nothing: each send is one line at info, `mail_code_issued`, carrying the purpose and the code, so a developer reads the code off the log. It has no settings and no section, and the sender is published only through it.

A code in a log line is a secret wherever more than the developer reads the log, so the module lets the sender in only where it should be: an allow-list rather than a list of what to refuse. Its factory runs at every boot, whether or not anything reads the slot, and refuses the boot unless `environment` — the name the configuration was selected by; the standalone template passes `CONFIG_ENV || NODE_ENV || "development"` — reads as `development` or `test`. It refuses too where that name, `CONFIG_ENV` or `NODE_ENV` reads as `production` or `staging` (core's `productionEnvironmentIn`, each read whatever its case and the whitespace around it, none lifting another's), and where `core.deployment.mode` is `"multi"`.

## API

| Export | What it is |
| --- | --- |
| [`renderStandardMail`](src/mail/render.mts) | A send's subject line and body at a given time; a `RangeError` that quotes nothing of the send for one it cannot render |
| [`standardSmtpMailSenderModule`](src/mail/smtp/module.mts) | The SMTP mail sender's module, `standard-smtp-mail-sender`: its section |
| [`standardSmtpMailSenderConfigSchema`](src/mail/smtp/config.mts) | The shape and rules of `standard-smtp-mail-sender` |
| [`standardDevelopmentMailSenderModule`](src/mail/development/module.mts) | The development sender's module, for the environment the configuration was selected by |

On `@o3co/auth-provider-standard/testing`:

| Export | What it is |
| --- | --- |
| [`standardSmtpMailSenderConfigForTests`](src/testing/index.mts) | The SMTP sender's section, keyed by its module's name, as the reference defaults it, with the keys a test lays over it |
