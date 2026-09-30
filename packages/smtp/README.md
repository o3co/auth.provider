# @o3co/auth-provider-smtp

Last updated: 2026-09-30

An SMTP `MailSender` for [`auth.provider`](../../README.md): how multi-factor authentication's one-time codes and security notices leave the provider — the package [the MFA ADR](../core/docs/adr/2026-09-25-multi-factor-authentication.md) places SMTP in (its D5).

> **Private, and not built.** The package is `"private": true` and its module provides no sender yet: it declares its section, which boot parses and holds to its rules. A composition that needs a `mailSender` is refused for want of one until the sender lands (the ADR's build-order step 17).

## Responsibility

**Role.** The adapter behind core's `MailSender` port for a deployment that delivers over SMTP: the MFA package renders a message and hands it to the `mailSender` slot, and this package is one thing that can fill it. A deployment that delivers through its own mail service implements `send` and installs none of this.

**Owns:** `smtpMailSenderModule` and its section, `smtp-mail-sender` — its defaults ([`config/reference.conf`](config/reference.conf), exported as `@o3co/auth-provider-smtp/reference.conf`) and its refusals.

**Does not own:** the `MailSender` port, `MailMessage` and the `mailSender` slot — core's (`packages/core/src/mail/`), with its contract suite, `mailSenderContract`, and a recording sender for tests on `@o3co/auth-provider-core/testing`; what a message says — the MFA package renders it.

**Why a separate package.** Its implementer and its consumer must not depend on each other (D5): the MFA package reaches mail through core's port, and a deployment that does not send over SMTP installs no mail library.

## Configuration

One section, its module's and named after it: `smtp-mail-sender`. Boot parses it with the module's schema before any factory runs, and refuses a key the section does not know. Layer [`config/reference.conf`](config/reference.conf) between your `application.conf` and core's `reference.conf`; `smtpMailSenderModule` declares it as its section's reference, so core's `moduleReferences(modules)` names it among the files to layer.

| Key | Env | Default | Meaning |
| --- | --- | --- | --- |
| `smtp-mail-sender.host` | `SMTP_MAIL_SENDER_HOST` | none | The relay's host: one line of well-formed text, not blank, with no control character |
| `smtp-mail-sender.port` | `SMTP_MAIL_SENDER_PORT` | `587` | 1 to 65535 |
| `smtp-mail-sender.secure` | `SMTP_MAIL_SENDER_SECURE` | `starttls` | `starttls` (upgrade a plain connection), `tls` (implicit TLS) or `none` — plaintext, taken only to `localhost` or a loopback address written in its canonical form (`127.0.0.1`, `::1`), and refused with no host: another spelling of an address (`127.0.0.08`, `2130706433`) is a name a resolver may send anywhere |
| `smtp-mail-sender.user` | `SMTP_MAIL_SENDER_USER` | none | The account the relay is signed in with |
| `smtp-mail-sender.password` | `SMTP_MAIL_SENDER_PASSWORD` | none | Its password, from the environment |
| `smtp-mail-sender.from` | `SMTP_MAIL_SENDER_FROM` | none | The sender's address, one line |

## API

| Export | What it is |
| --- | --- |
| [`smtpMailSenderModule`](src/module.mts) | The SMTP mail sender's module, `smtp-mail-sender`: its section; it provides no sender yet |
| [`smtpMailSenderConfigSchema`](src/config.mts) | The shape and rules of `smtp-mail-sender` |
