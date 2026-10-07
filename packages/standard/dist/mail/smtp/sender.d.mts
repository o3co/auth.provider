/**
 * The SMTP `MailSender`: each send one connection to the relay, over
 * nodemailer's SMTP connection, carrying the standard rendering.
 *
 * Guarantees:
 * - The envelope names one recipient, `mail.to` as written, and the `To`
 *   header carries it alone in angle brackets, written here rather than by
 *   an address parser. A recipient that is not one addr-spec in its
 *   normalised spelling is a `RangeError`; one the transport cannot send to
 *   as written — a quoted local part holding `<` or `>`, or an address
 *   beyond ASCII to a relay that does not offer SMTPUTF8 — is `rejected`
 *   before the envelope is sent.
 * - `tls` is TLS from the first byte; `starttls` requires STARTTLS and sends
 *   nothing more if it fails; `none` is plaintext, and only where the
 *   connected socket's address is loopback. The relay's certificate is
 *   always verified, against the configured host, whatever the process
 *   environment says. The account signs in only once the connection is
 *   secured as `secure` says.
 * - The TCP connection, implicit TLS's handshake, the greeting and each
 *   answer have a deadline, and so does the whole send up to the relay's
 *   answer to the message, which nothing the relay sends extends.
 * - A delivery ends with QUIT, bounded on its own; neither QUIT's answer nor
 *   its failure changes a delivery the relay confirmed. Every send ends with
 *   its socket destroyed.
 * - A limit is answered `refused_at_limit`; anything else rejects with a
 *   `MailTransportError` (see `failure.mts`). The sender logs nothing.
 */
import { type Socket } from "node:net";
import type { SecureContextOptions } from "node:tls";
import { type MailSender } from "@o3co/auth-provider-core";
import type { StandardSmtpMailSenderSettings } from "./config.mjs";
/**
 * How long a send waits, in milliseconds. The whole send, up to the relay's
 * answer to the message, has these three together, however the relay spaces
 * what it sends.
 */
export interface SmtpTimeouts {
    /** For the TCP connection; implicit TLS's handshake then has as long again. */
    readonly connectMs: number;
    /** For the relay's greeting. */
    readonly greetingMs: number;
    /** For any answer once connected: the longest silence taken. */
    readonly idleMs: number;
}
/** What the sender takes from outside its section. */
export interface StandardSmtpMailSenderDependencies {
    /** Opens the connection to the relay; `net.connect` unless given. */
    readonly connect?: (target: {
        readonly host: string;
        readonly port: number;
    }) => Socket;
    /** Certificate authorities trusted in place of the platform's for the relay's certificate. */
    readonly ca?: SecureContextOptions["ca"];
    readonly timeouts?: Partial<SmtpTimeouts>;
    /** The clock the minutes a code has left are counted from. */
    readonly now?: () => number;
}
/**
 * The SMTP sender over `settings`, the section as its schema parsed it. A
 * setting it cannot send without — no host, no single sender address, a
 * user without a password or the other way round — is a `RangeError` naming
 * the key and quoting no value.
 */
export declare function createStandardSmtpMailSender(settings: StandardSmtpMailSenderSettings, dependencies?: StandardSmtpMailSenderDependencies): MailSender;
//# sourceMappingURL=sender.d.mts.map