/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

import { connect as netConnect, type Socket } from "node:net";
import type { SecureContextOptions } from "node:tls";
import {
	createTrustedProxyMatcher,
	type MailSend,
	type MailSender,
	type MailSendResult,
	normaliseMailAddress,
} from "@o3co/auth-provider-core";
import addressparser from "nodemailer/lib/addressparser";
import MailComposer from "nodemailer/lib/mail-composer";
import SMTPConnection from "nodemailer/lib/smtp-connection";
import { renderStandardMail } from "../render.mjs";
import type { StandardSmtpMailSenderSettings } from "./config.mjs";
import { MailTransportError, readSendFailure, transportCodeOf } from "./failure.mjs";

const SECTION = "standard-smtp-mail-sender";

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

const TIMEOUTS: SmtpTimeouts = { connectMs: 10_000, greetingMs: 10_000, idleMs: 20_000 };

/** How long a delivered send waits for the relay to answer QUIT before closing anyway. */
const QUIT_MS = 1_000;

/** What the sender takes from outside its section. */
export interface StandardSmtpMailSenderDependencies {
	/** Opens the connection to the relay; `net.connect` unless given. */
	readonly connect?: (target: { readonly host: string; readonly port: number }) => Socket;
	/** Certificate authorities trusted in place of the platform's for the relay's certificate. */
	readonly ca?: SecureContextOptions["ca"];
	readonly timeouts?: Partial<SmtpTimeouts>;
	/** The clock the minutes a code has left are counted from. */
	readonly now?: () => number;
}

/** A setting the sender cannot send without, named by its key and variable. */
const unsendable = (key: string, rule: string): RangeError =>
	new RangeError(
		`${SECTION}.${key} (STANDARD_SMTP_MAIL_SENDER_${key.toUpperCase()}) ${rule}: the SMTP sender cannot send without it`,
	);

/** The sender's address: the one mailbox `from` names, with its display name. */
function senderOf(from: string | undefined): { readonly name: string; readonly address: string } {
	if (from === undefined) throw unsendable("from", "is not set");
	const mailboxes = addressparser(from, { flatten: true });
	const [mailbox] = mailboxes;
	if (
		mailboxes.length !== 1 ||
		mailbox === undefined ||
		normaliseMailAddress(mailbox.address) === undefined ||
		/[<>]/.test(mailbox.address)
	) {
		throw unsendable("from", "must name one address, alone or after a display name");
	}
	return { name: mailbox.name, address: mailbox.address };
}

/**
 * The account the relay is signed in with, or none: a user and a password
 * together. An empty password is no password.
 */
function credentialsOf(
	user: string | undefined,
	password: string | undefined,
): { readonly user: string; readonly pass: string } | undefined {
	const pass = password === "" ? undefined : password;
	if (user === undefined && pass === undefined) return undefined;
	if (user === undefined) throw unsendable("user", "is not set, and a password is");
	if (pass === undefined) throw unsendable("password", "is not set, and a user is");
	return { user, pass };
}

/** Whether a connected socket's peer is on the loopback interface, IPv4-mapped included. */
const isLoopbackPeer = createTrustedProxyMatcher(["loopback"], { label: SECTION });

/** Whether an address needs SMTPUTF8 (RFC 6531): it holds a character beyond ASCII. */
const beyondAscii = (address: string): boolean => /[^\p{ASCII}]/u.test(address);

/**
 * `mail.to` as the envelope carries it: one addr-spec in its normalised
 * spelling (else a `RangeError`), with no angle bracket, which the transport
 * refuses in an envelope address (else `rejected`). Neither quotes it.
 */
function recipientOf(mail: MailSend): string {
	const to: unknown = mail.to;
	if (typeof to !== "string" || normaliseMailAddress(to) !== to) {
		throw new RangeError(`${SECTION}: the recipient is not one address in its normalised spelling`);
	}
	if (/[<>]/.test(to)) {
		throw new MailTransportError(
			'the recipient\'s quoted local part holds "<" or ">", which the SMTP transport refuses in an envelope address',
			"rejected",
		);
	}
	return to;
}

/** The whole message: `To` written here, then the composed rest — headers, and the text. */
async function messageOf(
	to: string,
	from: { readonly name: string; readonly address: string },
	subjectLine: string,
	text: string,
): Promise<Buffer> {
	const composed = await new MailComposer({
		from,
		subject: subjectLine,
		text,
		envelope: { from: from.address, to: [] },
		disableFileAccess: true,
		disableUrlAccess: true,
	})
		.compile()
		.build();
	return Buffer.concat([Buffer.from(`To: <${to}>\r\n`), composed]);
}

/** The socket and the SMTP connection of one send, as far as it got: what its end tears down. */
interface Attempt {
	socket?: Socket;
	connection?: SMTPConnection;
}

/**
 * A connection to the relay, open within `connectMs`, kept in `attempt` from
 * the start; under `none`, only to a loopback address.
 */
function openConnection(
	target: { readonly host: string; readonly port: number },
	plaintext: boolean,
	connectMs: number,
	connect: NonNullable<StandardSmtpMailSenderDependencies["connect"]>,
	attempt: Attempt,
): Promise<Socket> {
	return new Promise((resolve, reject) => {
		const socket = connect(target);
		attempt.socket = socket;
		const fail = (error: MailTransportError): void => {
			clearTimeout(deadline);
			socket.removeListener("connect", connected);
			socket.removeListener("error", refused);
			socket.removeListener("close", closed);
			// A late error from the discarded socket is not this send's.
			socket.on("error", () => {});
			socket.destroy();
			reject(error);
		};
		const refused = (error: unknown): void =>
			fail(
				new MailTransportError("the relay could not be reached", "unreachable", {
					code: transportCodeOf(error),
				}),
			);
		const closed = (): void =>
			fail(new MailTransportError("the relay could not be reached", "unreachable"));
		const connected = (): void => {
			if (plaintext && !isLoopbackPeer(socket.remoteAddress)) {
				fail(
					new MailTransportError(
						'secure is "none", and the connected address is not loopback: nothing was sent',
						"unreachable",
					),
				);
				return;
			}
			clearTimeout(deadline);
			socket.removeListener("error", refused);
			socket.removeListener("close", closed);
			resolve(socket);
		};
		const deadline = setTimeout(
			() => fail(new MailTransportError("no connection to the relay in time", "timeout")),
			connectMs,
		);
		socket.once("error", refused);
		socket.once("close", closed);
		socket.once("connect", connected);
	});
}

/**
 * Greets, signs in where an account is set, and sends one message: the
 * send's answer, or the `MailTransportError` it rejects with. An envelope
 * beyond ASCII goes only to a relay whose EHLO offered SMTPUTF8.
 */
function exchange(
	connection: SMTPConnection,
	credentials: { readonly user: string; readonly pass: string } | undefined,
	envelope: { readonly from: string; readonly to: readonly string[] },
	message: Buffer,
): Promise<MailSendResult> {
	const needsSmtpUtf8 = [envelope.from, ...envelope.to].some(beyondAscii);
	return new Promise((resolve, reject) => {
		let settled = false;
		const finish = (failure?: unknown): void => {
			if (settled) return;
			settled = true;
			if (failure === undefined || failure === null) {
				resolve({ outcome: "delivered" });
				return;
			}
			const read =
				failure instanceof MailTransportError
					? failure
					: readSendFailure(failure, connection.upgrading === true);
			if (read === "refused_at_limit") resolve({ outcome: "refused_at_limit" });
			else reject(read);
		};
		connection.on("error", finish);
		connection.connect((failure) => {
			if (failure) return finish(failure);
			if (needsSmtpUtf8 && !/[ -]SMTPUTF8\b/im.test(String(connection.lastServerResponse))) {
				return finish(
					new MailTransportError(
						"the relay does not offer SMTPUTF8, which an address beyond ASCII needs: nothing was sent",
						"rejected",
					),
				);
			}
			const deliver = (): void =>
				connection.send({ from: envelope.from, to: [...envelope.to] }, message, (sent) =>
					finish(sent ?? undefined),
				);
			if (credentials === undefined) return deliver();
			connection.login({ credentials }, (refused) => (refused ? finish(refused) : deliver()));
		});
	});
}

/**
 * Sends QUIT and waits, `QUIT_MS` at most, for the connection to end. Never
 * rejects: the relay's answer to QUIT, or its failure, changes nothing.
 */
function quit(connection: SMTPConnection): Promise<void> {
	return new Promise((resolve) => {
		if (connection.destroyed) {
			resolve();
			return;
		}
		const timer = setTimeout(resolve, QUIT_MS);
		connection.once("end", () => {
			clearTimeout(timer);
			resolve();
		});
		try {
			connection.quit();
		} catch {
			clearTimeout(timer);
			resolve();
		}
	});
}

/**
 * The SMTP sender over `settings`, the section as its schema parsed it. A
 * setting it cannot send without — no host, no single sender address, a
 * user without a password or the other way round — is a `RangeError` naming
 * the key and quoting no value.
 */
export function createStandardSmtpMailSender(
	settings: StandardSmtpMailSenderSettings,
	dependencies: StandardSmtpMailSenderDependencies = {},
): MailSender {
	const { host, port, secure } = settings;
	if (host === undefined) throw unsendable("host", "is not set");
	const sender = senderOf(settings.from);
	const credentials = credentialsOf(settings.user, settings.password);
	const timeouts = { ...TIMEOUTS, ...dependencies.timeouts };
	const wholeMs = timeouts.connectMs + timeouts.greetingMs + timeouts.idleMs;
	const connect = dependencies.connect ?? ((target) => netConnect(target));
	const now = dependencies.now ?? Date.now;
	const tls = {
		minVersion: "TLSv1.2" as const,
		rejectUnauthorized: true,
		...(dependencies.ca === undefined ? {} : { ca: dependencies.ca }),
	};

	/** One send over one connection, from its opening to its answer. */
	const converse = async (attempt: Attempt, to: string, message: Buffer) => {
		const socket = await openConnection(
			{ host, port },
			secure === "none",
			timeouts.connectMs,
			connect,
			attempt,
		);
		const connection = new SMTPConnection({
			connection: socket,
			host,
			port,
			secure: secure === "tls",
			requireTLS: secure === "starttls",
			ignoreTLS: secure === "none",
			tls,
			connectionTimeout: timeouts.connectMs,
			greetingTimeout: timeouts.greetingMs,
			socketTimeout: timeouts.idleMs,
			logger: false,
			debug: false,
			transactionLog: false,
		});
		attempt.connection = connection;
		return exchange(connection, credentials, { from: sender.address, to: [to] }, message);
	};

	return {
		kind: "standard-smtp",
		async send(mail: MailSend): Promise<MailSendResult> {
			const to = recipientOf(mail);
			const { subjectLine, text } = renderStandardMail(mail, now());
			const message = await messageOf(to, sender, subjectLine, text);
			const attempt: Attempt = {};
			let deadline: NodeJS.Timeout | undefined;
			const expired = new Promise<never>((_, reject) => {
				deadline = setTimeout(
					() => reject(new MailTransportError("the send did not finish in time", "timeout")),
					wholeMs,
				);
			});
			try {
				const answer = await Promise.race([converse(attempt, to, message), expired]);
				// The relay's answer is known: nothing after it, QUIT included, changes it.
				clearTimeout(deadline);
				if (answer.outcome === "delivered" && attempt.connection !== undefined) {
					await quit(attempt.connection);
				}
				return answer;
			} finally {
				clearTimeout(deadline);
				attempt.connection?.close();
				attempt.socket?.destroy();
			}
		},
	};
}
