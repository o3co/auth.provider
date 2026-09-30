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
 *   normalised spelling, or that the envelope cannot carry as written (a
 *   quoted local part holding `<` or `>`), is refused before any connection.
 * - `tls` is TLS from the first byte; `starttls` requires STARTTLS and sends
 *   nothing more if it fails; `none` is plaintext, and only where the
 *   connected socket's address is loopback. The relay's certificate is
 *   always verified, against the configured host. The account signs in only
 *   once the connection is secured as `secure` says.
 * - Connecting, the greeting and each answer have a deadline.
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
import { MailTransportError, readSendFailure } from "./failure.mjs";

const SECTION = "standard-smtp-mail-sender";

/** How long a send waits for each step, in milliseconds. */
export interface SmtpTimeouts {
	/** For the connection, and implicit TLS's handshake. */
	readonly connectMs: number;
	/** For the relay's greeting. */
	readonly greetingMs: number;
	/** For any answer once connected. */
	readonly idleMs: number;
}

const TIMEOUTS: SmtpTimeouts = { connectMs: 10_000, greetingMs: 10_000, idleMs: 20_000 };

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

/** The account the relay is signed in with, or none: a user and a password together. */
function credentialsOf(
	user: string | undefined,
	password: string | undefined,
): { readonly user: string; readonly pass: string } | undefined {
	if (user === undefined && password === undefined) return undefined;
	if (user === undefined) throw unsendable("user", "is not set, and a password is");
	if (password === undefined) throw unsendable("password", "is not set, and a user is");
	return { user, pass: password };
}

/** Whether a connected socket's peer is on the loopback interface, IPv4-mapped included. */
const isLoopbackPeer = createTrustedProxyMatcher(["loopback"], { label: SECTION });

/**
 * `mail.to` as the envelope carries it, or a refusal naming nothing of it:
 * one addr-spec in its normalised spelling, with no angle bracket the
 * transport would refuse or rewrite.
 */
function recipientOf(mail: MailSend): string {
	const to: unknown = mail.to;
	if (typeof to !== "string" || normaliseMailAddress(to) !== to) {
		throw new RangeError(`${SECTION}: the recipient is not one address in its normalised spelling`);
	}
	if (/[<>]/.test(to)) {
		throw new RangeError(
			`${SECTION}: the recipient's quoted local part holds an angle bracket, which an SMTP envelope cannot carry as written`,
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

/**
 * A connection to the relay, open within `connectMs`; under `none`, only to
 * a loopback address.
 */
function openConnection(
	target: { readonly host: string; readonly port: number },
	plaintext: boolean,
	connectMs: number,
	connect: NonNullable<StandardSmtpMailSenderDependencies["connect"]>,
): Promise<Socket> {
	return new Promise((resolve, reject) => {
		const socket = connect(target);
		const fail = (error: MailTransportError): void => {
			clearTimeout(deadline);
			socket.removeListener("connect", connected);
			socket.removeListener("error", refused);
			// A late error from the discarded socket is not this send's.
			socket.on("error", () => {});
			socket.destroy();
			reject(error);
		};
		const refused = (): void =>
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
			resolve(socket);
		};
		const deadline = setTimeout(
			() => fail(new MailTransportError("no connection to the relay in time", "timeout")),
			connectMs,
		);
		socket.once("error", refused);
		socket.once("connect", connected);
	});
}

/** Greets, signs in where an account is set, and sends one message; closes the connection whatever came of it. */
function exchange(
	connection: SMTPConnection,
	credentials: { readonly user: string; readonly pass: string } | undefined,
	envelope: { readonly from: string; readonly to: readonly string[] },
	message: Buffer,
): Promise<void> {
	return new Promise((resolve, reject) => {
		let settled = false;
		const finish = (failure?: unknown): void => {
			if (settled) return;
			settled = true;
			connection.close();
			if (failure === undefined || failure === null) resolve();
			else reject(failure);
		};
		connection.on("error", finish);
		connection.connect((failure) => {
			if (failure) return finish(failure);
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
	const connect = dependencies.connect ?? ((target) => netConnect(target));
	const now = dependencies.now ?? Date.now;
	const tls = {
		minVersion: "TLSv1.2" as const,
		...(dependencies.ca === undefined ? {} : { ca: dependencies.ca }),
	};

	return {
		kind: "standard-smtp",
		async send(mail: MailSend): Promise<MailSendResult> {
			const to = recipientOf(mail);
			const { subjectLine, text } = renderStandardMail(mail, now());
			const message = await messageOf(to, sender, subjectLine, text);
			const socket = await openConnection(
				{ host, port },
				secure === "none",
				timeouts.connectMs,
				connect,
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
			try {
				await exchange(connection, credentials, { from: sender.address, to: [to] }, message);
			} catch (failure) {
				const read = readSendFailure(failure);
				if (read === "refused_at_limit") return { outcome: "refused_at_limit" };
				throw read;
			}
			return { outcome: "delivered" };
		},
	};
}
