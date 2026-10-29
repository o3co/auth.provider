import { connect as netConnect, type Socket } from "node:net";
import { isLoopbackAddress } from "@mod/address-reach";
import type { TlsOptions } from "@mod/tls-options";
import addressparser from "nodemailer/lib/addressparser";
import MailComposer from "nodemailer/lib/mail-composer";
import SMTPConnection from "nodemailer/lib/smtp-connection";
import { answerOf, RelayFailure, transportCode } from "./answers.ts";

export { RelayFailure, type Stage } from "./answers.ts";

export type Security = "starttls" | "tls" | "none";

export interface Mailbox {
	readonly name: string;
	readonly address: string;
}

export interface RelaySettings {
	readonly host: string;
	readonly port: number;
	readonly security: Security;
	readonly from: Mailbox;
	readonly account?: { readonly user: string; readonly pass: string } | undefined;
	/** For the whole send; connecting and the greeting get a quarter each, a silence half. */
	readonly deadlineMs: number;
	/** The floor every TLS connection holds to (`tls-options`): its own keys, copied last. */
	readonly floor: TlsOptions;
}

/** What one send carries: one address, already checked and in mail's canonical form, and the rendered text. */
export interface Letter {
	readonly to: string;
	readonly subject: string;
	readonly text: string;
}

/** Opens the TCP connection to the relay. */
export type Open = (host: string, port: number) => Socket;

/** The one mailbox `from` names, alone or after a display name, or none; its address unchecked. */
export function mailboxOf(from: string): Mailbox | undefined {
	const found = addressparser(from);
	const [first] = found;
	if (found.length !== 1 || first === undefined || first.group !== undefined) return undefined;
	return Object.freeze({ name: first.name, address: first.address });
}

const beyondAscii = /[^\p{ASCII}]/u;
/** The longest wait for the relay to end the connection after QUIT. */
const QUIT_MS = 1000;

/** `To` written here, alone and in angle brackets; the library composes the rest. */
async function compose(to: string, from: Mailbox, letter: Letter): Promise<Buffer> {
	const rest = await new MailComposer({
		// A copy: the library writes into the mailbox it is given.
		from: { ...from },
		subject: letter.subject,
		text: letter.text,
		disableFileAccess: true,
		disableUrlAccess: true,
	})
		.compile()
		.build();
	return Buffer.concat([Buffer.from(`To: <${to}>\r\n`), rest]);
}

/** What one send has opened, for its end to tear down. */
interface Held {
	socket?: Socket;
	connection?: SMTPConnection;
}

/** A connection within `ms`; under `none`, only to a loopback peer. */
function openSocket(settings: RelaySettings, open: Open, ms: number, held: Held): Promise<Socket> {
	return new Promise((resolve, reject) => {
		const socket = open(settings.host, settings.port);
		held.socket = socket;
		const settle = () => {
			clearTimeout(timer);
			socket.off("error", onError).off("close", onClose).off("connect", onConnect);
		};
		const fail = (failure: RelayFailure) => {
			settle();
			// A late error from the discarded socket is not this send's.
			socket.on("error", () => {});
			socket.destroy();
			reject(failure);
		};
		const onError = (error: unknown) => {
			const code = transportCode(error);
			fail(new RelayFailure("connection", code === undefined ? {} : { code }));
		};
		const onClose = () => fail(new RelayFailure("connection"));
		const onConnect = () => {
			if (settings.security === "none" && !isLoopbackAddress(socket.remoteAddress ?? "")) {
				return fail(new RelayFailure("security"));
			}
			settle();
			resolve(socket);
		};
		const timer = setTimeout(() => fail(new RelayFailure("connection", { code: "ETIMEDOUT" })), ms);
		socket.once("error", onError).once("close", onClose).once("connect", onConnect);
	});
}

/** Greets, signs in when there is an account, and sends: the relay's answer or a RelayFailure. */
function exchange(
	connection: SMTPConnection,
	settings: RelaySettings,
	to: string,
	message: Buffer,
): Promise<"sent" | "limited"> {
	const needsUtf8 = beyondAscii.test(to) || beyondAscii.test(settings.from.address);
	return new Promise((resolve, reject) => {
		let settled = false;
		const finish = (failure?: unknown) => {
			if (settled) return;
			settled = true;
			if (failure === undefined || failure === null) return resolve("sent");
			const answer = answerOf(failure, {
				securing: connection.upgrading === true,
				awaitingGreeting: connection.stage === "connected" && !connection.lastServerResponse,
			});
			if (answer === "limited") resolve(answer);
			else reject(answer);
		};
		connection.on("error", finish);
		connection.connect((failure) => {
			if (failure) return finish(failure);
			// RFC 6531: an address beyond ASCII goes only to a relay whose EHLO reply offers SMTPUTF8.
			if (needsUtf8 && !/[ -]SMTPUTF8\b/im.test(String(connection.lastServerResponse))) {
				return finish(new RelayFailure("address"));
			}
			const send = () =>
				connection.send({ from: settings.from.address, to: [to] }, message, finish);
			if (settings.account === undefined) return send();
			connection.login({ credentials: settings.account }, (refused) =>
				refused ? finish(refused) : send(),
			);
		});
	});
}

/** Sends QUIT and waits up to `ms` for the end; nothing about it changes the answer. */
function quit(connection: SMTPConnection, ms: number): Promise<void> {
	return new Promise((resolve) => {
		if (connection.destroyed) return resolve();
		const timer = setTimeout(resolve, ms);
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
 * One connection per send, never reused. The certificate is always checked against `host`, at the
 * floor's versions and suites; `starttls` sends nothing more when STARTTLS is missing or fails.
 */
export function relayOver(
	settings: RelaySettings,
	open: Open = (host, port) => netConnect({ host, port }),
): (letter: Letter) => Promise<"sent" | "limited"> {
	const { host, port, security, deadlineMs } = settings;
	// The floor read once, its own keys alone and last, so nothing loosens it.
	const tls = Object.freeze({
		rejectUnauthorized: true,
		minVersion: settings.floor.minVersion,
		ciphers: settings.floor.ciphers,
	});
	const stepMs = Math.max(1, Math.floor(deadlineMs / 4));
	const converse = async (held: Held, to: string, message: Buffer) => {
		const socket = await openSocket(settings, open, stepMs, held);
		const connection = new SMTPConnection({
			connection: socket,
			host,
			port,
			secure: security === "tls",
			requireTLS: security === "starttls",
			ignoreTLS: security === "none",
			// A copy per connection: the library may write into what it is given.
			tls: { ...tls },
			connectionTimeout: stepMs,
			greetingTimeout: stepMs,
			socketTimeout: stepMs * 2,
			logger: false,
			debug: false,
			transactionLog: false,
		});
		held.connection = connection;
		return exchange(connection, settings, to, message);
	};
	return async ({ to, ...letter }) => {
		const message = await compose(to, settings.from, { to, ...letter });
		const held: Held = {};
		const late = Promise.withResolvers<never>();
		const timer = setTimeout(() => late.reject(new RelayFailure("deadline")), deadlineMs);
		try {
			const answer = await Promise.race([converse(held, to, message), late.promise]);
			// The whole send's deadline stops here: QUIT has its own, and never changes the answer.
			clearTimeout(timer);
			if (answer === "sent" && held.connection)
				await quit(held.connection, Math.min(QUIT_MS, stepMs));
			return answer;
		} finally {
			clearTimeout(timer);
			held.connection?.close();
			held.socket?.destroy();
		}
	};
}
