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
 * An SMTP relay a test scripts, listening on `127.0.0.1`: it secures a
 * connection with implicit TLS, offers STARTTLS, or neither, with the
 * fixture certificate; offers AUTH PLAIN when asked, and SMTPUTF8 unless
 * told not to; answers each stage as a relay that accepts, or with the reply
 * a test gives it, or not at all, or a byte at a time without ever ending the
 * line, or by resetting the connection, each after a delay if asked; and
 * records every command line with when it arrived and whether the connection
 * was secured then, and each mail it accepted: the recipients its envelope
 * named, as written between the angle brackets, and the whole message.
 */

import { readFileSync } from "node:fs";
import { createServer, type Socket } from "node:net";
import { createSecureContext, TLSSocket } from "node:tls";
import type { RelayedMail } from "@o3co/auth-provider-test-kit";

const fixture = (name: string): Buffer =>
	readFileSync(new URL(`../fixtures/${name}`, import.meta.url));

/** The CA the fixture relay certificate chains to (for `localhost`, `127.0.0.1` and `::1`). */
export const RELAY_CA = fixture("relay-ca.pem");
export const RELAY_CERT = fixture("relay-cert.pem");
export const RELAY_KEY = fixture("relay-key.pem");

const secureContext = createSecureContext({ cert: RELAY_CERT, key: RELAY_KEY });

/** What a relay reply answers. */
export type RelayStage =
	| "greeting"
	| "ehlo"
	| "starttls"
	| "auth"
	| "mail"
	| "rcpt"
	| "data"
	| "message"
	| "quit";

export interface ScriptedRelayOptions {
	/** Implicit TLS from the first byte, STARTTLS offered, or neither. `starttls` by default. */
	readonly security?: "tls" | "starttls" | "none";
	/** Whether EHLO offers AUTH PLAIN. */
	readonly auth?: boolean;
	/** Replies in place of the relay's own, by the stage they answer. */
	readonly replies?: Partial<Record<RelayStage, string>>;
	/** The stage the relay never answers, holding the connection open. */
	readonly silent?: RelayStage;
	/** The stage whose reply the relay starts and never ends, a byte every 20 ms. */
	readonly trickle?: RelayStage;
	/** The stage the relay answers by resetting the connection. */
	readonly reset?: RelayStage;
	/** Whether EHLO offers SMTPUTF8; it does unless this is false. */
	readonly smtputf8?: boolean;
	/** Whether the relay keeps its side of a connection open once the client has closed its own. */
	readonly allowHalfOpen?: boolean;
	/** How long the relay waits before its reply to each stage named, in milliseconds. */
	readonly delays?: Partial<Record<RelayStage, number>>;
}

/** What a test may script anew between connections. */
type Script = Pick<ScriptedRelayOptions, "replies" | "silent" | "trickle" | "reset" | "delays">;

/** A command line as the relay read it, and whether TLS protected it. */
export interface RelayCommand {
	readonly line: string;
	readonly secure: boolean;
	/** When the relay read it, in epoch milliseconds. */
	readonly at: number;
}

export interface ScriptedRelay {
	readonly port: number;
	/** The mails the relay accepted, oldest first. */
	readonly relayed: () => Promise<RelayedMail[]>;
	/** Every command line it read, in order. */
	readonly commands: () => readonly RelayCommand[];
	/** How many connections it took. */
	readonly connections: () => number;
	/** Scripts the replies, and the stage never answered, of every connection from now on. */
	readonly rescript: (script: Script) => void;
	readonly close: () => Promise<void>;
}

const OWN_REPLIES: Readonly<Record<Exclude<RelayStage, "ehlo">, string>> = {
	greeting: "220 relay.test ESMTP",
	starttls: "220 2.0.0 Ready to start TLS",
	auth: "235 2.7.0 Authentication successful",
	mail: "250 2.1.0 Ok",
	rcpt: "250 2.1.5 Ok",
	data: "354 End data with <CR><LF>.<CR><LF>",
	message: "250 2.0.0 Ok: queued",
	quit: "221 2.0.0 Bye",
};

/** Starts a relay as `options` scripts it. */
export async function startScriptedRelay(
	options: ScriptedRelayOptions = {},
): Promise<ScriptedRelay> {
	const security = options.security ?? "starttls";
	const commands: RelayCommand[] = [];
	const accepted: RelayedMail[] = [];
	const sockets = new Set<Socket>();
	let connections = 0;
	let script: Script = options;

	const serve = (plain: Socket): void => {
		connections += 1;
		sockets.add(plain);
		plain.on("close", () => sockets.delete(plain));
		plain.on("error", () => {});
		let socket: Socket = plain;
		let secure = false;
		let pending = Buffer.alloc(0);
		let inData = false;
		let dataLines: string[] = [];
		let recipients: string[] = [];
		const { replies, silent, trickle, reset, delays } = script;

		/** Writes `opening`, then a byte every 20 ms, never ending the line. */
		const trickling = (opening: string): void => {
			socket.write(opening);
			const timer = setInterval(() => {
				if (socket.destroyed || !socket.writable) clearInterval(timer);
				else socket.write("x");
			}, 20);
			plain.once("close", () => clearInterval(timer));
		};

		/** Answers `stage`, as scripted, after its delay; `then` runs once a whole reply is written. */
		const answer = (stage: RelayStage, own: string, then?: () => void): void => {
			const respond = (): void => {
				if (reset === stage) {
					plain.resetAndDestroy();
					return;
				}
				if (silent === stage) return;
				const reply = replies?.[stage] ?? own;
				if (trickle === stage) {
					trickling(reply.slice(0, 4));
					return;
				}
				socket.write(`${reply}\r\n`);
				then?.();
			};
			const delay = delays?.[stage];
			if (delay === undefined) respond();
			else setTimeout(respond, delay);
		};

		const ehloReply = (): string => {
			const lines = [
				"relay.test",
				"8BITMIME",
				...(options.smtputf8 === false ? [] : ["SMTPUTF8"]),
				"ENHANCEDSTATUSCODES",
			];
			if (security === "starttls" && !secure) lines.push("STARTTLS");
			if (options.auth) lines.push("AUTH PLAIN");
			return lines.map((line, i) => `250${i === lines.length - 1 ? " " : "-"}${line}`).join("\r\n");
		};

		const starttls = (): void => {
			if (security !== "starttls" || secure) {
				answer("starttls", "502 5.5.1 STARTTLS not offered");
				return;
			}
			answer("starttls", OWN_REPLIES.starttls);
			if (replies?.starttls === undefined && ![silent, trickle, reset].includes("starttls")) {
				upgrade();
			}
		};

		const data = (): void => {
			answer("data", OWN_REPLIES.data);
			if ((replies?.data ?? OWN_REPLIES.data).startsWith("354")) {
				inData = true;
				dataLines = [];
			}
		};

		const command = (line: string): void => {
			commands.push({ line, secure, at: Date.now() });
			const verb = line.split(" ", 1)[0]?.toUpperCase() ?? "";
			if (verb === "EHLO" || verb === "HELO") answer("ehlo", ehloReply());
			else if (verb === "STARTTLS") starttls();
			else if (verb === "AUTH")
				answer("auth", options.auth ? OWN_REPLIES.auth : "502 5.5.1 AUTH not offered");
			else if (/^MAIL FROM:/i.test(line)) {
				recipients = [];
				answer("mail", OWN_REPLIES.mail);
			} else if (/^RCPT TO:/i.test(line)) {
				const argument = line.slice("RCPT TO:".length);
				recipients.push(argument.slice(argument.indexOf("<") + 1, argument.lastIndexOf(">")));
				answer("rcpt", OWN_REPLIES.rcpt);
			} else if (verb === "DATA") data();
			else if (verb === "RSET" || verb === "NOOP") socket.write("250 2.0.0 Ok\r\n");
			else if (verb === "QUIT") {
				answer("quit", OWN_REPLIES.quit, () => socket.end());
			} else socket.write("502 5.5.2 Command not recognized\r\n");
		};

		const endOfData = (): void => {
			inData = false;
			const content = dataLines.map((l) => (l.startsWith("..") ? l.slice(1) : l)).join("\r\n");
			const reply = replies?.message ?? OWN_REPLIES.message;
			if (reply.startsWith("2") && ![silent, trickle, reset].includes("message")) {
				accepted.push({ to: [...recipients], content });
			}
			answer("message", OWN_REPLIES.message);
		};

		const read = (chunk: Buffer): void => {
			pending = Buffer.concat([pending, chunk]);
			for (let end = pending.indexOf("\r\n"); end !== -1; end = pending.indexOf("\r\n")) {
				const line = pending.subarray(0, end).toString("utf8");
				pending = pending.subarray(end + 2);
				if (inData) {
					if (line === ".") endOfData();
					else dataLines.push(line);
					continue;
				}
				command(line);
				// A STARTTLS upgrade discards what the plain connection held.
				if (socket !== plain && !secure) return;
			}
		};

		const upgrade = (): void => {
			plain.removeListener("data", read);
			pending = Buffer.alloc(0);
			const tlsSocket = new TLSSocket(plain, { isServer: true, secureContext });
			tlsSocket.on("error", () => {});
			tlsSocket.on("secure", () => {
				secure = true;
			});
			tlsSocket.on("data", read);
			socket = tlsSocket;
		};

		if (security === "tls") {
			const tlsSocket = new TLSSocket(plain, { isServer: true, secureContext });
			tlsSocket.on("error", () => {});
			socket = tlsSocket;
			tlsSocket.on("secure", () => {
				secure = true;
				answer("greeting", OWN_REPLIES.greeting);
			});
			tlsSocket.on("data", read);
			return;
		}
		plain.on("data", read);
		answer("greeting", OWN_REPLIES.greeting);
	};

	const server = createServer({ allowHalfOpen: options.allowHalfOpen === true }, serve);
	await new Promise<void>((resolve, reject) => {
		server.once("error", reject);
		server.listen(0, "127.0.0.1", () => resolve());
	});
	const address = server.address();
	if (address === null || typeof address === "string") throw new Error("the relay has no port");

	return {
		port: address.port,
		relayed: async () => accepted.map((mail) => ({ to: [...mail.to], content: mail.content })),
		commands: () => [...commands],
		connections: () => connections,
		rescript: (next) => {
			script = next;
		},
		close: async () => {
			for (const socket of sockets) socket.destroy();
			await new Promise<void>((resolve) => server.close(() => resolve()));
		},
	};
}

/** A port on `127.0.0.1` nothing listens on: one a listener held and let go. */
export async function closedPort(): Promise<number> {
	const server = createServer();
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
	const address = server.address();
	await new Promise<void>((resolve) => server.close(() => resolve()));
	if (address === null || typeof address === "string") throw new Error("no port");
	return address.port;
}
