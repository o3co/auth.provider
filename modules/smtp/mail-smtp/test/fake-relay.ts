import { createServer, type Server, type Socket } from "node:net";
import { TLSSocket, type TlsOptions, createServer as tlsServer } from "node:tls";

/** How the fake relay behaves. */
export interface Script {
	/** EHLO's extensions; STARTTLS is offered only before TLS. */
	readonly extensions?: readonly string[];
	/** The certificate for STARTTLS, or for TLS from the first byte with `implicit`, and any other server options. */
	readonly certificate?: TlsOptions;
	readonly implicit?: boolean;
	/** Replies in place of the defaults, by verb ("greeting", "EHLO", "MAIL", "RCPT", "DATA", "message", "AUTH", "STARTTLS", "QUIT"). "drop" closes the connection, "none" says nothing. */
	readonly replies?: Readonly<Record<string, string>>;
	/** Answers EHLO with a continuation line every so many ms, never ending. */
	readonly trickleMs?: number;
}

export interface FakeRelay {
	readonly port: number;
	/** Each command line as received; "(tls)" marks where TLS began. */
	readonly lines: string[];
	/** Each message as received, up to its final dot. */
	readonly messages: string[];
	/** Bytes received over every connection. */
	readonly received: () => number;
	/** The code of each TLS error on its side: a handshake it refused, or a connection broken after. */
	readonly refused: string[];
	close(): Promise<void>;
}

const defaults: Readonly<Record<string, string>> = {
	greeting: "220 relay.test ESMTP",
	MAIL: "250 2.1.0 ok",
	RCPT: "250 2.1.5 ok",
	DATA: "354 go ahead",
	message: "250 2.0.0 queued",
	AUTH: "235 2.7.0 accepted",
	STARTTLS: "220 2.0.0 ready",
	QUIT: "221 2.0.0 bye",
	RSET: "250 ok",
	NOOP: "250 ok",
};

/** A scripted SMTP relay on loopback. */
export async function fakeRelay(script: Script = {}): Promise<FakeRelay> {
	const lines: string[] = [];
	const messages: string[] = [];
	const refused: string[] = [];
	const noteRefused = (error: NodeJS.ErrnoException) => refused.push(error.code ?? error.message);
	const sockets = new Set<Socket>();
	let received = 0;
	const replyTo = (verb: string) => script.replies?.[verb] ?? defaults[verb] ?? "502 5.5.1 unknown";

	const serve = (plain: Socket) => {
		sockets.add(plain);
		plain.on("error", () => {});
		let socket: Socket = plain;
		let secured = script.implicit === true;
		let buffer = "";
		let message: string[] | undefined;
		let trickle: ReturnType<typeof setInterval> | undefined;
		plain.on("close", () => clearInterval(trickle));
		const say = (reply: string) => {
			if (reply === "drop") return socket.destroy();
			if (reply !== "none") socket.write(`${reply}\r\n`);
		};
		const ehlo = () => {
			if (script.trickleMs !== undefined) {
				trickle = setInterval(() => socket.write("250-still here\r\n"), script.trickleMs);
				return;
			}
			if (script.replies?.EHLO) return say(script.replies.EHLO);
			const offered = (script.extensions ?? []).filter((e) => !(secured && e === "STARTTLS"));
			const all = ["relay.test", ...offered];
			socket.write(all.map((e, i) => `250${i === all.length - 1 ? " " : "-"}${e}\r\n`).join(""));
		};
		const command = (text: string) => {
			lines.push(text);
			const verb = text.split(/[ :]/)[0]?.toUpperCase() ?? "";
			if (verb === "EHLO") return ehlo();
			if (verb === "DATA") {
				const reply = replyTo("DATA");
				if (reply.startsWith("354")) message = [];
				return say(reply);
			}
			const offered = verb !== "STARTTLS" || script.extensions?.includes("STARTTLS");
			const reply = offered ? replyTo(verb) : "502 5.5.1 not offered";
			say(reply);
			if (verb === "QUIT") socket.end();
			if (verb === "STARTTLS" && reply.startsWith("220") && script.certificate) {
				socket.off("data", read);
				socket = new TLSSocket(plain, { isServer: true, ...script.certificate });
				socket.on("error", noteRefused);
				socket.on("data", read);
				secured = true;
				lines.push("(tls)");
			}
		};
		const read = (chunk: Buffer) => {
			received += chunk.length;
			buffer += chunk.toString("utf8");
			for (let end = buffer.indexOf("\r\n"); end >= 0; end = buffer.indexOf("\r\n")) {
				const text = buffer.slice(0, end);
				buffer = buffer.slice(end + 2);
				if (message === undefined) command(text);
				else if (text !== ".") message.push(text);
				else {
					messages.push(message.join("\r\n"));
					message = undefined;
					say(replyTo("message"));
				}
			}
		};
		socket.on("data", read);
		say(replyTo("greeting"));
	};

	const server: Server = script.implicit
		? tlsServer({ ...script.certificate }, serve)
		: createServer(serve);
	server.on("tlsClientError", noteRefused);
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const address = server.address();
	if (address === null || typeof address === "string") throw new Error("no port");
	return {
		port: address.port,
		lines,
		messages,
		received: () => received,
		refused,
		close: () =>
			new Promise((resolve) => {
				for (const s of sockets) s.destroy();
				server.close(() => resolve());
			}),
	};
}
