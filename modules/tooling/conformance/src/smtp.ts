import { createServer, type Socket } from "node:net";

/** A message the fake took: its envelope, and its text decoded as its transfer encoding says. */
export interface Mailed {
	readonly from: string;
	readonly to: readonly string[];
	readonly headers: Readonly<Record<string, string>>;
	readonly text: string;
}

/** What a fake relay took. */
export interface Mailbox {
	/** Every message it took, in order. */
	readonly received: readonly Mailed[];
	/** The latest message to the address, compared without case; none when there is none. */
	latestTo(address: string): Mailed | undefined;
}

export interface FakeSmtp extends Mailbox {
	readonly host: string;
	readonly port: number;
	stop(): Promise<void>;
}

const host = "127.0.0.1";

const addressIn = (arg: string) => /<([^>]*)>/.exec(arg)?.[1] ?? arg.trim();

/** RFC 2045 §6.7 and §6.8: the two transfer encodings a sender uses for text. */
function decoded(body: string, encoding: string | undefined): string {
	const kind = encoding?.trim().toLowerCase();
	if (kind === "base64") return Buffer.from(body.replace(/\s+/g, ""), "base64").toString("utf8");
	if (kind !== "quoted-printable") return body;
	const joined = body.replace(/=\r?\n/g, "");
	const bytes = Buffer.from(
		joined.replace(/=([0-9A-Fa-f]{2})/g, (_, hex: string) =>
			String.fromCharCode(Number.parseInt(hex, 16)),
		),
		"latin1",
	);
	return bytes.toString("utf8");
}

/** Headers and the decoded body of a message as sent, folded headers unfolded. */
function parsed(data: string): Pick<Mailed, "headers" | "text"> {
	const split = data.search(/\r?\n\r?\n/);
	const head = split < 0 ? data : data.slice(0, split);
	const body = split < 0 ? "" : data.slice(split).replace(/^\r?\n\r?\n/, "");
	const headers: Record<string, string> = {};
	for (const line of head.replace(/\r?\n[ \t]+/g, " ").split(/\r?\n/)) {
		const at = line.indexOf(":");
		if (at > 0) headers[line.slice(0, at).trim().toLowerCase()] = line.slice(at + 1).trim();
	}
	return { headers, text: decoded(body, headers["content-transfer-encoding"]) };
}

/** A fake SMTP relay at loopback, on a free port unless one is given; plain SMTP, every message taken. */
export async function fakeSmtp(port = 0): Promise<FakeSmtp> {
	const received: Mailed[] = [];
	const sockets = new Set<Socket>();
	const server = createServer((socket) => {
		sockets.add(socket);
		socket.on("close", () => sockets.delete(socket));
		socket.on("error", () => socket.destroy());
		let from = "";
		let to: string[] = [];
		let data: string[] | undefined;
		let pending = "";
		const say = (line: string) => socket.write(`${line}\r\n`);
		const line = (text: string) => {
			if (data) {
				if (text !== ".") {
					// RFC 5321 §4.5.2: a line the sender began with a dot carries one more.
					data.push(text.startsWith(".") ? text.slice(1) : text);
					return;
				}
				received.push({ from, to, ...parsed(data.join("\r\n")) });
				data = undefined;
				from = "";
				to = [];
				say("250 taken");
				return;
			}
			const [verb = "", ...rest] = text.split(" ");
			const arg = rest.join(" ");
			switch (verb.toUpperCase()) {
				case "EHLO":
					say("250-fake");
					say("250 8BITMIME");
					return;
				case "HELO":
				case "NOOP":
					say("250 ok");
					return;
				case "MAIL":
					from = addressIn(arg.replace(/^FROM:/i, ""));
					say("250 ok");
					return;
				case "RCPT":
					to.push(addressIn(arg.replace(/^TO:/i, "")));
					say("250 ok");
					return;
				case "DATA":
					data = [];
					say("354 go on");
					return;
				case "RSET":
					from = "";
					to = [];
					say("250 ok");
					return;
				case "QUIT":
					say("221 bye");
					socket.end();
					return;
				default:
					say("502 not here");
			}
		};
		socket.on("data", (chunk: Buffer) => {
			pending += chunk.toString("utf8");
			for (let at = pending.indexOf("\r\n"); at >= 0; at = pending.indexOf("\r\n")) {
				line(pending.slice(0, at));
				pending = pending.slice(at + 2);
			}
		});
		say("220 fake ESMTP");
	});
	await new Promise<void>((started, failed) => {
		server.once("error", (error: NodeJS.ErrnoException) =>
			failed(
				error.code === "EADDRINUSE" ? new Error(`fake SMTP: ${host}:${port} is in use`) : error,
			),
		);
		server.listen(port, host, () => started());
	});
	const address = server.address();
	return {
		host,
		port: typeof address === "object" && address ? address.port : port,
		received,
		latestTo: (address) =>
			received.findLast((mailed) =>
				mailed.to.some((to) => to.toLowerCase() === address.toLowerCase()),
			),
		stop: async () => {
			for (const socket of sockets) socket.destroy();
			await new Promise<void>((done) => server.close(() => done()));
		},
	};
}
