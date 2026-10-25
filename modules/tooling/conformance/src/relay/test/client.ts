import { createConnection, createServer, type Socket } from "node:net";
import { frames, type Reply } from "../resp.ts";

/** A command as RESP2 sends it. */
export const encode = (...args: string[]) =>
	Buffer.from(
		`*${args.length}\r\n${args.map((a) => `$${Buffer.byteLength(a)}\r\n${a}\r\n`).join("")}`,
	);

/** A plain client: writes the bytes it is given as one write, and keeps each answer as it comes. */
export async function rawClient(url: string) {
	const { hostname, port } = new URL(url);
	const socket = createConnection({ host: hostname, port: Number(port) });
	await new Promise<void>((resolve, reject) => {
		socket.once("connect", resolve);
		socket.once("error", reject);
	});
	const reader = frames();
	const replies: Reply[] = [];
	let waiters: (() => void)[] = [];
	const wake = () => {
		for (const w of waiters) w();
		waiters = [];
	};
	socket.on("data", (chunk: Buffer) => {
		replies.push(...reader.push(chunk).map((f) => f.value));
		wake();
	});
	const closed = new Promise<void>((resolve) => socket.once("close", () => resolve()));
	let isClosed = false;
	void closed.then(() => {
		isClosed = true;
		wake();
	});
	socket.on("error", () => {});
	return {
		write: (...chunks: Buffer[]) => socket.write(Buffer.concat(chunks)),
		/** Each byte as its own write, a moment apart, so it arrives split. */
		trickle: async (data: Buffer) => {
			for (const b of data) {
				socket.write(Buffer.from([b]));
				await new Promise((resolve) => setTimeout(resolve, 1));
			}
		},
		/** The first `n` answers, or those that came before the connection closed. */
		replies: async (n: number, withinMs = 5_000) => {
			const until = performance.now() + withinMs;
			while (replies.length < n && !isClosed && performance.now() < until) {
				await new Promise<void>((resolve) => {
					waiters.push(resolve);
					setTimeout(resolve, 50);
				});
			}
			return replies.slice(0, n);
		},
		got: () => [...replies],
		closed,
		isClosed: () => isClosed,
		end: () => socket.destroy(),
	};
}

/** Asks a Redis one command on a connection of its own, and answers its reply. */
export async function ask(url: string, ...args: string[]): Promise<Reply | undefined> {
	const c = await rawClient(url);
	c.write(encode(...args));
	const [reply] = await c.replies(1);
	c.end();
	return reply;
}

/** A server that answers each request with the next of `answers`, written a byte at a time. */
export async function tricklingServer(answers: readonly Buffer[]) {
	let next = 0;
	const sockets: Socket[] = [];
	const server = createServer((socket) => {
		sockets.push(socket);
		const reader = frames();
		// Answers go out in order, a chunk's after the one before.
		let chain = Promise.resolve();
		socket.on("data", (chunk: Buffer) => {
			const asked = reader.push(chunk).length;
			chain = chain.then(async () => {
				for (let i = 0; i < asked; i++) {
					for (const b of answers[next++] ?? Buffer.from("-ERR none left\r\n")) {
						socket.write(Buffer.from([b]));
						await new Promise((resolve) => setTimeout(resolve, 1));
					}
				}
			});
		});
		socket.on("error", () => {});
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const address = server.address();
	const port = typeof address === "object" && address ? address.port : 0;
	return {
		upstream: { host: "127.0.0.1", port },
		stop: () =>
			new Promise<void>((resolve) => {
				for (const s of sockets) s.destroy();
				server.close(() => resolve());
			}),
	};
}
