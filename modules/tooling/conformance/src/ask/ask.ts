import { createConnection } from "node:net";
import type { Reply, Upstream } from "../relay/relay.ts";
import { frames } from "../relay/resp.ts";

const command = (args: readonly string[]) =>
	Buffer.from(
		`*${args.length}\r\n${args.map((a) => `$${Buffer.byteLength(a)}\r\n${a}\r\n`).join("")}`,
	);

/** One command on a connection of its own, and its reply. */
export function ask(to: Upstream, args: readonly string[], timeoutMs = 30_000): Promise<Reply> {
	return new Promise((resolve, reject) => {
		const socket = createConnection(to, () => socket.write(command(args)));
		const reader = frames();
		const timer = setTimeout(() => socket.destroy(new Error(`no reply to ${args[0]}`)), timeoutMs);
		let done = false;
		socket.on("data", (chunk: Buffer) => {
			let frame: ReturnType<typeof reader.push>[number] | undefined;
			try {
				[frame] = reader.push(chunk);
			} catch (error) {
				// An answer it cannot read ends the request through the error handler.
				socket.destroy(error as Error);
				return;
			}
			if (!frame) return;
			done = true;
			clearTimeout(timer);
			socket.end();
			resolve(frame.value);
		});
		socket.on("error", (error) => {
			done = true;
			clearTimeout(timer);
			reject(error);
		});
		socket.on("close", () => {
			clearTimeout(timer);
			if (!done) reject(new Error(`closed before its reply to ${args[0]}`));
		});
	});
}

/** Several commands in one write on a connection of its own, and their replies in order. */
export function askAll(
	to: Upstream,
	commands: readonly (readonly string[])[],
	timeoutMs = 30_000,
): Promise<Reply[]> {
	return new Promise((resolve, reject) => {
		const socket = createConnection(to, () => socket.write(Buffer.concat(commands.map(command))));
		const reader = frames();
		const replies: Reply[] = [];
		const timer = setTimeout(() => socket.destroy(new Error("no reply")), timeoutMs);
		let done = false;
		socket.on("data", (chunk: Buffer) => {
			try {
				replies.push(...reader.push(chunk).map((f) => f.value));
			} catch (error) {
				socket.destroy(error as Error);
				return;
			}
			if (replies.length < commands.length) return;
			done = true;
			clearTimeout(timer);
			socket.end();
			resolve(replies);
		});
		socket.on("error", (error) => {
			done = true;
			clearTimeout(timer);
			reject(error);
		});
		socket.on("close", () => {
			clearTimeout(timer);
			if (!done) reject(new Error("closed before all its replies"));
		});
	});
}

/** A `TIME` reply as microseconds on Redis's clock. */
export const microsOf = (reply: Reply | undefined): number => {
	const items = reply?.kind === "array" ? (reply.items ?? []) : [];
	const [s, us] = items.map((i) => (i.kind === "bulk" ? Number(i.data?.toString()) : Number.NaN));
	return (s ?? Number.NaN) * 1_000_000 + (us ?? Number.NaN);
};

const refused = (reply: Reply, what: readonly string[]) =>
	new Error(
		`${what.join(" ")} refused: ${reply.kind === "error" ? reply.text : `answered ${reply.kind}`}`,
	);

/** Fails unless Redis answered `OK`: an error answer is a refusal, never a success. */
export function ok(reply: Reply, what: readonly string[]): void {
	if (!(reply.kind === "simple" && reply.text === "OK")) throw refused(reply, what);
}

/** The text of a string answer; an error answer, or none, fails. */
export function textOf(reply: Reply, what: readonly string[]): string {
	if (reply.kind !== "bulk" || reply.data === null) throw refused(reply, what);
	return reply.data.toString();
}
