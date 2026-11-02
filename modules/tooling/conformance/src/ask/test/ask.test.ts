import { createServer, type Socket } from "node:net";
import { describe, expect, it } from "vitest";
import { ask, askAll, ok, textOf } from "../ask.ts";

describe("asking Redis", () => {
	it("asks a server that closes before answering, and is refused at once", async () => {
		const sockets: Socket[] = [];
		const server = createServer((socket) => {
			sockets.push(socket);
			socket.end();
		});
		await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
		const address = server.address();
		const to = {
			host: "127.0.0.1",
			port: typeof address === "object" && address ? address.port : 0,
		};
		const started = performance.now();
		await expect(ask(to, ["PING"], 10_000)).rejects.toThrow();
		await expect(askAll(to, [["PING"], ["PING"]], 10_000)).rejects.toThrow();
		expect(performance.now() - started).toBeLessThan(5_000);
		for (const s of sockets) s.destroy();
		await new Promise((resolve) => server.close(resolve));
	});
});

describe("reading what Redis answered", () => {
	it("takes OK as done, and any other answer, an error above all, as a refusal naming the command", () => {
		expect(() => ok({ kind: "simple", text: "OK" }, ["CLIENT", "PAUSE"])).not.toThrow();
		expect(() => ok({ kind: "error", text: "NOPERM no" }, ["CLIENT", "PAUSE"])).toThrow(
			"CLIENT PAUSE refused: NOPERM no",
		);
		expect(() => ok({ kind: "integer", value: 1 }, ["REPLICAOF"])).toThrow(/REPLICAOF refused/);
	});

	it("reads a string answer's text, and refuses an error or none", () => {
		expect(textOf({ kind: "bulk", data: Buffer.from("role:master") }, ["INFO"])).toBe(
			"role:master",
		);
		expect(() => textOf({ kind: "error", text: "NOPERM" }, ["INFO"])).toThrow(
			"INFO refused: NOPERM",
		);
		expect(() => textOf({ kind: "bulk", data: null }, ["INFO"])).toThrow(/INFO refused/);
	});
});

describe("an answer Redis did not send as RESP2", () => {
	for (const [what, bytes] of [
		["RESP3", "%1\r\n+a\r\n+b\r\n"],
		["a broken frame", "$x\r\n"],
	] as const) {
		it(`is refused, ${what}, for one command and for several`, async () => {
			const sockets: Socket[] = [];
			const server = createServer((socket) => {
				sockets.push(socket);
				socket.on("data", () => socket.write(bytes));
			});
			await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
			const address = server.address();
			const to = {
				host: "127.0.0.1",
				port: typeof address === "object" && address ? address.port : 0,
			};
			await expect(ask(to, ["PING"], 5_000)).rejects.toThrow(/RESP3|malformed/);
			await expect(askAll(to, [["PING"], ["PING"]], 5_000)).rejects.toThrow(/RESP3|malformed/);
			for (const s of sockets) s.destroy();
			await new Promise((resolve) => server.close(resolve));
		});
	}
});
