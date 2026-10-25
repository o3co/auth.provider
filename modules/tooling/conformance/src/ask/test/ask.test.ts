import { createServer, type Socket } from "node:net";
import { describe, expect, it } from "vitest";
import { ask, askAll } from "../ask.ts";

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
