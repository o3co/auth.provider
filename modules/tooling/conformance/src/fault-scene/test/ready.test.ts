import { createServer, type Socket } from "node:net";
import { expect, it } from "vitest";
import type { Instance } from "../../deployment/deployment.ts";
import { ready } from "../fault-scene.ts";

it("gives up on an instance that takes a request and never answers, at its bound", async () => {
	const held: Socket[] = [];
	// Takes each connection and sends nothing back, headers included.
	const silent = createServer((socket) => held.push(socket));
	await new Promise<void>((resolve) => silent.listen(0, "127.0.0.1", resolve));
	const address = silent.address();
	const port = typeof address === "object" && address ? address.port : 0;
	const instance = { index: 0, baseUrl: `http://127.0.0.1:${port}` } as Instance;
	const began = performance.now();
	try {
		await expect(ready(instance, 300)).rejects.toThrow(/not ready within 300 ms/);
		expect(performance.now() - began).toBeLessThan(2_000);
	} finally {
		for (const socket of held) socket.destroy();
		await new Promise((resolve) => silent.close(resolve));
	}
});
