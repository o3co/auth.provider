import { createServer } from "node:http";
import { describe, expect, it } from "vitest";
import { startTrace } from "../trace.ts";

/** A server that answers each request with its method, path and body, and two cookies. */
async function echo() {
	const server = createServer((req, res) => {
		let body = "";
		req.on("data", (c: Buffer) => {
			body += c;
		});
		req.on("end", () => {
			res.setHeader("Set-Cookie", ["a=1", "b=2"]);
			res.writeHead(201, { "content-type": "text/plain" });
			res.end(`${req.method} ${req.url} ${body}`);
		});
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const address = server.address();
	const port = typeof address === "object" && address ? address.port : 0;
	return { base: `http://127.0.0.1:${port}`, stop: () => new Promise((r) => server.close(r)) };
}

describe("an instance's trace", () => {
	it("passes each request and its answer through as they are, and records its method and path", async () => {
		const target = await echo();
		const trace = await startTrace(target.base);
		const answer = await fetch(`${trace.url}/session/logout?x=1`, { method: "POST", body: "hi" });
		expect(answer.status).toBe(201);
		expect(await answer.text()).toBe("POST /session/logout?x=1 hi");
		expect(answer.headers.getSetCookie()).toEqual(["a=1", "b=2"]);
		expect(trace.requests().map(({ method, path }) => [method, path])).toEqual([
			["POST", "/session/logout?x=1"],
		]);
		await trace.stop();
		await target.stop();
	});

	it("goes on at the same URL once pointed at the instance started again", async () => {
		const [first, second] = [await echo(), await echo()];
		const trace = await startTrace(first.base);
		await fetch(`${trace.url}/a`);
		trace.pointAt(second.base);
		expect(await (await fetch(`${trace.url}/b`)).text()).toBe("GET /b ");
		expect(trace.requests().map((r) => r.path)).toEqual(["/a", "/b"]);
		await trace.stop();
		await Promise.all([first.stop(), second.stop()]);
	});

	it("answers 502 while its instance is down, and records the request", async () => {
		const trace = await startTrace("http://127.0.0.1:1");
		expect((await fetch(`${trace.url}/c`)).status).toBe(502);
		expect(trace.requests().map((r) => r.path)).toEqual(["/c"]);
		await trace.stop();
	});
});
