import { createServer, request } from "node:http";
import { type AddressInfo, connect, createServer as createNetServer } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { startTunnel } from "../src/tunnel.ts";

const stops: (() => Promise<void>)[] = [];
afterEach(async () => {
	await Promise.all(stops.splice(0).map((stop) => stop()));
});

/** A TCP echo server: what goes through the tunnel comes back. */
async function echo() {
	const server = createNetServer((socket) => socket.pipe(socket));
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	stops.push(() => new Promise((resolve) => server.close(() => resolve())));
	return (server.address() as AddressInfo).port;
}

/** Sends `CONNECT target` to the tunnel, then `payload`; answers the status line and what came back. */
function through(tunnel: number, target: string, payload: string) {
	return new Promise<{ status: string; back: string }>((resolve, reject) => {
		const socket = connect(tunnel, "127.0.0.1", () => {
			socket.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`);
		});
		let text = "";
		let status = "";
		socket.on("data", (chunk) => {
			text += chunk;
			if (status === "" && text.includes("\r\n\r\n")) {
				status = text.split("\r\n")[0] ?? "";
				text = text.slice(text.indexOf("\r\n\r\n") + 4);
				if (status.includes(" 200")) socket.write(payload);
				else socket.end();
			}
			if (status.includes(" 200") && text.length >= payload.length) {
				socket.end();
				resolve({ status, back: text });
			}
		});
		socket.on("end", () => resolve({ status, back: text }));
		socket.on("error", reject);
	});
}

describe("the CONNECT proxy the app's outbound goes through to the suite", () => {
	it("tunnels to a destination it is allowed, mapping its name to where it listens", async () => {
		const port = await echo();
		const t = await startTunnel({ allow: { "suite.test:8443": `127.0.0.1:${port}` } });
		stops.push(t.stop);
		expect(await through(t.port, "suite.test:8443", "hello")).toEqual({
			status: "HTTP/1.1 200 Connection Established",
			back: "hello",
		});
		expect(t.opened()).toEqual(["suite.test:8443"]);
	});

	it("refuses any other destination, and any method but CONNECT", async () => {
		const t = await startTunnel({ allow: { "suite.test:8443": "127.0.0.1:1" } });
		stops.push(t.stop);
		expect((await through(t.port, "elsewhere.test:443", "x")).status).toBe(
			"HTTP/1.1 403 Forbidden",
		);
		const plain = await new Promise<number>((resolve) => {
			request({ host: "127.0.0.1", port: t.port, path: "http://suite.test:8443/" }, (res) => {
				res.resume();
				resolve(res.statusCode ?? 0);
			}).end();
		});
		expect(plain).toBe(405);
		expect(t.opened()).toEqual([]);
	});

	it("answers 502 where the destination cannot be reached", async () => {
		const closed = createServer();
		await new Promise<void>((resolve) => closed.listen(0, "127.0.0.1", resolve));
		const port = (closed.address() as AddressInfo).port;
		await new Promise<void>((resolve) => closed.close(() => resolve()));
		const t = await startTunnel({ allow: { "suite.test:8443": `127.0.0.1:${port}` } });
		stops.push(t.stop);
		expect((await through(t.port, "suite.test:8443", "x")).status).toBe("HTTP/1.1 502 Bad Gateway");
	});

	it("refuses a destination named like an object's own property, as any it is not allowed", async () => {
		const t = await startTunnel({ allow: { "suite.test:8443": "127.0.0.1:1" } });
		stops.push(t.stop);
		for (const target of ["constructor", "__proto__", "toString"]) {
			expect((await through(t.port, target, "x")).status).toBe("HTTP/1.1 403 Forbidden");
		}
	});

	it("answers 502 to a later tunnel that cannot open, after one to the same destination did", async () => {
		const server = createNetServer((socket) => socket.pipe(socket));
		await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
		const port = (server.address() as AddressInfo).port;
		const t = await startTunnel({ allow: { "suite.test:8443": `127.0.0.1:${port}` } });
		stops.push(t.stop);
		expect((await through(t.port, "suite.test:8443", "a")).status).toBe(
			"HTTP/1.1 200 Connection Established",
		);
		await new Promise<void>((resolve) => server.close(() => resolve()));
		expect((await through(t.port, "suite.test:8443", "b")).status).toBe("HTTP/1.1 502 Bad Gateway");
	});

	it("closes the destination's side where the client goes away abruptly", async () => {
		let closed = 0;
		const opened: Promise<void>[] = [];
		const server = createNetServer((socket) => {
			opened.push(new Promise((resolve) => socket.on("close", () => resolve())));
		});
		await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
		stops.push(() => new Promise((resolve) => server.close(() => resolve())));
		const port = (server.address() as AddressInfo).port;
		const t = await startTunnel({ allow: { "suite.test:8443": `127.0.0.1:${port}` } });
		stops.push(t.stop);
		await new Promise<void>((resolve, reject) => {
			const socket = connect(t.port, "127.0.0.1", () => {
				socket.write("CONNECT suite.test:8443 HTTP/1.1\r\nHost: suite.test:8443\r\n\r\n");
			});
			// Gone at once, by a reset: no end reaches the tunnel for its pipe to pass on.
			socket.once("data", () => {
				socket.resetAndDestroy();
				resolve();
			});
			socket.on("error", reject);
		});
		await Promise.race([
			Promise.all(opened).then(() => {
				closed = opened.length;
			}),
			new Promise((resolve) => setTimeout(resolve, 2_000)),
		]);
		expect(closed).toBe(1);
	});
});
