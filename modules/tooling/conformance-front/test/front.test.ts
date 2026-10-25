import { X509Certificate } from "node:crypto";
import { mkdtemp } from "node:fs/promises";
import { createServer, type IncomingHttpHeaders } from "node:http";
import { request } from "node:https";
import { type AddressInfo, createServer as createNetServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import { type Front, type FrontOptions, selfSigned, startFront } from "../src/front.ts";

interface Seen {
	readonly method: string | undefined;
	readonly url: string | undefined;
	readonly headers: IncomingHttpHeaders;
	readonly body: string;
}

/** The app behind the front: answers each request with `answer`, keeping what it was sent. */
async function app(answer: (seen: Seen) => { status: number; headers?: Record<string, string> }) {
	const seen: Seen[] = [];
	const server = createServer((req, res) => {
		let body = "";
		req.on("data", (chunk) => {
			body += chunk;
		});
		req.on("end", () => {
			const one = { method: req.method, url: req.url, headers: req.headers, body };
			seen.push(one);
			const { status, headers } = answer(one);
			res.writeHead(status, headers ?? {});
			res.end(`answered ${req.url}`);
		});
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	stops.push(() => new Promise((resolve) => server.close(() => resolve())));
	return { base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, seen };
}

const stops: (() => Promise<void>)[] = [];
afterEach(async () => {
	await Promise.all(stops.splice(0).map((stop) => stop()));
});

let server: { key: string; cert: string };
let client: { key: string; cert: string };
beforeAll(async () => {
	const dir = await mkdtemp(join(tmpdir(), "front-"));
	server = await selfSigned("op.test", join(dir, "server"));
	client = await selfSigned("client.test", join(dir, "client"));
});

async function front(upstream: string, more: Partial<FrontOptions> = {}): Promise<Front> {
	const started = await startFront({
		upstream: () => upstream,
		publicHost: "localhost",
		listen: "127.0.0.1",
		tls: server,
		...more,
	});
	stops.push(started.stop);
	return started;
}

/** A request to the front over https, trusting its certificate alone, with a client's if given. */
function send(
	at: string,
	path: string,
	init: {
		method?: string;
		headers?: Record<string, string>;
		body?: string;
		certificate?: { key: string; cert: string };
	} = {},
) {
	return new Promise<{ status: number; headers: IncomingHttpHeaders; body: string }>(
		(resolve, reject) => {
			const req = request(
				`${at}${path}`,
				{
					method: init.method ?? "GET",
					headers: init.headers,
					ca: server.cert,
					...(init.certificate ?? {}),
				},
				(res) => {
					let body = "";
					res.on("data", (chunk) => {
						body += chunk;
					});
					res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }));
				},
			);
			req.on("error", reject);
			req.end(init.body);
		},
	);
}

describe("a self-signed certificate for a front", () => {
	it("names its curve, as every TLS client takes it, and the host and loopback", () => {
		const parsed = new X509Certificate(server.cert);
		// An EC key written with explicit parameters is refused by Java's TLS, the suite's: the
		// certificate carries P-256's identifier (1.2.840.10045.3.1.7) and no prime field (1.2.840.10045.1.1).
		expect(parsed.raw.includes(Buffer.from("06082a8648ce3d030107", "hex"))).toBe(true);
		expect(parsed.raw.includes(Buffer.from("06072a8648ce3d0101", "hex"))).toBe(false);
		expect(parsed.subjectAltName).toBe("DNS:op.test, DNS:localhost, IP Address:127.0.0.1");
	});
});

describe("an https front of an app, as a deployment's proxy is", () => {
	it("is reached at its public host, on the port it took, under its own certificate", async () => {
		const a = await app(() => ({ status: 200 }));
		const f = await front(a.base);
		expect(f.origin).toMatch(/^https:\/\/localhost:\d+$/);
		expect((await send(f.origin, "/")).status).toBe(200);
	});

	it("passes a request on as one over https from its sender's address, and the answer back", async () => {
		const a = await app(() => ({ status: 201, headers: { "x-answer": "yes" } }));
		const f = await front(a.base);
		const answer = await send(f.origin, "/userinfo?x=1", {
			method: "POST",
			headers: {
				"content-type": "text/plain",
				"x-forwarded-for": "203.0.113.9",
				"x-forwarded-proto": "http",
				forwarded: "for=203.0.113.9",
			},
			body: "a=b",
		});
		expect(answer.status).toBe(201);
		expect(answer.headers["x-answer"]).toBe("yes");
		expect(answer.body).toBe("answered /userinfo?x=1");
		const sent = a.seen[0];
		expect(sent?.method).toBe("POST");
		expect(sent?.body).toBe("a=b");
		expect(sent?.headers["content-type"]).toBe("text/plain");
		// The front's own say alone: one scheme, and the address the request came from.
		expect(sent?.headers["x-forwarded-proto"]).toBe("https");
		expect(sent?.headers["x-forwarded-for"]).toBe("127.0.0.1");
		expect(sent?.headers.forwarded).toBeUndefined();
	});

	it("tells the app the sender the harness names, where it names one, in place of the peer's address", async () => {
		const a = await app(() => ({ status: 200 }));
		// A client on this machine reaches the front from loopback, as the app's trusted proxy does.
		const f = await front(a.base, { sender: "198.51.100.30" });
		await send(f.origin, "/x", { headers: { "x-forwarded-for": "203.0.113.9" } });
		expect(a.seen[0]?.headers["x-forwarded-for"]).toBe("198.51.100.30");
	});

	it("reaches the app where it runs once it runs, after the front started", async () => {
		let upstream = "http://127.0.0.1:1";
		const f = await startFront({
			upstream: () => upstream,
			publicHost: "localhost",
			listen: "127.0.0.1",
			tls: server,
		});
		stops.push(f.stop);
		const a = await app(() => ({ status: 204 }));
		upstream = a.base;
		expect((await send(f.origin, "/late")).status).toBe(204);
	});

	it("answers 502 while the app cannot be reached", async () => {
		const f = await front("http://127.0.0.1:1");
		expect((await send(f.origin, "/")).status).toBe(502);
	});

	it("answers a request itself where its handler does, and passes on the rest", async () => {
		const a = await app(() => ({ status: 200 }));
		const f = await front(a.base, {
			handle: (req) =>
				req.url.pathname === "/login"
					? {
							status: 200,
							headers: { "content-type": "text/html" },
							body: `page ${req.method} ${req.body}`,
						}
					: undefined,
		});
		const page = await send(f.origin, "/login", { method: "POST", body: "u=1" });
		expect(page.body).toBe("page POST u=1");
		await send(f.origin, "/other");
		expect(a.seen.map((s) => s.url)).toEqual(["/other"]);
	});

	it("passes on a request as its rewrite changes it, with the body's length", async () => {
		const a = await app(() => ({ status: 200 }));
		const f = await front(a.base, {
			rewrite: (req) => {
				const url = new URL(req.url);
				url.searchParams.set("added", "1");
				return { url, body: Buffer.from(`${req.body}&more=2`) };
			},
		});
		await send(f.origin, "/x?a=1", { method: "POST", body: "b=1" });
		expect(a.seen[0]?.url).toBe("/x?a=1&added=1");
		expect(a.seen[0]?.body).toBe("b=1&more=2");
		expect(a.seen[0]?.headers["content-length"]).toBe("10");
	});

	it("tells the app's answers to its watcher, with the request they answer", async () => {
		const a = await app(() => ({
			status: 302,
			headers: { location: "https://rp.test/cb?code=c" },
		}));
		const told: string[] = [];
		const f = await front(a.base, {
			answered: (req, answer) =>
				told.push(`${req.url.pathname} ${answer.status} ${answer.headers.location}`),
		});
		await send(f.origin, "/authorize");
		expect(told).toEqual(["/authorize 302 https://rp.test/cb?code=c"]);
	});

	it("forwards the certificate a client presents in the header named, and never one a client wrote", async () => {
		const a = await app(() => ({ status: 200 }));
		const f = await front(a.base, { clientCertificate: { header: "x-client-cert" } });
		await send(f.origin, "/token", { certificate: client, headers: { "x-client-cert": "forged" } });
		await send(f.origin, "/token", { headers: { "x-client-cert": "forged" } });
		const [withCert, without] = a.seen;
		expect(decodeURIComponent(withCert?.headers["x-client-cert"] as string)).toBe(
			client.cert.trim(),
		);
		expect(without?.headers["x-client-cert"]).toBeUndefined();
	});
});

describe("what an https front passes on of a connection", () => {
	it("drops a request's per-connection headers, those its Connection header names among them", async () => {
		const a = await app(() => ({ status: 200 }));
		const f = await front(a.base);
		await send(f.origin, "/x", {
			headers: {
				connection: "x-hop, X-Other",
				"x-hop": "value",
				"x-other": "v",
				"x-kept": "k",
				te: "trailers",
			},
		});
		const sent = a.seen[0]?.headers;
		expect(sent?.["x-hop"]).toBeUndefined();
		expect(sent?.["x-other"]).toBeUndefined();
		expect(sent?.te).toBeUndefined();
		expect(sent?.["x-kept"]).toBe("k");
	});

	it("passes a chunked request with a declared trailer on whole, by its length", async () => {
		const a = await app(() => ({ status: 200 }));
		const f = await front(a.base);
		const answer = await new Promise<number>((resolve, reject) => {
			const req = request(
				`${f.origin}/chunked`,
				{ method: "POST", ca: server.cert, headers: { trailer: "x-sum" } },
				(res) => {
					res.resume();
					res.on("end", () => resolve(res.statusCode ?? 0));
				},
			);
			req.on("error", reject);
			req.write("a=1&");
			req.write("b=2");
			req.addTrailers({ "x-sum": "2" });
			req.end();
		});
		expect(answer).toBe(200);
		expect(a.seen[0]?.body).toBe("a=1&b=2");
		expect(a.seen[0]?.headers.trailer).toBeUndefined();
		expect(a.seen[0]?.headers["content-length"]).toBe("7");
	});

	it("drops an answer's per-connection headers, those the app's Connection header names among them", async () => {
		const a = await app(() => ({
			status: 200,
			headers: {
				connection: "x-internal",
				"x-internal": "secret",
				trailer: "x-sum",
				"x-shown": "s",
			},
		}));
		const f = await front(a.base);
		const answer = await send(f.origin, "/x");
		expect(answer.headers["x-internal"]).toBeUndefined();
		expect(answer.headers.trailer).toBeUndefined();
		expect(answer.headers["x-shown"]).toBe("s");
	});

	it("ends the client's answer where the app's is cut off midway", async () => {
		const cut = createServer((_req, res) => {
			res.writeHead(200, { "content-length": "100" });
			res.write("partial");
			setTimeout(() => res.socket?.destroy(), 50);
		});
		await new Promise<void>((resolve) => cut.listen(0, "127.0.0.1", resolve));
		stops.push(() => new Promise((resolve) => cut.close(() => resolve())));
		const f = await front(`http://127.0.0.1:${(cut.address() as AddressInfo).port}`);
		const ended = await new Promise<string>((resolve) => {
			const timer = setTimeout(() => resolve("still open"), 5_000);
			const req = request(`${f.origin}/x`, { ca: server.cert }, (res) => {
				res.on("data", () => {});
				res.on("error", () => resolve("ended"));
				res.on("aborted", () => resolve("ended"));
				res.on("close", () => {
					clearTimeout(timer);
					resolve("ended");
				});
			});
			req.on("error", () => resolve("ended"));
			req.end();
		});
		expect(ended).toBe("ended");
	});

	it("answers 502 where the watcher of the app's answers throws, and goes on serving", async () => {
		const a = await app(() => ({ status: 200 }));
		const f = await front(a.base, {
			answered: () => {
				throw new Error("a harness's hook failed");
			},
		});
		expect((await send(f.origin, "/x")).status).toBe(502);
		expect((await send(f.origin, "/y")).status).toBe(502);
	});

	it("ends the client's answer where the app's breaks after its headers went", async () => {
		// A good chunk, then a frame that is none: the request to the app fails after the answer began.
		const broken = createNetServer((socket) => {
			socket.once("data", () => {
				socket.write("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\nZZ\r\n");
			});
		});
		await new Promise<void>((resolve) => broken.listen(0, "127.0.0.1", resolve));
		stops.push(() => new Promise((resolve) => broken.close(() => resolve())));
		const f = await front(`http://127.0.0.1:${(broken.address() as AddressInfo).port}`);
		const ended = await new Promise<string>((resolve) => {
			const timer = setTimeout(() => resolve("still open"), 5_000);
			const req = request(`${f.origin}/x`, { ca: server.cert }, (res) => {
				res.on("data", () => {});
				res.on("error", () => resolve("ended"));
				res.on("close", () => {
					clearTimeout(timer);
					resolve("ended");
				});
			});
			req.on("error", () => resolve("ended"));
			req.end();
		});
		expect(ended).toBe("ended");
		// The front still serves.
		const a = await app(() => ({ status: 204 }));
		const g = await front(a.base);
		expect((await send(g.origin, "/z")).status).toBe(204);
	});
});
