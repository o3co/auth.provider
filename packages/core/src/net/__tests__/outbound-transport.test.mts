/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * The outbound fetch over real loopback sockets: the connection goes to the
 * address the policy checked and nowhere else, the TLS server name and
 * certificate identity are the URL's host, and the deadline, the cap and the
 * redirect and encoding rules hold against a real peer.
 */

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import type { AddressInfo, Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { TLSSocket } from "node:tls";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { isOutboundRefusal } from "#/net/outbound-fetch.mjs";
import { createNodeTransport, type OutboundTransport } from "#/net/outbound-transport.mjs";
import {
	createOutboundFetchForTesting,
	OutboundFetchError,
	withOutbound,
} from "#/testing/outboundFetch.mjs";

type Handler = (req: IncomingMessage, res: ServerResponse) => void;

interface Peer {
	readonly port: number;
	readonly requests: {
		method?: string;
		url?: string;
		headers: IncomingMessage["headers"];
		body: string;
	}[];
	/** The TLS server name each connection asked for (`false` for none). */
	readonly servernames: (string | false | null)[];
	/** How many connections the peer saw closed. */
	closedSockets(): number;
}

const servers: Server[] = [];

afterEach(async () => {
	await Promise.all(
		servers.splice(0).map(
			(server) =>
				new Promise<void>((resolve) => {
					server.closeAllConnections();
					server.close(() => resolve());
				}),
		),
	);
});

const record = (server: Server, handler: Handler, host: string): Promise<Peer> => {
	const requests: Peer["requests"] = [];
	const servernames: Peer["servernames"] = [];
	let closed = 0;
	server.on("connection", (socket: Socket) => {
		socket.on("close", () => {
			closed += 1;
		});
	});
	server.on("secureConnection", (socket: TLSSocket) => {
		servernames.push(socket.servername);
	});
	server.on("request", (req: IncomingMessage, res: ServerResponse) => {
		let body = "";
		req.on("data", (chunk: Buffer) => {
			body += chunk.toString("utf8");
		});
		req.on("end", () => {
			requests.push({ method: req.method, url: req.url, headers: req.headers, body });
			handler(req, res);
		});
	});
	servers.push(server);
	return new Promise((resolve) => {
		server.listen(0, host, () =>
			resolve({
				port: (server.address() as AddressInfo).port,
				requests,
				servernames,
				closedSockets: () => closed,
			}),
		);
	});
};

const httpPeer = (handler: Handler, host = "127.0.0.1"): Promise<Peer> =>
	record(createServer(), handler, host);

/** A resolver that answers each question with the next answer in `answers`, recording the questions. */
const sequence = (...answers: (readonly string[])[]) => {
	const calls: string[] = [];
	return {
		calls,
		lookup: async (hostname: string) => {
			calls.push(hostname);
			return answers[Math.min(calls.length - 1, answers.length - 1)] ?? [];
		},
	};
};

const localFetch = (
	options: {
		readonly lookup?: (hostname: string) => Promise<readonly string[]>;
		readonly transport?: OutboundTransport;
		readonly internalHosts?: readonly string[];
		readonly timeoutMs?: number;
		readonly maxResponseBytes?: number;
	} = {},
) =>
	createOutboundFetchForTesting({
		config: withOutbound({}, { internalHosts: [...(options.internalHosts ?? ["localhost"])] }),
		source: "registration",
		lookup: options.lookup ?? sequence(["127.0.0.1"]).lookup,
		...(options.transport !== undefined ? { transport: options.transport } : {}),
		...(options.timeoutMs !== undefined ? { timeoutMs: options.timeoutMs } : {}),
		...(options.maxResponseBytes !== undefined
			? { maxResponseBytes: options.maxResponseBytes }
			: {}),
	});

const reason = async (promise: Promise<unknown>): Promise<string> => {
	try {
		await promise;
	} catch (err) {
		expect(err).toBeInstanceOf(OutboundFetchError);
		return (err as OutboundFetchError).reason;
	}
	throw new Error("expected a rejection");
};

describe("plain http to a listed loopback host", () => {
	it("connects to the address the policy checked, resolving the name once", async () => {
		const peer = await httpPeer((_req, res) => res.end("ok"));
		const resolver = sequence(["127.0.0.1"], ["10.0.0.9"]);
		const res = await localFetch({ lookup: resolver.lookup })(
			`http://localhost:${peer.port}/bc?x=1`,
		);
		expect(await res.text()).toBe("ok");
		expect(resolver.calls).toEqual(["localhost"]);
		expect(peer.requests.map((r) => [r.url, r.headers.host])).toEqual([
			["/bc?x=1", `localhost:${peer.port}`],
		]);
	});

	it("posts the body with its length, asks for the identity encoding, and closes the connection", async () => {
		const peer = await httpPeer((_req, res) => {
			res.statusCode = 200;
			res.end();
		});
		const res = await localFetch()(`http://localhost:${peer.port}/bc`, {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: "logout_token=t",
		});
		expect(res.status).toBe(200);
		const [request] = peer.requests;
		expect(request?.method).toBe("POST");
		expect(request?.body).toBe("logout_token=t");
		expect(request?.headers["content-length"]).toBe("14");
		expect(request?.headers["accept-encoding"]).toBe("identity");
		await expect.poll(() => peer.closedSockets()).toBe(1);
	});

	it("refuses a redirect, and contacts nothing else", async () => {
		const peer = await httpPeer((_req, res) => {
			res.writeHead(307, { location: "http://169.254.169.254/latest" });
			res.end("moved");
		});
		const resolver = sequence(["127.0.0.1"]);
		expect(
			await reason(localFetch({ lookup: resolver.lookup })(`http://localhost:${peer.port}/`)),
		).toBe("redirect_refused");
		expect(resolver.calls).toHaveLength(1);
		expect(peer.requests).toHaveLength(1);
	});

	it("passes a 304, and answers a 404 at once though its body never ends", async () => {
		const notModified = await httpPeer((_req, res) => {
			res.writeHead(304, { etag: '"v1"' });
			res.end();
		});
		const res = await localFetch()(`http://localhost:${notModified.port}/`);
		expect(res.status).toBe(304);
		expect(res.headers.get("etag")).toBe('"v1"');

		const stalled = await httpPeer((_req, res) => {
			res.writeHead(404, { "content-length": "1000000" });
			res.write("partial");
		});
		const started = Date.now();
		const missing = await localFetch({ timeoutMs: 2000 })(`http://localhost:${stalled.port}/`);
		expect(missing.status).toBe(404);
		expect(missing.body).toBeNull();
		expect(Date.now() - started).toBeLessThan(1500);
		await expect.poll(() => stalled.closedSockets()).toBe(1);
	});

	it("refuses a body past the cap, declared or streamed, and closes the connection", async () => {
		const declared = await httpPeer((_req, res) => {
			res.writeHead(200, { "content-length": "100" });
			res.end("x".repeat(100));
		});
		expect(
			await reason(localFetch({ maxResponseBytes: 64 })(`http://localhost:${declared.port}/`)),
		).toBe("response_too_large");

		const streamed = await httpPeer((_req, res) => {
			res.writeHead(200);
			res.write("x".repeat(40));
			setTimeout(() => res.write("x".repeat(40)), 10);
		});
		expect(
			await reason(localFetch({ maxResponseBytes: 64 })(`http://localhost:${streamed.port}/`)),
		).toBe("response_too_large");
		await expect.poll(() => streamed.closedSockets()).toBe(1);
	});

	it("refuses an encoded body", async () => {
		const peer = await httpPeer((_req, res) => {
			res.writeHead(200, { "content-encoding": "gzip" });
			res.end(Buffer.from([0x1f, 0x8b]));
		});
		expect(await reason(localFetch()(`http://localhost:${peer.port}/`))).toBe(
			"unsupported_encoding",
		);
	});

	it("fails with timeout when the peer never answers, and closes the connection", async () => {
		const peer = await httpPeer(() => undefined);
		const err = localFetch({ timeoutMs: 100 })(`http://localhost:${peer.port}/`);
		expect(await reason(err)).toBe("timeout");
		await expect.poll(() => peer.closedSockets()).toBe(1);
	});

	it("reports a refused connection as a network failure, not a refusal", async () => {
		const peer = await httpPeer(() => undefined);
		const port = peer.port;
		await new Promise<void>((resolve) => servers.splice(0)[0]?.close(() => resolve()));
		try {
			await localFetch()(`http://localhost:${port}/`);
			throw new Error("expected a rejection");
		} catch (err) {
			expect((err as OutboundFetchError).reason).toBe("network_error");
			expect(isOutboundRefusal(err)).toBe(false);
		}
	});
});

describe("the transport alone", () => {
	it("rejects an exchange whose signal is already aborted, without opening a connection", async () => {
		const peer = await httpPeer((_req, res) => res.end("ok"));
		const reason = new Error("already aborted");
		await expect(
			createNodeTransport()({
				url: new URL(`http://localhost:${peer.port}/`),
				servername: undefined,
				addresses: ["127.0.0.1"],
				method: "GET",
				headers: {},
				body: undefined,
				signal: AbortSignal.abort(reason),
			}),
		).rejects.toBe(reason);
		expect(peer.closedSockets()).toBe(0);
		expect(peer.requests).toEqual([]);
	});
});

describe("https", () => {
	let dir: string;
	let full: { key: string; cert: string };
	let namesOnly: { key: string; cert: string };

	/** A self-signed certificate for `san`, made for this run so none expires in the tree. */
	const mint = (name: string, san: string) => {
		const key = join(dir, `${name}.key`);
		const cert = join(dir, `${name}.pem`);
		execFileSync(
			"openssl",
			[
				"req",
				"-x509",
				"-newkey",
				"ec",
				"-pkeyopt",
				"ec_paramgen_curve:prime256v1",
				"-nodes",
				"-keyout",
				key,
				"-out",
				cert,
				"-days",
				"2",
				"-subj",
				`/CN=${name}`,
				"-addext",
				`subjectAltName=${san}`,
			],
			{ stdio: "ignore" },
		);
		return { key: readFileSync(key, "utf8"), cert: readFileSync(cert, "utf8") };
	};

	beforeAll(() => {
		dir = mkdtempSync(join(tmpdir(), "outbound-transport-"));
		full = mint("full", "DNS:rp.pinned.test,IP:127.0.0.1,IP:::1");
		namesOnly = mint("names-only", "DNS:rp.pinned.test");
	});

	afterAll(() => {
		rmSync(dir, { recursive: true, force: true });
	});

	const httpsPeer = (pair: { key: string; cert: string }, host: string) =>
		record(createHttpsServer(pair), (_req, res) => res.end("secure"), host);

	it("connects a name to the checked address, sending the name as SNI and verifying it", async () => {
		const peer = await httpsPeer(full, "127.0.0.1");
		const resolver = sequence(["127.0.0.1"], ["10.0.0.9"]);
		const res = await localFetch({
			lookup: resolver.lookup,
			internalHosts: ["rp.pinned.test"],
			transport: createNodeTransport({ ca: full.cert }),
		})(`https://rp.pinned.test:${peer.port}/jwks`);
		expect(await res.text()).toBe("secure");
		expect(resolver.calls).toEqual(["rp.pinned.test"]);
		expect(peer.servernames).toEqual(["rp.pinned.test"]);
		expect(peer.requests[0]?.headers.host).toBe(`rp.pinned.test:${peer.port}`);
	});

	it("sends no SNI for an IPv6 literal, and verifies the certificate's IP address", async () => {
		const peer = await httpsPeer(full, "::1");
		const res = await localFetch({
			internalHosts: ["::1"],
			transport: createNodeTransport({ ca: full.cert }),
		})(`https://[::1]:${peer.port}/jwks`);
		expect(await res.text()).toBe("secure");
		expect(peer.servernames).toEqual([false]);

		const unnamed = await httpsPeer(namesOnly, "::1");
		expect(
			await reason(
				localFetch({
					internalHosts: ["::1"],
					transport: createNodeTransport({ ca: namesOnly.cert }),
				})(`https://[::1]:${unnamed.port}/jwks`),
			),
		).toBe("network_error");
		expect(unnamed.requests).toEqual([]);
	});

	it("refuses a certificate the trust store does not vouch for", async () => {
		const peer = await httpsPeer(full, "127.0.0.1");
		expect(
			await reason(
				localFetch({ internalHosts: ["rp.pinned.test"] })(
					`https://rp.pinned.test:${peer.port}/jwks`,
				),
			),
		).toBe("network_error");
		expect(peer.requests).toEqual([]);
	});
});
